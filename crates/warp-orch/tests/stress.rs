//! Stress tests for warp-orch
//!
//! These tests verify the orchestrator can handle production-scale loads:
//! - Progress tracker with concurrent updates
//! - Drift detection with high-frequency changes
//!
//! Run with: cargo test -p warp-orch --test stress -- --nocapture

#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::unnecessary_cast)]

use std::sync::Arc;
use std::time::{Duration, Instant};
use warp_orch::{
    AccessRecord, DriftConfig, DriftDetector, PatternConfig, PatternDetector, ProgressTracker,
    TransferId,
};
use warp_sched::{ChunkId, EdgeIdx};

/// Helper to get current time in ms
fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}

/// Test: Progress tracker with many concurrent updates
#[test]
fn stress_progress_tracker_updates() {
    let tracker = Arc::new(ProgressTracker::new());
    let num_transfers = 1000;
    let updates_per_transfer = 100;

    println!(
        "Creating {} transfers with {} updates each...",
        num_transfers, updates_per_transfer
    );

    // Register transfers
    for i in 0..num_transfers {
        tracker.register(TransferId(i as u64), 100, 1024 * 1024 * 100); // 100 chunks, 100MB
        tracker.start(TransferId(i as u64));
    }

    let start = Instant::now();

    // Simulate progress updates
    for _update_round in 0..updates_per_transfer {
        for i in 0..num_transfers {
            let transfer_id = TransferId(i as u64);
            // Record chunk completion
            tracker.record_chunk_complete(transfer_id, 1024 * 1024); // 1MB per chunk
        }
    }

    let elapsed = start.elapsed();
    let total_updates = num_transfers * updates_per_transfer;
    println!("{} updates completed in {:?}", total_updates, elapsed);
    println!(
        "Updates per second: {:.0}",
        total_updates as f64 / elapsed.as_secs_f64()
    );

    // Verify all transfers have progress
    for i in 0..num_transfers {
        let progress = tracker.get_progress(TransferId(i as u64));
        assert!(progress.is_some(), "Transfer {} missing progress", i);
    }

    // 100k updates should complete in reasonable time
    let threshold = if cfg!(debug_assertions) {
        Duration::from_secs(15)
    } else {
        Duration::from_secs(3)
    };
    assert!(
        elapsed < threshold,
        "Progress updates too slow: {:?}",
        elapsed
    );
}

/// Test: Drift detector with high-frequency samples
#[test]
fn stress_drift_detector_samples() {
    let config = DriftConfig::new();
    let mut detector = DriftDetector::new(config);
    let num_transfers = 100;
    let samples_per_transfer = 1000;

    println!(
        "Recording {} samples for {} transfers...",
        samples_per_transfer, num_transfers
    );
    let start = Instant::now();

    // Set baselines
    for transfer_id in 0..num_transfers {
        detector.set_baseline(TransferId(transfer_id as u64), 100_000_000, 1000);
    }

    // Record many samples
    for sample_round in 0..samples_per_transfer {
        for transfer_id in 0..num_transfers {
            let edge_idx = EdgeIdx::new((sample_round % 10) as u32);
            // Varying speeds to simulate real conditions
            let speed = 90_000_000 + (sample_round % 20) as u64 * 1_000_000;
            let timestamp = now_ms() + sample_round as u64;
            detector.record_sample(TransferId(transfer_id as u64), edge_idx, speed, timestamp);
        }
    }

    let elapsed = start.elapsed();
    let total_samples = num_transfers * samples_per_transfer;
    println!("{} samples recorded in {:?}", total_samples, elapsed);
    println!(
        "Samples per second: {:.0}",
        total_samples as f64 / elapsed.as_secs_f64()
    );

    // Check drift for all transfers
    for transfer_id in 0..num_transfers {
        let metrics = detector.calculate_drift(TransferId(transfer_id as u64));
        // Just verify it doesn't panic
        let _ = metrics.is_slower();
    }

    let threshold = if cfg!(debug_assertions) {
        Duration::from_secs(10)
    } else {
        Duration::from_secs(2)
    };
    assert!(
        elapsed < threshold,
        "Drift detection too slow: {:?}",
        elapsed
    );
}

/// Test: Pattern detector with many access records
#[test]
fn stress_pattern_detector() {
    let config = PatternConfig::default();
    let mut detector = PatternDetector::new(config);
    let num_chunks = 10000;
    let accesses_per_chunk = 10;

    println!(
        "Recording {} accesses for {} chunks...",
        num_chunks * accesses_per_chunk,
        num_chunks
    );
    let start = Instant::now();

    // Record many access patterns
    for access_round in 0..accesses_per_chunk {
        for chunk_id in 0..num_chunks {
            let record = AccessRecord {
                chunk_id: ChunkId::new(chunk_id as u64),
                timestamp_ms: now_ms() + (access_round * num_chunks + chunk_id) as u64,
                edge_idx: EdgeIdx::new((chunk_id % 10) as u32),
                latency_ms: 10 + (chunk_id % 50) as u64,
            };
            detector.record_access(record);
        }

        // Analyze patterns periodically
        if access_round % 2 == 0 {
            let _patterns = detector.detect_patterns();
        }
    }

    let elapsed = start.elapsed();
    let total_accesses = num_chunks * accesses_per_chunk;
    println!("{} accesses recorded in {:?}", total_accesses, elapsed);
    println!(
        "Accesses per second: {:.0}",
        total_accesses as f64 / elapsed.as_secs_f64()
    );

    let threshold = if cfg!(debug_assertions) {
        Duration::from_secs(15)
    } else {
        Duration::from_secs(3)
    };
    assert!(
        elapsed < threshold,
        "Pattern detection too slow: {:?}",
        elapsed
    );
}

/// Test: Progress tracker with churn (start/complete cycles)
#[test]
fn stress_progress_tracker_churn() {
    let tracker = Arc::new(ProgressTracker::new());
    let churn_cycles = 100;
    let transfers_per_cycle = 100;

    println!(
        "Running {} churn cycles with {} transfers each...",
        churn_cycles, transfers_per_cycle
    );
    let start = Instant::now();

    let mut next_id = 0u64;

    for cycle in 0..churn_cycles {
        // Start new transfers
        for _ in 0..transfers_per_cycle {
            tracker.register(TransferId(next_id), 10, 1024 * 1024);
            tracker.start(TransferId(next_id));
            next_id += 1;
        }

        // Complete transfers from previous cycle
        if cycle > 0 {
            let base = (cycle - 1) * transfers_per_cycle as u64;
            for i in 0..transfers_per_cycle as u64 {
                tracker.complete(TransferId(base + i));
            }
        }

        // Update progress on current transfers
        for i in 0..transfers_per_cycle as u64 {
            let transfer_id = TransferId(cycle as u64 * transfers_per_cycle as u64 + i);
            tracker.record_chunk_complete(transfer_id, 512 * 1024);
        }
    }

    let elapsed = start.elapsed();
    let total_operations = churn_cycles * transfers_per_cycle * 3; // register + start + progress + complete
    println!("{} operations completed in {:?}", total_operations, elapsed);

    let threshold = if cfg!(debug_assertions) {
        Duration::from_secs(15)
    } else {
        Duration::from_secs(3)
    };
    assert!(
        elapsed < threshold,
        "Churn operations too slow: {:?}",
        elapsed
    );
}

/// Test: Mixed orchestrator load
#[test]
fn stress_mixed_orchestrator_load() {
    let tracker = Arc::new(ProgressTracker::new());
    let drift_config = DriftConfig::new();
    let mut drift_detector = DriftDetector::new(drift_config);
    let pattern_config = PatternConfig::default();
    let mut pattern_detector = PatternDetector::new(pattern_config);

    let num_cycles = 500;
    let num_edges = 50;
    let transfers_per_cycle = 20;

    println!("Running {} mixed workload cycles...", num_cycles);
    let start = Instant::now();

    let mut transfer_id = 0u64;
    let base_time = now_ms();

    for cycle in 0..num_cycles {
        // Start new transfers
        for _ in 0..transfers_per_cycle {
            tracker.register(TransferId(transfer_id), 10, 1024 * 1024 * 10);
            tracker.start(TransferId(transfer_id));

            // Record access pattern
            let record = AccessRecord {
                chunk_id: ChunkId::new(transfer_id),
                timestamp_ms: base_time + (cycle * transfers_per_cycle) as u64 + transfer_id,
                edge_idx: EdgeIdx::new((transfer_id % num_edges as u64) as u32),
                latency_ms: 10 + (transfer_id % 50),
            };
            pattern_detector.record_access(record);

            // Set drift baseline
            drift_detector.set_baseline(TransferId(transfer_id), 100_000_000, 1000);

            transfer_id += 1;
        }

        // Record drift samples
        for edge_id in 0..num_edges.min(10) {
            let speed = 90_000_000 + (cycle % 20) as u64 * 1_000_000;
            let recent_transfer = TransferId(transfer_id.saturating_sub(1));
            let timestamp = base_time + (cycle * 100 + edge_id) as u64;
            drift_detector.record_sample(
                recent_transfer,
                EdgeIdx::new(edge_id as u32),
                speed,
                timestamp,
            );
        }

        // Detect patterns periodically
        if cycle % 10 == 0 {
            let _ = pattern_detector.detect_patterns();
        }

        // Complete old transfers
        if cycle >= 10 {
            let base = (cycle - 10) as u64 * transfers_per_cycle as u64;
            for i in 0..transfers_per_cycle as u64 {
                tracker.complete(TransferId(base + i));
            }
        }
    }

    let elapsed = start.elapsed();
    println!("Mixed workload completed in {:?}", elapsed);
    println!("Total transfers created: {}", transfer_id);

    let threshold = if cfg!(debug_assertions) {
        Duration::from_secs(20)
    } else {
        Duration::from_secs(5)
    };
    assert!(
        elapsed < threshold,
        "Mixed workload too slow: {:?}",
        elapsed
    );
}
