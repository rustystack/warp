//! Stress tests for warp-sched
//!
//! These tests verify the scheduler can handle production-scale loads:
//! - Large numbers of chunks (100k+)
//! - Many edges (1k+)
//! - Rapid tick execution
//! - Concurrent operations
//! - Memory pressure
//!
//! Run with: cargo test -p warp-sched --test stress -- --nocapture

#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::suboptimal_flops)]
#![allow(clippy::cast_precision_loss)]

use std::time::{Duration, Instant};
use warp_sched::{
    ChunkId, ChunkState, CostConfig, CpuChunkScheduler, CpuCostMatrix, CpuStateBuffers, EdgeIdx,
    EdgeStateGpu, ScheduleRequest, SchedulerConfig,
};

/// Helper to create test state with specified number of chunks and edges
fn create_large_state(num_chunks: usize, num_edges: usize) -> CpuStateBuffers {
    let mut state = CpuStateBuffers::new(num_chunks, num_edges);

    // Add chunks
    for i in 0..num_chunks {
        let mut hash = [0u8; 32];
        hash[..8].copy_from_slice(&(i as u64).to_le_bytes());
        let chunk = ChunkState::new(hash, 256 * 1024, 128, 3);
        state.add_chunk(chunk).unwrap();
    }

    // Add edges
    for i in 0..num_edges {
        let edge = EdgeStateGpu::new(
            EdgeIdx::new(i as u32),
            1_000_000_000, // 1 Gbps
            10_000,        // 10ms RTT
            0.95,          // 95% health
            100,           // max 100 transfers
        );
        state.add_edge(i as u32, edge).unwrap();
    }

    // Add replicas - distribute chunks across edges (3 replicas per chunk)
    for chunk_idx in 0..num_chunks {
        for r in 0..3 {
            let edge_idx = ((chunk_idx * 3 + r) % num_edges) as u32;
            state.add_replica(chunk_idx as u32, EdgeIdx::new(edge_idx));
        }
    }

    state
}

/// Test: Large scale scheduling (100k chunks, 1k edges)
#[test]
fn stress_large_scale_scheduling() {
    let num_chunks = 100_000;
    let num_edges = 1_000;

    println!(
        "Creating state with {} chunks, {} edges...",
        num_chunks, num_edges
    );
    let start = Instant::now();
    let state = create_large_state(num_chunks, num_edges);
    println!("State created in {:?}", start.elapsed());

    // Verify state
    assert_eq!(state.chunk_count(), num_chunks);
    assert_eq!(state.edge_count(), num_edges);

    // Create cost matrix
    println!("Computing cost matrix...");
    let start = Instant::now();
    let mut cost_matrix = CpuCostMatrix::new(num_chunks, num_edges, CostConfig::default());
    cost_matrix.compute(&state);
    let cost_time = start.elapsed();
    println!("Cost matrix computed in {:?}", cost_time);

    // Cost matrix computation should complete in reasonable time
    assert!(
        cost_time < Duration::from_secs(30),
        "Cost matrix took too long: {:?}",
        cost_time
    );

    // Verify some costs are valid
    let valid_edges = cost_matrix.get_valid_edges(ChunkId::new(0));
    assert!(!valid_edges.is_empty(), "No valid edges for chunk 0");
}

/// Test: Rapid tick execution (1000 ticks)
#[test]
fn stress_rapid_ticks() {
    let num_chunks = 10_000;
    let num_edges = 100;
    let num_ticks = 1_000;

    let config = SchedulerConfig::default();
    let mut scheduler = CpuChunkScheduler::new(config, num_chunks, num_edges);

    // Set up initial state
    for i in 0..num_edges {
        let edge = EdgeStateGpu::new(EdgeIdx::new(i as u32), 1_000_000_000, 10_000, 0.95, 100);
        scheduler.state_mut().add_edge(i as u32, edge).unwrap();
    }

    // Add some chunks
    for i in 0..1000 {
        let mut hash = [0u8; 32];
        hash[..8].copy_from_slice(&(i as u64).to_le_bytes());
        let chunk = ChunkState::new(hash, 256 * 1024, 128, 3);
        scheduler.state_mut().add_chunk(chunk).unwrap();
        scheduler
            .state_mut()
            .add_replica(i as u32, EdgeIdx::new((i % num_edges) as u32));
    }

    println!("Running {} ticks...", num_ticks);
    let start = Instant::now();
    for _ in 0..num_ticks {
        scheduler.tick();
    }
    let tick_time = start.elapsed();
    println!("{} ticks completed in {:?}", num_ticks, tick_time);

    let avg_tick = tick_time / num_ticks as u32;
    println!("Average tick time: {:?}", avg_tick);

    // Debug builds are ~10x slower than release; 50ms threshold for debug
    // Release builds should achieve <10ms per tick
    let threshold = if cfg!(debug_assertions) {
        Duration::from_millis(50)
    } else {
        Duration::from_millis(10)
    };
    assert!(
        avg_tick < threshold,
        "Average tick too slow: {:?} (threshold: {:?})",
        avg_tick,
        threshold
    );

    assert_eq!(scheduler.metrics().tick_count, num_ticks as u64);
}

/// Test: Continuous scheduling with request bursts
#[test]
fn stress_request_bursts() {
    let num_edges = 100;
    let config = SchedulerConfig::default();
    let mut scheduler = CpuChunkScheduler::new(config, 100_000, num_edges);

    // Set up edges
    for i in 0..num_edges {
        let edge = EdgeStateGpu::new(EdgeIdx::new(i as u32), 1_000_000_000, 10_000, 0.95, 100);
        scheduler.state_mut().add_edge(i as u32, edge).unwrap();
    }

    println!("Sending 100 bursts of 1000 chunks each...");
    let start = Instant::now();

    for burst in 0..100 {
        // Create burst of requests
        let chunks: Vec<[u8; 32]> = (0..1000)
            .map(|i| {
                let mut hash = [0u8; 32];
                let id = (burst * 1000 + i) as u64;
                hash[..8].copy_from_slice(&id.to_le_bytes());
                hash
            })
            .collect();

        let request = ScheduleRequest::new(chunks, 128, 3);
        scheduler.schedule(request).unwrap();

        // Process with tick
        scheduler.tick();
    }

    let elapsed = start.elapsed();
    println!("100 bursts processed in {:?}", elapsed);
    println!(
        "Total scheduled: {} chunks",
        scheduler.metrics().scheduled_chunks
    );

    assert_eq!(scheduler.metrics().scheduled_chunks, 100_000);
    assert!(
        elapsed < Duration::from_secs(10),
        "Burst processing too slow: {:?}",
        elapsed
    );
}

/// Test: Memory stability under pressure
#[test]
fn stress_memory_stability() {
    let num_edges = 50;
    let config = SchedulerConfig::default();
    let mut scheduler = CpuChunkScheduler::new(config, 50_000, num_edges);

    // Set up edges
    for i in 0..num_edges {
        let edge = EdgeStateGpu::new(EdgeIdx::new(i as u32), 1_000_000_000, 10_000, 0.95, 100);
        scheduler.state_mut().add_edge(i as u32, edge).unwrap();
    }

    println!("Running 500 cycles of schedule + tick...");

    for cycle in 0..500 {
        // Schedule batch
        let chunks: Vec<[u8; 32]> = (0..100)
            .map(|i| {
                let mut hash = [0u8; 32];
                let id = (cycle * 100 + i) as u64;
                hash[..8].copy_from_slice(&id.to_le_bytes());
                hash
            })
            .collect();

        let request = ScheduleRequest::new(chunks, 128, 3);
        scheduler.schedule(request).unwrap();
        scheduler.tick();

        // Periodically check metrics
        if cycle % 100 == 0 {
            println!(
                "Cycle {}: scheduled={}, ticks={}",
                cycle,
                scheduler.metrics().scheduled_chunks,
                scheduler.metrics().tick_count
            );
        }
    }

    assert_eq!(scheduler.metrics().scheduled_chunks, 50_000);
    assert_eq!(scheduler.metrics().tick_count, 500);
}

/// Test: Failover handling under load
#[test]
fn stress_failover_handling() {
    use warp_sched::failover::{FailoverAction, FailoverDecision, FailoverReason};

    let num_edges = 100;
    let config = SchedulerConfig::default();
    let mut scheduler = CpuChunkScheduler::new(config, 10_000, num_edges);

    // Set up edges
    for i in 0..num_edges {
        let edge = EdgeStateGpu::new(EdgeIdx::new(i as u32), 1_000_000_000, 10_000, 0.95, 100);
        scheduler.state_mut().add_edge(i as u32, edge).unwrap();
    }

    println!("Simulating 1000 failovers...");
    let start = Instant::now();

    for i in 0..1000 {
        let decision = FailoverDecision {
            chunk_id: ChunkId::new(i as u64),
            reason: FailoverReason::Timeout,
            action: FailoverAction::Retry {
                edge_idx: EdgeIdx::new((i % num_edges) as u32),
            },
            failed_edge: EdgeIdx::new((i % num_edges) as u32),
            retry_count: 1,
            timestamp_ms: 12345,
        };
        scheduler.handle_failover(decision);
    }

    let elapsed = start.elapsed();
    println!("1000 failovers handled in {:?}", elapsed);

    assert_eq!(scheduler.metrics().failed_chunks, 1000);
    assert!(
        elapsed < Duration::from_millis(100),
        "Failover handling too slow: {:?}",
        elapsed
    );
}

/// Test: Cost matrix with varying edge health
#[test]
fn stress_cost_matrix_dynamic_health() {
    let num_chunks = 10_000;
    let num_edges = 100;

    let mut state = CpuStateBuffers::new(num_chunks, num_edges);

    // Add chunks with replicas
    for i in 0..num_chunks {
        let mut hash = [0u8; 32];
        hash[..8].copy_from_slice(&(i as u64).to_le_bytes());
        let chunk = ChunkState::new(hash, 256 * 1024, 128, 3);
        state.add_chunk(chunk).unwrap();

        for r in 0..3 {
            let edge_idx = ((i * 3 + r) % num_edges) as u32;
            state.add_replica(i as u32, EdgeIdx::new(edge_idx));
        }
    }

    // Add edges
    for i in 0..num_edges {
        let edge = EdgeStateGpu::new(EdgeIdx::new(i as u32), 1_000_000_000, 10_000, 0.95, 100);
        state.add_edge(i as u32, edge).unwrap();
    }

    let mut cost_matrix = CpuCostMatrix::new(num_chunks, num_edges, CostConfig::default());

    println!("Running 100 recomputations with health changes...");
    let start = Instant::now();

    for iteration in 0..100 {
        // Update some edge health values
        for i in 0..10 {
            let edge_idx = (iteration * 10 + i) % num_edges;
            let health = 0.5 + (iteration % 50) as f32 * 0.01;
            let edge = EdgeStateGpu::new(
                EdgeIdx::new(edge_idx as u32),
                1_000_000_000,
                10_000 + (iteration * 100) as u32,
                health,
                100,
            );
            let _ = state.update_edge(EdgeIdx::new(edge_idx as u32), edge);
        }

        // Recompute cost matrix
        cost_matrix.compute(&state);
    }

    let elapsed = start.elapsed();
    println!("100 recomputations completed in {:?}", elapsed);
    println!("Average recomputation: {:?}", elapsed / 100);

    assert!(
        elapsed < Duration::from_secs(30),
        "Dynamic recomputation too slow: {:?}",
        elapsed
    );
}

/// Test: Scheduler under mixed workload
#[test]
fn stress_mixed_workload() {
    let num_edges = 100;
    let config = SchedulerConfig::default();
    let mut scheduler = CpuChunkScheduler::new(config, 50_000, num_edges);

    // Set up edges with varying characteristics
    for i in 0..num_edges {
        let bandwidth = 100_000_000 + (i as u64 * 10_000_000); // 100Mbps - 1.1Gbps
        let rtt = 5_000 + (i as u32 * 500); // 5ms - 55ms
        let health = 0.7 + (i as f32 * 0.003); // 0.7 - 1.0

        let edge = EdgeStateGpu::new(
            EdgeIdx::new(i as u32),
            bandwidth,
            rtt,
            health,
            50 + (i as u16 % 50),
        );
        scheduler.state_mut().add_edge(i as u32, edge).unwrap();
    }

    println!("Running mixed workload simulation...");
    let start = Instant::now();

    // Simulate mixed workload
    for cycle in 0..200 {
        // Variable batch sizes
        let batch_size = match cycle % 4 {
            0 => 10,   // Small batch
            1 => 100,  // Medium batch
            2 => 500,  // Large batch
            _ => 1000, // Burst
        };

        let chunks: Vec<[u8; 32]> = (0..batch_size)
            .map(|i| {
                let mut hash = [0u8; 32];
                let id = (cycle * 1000 + i) as u64;
                hash[..8].copy_from_slice(&id.to_le_bytes());
                hash
            })
            .collect();

        let priority = match cycle % 3 {
            0 => 64,  // Low priority
            1 => 128, // Normal
            _ => 255, // High priority
        };

        let request = ScheduleRequest::new(chunks, priority, 3);
        scheduler.schedule(request).unwrap();

        // Multiple ticks per cycle for some cycles
        let tick_count = if cycle % 5 == 0 { 3 } else { 1 };
        for _ in 0..tick_count {
            scheduler.tick();
        }
    }

    let elapsed = start.elapsed();
    println!("Mixed workload completed in {:?}", elapsed);
    println!(
        "Metrics: scheduled={}, ticks={}, failed={}",
        scheduler.metrics().scheduled_chunks,
        scheduler.metrics().tick_count,
        scheduler.metrics().failed_chunks
    );

    assert!(
        elapsed < Duration::from_secs(10),
        "Mixed workload too slow: {:?}",
        elapsed
    );
}
