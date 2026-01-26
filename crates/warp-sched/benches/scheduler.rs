//! Benchmarks for warp-sched scheduler components
//!
//! Run with: cargo bench -p warp-sched

#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::semicolon_if_nothing_returned)]
#![allow(clippy::suboptimal_flops)]
#![allow(clippy::cast_precision_loss)]
#![allow(missing_docs)]

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use warp_sched::{
    ChunkId, ChunkState, CostConfig, CpuChunkScheduler, CpuCostMatrix, CpuPathSelector,
    CpuStateBuffers, EdgeIdx, EdgeStateGpu, PathConfig, ScheduleRequest, SchedulerConfig,
};

/// Create test state with specified number of chunks and edges
fn create_test_state(num_chunks: usize, num_edges: usize) -> CpuStateBuffers {
    let mut state = CpuStateBuffers::new(num_chunks, num_edges);

    // Add chunks
    for i in 0..num_chunks {
        let mut hash = [0u8; 32];
        hash[..4].copy_from_slice(&(i as u32).to_le_bytes());
        let chunk = ChunkState::new(
            hash,
            256 * 1024, // 256KB chunks
            128,        // priority
            3,          // target 3 replicas
        );
        state.add_chunk(chunk).unwrap();

        // Add replicas on edges (3 replicas per chunk)
        for r in 0..3 {
            let edge_idx = EdgeIdx::new((i * 3 + r) as u32 % num_edges as u32);
            state.add_replica(i as u32, edge_idx);
        }
    }

    // Add edges
    for i in 0..num_edges {
        let edge = EdgeStateGpu::new(
            EdgeIdx::new(i as u32),
            100_000_000, // 100 Mbps bandwidth
            10_000,      // 10ms RTT (in microseconds)
            0.85,        // 85% health (0.0-1.0 scale)
            10,          // max transfers
        );
        state.add_edge(i as u32, edge).unwrap();
    }

    state
}

/// Benchmark cost matrix computation
fn bench_cost_matrix(c: &mut Criterion) {
    let mut group = c.benchmark_group("cost_matrix");

    // Test different scales
    let configs = [
        (100, 10, "100x10"),
        (1_000, 100, "1Kx100"),
        (10_000, 100, "10Kx100"),
        (10_000, 1_000, "10Kx1K"),
    ];

    for (num_chunks, num_edges, label) in configs {
        let state = create_test_state(num_chunks, num_edges);
        let mut cost_matrix = CpuCostMatrix::new(num_chunks, num_edges, CostConfig::default());

        group.throughput(Throughput::Elements((num_chunks * num_edges) as u64));
        group.bench_with_input(BenchmarkId::new("compute", label), &state, |b, state| {
            b.iter(|| {
                cost_matrix.compute(black_box(state));
            })
        });
    }

    group.finish();
}

/// Benchmark path selection
fn bench_path_selection(c: &mut Criterion) {
    let mut group = c.benchmark_group("path_selection");

    let num_chunks = 1_000;
    let num_edges = 100;
    let state = create_test_state(num_chunks, num_edges);
    let mut cost_matrix = CpuCostMatrix::new(num_chunks, num_edges, CostConfig::default());
    cost_matrix.compute(&state);

    let path_selector = CpuPathSelector::new(PathConfig::default());

    // Benchmark selecting paths for different batch sizes
    for batch_size in [10, 100, 500, 1000] {
        let chunk_ids: Vec<ChunkId> = (0..batch_size).map(|i| ChunkId::new(i as u64)).collect();

        group.throughput(Throughput::Elements(batch_size as u64));
        group.bench_with_input(
            BenchmarkId::new("select_batch", batch_size),
            &chunk_ids,
            |b, ids| b.iter(|| path_selector.select_batch(black_box(ids), black_box(&cost_matrix))),
        );
    }

    group.finish();
}

/// Benchmark full scheduler tick
fn bench_scheduler_tick(c: &mut Criterion) {
    let mut group = c.benchmark_group("scheduler_tick");
    group.sample_size(50); // Reduce sample size for slower benchmarks

    let configs = [
        (100, 10, "small"),
        (1_000, 100, "medium"),
        (10_000, 100, "large"),
    ];

    for (num_chunks, num_edges, label) in configs {
        let config = SchedulerConfig::default();
        let mut scheduler = CpuChunkScheduler::new(config, num_chunks, num_edges);

        // Setup initial state via schedule requests
        let chunks: Vec<[u8; 32]> = (0..100)
            .map(|i| {
                let mut hash = [0u8; 32];
                hash[..4].copy_from_slice(&(i as u32).to_le_bytes());
                hash
            })
            .collect();

        let request = ScheduleRequest::new(
            chunks, 128, // priority
            3,   // replica_target
        );
        let _ = scheduler.schedule(request);

        group.bench_function(BenchmarkId::new("tick", label), |b| {
            b.iter(|| black_box(scheduler.tick()))
        });
    }

    group.finish();
}

/// Benchmark state buffer updates
fn bench_state_updates(c: &mut Criterion) {
    let mut group = c.benchmark_group("state_updates");

    let num_chunks = 10_000;
    let num_edges = 1_000;
    let mut state = create_test_state(num_chunks, num_edges);

    // Benchmark edge state updates
    group.bench_function("update_edge", |b| {
        let mut edge_idx = 0u32;
        b.iter(|| {
            let new_edge = EdgeStateGpu::new(
                EdgeIdx::new(edge_idx),
                100_000_000 + (edge_idx as u64 * 1000),
                10_000 + edge_idx,
                0.80 + (edge_idx % 20) as f32 * 0.01,
                10,
            );
            let _ = state.update_edge(EdgeIdx::new(edge_idx), new_edge);
            edge_idx = (edge_idx + 1) % num_edges as u32;
        })
    });

    // Benchmark replica lookups
    group.bench_function("get_replicas", |b| {
        let mut chunk_idx = 0u32;
        b.iter(|| {
            let replicas = state.get_replicas(black_box(chunk_idx));
            black_box(replicas);
            chunk_idx = (chunk_idx + 1) % num_chunks as u32;
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_cost_matrix,
    bench_path_selection,
    bench_scheduler_tick,
    bench_state_updates,
);
criterion_main!(benches);
