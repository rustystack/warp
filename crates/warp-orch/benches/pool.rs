//! Benchmarks for connection pool operations
//!
//! Measures the performance of:
//! - Connection acquisition (O(1) idle lookup via index)
//! - Connection release and reuse
//! - Concurrent access patterns
//! - Per-edge connection management

#![allow(clippy::collection_is_never_read)]
#![allow(clippy::semicolon_if_nothing_returned)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(missing_docs)]

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use tokio::runtime::Runtime;
use warp_orch::pool::{ConnectionPool, PoolConfig};
use warp_sched::EdgeIdx;

// ============================================================================
// ACQUIRE/RELEASE BENCHMARKS (O(1) via idle index)
// ============================================================================

fn bench_acquire_release(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("pool-acquire-release");

    let config = PoolConfig {
        max_connections_per_edge: 100,
        max_total_connections: 1000,
        idle_timeout_ms: 60000,
        connect_timeout_ms: 5000,
        health_check_interval_ms: 30000,
    };

    let pool = ConnectionPool::new(config).unwrap();
    let edge = EdgeIdx::new(1);

    // Pre-warm: Create and release connections to populate idle pool
    rt.block_on(async {
        let mut conns = Vec::new();
        for _ in 0..50 {
            conns.push(pool.acquire(edge).await.unwrap());
        }
        // Drop all to return to idle pool
    });

    group.throughput(Throughput::Elements(1));

    // Benchmark acquire from idle pool (O(1) via pop_idle_connection)
    group.bench_function("acquire-from-idle", |b| {
        b.iter(|| {
            rt.block_on(async {
                let conn = pool.acquire(black_box(edge)).await.unwrap();
                black_box(conn)
                // Connection released on drop
            })
        })
    });

    group.finish();
}

// ============================================================================
// CONCURRENT ACCESS BENCHMARKS
// ============================================================================

fn bench_concurrent_acquire(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("pool-concurrent");

    let config = PoolConfig {
        max_connections_per_edge: 32,
        max_total_connections: 256,
        idle_timeout_ms: 60000,
        connect_timeout_ms: 5000,
        health_check_interval_ms: 30000,
    };

    // Benchmark with different concurrency levels
    for num_concurrent in [4, 8, 16, 32] {
        let pool = ConnectionPool::new(config.clone()).unwrap();

        // Pre-warm with connections
        rt.block_on(async {
            let mut conns = Vec::new();
            for i in 0..num_concurrent {
                let edge = EdgeIdx::new(i as u32 % 4);
                conns.push(pool.acquire(edge).await.unwrap());
            }
        });

        group.throughput(Throughput::Elements(num_concurrent as u64));

        group.bench_with_input(
            BenchmarkId::new("parallel-acquire", num_concurrent),
            &num_concurrent,
            |b, &n| {
                b.iter(|| {
                    rt.block_on(async {
                        let mut handles = Vec::with_capacity(n);
                        for i in 0..n {
                            let pool = pool.clone();
                            let edge = EdgeIdx::new(i as u32 % 4);
                            handles.push(tokio::spawn(async move {
                                let conn = pool.acquire(edge).await.unwrap();
                                black_box(conn.conn_id())
                            }));
                        }
                        for handle in handles {
                            handle.await.unwrap();
                        }
                    })
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// MULTI-EDGE BENCHMARKS
// ============================================================================

fn bench_multi_edge(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("pool-multi-edge");

    let config = PoolConfig {
        max_connections_per_edge: 8,
        max_total_connections: 128,
        idle_timeout_ms: 60000,
        connect_timeout_ms: 5000,
        health_check_interval_ms: 30000,
    };

    // Benchmark with different number of edges
    for num_edges in [4, 8, 16] {
        let pool = ConnectionPool::new(config.clone()).unwrap();

        // Pre-warm connections for each edge
        rt.block_on(async {
            let mut conns = Vec::new();
            for i in 0..num_edges {
                let edge = EdgeIdx::new(i as u32);
                for _ in 0..4 {
                    conns.push(pool.acquire(edge).await.unwrap());
                }
            }
        });

        group.throughput(Throughput::Elements(num_edges as u64));

        group.bench_with_input(
            BenchmarkId::new("round-robin-edges", num_edges),
            &num_edges,
            |b, &n| {
                let mut edge_counter = 0u32;
                b.iter(|| {
                    rt.block_on(async {
                        let edge = EdgeIdx::new(edge_counter % n as u32);
                        edge_counter = edge_counter.wrapping_add(1);
                        let conn = pool.acquire(black_box(edge)).await.unwrap();
                        black_box(conn.conn_id())
                    })
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// POOL STATS BENCHMARKS
// ============================================================================

fn bench_pool_stats(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("pool-stats");

    let config = PoolConfig {
        max_connections_per_edge: 16,
        max_total_connections: 256,
        idle_timeout_ms: 60000,
        connect_timeout_ms: 5000,
        health_check_interval_ms: 30000,
    };

    // Benchmark with different pool sizes
    for num_connections in [32, 64, 128] {
        let pool = ConnectionPool::new(config.clone()).unwrap();

        // Create connections
        rt.block_on(async {
            let mut conns = Vec::new();
            for i in 0..num_connections {
                let edge = EdgeIdx::new(i as u32 % 8);
                conns.push(pool.acquire(edge).await.unwrap());
            }
            // Keep some, release others
            while conns.len() > num_connections / 2 {
                conns.pop();
            }
        });

        group.bench_with_input(
            BenchmarkId::new("collect-stats", num_connections),
            &num_connections,
            |b, _| b.iter(|| black_box(pool.stats())),
        );
    }

    group.finish();
}

// ============================================================================
// CONNECTION REUSE PATTERN
// ============================================================================

fn bench_connection_reuse(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("pool-reuse");

    let config = PoolConfig {
        max_connections_per_edge: 4,
        max_total_connections: 16,
        idle_timeout_ms: 60000,
        connect_timeout_ms: 5000,
        health_check_interval_ms: 30000,
    };

    let pool = ConnectionPool::new(config).unwrap();
    let edge = EdgeIdx::new(1);

    // Pre-warm with 4 connections
    rt.block_on(async {
        let mut conns = Vec::new();
        for _ in 0..4 {
            conns.push(pool.acquire(edge).await.unwrap());
        }
    });

    group.throughput(Throughput::Elements(100));

    // Simulate typical workload: acquire, use briefly, release
    group.bench_function("acquire-use-release-100", |b| {
        b.iter(|| {
            rt.block_on(async {
                for _ in 0..100 {
                    let conn = pool.acquire(black_box(edge)).await.unwrap();
                    // Simulate brief use
                    black_box(conn.conn_id());
                    // Connection released on drop
                }
            })
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_acquire_release,
    bench_concurrent_acquire,
    bench_multi_edge,
    bench_pool_stats,
    bench_connection_reuse,
);
criterion_main!(benches);
