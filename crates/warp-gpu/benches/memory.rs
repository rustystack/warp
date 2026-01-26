//! Benchmarks for pinned memory pool allocation and transfer performance

#![allow(unused_imports)]
#![allow(deprecated)]

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use warp_gpu::{GpuContext, PinnedMemoryPool, PoolConfig};

fn pool_allocation_benchmark(c: &mut Criterion) {
    let ctx = match GpuContext::new() {
        Ok(ctx) => ctx,
        Err(_) => {
            eprintln!("No GPU available, skipping benchmarks");
            return;
        }
    };

    let pool = PinnedMemoryPool::with_defaults(ctx.device().clone());

    let mut group = c.benchmark_group("pool_allocation");

    for size in &[64 * 1024, 1024 * 1024, 16 * 1024 * 1024] {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| {
                let buffer = pool.acquire(size).unwrap();
                black_box(&buffer);
                pool.release(buffer);
            });
        });
    }

    group.finish();
}

fn pool_reuse_benchmark(c: &mut Criterion) {
    let ctx = match GpuContext::new() {
        Ok(ctx) => ctx,
        Err(_) => return,
    };

    let pool = PinnedMemoryPool::with_defaults(ctx.device().clone());

    c.bench_function("pool_reuse_1mb", |b| {
        let size = 1024 * 1024;

        // Pre-warm the pool
        for _ in 0..4 {
            pool.release(pool.acquire(size).unwrap());
        }

        b.iter(|| {
            let buffer = pool.acquire(size).unwrap();
            black_box(&buffer);
            pool.release(buffer);
        });
    });
}

fn memory_transfer_benchmark(c: &mut Criterion) {
    let ctx = match GpuContext::new() {
        Ok(ctx) => ctx,
        Err(_) => return,
    };

    let mut group = c.benchmark_group("memory_transfer");

    for size in &[1024 * 1024, 16 * 1024 * 1024, 64 * 1024 * 1024] {
        let data = vec![42u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("host_to_device", size), size, |b, _| {
            b.iter(|| {
                let d_data = ctx.host_to_device(&data).unwrap();
                black_box(&d_data);
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    pool_allocation_benchmark,
    pool_reuse_benchmark,
    memory_transfer_benchmark
);
criterion_main!(benches);
