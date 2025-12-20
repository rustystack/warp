use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput, BenchmarkId};
use warp_io::{BuzhashChunker, SeqCdcChunker, SeqCdcConfig, ChunkerConfig};
use std::io::Cursor;

/// Generate pseudo-random test data with configurable patterns
fn generate_test_data(size: usize, pattern: DataPattern) -> Vec<u8> {
    match pattern {
        DataPattern::PseudoRandom => {
            (0..size)
                .map(|i| ((i.wrapping_mul(17).wrapping_add(31)) % 256) as u8)
                .collect()
        }
        DataPattern::Compressible => {
            // Mix of runs and varying data (simulates text/code)
            (0..size)
                .map(|i| {
                    if i % 100 < 20 {
                        // Runs of repeated bytes
                        b'a'
                    } else {
                        ((i.wrapping_mul(7).wrapping_add(13)) % 96 + 32) as u8
                    }
                })
                .collect()
        }
        DataPattern::Binary => {
            // Simulates binary data (e.g., compiled code)
            (0..size)
                .map(|i| {
                    let v = i.wrapping_mul(0x5DEECE66D).wrapping_add(0xB);
                    (v >> 16) as u8
                })
                .collect()
        }
        DataPattern::Monotonic => {
            // Data with many increasing/decreasing runs (favors SeqCDC)
            (0..size)
                .map(|i| {
                    let cycle = i % 512;
                    if cycle < 256 {
                        cycle as u8
                    } else {
                        (511 - cycle) as u8
                    }
                })
                .collect()
        }
    }
}

#[derive(Clone, Copy)]
enum DataPattern {
    PseudoRandom,
    Compressible,
    Binary,
    Monotonic,
}

impl DataPattern {
    fn name(&self) -> &'static str {
        match self {
            DataPattern::PseudoRandom => "random",
            DataPattern::Compressible => "text",
            DataPattern::Binary => "binary",
            DataPattern::Monotonic => "monotonic",
        }
    }
}

// ============================================================================
// BUZHASH BENCHMARKS (Legacy Baseline)
// ============================================================================

fn bench_buzhash(c: &mut Criterion) {
    let mut group = c.benchmark_group("buzhash");

    let sizes = [
        (1 * 1024 * 1024, "1MB"),
        (10 * 1024 * 1024, "10MB"),
        (100 * 1024 * 1024, "100MB"),
    ];

    for (size, name) in sizes {
        let data = generate_test_data(size, DataPattern::PseudoRandom);
        group.throughput(Throughput::Bytes(size as u64));

        let chunker = BuzhashChunker::new(ChunkerConfig::default());
        group.bench_with_input(BenchmarkId::new("chunk", name), &data, |b, data| {
            b.iter(|| chunker.chunk(Cursor::new(black_box(data))))
        });
    }

    group.finish();
}

// ============================================================================
// SEQCDC SCALAR BENCHMARKS
// ============================================================================

fn bench_seqcdc_scalar(c: &mut Criterion) {
    let mut group = c.benchmark_group("seqcdc-scalar");

    let sizes = [
        (1 * 1024 * 1024, "1MB"),
        (10 * 1024 * 1024, "10MB"),
        (100 * 1024 * 1024, "100MB"),
    ];

    for (size, name) in sizes {
        let data = generate_test_data(size, DataPattern::PseudoRandom);
        group.throughput(Throughput::Bytes(size as u64));

        let chunker = SeqCdcChunker::new(SeqCdcConfig::target_16kb());
        group.bench_with_input(BenchmarkId::new("chunk", name), &data, |b, data| {
            b.iter(|| chunker.chunk(Cursor::new(black_box(data))))
        });
    }

    group.finish();
}

// ============================================================================
// SEQCDC SIMD BENCHMARKS (AVX2/AVX-512)
// ============================================================================

fn bench_seqcdc_simd(c: &mut Criterion) {
    let mut group = c.benchmark_group("seqcdc-simd");

    let sizes = [
        (1 * 1024 * 1024, "1MB"),
        (10 * 1024 * 1024, "10MB"),
        (100 * 1024 * 1024, "100MB"),
    ];

    for (size, name) in sizes {
        let data = generate_test_data(size, DataPattern::PseudoRandom);
        group.throughput(Throughput::Bytes(size as u64));

        let chunker = SeqCdcChunker::new(SeqCdcConfig::target_16kb());
        group.bench_with_input(BenchmarkId::new("chunk", name), &data, |b, data| {
            b.iter(|| chunker.chunk_simd(Cursor::new(black_box(data))))
        });
    }

    group.finish();
}

// ============================================================================
// DIRECT SIMD MODULE BENCHMARKS (Zero-Copy)
// ============================================================================

fn bench_simd_direct(c: &mut Criterion) {
    use warp_io::simd;

    let mut group = c.benchmark_group("simd-direct");

    let sizes = [
        (1 * 1024 * 1024, "1MB"),
        (10 * 1024 * 1024, "10MB"),
        (100 * 1024 * 1024, "100MB"),
    ];

    let config = SeqCdcConfig::target_16kb();

    for (size, name) in sizes {
        let data = generate_test_data(size, DataPattern::PseudoRandom);
        group.throughput(Throughput::Bytes(size as u64));

        // Auto-dispatch (AVX-512 > AVX2 > scalar)
        group.bench_with_input(BenchmarkId::new("auto", name), &data, |b, data| {
            b.iter(|| {
                simd::chunk_buffer_auto(
                    black_box(data),
                    config.min_size,
                    config.max_size,
                    config.seq_length,
                    config.skip_trigger,
                    config.skip_size,
                    config.mode,
                )
            })
        });

        // Scalar-only boundary detection for comparison
        group.bench_with_input(BenchmarkId::new("boundaries-scalar", name), &data, |b, data| {
            b.iter(|| {
                simd::find_boundaries_scalar(
                    black_box(data),
                    config.seq_length,
                    config.mode,
                )
            })
        });
    }

    group.finish();
}

// ============================================================================
// DATA PATTERN COMPARISON
// ============================================================================

fn bench_data_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("patterns");
    let size = 10 * 1024 * 1024; // 10MB

    let patterns = [
        DataPattern::PseudoRandom,
        DataPattern::Compressible,
        DataPattern::Binary,
        DataPattern::Monotonic,
    ];

    let chunker = SeqCdcChunker::new(SeqCdcConfig::target_16kb());
    group.throughput(Throughput::Bytes(size as u64));

    for pattern in patterns {
        let data = generate_test_data(size, pattern);

        group.bench_with_input(
            BenchmarkId::new("seqcdc-simd", pattern.name()),
            &data,
            |b, data| {
                b.iter(|| chunker.chunk_simd(Cursor::new(black_box(data))))
            },
        );
    }

    group.finish();
}

// ============================================================================
// CHUNK SIZE COMPARISON
// ============================================================================

fn bench_chunk_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("chunk-sizes");
    let size = 10 * 1024 * 1024; // 10MB
    let data = generate_test_data(size, DataPattern::PseudoRandom);

    group.throughput(Throughput::Bytes(size as u64));

    // Different target chunk sizes
    let configs = [
        (SeqCdcConfig::target_4kb(), "4kb"),
        (SeqCdcConfig::target_8kb(), "8kb"),
        (SeqCdcConfig::target_16kb(), "16kb"),
    ];

    for (config, name) in configs {
        let chunker = SeqCdcChunker::new(config);

        group.bench_with_input(
            BenchmarkId::new("seqcdc-simd", name),
            &data,
            |b, data| {
                b.iter(|| chunker.chunk_simd(Cursor::new(black_box(data))))
            },
        );
    }

    group.finish();
}

// ============================================================================
// HEAD-TO-HEAD COMPARISON
// ============================================================================

fn bench_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("comparison");
    let size = 10 * 1024 * 1024; // 10MB
    let data = generate_test_data(size, DataPattern::PseudoRandom);

    group.throughput(Throughput::Bytes(size as u64));

    // Buzhash (legacy)
    let buzhash = BuzhashChunker::new(ChunkerConfig::default());
    group.bench_with_input(BenchmarkId::new("algorithm", "buzhash"), &data, |b, data| {
        b.iter(|| buzhash.chunk(Cursor::new(black_box(data))))
    });

    // SeqCDC scalar
    let seqcdc = SeqCdcChunker::new(SeqCdcConfig::target_16kb());
    group.bench_with_input(BenchmarkId::new("algorithm", "seqcdc-scalar"), &data, |b, data| {
        b.iter(|| seqcdc.chunk(Cursor::new(black_box(data))))
    });

    // SeqCDC SIMD
    group.bench_with_input(BenchmarkId::new("algorithm", "seqcdc-simd"), &data, |b, data| {
        b.iter(|| seqcdc.chunk_simd(Cursor::new(black_box(data))))
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_buzhash,
    bench_seqcdc_scalar,
    bench_seqcdc_simd,
    bench_simd_direct,
    bench_data_patterns,
    bench_chunk_sizes,
    bench_comparison,
);
criterion_main!(benches);
