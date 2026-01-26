//! Criterion benchmarks for warp-ec erasure coding
//!
//! Run with: cargo bench -p warp-ec

#![allow(clippy::needless_range_loop)]

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use rand::Rng;
use warp_ec::{ErasureConfig, ErasureDecoder, ErasureEncoder};

// ============================================================================
// Benchmark Data Sizes
// ============================================================================

const SIZES: &[(usize, &str)] = &[
    (1024, "1KB"),
    (64 * 1024, "64KB"),
    (1024 * 1024, "1MB"),
    (16 * 1024 * 1024, "16MB"),
];

// ============================================================================
// Helper Functions
// ============================================================================

fn generate_random_data(size: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut data = vec![0u8; size];
    rng.fill(&mut data[..]);
    data
}

// ============================================================================
// A. Throughput by Data Size
// ============================================================================

fn bench_encode_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode_throughput");
    let config = ErasureConfig::rs_10_4();
    let encoder = ErasureEncoder::new(config);

    for (size, name) in SIZES {
        let data = generate_random_data(*size);
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(name), size, |b, _| {
            b.iter(|| encoder.encode(black_box(&data)))
        });
    }
    group.finish();
}

fn bench_decode_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode_throughput");
    let config = ErasureConfig::rs_10_4();
    let encoder = ErasureEncoder::new(config.clone());
    let decoder = ErasureDecoder::new(config);

    for (size, name) in SIZES {
        let data = generate_random_data(*size);
        let shards = encoder.encode(&data).unwrap();
        let shards_opt: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(name), size, |b, _| {
            b.iter(|| decoder.decode(black_box(&shards_opt)))
        });
    }
    group.finish();
}

// ============================================================================
// B. Configuration Comparison
// ============================================================================

fn bench_config_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("config_comparison");
    let data = generate_random_data(1024 * 1024); // 1MB

    let configs = [
        ("RS(4,2)", ErasureConfig::rs_4_2()),
        ("RS(6,3)", ErasureConfig::rs_6_3()),
        ("RS(10,4)", ErasureConfig::rs_10_4()),
        ("RS(16,4)", ErasureConfig::rs_16_4()),
    ];

    // Encode benchmarks
    for (name, config) in &configs {
        let encoder = ErasureEncoder::new(config.clone());
        group.throughput(Throughput::Bytes(data.len() as u64));

        group.bench_function(BenchmarkId::new("encode", name), |b| {
            b.iter(|| encoder.encode(black_box(&data)))
        });
    }

    // Decode benchmarks (no loss)
    for (name, config) in &configs {
        let encoder = ErasureEncoder::new(config.clone());
        let decoder = ErasureDecoder::new(config.clone());
        let shards = encoder.encode(&data).unwrap();
        let shards_opt: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();

        group.throughput(Throughput::Bytes(data.len() as u64));

        group.bench_function(BenchmarkId::new("decode_no_loss", name), |b| {
            b.iter(|| decoder.decode(black_box(&shards_opt)))
        });
    }

    // Decode with max loss (recovery)
    for (name, config) in &configs {
        let encoder = ErasureEncoder::new(config.clone());
        let decoder = ErasureDecoder::new(config.clone());
        let shards = encoder.encode(&data).unwrap();

        // Remove maximum allowed parity shards
        let mut shards_opt: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        let parity_count = config.parity_shards();
        for i in 0..parity_count {
            shards_opt[config.data_shards() + i] = None;
        }

        group.throughput(Throughput::Bytes(data.len() as u64));

        group.bench_function(BenchmarkId::new("decode_max_loss", name), |b| {
            b.iter(|| decoder.decode(black_box(&shards_opt)))
        });
    }

    group.finish();
}

// ============================================================================
// C. Failure Recovery Patterns
// ============================================================================

fn bench_failure_recovery(c: &mut Criterion) {
    let mut group = c.benchmark_group("failure_recovery");
    let config = ErasureConfig::rs_10_4(); // 10 data, 4 parity
    let encoder = ErasureEncoder::new(config.clone());
    let decoder = ErasureDecoder::new(config.clone());

    let data = generate_random_data(1024 * 1024); // 1MB
    let shards = encoder.encode(&data).unwrap();

    group.throughput(Throughput::Bytes(data.len() as u64));

    // Test with 0, 1, 2, 3, 4 missing shards
    for missing in 0..=4usize {
        let mut shards_opt: Vec<Option<Vec<u8>>> = shards.clone().into_iter().map(Some).collect();

        // Remove 'missing' parity shards
        for i in 0..missing {
            shards_opt[10 + i] = None; // Remove parity shards
        }

        group.bench_function(BenchmarkId::new("parity_missing", missing), |b| {
            b.iter(|| decoder.decode(black_box(&shards_opt)))
        });
    }

    // Test with data shards missing
    for missing in 1..=4usize {
        let mut shards_opt: Vec<Option<Vec<u8>>> = shards.clone().into_iter().map(Some).collect();

        // Remove 'missing' data shards
        for i in 0..missing {
            shards_opt[i] = None; // Remove data shards
        }

        group.bench_function(BenchmarkId::new("data_missing", missing), |b| {
            b.iter(|| decoder.decode(black_box(&shards_opt)))
        });
    }

    // Mixed: some data, some parity missing
    {
        let mut shards_opt: Vec<Option<Vec<u8>>> = shards.clone().into_iter().map(Some).collect();
        shards_opt[0] = None; // 1 data shard
        shards_opt[1] = None; // 1 data shard
        shards_opt[10] = None; // 1 parity shard
        shards_opt[11] = None; // 1 parity shard

        group.bench_function("mixed_2data_2parity", |b| {
            b.iter(|| decoder.decode(black_box(&shards_opt)))
        });
    }

    group.finish();
}

// ============================================================================
// D. Fast-Path vs Slow-Path
// ============================================================================

fn bench_fast_slow_path(c: &mut Criterion) {
    let mut group = c.benchmark_group("fast_slow_path");
    let config = ErasureConfig::rs_10_4();
    let encoder = ErasureEncoder::new(config.clone());
    let decoder = ErasureDecoder::new(config.clone());

    let data = generate_random_data(1024 * 1024); // 1MB
    let shards = encoder.encode(&data).unwrap();

    group.throughput(Throughput::Bytes(data.len() as u64));

    // Fast path: all shards present (just concatenation)
    {
        let shards_opt: Vec<Option<Vec<u8>>> = shards.clone().into_iter().map(Some).collect();
        group.bench_function("fast_path_all_present", |b| {
            b.iter(|| decoder.decode(black_box(&shards_opt)))
        });
    }

    // Fast path: all data shards present (parity missing)
    {
        let mut shards_opt: Vec<Option<Vec<u8>>> = shards.clone().into_iter().map(Some).collect();
        // Remove all parity shards
        for i in 10..14 {
            shards_opt[i] = None;
        }
        group.bench_function("fast_path_data_only", |b| {
            b.iter(|| decoder.decode(black_box(&shards_opt)))
        });
    }

    // Slow path: minimum shards for recovery (needs RS decode)
    {
        let mut shards_opt: Vec<Option<Vec<u8>>> = shards.clone().into_iter().map(Some).collect();
        // Remove first 4 data shards - requires full RS reconstruction
        for i in 0..4 {
            shards_opt[i] = None;
        }
        group.bench_function("slow_path_min_shards", |b| {
            b.iter(|| decoder.decode(black_box(&shards_opt)))
        });
    }

    group.finish();
}

// ============================================================================
// E. Encode with Metadata
// ============================================================================

fn bench_encode_with_metadata(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode_with_metadata");
    let config = ErasureConfig::rs_10_4();
    let encoder = ErasureEncoder::new(config);

    for (size, name) in SIZES {
        let data = generate_random_data(*size);
        group.throughput(Throughput::Bytes(*size as u64));

        // Standard encode
        group.bench_with_input(BenchmarkId::new("encode", name), size, |b, _| {
            b.iter(|| encoder.encode(black_box(&data)))
        });

        // Encode with metadata (adds shard IDs)
        group.bench_with_input(
            BenchmarkId::new("encode_with_metadata", name),
            size,
            |b, _| b.iter(|| encoder.encode_with_metadata(black_box(&data))),
        );
    }

    group.finish();
}

// ============================================================================
// F. Decode Exact (with padding removal)
// ============================================================================

fn bench_decode_exact(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode_exact");
    let config = ErasureConfig::rs_10_4();
    let encoder = ErasureEncoder::new(config.clone());
    let decoder = ErasureDecoder::new(config);

    // Test with sizes that require padding
    let sizes_with_padding = [
        (1000, "1000B"), // Not divisible by 10
        (65535, "65535B"),
        (1000000, "1000000B"),
    ];

    for (size, name) in sizes_with_padding {
        let data = generate_random_data(size);
        let original_len = data.len();
        let shards = encoder.encode(&data).unwrap();
        let shards_opt: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();

        group.throughput(Throughput::Bytes(size as u64));

        // Standard decode (returns padded)
        group.bench_with_input(BenchmarkId::new("decode", name), &size, |b, _| {
            b.iter(|| decoder.decode(black_box(&shards_opt)))
        });

        // Decode exact (removes padding)
        group.bench_with_input(BenchmarkId::new("decode_exact", name), &size, |b, _| {
            b.iter(|| decoder.decode_exact(black_box(&shards_opt), original_len))
        });
    }

    group.finish();
}

// ============================================================================
// Criterion Groups
// ============================================================================

criterion_group!(
    benches,
    bench_encode_throughput,
    bench_decode_throughput,
    bench_config_comparison,
    bench_failure_recovery,
    bench_fast_slow_path,
    bench_encode_with_metadata,
    bench_decode_exact,
);

criterion_main!(benches);
