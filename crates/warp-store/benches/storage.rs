//! Performance benchmarks for warp-store
//!
//! Benchmarks cover:
//! - Object put/get operations
//! - Ephemeral token generation/verification
//! - Transport tier selection
//! - Parcode field access (when feature enabled)

#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(clippy::unit_arg)]

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use std::time::Duration;
use tempfile::TempDir;

use warp_store::{
    AccessScope, EphemeralToken, ObjectData, ObjectKey, Permissions, Store, StoreConfig,
    transport::{PeerLocation, StorageTransport, TransportConfig},
};

/// Setup a temporary store for benchmarks
async fn setup_store() -> (Store<warp_store::backend::LocalBackend>, TempDir) {
    let temp_dir = tempfile::tempdir().unwrap();
    let config = StoreConfig {
        root_path: temp_dir.path().to_path_buf(),
        ..Default::default()
    };
    let store = Store::new(config).await.unwrap();
    store
        .create_bucket("bench", Default::default())
        .await
        .unwrap();
    (store, temp_dir)
}

/// Generate random data of specified size
fn generate_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 256) as u8).collect()
}

fn bench_put_get(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (store, _temp_dir) = rt.block_on(setup_store());

    let mut group = c.benchmark_group("put_get");

    for size in [1024, 4096, 16384, 65536, 262144, 1048576] {
        let data = generate_data(size);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("put", size), &data, |b, data| {
            let key = ObjectKey::new("bench", "test-object").unwrap();
            b.to_async(&rt).iter(|| async {
                let key = key.clone();
                let data = ObjectData::from(data.clone());
                black_box(store.put(&key, data).await.unwrap());
            });
        });

        // Setup for get benchmark
        let key = ObjectKey::new("bench", &format!("get-object-{}", size)).unwrap();
        rt.block_on(async {
            store
                .put(&key, ObjectData::from(data.clone()))
                .await
                .unwrap();
        });

        group.bench_with_input(BenchmarkId::new("get", size), &key, |b, key| {
            b.to_async(&rt).iter(|| async {
                black_box(store.get(key).await.unwrap());
            });
        });
    }

    group.finish();
}

fn bench_ephemeral_token(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (store, _temp_dir) = rt.block_on(setup_store());

    let key = ObjectKey::new("bench", "secret.bin").unwrap();

    let mut group = c.benchmark_group("ephemeral_token");

    // Token generation
    group.bench_function("generate", |b| {
        b.iter(|| {
            black_box(
                store
                    .create_ephemeral_url(&key, Duration::from_secs(3600))
                    .unwrap(),
            );
        });
    });

    // Token with full options
    group.bench_function("generate_full", |b| {
        b.iter(|| {
            black_box(
                store
                    .create_ephemeral_url_with_options(
                        AccessScope::Object(key.clone()),
                        Permissions::READ_WRITE,
                        Duration::from_secs(3600),
                        Some(vec!["10.0.0.0/8".parse().unwrap()]),
                        None,
                    )
                    .unwrap(),
            );
        });
    });

    // Token verification
    let token = store
        .create_ephemeral_url(&key, Duration::from_secs(3600))
        .unwrap();
    group.bench_function("verify", |b| {
        b.iter(|| {
            black_box(store.verify_token(&token, None).unwrap());
        });
    });

    // Token encode/decode
    let encoded = token.encode();
    group.bench_function("encode", |b| {
        b.iter(|| {
            black_box(token.encode());
        });
    });

    group.bench_function("decode", |b| {
        b.iter(|| {
            black_box(EphemeralToken::decode(&encoded).unwrap());
        });
    });

    group.finish();
}

fn bench_transport_tier(c: &mut Criterion) {
    let config = TransportConfig::default();
    let transport = StorageTransport::new(config);
    let local = PeerLocation::local();

    let mut group = c.benchmark_group("transport_tier");

    // Same process tier detection
    let same_process_peer = PeerLocation::local();
    group.bench_function("tier_same_process", |b| {
        b.iter(|| {
            black_box(same_process_peer.optimal_tier(&local));
        });
    });

    // Same machine tier detection
    let same_machine_peer = PeerLocation::same_machine("/tmp/test.sock".into());
    group.bench_function("tier_same_machine", |b| {
        b.iter(|| {
            black_box(same_machine_peer.optimal_tier(&local));
        });
    });

    // Network tier detection
    let network_peer = PeerLocation::network(
        "peer-1".into(),
        "10.0.0.1:9000".parse().unwrap(),
        Some("us-east-1a".into()),
    );
    group.bench_function("tier_network", |b| {
        b.iter(|| {
            black_box(network_peer.optimal_tier(&local));
        });
    });

    // Route addition and lookup
    let key = ObjectKey::new("bench", "routed-key").unwrap();
    transport.add_route(&key, same_machine_peer.clone());

    group.bench_function("route_lookup", |b| {
        b.iter(|| {
            black_box(transport.get_tier(&key));
        });
    });

    group.bench_function("route_add", |b| {
        let key = ObjectKey::new("bench", "new-key").unwrap();
        b.iter(|| {
            transport.add_route(&key, same_machine_peer.clone());
        });
    });

    group.finish();
}

fn bench_object_key(c: &mut Criterion) {
    let mut group = c.benchmark_group("object_key");

    // Key parsing
    group.bench_function("parse_simple", |b| {
        b.iter(|| {
            black_box(ObjectKey::new("bucket", "key").unwrap());
        });
    });

    group.bench_function("parse_nested", |b| {
        b.iter(|| {
            black_box(ObjectKey::new("bucket", "path/to/deeply/nested/object.bin").unwrap());
        });
    });

    // Key comparison
    let key1 = ObjectKey::new("bucket", "key1").unwrap();
    let key2 = ObjectKey::new("bucket", "key2").unwrap();

    group.bench_function("compare", |b| {
        b.iter(|| {
            black_box(key1 == key2);
        });
    });

    // Prefix matching
    let key = ObjectKey::new("bucket", "prefix/subdir/file.bin").unwrap();
    group.bench_function("prefix_match", |b| {
        b.iter(|| {
            black_box(key.matches_prefix("prefix/"));
        });
    });

    group.finish();
}

fn bench_collective_context(c: &mut Criterion) {
    use warp_store::collective::{CollectiveContext, Rank};

    let mut group = c.benchmark_group("collective");

    // Context creation
    group.bench_function("context_new", |b| {
        b.iter(|| {
            black_box(CollectiveContext::new(64, Rank::new(0)));
        });
    });

    // Rank iteration
    let ctx = CollectiveContext::new(64, Rank::new(32));
    group.bench_function("all_ranks_iter", |b| {
        b.iter(|| {
            let ranks: Vec<Rank> = ctx.all_ranks().collect();
            black_box(ranks);
        });
    });

    group.bench_function("other_ranks_iter", |b| {
        b.iter(|| {
            let ranks: Vec<Rank> = ctx.other_ranks().collect();
            black_box(ranks);
        });
    });

    group.finish();
}

#[cfg(feature = "erasure")]
fn bench_erasure(c: &mut Criterion) {
    use warp_store::backend::{ErasureBackend, StoreErasureConfig};

    let rt = tokio::runtime::Runtime::new().unwrap();
    let temp_dir = tempfile::tempdir().unwrap();

    // RS(10,4) - 10 data shards, 4 parity shards
    let config = StoreErasureConfig::new(10, 4).unwrap();

    let backend =
        rt.block_on(async { ErasureBackend::new(temp_dir.path(), config).await.unwrap() });

    let mut group = c.benchmark_group("erasure");

    // Encoding throughput
    for size in [65536, 262144, 1048576, 4194304] {
        let data = generate_data(size);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("encode", size), &data, |b, data| {
            b.iter(|| {
                let (shards, _meta) = backend.encode_to_shards(data, None).unwrap();
                black_box(shards);
            });
        });

        // Prepare shards for decode benchmark
        let (shards, meta) = backend.encode_to_shards(&data, None).unwrap();
        let shard_opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();

        group.bench_with_input(
            BenchmarkId::new("decode", size),
            &shard_opts,
            |b, shards| {
                b.iter(|| {
                    let decoded = backend
                        .decode_from_shards(shards, meta.original_size)
                        .unwrap();
                    black_box(decoded);
                });
            },
        );

        // Decode with missing parity shards (still recoverable)
        let mut sparse_shards = shard_opts.clone();
        // Remove 4 parity shards (indices 10-13)
        for i in 10..14 {
            sparse_shards[i] = None;
        }

        group.bench_with_input(
            BenchmarkId::new("decode_recovery", size),
            &sparse_shards,
            |b, shards| {
                b.iter(|| {
                    let decoded = backend
                        .decode_from_shards(shards, meta.original_size)
                        .unwrap();
                    black_box(decoded);
                });
            },
        );
    }

    group.finish();
}

#[cfg(feature = "erasure")]
fn bench_erasure_put_get(c: &mut Criterion) {
    use warp_store::backend::{ErasureBackend, StorageBackend, StoreErasureConfig};
    use warp_store::object::PutOptions;

    let rt = tokio::runtime::Runtime::new().unwrap();
    let temp_dir = tempfile::tempdir().unwrap();

    // RS(10,4) - 10 data shards, 4 parity shards
    let config = StoreErasureConfig::new(10, 4).unwrap();

    let backend = rt.block_on(async {
        let b = ErasureBackend::new(temp_dir.path(), config).await.unwrap();
        b.create_bucket("bench").await.unwrap();
        b
    });

    let mut group = c.benchmark_group("erasure_io");

    for size in [65536, 262144, 1048576, 4194304] {
        let data = generate_data(size);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("put", size), &data, |b, data| {
            let key = ObjectKey::new("bench", &format!("put-{}", size)).unwrap();
            b.to_async(&rt).iter(|| async {
                let key = key.clone();
                let data = ObjectData::from(data.clone());
                black_box(
                    backend
                        .put(&key, data, PutOptions::default())
                        .await
                        .unwrap(),
                );
            });
        });

        // Setup for get benchmark
        let key = ObjectKey::new("bench", &format!("get-{}", size)).unwrap();
        rt.block_on(async {
            backend
                .put(&key, ObjectData::from(data.clone()), PutOptions::default())
                .await
                .unwrap();
        });

        group.bench_with_input(BenchmarkId::new("get", size), &key, |b, key| {
            b.to_async(&rt).iter(|| async {
                black_box(backend.get(key).await.unwrap());
            });
        });
    }

    group.finish();
}

#[cfg(feature = "erasure")]
fn bench_distributed(c: &mut Criterion) {
    use warp_store::backend::{DistributedBackend, DistributedConfig, StorageBackend};
    use warp_store::object::PutOptions;

    let rt = tokio::runtime::Runtime::new().unwrap();
    let temp_dir = tempfile::tempdir().unwrap();

    let config = DistributedConfig::default();

    let backend = rt.block_on(async {
        let b = DistributedBackend::new(temp_dir.path(), config)
            .await
            .unwrap();
        b.create_bucket("bench").await.unwrap();
        b
    });

    let mut group = c.benchmark_group("distributed");

    // Put/Get with distributed backend (local-only mode since no remote domains)
    for size in [65536, 262144, 1048576] {
        let data = generate_data(size);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("put", size), &data, |b, data| {
            let key = ObjectKey::new("bench", &format!("dist-put-{}", size)).unwrap();
            b.to_async(&rt).iter(|| async {
                let key = key.clone();
                let data = ObjectData::from(data.clone());
                black_box(
                    backend
                        .put(&key, data, PutOptions::default())
                        .await
                        .unwrap(),
                );
            });
        });

        // Setup for get benchmark
        let key = ObjectKey::new("bench", &format!("dist-get-{}", size)).unwrap();
        rt.block_on(async {
            backend
                .put(&key, ObjectData::from(data.clone()), PutOptions::default())
                .await
                .unwrap();
        });

        group.bench_with_input(BenchmarkId::new("get", size), &key, |b, key| {
            b.to_async(&rt).iter(|| async {
                black_box(backend.get(key).await.unwrap());
            });
        });
    }

    // Stats collection
    group.bench_function("stats", |b| {
        b.to_async(&rt).iter(|| async {
            black_box(backend.stats().await);
        });
    });

    group.finish();
}

#[cfg(feature = "erasure")]
fn bench_shard_operations(c: &mut Criterion) {
    use warp_store::backend::{ErasureBackend, StorageBackend, StoreErasureConfig};
    use warp_store::object::PutOptions;

    let rt = tokio::runtime::Runtime::new().unwrap();
    let temp_dir = tempfile::tempdir().unwrap();

    // RS(10,4) - 10 data shards, 4 parity shards
    let config = StoreErasureConfig::new(10, 4).unwrap();

    let backend = rt.block_on(async {
        let b = ErasureBackend::new(temp_dir.path(), config).await.unwrap();
        b.create_bucket("bench").await.unwrap();
        b
    });

    // Store an object to get shards from
    let key = ObjectKey::new("bench", "shard-test").unwrap();
    let data = generate_data(1048576); // 1MB
    rt.block_on(async {
        backend
            .put(&key, ObjectData::from(data), PutOptions::default())
            .await
            .unwrap();
    });

    let mut group = c.benchmark_group("shard_ops");

    // Get individual shard
    group.bench_function("get_shard", |b| {
        b.to_async(&rt).iter(|| async {
            black_box(backend.get_shard(&key, 0).await.unwrap());
        });
    });

    // Get multiple shards in sequence (avoid futures dep for simplicity)
    group.bench_function("get_shards_sequential", |b| {
        b.to_async(&rt).iter(|| async {
            for i in 0..10 {
                black_box(backend.get_shard(&key, i).await.unwrap());
            }
        });
    });

    // Put individual shard
    let shard_data = vec![0u8; 75000]; // ~75KB per shard for 1MB/14 shards
    group.bench_function("put_shard", |b| {
        b.to_async(&rt).iter(|| async {
            backend.put_shard(&key, 0, &shard_data).await.unwrap();
        });
    });

    // Get shard metadata
    group.bench_function("get_shard_meta", |b| {
        b.to_async(&rt).iter(|| async {
            black_box(backend.get_shard_meta(&key).await.unwrap());
        });
    });

    // Shard health check
    group.bench_function("shard_health", |b| {
        b.to_async(&rt).iter(|| async {
            black_box(backend.shard_health(&key).await.unwrap());
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_put_get,
    bench_ephemeral_token,
    bench_transport_tier,
    bench_object_key,
    bench_collective_context,
);

#[cfg(feature = "erasure")]
criterion_group!(
    erasure_benches,
    bench_erasure,
    bench_erasure_put_get,
    bench_distributed,
    bench_shard_operations,
);

#[cfg(feature = "erasure")]
criterion_main!(benches, erasure_benches);

#[cfg(not(feature = "erasure"))]
criterion_main!(benches);
