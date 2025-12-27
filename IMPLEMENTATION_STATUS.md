# Warp Implementation Status

> Reference document for tracking implementation progress

---

## Completed Features

### 1. SeqCDC SIMD Chunking
- **Status:** DONE
- **Files:** `crates/warp-io/src/chunker.rs`, `crates/warp-io/src/simd.rs`
- **Result:** 31 GB/s throughput (100x faster than Buzhash)
- **Platforms:** ARM NEON, AVX2, AVX-512

### 2. Zero-Copy QUIC Optimization
- **Status:** DONE
- **Files:**
  - `crates/warp-net/src/codec.rs` - Frame enum uses `Bytes` instead of `Vec<u8>`
  - `crates/warp-net/src/transport.rs` - `send_chunk`/`recv_chunk` use `Bytes`
  - `crates/warp-core/src/engine.rs` - Updated callers
  - `crates/warp-cli/src/commands/send.rs`, `bench.rs` - Updated callers
  - `crates/portal-net/src/manager.rs` - Updated callers
  - `crates/warp-orch/src/pool.rs` - Updated ConnectionHandle API

### 3. Sparse Merkle Trees
- **Status:** DONE
- **Files:**
  - `crates/warp-format/src/merkle.rs` - `SparseMerkleTree`, `MerkleProof`, `NodeCache`
  - `crates/warp-format/src/reader.rs` - WarpReader integration
- **Features:**
  - O(log n) single-chunk verification
  - Parallel root computation with rayon
  - LRU-cached node lookups
  - `verify_chunk_fast()`, `verify_random_sample()`

### 4. Reed-Solomon Erasure Coding (warp-ec)
- **Status:** DONE
- **Files:** `crates/warp-ec/` (new crate)
  - `src/lib.rs` - Exports and convenience functions
  - `src/config.rs` - `ErasureConfig` with presets RS(4,2), RS(6,3), RS(10,4), RS(16,4)
  - `src/encoder.rs` - `ErasureEncoder`
  - `src/decoder.rs` - `ErasureDecoder`
  - `src/shard.rs` - `Shard`, `ShardId`, `ShardType`
  - `src/error.rs` - Error types
- **Library:** `reed-solomon-simd` v3.0 (SIMD-optimized)
- **Tests:** 24 unit tests + 2 doc tests passing

### 5. Reverso QUIC Optimization
- **Status:** DONE
- **Goal:** CPU reduction in packet processing
- **Files modified:**
  - `crates/warp-net/src/codec.rs` - Pre-sized encoding, fast-path methods, string allocation fixes
  - `crates/warp-net/src/pool.rs` - Thread-local buffer cache
- **Optimizations implemented:**
  1. `encoded_size()` - Exact buffer pre-allocation (avoids BytesMut growth)
  2. `encode_preallocated()` - Pre-sized encoding for any frame
  3. `encode_chunk_fast()`, `encode_ack_fast()`, `encode_shard_fast()`, `encode_chunk_batch_fast()` - Specialized hot-path encoding with `#[inline(always)]`
  4. Thread-local buffer cache (4 buffers per tier) - Reduces global pool lock contention
  5. String allocation fixes - Use `std::str::from_utf8()` instead of `String::from_utf8(to_vec())`

### 6. Criterion Benchmarks for warp-ec
- **Status:** DONE
- **File:** `crates/warp-ec/benches/erasure.rs`
- **Benchmarks:**
  - `bench_encode_throughput` - 1KB, 64KB, 1MB, 16MB data sizes
  - `bench_decode_throughput` - Same sizes with all shards present
  - `bench_config_comparison` - RS(4,2), RS(6,3), RS(10,4), RS(16,4)
  - `bench_failure_recovery` - 0-4 missing shards, data vs parity loss
  - `bench_fast_slow_path` - Fast (all present) vs slow (reconstruction)
  - `bench_encode_with_metadata` - Metadata overhead comparison
  - `bench_decode_exact` - Padding removal overhead
- **Performance:** ~6.3 GiB/s encode throughput for 1MB (SIMD-optimized)
- **Run with:** `cargo bench -p warp-ec`

### 7. Integrate warp-ec into warp-core
- **Status:** DONE
- **Goal:** Use erasure coding in actual transfers
- **Implementation:**
  - `TransferConfig.erasure_config: Option<ErasureConfig>` - Configurable RS parameters
  - `send_remote()` - Encodes each chunk into shards via `ErasureEncoder`, sends `Frame::Shard`
  - `fetch_remote()` - Collects shards, decodes via `ErasureDecoder` when threshold met
  - Builder methods: `.with_erasure_coding()`, `.with_erasure_config()`
- **Usage:**
  ```rust
  let config = TransferConfig::default().with_erasure_coding();  // RS(10,4)
  let engine = TransferEngine::new(config);
  ```

### 8. Integrate SparseMerkleTree into Transfer Verification
- **Status:** DONE
- **Goal:** Use O(log n) verification during transfers
- **Implementation:**
  - `VerificationMode` enum: `None`, `Final`, `PerChunk`, `Sampling { percent }`
  - Sender builds `SparseMerkleTree` from chunk hashes
  - Sends `Frame::ChunkVerify { chunk_id, chunk_hash, proof }` for each verified chunk
  - Receiver verifies chunk hash on receipt
  - Builder methods: `.with_per_chunk_verification()`, `.with_sampling_verification(N)`
- **Usage:**
  ```rust
  let config = TransferConfig::default()
      .with_per_chunk_verification();  // Verify every chunk
  // Or: .with_sampling_verification(10)  // Verify 10% of chunks
  ```

---

### 9. Chonkers Algorithm (warp-chonkers) - All Phases Complete
- **Status:** DONE
- **Files:** `crates/warp-chonkers/` (new crate)
  - `src/lib.rs` - Main Chonkers API
  - `src/config.rs` - ChonkersConfig with layer presets
  - `src/chunk.rs` - ChunkId, ChunkWeight, Chunk types
  - `src/layer.rs` - Layer processing
  - `src/phases/balancing.rs` - Phase 1: Kitten merging
  - `src/phases/caterpillar.rs` - Phase 2: Z-algorithm periodic detection
  - `src/phases/diffbit.rs` - Phase 3: XOR priority merging
  - `src/tree/mod.rs` - ChonkerTree hierarchical structure
  - `src/tree/node.rs` - ChonkerNode with edit operations
  - `src/tree/persist.rs` - Tree serialization and storage
  - `src/dedup/mod.rs` - Deduplication module
  - `src/dedup/registry.rs` - ChunkRegistry with reference counting
  - `src/dedup/gc.rs` - Configurable garbage collection
  - `src/version/mod.rs` - Versioning module
  - `src/version/delta.rs` - Delta computation between versions
  - `src/version/timeline.rs` - Version timeline with commits/checkout
  - `src/simd.rs` - SIMD-accelerated kitten detection and priorities
- **Tests:** 99 unit tests passing
- **Key Features:**
  - Content-addressed chunks (BLAKE3)
  - Three-phase layer processing (Balancing, Caterpillar, Diffbit)
  - Edit locality guarantee (single byte edit affects ≤7 boundaries)
  - Configurable layer sizes with presets
  - **ChonkerTree**: Hierarchical chunk representation
  - **Tree diff**: Compute changes between versions
  - **Persistence**: MessagePack serialization, file/memory stores
  - **ChunkRegistry**: Reference-counted chunk storage with deduplication
  - **ChunkStore trait**: Pluggable storage backends (memory, custom)
  - **GarbageCollector**: Configurable GC with aggressive/conservative presets
  - **Delta**: Efficient diff between versions with byte/chunk stats
  - **VersionTimeline**: Git-like versioning with commits, refs, and history
  - **SIMD**: AVX2/NEON accelerated kitten detection and priority computation

### 10. Chonkers Integration with warp-store
- **Status:** DONE
- **Files:**
  - `crates/warp-store/Cargo.toml` - Added `chonkers` feature and `warp-chonkers` dependency
  - `crates/warp-store/src/backend/mod.rs` - Registered ChonkersBackend
  - `crates/warp-store/src/backend/chonkers.rs` - Full ChonkersBackend implementation
- **Features:**
  - `StorageBackend` trait implementation (get, put, delete, list, head, buckets, multipart)
  - Content-defined chunking with deduplication
  - Chunk caching and sharded filesystem storage
  - Reference counting for garbage collection
  - Integration with VersionTimeline for versioning support
- **Tests:** 5 integration tests passing
- **Usage:**
  ```rust
  use warp_store::backend::ChonkersBackend;

  // Create backend with default config
  let backend = ChonkersBackend::new(Path::new("/data/store")).await?;

  // Or with custom chunking config
  use warp_chonkers::ChonkersConfig;
  let config = ChonkersConfig::backup(); // Optimized for backups
  let backend = ChonkersBackend::with_config(path, config).await?;

  // Use standard StorageBackend API
  backend.create_bucket("my-bucket").await?;
  backend.put(&key, data, PutOptions::default()).await?;
  let data = backend.get(&key).await?;
  ```

### 11. OPRF Privacy-Preserving Protocols (warp-oprf)
- **Status:** DONE
- **Files:** `crates/warp-oprf/` (new crate)
  - `src/lib.rs` - Crate exports
  - `src/error.rs` - OprfError types
  - `src/suite.rs` - CipherSuite configuration
  - `src/oprf/` - Core OPRF client/server (Ristretto255)
  - `src/dedup/` - Blind deduplication (BlindDedupClient, BlindDedupServer)
  - `src/opaque/` - OPAQUE password-authenticated key exchange (RFC 9807)
  - `src/private_kdf/` - Private key derivation with server assistance
- **Libraries:** `curve25519-dalek` v4.1, `opaque-ke` v3.0 (optional)
- **Tests:** 40 unit tests passing
- **Key Features:**
  - **Core OPRF:** Diffie-Hellman based with Ristretto255 curve
    - Client blinds input: H(input)^r
    - Server evaluates: (H(input)^r)^k = H(input)^(rk)
    - Client unblinds: (H(input)^(rk))^(1/r) = H(input)^k
  - **BlindDedup:** Content-blind deduplication - server helps deduplicate without seeing hashes
  - **OPAQUE (types only):** Base types for password authentication (full protocol pending opaque-ke compatibility)
  - **PrivateKDF:** Derive keys with server assistance without revealing input
  - **Key rotation:** DedupKeyManager for managing multiple server keys
  - **Rate limiting:** RateLimitedKdfServer for dictionary attack prevention
  - **Zeroize:** All sensitive data zeroized on drop
- **Usage:**
  ```rust
  use warp_oprf::{Ristretto255Server, Ristretto255Client, OprfServerTrait, OprfClientTrait};

  // Server setup
  let server = Ristretto255Server::with_key_id("prod-key-v1")?;
  let public_key = server.public_key();

  // Client: blind input
  let client = Ristretto255Client::new(&public_key)?;
  let (blinded, state) = client.blind(b"secret-input")?;

  // Server: evaluate
  let evaluation = server.evaluate(&blinded)?;

  // Client: finalize (deterministic output for same input + server key)
  let output = client.finalize(state, &evaluation)?;
  ```

### 12. Blind Dedup Integration (warp-store + warp-oprf)
- **Status:** DONE
- **Files:**
  - `crates/warp-store/src/backend/blind_dedup.rs` - BlindDedupConfig, BlindDedupService trait, EmbeddedDedupService, SledDedupIndex
  - `crates/warp-store/src/backend/chonkers.rs` - Extended with `with_blind_dedup()` constructor and blind dedup chunk processing
  - `crates/warp-store/src/backend/mod.rs` - Module exports
  - `crates/warp-store/Cargo.toml` - Added `blind-dedup` feature
- **Tests:** 9 integration tests passing
- **Key Features:**
  - **Content-blind deduplication** - Server deduplicates without seeing content hashes
  - **Chunk-level OPRF** - Each chunk hash is blinded before dedup lookup
  - **Batch processing** - Multiple chunks processed in single OPRF round-trip
  - **Persistent index** - Sled-backed DedupIndex for cross-restart persistence
  - **Embedded service** - In-process OPRF server for simple deployments
- **Usage:**
  ```rust
  use warp_store::backend::{ChonkersBackend, BlindDedupConfig, EmbeddedDedupService};

  // Create embedded OPRF service
  let service = Arc::new(EmbeddedDedupService::new("dedup-key-v1")?);

  // Configure blind dedup with persistent index
  let config = BlindDedupConfig::new("dedup-key-v1")
      .with_index_path("/data/dedup-index");

  // Create backend with blind dedup
  let backend = ChonkersBackend::with_blind_dedup(
      "/data/store",
      ChonkersConfig::default(),
      config,
      service,
  ).await?;

  // Use normally - blind dedup happens transparently
  backend.put(&key, data, PutOptions::default()).await?;
  ```

### 13. WaLLoC Neural Compression (warp-neural)
- **Status:** DONE
- **Files:** `crates/warp-neural/` (new crate)
  - `src/lib.rs` - Crate exports and public API
  - `src/error.rs` - Neural-specific error types
  - `src/header.rs` - WLOC format (22-byte header)
  - `src/model/mod.rs` - Model management module
  - `src/model/presets.rs` - ModelPreset (Rgb16x, Stereo5x, Generic, Custom)
  - `src/model/session.rs` - SessionCache (thread-safe ONNX session management)
  - `src/detection/mod.rs` - Content detection module
  - `src/detection/classifier.rs` - ContentClassifier, ContentType, SuitabilityScore
  - `src/compressor/mod.rs` - Compressor module
  - `src/compressor/walloc.rs` - WallocCompressor (Wavelet Learned Lossy Compression)
  - `src/compressor/adaptive.rs` - AdaptiveNeuralCompressor (auto neural/lossless)
  - `src/compressor/batch.rs` - BatchNeuralCompressor (parallel processing)
- **Libraries:** `ort` v2.0.0-rc.10 (ONNX Runtime), `ndarray` v0.16
- **Tests:** 44 unit tests passing
- **Key Features:**
  - **WaLLoC Algorithm:** Wavelet transform → shallow autoencoder → entropy coding
    - 12-28× compression ratios (lossy) vs 2-4× (zstd lossless)
  - **Content Classification:** Entropy analysis, magic byte detection
    - ContentType: ImageLike, AudioLike, Scientific, Text, Incompressible, Unknown
  - **Model Presets:** Rgb16x (images), Stereo5x (audio), Generic, Custom
  - **ONNX Runtime:** GPU (CUDA) and CPU execution providers
  - **Adaptive Compression:** Auto-selects neural vs lossless based on content
  - **Fallback-safe:** Works without ONNX models (falls back to zstd)
  - **WLOC Header:** 22-byte format with magic, version, flags, sizes
- **Usage:**
  ```rust
  use warp_neural::{WallocCompressor, AdaptiveNeuralCompressor, QualityConfig};
  use warp_compress::Compressor;

  // Basic neural compression (with fallback)
  let compressor = WallocCompressor::fallback_only()?;
  let compressed = compressor.compress(&data)?;
  let restored = compressor.decompress(&compressed)?;

  // With quality settings
  let compressor = WallocCompressor::with_quality(QualityConfig::high_quality())?;

  // Adaptive mode (auto-selects neural vs lossless)
  let adaptive = AdaptiveNeuralCompressor::new()?;
  let compressed = adaptive.compress(&data)?;

  // Content classification
  use warp_neural::ContentClassifier;
  let classifier = ContentClassifier::new();
  let score = classifier.analyze(&data);
  println!("Content: {:?}, Neural suitable: {}",
      score.content_type, score.score);
  ```

### 14. DPU Offload (warp-dpu)
- **Status:** DONE
- **Files:** `crates/warp-dpu/` (new crate)
  - `src/lib.rs` - Crate exports and factory functions
  - `src/error.rs` - DPU-specific error types (DeviceInit, DocaOperation, RdmaError, etc.)
  - `src/backend.rs` - `DpuBackend` trait, `DpuInfo`, `DpuType`, `DpuBuffer`, `DpuWorkQueue`
  - `src/traits.rs` - Operation traits: `DpuOp`, `DpuHasher`, `DpuCipher`, `DpuCompressor`, `DpuErasureCoder`
  - `src/backends/stub.rs` - StubBackend for testing without hardware
  - `src/fallback.rs` - CPU fallback implementations
  - `benches/throughput.rs` - Criterion benchmarks
- **Scheduler Integration:** `crates/warp-sched/src/brain_link.rs`
  - `TransportType::DpuInline`, `TransportType::DpuRdma` - New transport types
  - `DpuType` enum - BlueField, Pensando, IntelIpu, None
  - `DpuCapabilities` struct - Inline crypto/compress/EC, RDMA, bandwidth
  - `EdgeNodeInfo` - Extended with `dpu_count`, `dpu_type`, `dpu_capabilities`
  - Placement scoring prefers DPU-capable edges
- **Libraries:** `blake3`, `chacha20poly1305`, `zstd`, `lz4_flex`, `reed-solomon-simd`
- **Tests:** 28 unit tests (warp-dpu) + 8 DPU tests (warp-sched)
- **Key Features:**
  - **Abstract Backend:** `DpuBackend` trait supporting multiple vendors
    - BlueField (NVIDIA), Pensando (AMD), Intel IPU
    - StubBackend for testing without hardware
  - **CPU Fallback:** Graceful degradation when DPU unavailable
    - `CpuHasher` - BLAKE3 hashing
    - `CpuCipher` - ChaCha20-Poly1305 AEAD
    - `CpuCompressor` - zstd/lz4 compression
    - `CpuErasureCoder` - Reed-Solomon erasure coding
  - **DPU-Aware Scheduling:** Scheduler prefers DPU-capable edges
    - +20 base bonus for DPU availability
    - +50 bonus for full DPU capabilities (crypto, compress, EC, RDMA)
    - +30 bonus when required transport matches DPU transport
  - **Inline Processing:** Zero-copy data processing on network path
- **Usage:**
  ```rust
  use warp_dpu::{get_hasher, get_cipher, get_compressor, get_erasure_coder};
  use warp_dpu::{DpuHasher, DpuCipher, DpuCompressor, DpuErasureCoder};

  // Get CPU fallback implementations (auto-selected when no DPU)
  let hasher = get_hasher();
  let cipher = get_cipher();
  let compressor = get_compressor();
  let erasure = get_erasure_coder(10, 4)?;

  // Hash data
  let hash = hasher.hash(b"data")?;

  // Encrypt/decrypt
  let key = [0u8; 32];
  let nonce = [0u8; 12];
  let encrypted = cipher.encrypt(b"plaintext", &key, &nonce)?;
  let decrypted = cipher.decrypt(&encrypted, &key, &nonce)?;

  // Compress/decompress
  let compressed = compressor.compress(b"data")?;
  let decompressed = compressor.decompress(&compressed)?;

  // Erasure encode/decode
  let shards = erasure.encode(b"data")?;
  let recovered = erasure.decode(&shards)?;
  ```

  ```rust
  // Scheduler integration
  use warp_sched::brain_link::{EdgeNodeInfo, DpuType, DpuCapabilities};

  let edge = EdgeNodeInfo::new(EdgeIdx(1), "dpu-node")
      .with_dpu(2, DpuType::BlueField, DpuCapabilities::bluefield3());

  // Edge now has DpuInline and DpuRdma transports
  // Scheduler will prefer this edge for transfers
  ```

---

## Architecture Reference

```
┌─────────────────────────────────────────────────────────────────┐
│                         warp-cli                                │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────────┐
│                        warp-core                                │
│              (Orchestration & Transfer Engine)                  │
└─────────────────────────────────────────────────────────────────┘
        │              │              │              │
┌───────┴───┐  ┌───────┴───┐  ┌───────┴───┐  ┌───────┴───┐
│warp-format│  │ warp-net  │  │warp-compress│ │ warp-hash │
│ (.warp)   │  │  (QUIC)   │  │(zstd/lz4)  │ │ (BLAKE3)  │
└───────────┘  └───────────┘  └────────────┘ └───────────┘
        │              │              │              │
┌───────┴──────────────┴──────────────┴──────────────┴───┐
│                       warp-io                          │
│            (Chunking, File I/O, Buffers)               │
└────────────────────────────────────────────────────────┘
                              │
┌──────────────┬──────────────┴──────────────┬───────────┐
│  warp-crypto │         warp-ec             │  warp-gpu │
│  (Encryption)│    (Erasure Coding)         │  (CUDA)   │
└──────────────┴─────────────────────────────┴───────────┘
                              │
      ┌───────────────────────┼───────────────────────┐
      │                       │                       │
┌─────┴─────────────┐ ┌───────┴───────┐ ┌─────────────┴─────┐
│   warp-chonkers   │ │  warp-neural  │ │     warp-oprf     │
│  (Versioned Dedup)│ │ (WaLLoC/ONNX) │ │(Privacy-Preserving)│
└───────────────────┘ └───────────────┘ └───────────────────┘
                              │
              ┌───────────────┴───────────────┐
              │           warp-dpu            │
              │  (DPU Offload: BlueField,     │
              │   Pensando, Intel IPU)        │
              └───────────────────────────────┘
```

---

## Key APIs

### warp-ec (Erasure Coding)
```rust
use warp_ec::{ErasureConfig, ErasureEncoder, ErasureDecoder};

// Create config
let config = ErasureConfig::new(10, 4)?;  // RS(10,4)
// Or use presets: rs_4_2(), rs_6_3(), rs_10_4(), rs_16_4()

// Encode
let encoder = ErasureEncoder::new(config.clone());
let shards: Vec<Vec<u8>> = encoder.encode(&data)?;

// Decode with missing shards
let mut received: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
received[0] = None;  // Simulate loss
let decoder = ErasureDecoder::new(config);
let recovered = decoder.decode(&received)?;
```

### SparseMerkleTree (Verification)
```rust
use warp_format::{SparseMerkleTree, WarpReader};

// Build from leaves
let tree = SparseMerkleTree::from_leaves(chunk_hashes);

// Generate proof for single chunk
let proof = tree.generate_proof(chunk_index);
assert!(proof.verify(&chunk_hash, &tree.root()));

// Via WarpReader
let reader = WarpReader::open_with_verification(path)?;
let valid = reader.verify_chunk_fast(index)?;
let (passed, total) = reader.verify_random_sample(100)?;
```

### Frame Codec (warp-net)
```rust
use warp_net::codec::Frame;
use bytes::{Bytes, BytesMut};

// Chunk frames use zero-copy Bytes
let frame = Frame::Chunk {
    chunk_id: 42,
    data: Bytes::from(vec![1, 2, 3]),
};

// Encode
let mut buf = BytesMut::new();
frame.encode(&mut buf)?;

// Decode
let decoded = Frame::decode(&mut buf)?;
```

### warp-oprf (Privacy-Preserving Protocols)
```rust
use warp_oprf::{Ristretto255Server, Ristretto255Client, OprfServerTrait, OprfClientTrait};
use warp_oprf::dedup::{BlindDedupClient, BlindDedupServer};

// Core OPRF flow
let server = Ristretto255Server::with_key_id("key-v1")?;
let client = Ristretto255Client::new(&server.public_key())?;

let (blinded, state) = client.blind(b"input")?;
let evaluation = server.evaluate(&blinded)?;
let output = client.finalize(state, &evaluation)?;

// Blind deduplication
let dedup_server = BlindDedupServer::new("dedup-key")?;
let dedup_client = BlindDedupClient::new(&dedup_server.public_key())?;

let content_hash = warp_hash::hash(&data);
let (request, state) = dedup_client.blind_hash(&content_hash)?;
let response = dedup_server.evaluate(&request)?;
let token = dedup_client.finalize(state, &response)?;

// Token is deterministic for same content + server key
// Use token to check dedup index without revealing content hash
```

### warp-chonkers (Versioned Dedup)
```rust
use warp_chonkers::{Chonkers, ChonkersConfig, Chunk, ChonkerTree};

// Create chunker with default config (3 layers: 4KB, 16KB, 64KB)
let config = ChonkersConfig::default();
let chunker = Chonkers::new(config.clone());

// Or use presets
let chunker = Chonkers::new(ChonkersConfig::backup());  // Optimized for backups

// Chunk data
let chunks: Vec<Chunk> = chunker.chunk(&data)?;

// Each chunk has content-addressed ID
for chunk in &chunks {
    println!("Chunk {}: {} bytes, ID: {}",
        chunk.index, chunk.length, chunk.id.short_hex());
}

// Build hierarchical tree for versioning
let tree1 = ChonkerTree::from_data(&data_v1, config.clone())?;
let tree2 = ChonkerTree::from_data(&data_v2, config)?;

// Compute diff between versions
let diff = tree1.diff(&tree2);
println!("Added: {}, Removed: {}, Unchanged: {}",
    diff.added.len(), diff.removed.len(), diff.unchanged.len());
println!("Dedup ratio: {:.1}%", diff.dedup_ratio() * 100.0);
```

---

## Test Commands

```bash
# Run all tests
cargo test --workspace

# Run specific crate tests
cargo test -p warp-ec
cargo test -p warp-format
cargo test -p warp-net
cargo test -p warp-chonkers
cargo test -p warp-oprf
cargo test -p warp-neural
cargo test -p warp-dpu

# Run scheduler with DPU feature
cargo test -p warp-sched --features dpu

# Run blind dedup integration tests
cargo test -p warp-store --features "chonkers,blind-dedup" blind_dedup

# Run benchmarks
cargo bench -p warp-ec
cargo bench -p warp-dpu

# Build in release mode
cargo build --release
```

---

## Git Status

Last commit: `5fcf1c3` - feat(warp-dpu): Add DPU offload crate with scheduler integration

All changes pushed to `origin/main`.

---

## Research Plan Reference

Full research plan with additional options is at:
`~/.claude/plans/sprightly-imagining-wall.md`

All planned features have been implemented (14 total).
