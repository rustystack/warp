# Changelog

All notable changes to Warp will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2024-XX-XX

### Added

#### Core Features
- Content-defined chunking with Buzhash rolling hash
- Zstd and LZ4 compression with automatic selection
- BLAKE3 hashing with parallel processing via rayon
- ChaCha20-Poly1305 AEAD encryption
- Ed25519 digital signatures
- Argon2 password-based key derivation
- Merkle tree integrity verification

#### Archive Format
- Native `.warp` archive format
- Memory-mapped reading for zero-copy access
- Streaming write support
- Directory tree preservation
- File metadata (permissions, timestamps)

#### Networking
- QUIC transport with TLS 1.3
- Multiplexed streams
- Connection resumption
- Protocol frame codec (Hello, Capabilities, Plan, Chunk, Ack, Nack, Verify)

#### Transfer Features
- Multi-source parallel downloads
- Transfer scheduling with bandwidth allocation
- Session persistence and resume
- Progress tracking with ETA
- Automatic retry on failure

#### GPU Acceleration
- nvCOMP integration for parallel compression
- CUDA kernel optimization framework
- Automatic GPU detection and fallback

#### Portal System
- Zero-knowledge encryption
- P2P mesh networking
- Edge node federation
- Hub-based relay

#### Observability
- Structured logging with tracing
- Metrics collection
- Telemetry spans for performance analysis

#### CLI
- `warp send` - Send files to remote
- `warp fetch` - Fetch files from remote
- `warp listen` - Start receiver daemon
- `warp plan` - Analyze transfer before execution

### Security
- Constant-time cryptographic operations
- Secure key derivation
- Input validation
- No unsafe code in critical paths

## [Unreleased]

### Added
- **SeqCDC Algorithm**: High-performance content-defined chunking replacing Buzhash
  - 100x faster than legacy Buzhash (31 GB/s vs 300 MB/s)
  - Monotonic sequence detection for boundary finding
  - Content-based skipping for unfavorable regions
- **SIMD Acceleration**: Platform-optimized vectorization
  - ARM NEON (128-bit): 12-31 GB/s on Apple Silicon
  - x86_64 AVX2 (256-bit): 15-20 GB/s
  - x86_64 AVX-512 (512-bit): 30+ GB/s
  - Automatic runtime detection and dispatch
- **Backward Compatibility**: Legacy `BuzhashChunker` still available
- **Comprehensive Benchmarks**: Criterion benchmarks for all chunking variants

### Changed
- Default chunker now uses SeqCDC instead of Buzhash
- `Chunker` type alias points to `SeqCdcChunker`
- Updated warp-io documentation with new algorithm details

### Planned
- WebSocket transport fallback
- Browser-based transfers
- Cloud storage backends
- Incremental sync
