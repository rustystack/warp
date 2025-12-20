# warp

> GPU-accelerated bulk data transfer with adaptive compression, deduplication, and Merkle verification

## Features

- **GPU Acceleration**: nvCOMP integration for parallel compression/decompression
- **Ultra-Fast Chunking**: SeqCDC algorithm with SIMD acceleration (30+ GB/s)
- **QUIC Transport**: Modern, multiplexed transport with built-in encryption
- **Merkle Verification**: Cryptographic integrity with incremental verification
- **Adaptive Compression**: Per-chunk algorithm selection based on entropy analysis
- **Resume Support**: Interrupted transfers continue from last verified chunk
- **Cross-Platform SIMD**: AVX2/AVX-512 on x86_64, NEON on ARM (Apple Silicon)

## Installation

```bash
cargo install warp-cli
```

## Quick Start

```bash
# Send data to a remote server
warp send ./data server:/archive

# Receive data
warp fetch server:/archive ./local

# Start a listener daemon
warp listen --port 9999

# Analyze transfer before executing
warp plan ./data server:/dest
```

## Examples

Run the included examples to explore warp's capabilities:

```bash
# Basic content-defined chunking
cargo run -p warp-core --example basic_chunking

# Compression and encryption pipeline
cargo run -p warp-core --example compress_encrypt

# Full pipeline (chunk → compress → encrypt → hash)
cargo run -p warp-core --example full_pipeline --release

# Archive creation and extraction
cargo run -p warp-core --example archive_roundtrip

# Parallel BLAKE3 hashing
cargo run -p warp-core --example parallel_hashing --release
```

## Performance

Benchmarks on modern hardware (release build):

| Operation | Throughput | Notes |
|-----------|------------|-------|
| **Chunking (SeqCDC SIMD)** | **31 GB/s** | ARM NEON / AVX-512 |
| Chunking (SeqCDC scalar) | 1-2 GB/s | Fallback |
| Chunking (Buzhash legacy) | 300 MB/s | For compatibility |
| Compression (Zstd) | 4,587 MB/s | |
| Encryption (ChaCha20-Poly1305) | 528 MB/s | |
| Hashing (BLAKE3) | 1,761 MB/s | |
| Full Pipeline | 500+ MB/s | With SeqCDC |

### Chunking Algorithm Comparison

| Algorithm | 10MB | 100MB | vs Buzhash |
|-----------|------|-------|------------|
| Buzhash (legacy) | 300 MiB/s | 300 MiB/s | baseline |
| SeqCDC Scalar | 255 MiB/s | 750 MiB/s | 2.5x |
| **SeqCDC SIMD** | **12.5 GiB/s** | **31 GiB/s** | **100x** |

*Tested on Apple M4 Pro with ARM NEON. x86_64 with AVX-512 achieves similar results.*

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         warp-cli                                │
│                    (User Interface)                             │
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
┌─────────────────────────────────────────────────────────────────┐
│                       warp-crypto                               │
│              (ChaCha20, Ed25519, Key Derivation)                │
└─────────────────────────────────────────────────────────────────┘
```

## Crates

| Crate | Description |
|-------|-------------|
| `warp-cli` | Command-line interface |
| `warp-core` | Core orchestration and transfer engine |
| `warp-format` | Native `.warp` archive format |
| `warp-net` | QUIC networking with TLS 1.3 |
| `warp-compress` | Zstd/LZ4 compression |
| `warp-hash` | BLAKE3 hashing with parallelism |
| `warp-crypto` | ChaCha20/Ed25519/Argon2 cryptography |
| `warp-io` | SeqCDC chunking (31 GB/s), file I/O, SIMD acceleration |
| `warp-gpu` | GPU acceleration via nvCOMP |
| `warp-sched` | Transfer scheduling |
| `warp-orch` | Multi-source orchestration |
| `portal-*` | Zero-knowledge portal system |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
