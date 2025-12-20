# Contributing to Warp

Thank you for your interest in contributing to Warp! This document provides guidelines and instructions for contributing.

## Development Setup

### Prerequisites

- Rust 1.85+ (edition 2024)
- CUDA toolkit (optional, for GPU acceleration)

### Building

```bash
# Clone the repository
git clone https://github.com/yourusername/warp.git
cd warp

# Build all crates
cargo build --workspace

# Run tests
cargo test --workspace

# Run with release optimizations
cargo build --release
```

### Running Examples

```bash
# Basic chunking demo
cargo run -p warp-core --example basic_chunking

# Full pipeline demo
cargo run -p warp-core --example full_pipeline --release

# Archive creation demo
cargo run -p warp-core --example archive_roundtrip
```

## Project Structure

```
warp/
├── crates/
│   ├── warp-cli/        # Command-line interface
│   ├── warp-core/       # Core orchestration
│   ├── warp-format/     # .warp archive format
│   ├── warp-net/        # QUIC networking
│   ├── warp-compress/   # Zstd/LZ4 compression
│   ├── warp-hash/       # BLAKE3 hashing
│   ├── warp-crypto/     # ChaCha20/Ed25519 crypto
│   ├── warp-io/         # Chunking and I/O
│   ├── warp-gpu/        # GPU acceleration
│   ├── warp-sched/      # Transfer scheduling
│   ├── warp-orch/       # Multi-source orchestration
│   ├── portal-*/        # Portal subsystem
│   └── ...
└── examples/            # Usage examples
```

## Code Guidelines

### Style

- Follow Rust idioms and best practices
- Use `rustfmt` for formatting: `cargo fmt`
- Use `clippy` for linting: `cargo clippy --workspace`
- Keep functions focused and well-documented
- Write tests for new functionality

### Documentation

- Add doc comments to public APIs
- Include examples in documentation where helpful
- Update README.md for user-facing changes

### Commits

- Write clear, descriptive commit messages
- Keep commits focused on a single change
- Reference issues in commit messages when applicable

## Testing

```bash
# Run all tests
cargo test --workspace

# Run specific crate tests
cargo test -p warp-core

# Run with output
cargo test --workspace -- --nocapture

# Run stress tests
cargo test -p warp-format --test stress --release -- --nocapture
```

## Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `cargo test --workspace`
5. Run lints: `cargo clippy --workspace`
6. Format code: `cargo fmt`
7. Push and create a pull request

## Reporting Issues

When reporting issues, please include:

- Rust version (`rustc --version`)
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs or error messages

## License

By contributing to Warp, you agree that your contributions will be licensed under the MIT OR Apache-2.0 license.
