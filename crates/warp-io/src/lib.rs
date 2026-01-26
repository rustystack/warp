//! warp-io: High-performance I/O utilities
//!
//! - Content-defined chunking (SeqCDC with SIMD - up to 31 GB/s)
//! - Fixed-size chunking for streaming
//! - Async chunking with tokio
//! - Directory walking (sync and async)
//! - Memory-mapped I/O
//! - Buffer pools
//!
//! # Chunking Algorithms
//!
//! This crate provides two content-defined chunking algorithms:
//!
//! - **SeqCDC** (default): High-performance monotonic sequence detection.
//!   - ARM NEON: 12-31 GB/s (Apple Silicon M1/M2/M3/M4)
//!   - x86_64 AVX-512: 30+ GB/s
//!   - x86_64 AVX2: 15-20 GB/s
//!   - Scalar fallback: 1-2 GB/s
//!
//! - **Buzhash**: Traditional rolling hash algorithm (~300 MB/s).
//!   Available via `BuzhashChunker` for backward compatibility.
//!
//! # Example
//!
//! ```rust,ignore
//! use warp_io::{Chunker, SeqCdcConfig};
//! use std::io::Cursor;
//!
//! // SeqCDC with SIMD (default, ultra-fast)
//! let chunker = Chunker::new(SeqCdcConfig::target_16kb());
//! let data = vec![0u8; 1024 * 1024]; // 1MB
//! let chunks = chunker.chunk_simd(Cursor::new(&data)).unwrap();
//!
//! // Buzhash (legacy, for compatibility)
//! use warp_io::BuzhashChunker;
//! let legacy = BuzhashChunker::default();
//! ```
//!
//! # SIMD Support
//!
//! The `simd` module provides platform-optimized implementations:
//! - `simd::neon` - ARM NEON (aarch64)
//! - `simd::avx2` - Intel/AMD AVX2 (x86_64)
//! - `simd::avx512` - Intel AVX-512 (x86_64)
//!
//! Runtime detection automatically selects the best available implementation.

#![warn(missing_docs)]
#![allow(clippy::unnecessary_to_owned)]
#![allow(dead_code)]

pub mod async_chunker;
pub mod async_walker;
pub mod chunker;
pub mod fixed_chunker;
pub mod mmap;
pub mod pool;
pub mod simd;
#[cfg(all(target_os = "linux", feature = "io-uring"))]
pub mod uring;
pub mod walker;

// SeqCDC (new, high-performance)
pub use chunker::{SeqCdcChunker, SeqCdcConfig, SeqMode};

// Buzhash (legacy, for backward compatibility)
pub use chunker::{BuzhashChunker, ChunkerConfig};

// Default Chunker alias (points to SeqCDC)
pub use chunker::Chunker;

pub use async_chunker::{chunk_file_async, chunk_file_stream};
pub use async_walker::{walk_directory_async, walk_directory_stream};
pub use fixed_chunker::FixedChunker;
pub use walker::{FileEntry, walk_directory};

// io_uring support (Linux only, feature-gated)
#[cfg(all(target_os = "linux", feature = "io-uring"))]
pub use uring::{
    IoUringAsyncReader, IoUringBackend, IoUringChunker, IoUringConfig, IoUringStats,
    RegisteredBuffer, RegisteredBufferPool, chunk_file_uring, is_available as uring_available,
};

/// I/O error types
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Walk error
    #[error("Walk error: {0}")]
    Walk(#[from] walkdir::Error),
}

/// Result type for I/O operations
pub type Result<T> = std::result::Result<T, Error>;
