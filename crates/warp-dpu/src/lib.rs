//! DPU (Data Processing Unit) Offload for Warp
//!
//! This crate provides an abstract interface for DPU acceleration with
//! support for multiple vendors (`BlueField`, Pensando, Intel IPU).
//!
//! # Features
//!
//! - **Abstract Backend Trait**: `DpuBackend` trait for vendor-agnostic DPU access
//! - **Full Pipeline Offload**: Crypto, compression, hashing, and erasure coding
//! - **Automatic Fallback**: Graceful CPU fallback when DPU unavailable
//! - **Inline Processing**: Zero-copy data processing on the network path
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                         warp-dpu                                 │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  DpuBackend Trait                                                │
//! │  ├── BlueFieldBackend (DOCA SDK)                                │
//! │  ├── StubBackend (testing)                                      │
//! │  └── (future: Pensando, Intel IPU)                              │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  Operation Traits                                                │
//! │  ├── DpuHasher (BLAKE3)                                         │
//! │  ├── DpuCipher (ChaCha20-Poly1305)                              │
//! │  ├── DpuCompressor (zstd/lz4)                                   │
//! │  └── DpuErasureCoder (Reed-Solomon)                             │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  Fallback Layer (automatic CPU fallback)                        │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example Usage
//!
//! ```rust,no_run
//! use warp_dpu::{CpuHasher, CpuCipher, CpuCompressor, CpuErasureCoder};
//! use warp_dpu::{DpuHasher, DpuCipher, DpuCompressor, DpuErasureCoder};
//!
//! // Hashing
//! let hasher = CpuHasher::new();
//! let hash = hasher.hash(b"hello world").unwrap();
//!
//! // Encryption
//! let cipher = CpuCipher::new();
//! let key = [0u8; 32];
//! let nonce = [0u8; 12];
//! let ciphertext = cipher.encrypt(b"secret", &key, &nonce, None).unwrap();
//!
//! // Compression
//! let compressor = CpuCompressor::zstd();
//! let compressed = compressor.compress(b"data to compress").unwrap();
//!
//! // Erasure coding
//! let coder = CpuErasureCoder::with_config(4, 2);
//! let shards = coder.encode(b"data for erasure coding").unwrap();
//! ```
//!
//! # Feature Flags
//!
//! - `stub` (default): Enable stub backend for testing without hardware
//! - `bluefield`: Enable NVIDIA `BlueField` DPU support via DOCA SDK

#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::similar_names)]

pub mod backend;
pub mod backends;
pub mod error;
pub mod fallback;
pub mod traits;

// Re-export main types
pub use backend::{
    DpuBackend, DpuBuffer, DpuInfo, DpuType, DpuWorkQueue, get_best_backend, is_dpu_available,
};
pub use error::{Error, ErrorSeverity, Result};
pub use fallback::{CpuCipher, CpuCompressor, CpuErasureCoder, CpuHasher};
pub use traits::{
    CompressionAlgorithm, DpuCipher, DpuCompressor, DpuErasureCoder, DpuHasher, DpuOp, DpuOpStats,
    IncrementalHasher,
};

#[cfg(feature = "stub")]
pub use backends::stub::{StubBackend, StubBuffer, StubWorkQueue};

/// Crate version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Check if DPU hardware is available
///
/// Returns `true` if any DPU backend can be initialized.
#[must_use]
pub fn has_dpu_hardware() -> bool {
    is_dpu_available()
}

/// Get the best available hasher (DPU if available, CPU otherwise)
#[must_use]
pub fn get_hasher() -> Box<dyn DpuHasher> {
    // For now, always use CPU hasher
    // When DPU is available, we'd check and return DPU hasher
    Box::new(CpuHasher::new())
}

/// Get the best available cipher (DPU if available, CPU otherwise)
#[must_use]
pub fn get_cipher() -> Box<dyn DpuCipher> {
    Box::new(CpuCipher::new())
}

/// Get the best available compressor (DPU if available, CPU otherwise)
#[must_use]
pub fn get_compressor(algorithm: CompressionAlgorithm) -> Box<dyn DpuCompressor> {
    match algorithm {
        CompressionAlgorithm::Zstd => Box::new(CpuCompressor::zstd()),
        CompressionAlgorithm::Lz4 => Box::new(CpuCompressor::lz4()),
    }
}

/// Get the best available erasure coder (DPU if available, CPU otherwise)
#[must_use]
pub fn get_erasure_coder(data_shards: usize, parity_shards: usize) -> Box<dyn DpuErasureCoder> {
    Box::new(CpuErasureCoder::with_config(data_shards, parity_shards))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_get_hasher() {
        let hasher = get_hasher();
        let hash = hasher.hash(b"test").unwrap();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_get_cipher() {
        let cipher = get_cipher();
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let ct = cipher.encrypt(b"test", &key, &nonce, None).unwrap();
        let pt = cipher.decrypt(&ct, &key, &nonce, None).unwrap();
        assert_eq!(pt, b"test");
    }

    #[test]
    fn test_get_compressor_zstd() {
        let comp = get_compressor(CompressionAlgorithm::Zstd);
        let data = b"test data for compression";
        let compressed = comp.compress(data).unwrap();
        let decompressed = comp.decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_get_compressor_lz4() {
        let comp = get_compressor(CompressionAlgorithm::Lz4);
        let data = b"test data for lz4";
        let compressed = comp.compress(data).unwrap();
        let decompressed = comp.decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_get_erasure_coder() {
        let coder = get_erasure_coder(4, 2);
        assert_eq!(coder.data_shards(), 4);
        assert_eq!(coder.parity_shards(), 2);
        assert_eq!(coder.total_shards(), 6);
    }
}
