//! warp-ec: Reed-Solomon erasure coding for fault-tolerant data transfer
//!
//! This crate provides Reed-Solomon erasure coding capabilities for warp,
//! enabling fault-tolerant data transfer that can survive node failures.
//!
//! # Overview
//!
//! Erasure coding splits data into `k` data shards and generates `m` parity
//! shards. The original data can be reconstructed from any `k` of the `k+m`
//! total shards.
//!
//! # Example
//!
//! ```
//! use warp_ec::{ErasureEncoder, ErasureDecoder, ErasureConfig};
//!
//! // Configure RS(10,4): 10 data shards, 4 parity shards
//! let config = ErasureConfig::new(10, 4).unwrap();
//!
//! // Encode data
//! let data = vec![0u8; 10240]; // Must be divisible by data_shards
//! let encoder = ErasureEncoder::new(config.clone());
//! let shards = encoder.encode(&data).unwrap();
//!
//! // Simulate losing 4 shards (indices 2, 5, 8, 11)
//! let mut received: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
//! received[2] = None;
//! received[5] = None;
//! received[8] = None;
//! received[11] = None;
//!
//! // Decode - still works with 4 missing shards!
//! let decoder = ErasureDecoder::new(config);
//! let recovered = decoder.decode(&received).unwrap();
//! assert_eq!(recovered, data);
//! ```
//!
//! # Performance
//!
//! This crate uses SIMD-optimized Reed-Solomon coding via `reed-solomon-simd`:
//! - AVX2 on x86-64
//! - SSSE3 fallback on older x86-64
//! - NEON on ARM64
//! - Pure Rust fallback on other platforms
//!
//! # Common Configurations
//!
//! | Config | Data | Parity | Overhead | Fault Tolerance |
//! |--------|------|--------|----------|-----------------|
//! | RS(4,2) | 4 | 2 | 50% | 2 failures |
//! | RS(6,3) | 6 | 3 | 50% | 3 failures |
//! | RS(10,4) | 10 | 4 | 40% | 4 failures |
//! | RS(16,4) | 16 | 4 | 25% | 4 failures |

#![warn(missing_docs)]
#![allow(clippy::needless_range_loop)]

mod config;
mod decoder;
mod encoder;
mod error;
mod shard;

pub use config::ErasureConfig;
pub use decoder::ErasureDecoder;
pub use encoder::ErasureEncoder;
pub use error::{Error, Result};
pub use shard::{Shard, ShardId, ShardType};

/// Convenience function to encode data with default RS(10,4) configuration
///
/// # Arguments
/// * `data` - Data to encode (length must be divisible by 10)
///
/// # Returns
/// A vector of 14 shards (10 data + 4 parity)
pub fn encode_default(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let config = ErasureConfig::new(10, 4)?;
    let encoder = ErasureEncoder::new(config);
    encoder.encode(data)
}

/// Convenience function to decode shards with default RS(10,4) configuration
///
/// # Arguments
/// * `shards` - Vector of optional shards (None for missing)
///
/// # Returns
/// The reconstructed original data
pub fn decode_default(shards: &[Option<Vec<u8>>]) -> Result<Vec<u8>> {
    let config = ErasureConfig::new(10, 4)?;
    let decoder = ErasureDecoder::new(config);
    decoder.decode(shards)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let config = ErasureConfig::new(4, 2).unwrap();
        let encoder = ErasureEncoder::new(config.clone());
        let decoder = ErasureDecoder::new(config);

        // Data must be divisible by data_shards (4)
        let data: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();

        let shards = encoder.encode(&data).unwrap();
        assert_eq!(shards.len(), 6); // 4 data + 2 parity

        // All shards present
        let received: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        let recovered = decoder.decode(&received).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn test_recover_from_failures() {
        let config = ErasureConfig::new(4, 2).unwrap();
        let encoder = ErasureEncoder::new(config.clone());
        let decoder = ErasureDecoder::new(config);

        let data: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
        let shards = encoder.encode(&data).unwrap();

        // Lose 2 shards (the maximum we can tolerate)
        let mut received: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        received[1] = None; // Lose data shard 1
        received[4] = None; // Lose parity shard 0

        let recovered = decoder.decode(&received).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn test_too_many_failures() {
        let config = ErasureConfig::new(4, 2).unwrap();
        let encoder = ErasureEncoder::new(config.clone());
        let decoder = ErasureDecoder::new(config);

        let data: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
        let shards = encoder.encode(&data).unwrap();

        // Lose 3 shards (more than parity count)
        let mut received: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        received[0] = None;
        received[1] = None;
        received[2] = None;

        let result = decoder.decode(&received);
        assert!(result.is_err());
    }

    #[test]
    fn test_default_functions() {
        // Data must be divisible by 10 for default config
        let data: Vec<u8> = (0..10240).map(|i| (i % 256) as u8).collect();

        let shards = encode_default(&data).unwrap();
        assert_eq!(shards.len(), 14); // 10 data + 4 parity

        let received: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        let recovered = decode_default(&received).unwrap();
        assert_eq!(recovered, data);
    }
}
