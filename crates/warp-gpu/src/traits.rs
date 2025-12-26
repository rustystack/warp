//! Traits for GPU-accelerated operations
//!
//! This module defines abstract interfaces for GPU operations that can be
//! implemented by higher-level crates (warp-hash, warp-crypto, warp-compress).
//! Each trait supports both GPU and CPU fallback implementations.

use crate::Result;
use rayon::prelude::*;

#[cfg(feature = "cuda")]
use crate::GpuContext;
#[cfg(feature = "cuda")]
use std::sync::Arc;

/// Base trait for GPU-accelerated operations
///
/// This trait provides common functionality for all GPU operations:
/// - Context management
/// - Size thresholds for GPU vs CPU
/// - Capability queries
#[cfg(feature = "cuda")]
pub trait GpuOp: Send + Sync {
    /// Get the GPU context
    fn context(&self) -> &Arc<GpuContext>;

    /// Get minimum size for GPU acceleration (bytes)
    ///
    /// Data smaller than this threshold should use CPU to avoid
    /// GPU transfer overhead.
    fn min_gpu_size(&self) -> usize {
        64 * 1024 // 64KB default
    }

    /// Check if input should use GPU based on size
    fn should_use_gpu(&self, input_size: usize) -> bool {
        input_size >= self.min_gpu_size()
            && self.context().has_sufficient_memory(input_size * 3)
    }

    /// Get operation name for logging/metrics
    fn name(&self) -> &'static str;
}

/// Base trait for GPU-accelerated operations (non-CUDA version)
#[cfg(not(feature = "cuda"))]
pub trait GpuOp: Send + Sync {
    /// Get minimum size for GPU acceleration (bytes)
    fn min_gpu_size(&self) -> usize {
        64 * 1024 // 64KB default
    }

    /// Check if input should use GPU based on size
    fn should_use_gpu(&self, input_size: usize) -> bool {
        input_size >= self.min_gpu_size()
    }

    /// Get operation name for logging/metrics
    fn name(&self) -> &'static str;
}

/// GPU-accelerated hashing operations
///
/// Implementations provide GPU kernels for cryptographic hash functions
/// like BLAKE3, SHA-256, etc. with automatic CPU fallback.
pub trait GpuHasher: GpuOp {
    /// Hash single input buffer
    ///
    /// # Arguments
    /// * `input` - Data to hash
    ///
    /// # Returns
    /// Hash digest (size depends on algorithm)
    fn hash(&self, input: &[u8]) -> Result<Vec<u8>>;

    /// Hash multiple buffers in batch
    ///
    /// This is more efficient than calling `hash` repeatedly as it
    /// batches GPU transfers and kernel launches.
    ///
    /// # Arguments
    /// * `inputs` - Slice of input buffers
    ///
    /// # Returns
    /// Vector of hash digests in same order as inputs
    fn hash_batch(&self, inputs: &[&[u8]]) -> Result<Vec<Vec<u8>>> {
        // Default implementation: hash in parallel using Rayon
        inputs.par_iter().map(|input| self.hash(input)).collect()
    }

    /// Get hash output size in bytes
    fn digest_size(&self) -> usize;

    /// Algorithm name (e.g., "blake3", "sha256")
    fn algorithm(&self) -> &'static str;
}

/// GPU-accelerated encryption/decryption operations
///
/// Implementations provide GPU kernels for symmetric ciphers like
/// ChaCha20-Poly1305, AES-GCM, etc. with automatic CPU fallback.
pub trait GpuCipher: GpuOp {
    /// Encrypt plaintext
    ///
    /// # Arguments
    /// * `plaintext` - Data to encrypt
    /// * `key` - Encryption key
    /// * `nonce` - Nonce/IV (size depends on algorithm)
    /// * `associated_data` - Optional AAD for AEAD ciphers
    ///
    /// # Returns
    /// Ciphertext (may include authentication tag)
    fn encrypt(
        &self,
        plaintext: &[u8],
        key: &[u8],
        nonce: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>>;

    /// Decrypt ciphertext
    ///
    /// # Arguments
    /// * `ciphertext` - Data to decrypt
    /// * `key` - Decryption key
    /// * `nonce` - Nonce/IV (size depends on algorithm)
    /// * `associated_data` - Optional AAD for AEAD ciphers
    ///
    /// # Returns
    /// Plaintext, or error if authentication fails
    fn decrypt(
        &self,
        ciphertext: &[u8],
        key: &[u8],
        nonce: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>>;

    /// Encrypt multiple plaintexts in batch
    ///
    /// # Arguments
    /// * `plaintexts` - Slice of input buffers
    /// * `key` - Shared encryption key
    /// * `nonces` - Nonce for each plaintext (must be unique!)
    /// * `associated_data` - Optional AAD (same for all)
    ///
    /// # Returns
    /// Vector of ciphertexts in same order
    fn encrypt_batch(
        &self,
        plaintexts: &[&[u8]],
        key: &[u8],
        nonces: &[&[u8]],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<Vec<u8>>> {
        if plaintexts.len() != nonces.len() {
            return Err(crate::Error::InvalidOperation(
                "Plaintext and nonce counts must match".into(),
            ));
        }

        plaintexts
            .par_iter()
            .zip(nonces.par_iter())
            .map(|(pt, nonce)| self.encrypt(pt, key, nonce, associated_data))
            .collect()
    }

    /// Decrypt multiple ciphertexts in batch
    fn decrypt_batch(
        &self,
        ciphertexts: &[&[u8]],
        key: &[u8],
        nonces: &[&[u8]],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<Vec<u8>>> {
        if ciphertexts.len() != nonces.len() {
            return Err(crate::Error::InvalidOperation(
                "Ciphertext and nonce counts must match".into(),
            ));
        }

        ciphertexts
            .par_iter()
            .zip(nonces.par_iter())
            .map(|(ct, nonce)| self.decrypt(ct, key, nonce, associated_data))
            .collect()
    }

    /// Algorithm name (e.g., "chacha20poly1305", "aes256gcm")
    fn algorithm(&self) -> &'static str;

    /// Key size in bytes
    fn key_size(&self) -> usize;

    /// Nonce size in bytes
    fn nonce_size(&self) -> usize;

    /// Tag size in bytes (for AEAD ciphers)
    fn tag_size(&self) -> usize {
        0 // Not AEAD by default
    }
}

/// GPU-accelerated compression operations
///
/// Implementations provide GPU kernels for compression algorithms like
/// LZ4, Zstd, etc. with automatic CPU fallback.
pub trait GpuCompressor: GpuOp {
    /// Compress data
    ///
    /// # Arguments
    /// * `input` - Data to compress
    ///
    /// # Returns
    /// Compressed data
    fn compress(&self, input: &[u8]) -> Result<Vec<u8>>;

    /// Decompress data
    ///
    /// # Arguments
    /// * `input` - Compressed data
    ///
    /// # Returns
    /// Decompressed data
    fn decompress(&self, input: &[u8]) -> Result<Vec<u8>>;

    /// Compress multiple chunks in batch
    ///
    /// # Arguments
    /// * `inputs` - Slice of input buffers
    ///
    /// # Returns
    /// Vector of compressed buffers in same order
    fn compress_batch(&self, inputs: &[&[u8]]) -> Result<Vec<Vec<u8>>> {
        inputs.par_iter().map(|input| self.compress(input)).collect()
    }

    /// Decompress multiple chunks in batch
    fn decompress_batch(&self, inputs: &[&[u8]]) -> Result<Vec<Vec<u8>>> {
        inputs.par_iter().map(|input| self.decompress(input)).collect()
    }

    /// Algorithm name (e.g., "lz4", "zstd")
    fn algorithm(&self) -> &'static str;

    /// Get compression level (if applicable)
    fn level(&self) -> Option<i32> {
        None
    }
}

/// Statistics for GPU operations
#[derive(Debug, Default, Clone)]
pub struct GpuOpStats {
    /// Total operations performed
    pub total_ops: u64,
    /// Operations processed on GPU
    pub gpu_ops: u64,
    /// Operations processed on CPU (fallback)
    pub cpu_ops: u64,
    /// Total bytes processed
    pub total_bytes: u64,
    /// Total GPU time (nanoseconds)
    pub gpu_time_ns: u64,
    /// Total CPU time (nanoseconds)
    pub cpu_time_ns: u64,
}

impl GpuOpStats {
    /// Get GPU utilization as percentage
    pub fn gpu_utilization(&self) -> f64 {
        if self.total_ops == 0 {
            0.0
        } else {
            (self.gpu_ops as f64 / self.total_ops as f64) * 100.0
        }
    }

    /// Get average throughput (bytes/second)
    pub fn throughput_bps(&self) -> f64 {
        let total_time_ns = self.gpu_time_ns + self.cpu_time_ns;
        if total_time_ns == 0 {
            0.0
        } else {
            (self.total_bytes as f64 / total_time_ns as f64) * 1_000_000_000.0
        }
    }

    /// Get throughput in GB/s
    pub fn throughput_gbps(&self) -> f64 {
        self.throughput_bps() / (1024.0 * 1024.0 * 1024.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gpu_op_stats() {
        let mut stats = GpuOpStats::default();
        stats.total_ops = 100;
        stats.gpu_ops = 75;
        stats.cpu_ops = 25;
        stats.total_bytes = 1024 * 1024 * 100; // 100MB
        stats.gpu_time_ns = 1_000_000; // 1ms

        assert_eq!(stats.gpu_utilization(), 75.0);

        let throughput = stats.throughput_gbps();
        assert!(throughput > 0.0);
    }

    #[test]
    fn test_stats_defaults() {
        let stats = GpuOpStats::default();
        assert_eq!(stats.gpu_utilization(), 0.0);
        assert_eq!(stats.throughput_bps(), 0.0);
    }
}
