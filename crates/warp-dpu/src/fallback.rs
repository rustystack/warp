//! CPU Fallback Implementations
//!
//! Provides CPU implementations of all DPU operations.
//! Used as fallback when DPU hardware is not available.

use crate::backend::{DpuBuffer, DpuType};
use crate::error::{Error, Result};
use crate::traits::{
    CompressionAlgorithm, DpuCipher, DpuCompressor, DpuErasureCoder, DpuHasher, DpuOp, DpuOpStats,
    IncrementalHasher,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

// ============================================================================
// CPU Hasher (BLAKE3)
// ============================================================================

/// CPU-based BLAKE3 hasher
#[derive(Debug)]
pub struct CpuHasher {
    stats: Arc<HasherStats>,
}

#[derive(Debug, Default)]
struct HasherStats {
    total_ops: AtomicU64,
    total_bytes: AtomicU64,
}

impl CpuHasher {
    /// Create a new CPU hasher
    #[must_use]
    pub fn new() -> Self {
        Self {
            stats: Arc::new(HasherStats::default()),
        }
    }
}

impl Default for CpuHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl DpuOp for CpuHasher {
    fn is_dpu_available(&self) -> bool {
        false
    }

    fn name(&self) -> &'static str {
        "cpu_hasher"
    }

    fn backend(&self) -> DpuType {
        DpuType::Cpu
    }

    fn stats(&self) -> DpuOpStats {
        DpuOpStats {
            total_ops: self.stats.total_ops.load(Ordering::Relaxed),
            cpu_ops: self.stats.total_ops.load(Ordering::Relaxed),
            total_bytes: self.stats.total_bytes.load(Ordering::Relaxed),
            ..Default::default()
        }
    }
}

impl DpuHasher for CpuHasher {
    fn hash(&self, input: &[u8]) -> Result<[u8; 32]> {
        self.stats.total_ops.fetch_add(1, Ordering::Relaxed);
        self.stats
            .total_bytes
            .fetch_add(input.len() as u64, Ordering::Relaxed);
        Ok(*blake3::hash(input).as_bytes())
    }

    fn hash_batch(&self, inputs: &[&[u8]]) -> Result<Vec<[u8; 32]>> {
        inputs.iter().map(|input| self.hash(input)).collect()
    }

    fn hash_keyed(&self, key: &[u8; 32], input: &[u8]) -> Result<[u8; 32]> {
        self.stats.total_ops.fetch_add(1, Ordering::Relaxed);
        self.stats
            .total_bytes
            .fetch_add(input.len() as u64, Ordering::Relaxed);
        Ok(*blake3::keyed_hash(key, input).as_bytes())
    }

    fn hasher(&self) -> Box<dyn IncrementalHasher> {
        Box::new(Blake3IncrementalHasher::new())
    }

    fn algorithm(&self) -> &'static str {
        "blake3"
    }
}

struct Blake3IncrementalHasher {
    hasher: blake3::Hasher,
}

impl Blake3IncrementalHasher {
    fn new() -> Self {
        Self {
            hasher: blake3::Hasher::new(),
        }
    }
}

impl IncrementalHasher for Blake3IncrementalHasher {
    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn finalize(self: Box<Self>) -> [u8; 32] {
        *self.hasher.finalize().as_bytes()
    }

    fn reset(&mut self) {
        self.hasher.reset();
    }
}

// ============================================================================
// CPU Cipher (ChaCha20-Poly1305)
// ============================================================================

/// CPU-based ChaCha20-Poly1305 cipher
#[derive(Debug)]
pub struct CpuCipher {
    stats: Arc<CipherStats>,
}

#[derive(Debug, Default)]
struct CipherStats {
    encrypt_ops: AtomicU64,
    decrypt_ops: AtomicU64,
    total_bytes: AtomicU64,
}

impl CpuCipher {
    /// Create a new CPU cipher
    #[must_use]
    pub fn new() -> Self {
        Self {
            stats: Arc::new(CipherStats::default()),
        }
    }
}

impl Default for CpuCipher {
    fn default() -> Self {
        Self::new()
    }
}

impl DpuOp for CpuCipher {
    fn is_dpu_available(&self) -> bool {
        false
    }

    fn name(&self) -> &'static str {
        "cpu_cipher"
    }

    fn backend(&self) -> DpuType {
        DpuType::Cpu
    }

    fn stats(&self) -> DpuOpStats {
        let total = self.stats.encrypt_ops.load(Ordering::Relaxed)
            + self.stats.decrypt_ops.load(Ordering::Relaxed);
        DpuOpStats {
            total_ops: total,
            cpu_ops: total,
            total_bytes: self.stats.total_bytes.load(Ordering::Relaxed),
            ..Default::default()
        }
    }
}

impl DpuCipher for CpuCipher {
    fn encrypt(
        &self,
        plaintext: &[u8],
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        use chacha20poly1305::{
            ChaCha20Poly1305, Nonce,
            aead::{Aead, KeyInit, Payload},
        };

        self.stats.encrypt_ops.fetch_add(1, Ordering::Relaxed);
        self.stats
            .total_bytes
            .fetch_add(plaintext.len() as u64, Ordering::Relaxed);

        let cipher = ChaCha20Poly1305::new(key.into());
        let nonce = Nonce::from_slice(nonce);

        let ciphertext = if let Some(aad) = aad {
            cipher.encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
        } else {
            cipher.encrypt(nonce, plaintext)
        }
        .map_err(|e| Error::CryptoAccel(format!("Encryption failed: {e}")))?;

        Ok(ciphertext)
    }

    fn decrypt(
        &self,
        ciphertext: &[u8],
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        use chacha20poly1305::{
            ChaCha20Poly1305, Nonce,
            aead::{Aead, KeyInit, Payload},
        };

        self.stats.decrypt_ops.fetch_add(1, Ordering::Relaxed);
        self.stats
            .total_bytes
            .fetch_add(ciphertext.len() as u64, Ordering::Relaxed);

        let cipher = ChaCha20Poly1305::new(key.into());
        let nonce = Nonce::from_slice(nonce);

        let plaintext = if let Some(aad) = aad {
            cipher.decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
        } else {
            cipher.decrypt(nonce, ciphertext)
        }
        .map_err(|e| Error::CryptoAccel(format!("Decryption failed: {e}")))?;

        Ok(plaintext)
    }

    fn encrypt_inline(
        &self,
        input_buffer: &dyn DpuBuffer,
        output_buffer: &mut dyn DpuBuffer,
        key: &[u8; 32],
        nonce: &[u8; 12],
    ) -> Result<usize> {
        let ciphertext = self.encrypt(input_buffer.as_slice(), key, nonce, None)?;
        let out_slice = output_buffer.as_mut_slice();
        if out_slice.len() < ciphertext.len() {
            return Err(Error::BufferSizeMismatch {
                expected: ciphertext.len(),
                actual: out_slice.len(),
            });
        }
        out_slice[..ciphertext.len()].copy_from_slice(&ciphertext);
        Ok(ciphertext.len())
    }

    fn decrypt_inline(
        &self,
        input_buffer: &dyn DpuBuffer,
        output_buffer: &mut dyn DpuBuffer,
        key: &[u8; 32],
        nonce: &[u8; 12],
    ) -> Result<usize> {
        let plaintext = self.decrypt(input_buffer.as_slice(), key, nonce, None)?;
        let out_slice = output_buffer.as_mut_slice();
        if out_slice.len() < plaintext.len() {
            return Err(Error::BufferSizeMismatch {
                expected: plaintext.len(),
                actual: out_slice.len(),
            });
        }
        out_slice[..plaintext.len()].copy_from_slice(&plaintext);
        Ok(plaintext.len())
    }

    fn encrypt_batch(
        &self,
        plaintexts: &[&[u8]],
        key: &[u8; 32],
        nonces: &[[u8; 12]],
        aad: Option<&[u8]>,
    ) -> Result<Vec<Vec<u8>>> {
        if plaintexts.len() != nonces.len() {
            return Err(Error::InvalidInput(
                "Plaintext and nonce count mismatch".into(),
            ));
        }
        plaintexts
            .iter()
            .zip(nonces.iter())
            .map(|(pt, nonce)| self.encrypt(pt, key, nonce, aad))
            .collect()
    }

    fn decrypt_batch(
        &self,
        ciphertexts: &[&[u8]],
        key: &[u8; 32],
        nonces: &[[u8; 12]],
        aad: Option<&[u8]>,
    ) -> Result<Vec<Vec<u8>>> {
        if ciphertexts.len() != nonces.len() {
            return Err(Error::InvalidInput(
                "Ciphertext and nonce count mismatch".into(),
            ));
        }
        ciphertexts
            .iter()
            .zip(nonces.iter())
            .map(|(ct, nonce)| self.decrypt(ct, key, nonce, aad))
            .collect()
    }

    fn algorithm(&self) -> &'static str {
        "chacha20-poly1305"
    }
}

// ============================================================================
// CPU Compressor (Zstd/LZ4)
// ============================================================================

/// CPU-based compressor supporting Zstd and LZ4
#[derive(Debug)]
pub struct CpuCompressor {
    algorithm: CompressionAlgorithm,
    level: i32,
    stats: Arc<CompressorStats>,
}

#[derive(Debug, Default)]
struct CompressorStats {
    compress_ops: AtomicU64,
    decompress_ops: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
}

impl CpuCompressor {
    /// Create a new Zstd compressor with default level
    #[must_use]
    pub fn zstd() -> Self {
        Self::zstd_with_level(3)
    }

    /// Create a Zstd compressor with specific level
    #[must_use]
    pub fn zstd_with_level(level: i32) -> Self {
        Self {
            algorithm: CompressionAlgorithm::Zstd,
            level,
            stats: Arc::new(CompressorStats::default()),
        }
    }

    /// Create a new LZ4 compressor
    #[must_use]
    pub fn lz4() -> Self {
        Self {
            algorithm: CompressionAlgorithm::Lz4,
            level: 0,
            stats: Arc::new(CompressorStats::default()),
        }
    }
}

impl Default for CpuCompressor {
    fn default() -> Self {
        Self::zstd()
    }
}

impl DpuOp for CpuCompressor {
    fn is_dpu_available(&self) -> bool {
        false
    }

    fn name(&self) -> &'static str {
        match self.algorithm {
            CompressionAlgorithm::Zstd => "cpu_zstd",
            CompressionAlgorithm::Lz4 => "cpu_lz4",
        }
    }

    fn backend(&self) -> DpuType {
        DpuType::Cpu
    }

    fn stats(&self) -> DpuOpStats {
        let total = self.stats.compress_ops.load(Ordering::Relaxed)
            + self.stats.decompress_ops.load(Ordering::Relaxed);
        DpuOpStats {
            total_ops: total,
            cpu_ops: total,
            total_bytes: self.stats.bytes_in.load(Ordering::Relaxed),
            ..Default::default()
        }
    }
}

impl DpuCompressor for CpuCompressor {
    fn compress(&self, input: &[u8]) -> Result<Vec<u8>> {
        self.stats.compress_ops.fetch_add(1, Ordering::Relaxed);
        self.stats
            .bytes_in
            .fetch_add(input.len() as u64, Ordering::Relaxed);

        let result = match self.algorithm {
            CompressionAlgorithm::Zstd => zstd::bulk::compress(input, self.level)
                .map_err(|e| Error::CompressAccel(format!("Zstd compression failed: {e}")))?,
            CompressionAlgorithm::Lz4 => lz4_flex::compress_prepend_size(input),
        };

        self.stats
            .bytes_out
            .fetch_add(result.len() as u64, Ordering::Relaxed);
        Ok(result)
    }

    fn decompress(&self, input: &[u8]) -> Result<Vec<u8>> {
        self.stats.decompress_ops.fetch_add(1, Ordering::Relaxed);
        self.stats
            .bytes_in
            .fetch_add(input.len() as u64, Ordering::Relaxed);

        let result = match self.algorithm {
            CompressionAlgorithm::Zstd => zstd::bulk::decompress(input, 64 * 1024 * 1024)
                .map_err(|e| Error::DecompressAccel(format!("Zstd decompression failed: {e}")))?,
            CompressionAlgorithm::Lz4 => lz4_flex::decompress_size_prepended(input)
                .map_err(|e| Error::DecompressAccel(format!("LZ4 decompression failed: {e}")))?,
        };

        self.stats
            .bytes_out
            .fetch_add(result.len() as u64, Ordering::Relaxed);
        Ok(result)
    }

    fn compress_inline(
        &self,
        input_buffer: &dyn DpuBuffer,
        output_buffer: &mut dyn DpuBuffer,
    ) -> Result<usize> {
        let compressed = self.compress(input_buffer.as_slice())?;
        let out_slice = output_buffer.as_mut_slice();
        if out_slice.len() < compressed.len() {
            return Err(Error::BufferSizeMismatch {
                expected: compressed.len(),
                actual: out_slice.len(),
            });
        }
        out_slice[..compressed.len()].copy_from_slice(&compressed);
        Ok(compressed.len())
    }

    fn decompress_inline(
        &self,
        input_buffer: &dyn DpuBuffer,
        output_buffer: &mut dyn DpuBuffer,
    ) -> Result<usize> {
        let decompressed = self.decompress(input_buffer.as_slice())?;
        let out_slice = output_buffer.as_mut_slice();
        if out_slice.len() < decompressed.len() {
            return Err(Error::BufferSizeMismatch {
                expected: decompressed.len(),
                actual: out_slice.len(),
            });
        }
        out_slice[..decompressed.len()].copy_from_slice(&decompressed);
        Ok(decompressed.len())
    }

    fn compress_batch(&self, inputs: &[&[u8]]) -> Result<Vec<Vec<u8>>> {
        inputs.iter().map(|input| self.compress(input)).collect()
    }

    fn decompress_batch(&self, inputs: &[&[u8]]) -> Result<Vec<Vec<u8>>> {
        inputs.iter().map(|input| self.decompress(input)).collect()
    }

    fn algorithm(&self) -> &'static str {
        self.algorithm.name()
    }

    fn level(&self) -> Option<i32> {
        Some(self.level)
    }

    fn estimate_compressed_size(&self, input_len: usize) -> usize {
        match self.algorithm {
            CompressionAlgorithm::Zstd => zstd::zstd_safe::compress_bound(input_len),
            CompressionAlgorithm::Lz4 => lz4_flex::block::get_maximum_output_size(input_len) + 4,
        }
    }
}

// ============================================================================
// CPU Erasure Coder (Reed-Solomon)
// ============================================================================

/// CPU-based Reed-Solomon erasure coder
#[derive(Debug)]
pub struct CpuErasureCoder {
    data_shards: usize,
    parity_shards: usize,
    stats: Arc<ErasureStats>,
}

#[derive(Debug, Default)]
struct ErasureStats {
    encode_ops: AtomicU64,
    decode_ops: AtomicU64,
    total_bytes: AtomicU64,
}

impl CpuErasureCoder {
    /// Create a new erasure coder with default 4+2 configuration
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(4, 2)
    }

    /// Create an erasure coder with specific configuration
    #[must_use]
    pub fn with_config(data_shards: usize, parity_shards: usize) -> Self {
        Self {
            data_shards,
            parity_shards,
            stats: Arc::new(ErasureStats::default()),
        }
    }
}

impl Default for CpuErasureCoder {
    fn default() -> Self {
        Self::new()
    }
}

impl DpuOp for CpuErasureCoder {
    fn is_dpu_available(&self) -> bool {
        false
    }

    fn name(&self) -> &'static str {
        "cpu_erasure"
    }

    fn backend(&self) -> DpuType {
        DpuType::Cpu
    }

    fn stats(&self) -> DpuOpStats {
        let total = self.stats.encode_ops.load(Ordering::Relaxed)
            + self.stats.decode_ops.load(Ordering::Relaxed);
        DpuOpStats {
            total_ops: total,
            cpu_ops: total,
            total_bytes: self.stats.total_bytes.load(Ordering::Relaxed),
            ..Default::default()
        }
    }
}

impl DpuErasureCoder for CpuErasureCoder {
    fn encode(&self, data: &[u8]) -> Result<Vec<Vec<u8>>> {
        self.stats.encode_ops.fetch_add(1, Ordering::Relaxed);
        self.stats
            .total_bytes
            .fetch_add(data.len() as u64, Ordering::Relaxed);

        // Calculate shard size (must be same for all shards, and multiple of 2 for reed-solomon-simd)
        let shard_size = {
            let base = data.len().div_ceil(self.data_shards);
            // Round up to next multiple of 2
            (base + 1) & !1
        };

        // Create original shards (padding data if necessary)
        let mut original_shards: Vec<Vec<u8>> = Vec::with_capacity(self.data_shards);
        for i in 0..self.data_shards {
            let start = i * shard_size;
            let end = ((i + 1) * shard_size).min(data.len());
            let mut shard = if start < data.len() {
                data[start..end].to_vec()
            } else {
                Vec::new()
            };
            shard.resize(shard_size, 0);
            original_shards.push(shard);
        }

        // Use the simple encode API
        let original_refs: Vec<&[u8]> = original_shards
            .iter()
            .map(std::vec::Vec::as_slice)
            .collect();
        let recovery =
            reed_solomon_simd::encode(self.data_shards, self.parity_shards, &original_refs)
                .map_err(|e| Error::ErasureCoding(format!("Encoding failed: {e}")))?;

        // Combine original and recovery shards
        let mut all_shards = original_shards;
        for shard in recovery {
            all_shards.push(shard);
        }

        Ok(all_shards)
    }

    fn decode(&self, shards: &[Option<Vec<u8>>]) -> Result<Vec<u8>> {
        self.stats.decode_ops.fetch_add(1, Ordering::Relaxed);

        if shards.len() != self.data_shards + self.parity_shards {
            return Err(Error::ErasureCoding(format!(
                "Expected {} shards, got {}",
                self.data_shards + self.parity_shards,
                shards.len()
            )));
        }

        // Count available shards
        let available: usize = shards.iter().filter(|s| s.is_some()).count();
        if available < self.data_shards {
            return Err(Error::ErasureCoding(format!(
                "Need at least {} shards, only {} available",
                self.data_shards, available
            )));
        }

        // Get shard size from first available shard
        let shard_size = shards
            .iter()
            .find_map(|s| s.as_ref().map(std::vec::Vec::len))
            .ok_or_else(|| Error::ErasureCoding("No shards available".into()))?;

        // Build original and recovery shard maps
        let mut original: Vec<(usize, &[u8])> = Vec::new();
        let mut recovery: Vec<(usize, &[u8])> = Vec::new();

        for (i, shard) in shards.iter().enumerate() {
            if let Some(data) = shard {
                if i < self.data_shards {
                    original.push((i, data));
                } else {
                    recovery.push((i - self.data_shards, data));
                }
            }
        }

        // Use the simple decode API
        let restored =
            reed_solomon_simd::decode(self.data_shards, self.parity_shards, original, recovery)
                .map_err(|e| Error::ErasureCoding(format!("Decoding failed: {e}")))?;

        // Reconstruct original data from restored shards
        // The restored map contains only the shards that were missing
        let original_len = shard_size * self.data_shards;
        let mut result = Vec::with_capacity(original_len);

        for i in 0..self.data_shards {
            if let Some(shard) = restored.get(&i) {
                // This shard was restored
                result.extend_from_slice(shard);
            } else if let Some(shard) = shards[i].as_ref() {
                // This shard was already available
                result.extend_from_slice(shard);
            } else {
                return Err(Error::ErasureCoding(format!("Missing shard {i}")));
            }
        }

        self.stats
            .total_bytes
            .fetch_add(original_len as u64, Ordering::Relaxed);

        Ok(result)
    }

    fn encode_inline(
        &self,
        _input_buffer: &dyn DpuBuffer,
        _output_buffers: &mut [&mut dyn DpuBuffer],
    ) -> Result<()> {
        Err(Error::NotSupported(
            "Inline erasure coding not supported on CPU".into(),
        ))
    }

    fn decode_inline(
        &self,
        _input_buffers: &[Option<&dyn DpuBuffer>],
        _output_buffer: &mut dyn DpuBuffer,
    ) -> Result<()> {
        Err(Error::NotSupported(
            "Inline erasure coding not supported on CPU".into(),
        ))
    }

    fn reconstruct(&self, shards: &mut [Option<Vec<u8>>]) -> Result<()> {
        // For CPU fallback, we decode and re-encode
        let decoded = self.decode(shards)?;
        let encoded = self.encode(&decoded)?;

        for (i, shard) in encoded.into_iter().enumerate() {
            if shards[i].is_none() {
                shards[i] = Some(shard);
            }
        }

        Ok(())
    }

    fn data_shards(&self) -> usize {
        self.data_shards
    }

    fn parity_shards(&self) -> usize {
        self.parity_shards
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpu_hasher() {
        let hasher = CpuHasher::new();
        let hash = hasher.hash(b"hello world").unwrap();
        assert_eq!(hash.len(), 32);

        // Verify consistency
        let hash2 = hasher.hash(b"hello world").unwrap();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_cpu_hasher_batch() {
        let hasher = CpuHasher::new();
        let inputs: Vec<&[u8]> = vec![b"one", b"two", b"three"];
        let hashes = hasher.hash_batch(&inputs).unwrap();
        assert_eq!(hashes.len(), 3);
    }

    #[test]
    fn test_cpu_cipher_roundtrip() {
        let cipher = CpuCipher::new();
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"Hello, World!";

        let ciphertext = cipher.encrypt(plaintext, &key, &nonce, None).unwrap();
        let decrypted = cipher.decrypt(&ciphertext, &key, &nonce, None).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_cpu_cipher_with_aad() {
        let cipher = CpuCipher::new();
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let plaintext = b"Secret data";
        let aad = b"additional authenticated data";

        let ciphertext = cipher.encrypt(plaintext, &key, &nonce, Some(aad)).unwrap();
        let decrypted = cipher
            .decrypt(&ciphertext, &key, &nonce, Some(aad))
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_cpu_compressor_zstd() {
        let compressor = CpuCompressor::zstd();
        let data = b"This is some test data that should compress well. ".repeat(100);

        let compressed = compressor.compress(&data).unwrap();
        assert!(compressed.len() < data.len());

        let decompressed = compressor.decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_cpu_compressor_lz4() {
        let compressor = CpuCompressor::lz4();
        let data = b"Test data for LZ4 compression. ".repeat(50);

        let compressed = compressor.compress(&data).unwrap();
        let decompressed = compressor.decompress(&compressed).unwrap();

        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_cpu_erasure_coder() {
        let coder = CpuErasureCoder::with_config(4, 2);
        let data = b"This is test data for erasure coding that needs to be long enough".to_vec();

        let shards = coder.encode(&data).unwrap();
        assert_eq!(shards.len(), 6);

        // Simulate losing 2 shards (within parity tolerance)
        let mut partial_shards: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        partial_shards[1] = None;
        partial_shards[3] = None;

        let recovered = coder.decode(&partial_shards).unwrap();
        // Recovered data should match original (may be padded)
        assert!(recovered.starts_with(&data));
    }
}
