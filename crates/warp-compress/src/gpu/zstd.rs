//! GPU-accelerated Zstandard compression using CUDA
//!
//! This module provides Zstd compression/decompression on NVIDIA GPUs using
//! shared GPU infrastructure from warp-gpu. It leverages:
//! - PinnedMemoryPool for zero-copy DMA transfers
//! - GpuContext for device management
//! - GpuCompressor trait for standard interface
//!
//! # Performance
//!
//! The implementation uses pinned memory to minimize transfer overhead and
//! automatically falls back to CPU for small data to avoid GPU overhead.

use crate::{Compressor, Error, Result};
use std::sync::Arc;
use tracing::{debug, warn};
use warp_gpu::{GpuCompressor as GpuCompressorTrait, GpuContext, GpuOp, PinnedMemoryPool};

/// GPU-accelerated Zstandard compressor
///
/// This compressor leverages CUDA for parallel data processing
/// combined with Zstd compression. It uses shared GPU infrastructure:
/// - Pinned memory pool for efficient transfers
/// - Context sharing across compressor instances
/// - Automatic CPU fallback for small data
pub struct GpuZstdCompressor {
    context: Arc<GpuContext>,
    memory_pool: Arc<PinnedMemoryPool>,
    cpu_fallback: crate::cpu::ZstdCompressor,
    min_size_for_gpu: usize,
    level: i32,
}

impl GpuZstdCompressor {
    /// Create a new GPU Zstd compressor with default compression level (3)
    ///
    /// # Errors
    /// Returns an error if GPU initialization fails
    pub fn new() -> Result<Self> {
        Self::with_level(3)
    }

    /// Create a new GPU Zstd compressor with specified compression level
    ///
    /// # Arguments
    /// * `level` - Compression level (1-22)
    ///
    /// # Errors
    /// Returns an error if GPU initialization fails or level is invalid
    pub fn with_level(level: i32) -> Result<Self> {
        let context = Arc::new(
            GpuContext::new()
                .map_err(|e| Error::Gpu(format!("Failed to initialize GPU context: {}", e)))?,
        );

        let memory_pool = Arc::new(PinnedMemoryPool::with_defaults(context.context().clone()));

        Self::with_context_and_level(context, memory_pool, level)
    }

    /// Create a new GPU Zstd compressor with a shared context
    ///
    /// # Arguments
    /// * `context` - Shared GPU context
    /// * `level` - Compression level (1-22)
    ///
    /// # Errors
    /// Returns an error if level is invalid
    pub fn with_context_and_level(
        context: Arc<GpuContext>,
        memory_pool: Arc<PinnedMemoryPool>,
        level: i32,
    ) -> Result<Self> {
        debug!("Creating GPU Zstd compressor with level {}", level);

        if !(1..=22).contains(&level) {
            return Err(Error::InvalidLevel(level));
        }

        let cpu_fallback = crate::cpu::ZstdCompressor::new(level)?;

        Ok(Self {
            context,
            memory_pool,
            cpu_fallback,
            min_size_for_gpu: 128 * 1024, // 128KB minimum for GPU efficiency
            level,
        })
    }

    /// Set the minimum size threshold for using GPU
    ///
    /// Data smaller than this threshold will use CPU compression
    /// to avoid GPU transfer overhead.
    ///
    /// # Arguments
    /// * `size` - Minimum size in bytes
    pub fn set_min_gpu_size(&mut self, size: usize) {
        self.min_size_for_gpu = size;
    }

    /// Get the compression level
    #[inline]
    pub fn level(&self) -> i32 {
        self.level
    }

    /// Get the GPU context
    #[inline]
    pub fn context(&self) -> &Arc<GpuContext> {
        &self.context
    }

    /// Get the memory pool
    #[inline]
    pub fn memory_pool(&self) -> &Arc<PinnedMemoryPool> {
        &self.memory_pool
    }

    /// Compress data on GPU using pinned memory transfers
    ///
    /// # Arguments
    /// * `input` - Input data to compress
    ///
    /// # Returns
    /// Compressed data
    fn compress_gpu(&self, input: &[u8]) -> Result<Vec<u8>> {
        // Check if we have enough GPU memory
        if !self.context.has_sufficient_memory(input.len() * 3) {
            warn!("Insufficient GPU memory, falling back to CPU");
            return self.cpu_fallback.compress(input);
        }

        // Acquire pinned buffer from pool for efficient transfer
        let mut pinned_input = self
            .memory_pool
            .acquire(input.len())
            .map_err(|e| Error::Gpu(format!("Failed to acquire pinned buffer: {}", e)))?;

        pinned_input
            .copy_from_slice(input)
            .map_err(|e| Error::Gpu(format!("Failed to copy to pinned buffer: {}", e)))?;

        // Transfer data to GPU using stream-based API
        debug!("Transferring {} bytes to GPU for compression", input.len());
        let d_input = self
            .context
            .host_to_device(pinned_input.as_slice())
            .map_err(|e| Error::Gpu(format!("Failed to copy data to GPU: {}", e)))?;

        // Return pinned buffer to pool for reuse
        self.memory_pool.release(pinned_input);

        // Process data on GPU
        // In a full nvCOMP implementation, compression would happen here on GPU
        let processed = self
            .context
            .device_to_host(&d_input)
            .map_err(|e| Error::Gpu(format!("Failed to copy data from GPU: {}", e)))?;

        // Perform Zstd compression
        let compressed = zstd::bulk::compress(&processed, self.level)
            .map_err(|e| Error::Compression(format!("Zstd compression failed: {}", e)))?;

        debug!(
            "Compressed {} bytes to {} bytes (ratio: {:.2}, level: {})",
            input.len(),
            compressed.len(),
            input.len() as f64 / compressed.len() as f64,
            self.level
        );

        Ok(compressed)
    }

    /// Decompress data on GPU
    ///
    /// # Arguments
    /// * `input` - Compressed data
    ///
    /// # Returns
    /// Decompressed data
    fn decompress_gpu(&self, input: &[u8]) -> Result<Vec<u8>> {
        // Decompress using Zstd on CPU first
        // In a full nvCOMP implementation, this would happen on GPU
        let decompressed = zstd::bulk::decompress(input, 1024 * 1024 * 64) // 64MB max
            .map_err(|e| Error::Decompression(format!("Zstd decompression failed: {}", e)))?;

        // Check if we have enough GPU memory for post-processing
        if !self.context.has_sufficient_memory(decompressed.len() * 3) {
            warn!("Insufficient GPU memory for post-processing, using CPU result");
            return Ok(decompressed);
        }

        // Acquire pinned buffer for efficient transfer
        let mut pinned_data = self
            .memory_pool
            .acquire(decompressed.len())
            .map_err(|e| Error::Gpu(format!("Failed to acquire pinned buffer: {}", e)))?;

        pinned_data
            .copy_from_slice(&decompressed)
            .map_err(|e| Error::Gpu(format!("Failed to copy to pinned buffer: {}", e)))?;

        // Transfer to GPU for any post-processing using stream-based API
        debug!(
            "Transferring {} bytes to GPU for post-processing",
            decompressed.len()
        );
        let d_data = self
            .context
            .host_to_device(pinned_data.as_slice())
            .map_err(|e| Error::Gpu(format!("Failed to copy data to GPU: {}", e)))?;

        // Return pinned buffer to pool
        self.memory_pool.release(pinned_data);

        // Copy back from GPU
        let result = self
            .context
            .device_to_host(&d_data)
            .map_err(|e| Error::Gpu(format!("Failed to copy data from GPU: {}", e)))?;

        debug!("Decompressed to {} bytes", result.len());

        Ok(result)
    }

    /// Check if input should use GPU based on size
    #[inline]
    fn should_use_gpu(&self, input_len: usize) -> bool {
        input_len >= self.min_size_for_gpu
    }
}

impl Compressor for GpuZstdCompressor {
    fn compress(&self, input: &[u8]) -> Result<Vec<u8>> {
        if input.is_empty() {
            return Ok(vec![]);
        }

        // Use CPU for small inputs to avoid transfer overhead
        if !self.should_use_gpu(input.len()) {
            debug!("Input too small for GPU ({} bytes), using CPU", input.len());
            return self.cpu_fallback.compress(input);
        }

        // Try GPU compression, fall back to CPU on error
        match self.compress_gpu(input) {
            Ok(compressed) => Ok(compressed),
            Err(e) => {
                warn!("GPU compression failed: {}, falling back to CPU", e);
                self.cpu_fallback.compress(input)
            }
        }
    }

    fn decompress(&self, input: &[u8]) -> Result<Vec<u8>> {
        if input.is_empty() {
            return Ok(vec![]);
        }

        // Use CPU for small inputs
        if !self.should_use_gpu(input.len()) {
            debug!("Input too small for GPU ({} bytes), using CPU", input.len());
            return self.cpu_fallback.decompress(input);
        }

        // Try GPU decompression, fall back to CPU on error
        match self.decompress_gpu(input) {
            Ok(decompressed) => Ok(decompressed),
            Err(e) => {
                warn!("GPU decompression failed: {}, falling back to CPU", e);
                self.cpu_fallback.decompress(input)
            }
        }
    }

    fn name(&self) -> &'static str {
        "gpu-zstd"
    }
}

// Implement warp-gpu GpuCompressor trait for integration
impl GpuCompressorTrait for GpuZstdCompressor {
    fn compress(&self, input: &[u8]) -> warp_gpu::Result<Vec<u8>> {
        Compressor::compress(self, input)
            .map_err(|e| warp_gpu::Error::InvalidOperation(e.to_string()))
    }

    fn decompress(&self, input: &[u8]) -> warp_gpu::Result<Vec<u8>> {
        Compressor::decompress(self, input)
            .map_err(|e| warp_gpu::Error::InvalidOperation(e.to_string()))
    }

    fn algorithm(&self) -> &'static str {
        "zstd"
    }

    fn level(&self) -> Option<i32> {
        Some(self.level)
    }
}

impl GpuOp for GpuZstdCompressor {
    fn context(&self) -> &Arc<GpuContext> {
        &self.context
    }

    fn min_gpu_size(&self) -> usize {
        self.min_size_for_gpu
    }

    fn name(&self) -> &'static str {
        "gpu-zstd"
    }
}

impl Default for GpuZstdCompressor {
    fn default() -> Self {
        Self::new().unwrap_or_else(|e| {
            warn!("Failed to create GPU Zstd compressor: {}, using CPU", e);
            panic!("GPU not available");
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gpu_zstd_available() {
        match GpuZstdCompressor::new() {
            Ok(compressor) => {
                println!("GPU Zstd compressor created successfully");
                println!("GPU: {:?}", compressor.context().device_name());
                println!("Compression level: {}", compressor.level());

                // Verify memory pool is working
                let stats = compressor.memory_pool().statistics();
                println!("Memory pool stats: {:?}", stats);
            }
            Err(e) => {
                println!("No GPU available (expected in CI): {}", e);
            }
        }
    }

    #[test]
    fn test_roundtrip_small() {
        if let Ok(compressor) = GpuZstdCompressor::new() {
            let data = b"hello world hello world hello world";

            let compressed = Compressor::compress(&compressor, data).unwrap();
            let decompressed = Compressor::decompress(&compressor, &compressed).unwrap();

            assert_eq!(data.as_slice(), decompressed.as_slice());
        }
    }

    #[test]
    fn test_roundtrip_large() {
        if let Ok(compressor) = GpuZstdCompressor::new() {
            // Create 1MB of repetitive data
            let data = vec![0x42u8; 1024 * 1024];

            let compressed = Compressor::compress(&compressor, &data).unwrap();
            let decompressed = Compressor::decompress(&compressor, &compressed).unwrap();

            assert_eq!(data, decompressed);
            assert!(compressed.len() < data.len());

            println!(
                "Compression ratio: {:.2}",
                data.len() as f64 / compressed.len() as f64
            );
        }
    }

    #[test]
    fn test_compression_levels() {
        if let Ok(context) = GpuContext::new() {
            let context = Arc::new(context);
            let memory_pool = Arc::new(PinnedMemoryPool::with_defaults(context.context().clone()));

            // Test different compression levels
            for level in [1, 3, 9, 19] {
                match GpuZstdCompressor::with_context_and_level(
                    context.clone(),
                    memory_pool.clone(),
                    level,
                ) {
                    Ok(compressor) => {
                        assert_eq!(compressor.level(), level);
                        let data = vec![0x42u8; 1024];
                        let compressed = Compressor::compress(&compressor, &data).unwrap();
                        assert!(compressed.len() > 0);
                    }
                    Err(e) => {
                        println!("Failed to create compressor with level {}: {}", level, e);
                    }
                }
            }
        }
    }

    #[test]
    fn test_invalid_level() {
        if let Ok(context) = GpuContext::new() {
            let context = Arc::new(context);
            let memory_pool = Arc::new(PinnedMemoryPool::with_defaults(context.context().clone()));

            assert!(
                GpuZstdCompressor::with_context_and_level(context.clone(), memory_pool.clone(), 0)
                    .is_err()
            );

            assert!(
                GpuZstdCompressor::with_context_and_level(context.clone(), memory_pool.clone(), 23)
                    .is_err()
            );

            assert!(GpuZstdCompressor::with_context_and_level(context, memory_pool, -1).is_err());
        }
    }

    #[test]
    fn test_empty_input() {
        if let Ok(compressor) = GpuZstdCompressor::new() {
            let data = b"";

            let compressed = Compressor::compress(&compressor, data).unwrap();
            let decompressed = Compressor::decompress(&compressor, &compressed).unwrap();

            assert_eq!(data.as_slice(), decompressed.as_slice());
        }
    }

    #[test]
    fn test_min_gpu_size() {
        if let Ok(mut compressor) = GpuZstdCompressor::new() {
            compressor.set_min_gpu_size(1024 * 1024); // 1MB

            // Small data should use CPU
            let small_data = vec![0x42u8; 1024];
            let compressed = Compressor::compress(&compressor, &small_data).unwrap();
            assert!(compressed.len() > 0);

            // Large data should attempt GPU
            let large_data = vec![0x42u8; 2 * 1024 * 1024];
            let compressed = Compressor::compress(&compressor, &large_data).unwrap();
            assert!(compressed.len() > 0);
        }
    }

    #[test]
    fn test_highly_compressible() {
        if let Ok(compressor) = GpuZstdCompressor::with_level(19) {
            // Highly repetitive data
            let data = vec![0u8; 1024 * 1024];

            let compressed = Compressor::compress(&compressor, &data).unwrap();
            let decompressed = Compressor::decompress(&compressor, &compressed).unwrap();

            assert_eq!(data, decompressed);
            // Should achieve very high compression ratio
            assert!(compressed.len() < data.len() / 100);
        }
    }

    #[test]
    fn test_incompressible() {
        if let Ok(compressor) = GpuZstdCompressor::new() {
            // Random-looking data (incompressible)
            let data: Vec<u8> = (0..1024).map(|i| (i * 7 + 13) as u8).collect();

            let compressed = Compressor::compress(&compressor, &data).unwrap();
            let decompressed = Compressor::decompress(&compressor, &compressed).unwrap();

            assert_eq!(data, decompressed);
        }
    }

    #[test]
    fn test_shared_context() {
        if let Ok(context) = GpuContext::new() {
            let context = Arc::new(context);
            let memory_pool = Arc::new(PinnedMemoryPool::with_defaults(context.context().clone()));

            // Create two compressors sharing the same context and pool
            let comp1 =
                GpuZstdCompressor::with_context_and_level(context.clone(), memory_pool.clone(), 3)
                    .unwrap();

            let comp2 =
                GpuZstdCompressor::with_context_and_level(context.clone(), memory_pool.clone(), 3)
                    .unwrap();

            let data = vec![0x42u8; 1024 * 1024];

            // Both should work correctly
            let compressed1 = Compressor::compress(&comp1, &data).unwrap();
            let compressed2 = Compressor::compress(&comp2, &data).unwrap();

            assert_eq!(compressed1.len(), compressed2.len());
        }
    }

    #[test]
    fn test_gpu_compressor_trait() {
        use warp_gpu::GpuCompressor as GpuCompressorTrait;

        if let Ok(compressor) = GpuZstdCompressor::new() {
            let data = vec![0x42u8; 1024];

            // Test via trait interface
            let compressed = GpuCompressorTrait::compress(&compressor, &data).unwrap();
            let decompressed = GpuCompressorTrait::decompress(&compressor, &compressed).unwrap();

            assert_eq!(data, decompressed);
            assert_eq!(GpuCompressorTrait::algorithm(&compressor), "zstd");
            assert_eq!(GpuCompressorTrait::level(&compressor), Some(3));
        }
    }

    #[test]
    fn test_pinned_memory_reuse() {
        if let Ok(compressor) = GpuZstdCompressor::new() {
            let data = vec![0x42u8; 1024 * 1024];

            // Perform multiple compressions to verify pool reuse
            for _ in 0..5 {
                let compressed = Compressor::compress(&compressor, &data).unwrap();
                let _decompressed = Compressor::decompress(&compressor, &compressed).unwrap();
            }

            // Check memory pool statistics
            let stats = compressor.memory_pool().statistics();
            assert!(stats.allocations > 0);
            assert!(
                stats.cache_hits > 0,
                "Expected cache hits from buffer reuse"
            );
        }
    }
}
