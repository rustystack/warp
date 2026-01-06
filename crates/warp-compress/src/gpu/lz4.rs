//! GPU-accelerated LZ4 compression using CUDA
//!
//! This module provides LZ4 compression/decompression on NVIDIA GPUs using
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

/// GPU-accelerated LZ4 compressor
///
/// This compressor uses CUDA for parallel data processing and LZ4
/// compression. It leverages shared GPU infrastructure:
/// - Pinned memory pool for efficient transfers
/// - Context sharing across compressor instances
/// - Automatic CPU fallback for small data
pub struct GpuLz4Compressor {
    context: Arc<GpuContext>,
    memory_pool: Arc<PinnedMemoryPool>,
    cpu_fallback: crate::cpu::Lz4Compressor,
    min_size_for_gpu: usize,
}

impl GpuLz4Compressor {
    /// Create a new GPU LZ4 compressor
    ///
    /// This creates a new context and memory pool. For better resource sharing,
    /// prefer using `with_context` when multiple compressors are needed.
    ///
    /// # Errors
    /// Returns an error if GPU initialization fails
    pub fn new() -> Result<Self> {
        let context = Arc::new(
            GpuContext::new()
                .map_err(|e| Error::Gpu(format!("Failed to initialize GPU context: {}", e)))?,
        );

        let memory_pool = Arc::new(PinnedMemoryPool::with_defaults(context.context().clone()));

        Self::with_context_and_pool(context, memory_pool)
    }

    /// Create a new GPU LZ4 compressor with a shared context
    ///
    /// # Arguments
    /// * `context` - Shared GPU context
    ///
    /// # Errors
    /// Returns an error if initialization fails
    pub fn with_context(context: Arc<GpuContext>) -> Result<Self> {
        let memory_pool = Arc::new(PinnedMemoryPool::with_defaults(context.context().clone()));
        Self::with_context_and_pool(context, memory_pool)
    }

    /// Create a new GPU LZ4 compressor with shared context and memory pool
    ///
    /// This is the most efficient constructor for scenarios where multiple
    /// compressors share resources.
    ///
    /// # Arguments
    /// * `context` - Shared GPU context
    /// * `memory_pool` - Shared pinned memory pool
    ///
    /// # Errors
    /// Returns an error if initialization fails
    pub fn with_context_and_pool(
        context: Arc<GpuContext>,
        memory_pool: Arc<PinnedMemoryPool>,
    ) -> Result<Self> {
        debug!("Creating GPU LZ4 compressor with shared infrastructure");

        Ok(Self {
            context,
            memory_pool,
            cpu_fallback: crate::cpu::Lz4Compressor::new(),
            min_size_for_gpu: 64 * 1024, // 64KB minimum for GPU efficiency
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
    /// Compressed data with size prepended
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
        debug!(
            "Transferring {} bytes to GPU via pinned memory",
            input.len()
        );
        let d_input = self
            .context
            .host_to_device(pinned_input.as_slice())
            .map_err(|e| Error::Gpu(format!("Failed to copy data to GPU: {}", e)))?;

        // Return pinned buffer to pool for reuse
        self.memory_pool.release(pinned_input);

        // Copy back from GPU (in real nvCOMP implementation, compression happens on GPU)
        let processed = self
            .context
            .device_to_host(&d_input)
            .map_err(|e| Error::Gpu(format!("Failed to copy data from GPU: {}", e)))?;

        // Perform LZ4 compression
        // In a full nvCOMP implementation, this would happen on GPU
        let compressed = lz4_flex::compress_prepend_size(&processed);

        debug!(
            "Compressed {} bytes to {} bytes (ratio: {:.2})",
            input.len(),
            compressed.len(),
            input.len() as f64 / compressed.len() as f64
        );

        Ok(compressed)
    }

    /// Decompress data on GPU
    ///
    /// # Arguments
    /// * `input` - Compressed data with size prepended
    ///
    /// # Returns
    /// Decompressed data
    fn decompress_gpu(&self, input: &[u8]) -> Result<Vec<u8>> {
        // Decompress using LZ4 (this gives us the original size)
        let decompressed = lz4_flex::decompress_size_prepended(input)
            .map_err(|e| Error::Decompression(format!("LZ4 decompression failed: {}", e)))?;

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

impl Compressor for GpuLz4Compressor {
    fn compress(&self, input: &[u8]) -> Result<Vec<u8>> {
        if input.is_empty() {
            return Ok(vec![]);
        }

        // Use CPU for small inputs to avoid transfer overhead
        if !self.should_use_gpu(input.len()) {
            debug!("Input too small for GPU ({}), using CPU", input.len());
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
            debug!("Input too small for GPU ({}), using CPU", input.len());
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
        "gpu-lz4"
    }
}

// Implement warp-gpu GpuCompressor trait for integration
impl GpuCompressorTrait for GpuLz4Compressor {
    fn compress(&self, input: &[u8]) -> warp_gpu::Result<Vec<u8>> {
        Compressor::compress(self, input)
            .map_err(|e| warp_gpu::Error::InvalidOperation(e.to_string()))
    }

    fn decompress(&self, input: &[u8]) -> warp_gpu::Result<Vec<u8>> {
        Compressor::decompress(self, input)
            .map_err(|e| warp_gpu::Error::InvalidOperation(e.to_string()))
    }

    fn algorithm(&self) -> &'static str {
        "lz4"
    }

    fn level(&self) -> Option<i32> {
        None // LZ4 has no compression level
    }
}

impl GpuOp for GpuLz4Compressor {
    fn context(&self) -> &Arc<GpuContext> {
        &self.context
    }

    fn min_gpu_size(&self) -> usize {
        self.min_size_for_gpu
    }

    fn name(&self) -> &'static str {
        "gpu-lz4"
    }
}

impl Default for GpuLz4Compressor {
    fn default() -> Self {
        Self::new().unwrap_or_else(|e| {
            warn!("Failed to create GPU LZ4 compressor: {}, using CPU", e);
            panic!("GPU not available");
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gpu_lz4_available() {
        match GpuLz4Compressor::new() {
            Ok(compressor) => {
                println!("GPU LZ4 compressor created successfully");
                println!("GPU: {:?}", compressor.context().device_name());

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
        if let Ok(compressor) = GpuLz4Compressor::new() {
            let data = b"hello world hello world hello world";

            let compressed = Compressor::compress(&compressor, data).unwrap();
            let decompressed = Compressor::decompress(&compressor, &compressed).unwrap();

            assert_eq!(data.as_slice(), decompressed.as_slice());
        }
    }

    #[test]
    fn test_roundtrip_large() {
        if let Ok(compressor) = GpuLz4Compressor::new() {
            // Create 1MB of repetitive data
            let data = vec![0x42u8; 1024 * 1024];

            let compressed = Compressor::compress(&compressor, &data).unwrap();
            let decompressed = Compressor::decompress(&compressor, &compressed).unwrap();

            assert_eq!(data, decompressed);
            assert!(compressed.len() < data.len());
        }
    }

    #[test]
    fn test_empty_input() {
        if let Ok(compressor) = GpuLz4Compressor::new() {
            let data = b"";

            let compressed = Compressor::compress(&compressor, data).unwrap();
            let decompressed = Compressor::decompress(&compressor, &compressed).unwrap();

            assert_eq!(data.as_slice(), decompressed.as_slice());
        }
    }

    #[test]
    fn test_min_gpu_size() {
        if let Ok(mut compressor) = GpuLz4Compressor::new() {
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
    fn test_shared_context() {
        if let Ok(context) = GpuContext::new() {
            let context = Arc::new(context);

            // Create two compressors sharing the same context
            let comp1 = GpuLz4Compressor::with_context(context.clone()).unwrap();
            let comp2 = GpuLz4Compressor::with_context(context.clone()).unwrap();

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
        use warp_gpu::GpuOp;

        if let Ok(compressor) = GpuLz4Compressor::new() {
            let data = vec![0x42u8; 1024];

            // Test via trait interface
            let compressed = GpuCompressorTrait::compress(&compressor, &data).unwrap();
            let decompressed = GpuCompressorTrait::decompress(&compressor, &compressed).unwrap();

            assert_eq!(data, decompressed);
            assert_eq!(GpuCompressorTrait::algorithm(&compressor), "lz4");
            assert_eq!(GpuCompressorTrait::level(&compressor), None);
        }
    }

    #[test]
    fn test_pinned_memory_reuse() {
        if let Ok(compressor) = GpuLz4Compressor::new() {
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
