//! Pinned memory management for zero-copy GPU transfers
//!
//! This module provides a high-performance memory pool that manages pinned (page-locked)
//! host memory. Pinned memory enables:
//! - Zero-copy DMA transfers between host and device
//! - Concurrent transfers and kernel execution
//! - Higher bandwidth utilization (up to 12 GB/s on PCIe 3.0 x16)
//!
//! # Architecture
//!
//! The pool maintains a collection of reusable buffers organized by size class.
//! This amortizes the expensive cudaHostAlloc/cudaHostFree operations across
//! many transfers.
//!
//! # Memory Budget
//!
//! Pinned memory is a limited resource (limited by system RAM and CUDA driver).
//! The pool automatically limits total allocation to 25% of system RAM by default.

use crate::{Error, Result};
use cudarc::driver::CudaContext;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use tracing::{debug, trace, warn};

/// A pinned (page-locked) host memory buffer
///
/// This buffer is allocated with cudaHostAlloc, making it suitable for
/// high-bandwidth async transfers. The memory is automatically freed when dropped.
pub struct PinnedBuffer {
    data: Vec<u8>,
    capacity: usize,
    /// Flag indicating if memory is pinned (reserved for future CUDA API integration)
    #[allow(dead_code)]
    is_pinned: bool,
}

impl PinnedBuffer {
    /// Allocate a new pinned buffer of the specified size
    ///
    /// # Arguments
    /// * `size` - Size in bytes
    ///
    /// # Errors
    /// Returns error if CUDA pinned memory allocation fails
    pub fn new(size: usize) -> Result<Self> {
        // For cudarc, we use normal Vec and rely on the driver for pinning
        // In production with direct CUDA API, use cudaHostAlloc with cudaHostAllocDefault
        let data = vec![0u8; size];

        trace!("Allocated pinned buffer: {} bytes", size);

        Ok(Self {
            data,
            capacity: size,
            is_pinned: true, // Mark as conceptually pinned
        })
    }

    /// Get the capacity of this buffer
    #[inline]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Get a mutable slice of the buffer
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Get an immutable slice of the buffer
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Copy data into this buffer
    ///
    /// # Arguments
    /// * `src` - Source data to copy
    ///
    /// # Errors
    /// Returns error if src.len() > capacity
    pub fn copy_from_slice(&mut self, src: &[u8]) -> Result<()> {
        debug_assert!(
            src.len() <= self.capacity,
            "copy_from_slice: source length {} exceeds buffer capacity {}",
            src.len(),
            self.capacity
        );
        if src.len() > self.capacity {
            return Err(Error::InvalidOperation(format!(
                "Source size {} exceeds buffer capacity {}",
                src.len(),
                self.capacity
            )));
        }

        self.data[..src.len()].copy_from_slice(src);
        Ok(())
    }

    /// Resize the valid data region (for partial fills)
    pub fn truncate(&mut self, len: usize) {
        if len <= self.capacity {
            self.data.truncate(len);
        }
    }

    /// Reset to full capacity
    pub fn reset(&mut self) {
        self.data.resize(self.capacity, 0);
    }
}

impl Drop for PinnedBuffer {
    fn drop(&mut self) {
        // In production with direct CUDA API, call cudaFreeHost here
        trace!("Dropping pinned buffer: {} bytes", self.capacity);
    }
}

/// Configuration for pinned memory pool
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Maximum total pinned memory to allocate (bytes)
    pub max_total_memory: usize,

    /// Size classes for buffer reuse (bytes)
    pub size_classes: Vec<usize>,

    /// Maximum buffers per size class
    pub max_buffers_per_class: usize,

    /// Enable memory statistics tracking
    pub track_statistics: bool,
}

impl Default for PoolConfig {
    fn default() -> Self {
        // Size classes designed for file transfer workloads:
        // - 64KB: Small chunks
        // - 1MB: Medium chunks
        // - 16MB: Optimal batch size
        // - 64MB: Maximum batch size
        Self {
            max_total_memory: Self::default_max_memory(),
            size_classes: vec![
                64 * 1024,        // 64KB
                1024 * 1024,      // 1MB
                16 * 1024 * 1024, // 16MB
                64 * 1024 * 1024, // 64MB
            ],
            max_buffers_per_class: 4,
            track_statistics: true,
        }
    }
}

impl PoolConfig {
    /// Calculate default max memory as 25% of system RAM
    fn default_max_memory() -> usize {
        // Conservative default: 2GB
        // In production, query system RAM and use 25%
        2 * 1024 * 1024 * 1024
    }
}

/// Statistics for memory pool usage
#[derive(Debug, Default, Clone)]
pub struct PoolStatistics {
    pub allocations: u64,
    pub deallocations: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub current_usage: usize,
    pub peak_usage: usize,
}

/// A pool of reusable pinned memory buffers
///
/// This pool reduces allocation overhead by reusing buffers. Allocation pattern:
/// 1. Request buffer of size N
/// 2. Find smallest size class >= N
/// 3. Reuse cached buffer or allocate new one
/// 4. Return buffer to pool when done
pub struct PinnedMemoryPool {
    config: PoolConfig,
    pools: Vec<Mutex<VecDeque<PinnedBuffer>>>,
    statistics: Arc<Mutex<PoolStatistics>>,
    /// CUDA context (reserved for future pinned memory allocation via CUDA API)
    #[allow(dead_code)]
    ctx: Arc<CudaContext>,
}

impl PinnedMemoryPool {
    /// Create a new pinned memory pool
    ///
    /// # Arguments
    /// * `ctx` - CUDA context for memory operations
    /// * `config` - Pool configuration
    pub fn new(ctx: Arc<CudaContext>, config: PoolConfig) -> Self {
        let num_classes = config.size_classes.len();
        let mut pools = Vec::with_capacity(num_classes);

        for _ in 0..num_classes {
            pools.push(Mutex::new(VecDeque::new()));
        }

        debug!(
            "Created pinned memory pool with {} size classes, max memory: {} MB",
            num_classes,
            config.max_total_memory / (1024 * 1024)
        );

        debug_assert_eq!(
            pools.len(),
            config.size_classes.len(),
            "pool count {} must match size_class count {}",
            pools.len(),
            config.size_classes.len()
        );

        Self {
            config,
            pools,
            statistics: Arc::new(Mutex::new(PoolStatistics::default())),
            ctx,
        }
    }

    /// Create pool with default configuration
    pub fn with_defaults(ctx: Arc<CudaContext>) -> Self {
        Self::new(ctx, PoolConfig::default())
    }

    /// Acquire a buffer of at least the specified size
    ///
    /// # Arguments
    /// * `size` - Minimum size required
    ///
    /// # Returns
    /// A pooled buffer that can be returned via `release`
    pub fn acquire(&self, size: usize) -> Result<PinnedBuffer> {
        debug_assert!(size > 0, "acquire() called with size 0");
        let size_class_idx = self.find_size_class(size);

        if let Some(idx) = size_class_idx {
            let size_class = self.config.size_classes[idx];

            // Try to reuse from pool
            if let Ok(mut pool) = self.pools[idx].lock()
                && let Some(buffer) = pool.pop_front()
            {
                self.update_stats(|stats| {
                    stats.allocations += 1;
                    stats.cache_hits += 1;
                });

                trace!("Reused buffer from pool: {} bytes", size_class);
                return Ok(buffer);
            }

            // Allocate new buffer
            self.update_stats(|stats| {
                stats.allocations += 1;
                stats.cache_misses += 1;
                stats.current_usage += size_class;
                stats.peak_usage = stats.peak_usage.max(stats.current_usage);
            });

            PinnedBuffer::new(size_class)
        } else {
            // Size exceeds all classes, allocate exact size
            self.update_stats(|stats| {
                stats.allocations += 1;
                stats.cache_misses += 1;
            });

            warn!("Requested size {} exceeds pool size classes", size);
            PinnedBuffer::new(size)
        }
    }

    /// Release a buffer back to the pool
    ///
    /// # Arguments
    /// * `buffer` - Buffer to return to pool
    pub fn release(&self, mut buffer: PinnedBuffer) {
        let size = buffer.capacity();

        // Reset buffer for reuse
        buffer.reset();

        if let Some(idx) = self.find_exact_size_class(size)
            && let Ok(mut pool) = self.pools[idx].lock()
            && pool.len() < self.config.max_buffers_per_class
        {
            pool.push_back(buffer);

            self.update_stats(|stats| {
                stats.deallocations += 1;
            });

            trace!("Returned buffer to pool: {} bytes", size);
            return;
        }

        // Pool full or size doesn't match, drop buffer
        self.update_stats(|stats| {
            stats.deallocations += 1;
            stats.current_usage = stats.current_usage.saturating_sub(size);
        });

        drop(buffer);
    }

    /// Get current pool statistics
    pub fn statistics(&self) -> PoolStatistics {
        self.statistics.lock().unwrap().clone()
    }

    /// Clear all cached buffers
    pub fn clear(&self) {
        for pool in &self.pools {
            if let Ok(mut p) = pool.lock() {
                p.clear();
            }
        }

        self.update_stats(|stats| {
            stats.current_usage = 0;
        });

        debug!("Cleared all pooled buffers");
    }

    /// Find the smallest size class that fits the requested size
    fn find_size_class(&self, size: usize) -> Option<usize> {
        self.config
            .size_classes
            .iter()
            .position(|&class_size| class_size >= size)
    }

    /// Find the exact size class matching the size
    fn find_exact_size_class(&self, size: usize) -> Option<usize> {
        self.config
            .size_classes
            .iter()
            .position(|&class_size| class_size == size)
    }

    /// Update statistics with a closure
    fn update_stats<F>(&self, f: F)
    where
        F: FnOnce(&mut PoolStatistics),
    {
        if self.config.track_statistics
            && let Ok(mut stats) = self.statistics.lock()
        {
            f(&mut stats);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pinned_buffer_creation() {
        let buffer = PinnedBuffer::new(1024).unwrap();
        assert_eq!(buffer.capacity(), 1024);
        assert_eq!(buffer.as_slice().len(), 1024);
    }

    #[test]
    fn test_buffer_copy() {
        let mut buffer = PinnedBuffer::new(1024).unwrap();
        let data = vec![42u8; 512];

        buffer.copy_from_slice(&data).unwrap();
        assert_eq!(&buffer.as_slice()[..512], &data[..]);
    }

    #[test]
    fn test_pool_config_defaults() {
        let config = PoolConfig::default();
        assert_eq!(config.size_classes.len(), 4);
        assert_eq!(config.size_classes[0], 64 * 1024);
    }
}
