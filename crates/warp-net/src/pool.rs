//! Zero-copy buffer pool for QUIC frame processing
//!
//! Provides tiered buffer pools to reduce allocations in hot paths:
//! - Small (256B): Control frames (HELLO, CAPABILITIES, DONE)
//! - Medium (4KB): Batch frames (CHUNK_BATCH, ACK_BATCH)
//! - Large (64KB): Chunk data headers
//!
//! Buffers are returned to the pool automatically when dropped (RAII).

use bytes::BytesMut;
use std::ops::{Deref, DerefMut};
use std::sync::Mutex;

/// Small buffer size for control frames
pub const SMALL_BUF_SIZE: usize = 256;

/// Medium buffer size for batch frames
pub const MEDIUM_BUF_SIZE: usize = 4 * 1024;

/// Large buffer size for chunk headers
pub const LARGE_BUF_SIZE: usize = 64 * 1024;

/// Maximum buffers per tier
const MAX_POOL_SIZE: usize = 64;

/// Tiered buffer pool for frame encoding/decoding
pub struct FrameBufferPool {
    small: Mutex<Vec<BytesMut>>,
    medium: Mutex<Vec<BytesMut>>,
    large: Mutex<Vec<BytesMut>>,
}

impl Default for FrameBufferPool {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameBufferPool {
    /// Create a new empty buffer pool
    pub const fn new() -> Self {
        Self {
            small: Mutex::new(Vec::new()),
            medium: Mutex::new(Vec::new()),
            large: Mutex::new(Vec::new()),
        }
    }

    /// Create a pre-warmed pool with initial buffers
    pub fn with_capacity(small_count: usize, medium_count: usize, large_count: usize) -> Self {
        let small = (0..small_count)
            .map(|_| BytesMut::with_capacity(SMALL_BUF_SIZE))
            .collect();
        let medium = (0..medium_count)
            .map(|_| BytesMut::with_capacity(MEDIUM_BUF_SIZE))
            .collect();
        let large = (0..large_count)
            .map(|_| BytesMut::with_capacity(LARGE_BUF_SIZE))
            .collect();

        Self {
            small: Mutex::new(small),
            medium: Mutex::new(medium),
            large: Mutex::new(large),
        }
    }

    /// Get a small buffer (256B) for control frames
    pub fn get_small(&self) -> PooledBuffer<'_> {
        let buf = self
            .small
            .lock()
            .unwrap()
            .pop()
            .unwrap_or_else(|| BytesMut::with_capacity(SMALL_BUF_SIZE));
        PooledBuffer::new(buf, BufferTier::Small, self)
    }

    /// Get a medium buffer (4KB) for batch frames
    pub fn get_medium(&self) -> PooledBuffer<'_> {
        let buf = self
            .medium
            .lock()
            .unwrap()
            .pop()
            .unwrap_or_else(|| BytesMut::with_capacity(MEDIUM_BUF_SIZE));
        PooledBuffer::new(buf, BufferTier::Medium, self)
    }

    /// Get a large buffer (64KB) for chunk data
    pub fn get_large(&self) -> PooledBuffer<'_> {
        let buf = self
            .large
            .lock()
            .unwrap()
            .pop()
            .unwrap_or_else(|| BytesMut::with_capacity(LARGE_BUF_SIZE));
        PooledBuffer::new(buf, BufferTier::Large, self)
    }

    /// Get a buffer sized for the given hint
    ///
    /// Automatically selects the appropriate tier based on expected size.
    pub fn get_for_size(&self, size_hint: usize) -> PooledBuffer<'_> {
        if size_hint <= SMALL_BUF_SIZE {
            self.get_small()
        } else if size_hint <= MEDIUM_BUF_SIZE {
            self.get_medium()
        } else {
            self.get_large()
        }
    }

    /// Return a buffer to the pool
    fn return_buffer(&self, mut buf: BytesMut, tier: BufferTier) {
        buf.clear();

        let pool = match tier {
            BufferTier::Small => &self.small,
            BufferTier::Medium => &self.medium,
            BufferTier::Large => &self.large,
        };

        let mut guard = pool.lock().unwrap();
        if guard.len() < MAX_POOL_SIZE {
            guard.push(buf);
        }
        // Buffer is dropped if pool is full
    }

    /// Get pool statistics
    pub fn stats(&self) -> PoolStats {
        PoolStats {
            small_available: self.small.lock().unwrap().len(),
            medium_available: self.medium.lock().unwrap().len(),
            large_available: self.large.lock().unwrap().len(),
        }
    }
}

/// Buffer tier for routing returns
#[derive(Clone, Copy, Debug)]
enum BufferTier {
    Small,
    Medium,
    Large,
}

/// RAII wrapper that returns buffer to pool on drop
pub struct PooledBuffer<'a> {
    buf: Option<BytesMut>,
    tier: BufferTier,
    pool: &'a FrameBufferPool,
}

impl<'a> PooledBuffer<'a> {
    fn new(buf: BytesMut, tier: BufferTier, pool: &'a FrameBufferPool) -> Self {
        Self {
            buf: Some(buf),
            tier,
            pool,
        }
    }

    /// Consume the pooled buffer and take ownership of the BytesMut
    ///
    /// This prevents the buffer from being returned to the pool.
    /// Use when you need to keep the buffer beyond the pool's lifetime.
    pub fn take(mut self) -> BytesMut {
        self.buf.take().unwrap()
    }

    /// Get the underlying BytesMut without consuming the wrapper
    pub fn inner(&self) -> &BytesMut {
        self.buf.as_ref().unwrap()
    }

    /// Get mutable reference to the underlying BytesMut
    pub fn inner_mut(&mut self) -> &mut BytesMut {
        self.buf.as_mut().unwrap()
    }
}

impl Deref for PooledBuffer<'_> {
    type Target = BytesMut;

    fn deref(&self) -> &Self::Target {
        self.buf.as_ref().unwrap()
    }
}

impl DerefMut for PooledBuffer<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buf.as_mut().unwrap()
    }
}

impl Drop for PooledBuffer<'_> {
    fn drop(&mut self) {
        if let Some(buf) = self.buf.take() {
            self.pool.return_buffer(buf, self.tier);
        }
    }
}

/// Pool statistics
#[derive(Debug, Clone, Copy)]
pub struct PoolStats {
    /// Number of small buffers available
    pub small_available: usize,
    /// Number of medium buffers available
    pub medium_available: usize,
    /// Number of large buffers available
    pub large_available: usize,
}

impl PoolStats {
    /// Total buffers available across all tiers
    pub fn total_available(&self) -> usize {
        self.small_available + self.medium_available + self.large_available
    }
}

/// Global buffer pool for the transport layer
///
/// Use `global_pool()` to access the singleton pool.
static GLOBAL_POOL: std::sync::OnceLock<FrameBufferPool> = std::sync::OnceLock::new();

/// Get the global buffer pool
///
/// The pool is lazily initialized on first access with default capacities.
pub fn global_pool() -> &'static FrameBufferPool {
    GLOBAL_POOL.get_or_init(|| FrameBufferPool::with_capacity(16, 8, 4))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_basic() {
        let pool = FrameBufferPool::new();

        // Get and return buffers
        let mut buf = pool.get_small();
        buf.extend_from_slice(b"hello");
        assert_eq!(buf.len(), 5);
        drop(buf);

        // Pool should have 1 buffer now
        let stats = pool.stats();
        assert_eq!(stats.small_available, 1);
    }

    #[test]
    fn test_pool_tiers() {
        let pool = FrameBufferPool::new();

        let small = pool.get_small();
        let medium = pool.get_medium();
        let large = pool.get_large();

        assert!(small.capacity() >= SMALL_BUF_SIZE);
        assert!(medium.capacity() >= MEDIUM_BUF_SIZE);
        assert!(large.capacity() >= LARGE_BUF_SIZE);
    }

    #[test]
    fn test_pool_size_hint() {
        let pool = FrameBufferPool::new();

        let buf = pool.get_for_size(100);
        assert!(buf.capacity() >= SMALL_BUF_SIZE);

        let buf = pool.get_for_size(1000);
        assert!(buf.capacity() >= MEDIUM_BUF_SIZE);

        let buf = pool.get_for_size(10000);
        assert!(buf.capacity() >= LARGE_BUF_SIZE);
    }

    #[test]
    fn test_pool_reuse() {
        let pool = FrameBufferPool::new();

        // Get and fill a buffer
        let mut buf = pool.get_small();
        buf.extend_from_slice(b"test data");
        drop(buf);

        // Get again - should be cleared
        let buf = pool.get_small();
        assert!(buf.is_empty());
    }

    #[test]
    fn test_pool_take() {
        let pool = FrameBufferPool::new();

        let mut buf = pool.get_small();
        buf.extend_from_slice(b"data");
        let taken = buf.take();

        assert_eq!(&taken[..], b"data");

        // Pool should be empty since we took the buffer
        let stats = pool.stats();
        assert_eq!(stats.small_available, 0);
    }

    #[test]
    fn test_pool_max_size() {
        let pool = FrameBufferPool::new();

        // Create more buffers than MAX_POOL_SIZE
        for _ in 0..100 {
            let buf = pool.get_small();
            drop(buf);
        }

        // Should be capped at MAX_POOL_SIZE
        let stats = pool.stats();
        assert!(stats.small_available <= MAX_POOL_SIZE);
    }

    #[test]
    fn test_global_pool() {
        let pool = global_pool();
        let mut buf = pool.get_medium();
        buf.extend_from_slice(b"global test");
        assert_eq!(buf.len(), 11);
    }

    #[test]
    fn test_prewarmed_pool() {
        let pool = FrameBufferPool::with_capacity(10, 5, 2);
        let stats = pool.stats();

        assert_eq!(stats.small_available, 10);
        assert_eq!(stats.medium_available, 5);
        assert_eq!(stats.large_available, 2);
    }
}
