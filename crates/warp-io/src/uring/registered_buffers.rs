//! Registered buffer pool for zero-copy io_uring operations
//!
//! Pre-registered buffers avoid the overhead of memory registration
//! on each I/O operation, enabling true zero-copy transfers.

#![cfg(all(target_os = "linux", feature = "io-uring"))]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use tracing::{debug, trace};

/// A registered buffer that can be used for zero-copy I/O
pub struct RegisteredBuffer {
    /// The actual buffer memory
    data: Vec<u8>,
    /// Index in the registered buffer table
    index: usize,
}

impl RegisteredBuffer {
    /// Create a new buffer with the given capacity
    fn new(capacity: usize, index: usize) -> Self {
        Self {
            data: vec![0u8; capacity],
            index,
        }
    }

    /// Get the buffer length
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get raw pointer for io_uring operations
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr()
    }

    /// Get buffer contents as slice
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Get buffer contents as mutable slice
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Get the registered buffer index
    pub fn index(&self) -> usize {
        self.index
    }

    /// Copy data into the buffer
    pub fn copy_from(&mut self, data: &[u8]) -> usize {
        let len = data.len().min(self.data.len());
        self.data[..len].copy_from_slice(&data[..len]);
        len
    }

    /// Clear buffer contents
    pub fn clear(&mut self) {
        self.data.fill(0);
    }
}

/// Pool of pre-registered buffers for efficient I/O
pub struct RegisteredBufferPool {
    /// Free buffers available for use
    free_buffers: Mutex<VecDeque<RegisteredBuffer>>,
    /// Total number of buffers
    total_count: usize,
    /// Size of each buffer
    buffer_size: usize,
}

impl RegisteredBufferPool {
    /// Create a new buffer pool
    pub fn new(count: usize, buffer_size: usize) -> Self {
        let mut free_buffers = VecDeque::with_capacity(count);

        for i in 0..count {
            free_buffers.push_back(RegisteredBuffer::new(buffer_size, i));
        }

        debug!(
            "Created buffer pool with {} buffers of {} bytes each",
            count, buffer_size
        );

        Self {
            free_buffers: Mutex::new(free_buffers),
            total_count: count,
            buffer_size,
        }
    }

    /// Acquire a buffer from the pool
    pub fn acquire(&self) -> Option<RegisteredBuffer> {
        let mut free = self.free_buffers.lock().unwrap();
        let buffer = free.pop_front();

        if buffer.is_some() {
            trace!("Acquired buffer, {} remaining", free.len());
        }

        buffer
    }

    /// Release a buffer back to the pool
    pub fn release(&self, mut buffer: RegisteredBuffer) {
        buffer.clear();
        let mut free = self.free_buffers.lock().unwrap();
        free.push_back(buffer);
        trace!("Released buffer, {} available", free.len());
    }

    /// Get number of available buffers
    pub fn available(&self) -> usize {
        self.free_buffers.lock().unwrap().len()
    }

    /// Get total number of buffers in pool
    pub fn total(&self) -> usize {
        self.total_count
    }

    /// Get size of each buffer
    pub fn buffer_size(&self) -> usize {
        self.buffer_size
    }

    /// Check if pool has available buffers
    pub fn has_available(&self) -> bool {
        !self.free_buffers.lock().unwrap().is_empty()
    }

    /// Try to acquire multiple buffers at once
    pub fn acquire_batch(&self, count: usize) -> Option<Vec<RegisteredBuffer>> {
        let mut free = self.free_buffers.lock().unwrap();

        if free.len() < count {
            return None;
        }

        let buffers: Vec<_> = (0..count).filter_map(|_| free.pop_front()).collect();
        trace!("Acquired {} buffers, {} remaining", count, free.len());
        Some(buffers)
    }

    /// Release multiple buffers back to the pool
    pub fn release_batch(&self, buffers: Vec<RegisteredBuffer>) {
        let mut free = self.free_buffers.lock().unwrap();
        for mut buffer in buffers {
            buffer.clear();
            free.push_back(buffer);
        }
        trace!("Released batch, {} available", free.len());
    }
}

/// Thread-safe handle to a shared buffer pool
pub type SharedBufferPool = Arc<RegisteredBufferPool>;

/// Create a shared buffer pool
pub fn create_shared_pool(count: usize, buffer_size: usize) -> SharedBufferPool {
    Arc::new(RegisteredBufferPool::new(count, buffer_size))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_creation() {
        let buffer = RegisteredBuffer::new(4096, 0);
        assert_eq!(buffer.len(), 4096);
        assert_eq!(buffer.index(), 0);
    }

    #[test]
    fn test_buffer_copy() {
        let mut buffer = RegisteredBuffer::new(1024, 0);
        let data = b"Hello, World!";
        let copied = buffer.copy_from(data);
        assert_eq!(copied, data.len());
        assert_eq!(&buffer.as_slice()[..data.len()], data);
    }

    #[test]
    fn test_pool_creation() {
        let pool = RegisteredBufferPool::new(16, 4096);
        assert_eq!(pool.available(), 16);
        assert_eq!(pool.total(), 16);
        assert_eq!(pool.buffer_size(), 4096);
    }

    #[test]
    fn test_pool_acquire_release() {
        let pool = RegisteredBufferPool::new(4, 1024);
        assert_eq!(pool.available(), 4);

        let buf1 = pool.acquire().unwrap();
        assert_eq!(pool.available(), 3);

        let buf2 = pool.acquire().unwrap();
        assert_eq!(pool.available(), 2);

        pool.release(buf1);
        assert_eq!(pool.available(), 3);

        pool.release(buf2);
        assert_eq!(pool.available(), 4);
    }

    #[test]
    fn test_pool_exhaustion() {
        let pool = RegisteredBufferPool::new(2, 1024);

        let _buf1 = pool.acquire().unwrap();
        let _buf2 = pool.acquire().unwrap();

        // Pool exhausted
        assert!(pool.acquire().is_none());
    }

    #[test]
    fn test_batch_acquire() {
        let pool = RegisteredBufferPool::new(8, 1024);

        let batch = pool.acquire_batch(4).unwrap();
        assert_eq!(batch.len(), 4);
        assert_eq!(pool.available(), 4);

        // Can't acquire more than available
        assert!(pool.acquire_batch(5).is_none());

        pool.release_batch(batch);
        assert_eq!(pool.available(), 8);
    }

    #[test]
    fn test_shared_pool() {
        let pool = create_shared_pool(4, 1024);
        let pool2 = Arc::clone(&pool);

        let buf1 = pool.acquire().unwrap();
        assert_eq!(pool2.available(), 3);

        pool2.release(buf1);
        assert_eq!(pool.available(), 4);
    }

    #[test]
    fn test_buffer_clear() {
        let mut buffer = RegisteredBuffer::new(16, 0);
        buffer.copy_from(b"sensitive data!!");
        assert_eq!(&buffer.as_slice()[..16], b"sensitive data!!");

        buffer.clear();
        assert!(buffer.as_slice().iter().all(|&b| b == 0));
    }
}
