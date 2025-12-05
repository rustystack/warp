//! Buffer pool for reusing allocations

use std::sync::Mutex;

/// A simple buffer pool
pub struct BufferPool {
    buffers: Mutex<Vec<Vec<u8>>>,
    buffer_size: usize,
}

impl BufferPool {
    /// Create a new buffer pool
    pub fn new(buffer_size: usize) -> Self {
        Self {
            buffers: Mutex::new(Vec::new()),
            buffer_size,
        }
    }
    
    /// Get a buffer from the pool (or allocate a new one)
    pub fn get(&self) -> PooledBuffer<'_> {
        let buffer = self
            .buffers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) // Recover from poison
            .pop()
            .unwrap_or_else(|| vec![0u8; self.buffer_size]);

        PooledBuffer {
            buffer: Some(buffer),
            pool: self,
        }
    }
    
    /// Return a buffer to the pool
    fn return_buffer(&self, mut buffer: Vec<u8>) {
        buffer.clear();
        buffer.resize(self.buffer_size, 0);
        // If poisoned, just drop the buffer (acceptable for pool)
        if let Ok(mut guard) = self.buffers.lock() {
            guard.push(buffer);
        }
    }
}

/// A buffer borrowed from the pool
pub struct PooledBuffer<'a> {
    buffer: Option<Vec<u8>>,
    pool: &'a BufferPool,
}

impl<'a> std::ops::Deref for PooledBuffer<'a> {
    type Target = Vec<u8>;
    
    fn deref(&self) -> &Self::Target {
        self.buffer.as_ref().unwrap()
    }
}

impl<'a> std::ops::DerefMut for PooledBuffer<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buffer.as_mut().unwrap()
    }
}

impl<'a> Drop for PooledBuffer<'a> {
    fn drop(&mut self) {
        if let Some(buffer) = self.buffer.take() {
            self.pool.return_buffer(buffer);
        }
    }
}
