//! io_uring backend implementation
//!
//! Provides high-performance async I/O using the Linux io_uring interface.

#![cfg(all(target_os = "linux", feature = "io-uring"))]

use super::IoUringConfig;
use super::registered_buffers::{RegisteredBuffer, RegisteredBufferPool};
use bytes::Bytes;
use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, trace, warn};

/// io_uring-based I/O backend for high-performance file operations
pub struct IoUringBackend {
    /// The io_uring instance
    ring: io_uring::IoUring,
    /// Pool of registered buffers for zero-copy
    buffer_pool: RegisteredBufferPool,
    /// Registered file descriptors (fd -> index)
    registered_fds: HashMap<RawFd, u32>,
    /// Configuration
    config: IoUringConfig,
    /// Stats: total bytes read
    bytes_read: AtomicU64,
    /// Stats: total bytes written
    bytes_written: AtomicU64,
    /// Stats: total operations
    ops_completed: AtomicU64,
}

/// Result of an I/O operation
#[derive(Debug)]
pub struct IoResult {
    /// Number of bytes transferred
    pub bytes: usize,
    /// Buffer containing data (for reads)
    pub buffer: Option<RegisteredBuffer>,
}

impl IoUringBackend {
    /// Create a new io_uring backend with the given configuration
    pub fn new(config: IoUringConfig) -> io::Result<Self> {
        let mut builder = io_uring::IoUring::builder();

        if config.enable_sqpoll {
            builder.setup_sqpoll(config.sqpoll_idle_ms);
        }

        let ring = builder.build(config.sq_entries)?;

        let buffer_pool =
            RegisteredBufferPool::new(config.num_registered_buffers, config.buffer_size);

        Ok(Self {
            ring,
            buffer_pool,
            registered_fds: HashMap::new(),
            config,
            bytes_read: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
            ops_completed: AtomicU64::new(0),
        })
    }

    /// Create with default configuration
    pub fn with_defaults() -> io::Result<Self> {
        Self::new(IoUringConfig::default())
    }

    /// Register a file descriptor for faster operations
    pub fn register_fd(&mut self, file: &File) -> io::Result<u32> {
        let fd = file.as_raw_fd();
        if let Some(&idx) = self.registered_fds.get(&fd) {
            return Ok(idx);
        }

        let idx = self.registered_fds.len() as u32;
        // Note: In real implementation, use ring.submitter().register_files()
        self.registered_fds.insert(fd, idx);
        debug!("Registered fd {} at index {}", fd, idx);
        Ok(idx)
    }

    /// Read from a file at the given offset
    pub fn read(&mut self, file: &File, offset: u64, len: usize) -> io::Result<Bytes> {
        let buffer = self
            .buffer_pool
            .acquire()
            .ok_or_else(|| io::Error::new(io::ErrorKind::WouldBlock, "No buffers available"))?;

        let read_len = len.min(buffer.len());
        let fd = io_uring::types::Fd(file.as_raw_fd());

        // Build read operation
        let read_op = io_uring::opcode::Read::new(fd, buffer.as_mut_ptr(), read_len as u32)
            .offset(offset)
            .build()
            .user_data(0);

        // Safety: We own the buffer and it lives until completion
        unsafe {
            self.ring.submission().push(&read_op).map_err(|_| {
                io::Error::new(io::ErrorKind::Other, "Failed to submit read operation")
            })?;
        }

        // Submit and wait
        self.ring.submit_and_wait(1)?;

        // Get completion
        let cqe = self
            .ring
            .completion()
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "No completion"))?;

        let result = cqe.result();
        if result < 0 {
            self.buffer_pool.release(buffer);
            return Err(io::Error::from_raw_os_error(-result));
        }

        let bytes_read = result as usize;
        self.bytes_read
            .fetch_add(bytes_read as u64, Ordering::Relaxed);
        self.ops_completed.fetch_add(1, Ordering::Relaxed);

        // Convert to Bytes
        let data = Bytes::copy_from_slice(&buffer.as_slice()[..bytes_read]);
        self.buffer_pool.release(buffer);

        trace!("Read {} bytes at offset {}", bytes_read, offset);
        Ok(data)
    }

    /// Read entire file into memory
    pub fn read_file(&mut self, path: impl AsRef<Path>) -> io::Result<Bytes> {
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        let len = metadata.len() as usize;

        if len == 0 {
            return Ok(Bytes::new());
        }

        // For large files, read in chunks
        if len > self.config.buffer_size {
            let mut result = Vec::with_capacity(len);
            let mut offset = 0u64;

            while (offset as usize) < len {
                let remaining = len - offset as usize;
                let chunk = self.read(&file, offset, remaining)?;
                result.extend_from_slice(&chunk);
                offset += chunk.len() as u64;
            }

            return Ok(Bytes::from(result));
        }

        self.read(&file, 0, len)
    }

    /// Write data to a file at the given offset
    pub fn write(&mut self, file: &File, offset: u64, data: &[u8]) -> io::Result<usize> {
        let fd = io_uring::types::Fd(file.as_raw_fd());

        // Build write operation
        let write_op = io_uring::opcode::Write::new(fd, data.as_ptr(), data.len() as u32)
            .offset(offset)
            .build()
            .user_data(0);

        // Safety: data must remain valid until completion
        unsafe {
            self.ring.submission().push(&write_op).map_err(|_| {
                io::Error::new(io::ErrorKind::Other, "Failed to submit write operation")
            })?;
        }

        // Submit and wait
        self.ring.submit_and_wait(1)?;

        // Get completion
        let cqe = self
            .ring
            .completion()
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "No completion"))?;

        let result = cqe.result();
        if result < 0 {
            return Err(io::Error::from_raw_os_error(-result));
        }

        let bytes_written = result as usize;
        self.bytes_written
            .fetch_add(bytes_written as u64, Ordering::Relaxed);
        self.ops_completed.fetch_add(1, Ordering::Relaxed);

        trace!("Wrote {} bytes at offset {}", bytes_written, offset);
        Ok(bytes_written)
    }

    /// Submit multiple read operations in a batch
    pub fn read_batch(
        &mut self,
        file: &File,
        requests: &[(u64, usize)], // (offset, len) pairs
    ) -> io::Result<Vec<Bytes>> {
        if requests.is_empty() {
            return Ok(Vec::new());
        }

        let fd = io_uring::types::Fd(file.as_raw_fd());
        let mut buffers = Vec::with_capacity(requests.len());
        let mut user_data_counter = 0u64;

        // Acquire buffers and submit all reads
        for &(offset, len) in requests {
            let buffer = self
                .buffer_pool
                .acquire()
                .ok_or_else(|| io::Error::new(io::ErrorKind::WouldBlock, "No buffers available"))?;

            let read_len = len.min(buffer.len());
            let read_op = io_uring::opcode::Read::new(fd, buffer.as_mut_ptr(), read_len as u32)
                .offset(offset)
                .build()
                .user_data(user_data_counter);

            unsafe {
                self.ring.submission().push(&read_op).map_err(|_| {
                    io::Error::new(io::ErrorKind::Other, "Failed to submit read operation")
                })?;
            }

            buffers.push(buffer);
            user_data_counter += 1;
        }

        // Submit all and wait for completions
        self.ring.submit_and_wait(requests.len())?;

        // Collect results in order
        let mut results: Vec<Option<Bytes>> = vec![None; requests.len()];
        let mut completed = 0;

        while completed < requests.len() {
            if let Some(cqe) = self.ring.completion().next() {
                let idx = cqe.user_data() as usize;
                let result = cqe.result();

                if result < 0 {
                    // Release all buffers on error
                    for buffer in buffers.into_iter() {
                        self.buffer_pool.release(buffer);
                    }
                    return Err(io::Error::from_raw_os_error(-result));
                }

                let bytes_read = result as usize;
                self.bytes_read
                    .fetch_add(bytes_read as u64, Ordering::Relaxed);

                let data = Bytes::copy_from_slice(&buffers[idx].as_slice()[..bytes_read]);
                results[idx] = Some(data);
                completed += 1;
            }
        }

        // Release buffers
        for buffer in buffers.into_iter() {
            self.buffer_pool.release(buffer);
        }

        self.ops_completed
            .fetch_add(requests.len() as u64, Ordering::Relaxed);

        Ok(results.into_iter().map(|r| r.unwrap()).collect())
    }

    /// Get statistics
    pub fn stats(&self) -> IoUringStats {
        IoUringStats {
            bytes_read: self.bytes_read.load(Ordering::Relaxed),
            bytes_written: self.bytes_written.load(Ordering::Relaxed),
            ops_completed: self.ops_completed.load(Ordering::Relaxed),
            buffers_available: self.buffer_pool.available(),
            buffers_total: self.config.num_registered_buffers,
        }
    }
}

/// Statistics for the io_uring backend
#[derive(Debug, Clone)]
pub struct IoUringStats {
    /// Total bytes read
    pub bytes_read: u64,
    /// Total bytes written
    pub bytes_written: u64,
    /// Total operations completed
    pub ops_completed: u64,
    /// Available buffers in pool
    pub buffers_available: usize,
    /// Total buffers in pool
    pub buffers_total: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_backend_creation() {
        let backend = IoUringBackend::with_defaults();
        assert!(backend.is_ok());
    }

    #[test]
    fn test_read_file() {
        let mut backend = IoUringBackend::with_defaults().unwrap();

        let mut file = NamedTempFile::new().unwrap();
        let data = b"Hello, io_uring!";
        file.write_all(data).unwrap();
        file.flush().unwrap();

        let result = backend.read_file(file.path()).unwrap();
        assert_eq!(&result[..], data);
    }

    #[test]
    fn test_read_at_offset() {
        let mut backend = IoUringBackend::with_defaults().unwrap();

        let mut temp_file = NamedTempFile::new().unwrap();
        let data = b"0123456789ABCDEF";
        temp_file.write_all(data).unwrap();
        temp_file.flush().unwrap();

        let file = File::open(temp_file.path()).unwrap();
        let result = backend.read(&file, 5, 5).unwrap();
        assert_eq!(&result[..], b"56789");
    }

    #[test]
    fn test_batch_read() {
        let mut backend = IoUringBackend::with_defaults().unwrap();

        let mut temp_file = NamedTempFile::new().unwrap();
        let data = b"AAAABBBBCCCCDDDD";
        temp_file.write_all(data).unwrap();
        temp_file.flush().unwrap();

        let file = File::open(temp_file.path()).unwrap();
        let requests = vec![(0, 4), (4, 4), (8, 4), (12, 4)];

        let results = backend.read_batch(&file, &requests).unwrap();
        assert_eq!(results.len(), 4);
        assert_eq!(&results[0][..], b"AAAA");
        assert_eq!(&results[1][..], b"BBBB");
        assert_eq!(&results[2][..], b"CCCC");
        assert_eq!(&results[3][..], b"DDDD");
    }

    #[test]
    fn test_stats() {
        let mut backend = IoUringBackend::with_defaults().unwrap();

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"test data").unwrap();
        file.flush().unwrap();

        let _ = backend.read_file(file.path()).unwrap();

        let stats = backend.stats();
        assert!(stats.bytes_read > 0);
        assert!(stats.ops_completed > 0);
    }
}
