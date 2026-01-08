//! Async I/O integration with io_uring
//!
//! This module provides async-compatible wrappers around the io_uring backend
//! for integration with tokio-based async code.

#![cfg(all(target_os = "linux", feature = "io-uring"))]

use super::IoUringConfig;
use super::backend::IoUringBackend;
use crate::{Result, SeqCdcConfig, SeqMode};
use bytes::Bytes;
use std::collections::VecDeque;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};

/// Async file reader using io_uring backend
///
/// This wraps the synchronous io_uring backend and runs it in a blocking
/// task pool for async compatibility.
pub struct IoUringAsyncReader {
    backend: Arc<Mutex<IoUringBackend>>,
}

impl IoUringAsyncReader {
    /// Create a new async reader with default configuration
    pub fn new() -> std::io::Result<Self> {
        let backend = IoUringBackend::with_defaults()?;
        Ok(Self {
            backend: Arc::new(Mutex::new(backend)),
        })
    }

    /// Create with custom configuration
    pub fn with_config(config: IoUringConfig) -> std::io::Result<Self> {
        let backend = IoUringBackend::new(config)?;
        Ok(Self {
            backend: Arc::new(Mutex::new(backend)),
        })
    }

    /// Read an entire file asynchronously
    pub async fn read_file(&self, path: impl AsRef<Path>) -> std::io::Result<Bytes> {
        let path = path.as_ref().to_path_buf();
        let backend = self.backend.clone();

        // Run io_uring operations in blocking task
        tokio::task::spawn_blocking(move || {
            let mut guard = backend.blocking_lock();
            guard.read_file(path)
        })
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?
    }

    /// Read a file at specific offset and length
    pub async fn read_at(
        &self,
        path: impl AsRef<Path>,
        offset: u64,
        len: usize,
    ) -> std::io::Result<Bytes> {
        let path = path.as_ref().to_path_buf();
        let backend = self.backend.clone();

        tokio::task::spawn_blocking(move || {
            let mut guard = backend.blocking_lock();
            let file = std::fs::File::open(path)?;
            guard.read(&file, offset, len)
        })
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?
    }

    /// Read multiple chunks from a file in a single batch
    pub async fn read_batch(
        &self,
        path: impl AsRef<Path>,
        requests: Vec<(u64, usize)>,
    ) -> std::io::Result<Vec<Bytes>> {
        let path = path.as_ref().to_path_buf();
        let backend = self.backend.clone();

        tokio::task::spawn_blocking(move || {
            let mut guard = backend.blocking_lock();
            let file = std::fs::File::open(path)?;
            guard.read_batch(&file, &requests)
        })
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?
    }

    /// Get the underlying backend for direct access
    pub fn backend(&self) -> Arc<Mutex<IoUringBackend>> {
        self.backend.clone()
    }
}

/// Async content-defined chunker using io_uring for file I/O
///
/// This provides the same SeqCDC algorithm as the tokio-based async_chunker,
/// but uses io_uring for file reads on Linux for better performance.
pub struct IoUringChunker {
    reader: IoUringAsyncReader,
    config: SeqCdcConfig,
}

impl IoUringChunker {
    /// Create a new chunker with default configuration
    pub fn new(config: impl Into<SeqCdcConfig>) -> std::io::Result<Self> {
        Ok(Self {
            reader: IoUringAsyncReader::new()?,
            config: config.into(),
        })
    }

    /// Create with custom io_uring configuration
    pub fn with_io_config(
        chunker_config: impl Into<SeqCdcConfig>,
        io_config: IoUringConfig,
    ) -> std::io::Result<Self> {
        Ok(Self {
            reader: IoUringAsyncReader::with_config(io_config)?,
            config: chunker_config.into(),
        })
    }

    /// Chunk a file asynchronously using io_uring
    pub async fn chunk_file(&self, path: impl AsRef<Path>) -> Result<Vec<Vec<u8>>> {
        let data = self.reader.read_file(path).await?;
        Ok(self.chunk_bytes(&data))
    }

    /// Stream chunks through a channel using io_uring for reading
    pub fn chunk_file_stream(
        &self,
        path: impl AsRef<Path> + Send + 'static,
        channel_capacity: usize,
    ) -> mpsc::Receiver<Result<Vec<u8>>> {
        let (tx, rx) = mpsc::channel(channel_capacity);
        let reader = self.reader.backend.clone();
        let config = self.config.clone();
        let path = path.as_ref().to_path_buf();

        tokio::spawn(async move {
            let result = Self::stream_with_uring(reader, path, config, tx.clone()).await;
            if let Err(e) = result {
                let _ = tx.send(Err(e)).await;
            }
        });

        rx
    }

    async fn stream_with_uring(
        backend: Arc<Mutex<IoUringBackend>>,
        path: std::path::PathBuf,
        config: SeqCdcConfig,
        tx: mpsc::Sender<Result<Vec<u8>>>,
    ) -> Result<()> {
        // Read file in large chunks using io_uring
        let read_chunk_size = 256 * 1024; // 256KB read chunks
        let metadata = tokio::fs::metadata(&path).await?;
        let file_size = metadata.len() as usize;

        if file_size == 0 {
            return Ok(());
        }

        let mut offset = 0u64;
        let mut current_chunk = Vec::with_capacity(config.target_size);
        let mut window: VecDeque<u8> = VecDeque::with_capacity(config.seq_length + 1);
        let mut opposing_count = 0usize;
        let mut skip_remaining = 0usize;

        while (offset as usize) < file_size {
            let remaining = file_size - offset as usize;
            let to_read = remaining.min(read_chunk_size);

            // Read using io_uring
            let buffer = {
                let path = path.clone();
                let backend = backend.clone();
                tokio::task::spawn_blocking(move || {
                    let mut guard = backend.blocking_lock();
                    let file = std::fs::File::open(path)?;
                    guard.read(&file, offset, to_read)
                })
                .await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))??
            };

            // Process buffer through SeqCDC
            for byte in buffer.iter() {
                let byte = *byte;

                // Handle skip mode
                if skip_remaining > 0 {
                    current_chunk.push(byte);
                    skip_remaining -= 1;
                    if skip_remaining == 0 {
                        window.clear();
                        opposing_count = 0;
                    }
                    continue;
                }

                // Track opposing pairs for skip heuristic
                if let Some(&prev) = window.back() {
                    let is_opposing = match config.mode {
                        SeqMode::Increasing => prev >= byte,
                        SeqMode::Decreasing => prev <= byte,
                    };
                    if is_opposing {
                        opposing_count += 1;
                    } else {
                        opposing_count = 0;
                    }
                }

                // Update window
                window.push_back(byte);
                if window.len() > config.seq_length {
                    window.pop_front();
                }

                current_chunk.push(byte);
                let size = current_chunk.len();

                // Check for boundary after minimum size
                if size >= config.min_size {
                    let at_boundary =
                        is_monotonic_boundary(&window, &config) || size >= config.max_size;

                    if at_boundary {
                        let chunk = std::mem::take(&mut current_chunk);
                        if tx.send(Ok(chunk)).await.is_err() {
                            return Ok(()); // Receiver dropped
                        }
                        current_chunk = Vec::with_capacity(config.target_size);
                        window.clear();
                        opposing_count = 0;
                    }
                }

                // Trigger skip if in unfavorable region
                if opposing_count >= config.skip_trigger && size < config.min_size {
                    skip_remaining = config.skip_size.min(config.min_size - size);
                    opposing_count = 0;
                }
            }

            offset += buffer.len() as u64;
        }

        // Send final chunk
        if !current_chunk.is_empty() {
            let _ = tx.send(Ok(current_chunk)).await;
        }

        Ok(())
    }

    /// Chunk bytes in memory using SeqCDC
    fn chunk_bytes(&self, data: &[u8]) -> Vec<Vec<u8>> {
        let mut chunks = Vec::new();
        let mut current_chunk = Vec::with_capacity(self.config.target_size);
        let mut window: VecDeque<u8> = VecDeque::with_capacity(self.config.seq_length + 1);
        let mut opposing_count = 0usize;
        let mut skip_remaining = 0usize;

        for &byte in data {
            // Handle skip mode
            if skip_remaining > 0 {
                current_chunk.push(byte);
                skip_remaining -= 1;
                if skip_remaining == 0 {
                    window.clear();
                    opposing_count = 0;
                }
                continue;
            }

            // Track opposing pairs for skip heuristic
            if let Some(&prev) = window.back() {
                let is_opposing = match self.config.mode {
                    SeqMode::Increasing => prev >= byte,
                    SeqMode::Decreasing => prev <= byte,
                };
                if is_opposing {
                    opposing_count += 1;
                } else {
                    opposing_count = 0;
                }
            }

            // Update window
            window.push_back(byte);
            if window.len() > self.config.seq_length {
                window.pop_front();
            }

            current_chunk.push(byte);
            let size = current_chunk.len();

            // Check for boundary after minimum size
            if size >= self.config.min_size {
                let at_boundary =
                    is_monotonic_boundary(&window, &self.config) || size >= self.config.max_size;

                if at_boundary {
                    chunks.push(std::mem::take(&mut current_chunk));
                    current_chunk = Vec::with_capacity(self.config.target_size);
                    window.clear();
                    opposing_count = 0;
                }
            }

            // Trigger skip if in unfavorable region
            if opposing_count >= self.config.skip_trigger && size < self.config.min_size {
                skip_remaining = self.config.skip_size.min(self.config.min_size - size);
                opposing_count = 0;
            }
        }

        // Don't forget the last chunk
        if !current_chunk.is_empty() {
            chunks.push(current_chunk);
        }

        chunks
    }
}

/// Check if window ends with a monotonic sequence (SeqCDC boundary detection)
#[inline]
fn is_monotonic_boundary(window: &VecDeque<u8>, config: &SeqCdcConfig) -> bool {
    if window.len() < config.seq_length {
        return false;
    }

    let start = window.len() - config.seq_length;

    match config.mode {
        SeqMode::Increasing => {
            let mut prev = window[start];
            for i in (start + 1)..window.len() {
                let curr = window[i];
                if prev >= curr {
                    return false;
                }
                prev = curr;
            }
            true
        }
        SeqMode::Decreasing => {
            let mut prev = window[start];
            for i in (start + 1)..window.len() {
                let curr = window[i];
                if prev <= curr {
                    return false;
                }
                prev = curr;
            }
            true
        }
    }
}

/// Chunk a file using io_uring (convenience function)
///
/// This is the recommended way to chunk files on Linux for maximum performance.
/// Falls back to tokio async I/O on non-Linux platforms.
pub async fn chunk_file_uring(
    path: impl AsRef<Path>,
    config: impl Into<SeqCdcConfig>,
) -> Result<Vec<Vec<u8>>> {
    let chunker = IoUringChunker::new(config)?;
    chunker.chunk_file(path).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_uring_async_reader() {
        let reader = IoUringAsyncReader::new().unwrap();

        let mut file = NamedTempFile::new().unwrap();
        let data = b"Hello, io_uring async!";
        file.write_all(data).unwrap();
        file.flush().unwrap();

        let result = reader.read_file(file.path()).await.unwrap();
        assert_eq!(&result[..], data);
    }

    #[tokio::test]
    async fn test_uring_async_read_at() {
        let reader = IoUringAsyncReader::new().unwrap();

        let mut file = NamedTempFile::new().unwrap();
        let data = b"0123456789ABCDEF";
        file.write_all(data).unwrap();
        file.flush().unwrap();

        let result = reader.read_at(file.path(), 5, 5).await.unwrap();
        assert_eq!(&result[..], b"56789");
    }

    #[tokio::test]
    async fn test_uring_chunker() {
        let mut file = NamedTempFile::new().unwrap();
        let data: Vec<u8> = (0..50_000).map(|i| (i % 256) as u8).collect();
        file.write_all(&data).unwrap();
        file.flush().unwrap();

        let config = SeqCdcConfig {
            min_size: 1024,
            target_size: 4096,
            max_size: 8192,
            seq_length: 3,
            skip_trigger: 20,
            skip_size: 128,
            mode: SeqMode::Increasing,
        };

        let chunker = IoUringChunker::new(config).unwrap();
        let chunks = chunker.chunk_file(file.path()).await.unwrap();

        // Verify all data is accounted for
        let total: usize = chunks.iter().map(|c| c.len()).sum();
        assert_eq!(total, data.len());
    }

    #[tokio::test]
    async fn test_uring_chunk_stream() {
        let mut file = NamedTempFile::new().unwrap();
        let data: Vec<u8> = (0..50_000).map(|i| (i % 256) as u8).collect();
        file.write_all(&data).unwrap();
        file.flush().unwrap();

        let config = SeqCdcConfig::target_8kb();
        let chunker = IoUringChunker::new(config).unwrap();
        let mut rx = chunker.chunk_file_stream(file.path().to_path_buf(), 16);

        let mut chunks = Vec::new();
        while let Some(result) = rx.recv().await {
            chunks.push(result.unwrap());
        }

        let total: usize = chunks.iter().map(|c| c.len()).sum();
        assert_eq!(total, data.len());
    }

    #[tokio::test]
    async fn test_chunk_file_uring_convenience() {
        let mut file = NamedTempFile::new().unwrap();
        let data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
        file.write_all(&data).unwrap();
        file.flush().unwrap();

        let chunks = chunk_file_uring(file.path(), SeqCdcConfig::target_16kb())
            .await
            .unwrap();

        let total: usize = chunks.iter().map(|c| c.len()).sum();
        assert_eq!(total, data.len());
    }
}
