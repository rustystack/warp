//! Async content-defined chunking using SeqCDC with tokio.
//!
//! This module provides async versions of the chunking functionality,
//! allowing non-blocking I/O operations for better concurrency.
//!
//! # Algorithm
//!
//! Uses the SeqCDC algorithm which detects chunk boundaries by finding
//! monotonically increasing/decreasing byte sequences. This is significantly
//! faster than traditional rolling hash approaches.

use crate::{SeqCdcConfig, SeqMode, Result};
use std::collections::VecDeque;
use std::path::Path;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;

/// Async chunk a file using content-defined chunking (SeqCDC).
///
/// This reads the file asynchronously and produces chunks using the SeqCDC
/// algorithm. Memory usage is bounded to approximately the max chunk size.
///
/// # Example
/// ```no_run
/// use warp_io::{chunk_file_async, SeqCdcConfig};
///
/// # async fn example() -> warp_io::Result<()> {
/// let chunks = chunk_file_async("/path/to/file", SeqCdcConfig::target_16kb()).await?;
/// println!("Got {} chunks", chunks.len());
/// # Ok(())
/// # }
/// ```
pub async fn chunk_file_async(
    path: impl AsRef<Path>,
    config: impl Into<SeqCdcConfig>,
) -> Result<Vec<Vec<u8>>> {
    let file = tokio::fs::File::open(path).await?;
    let config = config.into();
    chunk_async_reader(file, config).await
}

/// Stream chunks through a channel for pipeline processing.
///
/// This spawns a background task that reads the file and sends chunks
/// through an mpsc channel. The channel has a bounded capacity for backpressure.
///
/// # Arguments
/// * `path` - Path to the file
/// * `config` - Chunker configuration (SeqCdcConfig or ChunkerConfig)
/// * `channel_capacity` - Maximum number of chunks to buffer (for backpressure)
///
/// # Example
/// ```no_run
/// use warp_io::{chunk_file_stream, SeqCdcConfig};
///
/// # async fn example() -> warp_io::Result<()> {
/// let mut rx = chunk_file_stream("/path/to/file", SeqCdcConfig::target_16kb(), 16);
/// while let Some(result) = rx.recv().await {
///     let chunk = result?;
///     println!("Received chunk of {} bytes", chunk.len());
/// }
/// # Ok(())
/// # }
/// ```
pub fn chunk_file_stream(
    path: impl AsRef<Path> + Send + 'static,
    config: impl Into<SeqCdcConfig> + Send + 'static,
    channel_capacity: usize,
) -> mpsc::Receiver<Result<Vec<u8>>> {
    let (tx, rx) = mpsc::channel(channel_capacity);
    let path = path.as_ref().to_path_buf();
    let config = config.into();

    tokio::spawn(async move {
        let result = stream_chunks_to_channel(path, config, tx.clone()).await;
        if let Err(e) = result {
            // Try to send error, ignore if receiver dropped
            let _ = tx.send(Err(e)).await;
        }
    });

    rx
}

/// Internal function to stream chunks to a channel using SeqCDC.
async fn stream_chunks_to_channel(
    path: impl AsRef<Path>,
    config: SeqCdcConfig,
    tx: mpsc::Sender<Result<Vec<u8>>>,
) -> Result<()> {
    let file = tokio::fs::File::open(path).await?;
    let mut reader = file;
    let mut buffer = vec![0u8; 64 * 1024]; // 64KB read buffer
    let mut current_chunk = Vec::with_capacity(config.target_size);

    // Window for boundary detection - use VecDeque for O(1) pop_front
    let mut window: VecDeque<u8> = VecDeque::with_capacity(config.seq_length + 1);

    // Content-based skipping state
    let mut opposing_count = 0usize;
    let mut skip_remaining = 0usize;

    loop {
        let n = reader.read(&mut buffer).await?;
        if n == 0 {
            break;
        }

        let mut i = 0;
        while i < n {
            let byte = buffer[i];

            // Handle skip mode
            if skip_remaining > 0 {
                current_chunk.push(byte);
                skip_remaining -= 1;
                i += 1;

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

            // Update window - O(1) operations with VecDeque
            window.push_back(byte);
            if window.len() > config.seq_length {
                window.pop_front();
            }

            current_chunk.push(byte);
            i += 1;

            let size = current_chunk.len();

            // Check for boundary after minimum size
            if size >= config.min_size {
                let at_boundary = is_monotonic_boundary(&window, &config) || size >= config.max_size;

                if at_boundary {
                    let chunk = std::mem::take(&mut current_chunk);
                    if tx.send(Ok(chunk)).await.is_err() {
                        // Receiver dropped, stop processing
                        return Ok(());
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
    }

    // Don't forget the last chunk
    if !current_chunk.is_empty() {
        let _ = tx.send(Ok(current_chunk)).await;
    }

    Ok(())
}

/// Check if window ends with a monotonic sequence (SeqCDC boundary detection)
#[inline]
fn is_monotonic_boundary(window: &VecDeque<u8>, config: &SeqCdcConfig) -> bool {
    if window.len() < config.seq_length {
        return false;
    }

    // Check last seq_length bytes for monotonic pattern
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

/// Async chunk from any AsyncRead source using SeqCDC.
async fn chunk_async_reader<R>(mut reader: R, config: SeqCdcConfig) -> Result<Vec<Vec<u8>>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut chunks = Vec::new();
    let mut buffer = vec![0u8; 64 * 1024];
    let mut current_chunk = Vec::with_capacity(config.target_size);

    // Window for boundary detection - use VecDeque for O(1) pop_front
    let mut window: VecDeque<u8> = VecDeque::with_capacity(config.seq_length + 1);

    // Content-based skipping state
    let mut opposing_count = 0usize;
    let mut skip_remaining = 0usize;

    loop {
        let n = reader.read(&mut buffer).await?;
        if n == 0 {
            break;
        }

        let mut i = 0;
        while i < n {
            let byte = buffer[i];

            // Handle skip mode
            if skip_remaining > 0 {
                current_chunk.push(byte);
                skip_remaining -= 1;
                i += 1;

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

            // Update window - O(1) operations with VecDeque
            window.push_back(byte);
            if window.len() > config.seq_length {
                window.pop_front();
            }

            current_chunk.push(byte);
            i += 1;

            let size = current_chunk.len();

            // Check for boundary after minimum size
            if size >= config.min_size {
                let at_boundary = is_monotonic_boundary(&window, &config) || size >= config.max_size;

                if at_boundary {
                    chunks.push(std::mem::take(&mut current_chunk));
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
    }

    // Don't forget the last chunk
    if !current_chunk.is_empty() {
        chunks.push(current_chunk);
    }

    Ok(chunks)
}

// Note: From<ChunkerConfig> for SeqCdcConfig is implemented in chunker.rs

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ChunkerConfig;
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// Test 1: async_chunk works with SeqCdcConfig
    #[tokio::test]
    async fn test_async_seqcdc() {
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

        let chunks = chunk_file_async(file.path(), config).await.unwrap();

        // Verify all data is accounted for
        let total: usize = chunks.iter().map(|c| c.len()).sum();
        assert_eq!(total, data.len());
    }

    /// Test 2: async_chunk with legacy ChunkerConfig (backward compat)
    #[tokio::test]
    async fn test_async_legacy_config() {
        let mut file = NamedTempFile::new().unwrap();
        let data: Vec<u8> = (0..50_000).map(|i| (i % 256) as u8).collect();
        file.write_all(&data).unwrap();
        file.flush().unwrap();

        let config = ChunkerConfig {
            min_size: 1024,
            target_size: 4096,
            max_size: 8192,
            window_size: 32, // Ignored in SeqCDC
        };

        let chunks = chunk_file_async(file.path(), config).await.unwrap();

        // Verify all data is accounted for
        let total: usize = chunks.iter().map(|c| c.len()).sum();
        assert_eq!(total, data.len());
    }

    /// Test 3: async_chunk respects min/target/max sizes
    #[tokio::test]
    async fn test_async_chunk_sizes() {
        let mut file = NamedTempFile::new().unwrap();
        let data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
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

        let chunks = chunk_file_async(file.path(), config.clone()).await.unwrap();

        // All chunks except last should respect min_size
        for chunk in chunks.iter().take(chunks.len().saturating_sub(1)) {
            assert!(
                chunk.len() >= config.min_size,
                "Chunk size {} is less than min_size {}",
                chunk.len(),
                config.min_size
            );
        }

        // All chunks should respect max_size
        for chunk in &chunks {
            assert!(
                chunk.len() <= config.max_size,
                "Chunk size {} exceeds max_size {}",
                chunk.len(),
                config.max_size
            );
        }
    }

    /// Test 4: chunk_stream produces chunks via channel
    #[tokio::test]
    async fn test_chunk_stream() {
        let mut file = NamedTempFile::new().unwrap();
        let data: Vec<u8> = (0..50_000).map(|i| (i % 256) as u8).collect();
        file.write_all(&data).unwrap();
        file.flush().unwrap();

        let config = SeqCdcConfig::target_8kb();
        let mut rx = chunk_file_stream(file.path().to_path_buf(), config, 16);

        let mut chunks = Vec::new();
        while let Some(result) = rx.recv().await {
            chunks.push(result.unwrap());
        }

        // Verify all data is accounted for
        let total: usize = chunks.iter().map(|c| c.len()).sum();
        assert_eq!(total, data.len());
    }

    /// Test 5: async_chunk handles empty input
    #[tokio::test]
    async fn test_async_empty_file() {
        let file = NamedTempFile::new().unwrap();

        let chunks = chunk_file_async(file.path(), SeqCdcConfig::default())
            .await
            .unwrap();

        assert!(chunks.is_empty());
    }

    /// Test 6: async_chunk handles input smaller than min_size
    #[tokio::test]
    async fn test_async_small_input() {
        let mut file = NamedTempFile::new().unwrap();
        let data = b"small";
        file.write_all(data).unwrap();
        file.flush().unwrap();

        let config = SeqCdcConfig {
            min_size: 1024,
            target_size: 4096,
            max_size: 8192,
            ..Default::default()
        };

        let chunks = chunk_file_async(file.path(), config).await.unwrap();

        // Should produce exactly one chunk with all data
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], data);
    }

    /// Test 7: concurrent chunking of multiple files
    #[tokio::test]
    async fn test_concurrent_chunking() {
        let files: Vec<_> = (0..5)
            .map(|i| {
                let mut file = NamedTempFile::new().unwrap();
                let data: Vec<u8> = (0..10_000).map(|j| ((i * 100 + j) % 256) as u8).collect();
                file.write_all(&data).unwrap();
                file.flush().unwrap();
                (file, data)
            })
            .collect();

        let config = SeqCdcConfig::target_4kb();

        // Chunk all files concurrently using JoinSet
        let mut set = tokio::task::JoinSet::new();
        for (file, _) in files.iter() {
            let path = file.path().to_path_buf();
            let config = config.clone();
            set.spawn(async move { chunk_file_async(path, config).await });
        }

        let mut results = Vec::new();
        while let Some(result) = set.join_next().await {
            results.push(result.unwrap().unwrap());
        }

        // Verify each result has correct total size
        assert_eq!(results.len(), 5);
        for chunks in &results {
            let total: usize = chunks.iter().map(|c| c.len()).sum();
            assert_eq!(total, 10_000);
        }
    }

    /// Test 8: backpressure handling with bounded channel
    #[tokio::test]
    async fn test_backpressure() {
        let mut file = NamedTempFile::new().unwrap();
        // Large data to ensure many chunks
        let data: Vec<u8> = (0..500_000).map(|i| (i % 256) as u8).collect();
        file.write_all(&data).unwrap();
        file.flush().unwrap();

        let config = SeqCdcConfig::target_8kb();

        // Very small channel capacity to test backpressure
        let mut rx = chunk_file_stream(file.path().to_path_buf(), config, 2);

        let mut chunks = Vec::new();
        let mut count = 0;
        while let Some(result) = rx.recv().await {
            let chunk = result.unwrap();
            chunks.push(chunk);
            count += 1;

            // Simulate slow consumer
            if count % 5 == 0 {
                tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
            }
        }

        // Verify all data received despite backpressure
        let total: usize = chunks.iter().map(|c| c.len()).sum();
        assert_eq!(total, data.len());
    }

    /// Test 9: non-existent file returns error
    #[tokio::test]
    async fn test_async_file_not_found() {
        let result = chunk_file_async("/nonexistent/path", SeqCdcConfig::default()).await;
        assert!(result.is_err());
    }

    /// Test 10: stream handles file not found
    #[tokio::test]
    async fn test_stream_file_not_found() {
        let mut rx = chunk_file_stream(
            "/nonexistent/path".to_string(),
            SeqCdcConfig::default(),
            16,
        );

        let result = rx.recv().await;
        assert!(result.is_some());
        assert!(result.unwrap().is_err());
    }

    /// Test 11: SeqCDC config presets work with async
    #[tokio::test]
    async fn test_async_config_presets() {
        let mut file = NamedTempFile::new().unwrap();
        let data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
        file.write_all(&data).unwrap();
        file.flush().unwrap();

        // Test various presets
        for config in [
            SeqCdcConfig::target_4kb(),
            SeqCdcConfig::target_8kb(),
            SeqCdcConfig::target_16kb(),
            SeqCdcConfig::target_64kb(),
        ] {
            let chunks = chunk_file_async(file.path(), config).await.unwrap();
            let total: usize = chunks.iter().map(|c| c.len()).sum();
            assert_eq!(total, data.len());
        }
    }
}
