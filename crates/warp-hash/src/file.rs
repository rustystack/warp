//! File hashing with bounded memory and progress callbacks.
//!
//! This module provides functions for hashing files and readers with
//! streaming reads, ensuring bounded memory usage regardless of file size.

use crate::{Hash, Hasher, Result};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

/// Default buffer size for file hashing (1 MB)
const DEFAULT_BUFFER_SIZE: usize = 1024 * 1024;

/// Hash a file with streaming reads and bounded memory.
///
/// Uses a 1 MB buffer by default. For custom buffer sizes,
/// use [`hash_file_with_buffer`].
///
/// # Example
/// ```no_run
/// use warp_hash::hash_file;
///
/// let hash = hash_file("/path/to/file").unwrap();
/// println!("Hash: {:?}", hash);
/// ```
pub fn hash_file(path: impl AsRef<Path>) -> Result<Hash> {
    hash_file_with_buffer(path, DEFAULT_BUFFER_SIZE)
}

/// Hash a file with a custom buffer size.
///
/// # Arguments
/// * `path` - Path to the file
/// * `buffer_size` - Size of the read buffer in bytes
///
/// # Example
/// ```no_run
/// use warp_hash::hash_file_with_buffer;
///
/// // Use 4 MB buffer for better throughput
/// let hash = hash_file_with_buffer("/path/to/file", 4 * 1024 * 1024).unwrap();
/// ```
pub fn hash_file_with_buffer(path: impl AsRef<Path>, buffer_size: usize) -> Result<Hash> {
    let file = File::open(path)?;
    let reader = BufReader::with_capacity(buffer_size, file);
    hash_reader(reader)
}

/// Hash a file with progress callback.
///
/// The callback receives `(bytes_processed, total_bytes)` and is called
/// approximately every buffer-full of data (1 MB by default).
///
/// # Example
/// ```no_run
/// use warp_hash::hash_file_with_progress;
///
/// let hash = hash_file_with_progress("/path/to/file", |read, total| {
///     let percent = (read as f64 / total as f64) * 100.0;
///     println!("Progress: {:.1}%", percent);
/// }).unwrap();
/// ```
pub fn hash_file_with_progress<F>(path: impl AsRef<Path>, on_progress: F) -> Result<Hash>
where
    F: FnMut(u64, u64),
{
    let path = path.as_ref();
    let metadata = std::fs::metadata(path)?;
    let total = metadata.len();
    let file = File::open(path)?;
    let reader = BufReader::with_capacity(DEFAULT_BUFFER_SIZE, file);
    hash_reader_with_progress(reader, total, on_progress)
}

/// Hash from any `Read` implementation.
///
/// Reads data in 1 MB chunks and hashes incrementally.
/// Memory usage is bounded to approximately the buffer size.
///
/// # Example
/// ```
/// use warp_hash::hash_reader;
/// use std::io::Cursor;
///
/// let data = b"hello world";
/// let hash = hash_reader(Cursor::new(data)).unwrap();
/// ```
pub fn hash_reader<R: Read>(mut reader: R) -> Result<Hash> {
    let mut hasher = Hasher::new();
    let mut buffer = vec![0u8; DEFAULT_BUFFER_SIZE];

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(hasher.finalize())
}

/// Hash from a `Read` with progress callback.
///
/// # Arguments
/// * `reader` - The reader to hash from
/// * `total` - Total bytes expected (for progress calculation)
/// * `on_progress` - Callback receiving `(bytes_read, total_bytes)`
///
/// # Example
/// ```
/// use warp_hash::hash_reader_with_progress;
/// use std::io::Cursor;
///
/// let data = vec![0u8; 1024];
/// let mut progress_calls = 0;
/// let hash = hash_reader_with_progress(
///     Cursor::new(&data),
///     data.len() as u64,
///     |_, _| progress_calls += 1
/// ).unwrap();
/// ```
pub fn hash_reader_with_progress<R: Read, F>(
    mut reader: R,
    total: u64,
    mut on_progress: F,
) -> Result<Hash>
where
    F: FnMut(u64, u64),
{
    let mut hasher = Hasher::new();
    let mut buffer = vec![0u8; DEFAULT_BUFFER_SIZE];
    let mut bytes_processed: u64 = 0;

    // Report initial progress
    on_progress(0, total);

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
        bytes_processed += bytes_read as u64;
        on_progress(bytes_processed, total);
    }

    Ok(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use tempfile::NamedTempFile;

    /// Test 1: hash_file returns correct hash for small file
    #[test]
    fn test_hash_file_small() {
        let mut file = NamedTempFile::new().unwrap();
        let data = b"hello world";
        file.write_all(data).unwrap();
        file.flush().unwrap();

        let hash = hash_file(file.path()).unwrap();
        let expected = crate::hash(data);

        assert_eq!(hash, expected);
    }

    /// Test 2: hash_file works with larger data spanning multiple buffers
    #[test]
    fn test_hash_file_multi_buffer() {
        let mut file = NamedTempFile::new().unwrap();
        // Create data larger than default buffer (1 MB)
        let data: Vec<u8> = (0..2_500_000).map(|i| (i % 256) as u8).collect();
        file.write_all(&data).unwrap();
        file.flush().unwrap();

        let hash = hash_file(file.path()).unwrap();
        let expected = crate::hash(&data);

        assert_eq!(hash, expected);
    }

    /// Test 3: hash_file with progress callback reports progress
    #[test]
    fn test_hash_file_with_progress() {
        let mut file = NamedTempFile::new().unwrap();
        // 2.5 MB of data - should trigger at least 3 progress calls
        let data: Vec<u8> = (0..2_500_000).map(|i| (i % 256) as u8).collect();
        file.write_all(&data).unwrap();
        file.flush().unwrap();

        let mut progress_updates: Vec<(u64, u64)> = Vec::new();
        let hash = hash_file_with_progress(file.path(), |read, total| {
            progress_updates.push((read, total));
        })
        .unwrap();

        // Should have multiple progress updates
        assert!(
            progress_updates.len() >= 3,
            "Expected at least 3 progress updates, got {}",
            progress_updates.len()
        );

        // First should be 0, total
        assert_eq!(progress_updates[0], (0, data.len() as u64));

        // Last should be total, total
        let last = progress_updates.last().unwrap();
        assert_eq!(last.0, data.len() as u64);
        assert_eq!(last.1, data.len() as u64);

        // Hash should still be correct
        let expected = crate::hash(&data);
        assert_eq!(hash, expected);
    }

    /// Test 4: hash_file handles non-existent file with proper error
    #[test]
    fn test_hash_file_not_found() {
        let result = hash_file("/nonexistent/path/to/file.txt");
        assert!(result.is_err());

        let err = result.unwrap_err();
        match err {
            crate::Error::Io(io_err) => {
                assert_eq!(io_err.kind(), std::io::ErrorKind::NotFound);
            }
        }
    }

    /// Test 5: hash_file handles empty file correctly
    #[test]
    fn test_hash_file_empty() {
        let file = NamedTempFile::new().unwrap();

        let hash = hash_file(file.path()).unwrap();
        let expected = crate::hash(b"");

        assert_eq!(hash, expected);
    }

    /// Test 6: hash_file_with_buffer allows custom buffer size
    #[test]
    fn test_hash_file_custom_buffer() {
        let mut file = NamedTempFile::new().unwrap();
        let data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
        file.write_all(&data).unwrap();
        file.flush().unwrap();

        // Use small buffer (4 KB)
        let hash_small = hash_file_with_buffer(file.path(), 4 * 1024).unwrap();

        // Use large buffer (1 MB)
        let hash_large = hash_file_with_buffer(file.path(), 1024 * 1024).unwrap();

        // Both should produce same hash
        assert_eq!(hash_small, hash_large);

        // And match direct hash
        let expected = crate::hash(&data);
        assert_eq!(hash_small, expected);
    }

    /// Test 7: hash_reader works correctly
    #[test]
    fn test_hash_reader() {
        let data = b"test data for hashing";
        let reader = Cursor::new(data);

        let hash = hash_reader(reader).unwrap();
        let expected = crate::hash(data);

        assert_eq!(hash, expected);
    }

    /// Test 8: hash matches incremental Hasher for same content
    #[test]
    fn test_hash_reader_matches_incremental() {
        let data: Vec<u8> = (0..500_000).map(|i| (i % 256) as u8).collect();

        // Hash via reader
        let reader_hash = hash_reader(Cursor::new(&data)).unwrap();

        // Hash via incremental hasher
        let mut hasher = Hasher::new();
        for chunk in data.chunks(1000) {
            hasher.update(chunk);
        }
        let incremental_hash = hasher.finalize();

        // Hash via single-shot
        let direct_hash = crate::hash(&data);

        assert_eq!(reader_hash, incremental_hash);
        assert_eq!(reader_hash, direct_hash);
    }

    /// Test 9: progress callback receives monotonically increasing values
    #[test]
    fn test_progress_monotonic() {
        let data: Vec<u8> = (0..3_000_000).map(|i| (i % 256) as u8).collect();
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(&data).unwrap();
        file.flush().unwrap();

        let mut last_read = 0u64;
        hash_file_with_progress(file.path(), |read, total| {
            assert!(
                read >= last_read,
                "Progress should be monotonically increasing"
            );
            assert!(read <= total, "Progress should not exceed total");
            last_read = read;
        })
        .unwrap();

        assert_eq!(last_read, data.len() as u64);
    }

    /// Test 10: hash_reader_with_progress works with known length
    #[test]
    fn test_hash_reader_with_progress() {
        let data = vec![42u8; 5_000_000];
        let mut progress_count = 0;

        let hash = hash_reader_with_progress(Cursor::new(&data), data.len() as u64, |_, _| {
            progress_count += 1
        })
        .unwrap();

        // Should have called progress multiple times
        assert!(
            progress_count >= 5,
            "Expected at least 5 progress calls for 5MB, got {}",
            progress_count
        );

        // Hash should be correct
        let expected = crate::hash(&data);
        assert_eq!(hash, expected);
    }
}
