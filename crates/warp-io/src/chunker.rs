//! Content-defined chunking algorithms
//!
//! This module provides two CDC algorithms:
//! - **SeqCDC** (default): High-performance monotonic sequence detection
//! - **Buzhash**: Traditional rolling hash algorithm
//!
//! SeqCDC achieves ~30 GB/s with AVX-512 vs ~189 MB/s for Buzhash.

use std::io::Read;

// ============================================================================
// SeqCDC - High-Performance Monotonic Sequence Chunker
// ============================================================================

/// Detection mode for SeqCDC
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SeqMode {
    /// Look for ascending byte sequences (default)
    #[default]
    Increasing,
    /// Look for descending byte sequences
    Decreasing,
}

/// SeqCDC configuration
///
/// Parameters are tuned based on target chunk size per the SeqCDC paper:
/// - 4KB:  seq_length=5, skip_trigger=55, skip_size=256
/// - 8KB:  seq_length=5, skip_trigger=50, skip_size=256
/// - 16KB: seq_length=5, skip_trigger=50, skip_size=512
#[derive(Debug, Clone)]
pub struct SeqCdcConfig {
    /// Minimum chunk size
    pub min_size: usize,
    /// Target chunk size (used to auto-tune parameters)
    pub target_size: usize,
    /// Maximum chunk size
    pub max_size: usize,
    /// Length of monotonic sequence to detect (default: 5)
    pub seq_length: usize,
    /// Number of opposing byte-pairs before skipping (default: 50)
    pub skip_trigger: usize,
    /// Bytes to skip when in unfavorable region (default: 256-512)
    pub skip_size: usize,
    /// Detection mode (increasing or decreasing)
    pub mode: SeqMode,
}

impl SeqCdcConfig {
    /// Create config with automatic parameter tuning based on target size
    pub fn with_target(target_size: usize) -> Self {
        let (skip_trigger, skip_size) = if target_size <= 4096 {
            (55, 256)
        } else if target_size <= 8192 {
            (50, 256)
        } else {
            (50, 512)
        };

        Self {
            min_size: target_size / 4,
            target_size,
            max_size: target_size * 4,
            seq_length: 5,
            skip_trigger,
            skip_size,
            mode: SeqMode::Increasing,
        }
    }

    /// Create config for 4KB target chunks
    pub fn target_4kb() -> Self {
        Self::with_target(4096)
    }

    /// Create config for 8KB target chunks
    pub fn target_8kb() -> Self {
        Self::with_target(8192)
    }

    /// Create config for 16KB target chunks
    pub fn target_16kb() -> Self {
        Self::with_target(16384)
    }

    /// Create config for 64KB target chunks (good for larger files)
    pub fn target_64kb() -> Self {
        Self::with_target(65536)
    }

    /// Create config for 256KB target chunks
    pub fn target_256kb() -> Self {
        Self::with_target(262144)
    }

    /// Create config for 1MB target chunks (matches old default)
    pub fn target_1mb() -> Self {
        Self {
            min_size: 256 * 1024,
            target_size: 1024 * 1024,
            max_size: 4 * 1024 * 1024,
            seq_length: 5,
            skip_trigger: 50,
            skip_size: 1024,
            mode: SeqMode::Increasing,
        }
    }
}

impl Default for SeqCdcConfig {
    fn default() -> Self {
        // Default to 64KB chunks - good balance for most use cases
        Self::target_64kb()
    }
}

/// High-performance content-defined chunker using SeqCDC algorithm
///
/// SeqCDC detects chunk boundaries by finding monotonically increasing
/// or decreasing byte sequences, avoiding expensive hash computations.
///
/// # Algorithm
///
/// 1. **Monotonic sequence detection**: Instead of rolling hash, detect
///    sequences of `seq_length` bytes where each byte is strictly greater
///    (or less) than the previous.
///
/// 2. **Content-based skipping**: When encountering unfavorable regions
///    (too many opposing byte-pairs), skip ahead to avoid wasted scanning.
///
/// 3. **SIMD acceleration**: AVX2/AVX-512 can process 32-64 bytes in parallel.
///
/// # Performance
///
/// - Scalar: 5-10 GB/s
/// - AVX2: 15-20 GB/s
/// - AVX-512: 30+ GB/s
pub struct SeqCdcChunker {
    config: SeqCdcConfig,
}

impl SeqCdcChunker {
    /// Create a new SeqCDC chunker
    ///
    /// Accepts either `SeqCdcConfig` or legacy `ChunkerConfig` for backward compatibility.
    pub fn new(config: impl Into<SeqCdcConfig>) -> Self {
        Self { config: config.into() }
    }

    /// Get the chunker configuration
    pub fn config(&self) -> &SeqCdcConfig {
        &self.config
    }

    /// Check if the last `seq_length` bytes form a monotonic sequence
    #[inline]
    fn is_boundary(&self, window: &[u8]) -> bool {
        if window.len() < self.config.seq_length {
            return false;
        }

        let start = window.len() - self.config.seq_length;
        let seq = &window[start..];

        match self.config.mode {
            SeqMode::Increasing => seq.windows(2).all(|w| w[0] < w[1]),
            SeqMode::Decreasing => seq.windows(2).all(|w| w[0] > w[1]),
        }
    }

    /// Check if a byte pair is opposing (for skip heuristic)
    #[inline]
    fn is_opposing_pair(&self, prev: u8, curr: u8) -> bool {
        match self.config.mode {
            SeqMode::Increasing => prev >= curr,
            SeqMode::Decreasing => prev <= curr,
        }
    }

    /// Chunk data from a reader using scalar implementation
    pub fn chunk<R: Read>(&self, mut reader: R) -> crate::Result<Vec<Vec<u8>>> {
        let mut chunks = Vec::new();
        let mut buffer = vec![0u8; 64 * 1024]; // 64KB read buffer
        let mut current_chunk = Vec::with_capacity(self.config.target_size);

        // Window to track recent bytes for boundary detection
        let mut window: Vec<u8> = Vec::with_capacity(self.config.seq_length);

        // Counter for content-based skipping
        let mut opposing_count = 0usize;
        let mut skip_remaining = 0usize;

        loop {
            let n = reader.read(&mut buffer)?;
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

                    // Reset window after skip
                    if skip_remaining == 0 {
                        window.clear();
                        opposing_count = 0;
                    }
                    continue;
                }

                // Track opposing pairs for skip heuristic
                if let Some(&prev) = window.last() {
                    if self.is_opposing_pair(prev, byte) {
                        opposing_count += 1;
                    } else {
                        opposing_count = 0;
                    }
                }

                // Update window
                window.push(byte);
                if window.len() > self.config.seq_length {
                    window.remove(0);
                }

                current_chunk.push(byte);
                i += 1;

                let size = current_chunk.len();

                // Check for boundary after minimum size
                if size >= self.config.min_size {
                    let at_boundary = self.is_boundary(&window) || size >= self.config.max_size;

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
        }

        // Don't forget the last chunk
        if !current_chunk.is_empty() {
            chunks.push(current_chunk);
        }

        Ok(chunks)
    }

    /// Chunk data with SIMD acceleration (auto-detects best available)
    ///
    /// On x86_64, uses AVX-512 or AVX2 if available, otherwise falls back to scalar.
    /// On other architectures, uses scalar implementation.
    ///
    /// # Performance
    ///
    /// - AVX-512: ~30+ GB/s
    /// - AVX2: ~15-20 GB/s
    /// - Scalar: ~5-10 GB/s
    pub fn chunk_simd<R: Read>(&self, mut reader: R) -> crate::Result<Vec<Vec<u8>>> {
        // Read all data into memory for SIMD processing
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;

        if data.is_empty() {
            return Ok(Vec::new());
        }

        // Use the SIMD module for chunking
        let chunk_ranges = crate::simd::chunk_buffer_auto(
            &data,
            self.config.min_size,
            self.config.max_size,
            self.config.seq_length,
            self.config.skip_trigger,
            self.config.skip_size,
            self.config.mode,
        );

        // Convert ranges to actual chunk data
        let chunks: Vec<Vec<u8>> = chunk_ranges
            .into_iter()
            .map(|(start, len)| data[start..start + len].to_vec())
            .collect();

        Ok(chunks)
    }

    /// Chunk data using optimized SIMD with memory-mapped input
    ///
    /// For maximum throughput, use this with memory-mapped files.
    /// Processes the entire buffer using SIMD instructions.
    pub fn chunk_buffer(&self, data: &[u8]) -> Vec<Vec<u8>> {
        if data.is_empty() {
            return Vec::new();
        }

        let chunk_ranges = crate::simd::chunk_buffer_auto(
            data,
            self.config.min_size,
            self.config.max_size,
            self.config.seq_length,
            self.config.skip_trigger,
            self.config.skip_size,
            self.config.mode,
        );

        chunk_ranges
            .into_iter()
            .map(|(start, len)| data[start..start + len].to_vec())
            .collect()
    }

    /// Get chunk boundaries without copying data
    ///
    /// Returns (start, length) pairs for each chunk.
    /// Useful for zero-copy processing pipelines.
    pub fn chunk_boundaries(&self, data: &[u8]) -> Vec<(usize, usize)> {
        if data.is_empty() {
            return Vec::new();
        }

        crate::simd::chunk_buffer_auto(
            data,
            self.config.min_size,
            self.config.max_size,
            self.config.seq_length,
            self.config.skip_trigger,
            self.config.skip_size,
            self.config.mode,
        )
    }
}

impl Default for SeqCdcChunker {
    fn default() -> Self {
        Self::new(SeqCdcConfig::default())
    }
}

// ============================================================================
// Legacy Buzhash Chunker (for backward compatibility)
// ============================================================================

/// Legacy chunker configuration (Buzhash-based)
#[derive(Debug, Clone)]
pub struct ChunkerConfig {
    /// Minimum chunk size
    pub min_size: usize,
    /// Target chunk size
    pub target_size: usize,
    /// Maximum chunk size
    pub max_size: usize,
    /// Window size for rolling hash
    pub window_size: usize,
}

impl Default for ChunkerConfig {
    fn default() -> Self {
        Self {
            min_size: 1024 * 1024,       // 1MB
            target_size: 4 * 1024 * 1024, // 4MB
            max_size: 16 * 1024 * 1024,   // 16MB
            window_size: 48,
        }
    }
}

impl From<ChunkerConfig> for SeqCdcConfig {
    fn from(config: ChunkerConfig) -> Self {
        SeqCdcConfig {
            min_size: config.min_size,
            target_size: config.target_size,
            max_size: config.max_size,
            seq_length: 5,
            skip_trigger: 50,
            skip_size: config.target_size / 16,
            mode: SeqMode::Increasing,
        }
    }
}

/// Content-defined chunker using Buzhash rolling hash
///
/// This is the legacy chunker preserved for backward compatibility.
/// For new code, prefer `SeqCdcChunker` which is significantly faster.
pub struct BuzhashChunker {
    config: ChunkerConfig,
    mask: u64,
    table: [u64; 256],
}

impl BuzhashChunker {
    /// Create a new Buzhash chunker
    pub fn new(config: ChunkerConfig) -> Self {
        // Calculate mask for target size (find boundary when hash & mask == 0)
        let bits = (config.target_size as f64).log2() as u32;
        let mask = (1u64 << bits) - 1;

        // Initialize Buzhash table with pseudo-random values
        let mut table = [0u64; 256];
        let mut state = 0x123456789ABCDEFu64;
        for entry in &mut table {
            // Simple xorshift
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *entry = state;
        }

        Self { config, mask, table }
    }

    /// Get the chunker configuration
    pub fn config(&self) -> &ChunkerConfig {
        &self.config
    }

    /// Get the Buzhash table
    pub fn table(&self) -> &[u64; 256] {
        &self.table
    }

    /// Get the boundary mask
    pub fn mask(&self) -> u64 {
        self.mask
    }

    /// Chunk data from a reader
    pub fn chunk<R: Read>(&self, mut reader: R) -> crate::Result<Vec<Vec<u8>>> {
        let mut chunks = Vec::new();
        let mut buffer = vec![0u8; self.config.max_size];
        let mut current_chunk = Vec::with_capacity(self.config.target_size);
        let mut hash = 0u64;

        // Use fixed-size circular buffer instead of Vec for O(1) operations
        let mut window = [0u8; 64];
        let mut window_pos = 0usize;
        let mut window_len = 0usize;
        let window_size = self.config.window_size;

        loop {
            let n = reader.read(&mut buffer)?;
            if n == 0 {
                break;
            }

            for &byte in &buffer[..n] {
                // Update rolling hash using circular buffer
                if window_len >= window_size {
                    let old_byte = window[window_pos];
                    hash ^= self.table[old_byte as usize].rotate_left(window_size as u32);
                } else {
                    window_len += 1;
                }
                window[window_pos] = byte;
                window_pos = (window_pos + 1) % window_size;
                hash = hash.rotate_left(1) ^ self.table[byte as usize];

                current_chunk.push(byte);

                // Check for chunk boundary
                let size = current_chunk.len();
                if size >= self.config.min_size
                    && ((hash & self.mask) == 0 || size >= self.config.max_size)
                {
                    chunks.push(std::mem::take(&mut current_chunk));
                    current_chunk = Vec::with_capacity(self.config.target_size);
                    hash = 0;
                    window_pos = 0;
                    window_len = 0;
                }
            }
        }

        // Don't forget the last chunk
        if !current_chunk.is_empty() {
            chunks.push(current_chunk);
        }

        Ok(chunks)
    }
}

impl Default for BuzhashChunker {
    fn default() -> Self {
        Self::new(ChunkerConfig::default())
    }
}

// ============================================================================
// Type Aliases for Backward Compatibility
// ============================================================================

/// Default chunker type (SeqCDC for performance)
///
/// Use `BuzhashChunker` if you need the legacy algorithm.
pub type Chunker = SeqCdcChunker;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_seqcdc_basic() {
        let config = SeqCdcConfig {
            min_size: 64,
            target_size: 256,
            max_size: 1024,
            seq_length: 3,
            skip_trigger: 10,
            skip_size: 32,
            mode: SeqMode::Increasing,
        };

        let chunker = SeqCdcChunker::new(config);
        let data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();

        let chunks = chunker.chunk(Cursor::new(&data)).unwrap();

        // Verify all data is accounted for
        let total: usize = chunks.iter().map(|c| c.len()).sum();
        assert_eq!(total, data.len());

        // Verify chunks respect size limits
        for chunk in &chunks {
            assert!(chunk.len() <= 1024, "chunk too large: {}", chunk.len());
        }
    }

    #[test]
    fn test_seqcdc_decreasing_mode() {
        let config = SeqCdcConfig {
            min_size: 64,
            target_size: 256,
            max_size: 1024,
            seq_length: 3,
            skip_trigger: 10,
            skip_size: 32,
            mode: SeqMode::Decreasing,
        };

        let chunker = SeqCdcChunker::new(config);
        // Create data with decreasing sequences
        let data: Vec<u8> = (0..10000).map(|i| (255 - (i % 256)) as u8).collect();

        let chunks = chunker.chunk(Cursor::new(&data)).unwrap();

        let total: usize = chunks.iter().map(|c| c.len()).sum();
        assert_eq!(total, data.len());
    }

    #[test]
    fn test_seqcdc_boundary_detection() {
        let chunker = SeqCdcChunker::new(SeqCdcConfig {
            seq_length: 3,
            mode: SeqMode::Increasing,
            ..Default::default()
        });

        // Test increasing sequence boundary
        assert!(chunker.is_boundary(&[1, 2, 3]));
        assert!(chunker.is_boundary(&[0, 1, 2, 3]));
        assert!(!chunker.is_boundary(&[3, 2, 1]));
        assert!(!chunker.is_boundary(&[1, 2, 2])); // Equal not strictly increasing
    }

    #[test]
    fn test_seqcdc_config_presets() {
        let config_4k = SeqCdcConfig::target_4kb();
        assert_eq!(config_4k.target_size, 4096);
        assert_eq!(config_4k.skip_trigger, 55);
        assert_eq!(config_4k.skip_size, 256);

        let config_16k = SeqCdcConfig::target_16kb();
        assert_eq!(config_16k.target_size, 16384);
        assert_eq!(config_16k.skip_trigger, 50);
        assert_eq!(config_16k.skip_size, 512);
    }

    #[test]
    fn test_buzhash_backward_compat() {
        let config = ChunkerConfig {
            min_size: 64,
            target_size: 256,
            max_size: 1024,
            window_size: 16,
        };

        let chunker = BuzhashChunker::new(config);
        let data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();

        let chunks = chunker.chunk(Cursor::new(&data)).unwrap();

        // Verify all data is accounted for
        let total: usize = chunks.iter().map(|c| c.len()).sum();
        assert_eq!(total, data.len());

        // Verify chunks respect max size
        for chunk in &chunks {
            assert!(chunk.len() <= 1024);
        }
    }

    #[test]
    fn test_chunker_alias() {
        // Verify that Chunker is SeqCdcChunker
        let chunker: Chunker = Chunker::default();
        let data: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();

        let chunks = chunker.chunk(Cursor::new(&data)).unwrap();
        let total: usize = chunks.iter().map(|c| c.len()).sum();
        assert_eq!(total, data.len());
    }

    #[test]
    fn test_seqcdc_random_data() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let config = SeqCdcConfig::target_8kb();
        let chunker = SeqCdcChunker::new(config);

        // Generate pseudo-random data
        let mut data = Vec::with_capacity(1_000_000);
        let mut hasher = DefaultHasher::new();
        for i in 0..1_000_000u64 {
            i.hash(&mut hasher);
            data.push((hasher.finish() % 256) as u8);
        }

        let chunks = chunker.chunk(Cursor::new(&data)).unwrap();

        // Verify integrity
        let total: usize = chunks.iter().map(|c| c.len()).sum();
        assert_eq!(total, data.len());

        // Check chunk count is reasonable
        let expected_chunks = data.len() / 8192; // Approximate
        assert!(
            chunks.len() > expected_chunks / 4 && chunks.len() < expected_chunks * 4,
            "Unexpected chunk count: {} (expected ~{})",
            chunks.len(),
            expected_chunks
        );
    }

    #[test]
    fn test_seqcdc_empty_input() {
        let chunker = SeqCdcChunker::default();
        let chunks = chunker.chunk(Cursor::new(&[] as &[u8])).unwrap();
        assert!(chunks.is_empty());
    }

    #[test]
    fn test_seqcdc_small_input() {
        let config = SeqCdcConfig {
            min_size: 100,
            target_size: 200,
            max_size: 400,
            ..Default::default()
        };
        let chunker = SeqCdcChunker::new(config);

        // Input smaller than min_size should be one chunk
        let data: Vec<u8> = (0..50).collect();
        let chunks = chunker.chunk(Cursor::new(&data)).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].len(), 50);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_seqcdc_simd() {
        let config = SeqCdcConfig::target_8kb();
        let chunker = SeqCdcChunker::new(config);

        let data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();

        let chunks_scalar = chunker.chunk(Cursor::new(&data)).unwrap();
        let chunks_simd = chunker.chunk_simd(Cursor::new(&data)).unwrap();

        // Both should produce same total length
        let total_scalar: usize = chunks_scalar.iter().map(|c| c.len()).sum();
        let total_simd: usize = chunks_simd.iter().map(|c| c.len()).sum();

        assert_eq!(total_scalar, data.len());
        assert_eq!(total_simd, data.len());
    }
}
