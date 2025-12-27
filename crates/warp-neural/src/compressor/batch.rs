//! Batch neural compression
//!
//! Provides parallel compression of multiple data chunks.

use rayon::prelude::*;
use tracing::debug;
use warp_compress::Compressor;

use crate::error::Result;
use crate::model::ModelConfig;

use super::walloc::{QualityConfig, WallocCompressor};

/// Batch neural compressor for processing multiple chunks in parallel
pub struct BatchNeuralCompressor {
    /// Underlying compressor
    compressor: WallocCompressor,

    /// Maximum batch size
    max_batch_size: usize,
}

impl BatchNeuralCompressor {
    /// Create a new batch compressor with default settings
    pub fn new() -> Result<Self> {
        Self::with_config(ModelConfig::default(), QualityConfig::default())
    }

    /// Create with custom configuration
    pub fn with_config(model_config: ModelConfig, quality_config: QualityConfig) -> Result<Self> {
        Ok(Self {
            compressor: WallocCompressor::with_config(model_config, quality_config)?,
            max_batch_size: 256,
        })
    }

    /// Set maximum batch size
    #[must_use]
    pub fn with_max_batch_size(mut self, size: usize) -> Self {
        self.max_batch_size = size;
        self
    }

    /// Compress multiple chunks in parallel
    pub fn compress_batch(&self, chunks: &[&[u8]]) -> warp_compress::Result<Vec<Vec<u8>>> {
        debug!(chunks = chunks.len(), "Starting batch compression");

        let results: Vec<warp_compress::Result<Vec<u8>>> = chunks
            .par_iter()
            .map(|chunk| self.compressor.compress(chunk))
            .collect();

        // Collect results, propagating any errors
        let mut compressed = Vec::with_capacity(chunks.len());
        for result in results {
            compressed.push(result?);
        }

        debug!(
            chunks = chunks.len(),
            total_original = chunks.iter().map(|c| c.len()).sum::<usize>(),
            total_compressed = compressed.iter().map(|c| c.len()).sum::<usize>(),
            "Batch compression complete"
        );

        Ok(compressed)
    }

    /// Decompress multiple chunks in parallel
    pub fn decompress_batch(&self, chunks: &[&[u8]]) -> warp_compress::Result<Vec<Vec<u8>>> {
        debug!(chunks = chunks.len(), "Starting batch decompression");

        let results: Vec<warp_compress::Result<Vec<u8>>> = chunks
            .par_iter()
            .map(|chunk| self.compressor.decompress(chunk))
            .collect();

        // Collect results, propagating any errors
        let mut decompressed = Vec::with_capacity(chunks.len());
        for result in results {
            decompressed.push(result?);
        }

        debug!(
            chunks = chunks.len(),
            total_decompressed = decompressed.iter().map(|c| c.len()).sum::<usize>(),
            "Batch decompression complete"
        );

        Ok(decompressed)
    }

    /// Compress chunks with size information
    ///
    /// Returns (compressed_chunks, original_sizes, compressed_sizes)
    pub fn compress_batch_with_stats(
        &self,
        chunks: &[&[u8]],
    ) -> warp_compress::Result<(Vec<Vec<u8>>, Vec<usize>, Vec<usize>)> {
        let original_sizes: Vec<usize> = chunks.iter().map(|c| c.len()).collect();
        let compressed = self.compress_batch(chunks)?;
        let compressed_sizes: Vec<usize> = compressed.iter().map(|c| c.len()).collect();

        Ok((compressed, original_sizes, compressed_sizes))
    }

    /// Get the maximum batch size
    #[must_use]
    pub fn max_batch_size(&self) -> usize {
        self.max_batch_size
    }

    /// Check if neural compression is available
    #[must_use]
    pub fn is_neural_available(&self) -> bool {
        self.compressor.is_neural_available()
    }

    /// Check if using CUDA
    #[must_use]
    pub fn is_using_cuda(&self) -> bool {
        self.compressor.is_using_cuda()
    }
}

/// Batch compression statistics
#[derive(Debug, Clone, Default)]
pub struct BatchStats {
    /// Number of chunks processed
    pub chunk_count: usize,

    /// Total original size
    pub total_original_size: usize,

    /// Total compressed size
    pub total_compressed_size: usize,

    /// Chunks that used neural compression
    pub neural_chunks: usize,

    /// Chunks that used fallback compression
    pub fallback_chunks: usize,
}

impl BatchStats {
    /// Calculate overall compression ratio
    #[must_use]
    pub fn compression_ratio(&self) -> f64 {
        if self.total_compressed_size == 0 {
            0.0
        } else {
            self.total_original_size as f64 / self.total_compressed_size as f64
        }
    }

    /// Calculate space savings percentage
    #[must_use]
    pub fn space_savings(&self) -> f64 {
        if self.total_original_size == 0 {
            0.0
        } else {
            1.0 - (self.total_compressed_size as f64 / self.total_original_size as f64)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_compressor_creation() {
        let compressor = BatchNeuralCompressor::new().unwrap();
        assert_eq!(compressor.max_batch_size(), 256);
    }

    #[test]
    fn test_batch_compression() {
        let compressor = BatchNeuralCompressor::new().unwrap();

        let chunks: Vec<Vec<u8>> = (0..5).map(|i| vec![i as u8; 1024]).collect();
        let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();

        let compressed = compressor.compress_batch(&chunk_refs).unwrap();
        assert_eq!(compressed.len(), 5);

        let compressed_refs: Vec<&[u8]> = compressed.iter().map(|c| c.as_slice()).collect();
        let decompressed = compressor.decompress_batch(&compressed_refs).unwrap();
        assert_eq!(decompressed.len(), 5);

        for (original, recovered) in chunks.iter().zip(decompressed.iter()) {
            assert_eq!(original, recovered);
        }
    }

    #[test]
    fn test_batch_with_stats() {
        let compressor = BatchNeuralCompressor::new().unwrap();

        let chunks: Vec<Vec<u8>> = (0..3).map(|_| vec![42u8; 512]).collect();
        let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();

        let (compressed, original_sizes, compressed_sizes) =
            compressor.compress_batch_with_stats(&chunk_refs).unwrap();

        assert_eq!(compressed.len(), 3);
        assert_eq!(original_sizes.len(), 3);
        assert_eq!(compressed_sizes.len(), 3);

        for &size in &original_sizes {
            assert_eq!(size, 512);
        }
    }

    #[test]
    fn test_batch_empty() {
        let compressor = BatchNeuralCompressor::new().unwrap();

        let empty: Vec<&[u8]> = vec![];
        let compressed = compressor.compress_batch(&empty).unwrap();
        assert!(compressed.is_empty());
    }

    #[test]
    fn test_batch_stats() {
        let stats = BatchStats {
            chunk_count: 10,
            total_original_size: 10000,
            total_compressed_size: 2000,
            neural_chunks: 7,
            fallback_chunks: 3,
        };

        assert!((stats.compression_ratio() - 5.0).abs() < 0.01);
        assert!((stats.space_savings() - 0.8).abs() < 0.01);
    }
}
