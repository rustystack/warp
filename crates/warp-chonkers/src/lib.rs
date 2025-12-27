//! Chonkers Algorithm Implementation
//!
//! This crate implements the Chonkers algorithm (arXiv:2509.11121) for versioned
//! data deduplication with provable guarantees on both chunk size AND edit locality.
//!
//! # Key Properties
//!
//! - **Bounded chunk sizes**: All chunks are within [min_size, max_size]
//! - **Edit locality**: Single byte edit affects at most 7 chunk boundaries
//! - **Content-addressed**: Identical content produces identical chunk IDs
//! - **Hierarchical**: Multi-layer tree structure for efficient updates
//!
//! # Algorithm Overview
//!
//! Chonkers processes data through multiple layers, each with three phases:
//!
//! 1. **Balancing Phase**: Finds "kittens" (chunks lighter than both neighbors)
//!    and merges them with their lighter neighbor.
//!
//! 2. **Caterpillar Phase**: Detects periodic repetitions using Z-algorithm
//!    and collapses them into single chunks.
//!
//! 3. **Diffbit Phase**: Uses XOR of boundary bytes for priority-based merging
//!    to achieve final chunk boundaries.
//!
//! # Tree Structure
//!
//! The `ChonkerTree` provides a hierarchical view of chunks enabling:
//! - O(log n) incremental updates
//! - Efficient diff computation between versions
//! - Content-addressed deduplication at all levels
//!
//! # Usage
//!
//! ```rust,ignore
//! use warp_chonkers::{ChonkersConfig, Chonkers};
//!
//! // Create chunker with default config
//! let config = ChonkersConfig::default();
//! let chunker = Chonkers::new(config);
//!
//! // Chunk data
//! let data = b"your data here...";
//! let chunks = chunker.chunk(data)?;
//!
//! // Each chunk has a unique ID based on content
//! for chunk in &chunks {
//!     println!("Chunk {}: {} bytes at offset {}",
//!         chunk.id, chunk.length, chunk.offset);
//! }
//! ```

#![warn(missing_docs)]

mod chunk;
mod config;
pub mod dedup;
mod error;
mod layer;
mod phases;
pub mod simd;
pub mod tree;
pub mod version;

pub use chunk::{Chunk, ChunkFlags, ChunkId, ChunkWeight};
pub use config::{ChonkersConfig, LayerConfig};
pub use dedup::{
    ChunkMetadata, ChunkRegistry, ChunkStore, GarbageCollector, GcConfig, GcEvent,
    GcEventHandler, GcStats, LoggingGcHandler, MemoryChunkStore,
};
pub use error::{Error, Result};
pub use layer::Layer;
pub use phases::{BalancingPhase, CaterpillarPhase, DiffbitPhase};
pub use tree::{
    ChonkerNode, ChonkerTree, EditOp, FileTreeStore, MemoryTreeStore,
    TreeDiff, TreeSnapshot, TreeStore, VersionId,
};
pub use version::{
    ChunkMove, Delta, DeltaBuilder, DeltaStats, TimelineBuilder, VersionInfo,
    VersionTimeline,
};

use rayon::prelude::*;

/// Main Chonkers chunker implementing the algorithm
#[derive(Debug, Clone)]
pub struct Chonkers {
    config: ChonkersConfig,
}

impl Chonkers {
    /// Create a new Chonkers chunker with the given configuration
    pub fn new(config: ChonkersConfig) -> Self {
        Self { config }
    }

    /// Create a chunker with default configuration
    pub fn default_config() -> Self {
        Self::new(ChonkersConfig::default())
    }

    /// Chunk data into content-addressed chunks
    ///
    /// Returns a vector of chunks with their boundaries, IDs, and metadata.
    /// The chunks satisfy the Chonkers guarantees:
    /// - All chunks are within configured size bounds
    /// - Single byte edits affect at most 7 chunk boundaries
    pub fn chunk(&self, data: &[u8]) -> Result<Vec<Chunk>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        // Start with initial boundaries (every byte is a boundary)
        let mut boundaries: Vec<usize> = (0..=data.len()).collect();

        // Process each layer
        for layer_idx in 0..self.config.num_layers {
            let layer_config = self.config.layer(layer_idx);

            // Phase 1: Balancing - merge kittens
            boundaries = BalancingPhase::process(data, &boundaries, &layer_config)?;

            // Phase 2: Caterpillar - collapse periodic repetitions
            boundaries = CaterpillarPhase::process(data, &boundaries, &layer_config)?;

            // Phase 3: Diffbit - priority-based merging
            boundaries = DiffbitPhase::process(data, &boundaries, &layer_config)?;
        }

        // Convert boundaries to chunks
        self.boundaries_to_chunks(data, &boundaries)
    }

    /// Get chunk boundaries without computing chunk IDs
    ///
    /// This is faster when you only need the boundaries.
    pub fn chunk_boundaries(&self, data: &[u8]) -> Result<Vec<usize>> {
        if data.is_empty() {
            return Ok(vec![0]);
        }

        let mut boundaries: Vec<usize> = (0..=data.len()).collect();

        for layer_idx in 0..self.config.num_layers {
            let layer_config = self.config.layer(layer_idx);
            boundaries = BalancingPhase::process(data, &boundaries, &layer_config)?;
            boundaries = CaterpillarPhase::process(data, &boundaries, &layer_config)?;
            boundaries = DiffbitPhase::process(data, &boundaries, &layer_config)?;
        }

        Ok(boundaries)
    }

    /// Convert boundaries to chunks with content-addressed IDs
    fn boundaries_to_chunks(&self, data: &[u8], boundaries: &[usize]) -> Result<Vec<Chunk>> {
        if boundaries.len() < 2 {
            return Ok(Vec::new());
        }

        // Parallel chunk creation
        let chunks: Vec<Chunk> = boundaries
            .par_windows(2)
            .enumerate()
            .map(|(idx, window)| {
                let start = window[0];
                let end = window[1];
                let chunk_data = &data[start..end];

                Chunk::new(idx as u64, start, chunk_data)
            })
            .collect();

        Ok(chunks)
    }

    /// Get the configuration
    pub fn config(&self) -> &ChonkersConfig {
        &self.config
    }
}

impl Default for Chonkers {
    fn default() -> Self {
        Self::default_config()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_data() {
        let chunker = Chonkers::default();
        let chunks = chunker.chunk(&[]).unwrap();
        assert!(chunks.is_empty());
    }

    #[test]
    fn test_small_data() {
        let chunker = Chonkers::default();
        let data = b"hello world";
        let chunks = chunker.chunk(data).unwrap();

        // Small data should produce one chunk
        assert!(!chunks.is_empty());

        // Verify chunk covers all data
        let total_len: usize = chunks.iter().map(|c| c.length).sum();
        assert_eq!(total_len, data.len());
    }

    #[test]
    fn test_deterministic() {
        let chunker = Chonkers::default();
        let data = b"the quick brown fox jumps over the lazy dog";

        let chunks1 = chunker.chunk(data).unwrap();
        let chunks2 = chunker.chunk(data).unwrap();

        // Same data should produce same chunks
        assert_eq!(chunks1.len(), chunks2.len());
        for (c1, c2) in chunks1.iter().zip(chunks2.iter()) {
            assert_eq!(c1.id, c2.id);
            assert_eq!(c1.offset, c2.offset);
            assert_eq!(c1.length, c2.length);
        }
    }

    #[test]
    fn test_chunk_boundaries() {
        let chunker = Chonkers::default();
        let data = b"some test data for chunking";
        let boundaries = chunker.chunk_boundaries(data).unwrap();

        // Boundaries should start at 0 and end at data.len()
        assert_eq!(*boundaries.first().unwrap(), 0);
        assert_eq!(*boundaries.last().unwrap(), data.len());

        // Boundaries should be sorted
        for window in boundaries.windows(2) {
            assert!(window[0] < window[1]);
        }
    }
}
