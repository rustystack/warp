//! Layer processing for the Chonkers algorithm
//!
//! Each layer processes boundaries through three phases to achieve
//! the target chunk size while maintaining edit locality.

use crate::chunk::ChunkWeight;
use crate::config::LayerConfig;

/// A layer in the Chonkers hierarchy
#[derive(Debug, Clone)]
pub struct Layer {
    /// Layer configuration
    pub config: LayerConfig,

    /// Current boundaries (byte offsets)
    pub boundaries: Vec<usize>,

    /// Weights at each boundary
    pub weights: Vec<ChunkWeight>,
}

impl Layer {
    /// Create a new layer with initial boundaries
    pub fn new(config: LayerConfig, boundaries: Vec<usize>, data: &[u8]) -> Self {
        let weights = Self::compute_weights(&boundaries, data);
        Self {
            config,
            boundaries,
            weights,
        }
    }

    /// Compute weights for all boundaries
    fn compute_weights(boundaries: &[usize], data: &[u8]) -> Vec<ChunkWeight> {
        boundaries
            .iter()
            .map(|&offset| {
                if offset == 0 || offset >= data.len() {
                    ChunkWeight::new(u64::MAX) // Start/end always kept
                } else {
                    // Weight from bytes around boundary
                    let start = offset.saturating_sub(4);
                    let end = (offset + 4).min(data.len());
                    ChunkWeight::from_data(&data[start..end])
                }
            })
            .collect()
    }

    /// Get chunk sizes from current boundaries
    pub fn chunk_sizes(&self) -> Vec<usize> {
        self.boundaries
            .windows(2)
            .map(|w| w[1] - w[0])
            .collect()
    }

    /// Find "kittens" - chunks lighter than both neighbors
    ///
    /// Returns indices of chunks that are kittens (undersized and light)
    pub fn find_kittens(&self) -> Vec<usize> {
        let sizes = self.chunk_sizes();
        let mut kittens = Vec::new();

        for i in 1..sizes.len().saturating_sub(1) {
            let size = sizes[i];

            // Must be undersized
            if size >= self.config.min_size {
                continue;
            }

            // Get weights of boundaries
            let _left_weight = self.weights[i];
            let right_weight = self.weights[i + 1];

            // A kitten has lower weight than both neighbors
            // (we use the right boundary's weight as the chunk's weight)
            let prev_weight = self.weights[i - 1].max(self.weights[i]);
            let next_weight = self.weights[i + 1].max(
                self.weights.get(i + 2).copied().unwrap_or(ChunkWeight::new(u64::MAX))
            );

            if right_weight.is_lighter_than(&prev_weight)
                && right_weight.is_lighter_than(&next_weight)
            {
                kittens.push(i);
            }
        }

        kittens
    }

    /// Merge a kitten with its lighter neighbor
    ///
    /// Returns the new boundaries after merge
    pub fn merge_kitten(&mut self, kitten_idx: usize) {
        if kitten_idx == 0 || kitten_idx >= self.boundaries.len() - 1 {
            return;
        }

        // Determine which neighbor is lighter
        let left_weight = self.weights[kitten_idx];
        let right_weight = self.weights.get(kitten_idx + 2).copied()
            .unwrap_or(ChunkWeight::new(u64::MAX));

        if left_weight.is_lighter_than(&right_weight) {
            // Merge with left: remove boundary at kitten_idx
            self.boundaries.remove(kitten_idx);
            self.weights.remove(kitten_idx);
        } else {
            // Merge with right: remove boundary at kitten_idx + 1
            if kitten_idx + 1 < self.boundaries.len() {
                self.boundaries.remove(kitten_idx + 1);
                self.weights.remove(kitten_idx + 1);
            }
        }
    }

    /// Check if any chunks violate size constraints
    pub fn has_violations(&self) -> bool {
        self.chunk_sizes().iter().any(|&size| {
            size < self.config.min_size || size > self.config.max_size
        })
    }

    /// Count chunks that are too small (kittens)
    pub fn count_undersized(&self) -> usize {
        self.chunk_sizes()
            .iter()
            .filter(|&&size| size < self.config.min_size)
            .count()
    }

    /// Count chunks that are too large
    pub fn count_oversized(&self) -> usize {
        self.chunk_sizes()
            .iter()
            .filter(|&&size| size > self.config.max_size)
            .count()
    }

    /// Get number of chunks
    pub fn num_chunks(&self) -> usize {
        self.boundaries.len().saturating_sub(1)
    }

    /// Get total data size
    pub fn total_size(&self) -> usize {
        if self.boundaries.len() < 2 {
            0
        } else {
            self.boundaries.last().unwrap() - self.boundaries.first().unwrap()
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ChonkersConfig;

    fn make_layer(boundaries: Vec<usize>, data_len: usize) -> Layer {
        let config = ChonkersConfig::default().layer(0);
        let data = vec![0u8; data_len];
        Layer::new(config, boundaries, &data)
    }

    #[test]
    fn test_chunk_sizes() {
        let layer = make_layer(vec![0, 100, 250, 500], 500);
        let sizes = layer.chunk_sizes();
        assert_eq!(sizes, vec![100, 150, 250]);
    }

    #[test]
    fn test_num_chunks() {
        let layer = make_layer(vec![0, 100, 200, 300], 300);
        assert_eq!(layer.num_chunks(), 3);
    }

    #[test]
    fn test_total_size() {
        let layer = make_layer(vec![0, 100, 200, 500], 500);
        assert_eq!(layer.total_size(), 500);
    }

    #[test]
    fn test_count_undersized() {
        // Config default min_size for layer 0 is 1024
        let layer = make_layer(vec![0, 100, 200, 5000], 5000);
        // Chunks: 100, 100, 4800 - two undersized
        assert_eq!(layer.count_undersized(), 2);
    }
}
