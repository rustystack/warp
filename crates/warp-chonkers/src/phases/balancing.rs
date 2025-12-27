//! Phase 1: Balancing - Kitten Merging
//!
//! This phase identifies "kittens" (chunks that are both undersized and have
//! lower weight than both neighbors) and merges them with their lighter neighbor.
//!
//! The key insight is that by always merging kittens with their lighter neighbor,
//! we maintain stability and edit locality.

use crate::chunk::ChunkWeight;
use crate::config::LayerConfig;
use crate::Result;

/// Balancing phase processor
pub struct BalancingPhase;

impl BalancingPhase {
    /// Process boundaries through the balancing phase
    ///
    /// Repeatedly finds and merges kittens until none remain.
    pub fn process(
        data: &[u8],
        boundaries: &[usize],
        config: &LayerConfig,
    ) -> Result<Vec<usize>> {
        if boundaries.len() < 3 {
            return Ok(boundaries.to_vec());
        }

        let mut result = boundaries.to_vec();
        let mut weights = Self::compute_weights(&result, data);

        // Iterate until no more kittens
        let mut changed = true;
        let mut iterations = 0;
        const MAX_ITERATIONS: usize = 1000;

        while changed && iterations < MAX_ITERATIONS {
            changed = false;
            iterations += 1;

            // Find all kittens in current state
            let kittens = Self::find_kittens(&result, &weights, config);

            if kittens.is_empty() {
                break;
            }

            // Process kittens from right to left to maintain indices
            for &kitten_idx in kittens.iter().rev() {
                if kitten_idx > 0 && kitten_idx < result.len() - 1 {
                    Self::merge_kitten(&mut result, &mut weights, kitten_idx);
                    changed = true;
                }
            }
        }

        Ok(result)
    }

    /// Compute weights for all boundaries
    fn compute_weights(boundaries: &[usize], data: &[u8]) -> Vec<ChunkWeight> {
        boundaries
            .iter()
            .map(|&offset| {
                if offset == 0 || offset >= data.len() {
                    ChunkWeight::new(u64::MAX) // Start/end always kept
                } else {
                    Self::boundary_weight(offset, data)
                }
            })
            .collect()
    }

    /// Compute weight for a single boundary
    fn boundary_weight(offset: usize, data: &[u8]) -> ChunkWeight {
        // Use bytes around the boundary for weight
        let start = offset.saturating_sub(4);
        let end = (offset + 4).min(data.len());
        ChunkWeight::from_data(&data[start..end])
    }

    /// Find kitten indices (chunks lighter than both neighbors)
    fn find_kittens(
        boundaries: &[usize],
        weights: &[ChunkWeight],
        config: &LayerConfig,
    ) -> Vec<usize> {
        if boundaries.len() < 3 {
            return Vec::new();
        }

        let mut kittens = Vec::new();

        // Chunk i is between boundaries[i] and boundaries[i+1]
        // Its "weight" is taken from boundaries[i+1] (right boundary)
        for i in 0..boundaries.len() - 2 {
            let chunk_size = boundaries[i + 1] - boundaries[i];

            // Must be undersized
            if chunk_size >= config.min_size {
                continue;
            }

            // Get the weight of this chunk (right boundary)
            let chunk_weight = weights[i + 1];

            // Get weights of neighboring chunks
            let left_weight = if i > 0 { weights[i] } else { ChunkWeight::new(u64::MAX) };
            let right_weight = if i + 2 < weights.len() {
                weights[i + 2]
            } else {
                ChunkWeight::new(u64::MAX)
            };

            // Kitten: lighter than both neighbors
            if chunk_weight.is_lighter_than(&left_weight)
                && chunk_weight.is_lighter_than(&right_weight)
            {
                kittens.push(i);
            }
        }

        kittens
    }

    /// Merge a kitten with its lighter neighbor
    fn merge_kitten(
        boundaries: &mut Vec<usize>,
        weights: &mut Vec<ChunkWeight>,
        chunk_idx: usize,
    ) {
        // chunk_idx is the index of the chunk (0-indexed)
        // The chunk spans boundaries[chunk_idx] to boundaries[chunk_idx+1]
        // We remove one of these boundaries

        if chunk_idx >= boundaries.len() - 1 {
            return;
        }

        // Determine which neighbor is lighter
        let left_weight = weights[chunk_idx];
        let right_weight = weights.get(chunk_idx + 2).copied()
            .unwrap_or(ChunkWeight::new(u64::MAX));

        if left_weight.is_lighter_than(&right_weight) && chunk_idx > 0 {
            // Merge with left: remove boundary at chunk_idx
            boundaries.remove(chunk_idx);
            weights.remove(chunk_idx);
        } else if chunk_idx + 1 < boundaries.len() - 1 {
            // Merge with right: remove boundary at chunk_idx + 1
            boundaries.remove(chunk_idx + 1);
            weights.remove(chunk_idx + 1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> LayerConfig {
        LayerConfig {
            index: 0,
            target_size: 1000,
            min_size: 100,
            max_size: 4000,
            min_period_length: 64,
            min_repetitions: 3,
        }
    }

    #[test]
    fn test_no_kittens() {
        let config = test_config();
        let data = vec![0u8; 1000];
        // All chunks are >= min_size (100)
        let boundaries = vec![0, 200, 400, 600, 800, 1000];

        let result = BalancingPhase::process(&data, &boundaries, &config).unwrap();

        // No changes since no undersized chunks
        assert_eq!(result.len(), boundaries.len());
    }

    #[test]
    fn test_with_undersized() {
        let config = test_config();
        // Use varied data so weights differ at different boundaries
        let data: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
        // One small chunk (50 bytes) - the boundaries will have different weights
        let boundaries = vec![0, 200, 250, 500, 1000];

        let result = BalancingPhase::process(&data, &boundaries, &config).unwrap();

        // The algorithm may or may not merge depending on weight comparison
        // Just verify it preserves start/end and boundaries are valid
        assert!(*result.first().unwrap() == 0);
        assert!(*result.last().unwrap() == 1000);
        for w in result.windows(2) {
            assert!(w[0] < w[1], "Boundaries must be sorted");
        }
    }

    #[test]
    fn test_preserves_start_end() {
        let config = test_config();
        let data = vec![0u8; 500];
        let boundaries = vec![0, 50, 100, 200, 500];

        let result = BalancingPhase::process(&data, &boundaries, &config).unwrap();

        // First and last boundaries must be preserved
        assert_eq!(*result.first().unwrap(), 0);
        assert_eq!(*result.last().unwrap(), 500);
    }

    #[test]
    fn test_compute_weights() {
        let data: Vec<u8> = (0..100).collect();
        let boundaries = vec![0, 25, 50, 75, 100];

        let weights = BalancingPhase::compute_weights(&boundaries, &data);

        // Start and end have max weight
        assert_eq!(weights[0], ChunkWeight::new(u64::MAX));
        assert_eq!(weights[4], ChunkWeight::new(u64::MAX));

        // Middle weights are computed from data
        assert!(weights[1].value() < u64::MAX);
        assert!(weights[2].value() < u64::MAX);
        assert!(weights[3].value() < u64::MAX);
    }
}
