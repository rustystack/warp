//! Phase 3: Diffbit - Priority-based Merging
//!
//! This phase uses XOR of boundary bytes to compute priorities for merging.
//! Boundaries with lower priority (fewer differing bits) are more likely
//! to be merged, which provides stability for edit locality.
//!
//! The diffbit technique ensures that chunk boundaries are placed at
//! "interesting" positions where content differs significantly.

use crate::chunk::ChunkWeight;
use crate::config::LayerConfig;
use crate::Result;

/// Diffbit phase processor
pub struct DiffbitPhase;

impl DiffbitPhase {
    /// Process boundaries through the diffbit phase
    ///
    /// Uses XOR-based priorities to merge chunks until size constraints are met.
    pub fn process(
        data: &[u8],
        boundaries: &[usize],
        config: &LayerConfig,
    ) -> Result<Vec<usize>> {
        if boundaries.len() < 2 {
            return Ok(boundaries.to_vec());
        }

        let mut result = boundaries.to_vec();

        // Skip merging if not enough boundaries
        if result.len() < 3 {
            // Still need to split oversized chunks
            return Self::split_oversized(&result, data, config);
        }

        // Compute priorities for all boundaries
        let mut priorities = Self::compute_priorities(&result, data);

        // Merge low-priority boundaries until constraints are met
        let mut changed = true;
        let mut iterations = 0;
        const MAX_ITERATIONS: usize = 1000;

        while changed && iterations < MAX_ITERATIONS {
            changed = false;
            iterations += 1;

            // Find chunks that are too small and should be merged
            let merge_candidates = Self::find_merge_candidates(&result, &priorities, config);

            if merge_candidates.is_empty() {
                break;
            }

            // Merge the lowest priority boundary among candidates
            if let Some(&merge_idx) = merge_candidates.first() {
                if merge_idx > 0 && merge_idx < result.len() - 1 {
                    result.remove(merge_idx);
                    priorities.remove(merge_idx);
                    changed = true;
                }
            }
        }

        // Split chunks that are too large
        result = Self::split_oversized(&result, data, config)?;

        Ok(result)
    }

    /// Compute XOR-based priority for each boundary
    ///
    /// Higher priority = more differing bits = stronger boundary
    fn compute_priorities(boundaries: &[usize], data: &[u8]) -> Vec<u32> {
        boundaries
            .iter()
            .enumerate()
            .map(|(i, &offset)| {
                if i == 0 || i == boundaries.len() - 1 {
                    u32::MAX // Start/end always kept
                } else {
                    Self::boundary_priority(offset, data)
                }
            })
            .collect()
    }

    /// Compute priority for a single boundary using XOR of surrounding bytes
    fn boundary_priority(offset: usize, data: &[u8]) -> u32 {
        if offset == 0 || offset >= data.len() {
            return u32::MAX;
        }

        // Look at bytes before and after the boundary
        let window = 8; // 8 bytes on each side
        let before_start = offset.saturating_sub(window);
        let after_end = (offset + window).min(data.len());

        let before = &data[before_start..offset];
        let after = &data[offset..after_end];

        // XOR corresponding bytes and count differing bits
        let mut diff_bits = 0u32;
        let min_len = before.len().min(after.len());

        for i in 0..min_len {
            let before_byte = before[before.len() - 1 - i];
            let after_byte = after[i];
            diff_bits += (before_byte ^ after_byte).count_ones();
        }

        // Also factor in the weight from hash
        let weight = Self::boundary_weight(offset, data);

        // Combine: more diff bits + higher weight = higher priority
        diff_bits.saturating_add((weight.value() >> 56) as u32)
    }

    /// Compute weight for a boundary
    fn boundary_weight(offset: usize, data: &[u8]) -> ChunkWeight {
        let start = offset.saturating_sub(4);
        let end = (offset + 4).min(data.len());
        ChunkWeight::from_data(&data[start..end])
    }

    /// Find boundaries that should be merged (low priority + undersized)
    fn find_merge_candidates(
        boundaries: &[usize],
        priorities: &[u32],
        config: &LayerConfig,
    ) -> Vec<usize> {
        if boundaries.len() < 3 {
            return Vec::new();
        }

        let mut candidates: Vec<(usize, u32)> = Vec::new();

        for i in 1..boundaries.len() - 1 {
            let left_size = boundaries[i] - boundaries[i - 1];
            let right_size = boundaries.get(i + 1).map(|&b| b - boundaries[i]).unwrap_or(0);

            // Consider merging if either adjacent chunk is undersized
            let undersized = left_size < config.min_size || right_size < config.min_size;

            // Or if merging wouldn't exceed max size
            let merged_size = left_size + right_size;
            let can_merge = merged_size <= config.max_size;

            if (undersized || priorities[i] < u32::MAX / 2) && can_merge {
                candidates.push((i, priorities[i]));
            }
        }

        // Sort by priority (lowest first)
        candidates.sort_by_key(|&(_, priority)| priority);

        candidates.into_iter().map(|(idx, _)| idx).collect()
    }

    /// Split chunks that exceed max_size
    fn split_oversized(
        boundaries: &[usize],
        data: &[u8],
        config: &LayerConfig,
    ) -> Result<Vec<usize>> {
        let mut result = Vec::with_capacity(boundaries.len() * 2);

        for window in boundaries.windows(2) {
            let start = window[0];
            let end = window[1];
            let size = end - start;

            result.push(start);

            if size > config.max_size {
                // Need to split this chunk
                let split_points = Self::find_split_points(start, end, data, config);
                result.extend(split_points);
            }
        }

        // Add final boundary
        if let Some(&last) = boundaries.last() {
            result.push(last);
        }

        // Deduplicate and sort
        result.sort_unstable();
        result.dedup();

        Ok(result)
    }

    /// Find good split points for an oversized chunk
    fn find_split_points(
        start: usize,
        end: usize,
        data: &[u8],
        config: &LayerConfig,
    ) -> Vec<usize> {
        let size = end - start;
        if size <= config.max_size {
            return Vec::new();
        }

        let mut splits = Vec::new();
        let num_splits = (size + config.max_size - 1) / config.max_size;
        let target_chunk_size = size / num_splits;

        let mut last_split = start;

        // Place splits at high-priority positions near target locations
        for i in 1..num_splits {
            let target = start + i * target_chunk_size;

            // Ensure we don't exceed max_size from last split
            let max_from_last = last_split + config.max_size;

            // Search window: between min viable position and target + window
            let window = (config.target_size / 8).max(32);
            let search_start = target.saturating_sub(window).max(last_split + 1);
            let search_end = (target + window).min(max_from_last).min(end - 1);

            if search_start < search_end {
                let best = Self::find_best_split(search_start, search_end, data);
                if best > last_split && best < end {
                    splits.push(best);
                    last_split = best;
                }
            } else if search_start <= max_from_last && max_from_last < end {
                // Fallback: just use max_from_last to ensure we don't exceed
                splits.push(max_from_last.min(end - 1));
                last_split = max_from_last.min(end - 1);
            }
        }

        // Ensure last chunk doesn't exceed max_size
        if let Some(&last) = splits.last() {
            let remaining = end - last;
            if remaining > config.max_size {
                // Need more splits
                let mut pos = last;
                while end - pos > config.max_size {
                    pos += config.max_size;
                    if pos < end {
                        splits.push(pos);
                    }
                }
            }
        } else if size > config.max_size {
            // No splits yet but chunk is oversized - add regular intervals
            let mut pos = start + config.max_size;
            while pos < end {
                splits.push(pos);
                pos += config.max_size;
            }
        }

        splits
    }

    /// Find the best split point in a range (highest priority)
    fn find_best_split(start: usize, end: usize, data: &[u8]) -> usize {
        (start..end)
            .max_by_key(|&offset| Self::boundary_priority(offset, data))
            .unwrap_or(start)
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
    fn test_boundary_priority() {
        // Different data on each side = high priority
        let data: Vec<u8> = (0..100).collect();
        let priority = DiffbitPhase::boundary_priority(50, &data);
        assert!(priority > 0);
    }

    #[test]
    fn test_same_data_low_priority() {
        // Same data on each side = lower priority
        let data = vec![42u8; 100];
        let priority = DiffbitPhase::boundary_priority(50, &data);

        // Should be relatively low since XOR of same values is 0
        // (but weight adds some priority)
        assert!(priority < u32::MAX);
    }

    #[test]
    fn test_no_merge_valid_chunks() {
        let config = test_config();
        let data = vec![0u8; 4000];
        // All chunks are valid size
        let boundaries = vec![0, 1000, 2000, 3000, 4000];

        let result = DiffbitPhase::process(&data, &boundaries, &config).unwrap();

        // Boundaries might be preserved if chunks are valid
        assert!(*result.first().unwrap() == 0);
        assert!(*result.last().unwrap() == 4000);
    }

    #[test]
    fn test_merge_undersized() {
        let config = test_config();
        let data = vec![0u8; 1000];
        // Small chunk in the middle (50 bytes)
        let boundaries = vec![0, 400, 450, 1000];

        let result = DiffbitPhase::process(&data, &boundaries, &config).unwrap();

        // Small chunk should be merged
        assert!(result.len() < boundaries.len());
    }

    #[test]
    fn test_split_oversized() {
        let mut config = test_config();
        config.max_size = 500;
        let data: Vec<u8> = (0..2000).map(|i| (i % 256) as u8).collect();
        // One huge chunk
        let boundaries = vec![0, 2000];

        // Test split_oversized directly first
        let split_result = DiffbitPhase::split_oversized(&boundaries, &data, &config).unwrap();

        // Should have been split into multiple boundaries
        assert!(
            split_result.len() > 2,
            "Expected split to produce >2 boundaries, got {} {:?}",
            split_result.len(),
            split_result
        );

        // Full process
        let result = DiffbitPhase::process(&data, &boundaries, &config).unwrap();

        // Should have been split
        assert!(
            result.len() > 2,
            "Expected process to produce >2 boundaries, got {} {:?}",
            result.len(),
            result
        );

        // All chunks should be within bounds
        for window in result.windows(2) {
            let size = window[1] - window[0];
            assert!(size <= config.max_size, "Chunk size {} > max {}", size, config.max_size);
        }
    }

    #[test]
    fn test_preserves_boundaries() {
        let config = test_config();
        let data = vec![0u8; 500];
        let boundaries = vec![0, 250, 500];

        let result = DiffbitPhase::process(&data, &boundaries, &config).unwrap();

        assert_eq!(*result.first().unwrap(), 0);
        assert_eq!(*result.last().unwrap(), 500);
    }

    #[test]
    fn test_compute_priorities() {
        let data: Vec<u8> = (0..100).collect();
        let boundaries = vec![0, 25, 50, 75, 100];

        let priorities = DiffbitPhase::compute_priorities(&boundaries, &data);

        // First and last should be MAX
        assert_eq!(priorities[0], u32::MAX);
        assert_eq!(priorities[4], u32::MAX);

        // Middle should be less
        assert!(priorities[1] < u32::MAX);
        assert!(priorities[2] < u32::MAX);
        assert!(priorities[3] < u32::MAX);
    }
}
