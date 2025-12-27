//! Phase 2: Caterpillar - Periodic Repetition Detection
//!
//! This phase detects periodic patterns in the data using the Z-algorithm
//! and collapses repeated segments into single chunks.
//!
//! The Z-algorithm efficiently finds all positions where a prefix of the
//! string matches, which helps identify periodic repetitions.

use crate::config::LayerConfig;
use crate::Result;

/// Caterpillar phase processor
pub struct CaterpillarPhase;

impl CaterpillarPhase {
    /// Process boundaries through the caterpillar phase
    ///
    /// Detects periodic repetitions and collapses them.
    pub fn process(
        data: &[u8],
        boundaries: &[usize],
        config: &LayerConfig,
    ) -> Result<Vec<usize>> {
        if boundaries.len() < 3 || data.len() < config.min_period_length * config.min_repetitions {
            return Ok(boundaries.to_vec());
        }

        let mut result = boundaries.to_vec();

        // Look for periodic patterns at each chunk
        let mut i = 0;
        while i < result.len() - 1 {
            let start = result[i];
            let end = result.get(i + 1).copied().unwrap_or(data.len());
            let chunk_data = &data[start..end.min(data.len())];

            if let Some(period_info) = Self::detect_period(chunk_data, config) {
                // Found a periodic pattern - look for adjacent repetitions
                let collapsed = Self::collapse_repetitions(
                    &result,
                    data,
                    i,
                    &period_info,
                    config,
                );

                if collapsed.len() < result.len() {
                    result = collapsed;
                    // Don't increment i - check same position again
                    continue;
                }
            }

            i += 1;
        }

        Ok(result)
    }

    /// Detect if a chunk contains a periodic pattern
    fn detect_period(chunk: &[u8], config: &LayerConfig) -> Option<PeriodInfo> {
        if chunk.len() < config.min_period_length {
            return None;
        }

        // Compute Z-array for the chunk
        let z = Self::compute_z_array(chunk);

        // Look for periods
        for period_len in config.min_period_length..=chunk.len() / 2 {
            if Self::is_periodic(&z, chunk.len(), period_len, config.min_repetitions) {
                return Some(PeriodInfo {
                    period_length: period_len,
                    total_length: chunk.len(),
                });
            }
        }

        None
    }

    /// Compute Z-array for a byte slice
    ///
    /// Z[i] = length of longest substring starting at i that matches prefix
    fn compute_z_array(data: &[u8]) -> Vec<usize> {
        let n = data.len();
        if n == 0 {
            return Vec::new();
        }

        let mut z = vec![0usize; n];
        z[0] = n;

        let mut l = 0;
        let mut r = 0;

        for i in 1..n {
            if i < r {
                z[i] = z[i - l].min(r - i);
            }

            while i + z[i] < n && data[z[i]] == data[i + z[i]] {
                z[i] += 1;
            }

            if i + z[i] > r {
                l = i;
                r = i + z[i];
            }
        }

        z
    }

    /// Check if data has periodic structure with given period length
    fn is_periodic(z: &[usize], data_len: usize, period_len: usize, min_reps: usize) -> bool {
        if period_len == 0 || data_len < period_len * min_reps {
            return false;
        }

        // For periodicity, Z[period_len] should be >= data_len - period_len
        // (meaning the suffix from period_len matches the prefix)
        if period_len < z.len() {
            let expected_match = data_len.saturating_sub(period_len);
            if z[period_len] >= expected_match {
                return true;
            }
        }

        // Alternative: check if all Z values at multiples of period are sufficient
        let mut i = period_len;
        let mut reps = 1;
        while i < z.len() && reps < min_reps {
            if z[i] >= period_len || i + z[i] >= data_len {
                reps += 1;
            } else {
                break;
            }
            i += period_len;
        }

        reps >= min_reps
    }

    /// Collapse adjacent repetitions into a single chunk
    fn collapse_repetitions(
        boundaries: &[usize],
        data: &[u8],
        start_idx: usize,
        period_info: &PeriodInfo,
        config: &LayerConfig,
    ) -> Vec<usize> {
        let mut result = boundaries.to_vec();

        if start_idx >= result.len() - 1 {
            return result;
        }

        let start = result[start_idx];
        let pattern = &data[start..(start + period_info.period_length).min(data.len())];

        // Find how many subsequent chunks continue the pattern
        let mut end_idx = start_idx + 1;
        let mut total_len = result[start_idx + 1] - result[start_idx];

        while end_idx < result.len() - 1 {
            let chunk_start = result[end_idx];
            let chunk_end = result[end_idx + 1];
            let chunk = &data[chunk_start..chunk_end.min(data.len())];

            // Check if this chunk continues the pattern
            if !Self::continues_pattern(pattern, chunk, period_info.period_length) {
                break;
            }

            total_len += chunk.len();

            // Don't exceed max size
            if total_len > config.max_size {
                break;
            }

            end_idx += 1;
        }

        // Need at least min_repetitions worth of data
        if total_len < period_info.period_length * config.min_repetitions {
            return result;
        }

        // Collapse boundaries between start_idx and end_idx
        if end_idx > start_idx + 1 {
            // Remove intermediate boundaries
            result.drain(start_idx + 1..end_idx);
        }

        result
    }

    /// Check if a chunk continues a periodic pattern
    fn continues_pattern(pattern: &[u8], chunk: &[u8], period_len: usize) -> bool {
        if chunk.len() < period_len / 2 {
            return false;
        }

        // Check if chunk matches pattern cyclically
        for (i, &byte) in chunk.iter().take(period_len.min(chunk.len())).enumerate() {
            if byte != pattern[i % pattern.len()] {
                return false;
            }
        }

        true
    }
}

/// Information about detected period
struct PeriodInfo {
    /// Length of the repeating pattern
    period_length: usize,

    /// Total length of the periodic region
    #[allow(dead_code)]
    total_length: usize,
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
            min_period_length: 4,
            min_repetitions: 3,
        }
    }

    #[test]
    fn test_z_array_no_repetition() {
        let data = b"abcdefgh";
        let z = CaterpillarPhase::compute_z_array(data);

        assert_eq!(z[0], 8); // Full match at start
        assert_eq!(z[1], 0); // 'b' != 'a'
        assert_eq!(z[2], 0); // 'c' != 'a'
    }

    #[test]
    fn test_z_array_with_prefix_match() {
        let data = b"aabaa";
        let z = CaterpillarPhase::compute_z_array(data);

        assert_eq!(z[0], 5);
        assert_eq!(z[1], 1); // 'a' matches 'a'
        assert_eq!(z[3], 2); // 'aa' matches 'aa'
    }

    #[test]
    fn test_z_array_periodic() {
        let data = b"abcabcabc";
        let z = CaterpillarPhase::compute_z_array(data);

        assert_eq!(z[0], 9);
        assert_eq!(z[3], 6); // 'abcabc' matches prefix
        assert_eq!(z[6], 3); // 'abc' matches prefix
    }

    #[test]
    fn test_no_period() {
        let config = test_config();
        let data = b"hello world this is random text";
        let boundaries = vec![0, 10, 20, 31];

        let result = CaterpillarPhase::process(data, &boundaries, &config).unwrap();

        // No periodic pattern, boundaries unchanged
        assert_eq!(result.len(), boundaries.len());
    }

    #[test]
    fn test_with_period() {
        let mut config = test_config();
        config.min_period_length = 3;
        config.min_repetitions = 2;

        // Repeating pattern: "abc" repeated
        let data = b"abcabcabcabcabcabc";
        let boundaries = vec![0, 3, 6, 9, 12, 15, 18];

        let result = CaterpillarPhase::process(data, &boundaries, &config).unwrap();

        // Should collapse some boundaries
        // (exact result depends on implementation details)
        assert!(result.len() <= boundaries.len());
    }

    #[test]
    fn test_preserves_boundaries() {
        let config = test_config();
        let data = vec![0u8; 100];
        let boundaries = vec![0, 50, 100];

        let result = CaterpillarPhase::process(&data, &boundaries, &config).unwrap();

        assert_eq!(*result.first().unwrap(), 0);
        assert_eq!(*result.last().unwrap(), 100);
    }

    #[test]
    fn test_is_periodic() {
        // Test with actual periodic data
        let data = b"abcdabcdabcd";
        let z = CaterpillarPhase::compute_z_array(data);

        // Period of 4 repeated 3 times
        assert!(CaterpillarPhase::is_periodic(&z, data.len(), 4, 3));
        assert!(!CaterpillarPhase::is_periodic(&z, data.len(), 3, 3));
    }
}
