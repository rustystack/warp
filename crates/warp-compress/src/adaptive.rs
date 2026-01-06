//! Adaptive compression selection

use crate::{Compressor, Lz4Compressor, ZstdCompressor};
use rayon::prelude::*;

/// Entropy threshold for compression selection
pub const ENTROPY_THRESHOLD_HIGH: f64 = 0.95;
/// Entropy threshold for highly compressible data
pub const ENTROPY_THRESHOLD_LOW: f64 = 0.3;

/// Compression strategy based on data characteristics
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// No compression (already compressed data)
    None,
    /// Fast compression (LZ4)
    Fast,
    /// Balanced compression (Zstd level 3)
    Balanced,
    /// Maximum compression (Zstd level 19)
    Maximum,
}

impl Strategy {
    /// Select strategy based on entropy
    pub fn from_entropy(entropy: f64) -> Self {
        if entropy > ENTROPY_THRESHOLD_HIGH {
            Self::None
        } else if entropy > 0.7 {
            Self::Fast
        } else if entropy > ENTROPY_THRESHOLD_LOW {
            Self::Balanced
        } else {
            Self::Maximum
        }
    }

    /// Create compressor for this strategy
    pub fn compressor(&self) -> Option<Box<dyn Compressor>> {
        match self {
            Self::None => None,
            Self::Fast => Some(Box::new(Lz4Compressor::new())),
            Self::Balanced => Some(Box::new(ZstdCompressor::new(3).unwrap())),
            Self::Maximum => Some(Box::new(ZstdCompressor::new(19).unwrap())),
        }
    }
}

/// Threshold for using parallel entropy calculation
const PARALLEL_ENTROPY_THRESHOLD: usize = 64 * 1024; // 64KB

/// Calculate entropy of data (0.0 = compressible, 1.0 = random)
///
/// Uses parallel histogram computation for large buffers (>64KB)
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    // Use parallel computation for large buffers
    let freq = if data.len() >= PARALLEL_ENTROPY_THRESHOLD {
        calculate_frequency_parallel(data)
    } else {
        calculate_frequency_scalar(data)
    };

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy / 8.0 // Normalize to 0-1
}

/// Scalar frequency calculation (for small buffers)
///
/// Uses 4-way histogram split to avoid pipeline stalls from memory dependencies.
/// Each histogram buffer handles every 4th byte, then they're merged.
/// This is a well-known optimization for histogram computation (2-4x faster).
#[inline]
fn calculate_frequency_scalar(data: &[u8]) -> [u64; 256] {
    // 4-way split histograms to avoid memory dependency stalls
    let mut freq0 = [0u64; 256];
    let mut freq1 = [0u64; 256];
    let mut freq2 = [0u64; 256];
    let mut freq3 = [0u64; 256];

    // Process 4 bytes per iteration (unrolled)
    let chunks = data.chunks_exact(4);
    let remainder = chunks.remainder();

    for chunk in chunks {
        // Each increment goes to a different histogram, avoiding dependencies
        freq0[chunk[0] as usize] += 1;
        freq1[chunk[1] as usize] += 1;
        freq2[chunk[2] as usize] += 1;
        freq3[chunk[3] as usize] += 1;
    }

    // Handle remainder
    for (i, &byte) in remainder.iter().enumerate() {
        match i {
            0 => freq0[byte as usize] += 1,
            1 => freq1[byte as usize] += 1,
            2 => freq2[byte as usize] += 1,
            _ => freq3[byte as usize] += 1,
        }
    }

    // Merge histograms
    for i in 0..256 {
        freq0[i] += freq1[i] + freq2[i] + freq3[i];
    }

    freq0
}

/// Parallel frequency calculation using Rayon
///
/// Splits data into chunks, computes local histograms in parallel,
/// then merges them. Follows the lecture pattern: "high-level task-based parallelism"
fn calculate_frequency_parallel(data: &[u8]) -> [u64; 256] {
    // Split into chunks and compute local histograms in parallel
    data.par_chunks(16 * 1024) // 16KB chunks for good cache utilization
        .map(|chunk| {
            // Use 4-way split for each chunk too
            calculate_frequency_scalar(chunk)
        })
        .reduce(
            || [0u64; 256],
            |mut acc, local| {
                for i in 0..256 {
                    acc[i] += local[i];
                }
                acc
            },
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_zeros() {
        let data = vec![0u8; 1000];
        let entropy = calculate_entropy(&data);
        assert!(entropy < 0.1);
    }

    #[test]
    fn test_entropy_random() {
        let data: Vec<u8> = (0..=255).cycle().take(1000).collect();
        let entropy = calculate_entropy(&data);
        assert!(entropy > 0.9);
    }
}

#[cfg(test)]
mod proptest_tests {
    use super::{calculate_entropy, Strategy as CompressionStrategy};
    use proptest::prelude::*;

    proptest! {
        /// Property: entropy is always in range [0, 1]
        #[test]
        fn entropy_normalized(data in prop::collection::vec(any::<u8>(), 1..4096)) {
            let entropy = calculate_entropy(&data);

            prop_assert!(entropy >= 0.0, "entropy {} < 0", entropy);
            prop_assert!(entropy <= 1.0, "entropy {} > 1", entropy);
        }

        /// Property: higher entropy leads to less aggressive compression
        /// Strategy ordering: Maximum < Balanced < Fast < None
        #[test]
        fn strategy_monotonicity(
            low_entropy in 0.0f64..0.3,
            mid_entropy in 0.31f64..0.7,
            high_entropy in 0.71f64..0.95,
            very_high_entropy in 0.96f64..=1.0,
        ) {
            let s_low = CompressionStrategy::from_entropy(low_entropy);
            let s_mid = CompressionStrategy::from_entropy(mid_entropy);
            let s_high = CompressionStrategy::from_entropy(high_entropy);
            let s_very_high = CompressionStrategy::from_entropy(very_high_entropy);

            // Verify ordering: lower entropy -> more aggressive compression
            prop_assert_eq!(s_low, CompressionStrategy::Maximum);
            prop_assert_eq!(s_mid, CompressionStrategy::Balanced);
            prop_assert_eq!(s_high, CompressionStrategy::Fast);
            prop_assert_eq!(s_very_high, CompressionStrategy::None);
        }
    }

    #[test]
    fn entropy_empty_is_zero() {
        let entropy = calculate_entropy(&[]);
        assert_eq!(entropy, 0.0);
    }
}
