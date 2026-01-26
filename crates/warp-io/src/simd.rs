//! SIMD-accelerated boundary detection for SeqCDC
//!
//! This module provides vectorized implementations of monotonic sequence
//! detection for high-throughput content-defined chunking.
//!
//! Performance targets:
//! - Scalar: 1-2 GB/s
//! - ARM NEON (128-bit): 8-15 GB/s
//! - AVX2 (256-bit): 15-20 GB/s
//! - AVX-512 (512-bit): 30+ GB/s

use crate::chunker::SeqMode;

/// Result of scanning a buffer for monotonic sequences
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// Positions where monotonic sequences of required length were found
    pub boundaries: Vec<usize>,
    /// Number of consecutive opposing pairs at each position (for skip heuristic)
    pub opposing_runs: Vec<(usize, usize)>, // (start_pos, length)
}

/// Detect monotonic sequence boundaries in a byte buffer.
///
/// Returns positions where `seq_length` consecutive increasing (or decreasing)
/// bytes are found.
#[inline]
pub fn find_boundaries_scalar(data: &[u8], seq_length: usize, mode: SeqMode) -> Vec<usize> {
    if data.len() < seq_length {
        return Vec::new();
    }

    let mut boundaries = Vec::new();
    let mut consecutive = 0usize;

    for i in 1..data.len() {
        let is_monotonic = match mode {
            SeqMode::Increasing => data[i - 1] < data[i],
            SeqMode::Decreasing => data[i - 1] > data[i],
        };

        if is_monotonic {
            consecutive += 1;
            if consecutive >= seq_length - 1 {
                boundaries.push(i);
            }
        } else {
            consecutive = 0;
        }
    }

    boundaries
}

/// Find runs of opposing byte pairs (for content-based skipping)
#[inline]
pub fn find_opposing_runs(
    data: &[u8],
    mode: SeqMode,
    min_run_length: usize,
) -> Vec<(usize, usize)> {
    if data.len() < 2 {
        return Vec::new();
    }

    let mut runs = Vec::new();
    let mut run_start = 0usize;
    let mut run_length = 0usize;

    for i in 1..data.len() {
        let is_opposing = match mode {
            SeqMode::Increasing => data[i - 1] >= data[i],
            SeqMode::Decreasing => data[i - 1] <= data[i],
        };

        if is_opposing {
            if run_length == 0 {
                run_start = i - 1;
            }
            run_length += 1;
        } else {
            if run_length >= min_run_length {
                runs.push((run_start, run_length));
            }
            run_length = 0;
        }
    }

    if run_length >= min_run_length {
        runs.push((run_start, run_length));
    }

    runs
}

// ============================================================================
// AVX2 Implementation (256-bit, 32 bytes at a time)
// ============================================================================

#[cfg(target_arch = "x86_64")]
pub mod avx2 {
    use super::*;

    /// Check if AVX2 is available at runtime
    #[inline]
    pub fn is_available() -> bool {
        is_x86_feature_detected!("avx2")
    }

    /// Find first boundary in a 32-byte window using AVX2
    ///
    /// Returns the position of the first monotonic sequence of `seq_length`,
    /// or None if no boundary found in this window.
    ///
    /// # Safety
    ///
    /// - Caller must ensure AVX2 is available: `is_x86_feature_detected!("avx2")`
    /// - `data.len()` must be at least 33 bytes (32-byte vector + 1 for offset load)
    ///
    /// The function returns `None` if `data.len() < 33`, but this check should not
    /// be relied upon for safety - ensure preconditions are met before calling.
    #[target_feature(enable = "avx2")]
    #[inline]
    pub unsafe fn find_boundary_in_window(
        data: &[u8],
        seq_length: usize,
        mode: SeqMode,
    ) -> Option<usize> {
        use std::arch::x86_64::*;

        if data.len() < 33 {
            return None;
        }

        // Load 32 bytes at offset 0 and 1
        let v0 = _mm256_loadu_si256(data.as_ptr() as *const __m256i);
        let v1 = _mm256_loadu_si256(data[1..].as_ptr() as *const __m256i);

        // Compare adjacent bytes: result[i] = 0xFF if condition met, 0x00 otherwise
        let cmp_mask = match mode {
            SeqMode::Increasing => _mm256_cmpgt_epi8(v1, v0), // v1 > v0 means increasing
            SeqMode::Decreasing => _mm256_cmpgt_epi8(v0, v1), // v0 > v1 means decreasing
        };

        // Convert to bitmask: bit[i] = 1 if comparison at position i was true
        let mask = _mm256_movemask_epi8(cmp_mask) as u32;

        // Find consecutive runs of 1s of length >= seq_length - 1
        // A boundary at position i means positions (i-seq_length+1)..=i are all monotonic
        find_consecutive_ones(mask, seq_length - 1)
    }

    /// Count opposing pairs in a 32-byte window
    ///
    /// Returns the number of adjacent byte pairs where the monotonic condition
    /// is NOT satisfied (i.e., pairs that would break a monotonic sequence).
    ///
    /// # Safety
    ///
    /// - Caller must ensure AVX2 is available: `is_x86_feature_detected!("avx2")`
    /// - `data.len()` must be at least 33 bytes (32-byte vector + 1 for offset load)
    ///
    /// Returns 0 if `data.len() < 33`, but this should not be relied upon for safety.
    #[target_feature(enable = "avx2")]
    #[inline]
    pub unsafe fn count_opposing_pairs(data: &[u8], mode: SeqMode) -> u32 {
        use std::arch::x86_64::*;

        if data.len() < 33 {
            return 0;
        }

        let v0 = _mm256_loadu_si256(data.as_ptr() as *const __m256i);
        let v1 = _mm256_loadu_si256(data[1..].as_ptr() as *const __m256i);

        // For opposing: we want positions where the sequence is NOT monotonic
        let monotonic_mask = match mode {
            SeqMode::Increasing => _mm256_cmpgt_epi8(v1, v0),
            SeqMode::Decreasing => _mm256_cmpgt_epi8(v0, v1),
        };

        let mask = _mm256_movemask_epi8(monotonic_mask) as u32;

        // Count zeros (opposing pairs) = 32 - popcount(monotonic)
        32 - mask.count_ones()
    }

    /// Optimized chunking using AVX2 for the bulk processing phase
    ///
    /// This processes data in 32-byte chunks, using SIMD for:
    /// 1. Fast detection of all-opposing regions (skip candidates)
    /// 2. Boundary detection when approaching min_size
    ///
    /// # Arguments
    ///
    /// * `data` - Input buffer to chunk
    /// * `min_size` - Minimum chunk size (chunks won't be smaller)
    /// * `max_size` - Maximum chunk size (forced cut if reached)
    /// * `seq_length` - Number of consecutive monotonic bytes required for boundary
    /// * `skip_trigger` - Number of opposing pairs that triggers skip mode
    /// * `skip_size` - How many bytes to skip in skip mode
    /// * `mode` - Whether to detect increasing or decreasing sequences
    ///
    /// # Returns
    ///
    /// Vector of (start, length) tuples representing chunk boundaries.
    ///
    /// # Safety
    ///
    /// - Caller must ensure AVX2 is available: `is_x86_feature_detected!("avx2")`
    /// - For best performance, `data` should be at least 64 bytes
    ///
    /// The function handles short inputs safely, falling back to scalar paths.
    #[target_feature(enable = "avx2")]
    pub unsafe fn chunk_buffer_avx2(
        data: &[u8],
        min_size: usize,
        max_size: usize,
        seq_length: usize,
        skip_trigger: usize,
        skip_size: usize,
        mode: SeqMode,
    ) -> Vec<(usize, usize)> {
        use std::arch::x86_64::*;

        let mut chunks = Vec::new();
        let mut chunk_start = 0usize;
        let mut i = 0usize;

        while i < data.len() {
            let chunk_len = i - chunk_start;
            let remaining = data.len() - i;

            // Fast path: bulk processing before min_size
            if chunk_len + 32 < min_size && remaining >= 33 {
                let v0 = _mm256_loadu_si256(data[i..].as_ptr() as *const __m256i);
                let v1 = _mm256_loadu_si256(data[i + 1..].as_ptr() as *const __m256i);

                let cmp = match mode {
                    SeqMode::Increasing => _mm256_cmpgt_epi8(v1, v0),
                    SeqMode::Decreasing => _mm256_cmpgt_epi8(v0, v1),
                };
                let mask = _mm256_movemask_epi8(cmp) as u32;

                // If mostly opposing (< 25% monotonic), this is unfavorable region
                if mask.count_ones() < 8 {
                    // Skip ahead - all 32 bytes are mostly opposing
                    i += 32;
                    continue;
                }

                // Otherwise, advance 32 bytes
                i += 32;
                continue;
            }

            // Boundary detection phase: near min_size, check carefully
            if chunk_len >= min_size && remaining >= seq_length {
                // Check for boundary using SIMD if possible
                if remaining >= 33 {
                    if let Some(offset) = find_boundary_in_window(&data[i..], seq_length, mode) {
                        // Found boundary at i + offset
                        let boundary_pos = i + offset;
                        if boundary_pos - chunk_start >= min_size {
                            chunks.push((chunk_start, boundary_pos - chunk_start + 1));
                            chunk_start = boundary_pos + 1;
                            i = chunk_start;
                            continue;
                        }
                    }
                }

                // Scalar fallback for boundary detection
                let window_end = (i + seq_length).min(data.len());
                if window_end - i >= seq_length {
                    let window = &data[i..window_end];
                    let is_boundary = match mode {
                        SeqMode::Increasing => window.windows(2).all(|w| w[0] < w[1]),
                        SeqMode::Decreasing => window.windows(2).all(|w| w[0] > w[1]),
                    };

                    if is_boundary {
                        chunks.push((chunk_start, i + seq_length - 1 - chunk_start));
                        chunk_start = i + seq_length;
                        i = chunk_start;
                        continue;
                    }
                }
            }

            // Max size enforcement
            if chunk_len >= max_size {
                chunks.push((chunk_start, chunk_len));
                chunk_start = i;
            }

            i += 1;
        }

        // Final chunk
        if chunk_start < data.len() {
            chunks.push((chunk_start, data.len() - chunk_start));
        }

        chunks
    }
}

// ============================================================================
// AVX-512 Implementation (512-bit, 64 bytes at a time)
// ============================================================================

#[cfg(target_arch = "x86_64")]
pub mod avx512 {
    use super::*;

    /// Check if AVX-512 is available at runtime
    #[inline]
    pub fn is_available() -> bool {
        is_x86_feature_detected!("avx512f") && is_x86_feature_detected!("avx512bw")
    }

    /// Find first boundary in a 64-byte window using AVX-512
    ///
    /// # Safety
    ///
    /// - Caller must ensure AVX-512F and AVX-512BW are available:
    ///   `is_x86_feature_detected!("avx512f") && is_x86_feature_detected!("avx512bw")`
    /// - `data.len()` must be at least 65 bytes (64-byte vector + 1 for offset load)
    #[cfg(target_feature = "avx512f")]
    #[target_feature(enable = "avx512f", enable = "avx512bw")]
    #[inline]
    pub unsafe fn find_boundary_in_window(
        data: &[u8],
        seq_length: usize,
        mode: SeqMode,
    ) -> Option<usize> {
        use std::arch::x86_64::*;

        if data.len() < 65 {
            return None;
        }

        // Load 64 bytes at offset 0 and 1
        let v0 = _mm512_loadu_si512(data.as_ptr() as *const i32);
        let v1 = _mm512_loadu_si512(data[1..].as_ptr() as *const i32);

        // Compare adjacent bytes using AVX-512 comparison
        let cmp_mask = match mode {
            SeqMode::Increasing => _mm512_cmpgt_epi8_mask(v1, v0),
            SeqMode::Decreasing => _mm512_cmpgt_epi8_mask(v0, v1),
        };

        // Find consecutive runs of 1s of length >= seq_length - 1
        find_consecutive_ones_64(cmp_mask, seq_length - 1)
    }

    /// Count opposing pairs in a 64-byte window using AVX-512
    ///
    /// # Safety
    ///
    /// - Caller must ensure AVX-512F and AVX-512BW are available:
    ///   `is_x86_feature_detected!("avx512f") && is_x86_feature_detected!("avx512bw")`
    /// - `data.len()` must be at least 65 bytes (64-byte vector + 1 for offset load)
    #[cfg(target_feature = "avx512f")]
    #[target_feature(enable = "avx512f", enable = "avx512bw")]
    #[inline]
    pub unsafe fn count_opposing_pairs(data: &[u8], mode: SeqMode) -> u32 {
        use std::arch::x86_64::*;

        if data.len() < 65 {
            return 0;
        }

        let v0 = _mm512_loadu_si512(data.as_ptr() as *const i32);
        let v1 = _mm512_loadu_si512(data[1..].as_ptr() as *const i32);

        let monotonic_mask = match mode {
            SeqMode::Increasing => _mm512_cmpgt_epi8_mask(v1, v0),
            SeqMode::Decreasing => _mm512_cmpgt_epi8_mask(v0, v1),
        };

        // Count zeros (opposing pairs) = 64 - popcount(monotonic)
        64 - monotonic_mask.count_ones()
    }
}

// ============================================================================
// ARM NEON Implementation (128-bit, 16 bytes at a time)
// ============================================================================

#[cfg(target_arch = "aarch64")]
pub mod neon {
    //! ARM NEON SIMD implementation for SeqCDC chunking.

    use super::*;
    use std::arch::aarch64::*;

    /// NEON is always available on aarch64
    #[inline]
    pub fn is_available() -> bool {
        true
    }

    /// Find first boundary in a 16-byte window using NEON
    ///
    /// Returns the position of the first monotonic sequence of `seq_length`,
    /// or None if no boundary found in this window.
    ///
    /// # Safety
    ///
    /// - This function is only available on aarch64 targets where NEON is guaranteed
    /// - `data.len()` must be at least 17 bytes (16-byte vector + 1 for offset load)
    ///
    /// Returns `None` if `data.len() < 17`, but callers should ensure this precondition.
    #[inline]
    pub unsafe fn find_boundary_in_window(
        data: &[u8],
        seq_length: usize,
        mode: SeqMode,
    ) -> Option<usize> {
        // SAFETY: Caller guarantees data.len() >= 17 per function contract.
        // NEON intrinsics are safe on aarch64 (always available).
        // vld1q_u8 loads are valid: we check data.len() >= 17 before loading.
        unsafe {
            if data.len() < 17 {
                return None;
            }

            // Load 16 bytes at offset 0 and 1
            let v0 = vld1q_u8(data.as_ptr());
            let v1 = vld1q_u8(data[1..].as_ptr());

            // Compare adjacent bytes
            // vcgtq_u8 returns 0xFF where v0 > v1, 0x00 otherwise
            let cmp_mask = match mode {
                SeqMode::Increasing => vcgtq_u8(v1, v0), // v1 > v0 means increasing
                SeqMode::Decreasing => vcgtq_u8(v0, v1), // v0 > v1 means decreasing
            };

            // Convert vector to bitmask
            let mask = neon_movemask(cmp_mask);

            // Find consecutive runs of 1s of length >= seq_length - 1
            find_consecutive_ones_16(mask, seq_length - 1)
        }
    }

    /// Count opposing pairs in a 16-byte window using NEON
    ///
    /// # Safety
    ///
    /// - This function is only available on aarch64 targets where NEON is guaranteed
    /// - `data.len()` must be at least 17 bytes (16-byte vector + 1 for offset load)
    #[inline]
    pub unsafe fn count_opposing_pairs(data: &[u8], mode: SeqMode) -> u32 {
        // SAFETY: Caller guarantees data.len() >= 17 per function contract.
        // NEON intrinsics are safe on aarch64. All loads check bounds first.
        unsafe {
            if data.len() < 17 {
                return 0;
            }

            let v0 = vld1q_u8(data.as_ptr());
            let v1 = vld1q_u8(data[1..].as_ptr());

            let monotonic_mask = match mode {
                SeqMode::Increasing => vcgtq_u8(v1, v0),
                SeqMode::Decreasing => vcgtq_u8(v0, v1),
            };

            let mask = neon_movemask(monotonic_mask);

            // Count zeros (opposing pairs) = 16 - popcount(monotonic)
            16 - mask.count_ones()
        }
    }

    /// Optimized chunking using NEON for bulk processing
    ///
    /// Processes data in 16-byte chunks using SIMD for:
    /// 1. Fast detection of all-opposing regions (skip candidates)
    /// 2. Boundary detection when approaching min_size
    ///
    /// # Safety
    ///
    /// - This function is only available on aarch64 targets where NEON is guaranteed
    /// - For best performance, `data` should be at least 32 bytes
    ///
    /// The function handles short inputs safely, falling back to scalar comparisons.
    #[inline]
    pub unsafe fn chunk_buffer_neon(
        data: &[u8],
        min_size: usize,
        max_size: usize,
        seq_length: usize,
        _skip_trigger: usize,
        _skip_size: usize,
        mode: SeqMode,
    ) -> Vec<(usize, usize)> {
        // SAFETY: NEON is always available on aarch64. All vld1q_u8 loads are
        // guarded by bounds checks (remaining >= 17). The function falls back
        // to scalar for short inputs.
        unsafe {
            let mut chunks = Vec::new();
            let mut chunk_start = 0usize;
            let mut consecutive = 0usize;
            let mut i = 1usize; // Start at 1 to compare with previous byte

            while i < data.len() {
                let chunk_len = i - chunk_start;
                let remaining = data.len() - i;

                // Fast path: bulk processing before min_size using 16-byte SIMD
                if chunk_len + 16 < min_size && remaining >= 17 {
                    let v0 = vld1q_u8(data[i..].as_ptr());
                    let v1 = vld1q_u8(data[i + 1..].as_ptr());

                    let cmp = match mode {
                        SeqMode::Increasing => vcgtq_u8(v1, v0),
                        SeqMode::Decreasing => vcgtq_u8(v0, v1),
                    };
                    let mask = neon_movemask(cmp);

                    // If mostly opposing (< 25% monotonic = < 4 bits set), skip this region
                    if mask.count_ones() < 4 {
                        consecutive = 0; // Reset consecutive counter
                        i += 16;
                        continue;
                    }

                    // Otherwise, advance 16 bytes but reset consecutive
                    consecutive = 0;
                    i += 16;
                    continue;
                }

                // Check monotonicity at current position
                let is_monotonic = match mode {
                    SeqMode::Increasing => data[i - 1] < data[i],
                    SeqMode::Decreasing => data[i - 1] > data[i],
                };

                if is_monotonic {
                    consecutive += 1;
                } else {
                    consecutive = 0;
                }

                // Check for boundary
                if chunk_len >= min_size && consecutive >= seq_length - 1 {
                    chunks.push((chunk_start, chunk_len + 1));
                    chunk_start = i + 1;
                    consecutive = 0;
                } else if chunk_len >= max_size {
                    chunks.push((chunk_start, chunk_len));
                    chunk_start = i;
                    consecutive = 0;
                }

                i += 1;
            }

            // Final chunk
            if chunk_start < data.len() {
                chunks.push((chunk_start, data.len() - chunk_start));
            }

            chunks
        }
    }

    /// Convert NEON comparison result to a 16-bit mask
    /// Each bit corresponds to whether that byte position was 0xFF
    #[inline]
    unsafe fn neon_movemask(v: uint8x16_t) -> u16 {
        // SAFETY: NEON intrinsics are always safe on aarch64. The input v is a
        // valid uint8x16_t register. Stack array powers has valid alignment.
        unsafe {
            // Use the high bit of each byte to form a bitmask
            // Shift each byte right by 7 to get just the sign bit
            let shifted = vshrq_n_u8::<7>(v);

            // Now we have 0x01 or 0x00 for each byte
            // We need to pack these into a 16-bit integer

            // Create powers of 2 for each position
            let powers: [u8; 16] = [1, 2, 4, 8, 16, 32, 64, 128, 1, 2, 4, 8, 16, 32, 64, 128];
            let power_vec = vld1q_u8(powers.as_ptr());

            // Multiply each byte by its power of 2
            let weighted = vmulq_u8(shifted, power_vec);

            // Sum the low and high halves separately
            let low = vget_low_u8(weighted);
            let high = vget_high_u8(weighted);

            // Horizontal add to get two 8-bit sums
            let low_sum = vaddv_u8(low) as u16;
            let high_sum = vaddv_u8(high) as u16;

            low_sum | (high_sum << 8)
        }
    }
}

/// Find position of first consecutive run of `n` ones in a 16-bit mask
#[cfg(target_arch = "aarch64")]
#[inline]
fn find_consecutive_ones_16(mask: u16, n: usize) -> Option<usize> {
    if n == 0 {
        return Some(0);
    }
    if n > 16 {
        return None;
    }

    let pattern = (1u16 << n) - 1;

    for pos in 0..=(16 - n) {
        if (mask >> pos) & pattern == pattern {
            return Some(pos + n - 1);
        }
    }

    None
}

// ============================================================================
// Bit Manipulation Helpers
// ============================================================================

/// Find position of first consecutive run of `n` ones in a 32-bit mask
#[allow(dead_code)]
#[inline]
fn find_consecutive_ones(mask: u32, n: usize) -> Option<usize> {
    if n == 0 {
        return Some(0);
    }
    if n > 32 {
        return None;
    }

    // Create a pattern of n consecutive ones
    let pattern = (1u32 << n) - 1;

    // Slide the pattern across the mask
    for pos in 0..=(32 - n) {
        if (mask >> pos) & pattern == pattern {
            // Found n consecutive ones starting at pos
            // The boundary is at position pos + n - 1
            return Some(pos + n - 1);
        }
    }

    None
}

/// Find position of first consecutive run of `n` ones in a 64-bit mask
#[allow(dead_code)]
#[inline]
fn find_consecutive_ones_64(mask: u64, n: usize) -> Option<usize> {
    if n == 0 {
        return Some(0);
    }
    if n > 64 {
        return None;
    }

    let pattern = (1u64 << n) - 1;

    for pos in 0..=(64 - n) {
        if (mask >> pos) & pattern == pattern {
            return Some(pos + n - 1);
        }
    }

    None
}

// ============================================================================
// Runtime Dispatch
// ============================================================================

/// Chunk a buffer using the best available SIMD implementation
///
/// Automatically selects the best available SIMD implementation:
/// - x86_64: AVX-512 > AVX2 > scalar
/// - aarch64: NEON > scalar
pub fn chunk_buffer_auto(
    data: &[u8],
    min_size: usize,
    max_size: usize,
    seq_length: usize,
    skip_trigger: usize,
    skip_size: usize,
    mode: SeqMode,
) -> Vec<(usize, usize)> {
    #[cfg(target_arch = "x86_64")]
    {
        if avx2::is_available() {
            // SAFETY: We checked that AVX2 is available
            return unsafe {
                avx2::chunk_buffer_avx2(
                    data,
                    min_size,
                    max_size,
                    seq_length,
                    skip_trigger,
                    skip_size,
                    mode,
                )
            };
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        // NEON is always available on aarch64
        // SAFETY: NEON intrinsics are safe when target is aarch64
        return unsafe {
            neon::chunk_buffer_neon(
                data,
                min_size,
                max_size,
                seq_length,
                skip_trigger,
                skip_size,
                mode,
            )
        };
    }

    // Scalar fallback for other architectures
    #[allow(unreachable_code)]
    chunk_buffer_scalar(data, min_size, max_size, seq_length, mode)
}

/// Scalar implementation for reference and fallback
fn chunk_buffer_scalar(
    data: &[u8],
    min_size: usize,
    max_size: usize,
    seq_length: usize,
    mode: SeqMode,
) -> Vec<(usize, usize)> {
    let mut chunks = Vec::new();
    let mut chunk_start = 0usize;
    let mut consecutive = 0usize;

    for i in 1..data.len() {
        let chunk_len = i - chunk_start;

        let is_monotonic = match mode {
            SeqMode::Increasing => data[i - 1] < data[i],
            SeqMode::Decreasing => data[i - 1] > data[i],
        };

        if is_monotonic {
            consecutive += 1;
        } else {
            consecutive = 0;
        }

        // Check for boundary
        if chunk_len >= min_size && consecutive >= seq_length - 1 {
            chunks.push((chunk_start, chunk_len + 1));
            chunk_start = i + 1;
            consecutive = 0;
        } else if chunk_len >= max_size {
            chunks.push((chunk_start, chunk_len));
            chunk_start = i;
            consecutive = 0;
        }
    }

    // Final chunk
    if chunk_start < data.len() {
        chunks.push((chunk_start, data.len() - chunk_start));
    }

    chunks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_consecutive_ones() {
        // 0b11110000 has 4 consecutive ones at positions 4-7
        assert_eq!(find_consecutive_ones(0b11110000, 4), Some(7));
        assert_eq!(find_consecutive_ones(0b11110000, 5), None);

        // 0b00011100 has 3 consecutive ones at positions 2-4
        assert_eq!(find_consecutive_ones(0b00011100, 3), Some(4));
        assert_eq!(find_consecutive_ones(0b00011100, 4), None);

        // 0b11111111 has 8 consecutive ones
        assert_eq!(find_consecutive_ones(0xFF, 5), Some(4));
    }

    #[test]
    fn test_find_boundaries_scalar() {
        // Increasing sequence: 0, 1, 2, 3, 4
        let data = vec![0u8, 1, 2, 3, 4, 3, 2, 1, 0];
        let boundaries = find_boundaries_scalar(&data, 4, SeqMode::Increasing);
        assert!(!boundaries.is_empty());
        assert!(boundaries.contains(&4)); // Boundary at position 4

        // No increasing sequence of length 4
        let data2 = vec![5u8, 4, 3, 2, 1];
        let boundaries2 = find_boundaries_scalar(&data2, 4, SeqMode::Increasing);
        assert!(boundaries2.is_empty());
    }

    #[test]
    fn test_chunk_buffer_scalar() {
        let data: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
        let chunks = chunk_buffer_scalar(&data, 100, 500, 5, SeqMode::Increasing);

        // Verify all data accounted for
        let total: usize = chunks.iter().map(|(_, len)| len).sum();
        assert_eq!(total, data.len());

        // Verify chunk sizes
        for (_, len) in &chunks[..chunks.len().saturating_sub(1)] {
            assert!(*len >= 100, "Chunk too small: {}", len);
            assert!(*len <= 500, "Chunk too large: {}", len);
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_avx2_boundary_detection() {
        if !avx2::is_available() {
            return;
        }

        // Create data with a clear increasing sequence
        let mut data = vec![0u8; 64];
        data[10] = 1;
        data[11] = 2;
        data[12] = 3;
        data[13] = 4;
        data[14] = 5;

        unsafe {
            let result = avx2::find_boundary_in_window(&data, 4, SeqMode::Increasing);
            assert!(
                result.is_some(),
                "Should find boundary in increasing sequence"
            );
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_avx2_opposing_count() {
        if !avx2::is_available() {
            return;
        }

        // All same values = all opposing for increasing mode
        let data = vec![5u8; 64];
        unsafe {
            let count = avx2::count_opposing_pairs(&data, SeqMode::Increasing);
            assert!(count > 20, "Should find many opposing pairs: {}", count);
        }

        // Strictly increasing = no opposing
        let inc_data: Vec<u8> = (0..64).collect();
        unsafe {
            let count = avx2::count_opposing_pairs(&inc_data, SeqMode::Increasing);
            assert!(count < 5, "Should find few opposing pairs: {}", count);
        }
    }

    // ========================================================================
    // ARM NEON Tests
    // ========================================================================

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_find_consecutive_ones_16() {
        // 0b1111000000000000 has 4 consecutive ones at positions 12-15
        assert_eq!(find_consecutive_ones_16(0b1111000000000000, 4), Some(15));
        assert_eq!(find_consecutive_ones_16(0b1111000000000000, 5), None);

        // 0b0000000000011100 has 3 consecutive ones at positions 2-4
        assert_eq!(find_consecutive_ones_16(0b0000000000011100, 3), Some(4));

        // All ones
        assert_eq!(find_consecutive_ones_16(0xFFFF, 5), Some(4));
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_neon_boundary_detection() {
        // Create data with a clear increasing sequence
        let mut data = vec![0u8; 32];
        data[5] = 1;
        data[6] = 2;
        data[7] = 3;
        data[8] = 4;
        data[9] = 5;

        unsafe {
            let result = neon::find_boundary_in_window(&data, 4, SeqMode::Increasing);
            assert!(
                result.is_some(),
                "Should find boundary in increasing sequence"
            );
        }
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_neon_opposing_count() {
        // All same values = all opposing for increasing mode
        let data = vec![5u8; 32];
        unsafe {
            let count = neon::count_opposing_pairs(&data, SeqMode::Increasing);
            assert!(count > 10, "Should find many opposing pairs: {}", count);
        }

        // Strictly increasing = no opposing
        let inc_data: Vec<u8> = (0..32).collect();
        unsafe {
            let count = neon::count_opposing_pairs(&inc_data, SeqMode::Increasing);
            assert!(count < 3, "Should find few opposing pairs: {}", count);
        }
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_neon_chunk_buffer() {
        let data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();

        unsafe {
            let chunks = neon::chunk_buffer_neon(
                &data,
                100, // min_size
                500, // max_size
                5,   // seq_length
                50,  // skip_trigger
                256, // skip_size
                SeqMode::Increasing,
            );

            // Verify all data accounted for
            let total: usize = chunks.iter().map(|(_, len)| len).sum();
            assert_eq!(total, data.len(), "All data should be accounted for");

            // Verify chunk sizes (except last chunk)
            for (_, len) in &chunks[..chunks.len().saturating_sub(1)] {
                assert!(*len >= 100, "Chunk too small: {}", len);
                assert!(*len <= 500, "Chunk too large: {}", len);
            }
        }
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_neon_matches_scalar() {
        // Verify NEON produces same results as scalar for same input
        let data: Vec<u8> = (0..5000).map(|i| ((i * 17 + 31) % 256) as u8).collect();

        let scalar_chunks = chunk_buffer_scalar(&data, 200, 1000, 5, SeqMode::Increasing);

        let neon_chunks =
            unsafe { neon::chunk_buffer_neon(&data, 200, 1000, 5, 50, 256, SeqMode::Increasing) };

        // Total bytes should match
        let scalar_total: usize = scalar_chunks.iter().map(|(_, len)| len).sum();
        let neon_total: usize = neon_chunks.iter().map(|(_, len)| len).sum();
        assert_eq!(scalar_total, neon_total, "Total bytes should match");
        assert_eq!(scalar_total, data.len());

        // Number of chunks should be similar (may differ slightly due to SIMD boundary detection)
        let diff = (scalar_chunks.len() as i64 - neon_chunks.len() as i64).abs();
        assert!(
            diff < 10,
            "Chunk count should be similar: scalar={}, neon={}",
            scalar_chunks.len(),
            neon_chunks.len()
        );
    }
}
