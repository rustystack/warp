//! GPU-accelerated BLAKE3 hashing for Metal backend
//!
//! This module provides the Metal Shading Language (MSL) implementation
//! of BLAKE3 for Apple GPUs (M1/M2/M3/M4 series).
//!
//! # Algorithm Overview
//!
//! BLAKE3 is structured as a Merkle tree with 1KB chunks:
//! 1. Split input into 1KB chunks
//! 2. Hash each chunk independently (parallelizable)
//! 3. Merge hashes in binary tree fashion
//!
//! # Metal Parallelization Strategy
//!
//! ## Chunk-level parallelism (coarse-grained):
//! - One threadgroup per 1KB chunk
//! - Each threadgroup processes 16 x 64-byte blocks internally
//! - Threadgroup size: 256 threads
//!
//! ## Memory access pattern:
//! - Coalesced reads: threads read consecutive bytes
//! - Threadgroup memory staging: 1KB chunk per threadgroup
//! - Output: 32-byte hash per chunk to device memory

/// Metal Shading Language kernel source for BLAKE3 hashing
///
/// Key differences from CUDA version:
/// - Uses `kernel` instead of `__global__`
/// - Uses `threadgroup` instead of `__shared__`
/// - Uses `thread_position_in_threadgroup` instead of `threadIdx`
/// - Uses `threadgroup_position_in_grid` instead of `blockIdx`
/// - Uses `threadgroup_barrier(mem_flags::mem_threadgroup)` instead of `__syncthreads()`
pub const BLAKE3_METAL_KERNEL: &str = r#"
#include <metal_stdlib>
using namespace metal;

// BLAKE3 IV constants
constant uint32_t BLAKE3_IV[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

// Permutation indices for BLAKE3 mixing
constant uint8_t MSG_SCHEDULE[7][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8},
    {3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1},
    {10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6},
    {12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4},
    {9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7},
    {11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13}
};

// Rotation amounts for BLAKE3
inline uint32_t rotr32(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

// BLAKE3 G mixing function
inline void g(
    thread uint32_t *state,
    uint32_t a, uint32_t b, uint32_t c, uint32_t d,
    uint32_t mx, uint32_t my
) {
    state[a] = state[a] + state[b] + mx;
    state[d] = rotr32(state[d] ^ state[a], 16);
    state[c] = state[c] + state[d];
    state[b] = rotr32(state[b] ^ state[c], 12);
    state[a] = state[a] + state[b] + my;
    state[d] = rotr32(state[d] ^ state[a], 8);
    state[c] = state[c] + state[d];
    state[b] = rotr32(state[b] ^ state[c], 7);
}

// Round function
inline void round_fn(thread uint32_t *state, const thread uint32_t *msg) {
    // Columns
    g(state, 0, 4, 8, 12, msg[0], msg[1]);
    g(state, 1, 5, 9, 13, msg[2], msg[3]);
    g(state, 2, 6, 10, 14, msg[4], msg[5]);
    g(state, 3, 7, 11, 15, msg[6], msg[7]);

    // Diagonals
    g(state, 0, 5, 10, 15, msg[8], msg[9]);
    g(state, 1, 6, 11, 12, msg[10], msg[11]);
    g(state, 2, 7, 8, 13, msg[12], msg[13]);
    g(state, 3, 4, 9, 14, msg[14], msg[15]);
}

// Compress a single block of 64 bytes
inline void compress_block(
    thread uint32_t *chaining_value,
    const threadgroup uint32_t *block_words,
    uint64_t counter,
    uint32_t block_len,
    uint32_t flags
) {
    uint32_t state[16];

    // Initialize state: first 8 from chaining value, next 4 from IV, last 4 special
    for (int i = 0; i < 8; i++) {
        state[i] = chaining_value[i];
    }
    state[8] = BLAKE3_IV[0];
    state[9] = BLAKE3_IV[1];
    state[10] = BLAKE3_IV[2];
    state[11] = BLAKE3_IV[3];
    state[12] = (uint32_t)(counter & 0xFFFFFFFF);        // Counter low
    state[13] = (uint32_t)((counter >> 32) & 0xFFFFFFFF); // Counter high
    state[14] = block_len;
    state[15] = flags;

    // 7 rounds of permutation and mixing
    uint32_t msg[16];
    for (int round = 0; round < 7; round++) {
        // Permute message according to schedule
        for (int i = 0; i < 16; i++) {
            msg[i] = block_words[MSG_SCHEDULE[round][i]];
        }
        round_fn(state, msg);
    }

    // XOR upper and lower halves to produce output chaining value
    for (int i = 0; i < 8; i++) {
        chaining_value[i] = state[i] ^ state[i + 8];
    }
}

// Main BLAKE3 kernel - one threadgroup per 1KB chunk
// Grid: (num_chunks, 1, 1), Threadgroup: (256, 1, 1)
kernel void blake3_hash_chunks(
    device const uint8_t *input [[buffer(0)]],
    device uint32_t *output [[buffer(1)]],
    constant uint32_t &num_chunks [[buffer(2)]],
    constant uint64_t &total_size [[buffer(3)]],
    constant uint32_t &is_single_chunk [[buffer(4)]],
    uint tid [[thread_position_in_threadgroup]],
    uint chunk_idx [[threadgroup_position_in_grid]]
) {
    if (chunk_idx >= num_chunks) return;

    // Threadgroup memory for chunk data (1KB) and chaining value
    threadgroup uint32_t chunk_data[256];  // 1KB = 256 words
    threadgroup uint32_t cv[8];            // Chaining value (8 words = 32 bytes)

    // Load chunk data (coalesced reads)
    uint64_t chunk_offset = (uint64_t)chunk_idx * 1024;
    uint64_t chunk_end = min(chunk_offset + 1024, total_size);
    uint64_t chunk_size = chunk_end - chunk_offset;

    // Each thread loads 4 bytes (256 threads * 4 = 1KB)
    for (uint i = tid; i < 256; i += 256) {
        uint64_t byte_offset = chunk_offset + i * 4;
        if (byte_offset < total_size) {
            // Load 4 bytes as word (handle misalignment)
            uint32_t word = 0;
            for (int j = 0; j < 4; j++) {
                uint64_t off = byte_offset + j;
                if (off < total_size) {
                    word |= ((uint32_t)input[off]) << (j * 8);
                }
            }
            chunk_data[i] = word;
        } else {
            chunk_data[i] = 0;
        }
    }
    threadgroup_barrier(mem_flags::mem_threadgroup);

    // Initialize chaining value with IV for first block
    if (tid < 8) {
        cv[tid] = BLAKE3_IV[tid];
    }
    threadgroup_barrier(mem_flags::mem_threadgroup);

    // Process all 16 blocks in this chunk (each block is 64 bytes = 16 words)
    // Only thread 0 does the compression to avoid race conditions on shared cv
    if (tid == 0) {
        const int blocks_per_chunk = 16;

        for (int block_idx = 0; block_idx < blocks_per_chunk; block_idx++) {
            // Determine block length
            uint32_t block_len = 64;
            uint64_t block_start = block_idx * 64;
            if (block_start >= chunk_size) {
                break; // This block is entirely padding
            }
            if (block_start + 64 > chunk_size) {
                block_len = (uint32_t)(chunk_size - block_start);
            }

            // Set flags
            uint32_t flags = 0;
            if (block_idx == 0) {
                flags |= 0x01; // CHUNK_START
            }
            // Check if this is the last block in the chunk
            bool is_last_block = (block_idx == blocks_per_chunk - 1) || (block_start + 64 >= chunk_size);
            if (is_last_block) {
                flags |= 0x02; // CHUNK_END
                // For single-chunk inputs, also set ROOT flag on last block
                if (is_single_chunk) {
                    flags |= 0x08; // ROOT
                }
            }

            // Get pointer to this block's words (16 words = 64 bytes)
            const threadgroup uint32_t *block_words = &chunk_data[block_idx * 16];

            // Compress this block, updating cv in place
            compress_block(cv, block_words, (uint64_t)block_idx, block_len, flags);
        }
    }
    threadgroup_barrier(mem_flags::mem_threadgroup);

    // Write output hash (32 bytes = 8 words)
    if (tid < 8) {
        output[chunk_idx * 8 + tid] = cv[tid];
    }
}

// Merge tree kernel for combining chunk hashes
// This implements parent node compression in BLAKE3 tree
kernel void blake3_merge_tree(
    device const uint32_t *chunk_hashes [[buffer(0)]],
    device uint32_t *output [[buffer(1)]],
    constant uint32_t &num_parents [[buffer(2)]],
    constant uint32_t &num_children [[buffer(3)]],
    constant uint32_t &is_root [[buffer(4)]],
    uint gid [[thread_position_in_grid]]
) {
    uint parent_idx = gid;
    if (parent_idx >= num_parents) return;

    // Each parent node combines two child hashes (left and right)
    uint left_idx = parent_idx * 2;
    uint right_idx = parent_idx * 2 + 1;

    // Parent node compression: hash(left_cv || right_cv)
    // In BLAKE3, parent nodes use a 64-byte block containing both child CVs
    uint32_t block[16]; // 64 bytes
    uint32_t cv[8];

    // Initialize CV with IV
    for (int i = 0; i < 8; i++) {
        cv[i] = BLAKE3_IV[i];
    }

    // Load left child CV (32 bytes = 8 words)
    for (int i = 0; i < 8; i++) {
        block[i] = chunk_hashes[left_idx * 8 + i];
    }

    // Load right child CV (32 bytes = 8 words), or zeros if no right child
    for (int i = 0; i < 8; i++) {
        if (right_idx < num_children) {
            block[8 + i] = chunk_hashes[right_idx * 8 + i];
        } else {
            block[8 + i] = 0;
        }
    }

    // Compress parent node with PARENT flag (0x04), add ROOT flag (0x08) if this is the final merge
    uint32_t flags = 0x04; // PARENT
    if (is_root && parent_idx == 0) {
        flags |= 0x08; // ROOT
    }

    // Inline compress for parent node (uses thread-local block)
    uint32_t state[16];

    // Initialize state
    for (int i = 0; i < 8; i++) {
        state[i] = cv[i];
    }
    state[8] = BLAKE3_IV[0];
    state[9] = BLAKE3_IV[1];
    state[10] = BLAKE3_IV[2];
    state[11] = BLAKE3_IV[3];
    state[12] = 0; // Counter low
    state[13] = 0; // Counter high
    state[14] = 64; // block_len
    state[15] = flags;

    // 7 rounds
    uint32_t msg[16];
    for (int round = 0; round < 7; round++) {
        for (int i = 0; i < 16; i++) {
            msg[i] = block[MSG_SCHEDULE[round][i]];
        }
        // Inline round_fn
        // Columns
        g(state, 0, 4, 8, 12, msg[0], msg[1]);
        g(state, 1, 5, 9, 13, msg[2], msg[3]);
        g(state, 2, 6, 10, 14, msg[4], msg[5]);
        g(state, 3, 7, 11, 15, msg[6], msg[7]);
        // Diagonals
        g(state, 0, 5, 10, 15, msg[8], msg[9]);
        g(state, 1, 6, 11, 12, msg[10], msg[11]);
        g(state, 2, 7, 8, 13, msg[12], msg[13]);
        g(state, 3, 4, 9, 14, msg[14], msg[15]);
    }

    // XOR halves
    for (int i = 0; i < 8; i++) {
        cv[i] = state[i] ^ state[i + 8];
    }

    // Write output
    for (int i = 0; i < 8; i++) {
        output[parent_idx * 8 + i] = cv[i];
    }
}
"#;

#[cfg(test)]
mod tests {
    #[test]
    fn test_kernel_source_not_empty() {
        assert!(!super::BLAKE3_METAL_KERNEL.is_empty());
    }

    #[test]
    fn test_kernel_contains_functions() {
        let kernel = super::BLAKE3_METAL_KERNEL;
        assert!(kernel.contains("kernel void blake3_hash_chunks"));
        assert!(kernel.contains("kernel void blake3_merge_tree"));
    }

    #[test]
    fn test_kernel_contains_iv() {
        let kernel = super::BLAKE3_METAL_KERNEL;
        assert!(kernel.contains("0x6A09E667"));
        assert!(kernel.contains("BLAKE3_IV"));
    }
}
