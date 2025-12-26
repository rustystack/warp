//! GPU-accelerated ChaCha20-Poly1305 encryption for Metal backend
//!
//! This module provides the Metal Shading Language (MSL) implementation
//! of ChaCha20 for Apple GPUs (M1/M2/M3/M4 series).
//!
//! # Algorithm Overview
//!
//! ChaCha20 is a stream cipher that generates keystream blocks:
//! - 64-byte blocks generated from 256-bit key + 96-bit nonce + 32-bit counter
//! - Each block independent (highly parallelizable)
//! - XOR keystream with plaintext
//!
//! # Metal Parallelization Strategy
//!
//! ## Block-level parallelism:
//! - One thread per ChaCha20 block (64 bytes)
//! - Each thread keeps all state in registers
//! - 20 rounds of quarter-round operations
//!
//! ## Memory access pattern:
//! - Coalesced reads for key and nonce
//! - Each thread reads/writes 64 bytes
//! - Minimal memory divergence

/// Metal Shading Language kernel source for ChaCha20 encryption
///
/// Key differences from CUDA version:
/// - Uses `kernel` instead of `__global__`
/// - Uses `thread_position_in_grid` for global thread index
/// - Uses `constant` instead of `__constant__`
/// - No `#pragma unroll` (Metal compiler handles this)
pub const CHACHA20_METAL_KERNEL: &str = r#"
#include <metal_stdlib>
using namespace metal;

// ChaCha20 constants ("expand 32-byte k")
constant uint32_t SIGMA[4] = {
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
};

// Quarter round operation
inline void quarter_round(
    thread uint32_t &a, thread uint32_t &b,
    thread uint32_t &c, thread uint32_t &d
) {
    a += b; d ^= a; d = (d << 16) | (d >> 16);
    c += d; b ^= c; b = (b << 12) | (b >> 20);
    a += b; d ^= a; d = (d << 8) | (d >> 24);
    c += d; b ^= c; b = (b << 7) | (b >> 25);
}

// ChaCha20 block function - generates 64-byte keystream block
inline void chacha20_block(
    thread uint32_t state[16],
    const device uint32_t *key,       // 8 words
    const device uint32_t *nonce,     // 3 words
    uint32_t counter
) {
    // Initialize state
    state[0] = SIGMA[0];
    state[1] = SIGMA[1];
    state[2] = SIGMA[2];
    state[3] = SIGMA[3];

    // Key (8 words)
    for (int i = 0; i < 8; i++) {
        state[4 + i] = key[i];
    }

    // Counter (1 word)
    state[12] = counter;

    // Nonce (3 words)
    state[13] = nonce[0];
    state[14] = nonce[1];
    state[15] = nonce[2];

    // Save original state
    uint32_t original[16];
    for (int i = 0; i < 16; i++) {
        original[i] = state[i];
    }

    // 20 rounds (10 double rounds)
    for (int i = 0; i < 10; i++) {
        // Column rounds
        quarter_round(state[0], state[4], state[8], state[12]);
        quarter_round(state[1], state[5], state[9], state[13]);
        quarter_round(state[2], state[6], state[10], state[14]);
        quarter_round(state[3], state[7], state[11], state[15]);

        // Diagonal rounds
        quarter_round(state[0], state[5], state[10], state[15]);
        quarter_round(state[1], state[6], state[11], state[12]);
        quarter_round(state[2], state[7], state[8], state[13]);
        quarter_round(state[3], state[4], state[9], state[14]);
    }

    // Add original state
    for (int i = 0; i < 16; i++) {
        state[i] += original[i];
    }
}

// Main ChaCha20 encryption kernel
// Each thread processes one 64-byte ChaCha20 block
kernel void chacha20_encrypt(
    device const uint8_t *plaintext [[buffer(0)]],
    device uint8_t *ciphertext [[buffer(1)]],
    device const uint32_t *key [[buffer(2)]],       // 8 words (32 bytes)
    device const uint32_t *nonce [[buffer(3)]],     // 3 words (12 bytes)
    constant uint32_t &counter_base [[buffer(4)]],
    constant uint64_t &data_size [[buffer(5)]],
    uint gid [[thread_position_in_grid]]
) {
    uint64_t block_idx = gid;
    uint64_t byte_offset = block_idx * 64;

    if (byte_offset >= data_size) return;

    // Generate keystream for this block
    uint32_t state[16];

    // Generate keystream block
    uint32_t counter = counter_base + (uint32_t)block_idx;
    chacha20_block(state, key, nonce, counter);

    // XOR with plaintext (handle partial block at end)
    uint64_t remaining = data_size - byte_offset;
    int block_bytes = (remaining < 64) ? (int)remaining : 64;

    // Process in 4-byte words for efficiency
    for (int i = 0; i < 16 && (i * 4) < block_bytes; i++) {
        uint32_t plaintext_word = 0;
        uint32_t keystream_word = state[i];

        // Load plaintext word (handle partial word at end)
        for (int j = 0; j < 4 && (i * 4 + j) < block_bytes; j++) {
            plaintext_word |= ((uint32_t)plaintext[byte_offset + i * 4 + j]) << (j * 8);
        }

        // XOR and store
        uint32_t ciphertext_word = plaintext_word ^ keystream_word;

        // Write ciphertext (handle partial word)
        for (int j = 0; j < 4 && (i * 4 + j) < block_bytes; j++) {
            ciphertext[byte_offset + i * 4 + j] = (ciphertext_word >> (j * 8)) & 0xFF;
        }
    }
}

// Optimized version: process 4 blocks per thread for better ILP
kernel void chacha20_encrypt_coalesced(
    device const uint8_t *plaintext [[buffer(0)]],
    device uint8_t *ciphertext [[buffer(1)]],
    device const uint32_t *key [[buffer(2)]],
    device const uint32_t *nonce [[buffer(3)]],
    constant uint32_t &counter_base [[buffer(4)]],
    constant uint64_t &data_size [[buffer(5)]],
    uint gid [[thread_position_in_grid]]
) {
    // Each thread processes 4 consecutive 64-byte blocks
    uint64_t base_block = (uint64_t)gid * 4;
    uint64_t byte_offset = base_block * 64;

    if (byte_offset >= data_size) return;

    // Process 4 blocks
    for (int block_offset = 0; block_offset < 4; block_offset++) {
        uint64_t current_offset = byte_offset + block_offset * 64;
        if (current_offset >= data_size) break;

        uint32_t state[16];
        uint32_t counter = counter_base + (uint32_t)(base_block + block_offset);

        // Generate keystream
        chacha20_block(state, key, nonce, counter);

        // XOR with plaintext
        uint64_t remaining = data_size - current_offset;
        int block_bytes = (remaining < 64) ? (int)remaining : 64;

        for (int i = 0; i < 16; i++) {
            if (i * 4 >= block_bytes) break;

            uint32_t plain = 0;
            int bytes_to_process = min(4, block_bytes - i * 4);

            // Load plaintext
            for (int j = 0; j < bytes_to_process; j++) {
                plain |= ((uint32_t)plaintext[current_offset + i * 4 + j]) << (j * 8);
            }

            // Encrypt
            uint32_t cipher = plain ^ state[i];

            // Store ciphertext
            for (int j = 0; j < bytes_to_process; j++) {
                ciphertext[current_offset + i * 4 + j] = (cipher >> (j * 8)) & 0xFF;
            }
        }
    }
}
"#;

#[cfg(test)]
mod tests {
    #[test]
    fn test_kernel_source_not_empty() {
        assert!(!super::CHACHA20_METAL_KERNEL.is_empty());
    }

    #[test]
    fn test_kernel_contains_functions() {
        let kernel = super::CHACHA20_METAL_KERNEL;
        assert!(kernel.contains("kernel void chacha20_encrypt"));
        assert!(kernel.contains("kernel void chacha20_encrypt_coalesced"));
    }

    #[test]
    fn test_kernel_contains_sigma() {
        let kernel = super::CHACHA20_METAL_KERNEL;
        assert!(kernel.contains("0x61707865")); // "expa"
        assert!(kernel.contains("SIGMA"));
    }

    #[test]
    fn test_kernel_contains_quarter_round() {
        let kernel = super::CHACHA20_METAL_KERNEL;
        assert!(kernel.contains("quarter_round"));
        assert!(kernel.contains("chacha20_block"));
    }
}
