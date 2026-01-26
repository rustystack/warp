//! GPU-accelerated ChaCha20-Poly1305 encryption
//!
//! # Algorithm Overview
//!
//! ChaCha20 is a stream cipher that generates keystream blocks:
//! - 64-byte blocks generated from 256-bit key + 96-bit nonce + 32-bit counter
//! - Each block independent (highly parallelizable)
//! - XOR keystream with plaintext
//!
//! Poly1305 is a MAC (Message Authentication Code):
//! - Authenticates ciphertext
//! - Sequential dependency (less GPU-friendly)
//! - Use CPU for Poly1305, GPU for ChaCha20
//!
//! # GPU Parallelization Strategy
//!
//! ## Block-level parallelism:
//! - One thread per ChaCha20 block (64 bytes)
//! - Grid size: ceil(data_size / 64)
//! - Block size: 256 threads (8 warps) - process 256 blocks per SM
//!
//! ## Register-intensive computation:
//! - ChaCha20 state: 16 x 32-bit words (64 bytes)
//! - All state in registers (no shared memory needed)
//! - 20 rounds of quarter-round operations
//! - Maximize instruction-level parallelism
//!
//! ## Memory access pattern:
//! - Coalesced reads: 256 threads read 256 * 64 = 16KB per block
//! - Coalesced writes: 256 threads write 16KB per block
//! - Minimal memory divergence
//!
//! # Performance Characteristics
//!
//! On RTX 4090:
//! - 128 SMs * 256 threads/SM = 32,768 concurrent blocks
//! - 32K blocks * 64 bytes = 2MB per wave
//! - At 2000 MHz: ~10,000 waves/sec = 20+ GB/s
//! - Memory bandwidth bound on PCIe 3.0, compute bound on PCIe 4.0+

use crate::{Error, Result};
use cudarc::driver::{CudaContext, CudaFunction, CudaModule, CudaStream, PushKernelArg};
use cudarc::nvrtc::compile_ptx;
use std::sync::Arc;
use tracing::{debug, trace};

/// ChaCha20 constants
#[allow(dead_code)]
mod constants {
    pub const BLOCK_SIZE: usize = 64;
    pub const KEY_SIZE: usize = 32;
    pub const NONCE_SIZE: usize = 12;
    pub const TAG_SIZE: usize = 16;

    // "expand 32-byte k" in little-endian
    #[allow(dead_code)]
    pub const SIGMA: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
}

/// Minimum size to use GPU encryption (below this, CPU is faster due to transfer overhead)
pub const GPU_CROSSOVER_SIZE: usize = 256 * 1024; // 256KB

/// CUDA kernel for ChaCha20 encryption
///
/// Each thread processes one 64-byte block independently.
/// State is kept in registers for maximum throughput.
const CHACHA20_KERNEL: &str = r#"
// ChaCha20 constants ("expand 32-byte k")
__constant__ unsigned int SIGMA[4] = {
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
};

// Quarter round operation
__device__ __forceinline__ void quarter_round(
    unsigned int &a, unsigned int &b, unsigned int &c, unsigned int &d
) {
    a += b; d ^= a; d = (d << 16) | (d >> 16);
    c += d; b ^= c; b = (b << 12) | (b >> 20);
    a += b; d ^= a; d = (d << 8) | (d >> 24);
    c += d; b ^= c; b = (b << 7) | (b >> 25);
}

// ChaCha20 block function
__device__ void chacha20_block(
    unsigned int state[16],
    const unsigned int key[8],
    const unsigned int nonce[3],
    unsigned int counter
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
    unsigned int original[16];
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
// Grid: (num_blocks, 1, 1), Block: (256, 1, 1)
// Each thread processes one 64-byte ChaCha20 block
extern "C" __global__ void chacha20_encrypt(
    const unsigned char *plaintext,
    unsigned char *ciphertext,
    const unsigned int *key,        // 8 words (32 bytes)
    const unsigned int *nonce,      // 3 words (12 bytes)
    unsigned int counter_base,
    unsigned long long data_size
) {
    const unsigned long long block_idx = blockIdx.x * blockDim.x + threadIdx.x;
    const unsigned long long byte_offset = block_idx * 64;

    if (byte_offset >= data_size) return;

    // Generate keystream for this block
    unsigned int state[16];
    unsigned int key_local[8];
    unsigned int nonce_local[3];

    // Load key and nonce (broadcast from constant/global memory)
    for (int i = 0; i < 8; i++) {
        key_local[i] = key[i];
    }
    for (int i = 0; i < 3; i++) {
        nonce_local[i] = nonce[i];
    }

    // Generate keystream block
    unsigned int counter = counter_base + (unsigned int)block_idx;
    chacha20_block(state, key_local, nonce_local, counter);

    // XOR with plaintext (handle partial block at end)
    unsigned long long remaining = data_size - byte_offset;
    int block_bytes = (remaining < 64) ? remaining : 64;

    // Process in 4-byte words for efficiency
    for (int i = 0; i < 16 && (i * 4) < block_bytes; i++) {
        unsigned int plaintext_word = 0;
        unsigned int keystream_word = state[i];

        // Load plaintext word (handle partial word at end)
        for (int j = 0; j < 4 && (i * 4 + j) < block_bytes; j++) {
            plaintext_word |= ((unsigned int)plaintext[byte_offset + i * 4 + j]) << (j * 8);
        }

        // XOR and store
        unsigned int ciphertext_word = plaintext_word ^ keystream_word;

        // Write ciphertext (handle partial word)
        for (int j = 0; j < 4 && (i * 4 + j) < block_bytes; j++) {
            ciphertext[byte_offset + i * 4 + j] = (ciphertext_word >> (j * 8)) & 0xFF;
        }
    }
}

// Optimized version: process 4 blocks per thread for better ILP
extern "C" __global__ void chacha20_encrypt_coalesced(
    const unsigned char *plaintext,
    unsigned char *ciphertext,
    const unsigned int *key,
    const unsigned int *nonce,
    unsigned int counter_base,
    unsigned long long data_size
) {
    // Each thread processes 4 consecutive 64-byte blocks
    const unsigned long long thread_idx = blockIdx.x * blockDim.x + threadIdx.x;
    const unsigned long long base_block = thread_idx * 4;
    const unsigned long long byte_offset = base_block * 64;

    if (byte_offset >= data_size) return;

    // Load key and nonce once
    unsigned int key_local[8];
    unsigned int nonce_local[3];

    #pragma unroll
    for (int i = 0; i < 8; i++) {
        key_local[i] = key[i];
    }
    #pragma unroll
    for (int i = 0; i < 3; i++) {
        nonce_local[i] = nonce[i];
    }

    // Process 4 blocks
    #pragma unroll
    for (int block_offset = 0; block_offset < 4; block_offset++) {
        unsigned long long current_offset = byte_offset + block_offset * 64;
        if (current_offset >= data_size) break;

        unsigned int state[16];
        unsigned int counter = counter_base + (unsigned int)(base_block + block_offset);

        // Generate keystream
        chacha20_block(state, key_local, nonce_local, counter);

        // XOR with plaintext
        unsigned long long remaining = data_size - current_offset;
        int block_bytes = (remaining < 64) ? remaining : 64;

        #pragma unroll
        for (int i = 0; i < 16; i++) {
            if (i * 4 >= block_bytes) break;

            unsigned int plain = 0;
            int bytes_to_process = min(4, block_bytes - i * 4);

            // Load plaintext
            for (int j = 0; j < bytes_to_process; j++) {
                plain |= ((unsigned int)plaintext[current_offset + i * 4 + j]) << (j * 8);
            }

            // Encrypt
            unsigned int cipher = plain ^ state[i];

            // Store ciphertext
            for (int j = 0; j < bytes_to_process; j++) {
                ciphertext[current_offset + i * 4 + j] = (cipher >> (j * 8)) & 0xFF;
            }
        }
    }
}
"#;

/// GPU ChaCha20-Poly1305 cipher
pub struct ChaCha20Poly1305 {
    /// CUDA context (reserved for future multi-GPU support)
    #[allow(dead_code)]
    ctx: Arc<CudaContext>,
    /// CUDA stream for asynchronous kernel execution and memory transfers
    stream: Arc<CudaStream>,
    /// Compiled module (kept alive for function lifetime)
    #[allow(dead_code)]
    module: Arc<CudaModule>,
    /// CUDA function handle for the chacha20_encrypt kernel
    encrypt_fn: CudaFunction,
}

impl ChaCha20Poly1305 {
    /// Create a new ChaCha20-Poly1305 cipher
    ///
    /// # Arguments
    /// * `ctx` - CUDA context to use
    pub fn new(ctx: Arc<CudaContext>) -> Result<Self> {
        let stream = ctx.default_stream();

        // Compile PTX from CUDA kernel source
        debug!("Compiling ChaCha20 CUDA kernel");
        let ptx = compile_ptx(CHACHA20_KERNEL)
            .map_err(|e| Error::CudaOperation(format!("PTX compilation failed: {:?}", e)))?;

        // Load module
        debug!("Loading ChaCha20 CUDA module");
        let module = ctx
            .load_module(ptx)
            .map_err(|e| Error::CudaOperation(format!("Module load failed: {:?}", e)))?;

        // Get function handle
        debug!("Loading chacha20_encrypt function");
        let encrypt_fn = module
            .load_function("chacha20_encrypt")
            .map_err(|e| Error::CudaOperation(format!("Function load failed: {:?}", e)))?;

        debug!("Created ChaCha20-Poly1305 GPU cipher");

        Ok(Self {
            ctx,
            stream,
            module,
            encrypt_fn,
        })
    }

    /// Encrypt data using ChaCha20-Poly1305
    ///
    /// # Arguments
    /// * `plaintext` - Input data to encrypt
    /// * `key` - 32-byte encryption key
    /// * `nonce` - 12-byte nonce
    ///
    /// # Returns
    /// Encrypted data with 16-byte Poly1305 tag appended
    ///
    /// # Performance
    /// - Data < 256KB: Uses CPU (SIMD-optimized chacha20poly1305 crate)
    /// - Data >= 256KB: Uses GPU for ChaCha20, CPU for Poly1305 tag
    pub fn encrypt(&self, plaintext: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Result<Vec<u8>> {
        use chacha20poly1305::{
            ChaCha20Poly1305 as CpuCipher, Nonce,
            aead::{Aead, KeyInit},
        };

        // Use GPU for large data where transfer overhead is amortized
        if plaintext.len() >= GPU_CROSSOVER_SIZE {
            trace!("Using GPU encryption for {} bytes", plaintext.len());
            return self.encrypt_with_gpu_chacha20(plaintext, key, nonce);
        }

        // Use CPU for small data (transfer overhead > compute savings)
        trace!("Using CPU encryption for {} bytes", plaintext.len());
        let cipher = CpuCipher::new(key.into());
        let nonce_obj = Nonce::from_slice(nonce);

        cipher
            .encrypt(nonce_obj, plaintext)
            .map_err(|e| Error::Crypto(e.to_string()))
    }

    /// Encrypt using GPU ChaCha20 with CPU Poly1305 tag
    ///
    /// This hybrid approach uses GPU for the parallelizable ChaCha20 encryption
    /// and CPU for the sequential Poly1305 authentication tag computation.
    /// Follows RFC 8439 AEAD construction exactly.
    fn encrypt_with_gpu_chacha20(
        &self,
        plaintext: &[u8],
        key: &[u8; 32],
        nonce: &[u8; 12],
    ) -> Result<Vec<u8>> {
        use chacha20::{
            ChaCha20,
            cipher::{KeyIvInit, StreamCipher},
        };
        use poly1305::{
            Poly1305,
            universal_hash::{KeyInit as PolyKeyInit, UniversalHash},
        };

        // Step 1: Derive Poly1305 key from ChaCha20 block 0 (first 32 bytes of keystream)
        let mut poly_key_block = [0u8; 64];
        let mut chacha = ChaCha20::new(key.into(), nonce.into());
        chacha.apply_keystream(&mut poly_key_block);
        let poly_key: [u8; 32] = poly_key_block[..32].try_into().unwrap();

        // Step 2: Encrypt with GPU ChaCha20 starting at counter 1 (per RFC 8439)
        // Counter 0 is reserved for Poly1305 key derivation
        let ciphertext = self.encrypt_gpu_with_counter(plaintext, key, nonce, 1)?;

        // Step 3: Compute Poly1305 tag (RFC 8439 construction with no AAD)
        // Tag = Poly1305(poly_key, pad16(ciphertext) || len_aad || len_ciphertext)
        let mut mac = Poly1305::new((&poly_key).into());

        // Feed ciphertext with padding to 16-byte boundary
        mac.update_padded(&ciphertext);

        // Feed lengths (AAD length = 0, ciphertext length) - each as 8-byte LE
        let aad_len_bytes = 0u64.to_le_bytes();
        let ct_len_bytes = (ciphertext.len() as u64).to_le_bytes();
        let mut len_block = [0u8; 16];
        len_block[..8].copy_from_slice(&aad_len_bytes);
        len_block[8..].copy_from_slice(&ct_len_bytes);
        mac.update_padded(&len_block);

        let tag = mac.finalize();

        // Step 4: Append 16-byte tag to ciphertext
        let mut result = ciphertext;
        result.extend_from_slice(tag.as_slice());

        Ok(result)
    }

    /// Decrypt data using ChaCha20-Poly1305
    ///
    /// # Arguments
    /// * `ciphertext` - Encrypted data with tag
    /// * `key` - 32-byte decryption key
    /// * `nonce` - 12-byte nonce
    ///
    /// # Returns
    /// Decrypted plaintext if authentication succeeds
    pub fn decrypt(&self, ciphertext: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Result<Vec<u8>> {
        use chacha20poly1305::{
            ChaCha20Poly1305 as CpuCipher, Nonce,
            aead::{Aead, KeyInit},
        };

        // Use CPU implementation for correctness
        let cipher = CpuCipher::new(key.into());
        let nonce_obj = Nonce::from_slice(nonce);

        cipher
            .decrypt(nonce_obj, ciphertext)
            .map_err(|e| Error::Crypto(e.to_string()))
    }

    /// Encrypt data using GPU (experimental)
    ///
    /// # Warning
    /// This method uses the GPU kernel which is still under development.
    /// Results may not match CPU encryption for all inputs. Use `encrypt()` for
    /// production code.
    ///
    /// # Arguments
    /// * `plaintext` - Input data to encrypt
    /// * `key` - 32-byte encryption key
    /// * `nonce` - 12-byte nonce
    ///
    /// # Returns
    /// Encrypted data (ChaCha20 stream cipher output, no Poly1305 tag yet)
    pub fn encrypt_gpu_experimental(
        &self,
        plaintext: &[u8],
        key: &[u8; 32],
        nonce: &[u8; 12],
    ) -> Result<Vec<u8>> {
        self.encrypt_gpu(plaintext, key, nonce)
    }

    /// Internal GPU encryption implementation
    ///
    /// # Arguments
    /// * `plaintext` - Data to encrypt
    /// * `key` - 32-byte key
    /// * `nonce` - 12-byte nonce
    /// * `counter_base` - Starting counter value (0 for raw ChaCha20, 1 for AEAD)
    fn encrypt_gpu_with_counter(
        &self,
        plaintext: &[u8],
        key: &[u8; 32],
        nonce: &[u8; 12],
        counter_base: u32,
    ) -> Result<Vec<u8>> {
        if plaintext.is_empty() {
            return Ok(vec![]);
        }

        trace!(
            "GPU encrypting {} bytes with counter_base={}",
            plaintext.len(),
            counter_base
        );

        // 1. Transfer plaintext to GPU
        let d_plaintext = self.stream.clone_htod(plaintext)?;

        // 2. Allocate ciphertext buffer
        let mut d_ciphertext = self
            .stream
            .alloc_zeros::<u8>(plaintext.len())
            .map_err(|e| Error::CudaOperation(format!("Ciphertext allocation failed: {:?}", e)))?;

        // 3. Convert key to u32 words (8 words = 32 bytes)
        let mut key_words = [0u32; 8];
        for i in 0..8 {
            key_words[i] =
                u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
        }
        let d_key = self.stream.clone_htod(&key_words)?;

        // 4. Convert nonce to u32 words (3 words = 12 bytes)
        let mut nonce_words = [0u32; 3];
        for i in 0..3 {
            nonce_words[i] = u32::from_le_bytes([
                nonce[i * 4],
                nonce[i * 4 + 1],
                nonce[i * 4 + 2],
                nonce[i * 4 + 3],
            ]);
        }
        let d_nonce = self.stream.clone_htod(&nonce_words)?;

        // 5. Launch kernel
        let (grid_size, block_size, _) = self.compute_launch_config(plaintext.len(), false);
        trace!("Launch config: grid={}, block={}", grid_size, block_size);

        let data_size = plaintext.len() as u64;

        // SAFETY: CUDA kernel launch is safe because:
        // 1. self.encrypt_fn is a valid CudaFunction loaded from our compiled PTX
        // 2. All device buffers (d_plaintext, d_ciphertext, d_key, d_nonce) are valid
        //    allocations created by cudarc on this stream
        // 3. grid_size and block_size are computed to be within device limits
        // 4. The kernel arguments match the expected signature in the PTX code
        // 5. We synchronize the stream after launch to ensure completion
        unsafe {
            let cfg = cudarc::driver::LaunchConfig {
                grid_dim: (grid_size, 1, 1),
                block_dim: (block_size, 1, 1),
                shared_mem_bytes: 0,
            };

            self.stream
                .launch_builder(&self.encrypt_fn)
                .arg(&d_plaintext)
                .arg(&mut d_ciphertext)
                .arg(&d_key)
                .arg(&d_nonce)
                .arg(&counter_base)
                .arg(&data_size)
                .launch(cfg)
                .map_err(|e| Error::CudaOperation(format!("Kernel launch failed: {:?}", e)))?;
        }

        // 6. Synchronize stream
        self.stream
            .synchronize()
            .map_err(|e| Error::CudaOperation(format!("Stream sync failed: {:?}", e)))?;

        // 7. Transfer ciphertext back
        let ciphertext = self.stream.clone_dtoh(&d_ciphertext)?;

        trace!("GPU encryption completed");
        Ok(ciphertext)
    }

    /// Internal GPU encryption (counter starts at 0, for experimental use)
    fn encrypt_gpu(&self, plaintext: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Result<Vec<u8>> {
        self.encrypt_gpu_with_counter(plaintext, key, nonce, 0)
    }

    /// Compute launch configuration for encryption
    ///
    /// # Arguments
    /// * `data_size` - Size of input data
    /// * `coalesced` - Use coalesced kernel (4 blocks per thread)
    ///
    /// # Returns
    /// (grid_size, block_size, num_chacha_blocks)
    fn compute_launch_config(&self, data_size: usize, coalesced: bool) -> (u32, u32, usize) {
        const CHACHA_BLOCK: usize = 64;
        const THREADS_PER_BLOCK: u32 = 256;

        let num_chacha_blocks = data_size.div_ceil(CHACHA_BLOCK);

        if coalesced {
            // 4 blocks per thread
            let num_threads = num_chacha_blocks.div_ceil(4);
            let grid_size = num_threads.div_ceil(THREADS_PER_BLOCK as usize) as u32;
            (grid_size, THREADS_PER_BLOCK, num_chacha_blocks)
        } else {
            // 1 block per thread
            let grid_size = num_chacha_blocks.div_ceil(THREADS_PER_BLOCK as usize) as u32;
            (grid_size, THREADS_PER_BLOCK, num_chacha_blocks)
        }
    }
}

/// Batch encryption for multiple independent messages
///
/// Highly efficient on GPU as each message can be encrypted independently.
pub struct EncryptionBatch {
    /// Underlying ChaCha20-Poly1305 cipher instance used for encrypting all messages in the batch
    cipher: ChaCha20Poly1305,
}

impl EncryptionBatch {
    /// Create a new batch cipher
    pub fn new(ctx: Arc<CudaContext>) -> Result<Self> {
        Ok(Self {
            cipher: ChaCha20Poly1305::new(ctx)?,
        })
    }

    /// Encrypt multiple messages in parallel
    ///
    /// # Arguments
    /// * `plaintexts` - Slice of plaintext messages
    /// * `keys` - Encryption keys (one per message)
    /// * `nonces` - Nonces (one per message)
    ///
    /// # Returns
    /// Vector of encrypted messages with tags
    pub fn encrypt_batch(
        &self,
        plaintexts: &[&[u8]],
        keys: &[[u8; 32]],
        nonces: &[[u8; 12]],
    ) -> Result<Vec<Vec<u8>>> {
        if plaintexts.len() != keys.len() || plaintexts.len() != nonces.len() {
            return Err(Error::InvalidParameter(
                "Mismatched plaintexts, keys, and nonces lengths".to_string(),
            ));
        }

        // For each message, encrypt independently
        // In production, this would:
        // 1. Concatenate all messages with size prefixes
        // 2. Single GPU transfer
        // 3. Launch one grid processing all messages
        // 4. Single GPU transfer back
        // This amortizes transfer overhead

        plaintexts
            .iter()
            .zip(keys.iter())
            .zip(nonces.iter())
            .map(|((plain, key), nonce)| self.cipher.encrypt(plain, key, nonce))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to check if GPU is available
    fn try_get_cipher() -> Option<ChaCha20Poly1305> {
        match cudarc::driver::CudaContext::new(0) {
            Ok(ctx) => match ChaCha20Poly1305::new(ctx) {
                Ok(cipher) => Some(cipher),
                Err(e) => {
                    eprintln!("Failed to create cipher: {}", e);
                    None
                }
            },
            Err(e) => {
                eprintln!("No GPU available: {:?}", e);
                None
            }
        }
    }

    // ========================================================================
    // TDD Phase 1: Core Functionality Tests
    // ========================================================================

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // Test basic encrypt/decrypt roundtrip
        let plaintext = b"Hello, ChaCha20-Poly1305 world!";
        let key = [0x42u8; 32];
        let nonce = [0x13u8; 12];

        if let Some(cipher) = try_get_cipher() {
            let ciphertext = cipher
                .encrypt(plaintext, &key, &nonce)
                .expect("Encryption should succeed");

            // Ciphertext should be longer (includes 16-byte tag)
            assert!(ciphertext.len() > plaintext.len());
            assert_eq!(ciphertext.len(), plaintext.len() + 16);

            let decrypted = cipher
                .decrypt(&ciphertext, &key, &nonce)
                .expect("Decryption should succeed");

            assert_eq!(&decrypted[..], plaintext);
        } else {
            eprintln!("Skipping GPU test - no GPU available");
        }
    }

    #[test]
    fn test_hasher_creation() {
        // Test that cipher can be created (module loads, kernel compiles)
        if let Some(_cipher) = try_get_cipher() {
            // Success - kernel compiled and loaded
        } else {
            eprintln!("Skipping GPU test - no GPU available");
        }
    }

    #[test]
    fn test_empty_data() {
        // Test encrypting empty data
        let plaintext: &[u8] = &[];
        let key = [0u8; 32];
        let nonce = [0u8; 12];

        if let Some(cipher) = try_get_cipher() {
            let ciphertext = cipher
                .encrypt(plaintext, &key, &nonce)
                .expect("Empty data encryption should succeed");

            // Should only contain the 16-byte tag
            assert_eq!(ciphertext.len(), 16);

            let decrypted = cipher
                .decrypt(&ciphertext, &key, &nonce)
                .expect("Empty data decryption should succeed");

            assert_eq!(decrypted.len(), 0);
        } else {
            eprintln!("Skipping GPU test - no GPU available");
        }
    }

    #[test]
    fn test_different_keys_different_ciphertext() {
        // Test that different keys produce different ciphertexts
        let plaintext = b"Same plaintext for both encryptions";
        let key1 = [0x00u8; 32];
        let key2 = [0xFFu8; 32];
        let nonce = [0x42u8; 12];

        if let Some(cipher) = try_get_cipher() {
            let ciphertext1 = cipher
                .encrypt(plaintext, &key1, &nonce)
                .expect("Encryption 1 should succeed");
            let ciphertext2 = cipher
                .encrypt(plaintext, &key2, &nonce)
                .expect("Encryption 2 should succeed");

            assert_ne!(
                ciphertext1, ciphertext2,
                "Different keys should produce different ciphertexts"
            );
        } else {
            eprintln!("Skipping GPU test - no GPU available");
        }
    }

    #[test]
    fn test_different_nonces_different_ciphertext() {
        // Test that different nonces produce different ciphertexts
        let plaintext = b"Same plaintext for both encryptions";
        let key = [0x55u8; 32];
        let nonce1 = [0x00u8; 12];
        let nonce2 = [0xFFu8; 12];

        if let Some(cipher) = try_get_cipher() {
            let ciphertext1 = cipher
                .encrypt(plaintext, &key, &nonce1)
                .expect("Encryption 1 should succeed");
            let ciphertext2 = cipher
                .encrypt(plaintext, &key, &nonce2)
                .expect("Encryption 2 should succeed");

            assert_ne!(
                ciphertext1, ciphertext2,
                "Different nonces should produce different ciphertexts"
            );
        } else {
            eprintln!("Skipping GPU test - no GPU available");
        }
    }

    #[test]
    fn test_wrong_key_decryption_fails() {
        // Test that decryption with wrong key fails
        let plaintext = b"Secret message";
        let key_encrypt = [0x11u8; 32];
        let key_decrypt = [0x22u8; 32];
        let nonce = [0x33u8; 12];

        if let Some(cipher) = try_get_cipher() {
            let ciphertext = cipher
                .encrypt(plaintext, &key_encrypt, &nonce)
                .expect("Encryption should succeed");

            let result = cipher.decrypt(&ciphertext, &key_decrypt, &nonce);
            assert!(result.is_err(), "Decryption with wrong key should fail");
        } else {
            eprintln!("Skipping GPU test - no GPU available");
        }
    }

    #[test]
    fn test_wrong_nonce_decryption_fails() {
        // Test that decryption with wrong nonce fails
        let plaintext = b"Secret message";
        let key = [0x44u8; 32];
        let nonce_encrypt = [0x55u8; 12];
        let nonce_decrypt = [0x66u8; 12];

        if let Some(cipher) = try_get_cipher() {
            let ciphertext = cipher
                .encrypt(plaintext, &key, &nonce_encrypt)
                .expect("Encryption should succeed");

            let result = cipher.decrypt(&ciphertext, &key, &nonce_decrypt);
            assert!(result.is_err(), "Decryption with wrong nonce should fail");
        } else {
            eprintln!("Skipping GPU test - no GPU available");
        }
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        // Test that tampered ciphertext fails authentication
        let plaintext = b"Authenticated message";
        let key = [0x77u8; 32];
        let nonce = [0x88u8; 12];

        if let Some(cipher) = try_get_cipher() {
            let mut ciphertext = cipher
                .encrypt(plaintext, &key, &nonce)
                .expect("Encryption should succeed");

            // Tamper with the ciphertext (flip a bit in the middle)
            if ciphertext.len() > 10 {
                ciphertext[5] ^= 0x01;
            }

            let result = cipher.decrypt(&ciphertext, &key, &nonce);
            assert!(
                result.is_err(),
                "Tampered ciphertext should fail authentication"
            );
        } else {
            eprintln!("Skipping GPU test - no GPU available");
        }
    }

    // ========================================================================
    // TDD Phase 2: Size Tests (consolidated)
    // ========================================================================

    #[test]
    fn test_various_data_sizes() {
        // Test encryption at various sizes: 1B, 4KB, 1MB
        if let Some(cipher) = try_get_cipher() {
            for (size, pattern) in [(1, 0x99u8), (4096, 0xBBu8), (1024 * 1024, 0xEEu8)] {
                let plaintext = vec![pattern; size];
                let key = [pattern; 32];
                let nonce = [pattern; 12];

                let ciphertext = cipher
                    .encrypt(&plaintext, &key, &nonce)
                    .expect(&format!("Encryption should succeed for {} bytes", size));
                let decrypted = cipher
                    .decrypt(&ciphertext, &key, &nonce)
                    .expect(&format!("Decryption should succeed for {} bytes", size));

                assert_eq!(decrypted, plaintext, "Roundtrip failed for {} bytes", size);
            }
        } else {
            eprintln!("Skipping GPU test - no GPU available");
        }
    }

    // ========================================================================
    // TDD Phase 3: GPU Kernel Tests (Experimental)
    // ========================================================================

    #[test]
    fn test_gpu_experimental_encrypt() {
        // Test GPU encryption experimental path
        let plaintext = b"GPU encryption test";
        let key = [0x12u8; 32];
        let nonce = [0x34u8; 12];

        if let Some(cipher) = try_get_cipher() {
            // GPU path produces raw ChaCha20 output (no Poly1305 tag)
            let gpu_ciphertext = cipher
                .encrypt_gpu_experimental(plaintext, &key, &nonce)
                .expect("GPU encryption should succeed");

            // Should be same length as plaintext (no tag in experimental mode)
            assert_eq!(gpu_ciphertext.len(), plaintext.len());

            // XOR again should give back plaintext (stream cipher property)
            let decrypted = cipher
                .encrypt_gpu_experimental(&gpu_ciphertext, &key, &nonce)
                .expect("GPU decrypt should succeed");

            assert_eq!(&decrypted[..], plaintext);
        } else {
            eprintln!("Skipping GPU test - no GPU available");
        }
    }

    #[test]
    fn test_gpu_experimental_empty_data() {
        // Test GPU experimental with empty data
        let plaintext: &[u8] = &[];
        let key = [0x56u8; 32];
        let nonce = [0x78u8; 12];

        if let Some(cipher) = try_get_cipher() {
            let ciphertext = cipher
                .encrypt_gpu_experimental(plaintext, &key, &nonce)
                .expect("GPU empty encryption should succeed");

            assert_eq!(ciphertext.len(), 0);
        } else {
            eprintln!("Skipping GPU test - no GPU available");
        }
    }

    #[test]
    fn test_gpu_experimental_various_sizes() {
        // Test GPU experimental with various data sizes
        if let Some(cipher) = try_get_cipher() {
            let key = [0x9Au8; 32];
            let nonce = [0xBCu8; 12];

            // Test sizes: 1, 63, 64, 65, 127, 128, 129, 1024
            for size in [1, 63, 64, 65, 127, 128, 129, 1024] {
                let plaintext = vec![0xDEu8; size];

                let ciphertext = cipher
                    .encrypt_gpu_experimental(&plaintext, &key, &nonce)
                    .expect("GPU encryption should succeed");

                assert_eq!(ciphertext.len(), plaintext.len());

                // Verify stream cipher property (double encryption = plaintext)
                let decrypted = cipher
                    .encrypt_gpu_experimental(&ciphertext, &key, &nonce)
                    .expect("GPU decrypt should succeed");

                assert_eq!(decrypted, plaintext, "Failed at size {}", size);
            }
        } else {
            eprintln!("Skipping GPU test - no GPU available");
        }
    }

    // ========================================================================
    // TDD Phase 4: Batch Processing Tests
    // ========================================================================

    #[test]
    fn test_batch_encryption() {
        // Test batch encryption functionality
        if let Ok(ctx) = cudarc::driver::CudaContext::new(0) {
            if let Ok(batch) = EncryptionBatch::new(ctx) {
                let data: Vec<Vec<u8>> = vec![b"Msg1".to_vec(), b"Msg2".to_vec()];
                let plaintexts: Vec<&[u8]> = data.iter().map(|d| d.as_slice()).collect();
                let keys = [[0x11u8; 32], [0x22u8; 32]];
                let nonces = [[0x44u8; 12], [0x55u8; 12]];

                let ciphertexts = batch
                    .encrypt_batch(&plaintexts, &keys, &nonces)
                    .expect("Batch encryption should succeed");
                assert_eq!(ciphertexts.len(), 2, "Should have 2 ciphertexts");
            }
        } else {
            eprintln!("Skipping batch test - no GPU available");
        }
    }

    #[test]
    fn test_batch_mismatched_lengths() {
        // Test that batch encryption fails with mismatched lengths
        if let Ok(ctx) = cudarc::driver::CudaContext::new(0) {
            if let Ok(batch) = EncryptionBatch::new(ctx) {
                let data1 = b"First".to_vec();
                let data2 = b"Second".to_vec();

                let plaintexts: Vec<&[u8]> = vec![&data1, &data2];
                let keys = [[0u8; 32]]; // Only 1 key
                let nonces = [[0u8; 12], [1u8; 12]];

                let result = batch.encrypt_batch(&plaintexts, &keys, &nonces);
                assert!(result.is_err(), "Should fail with mismatched lengths");
            }
        } else {
            eprintln!("Skipping batch test - no GPU available");
        }
    }

    // ========================================================================
    // TDD Phase 5: Utility and Configuration Tests
    // ========================================================================

    #[test]
    fn test_launch_config() {
        if let Some(cipher) = try_get_cipher() {
            // Test launch config for various sizes
            let (_grid, block, num_blocks) = cipher.compute_launch_config(1024 * 1024, false);
            assert_eq!(num_blocks, (1024 * 1024) / 64);
            assert_eq!(block, 256);

            // Test coalesced mode
            let (grid_coal, block_coal, _) = cipher.compute_launch_config(1024 * 1024, true);
            assert_eq!(block_coal, 256);
            assert!(grid_coal <= num_blocks as u32 / 4); // 4 blocks per thread
        }
    }

    #[test]
    fn test_constants() {
        // Verify constants are correct
        assert_eq!(constants::BLOCK_SIZE, 64);
        assert_eq!(constants::KEY_SIZE, 32);
        assert_eq!(constants::NONCE_SIZE, 12);
        assert_eq!(constants::TAG_SIZE, 16);

        // Verify ChaCha20 SIGMA constant
        assert_eq!(constants::SIGMA[0], 0x61707865); // "expa"
        assert_eq!(constants::SIGMA[1], 0x3320646e); // "nd 3"
        assert_eq!(constants::SIGMA[2], 0x79622d32); // "2-by"
        assert_eq!(constants::SIGMA[3], 0x6b206574); // "te k"
    }
}
