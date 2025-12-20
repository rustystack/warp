//! Compression and encryption pipeline example
//!
//! Demonstrates the warp data transformation pipeline:
//! data -> compress -> encrypt -> ready for transfer
//!
//! Run with: cargo run --example compress_encrypt

use warp_compress::{Compressor, ZstdCompressor, Lz4Compressor};
use warp_crypto::encrypt::{encrypt, decrypt, Key};
use warp_hash::hash;

fn main() {
    // Sample data with some compressibility
    let original = b"This is sample data that will be compressed and encrypted. \
                     Repeating patterns help compression: AAAAAABBBBBBCCCCCC \
                     This demonstrates the warp security pipeline.";

    println!("Original size: {} bytes", original.len());
    println!("Original data: {:?}\n", String::from_utf8_lossy(original));

    // Step 1: Compress with Zstd (best ratio)
    let zstd = ZstdCompressor::new(3).expect("Failed to create compressor");
    let compressed = zstd.compress(original).expect("Compression failed");
    println!("Zstd compressed: {} bytes ({:.1}% of original)",
             compressed.len(),
             (compressed.len() as f64 / original.len() as f64) * 100.0);

    // Alternative: LZ4 (faster, less compression)
    let lz4 = Lz4Compressor::new();
    let lz4_compressed = lz4.compress(original).expect("LZ4 compression failed");
    println!("LZ4 compressed:  {} bytes ({:.1}% of original)\n",
             lz4_compressed.len(),
             (lz4_compressed.len() as f64 / original.len() as f64) * 100.0);

    // Step 2: Encrypt with ChaCha20-Poly1305
    let key = Key::from_bytes([0x42u8; 32]); // In production, derive from password
    let encrypted = encrypt(&key, &compressed).expect("Encryption failed");
    println!("Encrypted size: {} bytes (includes 12-byte nonce + 16-byte tag)",
             encrypted.len());

    // Step 3: Hash for integrity verification
    let content_hash = hash(&encrypted);
    println!("BLAKE3 hash: {}\n", hex::encode(&content_hash[..8]));

    // Reverse the pipeline
    println!("--- Decryption Pipeline ---");

    // Verify hash
    let verify_hash = hash(&encrypted);
    assert_eq!(content_hash, verify_hash, "Hash verification failed!");
    println!("Hash verified: OK");

    // Decrypt
    let decrypted = decrypt(&key, &encrypted).expect("Decryption failed");
    println!("Decrypted: {} bytes", decrypted.len());

    // Decompress
    let restored = zstd.decompress(&decrypted).expect("Decompression failed");
    println!("Decompressed: {} bytes", restored.len());

    // Verify
    assert_eq!(original.as_slice(), restored.as_slice());
    println!("\nFull roundtrip verified: OK");
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
