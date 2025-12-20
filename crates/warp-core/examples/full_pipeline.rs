//! Full warp data pipeline example
//!
//! Demonstrates the complete warp transfer preparation:
//! file -> chunk -> compress -> encrypt -> hash -> merkle tree
//!
//! Run with: cargo run --example full_pipeline

use std::io::Cursor;
use std::time::Instant;
use warp_io::{Chunker, ChunkerConfig};
use warp_compress::{Compressor, ZstdCompressor};
use warp_crypto::encrypt::{encrypt, decrypt, Key};
use warp_hash::hash;

fn main() {
    // Create 5MB of test data
    let data_size = 5 * 1024 * 1024;
    let data: Vec<u8> = (0..data_size)
        .map(|i| ((i * 17 + 13) % 256) as u8)
        .collect();

    println!("=== Warp Full Pipeline Demo ===\n");
    println!("Input: {} bytes ({:.2} MB)\n", data.len(), data.len() as f64 / 1024.0 / 1024.0);

    let start = Instant::now();

    // Step 1: Content-Defined Chunking
    println!("Step 1: Chunking (Buzhash rolling hash)");
    let config = ChunkerConfig {
        min_size: 128 * 1024,
        target_size: 512 * 1024,
        max_size: 2 * 1024 * 1024,
        window_size: 48,
    };
    let chunker = Chunker::new(config);
    let chunks = chunker.chunk(Cursor::new(&data)).expect("Chunking failed");
    println!("  Created {} chunks", chunks.len());

    // Step 2: Compression
    println!("\nStep 2: Compression (Zstd level 3)");
    let compressor = ZstdCompressor::new(3).expect("Compressor creation failed");
    let compressed: Vec<Vec<u8>> = chunks
        .iter()
        .map(|chunk| compressor.compress(chunk).expect("Compression failed"))
        .collect();
    let compressed_size: usize = compressed.iter().map(|c| c.len()).sum();
    println!("  Compressed: {} -> {} bytes ({:.1}x ratio)",
             data.len(), compressed_size,
             data.len() as f64 / compressed_size as f64);

    // Step 3: Encryption
    println!("\nStep 3: Encryption (ChaCha20-Poly1305)");
    let key = Key::from_bytes([0x42u8; 32]);
    let encrypted: Vec<Vec<u8>> = compressed
        .iter()
        .map(|chunk| encrypt(&key, chunk).expect("Encryption failed"))
        .collect();
    let encrypted_size: usize = encrypted.iter().map(|c| c.len()).sum();
    println!("  Encrypted: {} bytes (added {} bytes overhead)",
             encrypted_size, encrypted_size - compressed_size);

    // Step 4: Hashing
    println!("\nStep 4: Hashing (BLAKE3)");
    let chunk_hashes: Vec<[u8; 32]> = encrypted
        .iter()
        .map(|chunk| hash(chunk))
        .collect();
    println!("  Computed {} chunk hashes", chunk_hashes.len());

    // Step 5: Merkle Root
    println!("\nStep 5: Merkle Tree");
    let merkle_root = compute_merkle_root(&chunk_hashes);
    println!("  Root: {}", hex_encode(&merkle_root[..16]));

    let pipeline_time = start.elapsed();
    let throughput = data.len() as f64 / 1024.0 / 1024.0 / pipeline_time.as_secs_f64();

    println!("\n=== Pipeline Complete ===");
    println!("Time: {:?}", pipeline_time);
    println!("Throughput: {:.2} MB/s", throughput);

    // Verify reverse pipeline
    println!("\n=== Verification ===");
    let mut reconstructed = Vec::new();
    for (encrypted_chunk, expected_hash) in encrypted.iter().zip(chunk_hashes.iter()) {
        // Verify hash
        let actual_hash = hash(encrypted_chunk);
        assert_eq!(&actual_hash, expected_hash);

        // Decrypt
        let compressed = decrypt(&key, encrypted_chunk).expect("Decryption failed");

        // Decompress
        let original = compressor.decompress(&compressed).expect("Decompression failed");
        reconstructed.extend_from_slice(&original);
    }

    assert_eq!(reconstructed, data);
    println!("Full roundtrip verified: OK");
    println!("Data integrity: OK");
}

fn compute_merkle_root(hashes: &[[u8; 32]]) -> [u8; 32] {
    if hashes.is_empty() {
        return [0u8; 32];
    }
    if hashes.len() == 1 {
        return hashes[0];
    }

    let mut level = hashes.to_vec();
    while level.len() > 1 {
        let mut next_level = Vec::new();
        for pair in level.chunks(2) {
            let mut combined = Vec::with_capacity(64);
            combined.extend_from_slice(&pair[0]);
            if pair.len() > 1 {
                combined.extend_from_slice(&pair[1]);
            } else {
                combined.extend_from_slice(&pair[0]);
            }
            next_level.push(hash(&combined));
        }
        level = next_level;
    }
    level[0]
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
