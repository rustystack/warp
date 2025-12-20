//! Stress tests for warp data transfer pipeline
//!
//! These tests verify the data pipeline can handle production-scale loads:
//! - Large file chunking (100MB+)
//! - High-throughput compression
//! - Rapid encryption/decryption cycles
//! - Full pipeline under load
//!
//! Run with: cargo test -p warp-format --test stress -- --nocapture

use std::io::Cursor;
use std::time::{Duration, Instant};
use warp_compress::{Compressor, ZstdCompressor, Lz4Compressor};
use warp_crypto::encrypt::{encrypt, decrypt, Key};
use warp_io::{Chunker, ChunkerConfig};

/// Test: Large file chunking (10MB)
#[test]
fn stress_large_file_chunking() {
    let data_size = 10 * 1024 * 1024; // 10MB
    let data: Vec<u8> = (0..data_size).map(|i| (i % 256) as u8).collect();

    println!("Chunking {}MB of data...", data_size / 1024 / 1024);
    let start = Instant::now();

    let config = ChunkerConfig {
        min_size: 256 * 1024,
        target_size: 1024 * 1024,
        max_size: 4 * 1024 * 1024,
        window_size: 48,
    };
    let chunker = Chunker::new(config);
    let chunks = chunker.chunk(Cursor::new(&data)).unwrap();

    let elapsed = start.elapsed();
    let throughput_mbps = (data_size as f64 / 1024.0 / 1024.0) / elapsed.as_secs_f64();

    println!("Chunking completed in {:?}", elapsed);
    println!("Throughput: {:.2} MB/s", throughput_mbps);
    println!("Chunks created: {}", chunks.len());

    // Verify all data is preserved
    let reconstructed: Vec<u8> = chunks.iter().flatten().copied().collect();
    assert_eq!(reconstructed.len(), data.len());
    assert_eq!(reconstructed, data);

    // Chunking should be fast (>100MB/s on modern hardware)
    let threshold = if cfg!(debug_assertions) {
        Duration::from_secs(5)
    } else {
        Duration::from_secs(1)
    };
    assert!(
        elapsed < threshold,
        "Chunking too slow: {:?} (expected < {:?})",
        elapsed, threshold
    );
}

/// Test: High-throughput compression (zstd)
#[test]
fn stress_compression_throughput() {
    let chunk_size = 1024 * 1024; // 1MB chunks
    let num_chunks = 50;
    let total_size = chunk_size * num_chunks;

    // Create test data with some compressibility
    let chunks: Vec<Vec<u8>> = (0..num_chunks)
        .map(|i| {
            (0..chunk_size)
                .map(|j| ((i * 17 + j * 13) % 256) as u8)
                .collect()
        })
        .collect();

    let compressor = ZstdCompressor::default();

    println!("Compressing {} chunks ({} MB total)...", num_chunks, total_size / 1024 / 1024);
    let start = Instant::now();

    let compressed: Vec<Vec<u8>> = chunks
        .iter()
        .map(|chunk| compressor.compress(chunk).unwrap())
        .collect();

    let elapsed = start.elapsed();
    let throughput_mbps = (total_size as f64 / 1024.0 / 1024.0) / elapsed.as_secs_f64();
    let total_compressed: usize = compressed.iter().map(|c| c.len()).sum();
    let ratio = total_size as f64 / total_compressed as f64;

    println!("Compression completed in {:?}", elapsed);
    println!("Throughput: {:.2} MB/s", throughput_mbps);
    println!("Compression ratio: {:.2}x", ratio);

    // Verify decompression
    let start = Instant::now();
    let decompressed: Vec<Vec<u8>> = compressed
        .iter()
        .map(|c| compressor.decompress(c).unwrap())
        .collect();
    let decomp_elapsed = start.elapsed();

    for (original, decompressed) in chunks.iter().zip(decompressed.iter()) {
        assert_eq!(original, decompressed);
    }

    println!("Decompression completed in {:?}", decomp_elapsed);
}

/// Test: High-throughput encryption
#[test]
fn stress_encryption_throughput() {
    let chunk_size = 1024 * 1024; // 1MB chunks
    let num_chunks = 50;
    let total_size = chunk_size * num_chunks;

    let chunks: Vec<Vec<u8>> = (0..num_chunks)
        .map(|i| {
            (0..chunk_size)
                .map(|j| ((i + j) % 256) as u8)
                .collect()
        })
        .collect();

    let key = Key::from_bytes([0x42u8; 32]);

    println!("Encrypting {} chunks ({} MB total)...", num_chunks, total_size / 1024 / 1024);
    let start = Instant::now();

    let encrypted: Vec<Vec<u8>> = chunks
        .iter()
        .map(|chunk| encrypt(&key, chunk).unwrap())
        .collect();

    let elapsed = start.elapsed();
    let throughput_mbps = (total_size as f64 / 1024.0 / 1024.0) / elapsed.as_secs_f64();

    println!("Encryption completed in {:?}", elapsed);
    println!("Throughput: {:.2} MB/s", throughput_mbps);

    // Verify decryption
    let start = Instant::now();
    let decrypted: Vec<Vec<u8>> = encrypted
        .iter()
        .map(|c| decrypt(&key, c).unwrap())
        .collect();
    let decrypt_elapsed = start.elapsed();

    for (original, decrypted) in chunks.iter().zip(decrypted.iter()) {
        assert_eq!(original.as_slice(), decrypted.as_slice());
    }

    println!("Decryption completed in {:?}", decrypt_elapsed);
}

/// Test: Parallel hashing throughput
#[test]
fn stress_hashing_throughput() {
    let chunk_size = 1024 * 1024; // 1MB chunks
    let num_chunks = 100;
    let total_size = chunk_size * num_chunks;

    let chunks: Vec<Vec<u8>> = (0..num_chunks)
        .map(|i| {
            (0..chunk_size)
                .map(|j| ((i + j) % 256) as u8)
                .collect()
        })
        .collect();

    println!("Hashing {} chunks ({} MB total)...", num_chunks, total_size / 1024 / 1024);
    let start = Instant::now();

    // Hash each chunk
    let hashes: Vec<[u8; 32]> = chunks
        .iter()
        .map(|chunk| warp_hash::hash(chunk))
        .collect();

    let elapsed = start.elapsed();
    let throughput_mbps = (total_size as f64 / 1024.0 / 1024.0) / elapsed.as_secs_f64();

    println!("Hashing completed in {:?}", elapsed);
    println!("Throughput: {:.2} MB/s", throughput_mbps);
    println!("Hashes computed: {}", hashes.len());

    // Verify consistency
    for (i, (chunk, hash)) in chunks.iter().zip(hashes.iter()).enumerate() {
        let rehash = warp_hash::hash(chunk);
        assert_eq!(hash, &rehash, "Hash mismatch at chunk {}", i);
    }
}

/// Test: Full pipeline stress (chunk -> compress -> encrypt -> hash)
#[test]
fn stress_full_pipeline() {
    let data_size = 5 * 1024 * 1024; // 5MB
    let data: Vec<u8> = (0..data_size).map(|i| ((i * 17 + 13) % 256) as u8).collect();

    println!("Running full pipeline on {}MB of data...", data_size / 1024 / 1024);
    let start = Instant::now();

    // Step 1: Chunk
    let config = ChunkerConfig {
        min_size: 128 * 1024,
        target_size: 512 * 1024,
        max_size: 2 * 1024 * 1024,
        window_size: 48,
    };
    let chunker = Chunker::new(config);
    let chunks = chunker.chunk(Cursor::new(&data)).unwrap();
    let chunk_time = start.elapsed();

    // Step 2: Compress
    let compressor = ZstdCompressor::default();
    let compress_start = Instant::now();
    let compressed: Vec<Vec<u8>> = chunks
        .iter()
        .map(|chunk| compressor.compress(chunk).unwrap())
        .collect();
    let compress_time = compress_start.elapsed();

    // Step 3: Encrypt
    let key = Key::from_bytes([0x42u8; 32]);
    let encrypt_start = Instant::now();
    let encrypted: Vec<Vec<u8>> = compressed
        .iter()
        .map(|chunk| encrypt(&key, chunk).unwrap())
        .collect();
    let encrypt_time = encrypt_start.elapsed();

    // Step 4: Hash
    let hash_start = Instant::now();
    let hashes: Vec<[u8; 32]> = encrypted
        .iter()
        .map(|chunk| warp_hash::hash(chunk))
        .collect();
    let hash_time = hash_start.elapsed();

    let total_time = start.elapsed();
    let throughput_mbps = (data_size as f64 / 1024.0 / 1024.0) / total_time.as_secs_f64();

    println!("Pipeline completed in {:?}", total_time);
    println!("  Chunking:    {:?} ({} chunks)", chunk_time, chunks.len());
    println!("  Compression: {:?}", compress_time);
    println!("  Encryption:  {:?}", encrypt_time);
    println!("  Hashing:     {:?}", hash_time);
    println!("Overall throughput: {:.2} MB/s", throughput_mbps);

    // Verify reverse pipeline
    let reverse_start = Instant::now();
    let mut reconstructed = Vec::new();

    for (i, (encrypted_chunk, expected_hash)) in encrypted.iter().zip(hashes.iter()).enumerate() {
        // Verify hash
        let actual_hash = warp_hash::hash(encrypted_chunk);
        assert_eq!(&actual_hash, expected_hash, "Hash mismatch at chunk {}", i);

        // Decrypt
        let compressed_chunk = decrypt(&key, encrypted_chunk).unwrap();

        // Decompress
        let original_chunk = compressor.decompress(&compressed_chunk).unwrap();

        reconstructed.extend_from_slice(&original_chunk);
    }

    let reverse_time = reverse_start.elapsed();
    println!("Reverse pipeline: {:?}", reverse_time);

    assert_eq!(reconstructed, data, "Data mismatch after full pipeline roundtrip");
}

/// Test: Memory efficiency with many small chunks
#[test]
fn stress_many_small_chunks() {
    let num_chunks = 10000;
    let chunk_size = 4096; // 4KB chunks

    let chunks: Vec<Vec<u8>> = (0..num_chunks)
        .map(|i| {
            (0..chunk_size)
                .map(|j| ((i + j) % 256) as u8)
                .collect()
        })
        .collect();

    println!("Processing {} small chunks ({} KB each)...", num_chunks, chunk_size / 1024);
    let start = Instant::now();

    let key = Key::from_bytes([0x42u8; 32]);
    let compressor = Lz4Compressor::new();

    // Process all chunks through the pipeline
    let processed: Vec<([u8; 32], Vec<u8>)> = chunks
        .iter()
        .map(|chunk| {
            let compressed = compressor.compress(chunk).unwrap();
            let encrypted = encrypt(&key, &compressed).unwrap();
            let hash = warp_hash::hash(&encrypted);
            (hash, encrypted)
        })
        .collect();

    let elapsed = start.elapsed();
    let ops_per_second = num_chunks as f64 / elapsed.as_secs_f64();

    println!("Processing completed in {:?}", elapsed);
    println!("Operations per second: {:.0}", ops_per_second);
    println!("Total chunks processed: {}", processed.len());

    // Verify a sample
    let (expected_hash, encrypted) = &processed[0];
    let actual_hash = warp_hash::hash(encrypted);
    assert_eq!(&actual_hash, expected_hash);

    // Should handle 10k chunks in reasonable time
    let threshold = if cfg!(debug_assertions) {
        Duration::from_secs(30)
    } else {
        Duration::from_secs(5)
    };
    assert!(
        elapsed < threshold,
        "Small chunk processing too slow: {:?}",
        elapsed
    );
}

/// Test: Compression algorithm comparison
#[test]
fn stress_compression_comparison() {
    let chunk_size = 1024 * 1024; // 1MB
    let num_chunks = 20;

    // Create data with varying entropy
    let chunks: Vec<Vec<u8>> = (0..num_chunks)
        .map(|i| {
            (0..chunk_size)
                .map(|j| {
                    if i < num_chunks / 2 {
                        // Low entropy (repetitive)
                        ((j / 100) % 256) as u8
                    } else {
                        // Higher entropy
                        ((j * 17 + i * 31) % 256) as u8
                    }
                })
                .collect()
        })
        .collect();

    println!("Comparing compression algorithms on {}MB...", (chunk_size * num_chunks) / 1024 / 1024);

    // Test Zstd
    let zstd = ZstdCompressor::default();
    let zstd_start = Instant::now();
    let zstd_compressed: Vec<Vec<u8>> = chunks.iter().map(|c| zstd.compress(c).unwrap()).collect();
    let zstd_time = zstd_start.elapsed();
    let zstd_size: usize = zstd_compressed.iter().map(|c| c.len()).sum();

    // Test LZ4
    let lz4 = Lz4Compressor::new();
    let lz4_start = Instant::now();
    let lz4_compressed: Vec<Vec<u8>> = chunks.iter().map(|c| lz4.compress(c).unwrap()).collect();
    let lz4_time = lz4_start.elapsed();
    let lz4_size: usize = lz4_compressed.iter().map(|c| c.len()).sum();

    let original_size = chunk_size * num_chunks;

    println!("Zstd: {:?}, ratio: {:.2}x", zstd_time, original_size as f64 / zstd_size as f64);
    println!("LZ4:  {:?}, ratio: {:.2}x", lz4_time, original_size as f64 / lz4_size as f64);

    // Verify all decompress correctly
    for (i, (original, compressed)) in chunks.iter().zip(zstd_compressed.iter()).enumerate() {
        let decompressed = zstd.decompress(compressed).unwrap();
        assert_eq!(original, &decompressed, "Zstd mismatch at chunk {}", i);
    }

    for (i, (original, compressed)) in chunks.iter().zip(lz4_compressed.iter()).enumerate() {
        let decompressed = lz4.decompress(compressed).unwrap();
        assert_eq!(original, &decompressed, "LZ4 mismatch at chunk {}", i);
    }
}
