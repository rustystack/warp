//! Parallel hashing with BLAKE3 example
//!
//! Demonstrates high-throughput parallel hashing using
//! warp's BLAKE3 implementation with rayon parallelism.
//!
//! Run with: cargo run --example parallel_hashing --release

use std::time::Instant;
use warp_hash::{hash, hash_chunks_parallel, keyed_hash, derive_key, Hasher};

fn main() {
    println!("=== BLAKE3 Parallel Hashing Demo ===\n");

    // Create test chunks (100 x 1MB = 100MB total)
    let num_chunks = 100;
    let chunk_size = 1024 * 1024;
    let chunks: Vec<Vec<u8>> = (0..num_chunks)
        .map(|i| {
            (0..chunk_size)
                .map(|j| ((i + j) % 256) as u8)
                .collect()
        })
        .collect();

    let total_size = num_chunks * chunk_size;
    println!("Data: {} chunks x {} MB = {} MB\n",
             num_chunks, chunk_size / 1024 / 1024, total_size / 1024 / 1024);

    // Sequential hashing
    println!("Sequential hashing...");
    let seq_start = Instant::now();
    let seq_hashes: Vec<[u8; 32]> = chunks.iter().map(|c| hash(c)).collect();
    let seq_time = seq_start.elapsed();
    let seq_throughput = total_size as f64 / 1024.0 / 1024.0 / seq_time.as_secs_f64();
    println!("  Time: {:?}", seq_time);
    println!("  Throughput: {:.2} MB/s\n", seq_throughput);

    // Parallel hashing
    println!("Parallel hashing (rayon)...");
    let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
    let par_start = Instant::now();
    let par_hashes = hash_chunks_parallel(&chunk_refs);
    let par_time = par_start.elapsed();
    let par_throughput = total_size as f64 / 1024.0 / 1024.0 / par_time.as_secs_f64();
    println!("  Time: {:?}", par_time);
    println!("  Throughput: {:.2} MB/s", par_throughput);
    println!("  Speedup: {:.2}x\n", seq_time.as_secs_f64() / par_time.as_secs_f64());

    // Verify consistency
    assert_eq!(seq_hashes, par_hashes, "Hash mismatch!");
    println!("Hash consistency: OK\n");

    // Demonstrate incremental hashing
    println!("Incremental hashing demo:");
    let data = b"Hello, World!";
    let direct = hash(data);

    let mut hasher = Hasher::new();
    hasher.update(b"Hello, ");
    hasher.update(b"World!");
    let incremental = hasher.finalize();

    assert_eq!(direct, incremental);
    println!("  Direct hash:      {}", hex_encode(&direct[..16]));
    println!("  Incremental hash: {}", hex_encode(&incremental[..16]));
    println!("  Match: OK\n");

    // Demonstrate keyed hashing (MAC)
    println!("Keyed hashing (HMAC-like MAC):");
    let key = [0x42u8; 32];
    let mac = keyed_hash(&key, b"Authenticated message");
    println!("  Key: {}", hex_encode(&key[..8]));
    println!("  MAC: {}", hex_encode(&mac[..16]));

    // Demonstrate key derivation
    println!("\nKey derivation:");
    let context = "warp/example/v1";
    let material = b"input key material";
    let derived = derive_key(context, material);
    println!("  Context: {}", context);
    println!("  Derived: {}", hex_encode(&derived[..16]));
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
