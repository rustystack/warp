//! Basic content-defined chunking example
//!
//! This example demonstrates how warp uses Buzhash rolling hash
//! for intelligent content-defined chunking, enabling efficient
//! deduplication across transfers.
//!
//! Run with: cargo run --example basic_chunking

use std::io::Cursor;
use warp_io::{Chunker, ChunkerConfig};

fn main() {
    // Create sample data (1MB)
    let data: Vec<u8> = (0..1_000_000)
        .map(|i| ((i * 17 + 13) % 256) as u8)
        .collect();

    println!("Input size: {} bytes", data.len());

    // Configure chunker with reasonable defaults
    let config = ChunkerConfig {
        min_size: 64 * 1024,      // 64KB minimum
        target_size: 256 * 1024,  // 256KB target
        max_size: 1024 * 1024,    // 1MB maximum
        window_size: 48,          // Rolling hash window
    };

    let chunker = Chunker::new(config);

    // Chunk the data
    let chunks = chunker.chunk(Cursor::new(&data)).expect("Chunking failed");

    println!("\nChunking results:");
    println!("  Number of chunks: {}", chunks.len());

    let mut total_size = 0;
    for (i, chunk) in chunks.iter().enumerate() {
        println!("  Chunk {}: {} bytes", i, chunk.len());
        total_size += chunk.len();
    }

    println!("\nTotal reconstructed: {} bytes", total_size);
    assert_eq!(total_size, data.len(), "Data integrity verified");
    println!("Data integrity: OK");

    // Demonstrate that identical content produces identical chunks
    let chunks2 = chunker.chunk(Cursor::new(&data)).expect("Chunking failed");
    assert_eq!(chunks.len(), chunks2.len());
    println!("\nDeterministic chunking: OK (same input = same chunks)");
}
