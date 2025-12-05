//! Integration tests for warp

use std::io::Cursor;

/// Test basic chunking roundtrip
#[test]
fn test_chunking_roundtrip() {
    use warp_io::{Chunker, ChunkerConfig};

    let data = vec![0xAB; 100_000];
    let config = ChunkerConfig {
        min_size: 1024,
        target_size: 4096,
        max_size: 16384,
        window_size: 48,
    };
    let chunker = Chunker::new(config);
    let chunks = chunker.chunk(Cursor::new(&data)).unwrap();

    // Verify chunks reconstruct original data
    let reconstructed: Vec<u8> = chunks.into_iter().flatten().collect();
    assert_eq!(reconstructed, data);
}

/// Test compression roundtrip with zstd
#[test]
fn test_zstd_compression_roundtrip() {
    use warp_compress::{Compressor, ZstdCompressor};

    let data = b"Hello, warp! This is test data for compression. Repeating pattern helps compression.";
    let compressor = ZstdCompressor::new(3);

    let compressed = compressor.compress(data).unwrap();
    let decompressed = compressor.decompress(&compressed).unwrap();

    assert_eq!(decompressed, data);
    // Verify compression actually reduced size for repetitive data
    assert!(compressed.len() < data.len());
}

/// Test compression roundtrip with lz4
#[test]
fn test_lz4_compression_roundtrip() {
    use warp_compress::{Compressor, Lz4Compressor};

    let data = b"LZ4 is a fast compression algorithm. This text has some repetition for compression.";
    let compressor = Lz4Compressor::new();

    let compressed = compressor.compress(data).unwrap();
    let decompressed = compressor.decompress(&compressed).unwrap();

    assert_eq!(decompressed, data);
}

/// Test hashing consistency
#[test]
fn test_hashing_consistency() {
    let data = b"consistent hashing test";
    let hash1 = warp_hash::hash(data);
    let hash2 = warp_hash::hash(data);

    assert_eq!(hash1, hash2);
    assert_eq!(hash1.len(), 32); // BLAKE3 produces 32-byte hashes
}

/// Test incremental hasher
#[test]
fn test_incremental_hashing() {
    use warp_hash::Hasher;

    let full_data = b"hello world from warp";
    let direct_hash = warp_hash::hash(full_data);

    let mut hasher = Hasher::new();
    hasher.update(b"hello ");
    hasher.update(b"world ");
    hasher.update(b"from warp");
    let incremental_hash = hasher.finalize();

    assert_eq!(direct_hash, incremental_hash);
}

/// Test parallel chunk hashing
#[test]
fn test_parallel_chunk_hashing() {
    let chunks: Vec<&[u8]> = vec![b"chunk1", b"chunk2", b"chunk3", b"chunk4"];
    let hashes = warp_hash::hash_chunks_parallel(&chunks);

    assert_eq!(hashes.len(), 4);

    // Verify each hash is correct
    for (i, chunk) in chunks.iter().enumerate() {
        assert_eq!(hashes[i], warp_hash::hash(chunk));
    }
}

/// Test keyed hashing
#[test]
fn test_keyed_hashing() {
    let key = [0x42u8; 32];
    let data = b"secret message";

    let mac1 = warp_hash::keyed_hash(&key, data);
    let mac2 = warp_hash::keyed_hash(&key, data);

    // Same key and data should produce same MAC
    assert_eq!(mac1, mac2);

    // Different key should produce different MAC
    let different_key = [0x43u8; 32];
    let mac3 = warp_hash::keyed_hash(&different_key, data);
    assert_ne!(mac1, mac3);
}

/// Test buffer pool
#[test]
fn test_buffer_pool() {
    use warp_io::pool::BufferPool;

    let pool = BufferPool::new(1024);

    // Get a buffer
    let mut buf1 = pool.get();
    assert_eq!(buf1.len(), 1024);

    // Write to buffer
    buf1[0] = 0xFF;
    drop(buf1);

    // Get another buffer - should be the recycled one, but cleared
    let buf2 = pool.get();
    assert_eq!(buf2.len(), 1024);
    assert_eq!(buf2[0], 0); // Should be zeroed
}

/// Test chunking with varying data sizes
#[test]
fn test_chunking_various_sizes() {
    use warp_io::{Chunker, ChunkerConfig};

    let config = ChunkerConfig {
        min_size: 64,
        target_size: 256,
        max_size: 1024,
        window_size: 16,
    };
    let chunker = Chunker::new(config);

    // Test various sizes
    for size in [0, 1, 63, 64, 65, 255, 256, 257, 1023, 1024, 1025, 10000] {
        let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let chunks = chunker.chunk(Cursor::new(&data)).unwrap();

        let reconstructed: Vec<u8> = chunks.iter().flatten().copied().collect();
        assert_eq!(
            reconstructed, data,
            "Failed for size {}",
            size
        );

        // Verify max chunk size is respected
        for chunk in &chunks {
            assert!(chunk.len() <= 1024, "Chunk exceeds max size");
        }
    }
}

/// Test key derivation
#[test]
fn test_key_derivation() {
    let context = "warp/test/v1";
    let key_material = b"some secret key material";

    let key1 = warp_hash::derive_key(context, key_material);
    let key2 = warp_hash::derive_key(context, key_material);

    // Same inputs should produce same key
    assert_eq!(key1, key2);

    // Different context should produce different key
    let key3 = warp_hash::derive_key("different/context", key_material);
    assert_ne!(key1, key3);

    // Different key material should produce different key
    let key4 = warp_hash::derive_key(context, b"different material");
    assert_ne!(key1, key4);
}
