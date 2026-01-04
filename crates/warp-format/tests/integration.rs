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
    let compressor = ZstdCompressor::new(3).unwrap();

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

/// Test encryption roundtrip
#[test]
fn test_encryption_roundtrip() {
    use warp_crypto::encrypt::{encrypt, decrypt, Key};

    let key = Key::from_bytes([0x42u8; 32]);
    let plaintext = b"This is secret data that needs to be encrypted securely.";

    let ciphertext = encrypt(&key, plaintext).unwrap();

    // Ciphertext should be different from plaintext
    assert_ne!(&ciphertext[12..12 + plaintext.len()], plaintext.as_slice());
    // Ciphertext includes nonce (12) + tag (16) overhead
    assert!(ciphertext.len() > plaintext.len());

    let decrypted = decrypt(&key, &ciphertext).unwrap();

    assert_eq!(decrypted.as_slice(), plaintext.as_slice());
}

/// Test encryption with wrong key fails
#[test]
fn test_encryption_wrong_key_fails() {
    use warp_crypto::encrypt::{encrypt, decrypt, Key};

    let key1 = Key::from_bytes([0x42u8; 32]);
    let key2 = Key::from_bytes([0x43u8; 32]);
    let plaintext = b"Secret message";

    let ciphertext = encrypt(&key1, plaintext).unwrap();

    let result = decrypt(&key2, &ciphertext);

    assert!(result.is_err(), "Decryption with wrong key should fail");
}

/// Test full pipeline: chunk → compress → encrypt → hash
#[test]
fn test_full_pipeline() {
    use std::io::Cursor;
    use warp_io::{Chunker, ChunkerConfig};
    use warp_compress::{Compressor, ZstdCompressor};
    use warp_crypto::encrypt::{encrypt, decrypt, Key};

    // Create test data
    let data: Vec<u8> = (0..50_000).map(|i| (i % 256) as u8).collect();

    // Step 1: Chunk the data
    let config = ChunkerConfig {
        min_size: 1024,
        target_size: 4096,
        max_size: 16384,
        window_size: 48,
    };
    let chunker = Chunker::new(config);
    let chunks = chunker.chunk(Cursor::new(&data)).unwrap();

    // Step 2: Compress each chunk
    let compressor = ZstdCompressor::default();
    let compressed_chunks: Vec<Vec<u8>> = chunks
        .iter()
        .map(|chunk| compressor.compress(chunk).unwrap())
        .collect();

    // Step 3: Encrypt each compressed chunk
    let key = Key::from_bytes([0x42u8; 32]);
    let encrypted_chunks: Vec<Vec<u8>> = compressed_chunks
        .iter()
        .map(|chunk| encrypt(&key, chunk).unwrap())
        .collect();

    // Step 4: Hash each encrypted chunk for integrity
    let chunk_hashes: Vec<[u8; 32]> = encrypted_chunks
        .iter()
        .map(|chunk| warp_hash::hash(chunk))
        .collect();

    // Verify we have hashes for all chunks
    assert_eq!(chunk_hashes.len(), encrypted_chunks.len());

    // Now reverse the pipeline
    let mut reconstructed = Vec::new();
    for (encrypted, expected_hash) in encrypted_chunks.iter().zip(chunk_hashes.iter()) {
        // Verify hash
        let actual_hash = warp_hash::hash(encrypted);
        assert_eq!(&actual_hash, expected_hash, "Hash mismatch");

        // Decrypt
        let compressed = decrypt(&key, encrypted).unwrap();

        // Decompress
        let original_chunk = compressor.decompress(&compressed).unwrap();

        reconstructed.extend_from_slice(&original_chunk);
    }

    assert_eq!(reconstructed, data, "Data mismatch after full pipeline roundtrip");
}

/// Test Merkle tree construction and verification
#[test]
fn test_merkle_tree() {
    // Create chunk hashes
    let chunks: Vec<&[u8]> = vec![b"chunk1", b"chunk2", b"chunk3", b"chunk4"];
    let hashes: Vec<[u8; 32]> = chunks.iter().map(|c| warp_hash::hash(c)).collect();

    // Build Merkle tree (simplified - just hash pairs)
    fn merkle_root(hashes: &[[u8; 32]]) -> [u8; 32] {
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
                let mut combined = Vec::new();
                combined.extend_from_slice(&pair[0]);
                if pair.len() > 1 {
                    combined.extend_from_slice(&pair[1]);
                } else {
                    combined.extend_from_slice(&pair[0]); // Duplicate for odd
                }
                next_level.push(warp_hash::hash(&combined));
            }
            level = next_level;
        }
        level[0]
    }

    let root1 = merkle_root(&hashes);
    let root2 = merkle_root(&hashes);

    // Same hashes should produce same root
    assert_eq!(root1, root2);

    // Modifying one chunk should change root
    let mut modified_hashes = hashes.clone();
    modified_hashes[2] = warp_hash::hash(b"modified_chunk3");
    let root3 = merkle_root(&modified_hashes);
    assert_ne!(root1, root3);
}

/// Test large data handling
#[test]
fn test_large_data_handling() {
    use std::io::Cursor;
    use warp_io::{Chunker, ChunkerConfig};

    // Create 1MB of random-ish data
    let data: Vec<u8> = (0..1_000_000).map(|i| ((i * 17 + 13) % 256) as u8).collect();

    let config = ChunkerConfig::default();
    let chunker = Chunker::new(config);
    let chunks = chunker.chunk(Cursor::new(&data)).unwrap();

    // Verify all data is preserved
    let reconstructed: Vec<u8> = chunks.iter().flatten().copied().collect();
    assert_eq!(reconstructed.len(), data.len());
    assert_eq!(reconstructed, data);

    // Verify chunk count is reasonable
    assert!(chunks.len() >= 1, "Should have at least one chunk");
}

/// Test signature verification
#[test]
fn test_signature() {
    use warp_crypto::sign::{generate_keypair, sign, verify};

    // Generate a key pair
    let signing_key = generate_keypair();
    let verifying_key = signing_key.verifying_key();

    let message = b"This message needs to be signed";

    // Sign the message
    let signature = sign(&signing_key, message);

    // Verify the signature
    assert!(verify(&verifying_key, message, &signature).is_ok());

    // Verify with wrong message fails
    let wrong_message = b"This is a different message";
    assert!(verify(&verifying_key, wrong_message, &signature).is_err());
}

/// Test key derivation from password
#[test]
fn test_password_key_derivation() {
    use warp_crypto::kdf::derive_key;

    let password = b"strong_password_123!";
    let salt = [0x42u8; 16];

    let key1 = derive_key(password, &salt).unwrap();
    let key2 = derive_key(password, &salt).unwrap();

    // Same password and salt should produce same key
    assert_eq!(key1.as_bytes(), key2.as_bytes());

    // Different salt should produce different key
    let different_salt = [0x43u8; 16];
    let key3 = derive_key(password, &different_salt).unwrap();
    assert_ne!(key1.as_bytes(), key3.as_bytes());

    // Different password should produce different key
    let different_password = b"different_password";
    let key4 = derive_key(different_password, &salt).unwrap();
    assert_ne!(key1.as_bytes(), key4.as_bytes());
}

// ============================================================================
// ERROR PATH TESTS
// ============================================================================
// These tests verify that error conditions are properly detected and reported.
// Litmus test: "If you comment out a return Err, does a test fail?"

/// Test that decryption with tampered ciphertext fails
#[test]
fn test_decryption_tampered_ciphertext_error() {
    use warp_crypto::encrypt::{encrypt, decrypt, Key};

    let key = Key::from_bytes([0x42u8; 32]);
    let plaintext = b"Secret message";

    let mut ciphertext = encrypt(&key, plaintext).unwrap();

    // Tamper with the ciphertext (flip a bit in the encrypted payload)
    if ciphertext.len() > 15 {
        ciphertext[15] ^= 0xFF;
    }

    let result = decrypt(&key, &ciphertext);
    assert!(
        result.is_err(),
        "Decryption of tampered ciphertext should fail"
    );
}

/// Test that decryption with truncated ciphertext fails
#[test]
fn test_decryption_truncated_ciphertext_error() {
    use warp_crypto::encrypt::{decrypt, Key};

    let key = Key::from_bytes([0x42u8; 32]);

    // Too short - less than nonce (12) + tag (16) = 28 bytes minimum
    let short_ciphertext = vec![0u8; 20];

    let result = decrypt(&key, &short_ciphertext);
    assert!(
        result.is_err(),
        "Decryption of too-short ciphertext should fail"
    );
}

/// Test that erasure decoding with too few shards fails
#[test]
fn test_erasure_decode_too_few_shards_error() {
    use warp_ec::{ErasureConfig, ErasureEncoder, ErasureDecoder};

    let config = ErasureConfig::new(4, 2).unwrap();
    let encoder = ErasureEncoder::new(config.clone());
    let decoder = ErasureDecoder::new(config);

    let data: Vec<u8> = (0..256).map(|i| i as u8).collect();
    let shards = encoder.encode(&data).unwrap();

    // Remove 3 shards (more than parity_shards=2 can recover)
    let mut shard_opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
    shard_opts[0] = None;
    shard_opts[1] = None;
    shard_opts[2] = None;

    let result = decoder.decode(&shard_opts);
    assert!(
        result.is_err(),
        "Decoding with too many missing shards should fail"
    );
}

/// Test that erasure decoding with wrong shard count fails
#[test]
fn test_erasure_decode_wrong_shard_count_error() {
    use warp_ec::{ErasureConfig, ErasureDecoder};

    let config = ErasureConfig::new(4, 2).unwrap();
    let decoder = ErasureDecoder::new(config);

    // Provide wrong number of shards (5 instead of 6)
    let shard_opts: Vec<Option<Vec<u8>>> = vec![
        Some(vec![0u8; 64]),
        Some(vec![0u8; 64]),
        Some(vec![0u8; 64]),
        Some(vec![0u8; 64]),
        Some(vec![0u8; 64]),
    ];

    let result = decoder.decode(&shard_opts);
    assert!(
        result.is_err(),
        "Decoding with wrong shard count should fail"
    );
}

/// Test that erasure encoding with empty data fails
#[test]
fn test_erasure_encode_empty_data_error() {
    use warp_ec::{ErasureConfig, ErasureEncoder};

    let config = ErasureConfig::new(4, 2).unwrap();
    let encoder = ErasureEncoder::new(config);

    let result = encoder.encode(&[]);
    assert!(result.is_err(), "Encoding empty data should fail");
}

/// Test that stream cipher decryption with wrong counter fails
#[test]
fn test_stream_cipher_wrong_counter_error() {
    use warp_crypto::stream::StreamCipher;

    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];

    let mut encryptor = StreamCipher::new(&key, &nonce);
    let mut decryptor = StreamCipher::new(&key, &nonce);

    // Encrypt two chunks
    let _ct1 = encryptor.encrypt_chunk(b"first").unwrap();
    let ct2 = encryptor.encrypt_chunk(b"second").unwrap();

    // Try to decrypt second chunk with counter still at 0 (skipping first)
    let result = decryptor.decrypt_chunk(&ct2);
    assert!(
        result.is_err(),
        "Decrypting with wrong counter should fail"
    );
}

/// Test that stream cipher skip_to_counter backward fails
#[test]
fn test_stream_cipher_backward_skip_error() {
    use warp_crypto::stream::StreamCipher;

    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let mut cipher = StreamCipher::new(&key, &nonce);

    // Move counter forward
    cipher.skip_to_counter(100).unwrap();

    // Try to skip backward (would cause nonce reuse)
    let result = cipher.skip_to_counter(50);
    assert!(
        result.is_err(),
        "Skipping counter backward should fail (nonce reuse prevention)"
    );
}

/// Test that signature verification with wrong message fails
#[test]
fn test_signature_wrong_message_error() {
    use warp_crypto::sign::{generate_keypair, sign, verify};

    let signing_key = generate_keypair();
    let verifying_key = signing_key.verifying_key();

    let message = b"Original message";
    let signature = sign(&signing_key, message);

    let tampered_message = b"Tampered message";
    let result = verify(&verifying_key, tampered_message, &signature);

    assert!(
        result.is_err(),
        "Signature verification with wrong message should fail"
    );
}
