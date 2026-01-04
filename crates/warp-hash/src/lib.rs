//! warp-hash: BLAKE3 hashing and Merkle tree
//!
//! High-performance parallel hashing using BLAKE3 with rayon.
//!
//! # Features
//! - Single-shot and incremental hashing
//! - Parallel multi-chunk hashing
//! - File hashing with progress callbacks
//! - Bounded memory usage for large files

#![warn(missing_docs)]

use rayon::prelude::*;

mod file;
pub use file::{
    hash_file, hash_file_with_buffer, hash_file_with_progress, hash_reader,
    hash_reader_with_progress,
};

/// Error type for hashing operations
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// I/O error during file operations
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type for hashing operations
pub type Result<T> = std::result::Result<T, Error>;

/// Hash output (32 bytes)
pub type Hash = [u8; 32];

/// Hash a single chunk of data
pub fn hash(data: &[u8]) -> Hash {
    *blake3::hash(data).as_bytes()
}

/// Hash multiple chunks in parallel
pub fn hash_chunks_parallel(chunks: &[&[u8]]) -> Vec<Hash> {
    chunks.par_iter().map(|chunk| hash(chunk)).collect()
}

/// Keyed hash (for MAC)
pub fn keyed_hash(key: &[u8; 32], data: &[u8]) -> Hash {
    *blake3::keyed_hash(key, data).as_bytes()
}

/// Derive a key from context and key material
pub fn derive_key(context: &str, key_material: &[u8]) -> Hash {
    blake3::derive_key(context, key_material)
}

/// Incremental hasher
pub struct Hasher {
    inner: blake3::Hasher,
}

impl Hasher {
    /// Create a new hasher
    pub fn new() -> Self {
        Self {
            inner: blake3::Hasher::new(),
        }
    }

    /// Create a keyed hasher
    pub fn new_keyed(key: &[u8; 32]) -> Self {
        Self {
            inner: blake3::Hasher::new_keyed(key),
        }
    }

    /// Update with data
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalize and return hash
    pub fn finalize(&self) -> Hash {
        *self.inner.finalize().as_bytes()
    }

    /// Reset hasher for reuse
    pub fn reset(&mut self) {
        self.inner.reset();
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash() {
        let hash1 = hash(b"hello");
        let hash2 = hash(b"hello");
        let hash3 = hash(b"world");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_incremental() {
        let direct = hash(b"helloworld");

        let mut hasher = Hasher::new();
        hasher.update(b"hello");
        hasher.update(b"world");
        let incremental = hasher.finalize();

        assert_eq!(direct, incremental);
    }
}

#[cfg(test)]
mod proptest_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Property: same input always produces same hash (determinism)
        #[test]
        fn hash_is_deterministic(data in prop::collection::vec(any::<u8>(), 0..4096)) {
            let hash1 = hash(&data);
            let hash2 = hash(&data);

            prop_assert_eq!(hash1, hash2);
        }

        /// Property: incremental hashing matches direct hashing
        #[test]
        fn incremental_matches_direct(
            parts in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..256), 1..10)
        ) {
            // Concatenate all parts for direct hash
            let combined: Vec<u8> = parts.iter().flatten().copied().collect();
            let direct_hash = hash(&combined);

            // Incremental hash
            let mut hasher = Hasher::new();
            for part in &parts {
                hasher.update(part);
            }
            let incremental_hash = hasher.finalize();

            prop_assert_eq!(direct_hash, incremental_hash);
        }

        /// Property: parallel chunk hashing matches sequential hashing
        #[test]
        fn parallel_matches_sequential(
            chunks in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..256), 1..20)
        ) {
            let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
            let parallel_hashes = hash_chunks_parallel(&chunk_refs);

            // Sequential hashing
            let sequential_hashes: Vec<Hash> = chunks.iter().map(|c| hash(c)).collect();

            prop_assert_eq!(parallel_hashes, sequential_hashes);
        }

        /// Property: keyed hash differs from unkeyed hash
        #[test]
        fn keyed_differs_from_unkeyed(
            key in prop::array::uniform32(any::<u8>()),
            data in prop::collection::vec(any::<u8>(), 1..256),
        ) {
            let unkeyed = hash(&data);
            let keyed = keyed_hash(&key, &data);

            // Should be different (with overwhelming probability)
            prop_assert_ne!(unkeyed, keyed);
        }

        /// Property: hash output is always 32 bytes
        #[test]
        fn hash_output_is_32_bytes(data in prop::collection::vec(any::<u8>(), 0..4096)) {
            let result = hash(&data);
            prop_assert_eq!(result.len(), 32);
        }
    }
}
