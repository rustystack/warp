//! Convergent encryption for content-addressed storage
//!
//! This module implements convergent encryption, which ensures that identical plaintext
//! (when encrypted with the same master key) produces identical ciphertext. This enables
//! deduplication in content-addressed storage systems.
//!
//! # Convergent Encryption
//!
//! The encryption scheme works as follows:
//! 1. Compute content ID: `CID = BLAKE3(plaintext)`
//! 2. Derive chunk key: `chunk_key = HKDF(master_key, CID, "portal/chunk/v1")`
//! 3. Derive deterministic nonce: `nonce = BLAKE3(CID || "nonce")[0..12]`
//! 4. Encrypt: `ciphertext = ChaCha20-Poly1305(chunk_key, nonce, plaintext)`
//!
//! This ensures that the same plaintext always produces the same ciphertext when encrypted
//! with the same master key, enabling deduplication while maintaining semantic security.
//!
//! # Security Properties
//!
//! - **Content addressing**: Tampering with the ciphertext will fail decryption due to
//!   CID verification
//! - **Deterministic**: Same content always produces same ciphertext (enables deduplication)
//! - **Key isolation**: Different master keys produce different ciphertexts
//! - **Semantic security**: Content IDs are derived from plaintext, so identical plaintexts
//!   are linkable. Use `ManifestEncryptor` for non-deterministic encryption of metadata.
//!
//! # Examples
//!
//! ```
//! use portal_core::{RecoveryPhrase, KeyHierarchy};
//! use portal_core::encryption::ConvergentEncryptor;
//!
//! let hierarchy = KeyHierarchy::from_recovery_phrase(&RecoveryPhrase::generate()).unwrap();
//! let encryptor = ConvergentEncryptor::new(hierarchy.encryption().clone());
//!
//! let plaintext = b"Hello, Portal!";
//! let chunk = encryptor.encrypt_chunk(plaintext).unwrap();
//! let decrypted = encryptor.decrypt_chunk(&chunk).unwrap();
//! assert_eq!(plaintext.as_slice(), decrypted.as_slice());
//! ```

use crate::{ContentId, Error, MasterEncryptionKey, Result};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use hkdf::Hkdf;
use rand::{RngCore, rngs::OsRng};
use sha2::Sha256;

/// HKDF context for convergent chunk key derivation
const CONTEXT_CHUNK_KEY: &[u8] = b"portal/chunk/v1";

/// HKDF context for deterministic nonce derivation
const CONTEXT_NONCE: &[u8] = b"portal/nonce/v1";

/// Encrypted chunk with content-addressing
///
/// This structure represents an encrypted data chunk with its content identifier.
/// The content ID serves as both a hash of the plaintext and as input for deterministic
/// key derivation, enabling content-addressed storage with deduplication.
///
/// # Structure
///
/// - `cid`: BLAKE3 hash of the original plaintext
/// - `data`: ChaCha20-Poly1305 ciphertext (includes 16-byte authentication tag)
/// - `plaintext_size`: Original size before encryption (for validation)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedChunk {
    /// Content ID (BLAKE3 hash of plaintext)
    pub cid: ContentId,
    /// Encrypted data (ciphertext || tag)
    pub data: Vec<u8>,
    /// Size of original plaintext
    pub plaintext_size: u64,
}

impl EncryptedChunk {
    /// Get the total size of the encrypted chunk (ciphertext + tag)
    #[must_use]
    pub const fn encrypted_size(&self) -> u64 {
        self.data.len() as u64
    }

    /// Get the encryption overhead (encrypted size - plaintext size)
    #[must_use]
    pub const fn overhead(&self) -> u64 {
        self.encrypted_size().saturating_sub(self.plaintext_size)
    }
}

/// Convergent encryption engine
///
/// Provides deterministic encryption for content-addressed storage. The same plaintext
/// encrypted with the same master key will always produce the same ciphertext, enabling
/// deduplication.
///
/// # Security Considerations
///
/// - **Deterministic**: Identical plaintexts are linkable (they produce the same CID)
/// - **Key-dependent**: Different master keys produce different ciphertexts
/// - **Content integrity**: CID verification prevents tampering
/// - **No randomness**: Nonces are derived deterministically, not randomly
///
/// For non-deterministic encryption (e.g., for manifests), use `ManifestEncryptor`.
pub struct ConvergentEncryptor {
    master_key: MasterEncryptionKey,
}

impl ConvergentEncryptor {
    /// Create a new convergent encryptor with the given master key
    ///
    /// # Examples
    ///
    /// ```
    /// use portal_core::{RecoveryPhrase, KeyHierarchy};
    /// use portal_core::encryption::ConvergentEncryptor;
    ///
    /// let hierarchy = KeyHierarchy::from_recovery_phrase(&RecoveryPhrase::generate()).unwrap();
    /// let encryptor = ConvergentEncryptor::new(hierarchy.encryption().clone());
    /// ```
    #[must_use]
    pub const fn new(master_key: MasterEncryptionKey) -> Self {
        Self { master_key }
    }

    /// Encrypt a chunk with convergent encryption
    ///
    /// This method performs the following steps:
    /// 1. Compute content ID from plaintext
    /// 2. Derive chunk-specific encryption key
    /// 3. Derive deterministic nonce
    /// 4. Encrypt with ChaCha20-Poly1305
    ///
    /// # Errors
    ///
    /// Returns `Error::Encryption` if encryption fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use portal_core::{RecoveryPhrase, KeyHierarchy};
    /// use portal_core::encryption::ConvergentEncryptor;
    ///
    /// let hierarchy = KeyHierarchy::from_recovery_phrase(&RecoveryPhrase::generate()).unwrap();
    /// let encryptor = ConvergentEncryptor::new(hierarchy.encryption().clone());
    ///
    /// let plaintext = b"test data";
    /// let chunk = encryptor.encrypt_chunk(plaintext).unwrap();
    /// assert_eq!(chunk.plaintext_size, plaintext.len() as u64);
    /// ```
    pub fn encrypt_chunk(&self, plaintext: &[u8]) -> Result<EncryptedChunk> {
        // 1. Compute content ID from plaintext
        let cid = warp_hash::hash(plaintext);

        // 2. Derive chunk-specific encryption key
        let chunk_key = self.derive_chunk_key(&cid);

        // 3. Derive deterministic nonce
        let nonce_bytes = self.derive_nonce(&cid);

        // 4. Encrypt with ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305::new(chunk_key.as_ref().into());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let data = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| Error::Encryption(warp_crypto::Error::Encryption(e.to_string())))?;

        Ok(EncryptedChunk {
            cid,
            data,
            plaintext_size: plaintext.len() as u64,
        })
    }

    /// Decrypt a chunk and verify its content ID
    ///
    /// This method decrypts the chunk and verifies that the decrypted plaintext
    /// matches the claimed content ID. This prevents tampering with either the
    /// ciphertext or the CID.
    ///
    /// # Errors
    ///
    /// Returns `Error::Decryption` if decryption fails.
    /// Returns `Error::InvalidContentId` if the decrypted plaintext doesn't match the CID.
    ///
    /// # Examples
    ///
    /// ```
    /// use portal_core::{RecoveryPhrase, KeyHierarchy};
    /// use portal_core::encryption::ConvergentEncryptor;
    ///
    /// let hierarchy = KeyHierarchy::from_recovery_phrase(&RecoveryPhrase::generate()).unwrap();
    /// let encryptor = ConvergentEncryptor::new(hierarchy.encryption().clone());
    ///
    /// let plaintext = b"test data";
    /// let chunk = encryptor.encrypt_chunk(plaintext).unwrap();
    /// let decrypted = encryptor.decrypt_chunk(&chunk).unwrap();
    /// assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    /// ```
    pub fn decrypt_chunk(&self, chunk: &EncryptedChunk) -> Result<Vec<u8>> {
        // Derive chunk-specific encryption key
        let chunk_key = self.derive_chunk_key(&chunk.cid);

        // Derive deterministic nonce
        let nonce_bytes = self.derive_nonce(&chunk.cid);

        // Decrypt with ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305::new(chunk_key.as_ref().into());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, chunk.data.as_ref())
            .map_err(|e| Error::Encryption(warp_crypto::Error::Decryption(e.to_string())))?;

        // Verify content ID matches decrypted plaintext
        let computed_cid = warp_hash::hash(&plaintext);
        if computed_cid != chunk.cid {
            return Err(Error::InvalidContentId);
        }

        Ok(plaintext)
    }

    /// Derive a chunk-specific encryption key from the content ID
    ///
    /// Uses HKDF-SHA256 to derive a unique key for each content ID from the master key.
    /// This ensures that different chunks use different encryption keys, even though
    /// the nonces are deterministic.
    ///
    /// # Implementation
    ///
    /// ```text
    /// chunk_key = HKDF-SHA256(master_key, salt=CID, info="portal/chunk/v1")
    /// ```
    ///
    /// # Panics
    ///
    /// This function will never panic in practice, as 32 bytes is always a valid
    /// HKDF-SHA256 output length. The `expect` call is for defensive programming.
    #[must_use]
    pub fn derive_chunk_key(&self, content_id: &ContentId) -> [u8; 32] {
        let hkdf = Hkdf::<Sha256>::new(Some(content_id), self.master_key.as_bytes());
        let mut key = [0u8; 32];
        hkdf.expand(CONTEXT_CHUNK_KEY, &mut key)
            .expect("32 bytes is a valid HKDF output length");
        key
    }

    /// Derive a deterministic nonce from the content ID
    ///
    /// Uses BLAKE3 to derive a deterministic 12-byte nonce from the content ID.
    /// This ensures that the same content always uses the same nonce with the
    /// same chunk key, making encryption deterministic.
    ///
    /// # Implementation
    ///
    /// ```text
    /// nonce = BLAKE3(context="portal/nonce/v1", key_material=CID)[0..12]
    /// ```
    ///
    /// # Panics
    ///
    /// This function will never panic in practice, as `CONTEXT_NONCE` is a valid
    /// UTF-8 string literal. The `expect` call is for defensive programming.
    #[must_use]
    pub fn derive_nonce(&self, content_id: &ContentId) -> [u8; 12] {
        let full_hash = warp_hash::derive_key(
            std::str::from_utf8(CONTEXT_NONCE).expect("context is valid UTF-8"),
            content_id,
        );
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&full_hash[..12]);
        nonce
    }
}

/// Manifest encryption (non-convergent, uses random nonce)
///
/// Provides non-deterministic encryption for portal manifests and metadata.
/// Unlike convergent encryption, this uses random nonces to ensure that the same
/// plaintext produces different ciphertexts each time.
///
/// # Use Cases
///
/// - Portal manifests (file lists, metadata)
/// - Access control lists
/// - Any metadata that should not be linkable across encryptions
///
/// # Format
///
/// Encrypted data format: `nonce (12 bytes) || ciphertext || tag (16 bytes)`
pub struct ManifestEncryptor {
    master_key: MasterEncryptionKey,
}

impl ManifestEncryptor {
    /// Create a new manifest encryptor with the given master key
    ///
    /// # Examples
    ///
    /// ```
    /// use portal_core::{RecoveryPhrase, KeyHierarchy};
    /// use portal_core::encryption::ManifestEncryptor;
    ///
    /// let hierarchy = KeyHierarchy::from_recovery_phrase(&RecoveryPhrase::generate()).unwrap();
    /// let encryptor = ManifestEncryptor::new(hierarchy.encryption().clone());
    /// ```
    #[must_use]
    pub const fn new(master_key: MasterEncryptionKey) -> Self {
        Self { master_key }
    }

    /// Encrypt plaintext with a random nonce
    ///
    /// Returns: `nonce (12 bytes) || ciphertext || tag (16 bytes)`
    ///
    /// Each encryption uses a fresh random nonce, ensuring that the same plaintext
    /// produces different ciphertexts.
    ///
    /// # Errors
    ///
    /// Returns `Error::Encryption` if encryption fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use portal_core::{RecoveryPhrase, KeyHierarchy};
    /// use portal_core::encryption::ManifestEncryptor;
    ///
    /// let hierarchy = KeyHierarchy::from_recovery_phrase(&RecoveryPhrase::generate()).unwrap();
    /// let encryptor = ManifestEncryptor::new(hierarchy.encryption().clone());
    ///
    /// let plaintext = b"manifest data";
    /// let ciphertext1 = encryptor.encrypt(plaintext).unwrap();
    /// let ciphertext2 = encryptor.encrypt(plaintext).unwrap();
    /// // Different ciphertexts for same plaintext (non-deterministic)
    /// assert_ne!(ciphertext1, ciphertext2);
    /// ```
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(self.master_key.as_bytes().into());

        // Generate random nonce using cryptographically secure RNG
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| Error::Encryption(warp_crypto::Error::Encryption(e.to_string())))?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt ciphertext that was encrypted with a random nonce
    ///
    /// Expects input format: `nonce (12 bytes) || ciphertext || tag (16 bytes)`
    ///
    /// # Errors
    ///
    /// Returns `Error::Decryption` if:
    /// - The ciphertext is too short (< 28 bytes)
    /// - Authentication fails
    /// - Decryption fails for any other reason
    ///
    /// # Examples
    ///
    /// ```
    /// use portal_core::{RecoveryPhrase, KeyHierarchy};
    /// use portal_core::encryption::ManifestEncryptor;
    ///
    /// let hierarchy = KeyHierarchy::from_recovery_phrase(&RecoveryPhrase::generate()).unwrap();
    /// let encryptor = ManifestEncryptor::new(hierarchy.encryption().clone());
    ///
    /// let plaintext = b"manifest data";
    /// let ciphertext = encryptor.encrypt(plaintext).unwrap();
    /// let decrypted = encryptor.decrypt(&ciphertext).unwrap();
    /// assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    /// ```
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Minimum size: 12 (nonce) + 16 (tag)
        if ciphertext.len() < 28 {
            return Err(Error::Encryption(warp_crypto::Error::Decryption(
                "Ciphertext too short".into(),
            )));
        }

        let cipher = ChaCha20Poly1305::new(self.master_key.as_bytes().into());
        let nonce = Nonce::from_slice(&ciphertext[..12]);

        cipher
            .decrypt(nonce, &ciphertext[12..])
            .map_err(|e| Error::Encryption(warp_crypto::Error::Decryption(e.to_string())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KeyHierarchy, RecoveryPhrase};

    /// Test 1: Convergent encryption is deterministic (same plaintext = same ciphertext)
    #[test]
    fn test_convergent_encryption_deterministic() {
        let hierarchy = KeyHierarchy::from_recovery_phrase(&RecoveryPhrase::generate()).unwrap();
        let encryptor = ConvergentEncryptor::new(hierarchy.encryption().clone());

        let plaintext = b"Hello, Portal! This is test data.";

        // Encrypt the same plaintext twice
        let chunk1 = encryptor.encrypt_chunk(plaintext).unwrap();
        let chunk2 = encryptor.encrypt_chunk(plaintext).unwrap();

        // Should produce identical encrypted chunks
        assert_eq!(
            chunk1.cid, chunk2.cid,
            "Same plaintext should produce same CID"
        );
        assert_eq!(
            chunk1.data, chunk2.data,
            "Same plaintext should produce same ciphertext"
        );
        assert_eq!(
            chunk1.plaintext_size, chunk2.plaintext_size,
            "Should track same plaintext size"
        );
        assert_eq!(chunk1, chunk2, "Chunks should be identical");
    }

    /// Test 2: Convergent encryption roundtrip (encrypt then decrypt)
    #[test]
    fn test_convergent_encryption_roundtrip() {
        let hierarchy = KeyHierarchy::from_recovery_phrase(&RecoveryPhrase::generate()).unwrap();
        let encryptor = ConvergentEncryptor::new(hierarchy.encryption().clone());

        let plaintext = b"Test data for roundtrip verification";

        let chunk = encryptor.encrypt_chunk(plaintext).unwrap();
        let decrypted = encryptor.decrypt_chunk(&chunk).unwrap();

        assert_eq!(
            plaintext.as_slice(),
            decrypted.as_slice(),
            "Decrypted plaintext should match original"
        );
        assert_eq!(
            chunk.plaintext_size,
            plaintext.len() as u64,
            "Plaintext size should be tracked correctly"
        );
    }

    /// Test 3: Different plaintext produces different CID and ciphertext
    #[test]
    fn test_different_plaintext_different_cid() {
        let hierarchy = KeyHierarchy::from_recovery_phrase(&RecoveryPhrase::generate()).unwrap();
        let encryptor = ConvergentEncryptor::new(hierarchy.encryption().clone());

        let plaintext1 = b"First piece of data";
        let plaintext2 = b"Second piece of data";

        let chunk1 = encryptor.encrypt_chunk(plaintext1).unwrap();
        let chunk2 = encryptor.encrypt_chunk(plaintext2).unwrap();

        assert_ne!(
            chunk1.cid, chunk2.cid,
            "Different plaintext should produce different CID"
        );
        assert_ne!(
            chunk1.data, chunk2.data,
            "Different plaintext should produce different ciphertext"
        );
        assert_ne!(
            chunk1.plaintext_size, chunk2.plaintext_size,
            "Different plaintext sizes should be tracked"
        );
    }

    /// Test 4: Decrypting with wrong CID fails
    #[test]
    fn test_decrypt_wrong_cid_fails() {
        let hierarchy = KeyHierarchy::from_recovery_phrase(&RecoveryPhrase::generate()).unwrap();
        let encryptor = ConvergentEncryptor::new(hierarchy.encryption().clone());

        let plaintext = b"Original data";
        let chunk = encryptor.encrypt_chunk(plaintext).unwrap();

        // Create a tampered chunk with wrong CID
        let mut tampered = chunk.clone();
        tampered.cid[0] ^= 0xFF; // Flip bits in first byte

        let result = encryptor.decrypt_chunk(&tampered);
        assert!(result.is_err(), "Decryption should fail with wrong CID");

        // The error should be InvalidContentId since the CID won't match after decryption
        match result.unwrap_err() {
            Error::InvalidContentId => {
                // Expected - CID verification failed
            }
            Error::Encryption(_) => {
                // Also acceptable - decryption may fail due to wrong key derivation
            }
            other => panic!("Unexpected error type: {:?}", other),
        }
    }

    /// Test 5: Manifest encryption is non-deterministic
    #[test]
    fn test_manifest_encryption_non_deterministic() {
        let hierarchy = KeyHierarchy::from_recovery_phrase(&RecoveryPhrase::generate()).unwrap();
        let encryptor = ManifestEncryptor::new(hierarchy.encryption().clone());

        let plaintext = b"Manifest metadata";

        // Encrypt the same plaintext multiple times
        let ciphertext1 = encryptor.encrypt(plaintext).unwrap();
        let ciphertext2 = encryptor.encrypt(plaintext).unwrap();
        let ciphertext3 = encryptor.encrypt(plaintext).unwrap();

        // Should produce different ciphertexts (due to random nonces)
        assert_ne!(
            ciphertext1, ciphertext2,
            "Same plaintext should produce different ciphertext (random nonce)"
        );
        assert_ne!(ciphertext2, ciphertext3);
        assert_ne!(ciphertext1, ciphertext3);

        // All should have different nonces (first 12 bytes)
        assert_ne!(&ciphertext1[..12], &ciphertext2[..12]);
        assert_ne!(&ciphertext2[..12], &ciphertext3[..12]);
        assert_ne!(&ciphertext1[..12], &ciphertext3[..12]);
    }

    /// Test 6: Manifest encryption roundtrip
    #[test]
    fn test_manifest_encryption_roundtrip() {
        let hierarchy = KeyHierarchy::from_recovery_phrase(&RecoveryPhrase::generate()).unwrap();
        let encryptor = ManifestEncryptor::new(hierarchy.encryption().clone());

        let plaintext = b"Manifest data with metadata";

        let ciphertext = encryptor.encrypt(plaintext).unwrap();
        let decrypted = encryptor.decrypt(&ciphertext).unwrap();

        assert_eq!(
            plaintext.as_slice(),
            decrypted.as_slice(),
            "Decrypted plaintext should match original"
        );

        // Verify we can decrypt multiple different encryptions
        let ciphertext2 = encryptor.encrypt(plaintext).unwrap();
        let decrypted2 = encryptor.decrypt(&ciphertext2).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted2.as_slice());
    }

    /// Test 7: Empty plaintext handling
    #[test]
    fn test_empty_plaintext() {
        let hierarchy = KeyHierarchy::from_recovery_phrase(&RecoveryPhrase::generate()).unwrap();
        let conv_encryptor = ConvergentEncryptor::new(hierarchy.encryption().clone());
        let manifest_encryptor = ManifestEncryptor::new(hierarchy.encryption().clone());

        let empty: &[u8] = b"";

        // Convergent encryption of empty data
        let chunk = conv_encryptor.encrypt_chunk(empty).unwrap();
        assert_eq!(chunk.plaintext_size, 0);
        assert_eq!(chunk.data.len(), 16, "Should have 16-byte tag");

        let decrypted = conv_encryptor.decrypt_chunk(&chunk).unwrap();
        assert_eq!(decrypted.len(), 0);

        // Manifest encryption of empty data
        let ciphertext = manifest_encryptor.encrypt(empty).unwrap();
        assert_eq!(
            ciphertext.len(),
            28,
            "Should have 12-byte nonce + 16-byte tag"
        );

        let decrypted = manifest_encryptor.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted.len(), 0);
    }

    /// Test 8: Large plaintext (16MB+) handling
    #[test]
    fn test_large_plaintext() {
        let hierarchy = KeyHierarchy::from_recovery_phrase(&RecoveryPhrase::generate()).unwrap();
        let conv_encryptor = ConvergentEncryptor::new(hierarchy.encryption().clone());
        let manifest_encryptor = ManifestEncryptor::new(hierarchy.encryption().clone());

        // Create 16MB + 1 byte of data
        let size = 16 * 1024 * 1024 + 1;
        let large_data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

        // Convergent encryption
        let chunk = conv_encryptor.encrypt_chunk(&large_data).unwrap();
        assert_eq!(chunk.plaintext_size, size as u64);
        assert_eq!(
            chunk.encrypted_size(),
            size as u64 + 16,
            "Should add 16-byte tag"
        );
        assert_eq!(chunk.overhead(), 16);

        let decrypted = conv_encryptor.decrypt_chunk(&chunk).unwrap();
        assert_eq!(decrypted.len(), size);
        assert_eq!(decrypted, large_data);

        // Manifest encryption (this will be slower due to size)
        let ciphertext = manifest_encryptor.encrypt(&large_data).unwrap();
        assert_eq!(
            ciphertext.len(),
            size + 28,
            "Should add 12-byte nonce + 16-byte tag"
        );

        let decrypted = manifest_encryptor.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, large_data);
    }

    /// Test 9: Key isolation - different master keys can't decrypt each other's data
    #[test]
    fn test_key_isolation() {
        let hierarchy1 = KeyHierarchy::from_recovery_phrase(&RecoveryPhrase::generate()).unwrap();
        let hierarchy2 = KeyHierarchy::from_recovery_phrase(&RecoveryPhrase::generate()).unwrap();

        let encryptor1 = ConvergentEncryptor::new(hierarchy1.encryption().clone());
        let encryptor2 = ConvergentEncryptor::new(hierarchy2.encryption().clone());

        let plaintext = b"Secret data";

        // Encrypt with key 1
        let chunk1 = encryptor1.encrypt_chunk(plaintext).unwrap();

        // Try to decrypt with key 2 - should fail
        let result = encryptor2.decrypt_chunk(&chunk1);
        assert!(
            result.is_err(),
            "Should not be able to decrypt with different key"
        );

        // Same test for manifest encryption
        let manifest_enc1 = ManifestEncryptor::new(hierarchy1.encryption().clone());
        let manifest_enc2 = ManifestEncryptor::new(hierarchy2.encryption().clone());

        let ciphertext = manifest_enc1.encrypt(plaintext).unwrap();
        let result = manifest_enc2.decrypt(&ciphertext);
        assert!(
            result.is_err(),
            "Should not be able to decrypt manifest with different key"
        );
    }

    /// Test 10: CID tampering detection
    #[test]
    fn test_cid_tampering_detection() {
        let hierarchy = KeyHierarchy::from_recovery_phrase(&RecoveryPhrase::generate()).unwrap();
        let encryptor = ConvergentEncryptor::new(hierarchy.encryption().clone());

        let plaintext = b"Important data";
        let chunk = encryptor.encrypt_chunk(plaintext).unwrap();

        // Tamper with ciphertext but keep CID
        let mut tampered = chunk.clone();
        if !tampered.data.is_empty() {
            tampered.data[0] ^= 0xFF;
        }

        let result = encryptor.decrypt_chunk(&tampered);
        assert!(result.is_err(), "Should detect tampered ciphertext");
    }

    /// Test 11: Manifest decryption with too-short ciphertext
    #[test]
    fn test_manifest_decrypt_short_ciphertext() {
        let hierarchy = KeyHierarchy::from_recovery_phrase(&RecoveryPhrase::generate()).unwrap();
        let encryptor = ManifestEncryptor::new(hierarchy.encryption().clone());

        // Too short (< 28 bytes)
        let short = vec![0u8; 27];
        let result = encryptor.decrypt(&short);
        assert!(result.is_err(), "Should reject too-short ciphertext");

        // Empty
        let empty = vec![];
        let result = encryptor.decrypt(&empty);
        assert!(result.is_err(), "Should reject empty ciphertext");
    }

    /// Test 12: Convergent encryption produces consistent chunk keys
    #[test]
    fn test_derive_chunk_key_deterministic() {
        let hierarchy = KeyHierarchy::from_recovery_phrase(&RecoveryPhrase::generate()).unwrap();
        let encryptor = ConvergentEncryptor::new(hierarchy.encryption().clone());

        let cid = warp_hash::hash(b"test data");

        let key1 = encryptor.derive_chunk_key(&cid);
        let key2 = encryptor.derive_chunk_key(&cid);

        assert_eq!(key1, key2, "Same CID should produce same chunk key");

        // Different CID should produce different key
        let cid2 = warp_hash::hash(b"different data");
        let key3 = encryptor.derive_chunk_key(&cid2);
        assert_ne!(key1, key3, "Different CID should produce different key");
    }

    /// Test 13: Convergent encryption produces consistent nonces
    #[test]
    fn test_derive_nonce_deterministic() {
        let hierarchy = KeyHierarchy::from_recovery_phrase(&RecoveryPhrase::generate()).unwrap();
        let encryptor = ConvergentEncryptor::new(hierarchy.encryption().clone());

        let cid = warp_hash::hash(b"test data");

        let nonce1 = encryptor.derive_nonce(&cid);
        let nonce2 = encryptor.derive_nonce(&cid);

        assert_eq!(nonce1, nonce2, "Same CID should produce same nonce");
        assert_eq!(nonce1.len(), 12, "Nonce should be 12 bytes");

        // Different CID should produce different nonce
        let cid2 = warp_hash::hash(b"different data");
        let nonce3 = encryptor.derive_nonce(&cid2);
        assert_ne!(
            nonce1, nonce3,
            "Different CID should produce different nonce"
        );
    }

    /// Test 14: EncryptedChunk metadata methods
    #[test]
    fn test_encrypted_chunk_metadata() {
        let hierarchy = KeyHierarchy::from_recovery_phrase(&RecoveryPhrase::generate()).unwrap();
        let encryptor = ConvergentEncryptor::new(hierarchy.encryption().clone());

        let plaintext = b"Test data";
        let chunk = encryptor.encrypt_chunk(plaintext).unwrap();

        assert_eq!(chunk.plaintext_size, plaintext.len() as u64);
        assert_eq!(
            chunk.encrypted_size(),
            (plaintext.len() + 16) as u64,
            "Encrypted size = plaintext + 16-byte tag"
        );
        assert_eq!(chunk.overhead(), 16, "Overhead should be 16 bytes (tag)");
    }

    /// Test 15: Different keys produce different ciphertexts for same plaintext
    #[test]
    fn test_different_keys_different_ciphertext() {
        let hierarchy1 = KeyHierarchy::from_recovery_phrase(&RecoveryPhrase::generate()).unwrap();
        let hierarchy2 = KeyHierarchy::from_recovery_phrase(&RecoveryPhrase::generate()).unwrap();

        let encryptor1 = ConvergentEncryptor::new(hierarchy1.encryption().clone());
        let encryptor2 = ConvergentEncryptor::new(hierarchy2.encryption().clone());

        let plaintext = b"Same plaintext";

        let chunk1 = encryptor1.encrypt_chunk(plaintext).unwrap();
        let chunk2 = encryptor2.encrypt_chunk(plaintext).unwrap();

        // CIDs should be the same (based on plaintext)
        assert_eq!(
            chunk1.cid, chunk2.cid,
            "CID is content-based, should be same"
        );

        // But ciphertexts should be different (due to different keys)
        assert_ne!(
            chunk1.data, chunk2.data,
            "Different keys should produce different ciphertext"
        );
    }

    /// Test 16: Verify chunk key derivation uses CID as salt
    #[test]
    fn test_chunk_key_uses_cid_as_salt() {
        let hierarchy = KeyHierarchy::from_recovery_phrase(&RecoveryPhrase::generate()).unwrap();
        let encryptor = ConvergentEncryptor::new(hierarchy.encryption().clone());

        // Two different plaintexts
        let plaintext1 = b"First data";
        let plaintext2 = b"Second data";

        let cid1 = warp_hash::hash(plaintext1);
        let cid2 = warp_hash::hash(plaintext2);

        let key1 = encryptor.derive_chunk_key(&cid1);
        let key2 = encryptor.derive_chunk_key(&cid2);

        assert_ne!(
            key1, key2,
            "Different CIDs should produce different chunk keys"
        );
    }
}
