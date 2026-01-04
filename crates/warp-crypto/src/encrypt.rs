//! ChaCha20-Poly1305 AEAD encryption

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroize;

use crate::{Error, Result};

/// Encryption key (32 bytes)
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Key([u8; 32]);

impl Key {
    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Generate random key
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Get bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Encrypt data with ChaCha20-Poly1305
///
/// Returns: nonce (12 bytes) || ciphertext || tag (16 bytes)
pub fn encrypt(key: &Key, plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.0.as_ref().into());

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| Error::Encryption(e.to_string()))?;

    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt data with ChaCha20-Poly1305
///
/// Input: nonce (12 bytes) || ciphertext || tag (16 bytes)
pub fn decrypt(key: &Key, ciphertext: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < 12 + 16 {
        return Err(Error::Decryption("Ciphertext too short".into()));
    }

    let cipher = ChaCha20Poly1305::new(key.0.as_ref().into());
    let nonce = Nonce::from_slice(&ciphertext[..12]);

    cipher
        .decrypt(nonce, &ciphertext[12..])
        .map_err(|e| Error::Decryption(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let key = Key::generate();
        let plaintext = b"hello, world!";

        let ciphertext = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &ciphertext).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
}

#[cfg(test)]
mod proptest_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Property: encrypt then decrypt recovers original plaintext
        #[test]
        fn roundtrip_any_data(plaintext in prop::collection::vec(any::<u8>(), 0..4096)) {
            let key = Key::generate();

            let ciphertext = encrypt(&key, &plaintext).unwrap();
            let decrypted = decrypt(&key, &ciphertext).unwrap();

            prop_assert_eq!(plaintext, decrypted);
        }

        /// Property: ciphertext is always longer than plaintext (nonce + tag overhead)
        #[test]
        fn ciphertext_has_overhead(plaintext in prop::collection::vec(any::<u8>(), 0..1024)) {
            let key = Key::generate();

            let ciphertext = encrypt(&key, &plaintext).unwrap();

            // 12 bytes nonce + 16 bytes tag = 28 bytes overhead
            prop_assert_eq!(ciphertext.len(), plaintext.len() + 28);
        }

        /// Property: different keys produce different ciphertexts
        #[test]
        fn different_keys_different_ciphertext(plaintext in prop::collection::vec(any::<u8>(), 1..256)) {
            let key1 = Key::generate();
            let key2 = Key::generate();

            let ct1 = encrypt(&key1, &plaintext).unwrap();
            let ct2 = encrypt(&key2, &plaintext).unwrap();

            // Ciphertexts should differ (overwhelmingly likely due to random nonces too)
            prop_assert_ne!(ct1, ct2);
        }

        /// Property: wrong key fails decryption
        #[test]
        fn wrong_key_fails(plaintext in prop::collection::vec(any::<u8>(), 1..256)) {
            let key1 = Key::generate();
            let key2 = Key::generate();

            let ciphertext = encrypt(&key1, &plaintext).unwrap();
            let result = decrypt(&key2, &ciphertext);

            prop_assert!(result.is_err());
        }
    }
}
