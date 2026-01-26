//! Cryptographic primitives for WireGuard
//!
//! This module provides the low-level cryptographic operations used by
//! the Noise protocol implementation.

#![allow(clippy::explicit_auto_deref)]

use aead::{Aead, KeyInit as AeadKeyInit, Payload};
use blake2::digest::consts::U32;
use blake2::digest::{FixedOutput, KeyInit, Mac, Update};
use blake2::{Blake2s256, Blake2sMac, Digest};
use chacha20poly1305::ChaCha20Poly1305;

use super::WireGuardError;

/// WireGuard protocol identifier for Noise
pub const NOISE_PROTOCOL_NAME: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";

/// WireGuard identifier
pub const WG_IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";

/// BLAKE2s hash output size
pub const HASH_LEN: usize = 32;

/// ChaCha20-Poly1305 key size
pub const KEY_LEN: usize = 32;

/// ChaCha20-Poly1305 nonce size
pub const NONCE_LEN: usize = 12;

/// ChaCha20-Poly1305 tag size
pub const TAG_LEN: usize = 16;

/// BLAKE2s-based MAC (keyed hash)
type Blake2sMac256 = Blake2sMac<U32>;

/// Compute BLAKE2s hash
pub fn hash(data: &[u8]) -> [u8; HASH_LEN] {
    let mut hasher = Blake2s256::new();
    Digest::update(&mut hasher, data);
    hasher.finalize().into()
}

/// Compute BLAKE2s hash of multiple inputs
pub fn hash_many(data: &[&[u8]]) -> [u8; HASH_LEN] {
    let mut hasher = Blake2s256::new();
    for d in data {
        Digest::update(&mut hasher, *d);
    }
    hasher.finalize().into()
}

/// HMAC-BLAKE2s using keyed BLAKE2s (more efficient than HMAC wrapper)
///
/// WireGuard uses BLAKE2s in keyed mode which is equivalent to HMAC
/// for BLAKE2s but more efficient.
pub fn hmac(key: &[u8], data: &[u8]) -> [u8; HASH_LEN] {
    // For keys > 32 bytes, hash the key first
    let key_bytes: [u8; 32] = if key.len() > 32 {
        hash(key)
    } else {
        let mut k = [0u8; 32];
        k[..key.len()].copy_from_slice(key);
        k
    };

    let mut mac: Blake2sMac256 = KeyInit::new_from_slice(&key_bytes[..key.len().min(32)])
        .expect("BLAKE2s MAC accepts any key size up to 32 bytes");
    Update::update(&mut mac, data);
    mac.finalize_fixed().into()
}

/// HMAC-BLAKE2s with multiple data inputs
pub fn hmac_many(key: &[u8], data: &[&[u8]]) -> [u8; HASH_LEN] {
    let key_bytes: [u8; 32] = if key.len() > 32 {
        hash(key)
    } else {
        let mut k = [0u8; 32];
        k[..key.len()].copy_from_slice(key);
        k
    };

    let mut mac: Blake2sMac256 = KeyInit::new_from_slice(&key_bytes[..key.len().min(32)])
        .expect("BLAKE2s MAC accepts any key size up to 32 bytes");
    for d in data {
        Update::update(&mut mac, *d);
    }
    mac.finalize_fixed().into()
}

/// HKDF function that extracts and expands in one step
///
/// Returns (output1, output2) where each is 32 bytes
pub fn hkdf2(chaining_key: &[u8; HASH_LEN], input: &[u8]) -> ([u8; HASH_LEN], [u8; HASH_LEN]) {
    // Extract
    let prk = hmac(chaining_key, input);

    // Expand to two outputs
    let t1 = hmac(&prk, &[1]);
    let mut t2_input = [0u8; HASH_LEN + 1];
    t2_input[..HASH_LEN].copy_from_slice(&t1);
    t2_input[HASH_LEN] = 2;
    let t2 = hmac(&prk, &t2_input);

    (t1, t2)
}

/// HKDF function that extracts and expands to three outputs
///
/// Returns (output1, output2, output3) where each is 32 bytes
pub fn hkdf3(
    chaining_key: &[u8; HASH_LEN],
    input: &[u8],
) -> ([u8; HASH_LEN], [u8; HASH_LEN], [u8; HASH_LEN]) {
    // Extract
    let prk = hmac(chaining_key, input);

    // Expand to three outputs
    let t1 = hmac(&prk, &[1]);

    let mut t2_input = [0u8; HASH_LEN + 1];
    t2_input[..HASH_LEN].copy_from_slice(&t1);
    t2_input[HASH_LEN] = 2;
    let t2 = hmac(&prk, &t2_input);

    let mut t3_input = [0u8; HASH_LEN + 1];
    t3_input[..HASH_LEN].copy_from_slice(&t2);
    t3_input[HASH_LEN] = 3;
    let t3 = hmac(&prk, &t3_input);

    (t1, t2, t3)
}

/// ChaCha20-Poly1305 AEAD encryption
pub fn aead_encrypt(
    key: &[u8; KEY_LEN],
    counter: u64,
    plaintext: &[u8],
    aad: &[u8],
    output: &mut [u8],
) -> Result<usize, WireGuardError> {
    let cipher: ChaCha20Poly1305 =
        AeadKeyInit::new_from_slice(key).map_err(|_| WireGuardError::EncryptionFailed)?;

    // Build nonce: 4 bytes of zeros + 8 bytes little-endian counter
    let mut nonce = [0u8; NONCE_LEN];
    nonce[4..12].copy_from_slice(&counter.to_le_bytes());

    let payload = Payload {
        msg: plaintext,
        aad,
    };

    let ciphertext = cipher
        .encrypt((&nonce).into(), payload)
        .map_err(|_| WireGuardError::EncryptionFailed)?;

    if output.len() < ciphertext.len() {
        return Err(WireGuardError::DestinationBufferTooSmall);
    }

    output[..ciphertext.len()].copy_from_slice(&ciphertext);
    Ok(ciphertext.len())
}

/// ChaCha20-Poly1305 AEAD decryption
pub fn aead_decrypt(
    key: &[u8; KEY_LEN],
    counter: u64,
    ciphertext: &[u8],
    aad: &[u8],
    output: &mut [u8],
) -> Result<usize, WireGuardError> {
    if ciphertext.len() < TAG_LEN {
        return Err(WireGuardError::InvalidPacket);
    }

    let cipher: ChaCha20Poly1305 =
        AeadKeyInit::new_from_slice(key).map_err(|_| WireGuardError::DecryptionFailed)?;

    // Build nonce: 4 bytes of zeros + 8 bytes little-endian counter
    let mut nonce = [0u8; NONCE_LEN];
    nonce[4..12].copy_from_slice(&counter.to_le_bytes());

    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    let plaintext = cipher
        .decrypt((&nonce).into(), payload)
        .map_err(|_| WireGuardError::DecryptionFailed)?;

    if output.len() < plaintext.len() {
        return Err(WireGuardError::DestinationBufferTooSmall);
    }

    output[..plaintext.len()].copy_from_slice(&plaintext);
    Ok(plaintext.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash() {
        let data = b"test data";
        let h = hash(data);
        assert_eq!(h.len(), HASH_LEN);

        // Same input should produce same output
        let h2 = hash(data);
        assert_eq!(h, h2);

        // Different input should produce different output
        let h3 = hash(b"different data");
        assert_ne!(h, h3);
    }

    #[test]
    fn test_hmac() {
        let key = b"secret key";
        let data = b"message";

        let mac = hmac(key, data);
        assert_eq!(mac.len(), HASH_LEN);

        // Same inputs should produce same output
        let mac2 = hmac(key, data);
        assert_eq!(mac, mac2);

        // Different key should produce different output
        let mac3 = hmac(b"different key", data);
        assert_ne!(mac, mac3);
    }

    #[test]
    fn test_hkdf2() {
        let ck = [0u8; HASH_LEN];
        let input = b"input keying material";

        let (t1, t2) = hkdf2(&ck, input);

        assert_eq!(t1.len(), HASH_LEN);
        assert_eq!(t2.len(), HASH_LEN);
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_hkdf3() {
        let ck = [0u8; HASH_LEN];
        let input = b"input keying material";

        let (t1, t2, t3) = hkdf3(&ck, input);

        assert_eq!(t1.len(), HASH_LEN);
        assert_eq!(t2.len(), HASH_LEN);
        assert_eq!(t3.len(), HASH_LEN);
        assert_ne!(t1, t2);
        assert_ne!(t2, t3);
        assert_ne!(t1, t3);
    }

    #[test]
    fn test_aead_roundtrip() {
        let key = [1u8; KEY_LEN];
        let counter = 0u64;
        let plaintext = b"Hello, WireGuard!";
        let aad = b"additional data";

        let mut ciphertext = vec![0u8; plaintext.len() + TAG_LEN];
        let ct_len = aead_encrypt(&key, counter, plaintext, aad, &mut ciphertext).unwrap();
        assert_eq!(ct_len, plaintext.len() + TAG_LEN);

        let mut decrypted = vec![0u8; plaintext.len()];
        let pt_len =
            aead_decrypt(&key, counter, &ciphertext[..ct_len], aad, &mut decrypted).unwrap();
        assert_eq!(pt_len, plaintext.len());
        assert_eq!(&decrypted[..pt_len], plaintext);
    }

    #[test]
    fn test_aead_wrong_key() {
        let key = [1u8; KEY_LEN];
        let wrong_key = [2u8; KEY_LEN];
        let counter = 0u64;
        let plaintext = b"Hello, WireGuard!";
        let aad = b"additional data";

        let mut ciphertext = vec![0u8; plaintext.len() + TAG_LEN];
        aead_encrypt(&key, counter, plaintext, aad, &mut ciphertext).unwrap();

        let mut decrypted = vec![0u8; plaintext.len()];
        let result = aead_decrypt(&wrong_key, counter, &ciphertext, aad, &mut decrypted);
        assert!(matches!(result, Err(WireGuardError::DecryptionFailed)));
    }

    #[test]
    fn test_aead_wrong_aad() {
        let key = [1u8; KEY_LEN];
        let counter = 0u64;
        let plaintext = b"Hello, WireGuard!";
        let aad = b"additional data";
        let wrong_aad = b"wrong aad";

        let mut ciphertext = vec![0u8; plaintext.len() + TAG_LEN];
        aead_encrypt(&key, counter, plaintext, aad, &mut ciphertext).unwrap();

        let mut decrypted = vec![0u8; plaintext.len()];
        let result = aead_decrypt(&key, counter, &ciphertext, wrong_aad, &mut decrypted);
        assert!(matches!(result, Err(WireGuardError::DecryptionFailed)));
    }
}
