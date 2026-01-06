//! Ed25519 signatures

use crate::{Error, Result};
use ed25519_dalek::Signer;
pub use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use rand::rngs::OsRng;

/// Sign data with Ed25519
pub fn sign(key: &SigningKey, data: &[u8]) -> Signature {
    key.sign(data)
}

/// Verify an Ed25519 signature
pub fn verify(key: &VerifyingKey, data: &[u8], signature: &Signature) -> Result<()> {
    use ed25519_dalek::Verifier;
    key.verify(data, signature)
        .map_err(|_| Error::InvalidSignature)
}

/// Generate a new signing keypair using cryptographically secure OS randomness
pub fn generate_keypair() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify() {
        let signing_key = generate_keypair();
        let verifying_key = signing_key.verifying_key();
        let data = b"test message";

        let signature = sign(&signing_key, data);
        verify(&verifying_key, data, &signature).unwrap();
    }

    #[test]
    fn test_keypair_generation_unique() {
        let key1 = generate_keypair();
        let key2 = generate_keypair();

        // Each keypair should be unique
        assert_ne!(key1.to_bytes(), key2.to_bytes());
    }

    #[test]
    fn test_sign_empty_data() {
        let signing_key = generate_keypair();
        let verifying_key = signing_key.verifying_key();
        let data = b"";

        let signature = sign(&signing_key, data);
        verify(&verifying_key, data, &signature).unwrap();
    }

    #[test]
    fn test_sign_large_data() {
        let signing_key = generate_keypair();
        let verifying_key = signing_key.verifying_key();
        let data = vec![0xABu8; 1024 * 1024]; // 1MB

        let signature = sign(&signing_key, &data);
        verify(&verifying_key, &data, &signature).unwrap();
    }

    #[test]
    fn test_verify_wrong_data_fails() {
        let signing_key = generate_keypair();
        let verifying_key = signing_key.verifying_key();
        let data = b"original message";
        let wrong_data = b"modified message";

        let signature = sign(&signing_key, data);
        let result = verify(&verifying_key, wrong_data, &signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_wrong_key_fails() {
        let signing_key1 = generate_keypair();
        let signing_key2 = generate_keypair();
        let verifying_key2 = signing_key2.verifying_key();
        let data = b"test message";

        // Sign with key1, verify with key2
        let signature = sign(&signing_key1, data);
        let result = verify(&verifying_key2, data, &signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_signature_deterministic() {
        let signing_key = generate_keypair();
        let data = b"test message";

        let sig1 = sign(&signing_key, data);
        let sig2 = sign(&signing_key, data);

        // Ed25519 signatures should be deterministic for the same key and data
        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn test_different_data_different_signatures() {
        let signing_key = generate_keypair();
        let data1 = b"message 1";
        let data2 = b"message 2";

        let sig1 = sign(&signing_key, data1);
        let sig2 = sign(&signing_key, data2);

        assert_ne!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn test_verifying_key_from_signing_key() {
        let signing_key = generate_keypair();
        let verifying_key = signing_key.verifying_key();

        // Verify the public key can verify signatures
        let data = b"test";
        let signature = sign(&signing_key, data);
        assert!(verify(&verifying_key, data, &signature).is_ok());
    }

    #[test]
    fn test_sign_binary_data() {
        let signing_key = generate_keypair();
        let verifying_key = signing_key.verifying_key();
        // Binary data with all byte values
        let data: Vec<u8> = (0..=255).collect();

        let signature = sign(&signing_key, &data);
        verify(&verifying_key, &data, &signature).unwrap();
    }
}
