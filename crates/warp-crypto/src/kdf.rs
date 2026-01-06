//! Key derivation using Argon2id

use argon2::{Argon2, password_hash::SaltString};
use rand::rngs::OsRng;
use zeroize::Zeroize;

use crate::{Error, Result};

/// Derived key (32 bytes)
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct DerivedKey([u8; 32]);

impl DerivedKey {
    /// Get bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Derive a key from a password using Argon2id
pub fn derive_key(password: &[u8], salt: &[u8]) -> Result<DerivedKey> {
    let mut output = [0u8; 32];

    Argon2::default()
        .hash_password_into(password, salt, &mut output)
        .map_err(|e| Error::InvalidKey(e.to_string()))?;

    Ok(DerivedKey(output))
}

/// Generate a random salt
pub fn generate_salt() -> [u8; 16] {
    let salt = SaltString::generate(&mut OsRng);
    let mut output = [0u8; 16];
    output.copy_from_slice(&salt.as_str().as_bytes()[..16]);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive() {
        let password = b"test password";
        let salt = generate_salt();

        let key1 = derive_key(password, &salt).unwrap();
        let key2 = derive_key(password, &salt).unwrap();

        assert_eq!(key1.0, key2.0);
    }

    #[test]
    fn test_different_passwords_different_keys() {
        let salt = generate_salt();
        let key1 = derive_key(b"password1", &salt).unwrap();
        let key2 = derive_key(b"password2", &salt).unwrap();

        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_different_salts_different_keys() {
        let password = b"same password";
        let salt1 = generate_salt();
        let salt2 = generate_salt();

        let key1 = derive_key(password, &salt1).unwrap();
        let key2 = derive_key(password, &salt2).unwrap();

        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_empty_password() {
        let salt = generate_salt();
        let key = derive_key(b"", &salt).unwrap();

        // Should succeed and produce 32 bytes
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn test_long_password() {
        let salt = generate_salt();
        let long_password = vec![b'a'; 1024];
        let key = derive_key(&long_password, &salt).unwrap();

        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn test_key_length() {
        let password = b"test";
        let salt = generate_salt();
        let key = derive_key(password, &salt).unwrap();

        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn test_salt_generation_unique() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();

        assert_ne!(salt1, salt2);
    }

    #[test]
    fn test_salt_length() {
        let salt = generate_salt();
        assert_eq!(salt.len(), 16);
    }

    #[test]
    fn test_derivation_deterministic() {
        let password = b"fixed password";
        let salt = [1u8; 16]; // Fixed salt for determinism test

        let key1 = derive_key(password, &salt).unwrap();
        let key2 = derive_key(password, &salt).unwrap();

        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_binary_password() {
        let salt = generate_salt();
        // Password with all byte values
        let password: Vec<u8> = (0..=255).collect();
        let key = derive_key(&password, &salt).unwrap();

        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn test_unicode_password() {
        let salt = generate_salt();
        let password = "密码测试🔒".as_bytes();
        let key = derive_key(password, &salt).unwrap();

        assert_eq!(key.as_bytes().len(), 32);
    }
}
