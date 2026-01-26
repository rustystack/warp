//! # warp-kms: Key Management Service
//!
//! Provides key management and envelope encryption for warp storage.
//!
//! ## Features
//!
//! - **Local KMS**: In-memory key management with secure key derivation
//! - **AWS KMS** (optional): Integration with AWS Key Management Service
//! - **Envelope Encryption**: Data keys encrypted by master keys
//! - **Key Rotation**: Automatic key versioning and rotation
//!
//! ## Example
//!
//! ```ignore
//! use warp_kms::{LocalKms, KmsProvider};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let kms = LocalKms::new()?;
//!
//!     // Create a master key
//!     let key_id = kms.create_key("my-key").await?;
//!
//!     // Generate a data key for encryption
//!     let data_key = kms.generate_data_key(&key_id).await?;
//!
//!     // Use data_key.plaintext for encryption
//!     // Store data_key.ciphertext with the encrypted data
//!
//!     Ok(())
//! }
//! ```

#![warn(missing_docs)]
#![allow(clippy::explicit_counter_loop)]
#![allow(clippy::collapsible_if)]

mod envelope;
mod error;
mod key;
mod local;
mod aws;

pub use envelope::{
    ChunkedEncryptedData, EncryptedChunk, EncryptedData, EnvelopeEncryption, StreamingEnvelope,
};
pub use error::{KmsError, KmsResult};
pub use key::{
    DataKey, KeyAlgorithm, KeyMetadata, KeyOrigin, KeyState, KeyUsage, KeyVersion, MasterKey,
};
pub use local::LocalKms;
pub use aws::{AwsKms, AwsKmsConfig};

use async_trait::async_trait;

/// Key Management Service provider trait
///
/// Implement this trait to provide key management functionality.
#[async_trait]
pub trait KmsProvider: Send + Sync {
    /// Create a new master key
    ///
    /// Returns the key ID for the newly created key.
    async fn create_key(&self, alias: &str) -> KmsResult<String>;

    /// Generate a data key for encryption
    ///
    /// Returns a data key with both plaintext and ciphertext versions.
    /// The plaintext is used for encryption, and the ciphertext is stored
    /// alongside the encrypted data.
    async fn generate_data_key(&self, key_id: &str) -> KmsResult<DataKey>;

    /// Decrypt a data key ciphertext
    ///
    /// Returns the plaintext data key that can be used for decryption.
    async fn decrypt_data_key(&self, key_id: &str, ciphertext: &[u8]) -> KmsResult<Vec<u8>>;

    /// Encrypt data directly with a master key
    ///
    /// For small data (< 4KB), you can encrypt directly with the master key.
    async fn encrypt(&self, key_id: &str, plaintext: &[u8]) -> KmsResult<Vec<u8>>;

    /// Decrypt data directly with a master key
    async fn decrypt(&self, key_id: &str, ciphertext: &[u8]) -> KmsResult<Vec<u8>>;

    /// Rotate a key to a new version
    ///
    /// Creates a new key version while keeping the old version for decryption.
    async fn rotate_key(&self, key_id: &str) -> KmsResult<String>;

    /// Get key metadata
    async fn get_key_metadata(&self, key_id: &str) -> KmsResult<KeyMetadata>;

    /// List all keys
    async fn list_keys(&self) -> KmsResult<Vec<String>>;

    /// Delete a key (soft delete - marks as pending deletion)
    async fn schedule_key_deletion(&self, key_id: &str) -> KmsResult<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_local_kms_basic() {
        let kms = LocalKms::new().unwrap();

        // Create a key
        let key_id = kms.create_key("test-key").await.unwrap();
        assert!(!key_id.is_empty());

        // Generate a data key
        let data_key = kms.generate_data_key(&key_id).await.unwrap();
        assert_eq!(data_key.plaintext.len(), 32);
        assert!(!data_key.ciphertext.is_empty());

        // Decrypt the data key
        let decrypted = kms
            .decrypt_data_key(&key_id, &data_key.ciphertext)
            .await
            .unwrap();
        assert_eq!(decrypted, data_key.plaintext);
    }

    #[tokio::test]
    async fn test_local_kms_encrypt_decrypt() {
        let kms = LocalKms::new().unwrap();
        let key_id = kms.create_key("encrypt-test").await.unwrap();

        let plaintext = b"Hello, KMS!";
        let ciphertext = kms.encrypt(&key_id, plaintext).await.unwrap();
        let decrypted = kms.decrypt(&key_id, &ciphertext).await.unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_local_kms_key_rotation() {
        let kms = LocalKms::new().unwrap();
        let key_id = kms.create_key("rotate-test").await.unwrap();

        // Encrypt with original key
        let plaintext = b"Rotate me!";
        let ciphertext = kms.encrypt(&key_id, plaintext).await.unwrap();

        // Rotate the key
        let new_version = kms.rotate_key(&key_id).await.unwrap();
        assert!(!new_version.is_empty());

        // Should still be able to decrypt old data
        let decrypted = kms.decrypt(&key_id, &ciphertext).await.unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_envelope_encryption() {
        let kms = LocalKms::new().unwrap();
        let key_id = kms.create_key("envelope-test").await.unwrap();

        let envelope = EnvelopeEncryption::new(kms);

        let plaintext = b"Large data to encrypt with envelope encryption";
        let encrypted = envelope.encrypt(&key_id, plaintext).await.unwrap();
        let decrypted = envelope.decrypt(&key_id, &encrypted).await.unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
