//! Envelope encryption implementation
//!
//! Envelope encryption uses a two-tier key hierarchy:
//! 1. Master keys (stored in KMS) encrypt data keys
//! 2. Data keys encrypt the actual data
//!
//! This pattern allows efficient encryption of large data while keeping
//! master keys secure and enabling key rotation.

use std::sync::Arc;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::error::{KmsError, KmsResult};
use crate::key::KeyAlgorithm;
use crate::KmsProvider;

/// Encrypted data with envelope encryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    /// Encrypted data key (encrypted by master key)
    pub encrypted_data_key: Vec<u8>,

    /// Master key ID used to encrypt the data key
    pub master_key_id: String,

    /// Nonce used for data encryption
    pub nonce: Vec<u8>,

    /// The actual encrypted data
    pub ciphertext: Vec<u8>,

    /// Algorithm used for data encryption
    pub algorithm: KeyAlgorithm,
}

impl EncryptedData {
    /// Serialize to bytes for storage
    pub fn to_bytes(&self) -> KmsResult<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|e| KmsError::SerializationError(format!("Failed to serialize: {}", e)))
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> KmsResult<Self> {
        serde_json::from_slice(bytes)
            .map_err(|e| KmsError::SerializationError(format!("Failed to deserialize: {}", e)))
    }
}

/// Envelope encryption helper
///
/// Provides high-level envelope encryption operations using a KMS provider.
pub struct EnvelopeEncryption<K: KmsProvider> {
    kms: Arc<K>,
    algorithm: KeyAlgorithm,
}

impl<K: KmsProvider> EnvelopeEncryption<K> {
    /// Create a new envelope encryption helper
    pub fn new(kms: K) -> Self {
        Self {
            kms: Arc::new(kms),
            algorithm: KeyAlgorithm::Aes256Gcm,
        }
    }

    /// Create with a specific algorithm
    pub fn with_algorithm(kms: K, algorithm: KeyAlgorithm) -> Self {
        Self {
            kms: Arc::new(kms),
            algorithm,
        }
    }

    /// Create from an Arc'd KMS provider
    pub fn from_arc(kms: Arc<K>) -> Self {
        Self {
            kms,
            algorithm: KeyAlgorithm::Aes256Gcm,
        }
    }

    /// Get a reference to the KMS provider
    pub fn kms(&self) -> &K {
        &self.kms
    }

    /// Encrypt data using envelope encryption
    ///
    /// 1. Generate a data key using the master key
    /// 2. Encrypt the data with the data key
    /// 3. Return encrypted data + encrypted data key
    pub async fn encrypt(&self, key_id: &str, plaintext: &[u8]) -> KmsResult<EncryptedData> {
        // Generate a data key
        let data_key = self.kms.generate_data_key(key_id).await?;

        // Encrypt the data with the data key
        let (ciphertext, nonce) = self.encrypt_with_key(&data_key.plaintext, plaintext)?;

        Ok(EncryptedData {
            encrypted_data_key: data_key.ciphertext.clone(),
            master_key_id: key_id.to_string(),
            nonce,
            ciphertext,
            algorithm: self.algorithm,
        })
    }

    /// Decrypt envelope-encrypted data
    ///
    /// 1. Decrypt the data key using the master key
    /// 2. Decrypt the data with the data key
    pub async fn decrypt(&self, key_id: &str, encrypted: &EncryptedData) -> KmsResult<Vec<u8>> {
        // Decrypt the data key
        let data_key_plaintext = self
            .kms
            .decrypt_data_key(key_id, &encrypted.encrypted_data_key)
            .await?;

        // Decrypt the data
        self.decrypt_with_key(
            &data_key_plaintext,
            &encrypted.nonce,
            &encrypted.ciphertext,
            encrypted.algorithm,
        )
    }

    /// Encrypt data using a raw key
    fn encrypt_with_key(&self, key: &[u8], plaintext: &[u8]) -> KmsResult<(Vec<u8>, Vec<u8>)> {
        match self.algorithm {
            KeyAlgorithm::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| {
                    KmsError::InternalError(format!("Failed to create cipher: {}", e))
                })?;

                let mut nonce_bytes = [0u8; 12];
                rand::thread_rng().fill_bytes(&mut nonce_bytes);
                let nonce = Nonce::from_slice(&nonce_bytes);

                let ciphertext = cipher.encrypt(nonce, plaintext).map_err(|e| {
                    KmsError::EncryptionFailed(format!("Encryption failed: {}", e))
                })?;

                Ok((ciphertext, nonce_bytes.to_vec()))
            }
            KeyAlgorithm::ChaCha20Poly1305 => {
                use chacha20poly1305::ChaCha20Poly1305;

                let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|e| {
                    KmsError::InternalError(format!("Failed to create cipher: {}", e))
                })?;

                let mut nonce_bytes = [0u8; 12];
                rand::thread_rng().fill_bytes(&mut nonce_bytes);
                let nonce = Nonce::from_slice(&nonce_bytes);

                let ciphertext = cipher.encrypt(nonce, plaintext).map_err(|e| {
                    KmsError::EncryptionFailed(format!("Encryption failed: {}", e))
                })?;

                Ok((ciphertext, nonce_bytes.to_vec()))
            }
        }
    }

    /// Decrypt data using a raw key
    fn decrypt_with_key(
        &self,
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        algorithm: KeyAlgorithm,
    ) -> KmsResult<Vec<u8>> {
        if nonce.len() != 12 {
            return Err(KmsError::InvalidCiphertext(format!(
                "Invalid nonce length: {}",
                nonce.len()
            )));
        }

        let nonce = Nonce::from_slice(nonce);

        match algorithm {
            KeyAlgorithm::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| {
                    KmsError::InternalError(format!("Failed to create cipher: {}", e))
                })?;

                cipher.decrypt(nonce, ciphertext).map_err(|e| {
                    KmsError::DecryptionFailed(format!("Decryption failed: {}", e))
                })
            }
            KeyAlgorithm::ChaCha20Poly1305 => {
                use chacha20poly1305::ChaCha20Poly1305;

                let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|e| {
                    KmsError::InternalError(format!("Failed to create cipher: {}", e))
                })?;

                cipher.decrypt(nonce, ciphertext).map_err(|e| {
                    KmsError::DecryptionFailed(format!("Decryption failed: {}", e))
                })
            }
        }
    }
}

/// Streaming envelope encryption for large data
///
/// Encrypts data in chunks, each with its own nonce for additional security.
pub struct StreamingEnvelope<K: KmsProvider> {
    kms: Arc<K>,
    chunk_size: usize,
    algorithm: KeyAlgorithm,
}

impl<K: KmsProvider> StreamingEnvelope<K> {
    /// Create a new streaming envelope encryptor
    ///
    /// Default chunk size is 64KB.
    pub fn new(kms: K) -> Self {
        Self {
            kms: Arc::new(kms),
            chunk_size: 64 * 1024, // 64KB chunks
            algorithm: KeyAlgorithm::Aes256Gcm,
        }
    }

    /// Set the chunk size
    pub fn with_chunk_size(mut self, size: usize) -> Self {
        self.chunk_size = size;
        self
    }

    /// Encrypt data in chunks
    ///
    /// Returns a vector of encrypted chunks with metadata.
    pub async fn encrypt_chunked(
        &self,
        key_id: &str,
        plaintext: &[u8],
    ) -> KmsResult<ChunkedEncryptedData> {
        // Generate a single data key for all chunks
        let data_key = self.kms.generate_data_key(key_id).await?;

        let mut chunks = Vec::new();
        let mut chunk_index = 0u64;

        for chunk in plaintext.chunks(self.chunk_size) {
            let (ciphertext, nonce) = self.encrypt_chunk(&data_key.plaintext, chunk, chunk_index)?;
            chunks.push(EncryptedChunk {
                index: chunk_index,
                nonce,
                ciphertext,
            });
            chunk_index += 1;
        }

        Ok(ChunkedEncryptedData {
            encrypted_data_key: data_key.ciphertext.clone(),
            master_key_id: key_id.to_string(),
            algorithm: self.algorithm,
            chunk_size: self.chunk_size,
            total_chunks: chunks.len(),
            chunks,
        })
    }

    /// Decrypt chunked data
    pub async fn decrypt_chunked(
        &self,
        key_id: &str,
        encrypted: &ChunkedEncryptedData,
    ) -> KmsResult<Vec<u8>> {
        // Decrypt the data key
        let data_key_plaintext = self
            .kms
            .decrypt_data_key(key_id, &encrypted.encrypted_data_key)
            .await?;

        let mut plaintext = Vec::new();

        for chunk in &encrypted.chunks {
            let decrypted = self.decrypt_chunk(
                &data_key_plaintext,
                &chunk.nonce,
                &chunk.ciphertext,
                chunk.index,
                encrypted.algorithm,
            )?;
            plaintext.extend(decrypted);
        }

        Ok(plaintext)
    }

    /// Encrypt a single chunk with chunk-specific context
    fn encrypt_chunk(
        &self,
        key: &[u8],
        plaintext: &[u8],
        chunk_index: u64,
    ) -> KmsResult<(Vec<u8>, Vec<u8>)> {
        // Create nonce with chunk index for uniqueness
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes[..4]); // Random prefix
        nonce_bytes[4..12].copy_from_slice(&chunk_index.to_le_bytes()); // Chunk index

        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = match self.algorithm {
            KeyAlgorithm::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| {
                    KmsError::InternalError(format!("Failed to create cipher: {}", e))
                })?;

                cipher.encrypt(nonce, plaintext).map_err(|e| {
                    KmsError::EncryptionFailed(format!("Chunk encryption failed: {}", e))
                })?
            }
            KeyAlgorithm::ChaCha20Poly1305 => {
                use chacha20poly1305::ChaCha20Poly1305;

                let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|e| {
                    KmsError::InternalError(format!("Failed to create cipher: {}", e))
                })?;

                cipher.encrypt(nonce, plaintext).map_err(|e| {
                    KmsError::EncryptionFailed(format!("Chunk encryption failed: {}", e))
                })?
            }
        };

        Ok((ciphertext, nonce_bytes.to_vec()))
    }

    /// Decrypt a single chunk
    fn decrypt_chunk(
        &self,
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        expected_index: u64,
        algorithm: KeyAlgorithm,
    ) -> KmsResult<Vec<u8>> {
        // Verify chunk index in nonce
        if nonce.len() != 12 {
            return Err(KmsError::InvalidCiphertext("Invalid nonce length".to_string()));
        }

        let stored_index = u64::from_le_bytes(nonce[4..12].try_into().unwrap());
        if stored_index != expected_index {
            return Err(KmsError::InvalidCiphertext(format!(
                "Chunk index mismatch: expected {}, got {}",
                expected_index, stored_index
            )));
        }

        let nonce = Nonce::from_slice(nonce);

        match algorithm {
            KeyAlgorithm::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| {
                    KmsError::InternalError(format!("Failed to create cipher: {}", e))
                })?;

                cipher.decrypt(nonce, ciphertext).map_err(|e| {
                    KmsError::DecryptionFailed(format!("Chunk decryption failed: {}", e))
                })
            }
            KeyAlgorithm::ChaCha20Poly1305 => {
                use chacha20poly1305::ChaCha20Poly1305;

                let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|e| {
                    KmsError::InternalError(format!("Failed to create cipher: {}", e))
                })?;

                cipher.decrypt(nonce, ciphertext).map_err(|e| {
                    KmsError::DecryptionFailed(format!("Chunk decryption failed: {}", e))
                })
            }
        }
    }
}

/// A single encrypted chunk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedChunk {
    /// Chunk index (0-based)
    pub index: u64,

    /// Nonce for this chunk
    pub nonce: Vec<u8>,

    /// Encrypted chunk data
    pub ciphertext: Vec<u8>,
}

/// Chunked encrypted data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkedEncryptedData {
    /// Encrypted data key
    pub encrypted_data_key: Vec<u8>,

    /// Master key ID
    pub master_key_id: String,

    /// Algorithm used
    pub algorithm: KeyAlgorithm,

    /// Chunk size used
    pub chunk_size: usize,

    /// Total number of chunks
    pub total_chunks: usize,

    /// The encrypted chunks
    pub chunks: Vec<EncryptedChunk>,
}

impl ChunkedEncryptedData {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> KmsResult<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|e| KmsError::SerializationError(format!("Failed to serialize: {}", e)))
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> KmsResult<Self> {
        serde_json::from_slice(bytes)
            .map_err(|e| KmsError::SerializationError(format!("Failed to deserialize: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LocalKms;

    #[tokio::test]
    async fn test_envelope_encryption() {
        let kms = LocalKms::new().unwrap();
        let key_id = kms.create_key("envelope-test").await.unwrap();

        let envelope = EnvelopeEncryption::new(kms);

        let plaintext = b"Hello, Envelope Encryption!";
        let encrypted = envelope.encrypt(&key_id, plaintext).await.unwrap();

        assert!(!encrypted.ciphertext.is_empty());
        assert!(!encrypted.encrypted_data_key.is_empty());

        let decrypted = envelope.decrypt(&key_id, &encrypted).await.unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_encrypted_data_serialization() {
        let kms = LocalKms::new().unwrap();
        let key_id = kms.create_key("serialize-test").await.unwrap();

        let envelope = EnvelopeEncryption::new(kms);

        let plaintext = b"Serialize me!";
        let encrypted = envelope.encrypt(&key_id, plaintext).await.unwrap();

        // Serialize
        let bytes = encrypted.to_bytes().unwrap();

        // Deserialize
        let restored = EncryptedData::from_bytes(&bytes).unwrap();

        assert_eq!(restored.master_key_id, encrypted.master_key_id);
        assert_eq!(restored.ciphertext, encrypted.ciphertext);
    }

    #[tokio::test]
    async fn test_streaming_envelope() {
        let kms = LocalKms::new().unwrap();
        let key_id = kms.create_key("streaming-test").await.unwrap();

        let streaming = StreamingEnvelope::new(kms).with_chunk_size(16); // Small chunks for testing

        let plaintext = b"This is a longer message that will be split into multiple chunks for encryption.";
        let encrypted = streaming.encrypt_chunked(&key_id, plaintext).await.unwrap();

        assert!(encrypted.total_chunks > 1);
        assert_eq!(encrypted.chunks.len(), encrypted.total_chunks);

        let decrypted = streaming.decrypt_chunked(&key_id, &encrypted).await.unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_chunked_data_serialization() {
        let kms = LocalKms::new().unwrap();
        let key_id = kms.create_key("chunked-serialize-test").await.unwrap();

        let streaming = StreamingEnvelope::new(kms).with_chunk_size(32);

        let plaintext = b"Chunked data for serialization testing purposes.";
        let encrypted = streaming.encrypt_chunked(&key_id, plaintext).await.unwrap();

        // Serialize
        let bytes = encrypted.to_bytes().unwrap();

        // Deserialize
        let restored = ChunkedEncryptedData::from_bytes(&bytes).unwrap();

        assert_eq!(restored.total_chunks, encrypted.total_chunks);
        assert_eq!(restored.chunks.len(), encrypted.chunks.len());
    }
}
