//! Local KMS implementation
//!
//! Provides in-memory key management with secure key derivation and storage.
//! Suitable for development, testing, and single-node deployments.

use std::collections::HashMap;
use std::sync::RwLock;

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use async_trait::async_trait;
use chrono::Utc;
use rand::RngCore;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::KmsProvider;
use crate::error::{KmsError, KmsResult};
use crate::key::{DataKey, KeyAlgorithm, KeyMetadata, KeyState, MasterKey};

/// Local KMS implementation
///
/// Stores keys in memory with secure handling.
/// Keys are encrypted with a root key derived from a master secret.
pub struct LocalKms {
    /// Root encryption key (encrypts master keys)
    root_key: Vec<u8>,

    /// Stored master keys (key_id -> encrypted key material for each version)
    keys: RwLock<HashMap<String, Vec<EncryptedMasterKey>>>,

    /// Key metadata
    metadata: RwLock<HashMap<String, KeyMetadata>>,

    /// Alias to key ID mapping
    aliases: RwLock<HashMap<String, String>>,

    /// Default algorithm for new keys
    default_algorithm: KeyAlgorithm,
}

/// Encrypted master key storage
#[derive(Clone)]
struct EncryptedMasterKey {
    version: u32,
    ciphertext: Vec<u8>,
    nonce: [u8; 12],
}

impl LocalKms {
    /// Create a new LocalKms with a random root key
    pub fn new() -> KmsResult<Self> {
        let mut root_key = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut root_key);

        Ok(Self {
            root_key,
            keys: RwLock::new(HashMap::new()),
            metadata: RwLock::new(HashMap::new()),
            aliases: RwLock::new(HashMap::new()),
            default_algorithm: KeyAlgorithm::Aes256Gcm,
        })
    }

    /// Create a new LocalKms with a specific root key
    ///
    /// The root key should be 32 bytes for AES-256.
    pub fn with_root_key(root_key: Vec<u8>) -> KmsResult<Self> {
        if root_key.len() != 32 {
            return Err(KmsError::ConfigurationError(
                "Root key must be 32 bytes".to_string(),
            ));
        }

        Ok(Self {
            root_key,
            keys: RwLock::new(HashMap::new()),
            metadata: RwLock::new(HashMap::new()),
            aliases: RwLock::new(HashMap::new()),
            default_algorithm: KeyAlgorithm::Aes256Gcm,
        })
    }

    /// Create from a passphrase using PBKDF2-like derivation
    pub fn from_passphrase(passphrase: &str) -> KmsResult<Self> {
        // Simple key derivation (in production, use proper PBKDF2 or Argon2)
        let mut hasher = Sha256::new();
        hasher.update(passphrase.as_bytes());
        hasher.update(b"warp-kms-root-key-derivation");
        let root_key = hasher.finalize().to_vec();

        Self::with_root_key(root_key)
    }

    /// Set the default algorithm for new keys
    pub fn set_default_algorithm(&mut self, algorithm: KeyAlgorithm) {
        self.default_algorithm = algorithm;
    }

    /// Encrypt key material with the root key
    fn encrypt_key_material(&self, plaintext: &[u8]) -> KmsResult<(Vec<u8>, [u8; 12])> {
        let cipher = Aes256Gcm::new_from_slice(&self.root_key)
            .map_err(|e| KmsError::InternalError(format!("Failed to create cipher: {}", e)))?;

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| KmsError::EncryptionFailed(format!("Failed to encrypt key: {}", e)))?;

        Ok((ciphertext, nonce_bytes))
    }

    /// Decrypt key material with the root key
    fn decrypt_key_material(&self, ciphertext: &[u8], nonce: &[u8; 12]) -> KmsResult<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(&self.root_key)
            .map_err(|e| KmsError::InternalError(format!("Failed to create cipher: {}", e)))?;

        let nonce = Nonce::from_slice(nonce);

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| KmsError::DecryptionFailed(format!("Failed to decrypt key: {}", e)))
    }

    /// Get the current (primary) master key for a key ID
    fn get_current_master_key(&self, key_id: &str) -> KmsResult<MasterKey> {
        let metadata = self.metadata.read().unwrap();
        let meta = metadata
            .get(key_id)
            .ok_or_else(|| KmsError::KeyNotFound(key_id.to_string()))?;

        if !meta.is_usable() {
            match meta.state {
                KeyState::Disabled => return Err(KmsError::KeyDisabled(key_id.to_string())),
                KeyState::PendingDeletion => {
                    return Err(KmsError::KeyPendingDeletion(key_id.to_string()));
                }
                _ => return Err(KmsError::InvalidKeyState(format!("{:?}", meta.state))),
            }
        }

        let algorithm = meta.algorithm;
        let version = meta.version;
        drop(metadata);

        let keys = self.keys.read().unwrap();
        let versions = keys
            .get(key_id)
            .ok_or_else(|| KmsError::KeyNotFound(key_id.to_string()))?;

        let encrypted = versions
            .iter()
            .find(|k| k.version == version)
            .ok_or_else(|| KmsError::KeyVersionNotFound(format!("{}:v{}", key_id, version)))?;

        let material = self.decrypt_key_material(&encrypted.ciphertext, &encrypted.nonce)?;

        Ok(MasterKey::new(
            key_id.to_string(),
            version,
            material,
            algorithm,
        ))
    }

    /// Get a specific version of a master key
    fn get_master_key_version(&self, key_id: &str, version: u32) -> KmsResult<MasterKey> {
        let metadata = self.metadata.read().unwrap();
        let meta = metadata
            .get(key_id)
            .ok_or_else(|| KmsError::KeyNotFound(key_id.to_string()))?;

        let algorithm = meta.algorithm;
        drop(metadata);

        let keys = self.keys.read().unwrap();
        let versions = keys
            .get(key_id)
            .ok_or_else(|| KmsError::KeyNotFound(key_id.to_string()))?;

        let encrypted = versions
            .iter()
            .find(|k| k.version == version)
            .ok_or_else(|| KmsError::KeyVersionNotFound(format!("{}:v{}", key_id, version)))?;

        let material = self.decrypt_key_material(&encrypted.ciphertext, &encrypted.nonce)?;

        Ok(MasterKey::new(
            key_id.to_string(),
            version,
            material,
            algorithm,
        ))
    }

    /// Encrypt data using a cipher based on algorithm
    fn encrypt_with_algorithm(
        &self,
        algorithm: KeyAlgorithm,
        key: &[u8],
        plaintext: &[u8],
    ) -> KmsResult<Vec<u8>> {
        match algorithm {
            KeyAlgorithm::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| {
                    KmsError::InternalError(format!("Failed to create cipher: {}", e))
                })?;

                let mut nonce_bytes = [0u8; 12];
                rand::thread_rng().fill_bytes(&mut nonce_bytes);
                let nonce = Nonce::from_slice(&nonce_bytes);

                let ciphertext = cipher.encrypt(nonce, plaintext).map_err(|e| {
                    KmsError::EncryptionFailed(format!("AES-GCM encryption failed: {}", e))
                })?;

                // Prepend nonce to ciphertext
                let mut result = nonce_bytes.to_vec();
                result.extend(ciphertext);
                Ok(result)
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
                    KmsError::EncryptionFailed(format!(
                        "ChaCha20-Poly1305 encryption failed: {}",
                        e
                    ))
                })?;

                // Prepend nonce to ciphertext
                let mut result = nonce_bytes.to_vec();
                result.extend(ciphertext);
                Ok(result)
            }
        }
    }

    /// Decrypt data using a cipher based on algorithm
    fn decrypt_with_algorithm(
        &self,
        algorithm: KeyAlgorithm,
        key: &[u8],
        ciphertext: &[u8],
    ) -> KmsResult<Vec<u8>> {
        if ciphertext.len() < 12 {
            return Err(KmsError::InvalidCiphertext(
                "Ciphertext too short".to_string(),
            ));
        }

        let (nonce_bytes, actual_ciphertext) = ciphertext.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        match algorithm {
            KeyAlgorithm::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| {
                    KmsError::InternalError(format!("Failed to create cipher: {}", e))
                })?;

                cipher.decrypt(nonce, actual_ciphertext).map_err(|e| {
                    KmsError::DecryptionFailed(format!("AES-GCM decryption failed: {}", e))
                })
            }
            KeyAlgorithm::ChaCha20Poly1305 => {
                use chacha20poly1305::ChaCha20Poly1305;

                let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|e| {
                    KmsError::InternalError(format!("Failed to create cipher: {}", e))
                })?;

                cipher.decrypt(nonce, actual_ciphertext).map_err(|e| {
                    KmsError::DecryptionFailed(format!(
                        "ChaCha20-Poly1305 decryption failed: {}",
                        e
                    ))
                })
            }
        }
    }
}

#[async_trait]
impl KmsProvider for LocalKms {
    async fn create_key(&self, alias: &str) -> KmsResult<String> {
        // Check if alias already exists
        {
            let aliases = self.aliases.read().unwrap();
            if aliases.contains_key(alias) {
                return Err(KmsError::AliasAlreadyExists(alias.to_string()));
            }
        }

        // Generate key ID and material
        let key_id = Uuid::new_v4().to_string();
        let mut key_material = vec![0u8; self.default_algorithm.key_size()];
        rand::thread_rng().fill_bytes(&mut key_material);

        // Encrypt the key material
        let (ciphertext, nonce) = self.encrypt_key_material(&key_material)?;

        // Store encrypted key
        let encrypted = EncryptedMasterKey {
            version: 1,
            ciphertext,
            nonce,
        };

        {
            let mut keys = self.keys.write().unwrap();
            keys.insert(key_id.clone(), vec![encrypted]);
        }

        // Store metadata
        let metadata = KeyMetadata::new(key_id.clone(), alias.to_string(), self.default_algorithm);
        {
            let mut meta_store = self.metadata.write().unwrap();
            meta_store.insert(key_id.clone(), metadata);
        }

        // Store alias mapping
        {
            let mut aliases = self.aliases.write().unwrap();
            aliases.insert(alias.to_string(), key_id.clone());
        }

        info!(key_id = %key_id, alias = %alias, "Created new master key");
        Ok(key_id)
    }

    async fn generate_data_key(&self, key_id: &str) -> KmsResult<DataKey> {
        let master_key = self.get_current_master_key(key_id)?;

        // Generate random data key
        let mut plaintext = vec![0u8; master_key.algorithm.key_size()];
        rand::thread_rng().fill_bytes(&mut plaintext);

        // Encrypt data key with master key
        let ciphertext =
            self.encrypt_with_algorithm(master_key.algorithm, &master_key.material, &plaintext)?;

        debug!(
            key_id = %key_id,
            version = %master_key.version,
            "Generated data key"
        );

        Ok(DataKey::new(
            plaintext,
            ciphertext,
            master_key.algorithm,
            key_id.to_string(),
            master_key.version,
        ))
    }

    async fn decrypt_data_key(&self, key_id: &str, ciphertext: &[u8]) -> KmsResult<Vec<u8>> {
        // Try current version first
        let master_key = self.get_current_master_key(key_id)?;

        match self.decrypt_with_algorithm(master_key.algorithm, &master_key.material, ciphertext) {
            Ok(plaintext) => {
                debug!(key_id = %key_id, version = %master_key.version, "Decrypted data key");
                return Ok(plaintext);
            }
            Err(_) => {
                // Try older versions (for rotated keys)
                let keys = self.keys.read().unwrap();
                if let Some(versions) = keys.get(key_id) {
                    for encrypted in versions.iter().rev() {
                        if encrypted.version == master_key.version {
                            continue; // Already tried
                        }

                        if let Ok(old_master) =
                            self.get_master_key_version(key_id, encrypted.version)
                            && let Ok(plaintext) = self.decrypt_with_algorithm(
                                old_master.algorithm,
                                &old_master.material,
                                ciphertext,
                            )
                        {
                            debug!(
                                key_id = %key_id,
                                version = %encrypted.version,
                                "Decrypted data key with older version"
                            );
                            return Ok(plaintext);
                        }
                    }
                }
            }
        }

        Err(KmsError::DecryptionFailed(
            "Failed to decrypt with any key version".to_string(),
        ))
    }

    async fn encrypt(&self, key_id: &str, plaintext: &[u8]) -> KmsResult<Vec<u8>> {
        let master_key = self.get_current_master_key(key_id)?;

        // Prepend version for decryption routing
        let mut result = Vec::with_capacity(4 + plaintext.len() + 28); // version + nonce + ciphertext + tag
        result.extend(&master_key.version.to_le_bytes());

        let ciphertext =
            self.encrypt_with_algorithm(master_key.algorithm, &master_key.material, plaintext)?;
        result.extend(ciphertext);

        debug!(
            key_id = %key_id,
            version = %master_key.version,
            plaintext_len = %plaintext.len(),
            "Encrypted data"
        );

        Ok(result)
    }

    async fn decrypt(&self, key_id: &str, ciphertext: &[u8]) -> KmsResult<Vec<u8>> {
        if ciphertext.len() < 4 {
            return Err(KmsError::InvalidCiphertext(
                "Ciphertext too short".to_string(),
            ));
        }

        // Extract version
        let version_bytes: [u8; 4] = ciphertext[..4].try_into().unwrap();
        let version = u32::from_le_bytes(version_bytes);
        let actual_ciphertext = &ciphertext[4..];

        // Get the specific key version
        let master_key = self.get_master_key_version(key_id, version)?;

        let plaintext = self.decrypt_with_algorithm(
            master_key.algorithm,
            &master_key.material,
            actual_ciphertext,
        )?;

        debug!(
            key_id = %key_id,
            version = %version,
            plaintext_len = %plaintext.len(),
            "Decrypted data"
        );

        Ok(plaintext)
    }

    async fn rotate_key(&self, key_id: &str) -> KmsResult<String> {
        // Get current metadata
        let (new_version, algorithm) = {
            let mut metadata = self.metadata.write().unwrap();
            let meta = metadata
                .get_mut(key_id)
                .ok_or_else(|| KmsError::KeyNotFound(key_id.to_string()))?;

            if !meta.is_usable() {
                return Err(KmsError::InvalidKeyState(format!("{:?}", meta.state)));
            }

            meta.version += 1;
            meta.last_rotated_at = Some(Utc::now());

            (meta.version, meta.algorithm)
        };

        // Generate new key material
        let mut key_material = vec![0u8; algorithm.key_size()];
        rand::thread_rng().fill_bytes(&mut key_material);

        // Encrypt the new key material
        let (ciphertext, nonce) = self.encrypt_key_material(&key_material)?;

        let encrypted = EncryptedMasterKey {
            version: new_version,
            ciphertext,
            nonce,
        };

        // Add new version
        {
            let mut keys = self.keys.write().unwrap();
            if let Some(versions) = keys.get_mut(key_id) {
                versions.push(encrypted);
            }
        }

        let version_str = format!("{}:v{}", key_id, new_version);
        info!(key_id = %key_id, version = %new_version, "Rotated key");

        Ok(version_str)
    }

    async fn get_key_metadata(&self, key_id: &str) -> KmsResult<KeyMetadata> {
        let metadata = self.metadata.read().unwrap();
        metadata
            .get(key_id)
            .cloned()
            .ok_or_else(|| KmsError::KeyNotFound(key_id.to_string()))
    }

    async fn list_keys(&self) -> KmsResult<Vec<String>> {
        let metadata = self.metadata.read().unwrap();
        Ok(metadata.keys().cloned().collect())
    }

    async fn schedule_key_deletion(&self, key_id: &str) -> KmsResult<()> {
        let mut metadata = self.metadata.write().unwrap();
        let meta = metadata
            .get_mut(key_id)
            .ok_or_else(|| KmsError::KeyNotFound(key_id.to_string()))?;

        if meta.state == KeyState::PendingDeletion {
            return Err(KmsError::KeyPendingDeletion(key_id.to_string()));
        }

        meta.state = KeyState::PendingDeletion;
        meta.deletion_date = Some(Utc::now() + chrono::Duration::days(7));

        warn!(key_id = %key_id, "Key scheduled for deletion");
        Ok(())
    }
}

impl Default for LocalKms {
    fn default() -> Self {
        Self::new().expect("Failed to create default LocalKms")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_key() {
        let kms = LocalKms::new().unwrap();
        let key_id = kms.create_key("test-key").await.unwrap();
        assert!(!key_id.is_empty());

        // Should fail for duplicate alias
        let result = kms.create_key("test-key").await;
        assert!(matches!(result, Err(KmsError::AliasAlreadyExists(_))));
    }

    #[tokio::test]
    async fn test_generate_data_key() {
        let kms = LocalKms::new().unwrap();
        let key_id = kms.create_key("data-key-test").await.unwrap();

        let data_key = kms.generate_data_key(&key_id).await.unwrap();
        assert_eq!(data_key.plaintext.len(), 32);
        assert!(!data_key.ciphertext.is_empty());
    }

    #[tokio::test]
    async fn test_decrypt_data_key() {
        let kms = LocalKms::new().unwrap();
        let key_id = kms.create_key("decrypt-test").await.unwrap();

        let data_key = kms.generate_data_key(&key_id).await.unwrap();
        let decrypted = kms
            .decrypt_data_key(&key_id, &data_key.ciphertext)
            .await
            .unwrap();

        assert_eq!(decrypted, data_key.plaintext);
    }

    #[tokio::test]
    async fn test_encrypt_decrypt() {
        let kms = LocalKms::new().unwrap();
        let key_id = kms.create_key("encrypt-test").await.unwrap();

        let plaintext = b"Hello, KMS!";
        let ciphertext = kms.encrypt(&key_id, plaintext).await.unwrap();
        let decrypted = kms.decrypt(&key_id, &ciphertext).await.unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_key_rotation() {
        let kms = LocalKms::new().unwrap();
        let key_id = kms.create_key("rotate-test").await.unwrap();

        // Encrypt with original key
        let plaintext = b"Rotate me!";
        let ciphertext = kms.encrypt(&key_id, plaintext).await.unwrap();

        // Rotate the key
        let new_version = kms.rotate_key(&key_id).await.unwrap();
        assert!(new_version.contains(":v2"));

        // Should still decrypt old data
        let decrypted = kms.decrypt(&key_id, &ciphertext).await.unwrap();
        assert_eq!(decrypted, plaintext);

        // New encryptions use new version
        let new_ciphertext = kms.encrypt(&key_id, plaintext).await.unwrap();
        assert_ne!(ciphertext, new_ciphertext);
    }

    #[tokio::test]
    async fn test_key_metadata() {
        let kms = LocalKms::new().unwrap();
        let key_id = kms.create_key("meta-test").await.unwrap();

        let meta = kms.get_key_metadata(&key_id).await.unwrap();
        assert_eq!(meta.alias, "meta-test");
        assert_eq!(meta.version, 1);
        assert_eq!(meta.state, KeyState::Enabled);
    }

    #[tokio::test]
    async fn test_schedule_deletion() {
        let kms = LocalKms::new().unwrap();
        let key_id = kms.create_key("delete-test").await.unwrap();

        kms.schedule_key_deletion(&key_id).await.unwrap();

        let meta = kms.get_key_metadata(&key_id).await.unwrap();
        assert_eq!(meta.state, KeyState::PendingDeletion);

        // Should fail to use key
        let result = kms.encrypt(&key_id, b"test").await;
        assert!(matches!(result, Err(KmsError::KeyPendingDeletion(_))));
    }
}
