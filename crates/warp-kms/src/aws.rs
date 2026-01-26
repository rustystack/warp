//! AWS KMS integration
//!
//! Provides envelope encryption using AWS Key Management Service.

use crate::{DataKey, KeyMetadata, KmsError, KmsResult};
#[cfg(feature = "aws")]
use crate::{KeyAlgorithm, KeyOrigin, KeyState, KeyUsage};
use async_trait::async_trait;

/// AWS KMS provider configuration
#[derive(Debug, Clone)]
pub struct AwsKmsConfig {
    /// AWS region
    pub region: String,
    /// Optional endpoint override (for LocalStack or VPC endpoints)
    pub endpoint: Option<String>,
}

impl Default for AwsKmsConfig {
    fn default() -> Self {
        Self {
            region: "us-east-1".to_string(),
            endpoint: None,
        }
    }
}

impl AwsKmsConfig {
    /// Create a new AWS KMS config with the specified region
    pub fn new(region: impl Into<String>) -> Self {
        Self {
            region: region.into(),
            endpoint: None,
        }
    }

    /// Set a custom endpoint (for LocalStack or VPC endpoints)
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }
}

/// AWS KMS provider
#[cfg(feature = "aws")]
pub struct AwsKms {
    config: AwsKmsConfig,
    client: aws_sdk_kms::Client,
}

#[cfg(feature = "aws")]
impl AwsKms {
    /// Get the provider configuration
    pub fn config(&self) -> &AwsKmsConfig {
        &self.config
    }
}

#[cfg(feature = "aws")]
impl AwsKms {
    /// Create a new AWS KMS provider
    pub async fn new(config: AwsKmsConfig) -> KmsResult<Self> {
        use aws_config::BehaviorVersion;

        let mut aws_config = aws_config::defaults(BehaviorVersion::latest())
            .region(aws_config::Region::new(config.region.clone()));

        if let Some(ref endpoint) = config.endpoint {
            aws_config = aws_config.endpoint_url(endpoint);
        }

        let sdk_config = aws_config.load().await;
        let client = aws_sdk_kms::Client::new(&sdk_config);

        Ok(Self { config, client })
    }

    /// Create with custom AWS SDK config
    pub fn with_sdk_config(config: AwsKmsConfig, sdk_config: &aws_config::SdkConfig) -> Self {
        Self {
            config,
            client: aws_sdk_kms::Client::new(sdk_config),
        }
    }

    /// Get the underlying AWS KMS client for advanced operations
    pub fn client(&self) -> &aws_sdk_kms::Client {
        &self.client
    }

    /// Health check - verify AWS KMS is accessible
    pub async fn health_check(&self) -> KmsResult<bool> {
        // Try to list keys with limit 1 to verify connectivity
        self.client
            .list_keys()
            .limit(1)
            .send()
            .await
            .map_err(|e| KmsError::AwsKmsError(format!("Health check failed: {}", e)))?;
        Ok(true)
    }
}

#[cfg(feature = "aws")]
#[async_trait]
impl crate::KmsProvider for AwsKms {
    async fn create_key(&self, alias: &str) -> KmsResult<String> {
        let result = self
            .client
            .create_key()
            .description(format!("WARP encryption key: {}", alias))
            .key_usage(aws_sdk_kms::types::KeyUsageType::EncryptDecrypt)
            .key_spec(aws_sdk_kms::types::KeySpec::SymmetricDefault)
            .send()
            .await
            .map_err(|e| KmsError::AwsKmsError(format!("CreateKey failed: {}", e)))?;

        let key_metadata = result
            .key_metadata()
            .ok_or_else(|| KmsError::AwsKmsError("No key metadata returned".to_string()))?;

        let key_id = key_metadata
            .key_id()
            .to_string();

        // Create alias for the key
        let alias_name = format!("alias/{}", alias);
        self.client
            .create_alias()
            .alias_name(&alias_name)
            .target_key_id(&key_id)
            .send()
            .await
            .map_err(|e| KmsError::AwsKmsError(format!("CreateAlias failed: {}", e)))?;

        Ok(key_id)
    }

    async fn generate_data_key(&self, key_id: &str) -> KmsResult<DataKey> {
        let result = self
            .client
            .generate_data_key()
            .key_id(key_id)
            .key_spec(aws_sdk_kms::types::DataKeySpec::Aes256)
            .send()
            .await
            .map_err(|e| KmsError::AwsKmsError(format!("GenerateDataKey failed: {}", e)))?;

        let plaintext = result
            .plaintext()
            .ok_or_else(|| KmsError::AwsKmsError("No plaintext returned".to_string()))?
            .as_ref()
            .to_vec();

        let ciphertext = result
            .ciphertext_blob()
            .ok_or_else(|| KmsError::AwsKmsError("No ciphertext returned".to_string()))?
            .as_ref()
            .to_vec();

        Ok(DataKey::new(
            plaintext,
            ciphertext,
            KeyAlgorithm::Aes256Gcm,
            key_id.to_string(),
            1, // AWS KMS handles versioning internally
        ))
    }

    async fn decrypt_data_key(&self, key_id: &str, ciphertext: &[u8]) -> KmsResult<Vec<u8>> {
        let result = self
            .client
            .decrypt()
            .key_id(key_id)
            .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(ciphertext))
            .send()
            .await
            .map_err(|e| KmsError::AwsKmsError(format!("Decrypt failed: {}", e)))?;

        let plaintext = result
            .plaintext()
            .ok_or_else(|| KmsError::AwsKmsError("No plaintext returned".to_string()))?
            .as_ref()
            .to_vec();

        Ok(plaintext)
    }

    async fn encrypt(&self, key_id: &str, plaintext: &[u8]) -> KmsResult<Vec<u8>> {
        let result = self
            .client
            .encrypt()
            .key_id(key_id)
            .plaintext(aws_sdk_kms::primitives::Blob::new(plaintext))
            .send()
            .await
            .map_err(|e| KmsError::AwsKmsError(format!("Encrypt failed: {}", e)))?;

        let ciphertext = result
            .ciphertext_blob()
            .ok_or_else(|| KmsError::AwsKmsError("No ciphertext returned".to_string()))?
            .as_ref()
            .to_vec();

        Ok(ciphertext)
    }

    async fn decrypt(&self, key_id: &str, ciphertext: &[u8]) -> KmsResult<Vec<u8>> {
        self.decrypt_data_key(key_id, ciphertext).await
    }

    async fn rotate_key(&self, key_id: &str) -> KmsResult<String> {
        // Enable automatic key rotation (rotates annually)
        self.client
            .enable_key_rotation()
            .key_id(key_id)
            .send()
            .await
            .map_err(|e| KmsError::AwsKmsError(format!("EnableKeyRotation failed: {}", e)))?;

        Ok(key_id.to_string())
    }

    async fn get_key_metadata(&self, key_id: &str) -> KmsResult<KeyMetadata> {
        let result = self
            .client
            .describe_key()
            .key_id(key_id)
            .send()
            .await
            .map_err(|e| KmsError::AwsKmsError(format!("DescribeKey failed: {}", e)))?;

        let metadata = result
            .key_metadata()
            .ok_or_else(|| KmsError::AwsKmsError("No metadata returned".to_string()))?;

        let state = match metadata.key_state() {
            Some(aws_sdk_kms::types::KeyState::Enabled) => KeyState::Enabled,
            Some(aws_sdk_kms::types::KeyState::Disabled) => KeyState::Disabled,
            Some(aws_sdk_kms::types::KeyState::PendingDeletion) => KeyState::PendingDeletion,
            _ => KeyState::Disabled,
        };

        let created_at = metadata
            .creation_date()
            .map(|d| {
                chrono::DateTime::from_timestamp(d.secs(), d.subsec_nanos())
                    .unwrap_or_else(chrono::Utc::now)
            })
            .unwrap_or_else(chrono::Utc::now);

        let deletion_date = metadata
            .deletion_date()
            .map(|d| {
                chrono::DateTime::from_timestamp(d.secs(), d.subsec_nanos())
                    .unwrap_or_else(chrono::Utc::now)
            });

        // Get alias for this key
        let alias = self.get_key_alias(key_id).await.unwrap_or_default();

        Ok(KeyMetadata {
            key_id: metadata.key_id().to_string(),
            alias,
            version: 1, // AWS KMS manages versions internally
            state,
            algorithm: KeyAlgorithm::Aes256Gcm,
            usage: KeyUsage::EncryptDecrypt,
            origin: KeyOrigin::AwsKms,
            created_at,
            last_rotated_at: None,
            deletion_date,
            description: metadata.description().map(|s| s.to_string()),
            tags: Vec::new(),
        })
    }

    async fn list_keys(&self) -> KmsResult<Vec<String>> {
        let mut keys = Vec::new();
        let mut marker: Option<String> = None;

        loop {
            let mut request = self.client.list_keys();
            if let Some(ref m) = marker {
                request = request.marker(m);
            }

            let result = request
                .send()
                .await
                .map_err(|e| KmsError::AwsKmsError(format!("ListKeys failed: {}", e)))?;

            for key in result.keys() {
                if let Some(key_id) = key.key_id() {
                    keys.push(key_id.to_string());
                }
            }

            if result.truncated() {
                marker = result.next_marker().map(|s| s.to_string());
            } else {
                break;
            }
        }

        Ok(keys)
    }

    async fn schedule_key_deletion(&self, key_id: &str) -> KmsResult<()> {
        self.client
            .schedule_key_deletion()
            .key_id(key_id)
            .pending_window_in_days(7) // Minimum waiting period
            .send()
            .await
            .map_err(|e| {
                KmsError::AwsKmsError(format!("ScheduleKeyDeletion failed: {}", e))
            })?;

        Ok(())
    }
}

#[cfg(feature = "aws")]
impl AwsKms {
    /// Get the alias for a key ID
    async fn get_key_alias(&self, key_id: &str) -> KmsResult<String> {
        let result = self
            .client
            .list_aliases()
            .key_id(key_id)
            .send()
            .await
            .map_err(|e| KmsError::AwsKmsError(format!("ListAliases failed: {}", e)))?;

        if let Some(alias) = result.aliases().first() {
            if let Some(name) = alias.alias_name() {
                return Ok(name.strip_prefix("alias/").unwrap_or(name).to_string());
            }
        }

        Ok(String::new())
    }

    /// Disable a key (without deleting it)
    pub async fn disable_key(&self, key_id: &str) -> KmsResult<()> {
        self.client
            .disable_key()
            .key_id(key_id)
            .send()
            .await
            .map_err(|e| KmsError::AwsKmsError(format!("DisableKey failed: {}", e)))?;
        Ok(())
    }

    /// Enable a previously disabled key
    pub async fn enable_key(&self, key_id: &str) -> KmsResult<()> {
        self.client
            .enable_key()
            .key_id(key_id)
            .send()
            .await
            .map_err(|e| KmsError::AwsKmsError(format!("EnableKey failed: {}", e)))?;
        Ok(())
    }

    /// Cancel scheduled key deletion
    pub async fn cancel_key_deletion(&self, key_id: &str) -> KmsResult<()> {
        self.client
            .cancel_key_deletion()
            .key_id(key_id)
            .send()
            .await
            .map_err(|e| KmsError::AwsKmsError(format!("CancelKeyDeletion failed: {}", e)))?;
        Ok(())
    }

    /// Generate a data key without returning the plaintext (for re-encryption)
    pub async fn generate_data_key_without_plaintext(
        &self,
        key_id: &str,
    ) -> KmsResult<Vec<u8>> {
        let result = self
            .client
            .generate_data_key_without_plaintext()
            .key_id(key_id)
            .key_spec(aws_sdk_kms::types::DataKeySpec::Aes256)
            .send()
            .await
            .map_err(|e| {
                KmsError::AwsKmsError(format!("GenerateDataKeyWithoutPlaintext failed: {}", e))
            })?;

        let ciphertext = result
            .ciphertext_blob()
            .ok_or_else(|| KmsError::AwsKmsError("No ciphertext returned".to_string()))?
            .as_ref()
            .to_vec();

        Ok(ciphertext)
    }

    /// Re-encrypt data under a new key
    pub async fn re_encrypt(
        &self,
        ciphertext: &[u8],
        source_key_id: &str,
        destination_key_id: &str,
    ) -> KmsResult<Vec<u8>> {
        let result = self
            .client
            .re_encrypt()
            .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(ciphertext))
            .source_key_id(source_key_id)
            .destination_key_id(destination_key_id)
            .send()
            .await
            .map_err(|e| KmsError::AwsKmsError(format!("ReEncrypt failed: {}", e)))?;

        let new_ciphertext = result
            .ciphertext_blob()
            .ok_or_else(|| KmsError::AwsKmsError("No ciphertext returned".to_string()))?
            .as_ref()
            .to_vec();

        Ok(new_ciphertext)
    }

    /// Add tags to a key
    pub async fn tag_key(&self, key_id: &str, tags: Vec<(String, String)>) -> KmsResult<()> {
        let aws_tags: Vec<_> = tags
            .into_iter()
            .map(|(k, v)| {
                aws_sdk_kms::types::Tag::builder()
                    .tag_key(k)
                    .tag_value(v)
                    .build()
                    .expect("tag build should not fail")
            })
            .collect();

        self.client
            .tag_resource()
            .key_id(key_id)
            .set_tags(Some(aws_tags))
            .send()
            .await
            .map_err(|e| KmsError::AwsKmsError(format!("TagResource failed: {}", e)))?;

        Ok(())
    }

    /// Check if key rotation is enabled
    pub async fn is_key_rotation_enabled(&self, key_id: &str) -> KmsResult<bool> {
        let result = self
            .client
            .get_key_rotation_status()
            .key_id(key_id)
            .send()
            .await
            .map_err(|e| KmsError::AwsKmsError(format!("GetKeyRotationStatus failed: {}", e)))?;

        Ok(result.key_rotation_enabled())
    }
}

/// AWS KMS provider (stub when aws feature is disabled)
#[cfg(not(feature = "aws"))]
pub struct AwsKms {
    #[allow(dead_code)]
    config: AwsKmsConfig,
}

#[cfg(not(feature = "aws"))]
impl AwsKms {
    /// Create a new AWS KMS provider (stub)
    pub async fn new(config: AwsKmsConfig) -> KmsResult<Self> {
        Ok(Self { config })
    }

    /// Health check (stub)
    pub async fn health_check(&self) -> KmsResult<bool> {
        Err(KmsError::NotSupported(
            "AWS KMS requires the 'aws' feature".to_string(),
        ))
    }
}

#[cfg(not(feature = "aws"))]
#[async_trait]
impl crate::KmsProvider for AwsKms {
    async fn create_key(&self, _alias: &str) -> KmsResult<String> {
        Err(KmsError::NotSupported(
            "AWS KMS requires the 'aws' feature".to_string(),
        ))
    }

    async fn generate_data_key(&self, _key_id: &str) -> KmsResult<DataKey> {
        Err(KmsError::NotSupported(
            "AWS KMS requires the 'aws' feature".to_string(),
        ))
    }

    async fn decrypt_data_key(&self, _key_id: &str, _ciphertext: &[u8]) -> KmsResult<Vec<u8>> {
        Err(KmsError::NotSupported(
            "AWS KMS requires the 'aws' feature".to_string(),
        ))
    }

    async fn encrypt(&self, _key_id: &str, _plaintext: &[u8]) -> KmsResult<Vec<u8>> {
        Err(KmsError::NotSupported(
            "AWS KMS requires the 'aws' feature".to_string(),
        ))
    }

    async fn decrypt(&self, _key_id: &str, _ciphertext: &[u8]) -> KmsResult<Vec<u8>> {
        Err(KmsError::NotSupported(
            "AWS KMS requires the 'aws' feature".to_string(),
        ))
    }

    async fn rotate_key(&self, _key_id: &str) -> KmsResult<String> {
        Err(KmsError::NotSupported(
            "AWS KMS requires the 'aws' feature".to_string(),
        ))
    }

    async fn get_key_metadata(&self, _key_id: &str) -> KmsResult<KeyMetadata> {
        Err(KmsError::NotSupported(
            "AWS KMS requires the 'aws' feature".to_string(),
        ))
    }

    async fn list_keys(&self) -> KmsResult<Vec<String>> {
        Err(KmsError::NotSupported(
            "AWS KMS requires the 'aws' feature".to_string(),
        ))
    }

    async fn schedule_key_deletion(&self, _key_id: &str) -> KmsResult<()> {
        Err(KmsError::NotSupported(
            "AWS KMS requires the 'aws' feature".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KmsProvider;

    #[test]
    fn test_aws_kms_config_default() {
        let config = AwsKmsConfig::default();
        assert_eq!(config.region, "us-east-1");
        assert!(config.endpoint.is_none());
    }

    #[test]
    fn test_aws_kms_config_custom() {
        let config = AwsKmsConfig::new("eu-west-1")
            .with_endpoint("http://localhost:4566");
        assert_eq!(config.region, "eu-west-1");
        assert_eq!(config.endpoint.unwrap(), "http://localhost:4566");
    }

    #[tokio::test]
    #[cfg(not(feature = "aws"))]
    async fn test_aws_kms_stub_returns_error() {
        let config = AwsKmsConfig::default();
        let kms = AwsKms::new(config).await.unwrap();

        let result = kms.create_key("test").await;
        assert!(matches!(result, Err(KmsError::NotSupported(_))));

        let result = kms.generate_data_key("test").await;
        assert!(matches!(result, Err(KmsError::NotSupported(_))));

        let result = kms.list_keys().await;
        assert!(matches!(result, Err(KmsError::NotSupported(_))));

        let result = kms.health_check().await;
        assert!(matches!(result, Err(KmsError::NotSupported(_))));
    }
}
