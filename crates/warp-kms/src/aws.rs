//! AWS KMS integration
//!
//! This module is a placeholder for AWS KMS integration.
//! Enable with `--features aws` once aws-sdk-kms bindings are implemented.

use crate::{DataKey, KeyMetadata, KmsError, KmsResult};
use async_trait::async_trait;

/// AWS KMS provider configuration
#[derive(Debug, Clone)]
pub struct AwsKmsConfig {
    /// AWS region
    pub region: String,
    /// Optional endpoint override (for LocalStack)
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

/// AWS KMS provider
pub struct AwsKms {
    #[allow(dead_code)]
    config: AwsKmsConfig,
}

impl AwsKms {
    /// Create a new AWS KMS provider
    ///
    /// # Errors
    /// Returns error if AWS credentials are not configured
    pub async fn new(config: AwsKmsConfig) -> KmsResult<Self> {
        Ok(Self { config })
    }
}

#[async_trait]
impl crate::KmsProvider for AwsKms {
    async fn create_key(&self, _alias: &str) -> KmsResult<String> {
        // In real implementation, would call AWS KMS CreateKey API
        Err(KmsError::NotSupported(
            "AWS KMS provider not yet implemented".to_string(),
        ))
    }

    async fn generate_data_key(&self, _key_id: &str) -> KmsResult<DataKey> {
        // In real implementation, would call AWS KMS GenerateDataKey API
        Err(KmsError::NotSupported(
            "AWS KMS provider not yet implemented".to_string(),
        ))
    }

    async fn decrypt_data_key(&self, _key_id: &str, _ciphertext: &[u8]) -> KmsResult<Vec<u8>> {
        // In real implementation, would call AWS KMS Decrypt API
        Err(KmsError::NotSupported(
            "AWS KMS provider not yet implemented".to_string(),
        ))
    }

    async fn encrypt(&self, _key_id: &str, _plaintext: &[u8]) -> KmsResult<Vec<u8>> {
        // In real implementation, would call AWS KMS Encrypt API
        Err(KmsError::NotSupported(
            "AWS KMS provider not yet implemented".to_string(),
        ))
    }

    async fn decrypt(&self, _key_id: &str, _ciphertext: &[u8]) -> KmsResult<Vec<u8>> {
        // In real implementation, would call AWS KMS Decrypt API
        Err(KmsError::NotSupported(
            "AWS KMS provider not yet implemented".to_string(),
        ))
    }

    async fn rotate_key(&self, _key_id: &str) -> KmsResult<String> {
        // In real implementation, would enable automatic key rotation
        Err(KmsError::NotSupported(
            "AWS KMS provider not yet implemented".to_string(),
        ))
    }

    async fn get_key_metadata(&self, _key_id: &str) -> KmsResult<KeyMetadata> {
        // In real implementation, would call AWS KMS DescribeKey API
        Err(KmsError::NotSupported(
            "AWS KMS provider not yet implemented".to_string(),
        ))
    }

    async fn list_keys(&self) -> KmsResult<Vec<String>> {
        // In real implementation, would call AWS KMS ListKeys API
        Err(KmsError::NotSupported(
            "AWS KMS provider not yet implemented".to_string(),
        ))
    }

    async fn schedule_key_deletion(&self, _key_id: &str) -> KmsResult<()> {
        // In real implementation, would call AWS KMS ScheduleKeyDeletion API
        Err(KmsError::NotSupported(
            "AWS KMS provider not yet implemented".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_aws_kms_not_implemented() {
        let config = AwsKmsConfig::default();
        let kms = AwsKms::new(config).await.unwrap();

        let result = kms.create_key("test").await;
        assert!(result.is_err());
    }
}
