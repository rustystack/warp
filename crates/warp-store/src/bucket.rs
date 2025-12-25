//! Bucket management and configuration

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::version::VersioningMode;

/// A storage bucket
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bucket {
    /// Bucket name
    name: String,

    /// Bucket configuration
    config: BucketConfig,

    /// Creation time
    created_at: DateTime<Utc>,

    /// Last modification time
    modified_at: DateTime<Utc>,
}

impl Bucket {
    /// Create a new bucket
    pub fn new(name: String, config: BucketConfig) -> Self {
        let now = Utc::now();
        Self {
            name,
            config,
            created_at: now,
            modified_at: now,
        }
    }

    /// Get the bucket name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the bucket configuration
    pub fn config(&self) -> &BucketConfig {
        &self.config
    }

    /// Update bucket configuration
    pub fn update_config(&mut self, config: BucketConfig) {
        self.config = config;
        self.modified_at = Utc::now();
    }

    /// Get creation time
    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    /// Get last modification time
    pub fn modified_at(&self) -> DateTime<Utc> {
        self.modified_at
    }
}

/// Bucket configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketConfig {
    /// Versioning mode
    pub versioning: VersioningMode,

    /// Access policy
    pub policy: BucketPolicy,

    /// Default storage class
    pub default_storage_class: crate::object::StorageClass,

    /// Enable server-side encryption
    pub encryption: EncryptionConfig,

    /// Lifecycle rules
    pub lifecycle: Vec<LifecycleRule>,

    /// CORS configuration
    pub cors: Option<CorsConfig>,

    /// Replication configuration
    pub replication: Option<ReplicationConfig>,

    /// Tags
    pub tags: Vec<(String, String)>,
}

impl Default for BucketConfig {
    fn default() -> Self {
        Self {
            versioning: VersioningMode::Disabled,
            policy: BucketPolicy::Private,
            default_storage_class: crate::object::StorageClass::Standard,
            encryption: EncryptionConfig::default(),
            lifecycle: Vec::new(),
            cors: None,
            replication: None,
            tags: Vec::new(),
        }
    }
}

/// Bucket access policy
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum BucketPolicy {
    /// Private - only owner can access
    #[default]
    Private,

    /// Public read - anyone can read
    PublicRead,

    /// Public read-write - anyone can read and write
    PublicReadWrite,

    /// Authenticated read - any authenticated user can read
    AuthenticatedRead,
}

/// Server-side encryption configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EncryptionConfig {
    /// Enable encryption
    pub enabled: bool,

    /// Encryption algorithm
    pub algorithm: EncryptionAlgorithm,

    /// Key ID for customer-managed keys
    pub key_id: Option<String>,
}

/// Encryption algorithm
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    /// No encryption
    #[default]
    None,

    /// ChaCha20-Poly1305 (default for warp-store)
    ChaCha20Poly1305,

    /// AES-256-GCM (S3 compatible)
    Aes256Gcm,
}

/// Lifecycle rule for automatic object management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleRule {
    /// Rule ID
    pub id: String,

    /// Rule is enabled
    pub enabled: bool,

    /// Prefix filter
    pub prefix: Option<String>,

    /// Tag filter
    pub tags: Vec<(String, String)>,

    /// Transition actions
    pub transitions: Vec<TransitionAction>,

    /// Expiration action
    pub expiration: Option<ExpirationAction>,

    /// Noncurrent version transitions
    pub noncurrent_transitions: Vec<NoncurrentTransitionAction>,

    /// Noncurrent version expiration
    pub noncurrent_expiration: Option<NoncurrentExpirationAction>,
}

/// Transition to different storage class
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitionAction {
    /// Days after object creation
    pub days: u32,

    /// Target storage class
    pub storage_class: crate::object::StorageClass,
}

/// Object expiration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpirationAction {
    /// Days after object creation
    pub days: Option<u32>,

    /// Specific date
    pub date: Option<DateTime<Utc>>,

    /// Also delete expired delete markers
    pub expired_object_delete_marker: bool,
}

/// Noncurrent version transition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoncurrentTransitionAction {
    /// Days after becoming noncurrent
    pub noncurrent_days: u32,

    /// Number of newer versions to keep
    pub newer_noncurrent_versions: Option<u32>,

    /// Target storage class
    pub storage_class: crate::object::StorageClass,
}

/// Noncurrent version expiration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoncurrentExpirationAction {
    /// Days after becoming noncurrent
    pub noncurrent_days: u32,

    /// Number of newer versions to keep
    pub newer_noncurrent_versions: Option<u32>,
}

/// CORS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsConfig {
    /// CORS rules
    pub rules: Vec<CorsRule>,
}

/// A CORS rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsRule {
    /// Allowed origins
    pub allowed_origins: Vec<String>,

    /// Allowed methods
    pub allowed_methods: Vec<String>,

    /// Allowed headers
    pub allowed_headers: Vec<String>,

    /// Exposed headers
    pub expose_headers: Vec<String>,

    /// Max age in seconds
    pub max_age_seconds: Option<u32>,
}

/// Replication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationConfig {
    /// Replication rules
    pub rules: Vec<ReplicationRule>,
}

/// A replication rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationRule {
    /// Rule ID
    pub id: String,

    /// Rule is enabled
    pub enabled: bool,

    /// Source prefix filter
    pub prefix: Option<String>,

    /// Destination bucket
    pub destination_bucket: String,

    /// Destination storage class
    pub destination_storage_class: Option<crate::object::StorageClass>,

    /// Replicate delete markers
    pub replicate_deletes: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bucket_creation() {
        let config = BucketConfig::default();
        let bucket = Bucket::new("test-bucket".to_string(), config);

        assert_eq!(bucket.name(), "test-bucket");
        assert_eq!(bucket.config().versioning, VersioningMode::Disabled);
        assert_eq!(bucket.config().policy, BucketPolicy::Private);
    }

    #[test]
    fn test_bucket_config_update() {
        let config = BucketConfig::default();
        let mut bucket = Bucket::new("test-bucket".to_string(), config);

        let old_modified = bucket.modified_at();

        let new_config = BucketConfig {
            versioning: VersioningMode::Enabled,
            policy: BucketPolicy::PublicRead,
            ..Default::default()
        };

        bucket.update_config(new_config);

        assert_eq!(bucket.config().versioning, VersioningMode::Enabled);
        assert_eq!(bucket.config().policy, BucketPolicy::PublicRead);
        assert!(bucket.modified_at() >= old_modified);
    }
}
