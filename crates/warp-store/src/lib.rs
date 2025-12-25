//! # warp-store: Next-Generation HPC Object Storage
//!
//! A modern S3 replacement that surpasses traditional object storage by leveraging
//! the full HPC-AI ecosystem:
//!
//! - **Performance**: RDMA (1-50µs), GPUDirect (400 Gbps), zero-copy
//! - **Features**: Ephemeral URLs, lazy loading, ZK proofs, field-level access
//! - **Integration**: Native to all 12 HPC-AI projects
//! - **Scale**: WireGuard mesh spanning domains, P2P distribution
//! - **Compatibility**: S3 API as secondary interface
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use warp_store::{Store, StoreConfig, ObjectKey};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), warp_store::Error> {
//!     // Create a store with local backend
//!     let store = Store::new(StoreConfig::default()).await?;
//!
//!     // Put an object
//!     let key = ObjectKey::new("my-bucket", "data/file.bin")?;
//!     store.put(&key, b"Hello, warp-store!".to_vec().into()).await?;
//!
//!     // Get it back
//!     let data = store.get(&key).await?;
//!     println!("Retrieved {} bytes", data.len());
//!
//!     // Generate an ephemeral URL (valid for 1 hour)
//!     let token = store.create_ephemeral_url(&key, std::time::Duration::from_secs(3600))?;
//!     println!("Ephemeral URL token: {}", token.encode());
//!
//!     Ok(())
//! }
//! ```

#![warn(missing_docs)]

pub mod backend;
pub mod bucket;
pub mod ephemeral;
pub mod error;
pub mod key;
pub mod object;
pub mod version;

pub use backend::{StorageBackend, HpcStorageBackend};
pub use bucket::{Bucket, BucketConfig, BucketPolicy};
pub use ephemeral::{EphemeralToken, AccessScope, Permissions, RateLimit};
pub use error::{Error, Result};
pub use key::ObjectKey;
pub use object::{ObjectData, ObjectMeta, PutOptions, ListOptions, ObjectList};
pub use version::{Version, VersionId, VersioningMode};

use std::sync::Arc;
use dashmap::DashMap;
use tracing::{info, debug};

/// Main store configuration
#[derive(Debug, Clone)]
pub struct StoreConfig {
    /// Root directory for local storage
    pub root_path: std::path::PathBuf,

    /// Default versioning mode for new buckets
    pub default_versioning: VersioningMode,

    /// Maximum object size (default: 5TB)
    pub max_object_size: u64,

    /// Enable content-addressed storage
    pub content_addressed: bool,

    /// Signing key for ephemeral tokens
    pub signing_key: Option<ed25519_dalek::SigningKey>,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            root_path: std::path::PathBuf::from("/tmp/warp-store"),
            default_versioning: VersioningMode::Disabled,
            max_object_size: 5 * 1024 * 1024 * 1024 * 1024, // 5TB
            content_addressed: false,
            signing_key: None,
        }
    }
}

/// The main warp-store instance
///
/// Provides a unified interface to object storage with pluggable backends.
pub struct Store<B: StorageBackend = backend::LocalBackend> {
    /// The storage backend
    backend: Arc<B>,

    /// Bucket registry
    buckets: DashMap<String, Bucket>,

    /// Store configuration
    config: StoreConfig,

    /// Signing key for ephemeral tokens
    signing_key: ed25519_dalek::SigningKey,

    /// Verifying key for ephemeral tokens
    verifying_key: ed25519_dalek::VerifyingKey,
}

impl Store<backend::LocalBackend> {
    /// Create a new store with local filesystem backend
    pub async fn new(config: StoreConfig) -> Result<Self> {
        let backend = backend::LocalBackend::new(&config.root_path).await?;
        Self::with_backend(backend, config).await
    }
}

impl<B: StorageBackend> Store<B> {
    /// Create a store with a custom backend
    pub async fn with_backend(backend: B, config: StoreConfig) -> Result<Self> {
        // Generate or use provided signing key
        let signing_key = config.signing_key.clone().unwrap_or_else(|| {
            let mut rng = rand::thread_rng();
            ed25519_dalek::SigningKey::generate(&mut rng)
        });
        let verifying_key = signing_key.verifying_key();

        info!(root = %config.root_path.display(), "Initializing warp-store");

        Ok(Self {
            backend: Arc::new(backend),
            buckets: DashMap::new(),
            config,
            signing_key,
            verifying_key,
        })
    }

    /// Create a new bucket
    pub async fn create_bucket(&self, name: &str, config: BucketConfig) -> Result<()> {
        if self.buckets.contains_key(name) {
            return Err(Error::BucketAlreadyExists(name.to_string()));
        }

        let bucket = Bucket::new(name.to_string(), config);
        self.buckets.insert(name.to_string(), bucket);

        // Ensure backend storage is created
        self.backend.create_bucket(name).await?;

        debug!(bucket = name, "Created bucket");
        Ok(())
    }

    /// Delete a bucket (must be empty)
    pub async fn delete_bucket(&self, name: &str) -> Result<()> {
        // Check if bucket exists
        if !self.buckets.contains_key(name) {
            return Err(Error::BucketNotFound(name.to_string()));
        }

        // Check if bucket is empty
        let list = self.backend.list(name, "", ListOptions::default()).await?;
        if !list.objects.is_empty() {
            return Err(Error::BucketNotEmpty(name.to_string()));
        }

        self.buckets.remove(name);
        self.backend.delete_bucket(name).await?;

        debug!(bucket = name, "Deleted bucket");
        Ok(())
    }

    /// List all buckets
    pub fn list_buckets(&self) -> Vec<String> {
        self.buckets.iter().map(|r| r.key().clone()).collect()
    }

    /// Get an object
    pub async fn get(&self, key: &ObjectKey) -> Result<ObjectData> {
        debug!(key = %key, "Getting object");
        self.backend.get(key).await
    }

    /// Get object metadata without data
    pub async fn head(&self, key: &ObjectKey) -> Result<ObjectMeta> {
        self.backend.head(key).await
    }

    /// Put an object
    pub async fn put(&self, key: &ObjectKey, data: ObjectData) -> Result<ObjectMeta> {
        self.put_with_options(key, data, PutOptions::default()).await
    }

    /// Put an object with options
    pub async fn put_with_options(
        &self,
        key: &ObjectKey,
        data: ObjectData,
        opts: PutOptions,
    ) -> Result<ObjectMeta> {
        // Check size limit
        if data.len() as u64 > self.config.max_object_size {
            return Err(Error::ObjectTooLarge {
                size: data.len() as u64,
                max: self.config.max_object_size,
            });
        }

        debug!(key = %key, size = data.len(), "Putting object");
        self.backend.put(key, data, opts).await
    }

    /// Delete an object
    pub async fn delete(&self, key: &ObjectKey) -> Result<()> {
        debug!(key = %key, "Deleting object");
        self.backend.delete(key).await
    }

    /// List objects with prefix
    pub async fn list(&self, bucket: &str, prefix: &str) -> Result<ObjectList> {
        self.list_with_options(bucket, prefix, ListOptions::default()).await
    }

    /// List objects with options
    pub async fn list_with_options(
        &self,
        bucket: &str,
        prefix: &str,
        opts: ListOptions,
    ) -> Result<ObjectList> {
        self.backend.list(bucket, prefix, opts).await
    }

    /// Create an ephemeral access URL/token
    pub fn create_ephemeral_url(
        &self,
        key: &ObjectKey,
        ttl: std::time::Duration,
    ) -> Result<EphemeralToken> {
        self.create_ephemeral_url_with_options(
            AccessScope::Object(key.clone()),
            Permissions::READ,
            ttl,
            None,
            None,
        )
    }

    /// Create an ephemeral URL with full options
    pub fn create_ephemeral_url_with_options(
        &self,
        scope: AccessScope,
        permissions: Permissions,
        ttl: std::time::Duration,
        ip_restrictions: Option<Vec<ipnet::IpNet>>,
        rate_limit: Option<RateLimit>,
    ) -> Result<EphemeralToken> {
        EphemeralToken::generate(
            &self.signing_key,
            scope,
            permissions,
            ttl,
            ip_restrictions,
            rate_limit,
        )
    }

    /// Verify an ephemeral token
    pub fn verify_token(
        &self,
        token: &EphemeralToken,
        request_ip: Option<std::net::IpAddr>,
    ) -> Result<()> {
        token.verify(&self.verifying_key, request_ip)
    }

    /// Get the verifying key (for distributing to other services)
    pub fn verifying_key(&self) -> &ed25519_dalek::VerifyingKey {
        &self.verifying_key
    }

    /// Get the backend (for advanced operations)
    pub fn backend(&self) -> &B {
        &self.backend
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_store_basic_operations() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = StoreConfig {
            root_path: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let store = Store::new(config).await.unwrap();

        // Create bucket
        store.create_bucket("test-bucket", BucketConfig::default()).await.unwrap();

        // Put object
        let key = ObjectKey::new("test-bucket", "hello.txt").unwrap();
        let data = ObjectData::from(b"Hello, World!".to_vec());
        store.put(&key, data.clone()).await.unwrap();

        // Get object
        let retrieved = store.get(&key).await.unwrap();
        assert_eq!(retrieved.as_ref(), b"Hello, World!");

        // Delete object
        store.delete(&key).await.unwrap();

        // Verify deleted
        assert!(store.get(&key).await.is_err());
    }

    #[tokio::test]
    async fn test_ephemeral_token() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = StoreConfig {
            root_path: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let store = Store::new(config).await.unwrap();
        let key = ObjectKey::new("test-bucket", "secret.bin").unwrap();

        // Generate token
        let token = store.create_ephemeral_url(&key, std::time::Duration::from_secs(3600)).unwrap();

        // Verify token
        assert!(store.verify_token(&token, None).is_ok());

        // Encode and decode
        let encoded = token.encode();
        let decoded = EphemeralToken::decode(&encoded).unwrap();
        assert!(store.verify_token(&decoded, None).is_ok());
    }
}
