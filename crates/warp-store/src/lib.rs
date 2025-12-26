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
pub mod collective;
#[cfg(feature = "raft")]
pub mod consistency;
pub mod ephemeral;
pub mod error;
pub mod events;
pub mod key;
pub mod lifecycle;
pub mod metrics;
pub mod object;
pub mod object_lock;
pub mod replication;
pub mod transport;
pub mod version;

pub use backend::{StorageBackend, HpcStorageBackend};
pub use bucket::{Bucket, BucketConfig, BucketPolicy};
pub use collective::{Rank, CollectiveContext, StorageCollectiveOps, CollectiveAdapter};
pub use replication::{
    ReplicationPolicy, ErasurePolicy, PlacementConstraints, ReadPreference, ShardDistribution,
    Domain, DomainId, DomainRegistry, DomainHealth, NodeInfo, NodeStatus,
    WireGuardTunnelManager, WireGuardTunnel, WireGuardConfig, WireGuardKeyPair, TunnelStatus, TunnelStats,
    DistributedShardManager, ShardKey, ShardLocation, ShardHealth, ShardIndex, ShardDistributionInfo, ShardManagerStats,
    GeoRouter, LatencyStats, ShardReadPlan, GeoRouterStats,
};
#[cfg(feature = "raft")]
pub use consistency::{RaftStore, RaftStoreConfig, RaftMetrics, NodeId, ObjectMetadataEntry};
pub use ephemeral::{EphemeralToken, AccessScope, Permissions, RateLimit};
pub use error::{Error, Result};
pub use key::ObjectKey;
pub use metrics::{MetricsCollector, MetricsSnapshot, LatencyTimer};
pub use object::{ObjectData, ObjectMeta, PutOptions, ListOptions, ObjectList, ObjectSummary, FieldData, FieldValue};
pub use version::{Version, VersionId, VersioningMode};
pub use lifecycle::{LifecycleExecutor, LifecycleConfig, LifecycleStats, LifecycleRuleBuilder};
pub use events::{EventEmitter, EventConfig, S3Event, EventType, NotificationConfiguration};
pub use object_lock::{
    ObjectLockConfig, ObjectLockManager, ObjectLockStatus, ObjectRetention,
    RetentionMode, LegalHoldStatus, DefaultRetention,
};

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

    /// Distributed mode configuration (requires "raft" feature)
    #[cfg(feature = "raft")]
    pub distributed: Option<DistributedConfig>,
}

/// Configuration for distributed mode with Raft consensus
#[cfg(feature = "raft")]
#[derive(Debug, Clone)]
pub struct DistributedConfig {
    /// This node's ID in the Raft cluster
    pub node_id: NodeId,

    /// Whether to initialize as a new single-node cluster
    /// (set true for the first node, false for joining nodes)
    pub init_cluster: bool,

    /// Raft-specific configuration
    pub raft_config: RaftStoreConfig,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            root_path: std::path::PathBuf::from("/tmp/warp-store"),
            default_versioning: VersioningMode::Disabled,
            max_object_size: 5 * 1024 * 1024 * 1024 * 1024, // 5TB
            content_addressed: false,
            signing_key: None,
            #[cfg(feature = "raft")]
            distributed: None,
        }
    }
}

#[cfg(feature = "raft")]
impl DistributedConfig {
    /// Create a config for the first node in a new cluster
    pub fn new_cluster(node_id: NodeId) -> Self {
        Self {
            node_id,
            init_cluster: true,
            raft_config: RaftStoreConfig::default(),
        }
    }

    /// Create a config for joining an existing cluster
    pub fn join_cluster(node_id: NodeId) -> Self {
        Self {
            node_id,
            init_cluster: false,
            raft_config: RaftStoreConfig::default(),
        }
    }
}

/// The main warp-store instance
///
/// Provides a unified interface to object storage with pluggable backends.
/// When the "raft" feature is enabled and distributed mode is configured,
/// metadata operations (bucket/object metadata) are replicated via Raft consensus.
pub struct Store<B: StorageBackend = backend::LocalBackend> {
    /// The storage backend (handles actual data storage)
    backend: Arc<B>,

    /// Bucket registry (local fallback when not using Raft)
    buckets: DashMap<String, Bucket>,

    /// Store configuration
    config: StoreConfig,

    /// Signing key for ephemeral tokens
    signing_key: ed25519_dalek::SigningKey,

    /// Verifying key for ephemeral tokens
    verifying_key: ed25519_dalek::VerifyingKey,

    /// Distributed metadata store (when raft feature is enabled)
    #[cfg(feature = "raft")]
    raft_store: Option<Arc<RaftStore>>,
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

        // Initialize Raft store if distributed mode is configured
        #[cfg(feature = "raft")]
        let raft_store = if let Some(ref dist_config) = config.distributed {
            info!(
                node_id = dist_config.node_id,
                init_cluster = dist_config.init_cluster,
                "Initializing distributed mode with Raft"
            );

            let raft = RaftStore::with_config(
                dist_config.node_id,
                dist_config.raft_config.clone(),
            )
            .await?;

            if dist_config.init_cluster {
                raft.init_cluster().await?;
                // Wait for leader election
                raft.wait_for_leader(std::time::Duration::from_secs(5)).await?;
            }

            Some(Arc::new(raft))
        } else {
            None
        };

        info!(root = %config.root_path.display(), "Initializing warp-store");

        Ok(Self {
            backend: Arc::new(backend),
            buckets: DashMap::new(),
            config,
            signing_key,
            verifying_key,
            #[cfg(feature = "raft")]
            raft_store,
        })
    }

    /// Create a new bucket
    ///
    /// When running in distributed mode, this operation is replicated via Raft consensus.
    pub async fn create_bucket(&self, name: &str, config: BucketConfig) -> Result<()> {
        // Use Raft for metadata if available
        #[cfg(feature = "raft")]
        if let Some(ref raft) = self.raft_store {
            raft.create_bucket(name, config.clone()).await?;
        } else {
            // Local-only mode
            if self.buckets.contains_key(name) {
                return Err(Error::BucketAlreadyExists(name.to_string()));
            }
            let bucket = Bucket::new(name.to_string(), config.clone());
            self.buckets.insert(name.to_string(), bucket);
        }

        #[cfg(not(feature = "raft"))]
        {
            if self.buckets.contains_key(name) {
                return Err(Error::BucketAlreadyExists(name.to_string()));
            }
            let bucket = Bucket::new(name.to_string(), config.clone());
            self.buckets.insert(name.to_string(), bucket);
        }

        // Ensure backend storage is created
        self.backend.create_bucket(name).await?;

        debug!(bucket = name, "Created bucket");
        Ok(())
    }

    /// Delete a bucket (must be empty)
    ///
    /// When running in distributed mode, this operation is replicated via Raft consensus.
    pub async fn delete_bucket(&self, name: &str) -> Result<()> {
        // Check if bucket is empty
        let list = self.backend.list(name, "", ListOptions::default()).await?;
        if !list.objects.is_empty() {
            return Err(Error::BucketNotEmpty(name.to_string()));
        }

        // Use Raft for metadata if available
        #[cfg(feature = "raft")]
        if let Some(ref raft) = self.raft_store {
            raft.delete_bucket(name).await?;
        } else {
            if !self.buckets.contains_key(name) {
                return Err(Error::BucketNotFound(name.to_string()));
            }
            self.buckets.remove(name);
        }

        #[cfg(not(feature = "raft"))]
        {
            if !self.buckets.contains_key(name) {
                return Err(Error::BucketNotFound(name.to_string()));
            }
            self.buckets.remove(name);
        }

        self.backend.delete_bucket(name).await?;

        debug!(bucket = name, "Deleted bucket");
        Ok(())
    }

    /// List all buckets
    ///
    /// In distributed mode, reads from the Raft-replicated metadata store.
    pub async fn list_buckets(&self) -> Vec<String> {
        #[cfg(feature = "raft")]
        if let Some(ref raft) = self.raft_store {
            return raft.list_buckets().await;
        }

        self.buckets.iter().map(|r| r.key().clone()).collect()
    }

    /// Get an object
    pub async fn get(&self, key: &ObjectKey) -> Result<ObjectData> {
        debug!(key = %key, "Getting object");
        self.backend.get(key).await
    }

    /// Get specific fields from an object (lazy loading)
    ///
    /// For backends that support lazy loading (like Parcode), this efficiently
    /// retrieves only the requested fields without loading the entire object.
    /// This is critical for checkpoint resume where only metadata or specific
    /// layer weights need to be accessed.
    ///
    /// # Example
    /// ```ignore
    /// // Resume from checkpoint by loading only needed fields
    /// let fields = store.get_fields(&checkpoint_key, &["epoch", "step", "optimizer_state"]).await?;
    /// ```
    pub async fn get_fields(&self, key: &ObjectKey, fields: &[&str]) -> Result<FieldData> {
        debug!(key = %key, fields = ?fields, "Getting object fields (lazy)");
        self.backend.get_fields(key, fields).await
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

    // =========================================================================
    // Multipart Upload API
    // =========================================================================

    /// Initiate a multipart upload
    pub async fn create_multipart(&self, key: &ObjectKey) -> Result<backend::MultipartUpload> {
        debug!(key = %key, "Creating multipart upload");
        self.backend.create_multipart(key).await
    }

    /// Upload a part to a multipart upload
    pub async fn upload_part(
        &self,
        upload: &backend::MultipartUpload,
        part_number: u32,
        data: ObjectData,
    ) -> Result<backend::PartInfo> {
        debug!(
            upload_id = %upload.upload_id,
            part_number,
            size = data.len(),
            "Uploading part"
        );
        self.backend.upload_part(upload, part_number, data).await
    }

    /// Complete a multipart upload
    pub async fn complete_multipart(
        &self,
        upload: &backend::MultipartUpload,
        parts: Vec<backend::PartInfo>,
    ) -> Result<ObjectMeta> {
        debug!(
            upload_id = %upload.upload_id,
            parts = parts.len(),
            "Completing multipart upload"
        );
        self.backend.complete_multipart(upload, parts).await
    }

    /// Abort a multipart upload
    pub async fn abort_multipart(&self, upload: &backend::MultipartUpload) -> Result<()> {
        debug!(upload_id = %upload.upload_id, "Aborting multipart upload");
        self.backend.abort_multipart(upload).await
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

    // =========================================================================
    // Distributed Mode Operations (requires "raft" feature)
    // =========================================================================

    /// Check if distributed mode is active
    #[cfg(feature = "raft")]
    pub fn is_distributed(&self) -> bool {
        self.raft_store.is_some()
    }

    /// Check if this node is the Raft leader
    ///
    /// Returns false if not in distributed mode.
    #[cfg(feature = "raft")]
    pub fn is_leader(&self) -> bool {
        self.raft_store
            .as_ref()
            .map(|r| r.is_leader())
            .unwrap_or(false)
    }

    /// Get the current leader node ID
    ///
    /// Returns None if not in distributed mode or no leader is elected.
    #[cfg(feature = "raft")]
    pub fn current_leader(&self) -> Option<NodeId> {
        self.raft_store.as_ref().and_then(|r| r.current_leader())
    }

    /// Get Raft cluster metrics
    ///
    /// Returns None if not in distributed mode.
    #[cfg(feature = "raft")]
    pub fn raft_metrics(&self) -> Option<RaftMetrics> {
        self.raft_store.as_ref().map(|r| r.metrics())
    }

    /// Add a node to the distributed cluster
    ///
    /// Only the leader can add nodes.
    #[cfg(feature = "raft")]
    pub async fn add_cluster_node(&self, node_id: NodeId, addr: String) -> Result<()> {
        match &self.raft_store {
            Some(raft) => raft.add_node(node_id, addr).await,
            None => Err(Error::Raft("Not in distributed mode".to_string())),
        }
    }

    /// Remove a node from the distributed cluster
    ///
    /// Only the leader can remove nodes.
    #[cfg(feature = "raft")]
    pub async fn remove_cluster_node(&self, node_id: NodeId) -> Result<()> {
        match &self.raft_store {
            Some(raft) => raft.remove_node(node_id).await,
            None => Err(Error::Raft("Not in distributed mode".to_string())),
        }
    }

    /// Get the underlying Raft store (for advanced operations)
    #[cfg(feature = "raft")]
    pub fn raft_store(&self) -> Option<&Arc<RaftStore>> {
        self.raft_store.as_ref()
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

    #[cfg(feature = "raft")]
    #[tokio::test]
    async fn test_distributed_store() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = StoreConfig {
            root_path: temp_dir.path().to_path_buf(),
            distributed: Some(DistributedConfig::new_cluster(1)),
            ..Default::default()
        };

        let store = Store::new(config).await.unwrap();

        // Verify distributed mode is active
        assert!(store.is_distributed());

        // Should become leader of single-node cluster
        assert!(store.is_leader());
        assert_eq!(store.current_leader(), Some(1));

        // Create bucket via Raft
        store.create_bucket("raft-bucket", BucketConfig::default()).await.unwrap();

        // List buckets
        let buckets = store.list_buckets().await;
        assert!(buckets.contains(&"raft-bucket".to_string()));

        // Get Raft metrics
        let metrics = store.raft_metrics().unwrap();
        assert_eq!(metrics.node_id, 1);
        assert!(metrics.membership.contains(&1));
    }
}
