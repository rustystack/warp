#![allow(clippy::collapsible_if)]
#![allow(clippy::if_same_then_else)]
#![allow(clippy::field_reassign_with_default)]
#![allow(dead_code)]

//! # warp-store-api: HTTP API Server for warp-store
//!
//! Provides both S3-compatible REST endpoints and native HPC endpoints.
//!
//! ## S3 Compatibility
//!
//! Implements core S3 operations:
//! - GetObject, PutObject, DeleteObject
//! - ListObjectsV2, HeadObject
//! - CreateBucket, DeleteBucket, ListBuckets
//! - AWS Signature V4 authentication
//!
//! ## Native HPC API
//!
//! High-performance endpoints for HPC workloads:
//! - LazyGet - field-level access
//! - CollectiveRead - distributed reads
//! - EphemeralURL - token-based access
//! - StreamChunked - streaming large objects
//!
//! ## Example
//!
//! ```ignore
//! use warp_store_api::{ApiServer, ApiConfig};
//! use warp_store::{Store, StoreConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//!     let store = Store::new(StoreConfig::default()).await?;
//!
//!     let config = ApiConfig {
//!         bind_addr: "0.0.0.0:9000".parse()?,
//!         ..Default::default()
//!     };
//!
//!     let server = ApiServer::new(store, config).await;
//!     server.run().await?;
//!
//!     Ok(())
//! }
//! ```

#![warn(missing_docs)]

pub mod admin;
pub mod auth;
pub mod error;
pub mod native;
pub mod s3;

pub use error::{ApiError, ApiResult};

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
#[cfg(feature = "iam")]
use axum::middleware;
use dashmap::DashMap;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::info;

use warp_store::backend::{MultipartUpload, PartInfo, StorageBackend};
use warp_store::bucket::{CorsConfig, EncryptionConfig, LifecycleRule, ReplicationConfig};
use warp_store::events::NotificationConfiguration;
use warp_store::object_lock::ObjectLockManager;
use warp_store::version::VersioningMode;
use warp_store::{MetricsCollector, Store};

use s3::BucketPolicyManager;

#[cfg(feature = "iam")]
use auth::IamManagers;

/// API server configuration
#[derive(Debug, Clone)]
pub struct ApiConfig {
    /// Address to bind the server
    pub bind_addr: SocketAddr,

    /// Enable S3 API
    pub enable_s3: bool,

    /// Enable native HPC API
    pub enable_native: bool,

    /// AWS access key ID for S3 auth
    pub access_key_id: Option<String>,

    /// AWS secret access key for S3 auth
    pub secret_access_key: Option<String>,

    /// Region for S3 API
    pub region: String,

    /// Enable IAM-based authentication (requires `iam` feature)
    #[cfg(feature = "iam")]
    pub enable_iam: bool,

    /// Session TTL in seconds (default: 3600 = 1 hour)
    #[cfg(feature = "iam")]
    pub session_ttl_seconds: u64,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:9000".parse().unwrap(),
            enable_s3: true,
            enable_native: true,
            access_key_id: None,
            secret_access_key: None,
            region: "us-east-1".to_string(),
            #[cfg(feature = "iam")]
            enable_iam: false,
            #[cfg(feature = "iam")]
            session_ttl_seconds: 3600,
        }
    }
}

/// Shared application state
pub struct AppState<B: StorageBackend> {
    /// The storage backend
    pub store: Arc<Store<B>>,

    /// API configuration
    pub config: ApiConfig,

    /// Metrics collector
    pub metrics: Option<Arc<MetricsCollector>>,

    /// Active multipart uploads (upload_id -> MultipartUpload)
    uploads: Arc<DashMap<String, MultipartUpload>>,

    /// Parts for each upload (upload_id -> Vec<PartInfo>)
    parts: Arc<DashMap<String, Vec<PartInfo>>>,

    /// Lifecycle rules per bucket (bucket_name -> Vec<LifecycleRule>)
    lifecycle_rules: Arc<DashMap<String, Vec<LifecycleRule>>>,

    /// Notification configurations per bucket (bucket_name -> NotificationConfiguration)
    notification_configs: Arc<DashMap<String, NotificationConfiguration>>,

    /// Bucket policy manager
    pub policy_manager: Option<Arc<BucketPolicyManager>>,

    /// Object Lock manager for WORM compliance
    pub object_lock_manager: Option<Arc<ObjectLockManager>>,

    /// Versioning configurations per bucket (bucket_name -> VersioningMode)
    pub versioning_configs: Arc<DashMap<String, VersioningMode>>,

    /// Encryption configurations per bucket (bucket_name -> EncryptionConfig)
    pub encryption_configs: Arc<DashMap<String, EncryptionConfig>>,

    /// Replication configurations per bucket (bucket_name -> ReplicationConfig)
    pub replication_configs: Arc<DashMap<String, ReplicationConfig>>,

    /// CORS configurations per bucket (bucket_name -> CorsConfig)
    pub cors_configs: Arc<DashMap<String, CorsConfig>>,

    /// Bucket tags (bucket_name -> Vec<(key, value)>)
    pub bucket_tags: Arc<DashMap<String, Vec<(String, String)>>>,

    /// Object tags ((bucket_name, key) -> Vec<(key, value)>)
    pub object_tags: Arc<DashMap<(String, String), Vec<(String, String)>>>,

    /// Bucket ACLs (bucket_name -> AccessControlPolicy)
    pub bucket_acls: Arc<DashMap<String, s3::AccessControlPolicy>>,

    /// Object ACLs ((bucket_name, key) -> AccessControlPolicy)
    pub object_acls: Arc<DashMap<(String, String), s3::AccessControlPolicy>>,

    /// IAM managers for authentication and authorization
    #[cfg(feature = "iam")]
    pub iam: Option<Arc<IamManagers>>,
}

impl<B: StorageBackend> Clone for AppState<B> {
    fn clone(&self) -> Self {
        Self {
            store: Arc::clone(&self.store),
            config: self.config.clone(),
            metrics: self.metrics.clone(),
            uploads: Arc::clone(&self.uploads),
            parts: Arc::clone(&self.parts),
            lifecycle_rules: Arc::clone(&self.lifecycle_rules),
            notification_configs: Arc::clone(&self.notification_configs),
            policy_manager: self.policy_manager.clone(),
            object_lock_manager: self.object_lock_manager.clone(),
            versioning_configs: Arc::clone(&self.versioning_configs),
            encryption_configs: Arc::clone(&self.encryption_configs),
            replication_configs: Arc::clone(&self.replication_configs),
            cors_configs: Arc::clone(&self.cors_configs),
            bucket_tags: Arc::clone(&self.bucket_tags),
            object_tags: Arc::clone(&self.object_tags),
            bucket_acls: Arc::clone(&self.bucket_acls),
            object_acls: Arc::clone(&self.object_acls),
            #[cfg(feature = "iam")]
            iam: self.iam.clone(),
        }
    }
}

impl<B: StorageBackend> AppState<B> {
    /// Add a new multipart upload
    pub fn add_upload(&self, upload_id: String, upload: MultipartUpload) {
        self.uploads.insert(upload_id.clone(), upload);
        self.parts.insert(upload_id, Vec::new());
    }

    /// Get an existing upload
    pub fn get_upload(&self, upload_id: &str) -> Option<MultipartUpload> {
        self.uploads
            .get(upload_id)
            .map(|u: dashmap::mapref::one::Ref<'_, String, MultipartUpload>| u.value().clone())
    }

    /// Add a part to an upload
    pub fn add_part(&self, upload_id: &str, part: PartInfo) {
        if let Some(mut parts) = self.parts.get_mut(upload_id) {
            parts.value_mut().push(part);
        }
    }

    /// Get all parts for an upload
    pub fn get_parts(&self, upload_id: &str) -> Vec<PartInfo> {
        self.parts
            .get(upload_id)
            .map(|p: dashmap::mapref::one::Ref<'_, String, Vec<PartInfo>>| p.value().clone())
            .unwrap_or_default()
    }

    /// Remove an upload and its parts
    pub fn remove_upload(&self, upload_id: &str) {
        self.uploads.remove(upload_id);
        self.parts.remove(upload_id);
    }

    /// Get lifecycle rules for a bucket
    pub fn get_lifecycle_rules(&self, bucket: &str) -> Vec<LifecycleRule> {
        self.lifecycle_rules
            .get(bucket)
            .map(|r| r.value().clone())
            .unwrap_or_default()
    }

    /// Set lifecycle rules for a bucket
    pub fn set_lifecycle_rules(&self, bucket: &str, rules: Vec<LifecycleRule>) {
        if rules.is_empty() {
            self.lifecycle_rules.remove(bucket);
        } else {
            self.lifecycle_rules.insert(bucket.to_string(), rules);
        }
    }

    /// Get notification configuration for a bucket
    pub fn get_notification_config(&self, bucket: &str) -> Option<NotificationConfiguration> {
        self.notification_configs
            .get(bucket)
            .map(|r| r.value().clone())
    }

    /// Set notification configuration for a bucket
    pub fn set_notification_config(&self, bucket: &str, config: NotificationConfiguration) {
        // Check if config is empty (no configurations of any type)
        let is_empty = config.topic_configurations.is_empty()
            && config.queue_configurations.is_empty()
            && config.lambda_function_configurations.is_empty()
            && config.hpc_channel_configurations.is_empty();

        if is_empty {
            self.notification_configs.remove(bucket);
        } else {
            self.notification_configs.insert(bucket.to_string(), config);
        }
    }
}

/// The API server
pub struct ApiServer<B: StorageBackend> {
    state: AppState<B>,
}

impl ApiServer<warp_store::backend::LocalBackend> {
    /// Create a new API server with default local backend
    pub async fn new(store: Store<warp_store::backend::LocalBackend>, config: ApiConfig) -> Self {
        #[cfg(feature = "iam")]
        let iam = if config.enable_iam {
            Some(Arc::new(IamManagers::with_ttl(config.session_ttl_seconds)))
        } else {
            None
        };

        Self {
            state: AppState {
                store: Arc::new(store),
                config,
                metrics: Some(Arc::new(MetricsCollector::new())),
                uploads: Arc::new(DashMap::new()),
                parts: Arc::new(DashMap::new()),
                lifecycle_rules: Arc::new(DashMap::new()),
                notification_configs: Arc::new(DashMap::new()),
                policy_manager: Some(Arc::new(BucketPolicyManager::new())),
                object_lock_manager: Some(Arc::new(ObjectLockManager::new())),
                versioning_configs: Arc::new(DashMap::new()),
                encryption_configs: Arc::new(DashMap::new()),
                replication_configs: Arc::new(DashMap::new()),
                cors_configs: Arc::new(DashMap::new()),
                bucket_tags: Arc::new(DashMap::new()),
                object_tags: Arc::new(DashMap::new()),
                bucket_acls: Arc::new(DashMap::new()),
                object_acls: Arc::new(DashMap::new()),
                #[cfg(feature = "iam")]
                iam,
            },
        }
    }
}

impl<B: StorageBackend> ApiServer<B> {
    /// Create with custom backend
    pub fn with_backend(store: Store<B>, config: ApiConfig) -> Self {
        #[cfg(feature = "iam")]
        let iam = if config.enable_iam {
            Some(Arc::new(IamManagers::with_ttl(config.session_ttl_seconds)))
        } else {
            None
        };

        Self {
            state: AppState {
                store: Arc::new(store),
                config,
                metrics: Some(Arc::new(MetricsCollector::new())),
                uploads: Arc::new(DashMap::new()),
                parts: Arc::new(DashMap::new()),
                lifecycle_rules: Arc::new(DashMap::new()),
                notification_configs: Arc::new(DashMap::new()),
                policy_manager: Some(Arc::new(BucketPolicyManager::new())),
                object_lock_manager: Some(Arc::new(ObjectLockManager::new())),
                versioning_configs: Arc::new(DashMap::new()),
                encryption_configs: Arc::new(DashMap::new()),
                replication_configs: Arc::new(DashMap::new()),
                cors_configs: Arc::new(DashMap::new()),
                bucket_tags: Arc::new(DashMap::new()),
                object_tags: Arc::new(DashMap::new()),
                bucket_acls: Arc::new(DashMap::new()),
                object_acls: Arc::new(DashMap::new()),
                #[cfg(feature = "iam")]
                iam,
            },
        }
    }

    /// Create with custom backend and optional metrics
    pub fn with_backend_and_metrics(
        store: Store<B>,
        config: ApiConfig,
        metrics: Option<Arc<MetricsCollector>>,
    ) -> Self {
        #[cfg(feature = "iam")]
        let iam = if config.enable_iam {
            Some(Arc::new(IamManagers::with_ttl(config.session_ttl_seconds)))
        } else {
            None
        };

        Self {
            state: AppState {
                store: Arc::new(store),
                config,
                metrics,
                uploads: Arc::new(DashMap::new()),
                parts: Arc::new(DashMap::new()),
                lifecycle_rules: Arc::new(DashMap::new()),
                notification_configs: Arc::new(DashMap::new()),
                policy_manager: Some(Arc::new(BucketPolicyManager::new())),
                object_lock_manager: Some(Arc::new(ObjectLockManager::new())),
                versioning_configs: Arc::new(DashMap::new()),
                encryption_configs: Arc::new(DashMap::new()),
                replication_configs: Arc::new(DashMap::new()),
                cors_configs: Arc::new(DashMap::new()),
                bucket_tags: Arc::new(DashMap::new()),
                object_tags: Arc::new(DashMap::new()),
                bucket_acls: Arc::new(DashMap::new()),
                object_acls: Arc::new(DashMap::new()),
                #[cfg(feature = "iam")]
                iam,
            },
        }
    }

    /// Build the router
    pub fn router(&self) -> Router {
        let mut router = Router::new();

        // Add S3 routes
        if self.state.config.enable_s3 {
            router = router.merge(s3::routes(self.state.clone()));
        }

        // Add native HPC routes
        if self.state.config.enable_native {
            router = router.merge(native::routes(self.state.clone()));
        }

        // Add admin API routes
        router = router.merge(admin::routes(self.state.clone()));

        // Add IAM middleware if enabled
        #[cfg(feature = "iam")]
        if let Some(ref iam) = self.state.iam {
            router = router
                .layer(middleware::from_fn_with_state(
                    Arc::clone(iam),
                    auth::iam_authz_middleware,
                ))
                .layer(middleware::from_fn_with_state(
                    Arc::clone(iam),
                    auth::iam_auth_middleware,
                ));
        }

        // Add standard middleware
        router
            .layer(TraceLayer::new_for_http())
            .layer(CorsLayer::permissive())
    }

    /// Run the server
    pub async fn run(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let addr = self.state.config.bind_addr;
        let router = self.router();

        info!(addr = %addr, "Starting warp-store API server");

        let listener = TcpListener::bind(addr).await?;
        axum::serve(listener, router).await?;

        Ok(())
    }
}
