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

pub mod auth;
pub mod error;
pub mod native;
pub mod s3;

pub use error::{ApiError, ApiResult};

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::info;

use warp_store::{Store, StoreConfig};
use warp_store::backend::StorageBackend;

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
        }
    }
}

/// Shared application state
pub struct AppState<B: StorageBackend> {
    /// The storage backend
    pub store: Arc<Store<B>>,

    /// API configuration
    pub config: ApiConfig,
}

impl<B: StorageBackend> Clone for AppState<B> {
    fn clone(&self) -> Self {
        Self {
            store: Arc::clone(&self.store),
            config: self.config.clone(),
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
        Self {
            state: AppState {
                store: Arc::new(store),
                config,
            },
        }
    }
}

impl<B: StorageBackend> ApiServer<B> {
    /// Create with custom backend
    pub fn with_backend(store: Store<B>, config: ApiConfig) -> Self {
        Self {
            state: AppState {
                store: Arc::new(store),
                config,
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

        // Add middleware
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
