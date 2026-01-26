//! Portal Hub - Distributed storage coordination server
//!
//! This crate provides a central Hub server that coordinates Portal distributed storage:
//! - Edge registration and authentication
//! - Portal metadata management
//! - Encrypted chunk storage (content-addressed)
//! - Encrypted manifest storage
//! - In-memory storage for MVP (no database yet)
//!
//! # Architecture
//!
//! The Hub operates with zero-knowledge principles:
//! - All content is encrypted client-side
//! - Hub only stores encrypted chunks and manifests
//! - Authentication via Ed25519 signatures
//! - Content-addressed storage using BLAKE3 hashes
//!
//! # Example
//!
//! ```no_run
//! use portal_hub::{HubServer, HubConfig};
//! use std::net::SocketAddr;
//!
//! #[tokio::main]
//! async fn main() -> portal_hub::Result<()> {
//!     let config = HubConfig {
//!         bind_addr: "127.0.0.1:8080".parse().unwrap(),
//!         max_chunk_size: 4 * 1024 * 1024, // 4MB
//!     };
//!
//!     let server = HubServer::new(config);
//!     server.run().await
//! }
//! ```

#![warn(missing_docs)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::similar_names)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::manual_string_new)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::redundant_clone)]
#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::significant_drop_tightening)]
#![allow(clippy::field_reassign_with_default)]

pub mod auth;
pub mod ephemeral_auth;
pub mod persistence;
pub mod replication;
pub mod routes;
pub mod server;
pub mod storage;

// Re-exports
pub use persistence::{HybridStorage, PersistentStorage};
pub use replication::{ReplicationConfig, ReplicationManager};
pub use server::{HubConfig, HubServer};
pub use storage::HubStorage;

use portal_core::PortalId;

/// Hub error types
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Portal not found
    #[error("Portal not found: {0}")]
    PortalNotFound(PortalId),

    /// Authentication failed
    #[error("Authentication failed")]
    AuthFailed,

    /// Invalid signature
    #[error("Invalid signature")]
    InvalidSignature,

    /// Storage error
    #[error("Storage error: {0}")]
    Storage(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Invalid content ID
    #[error("Invalid content ID")]
    InvalidContentId,

    /// Chunk not found
    #[error("Chunk not found: {}", hex::encode(.0))]
    ChunkNotFound(portal_core::ContentId),

    /// Edge not found
    #[error("Edge not found: {0}")]
    EdgeNotFound(uuid::Uuid),

    /// Manifest not found
    #[error("Manifest not found: {0}")]
    ManifestNotFound(PortalId),

    /// Chunk too large
    #[error("Chunk too large: {0} bytes (max {1} bytes)")]
    ChunkTooLarge(usize, usize),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Portal core error
    #[error("Portal core error: {0}")]
    PortalCore(#[from] portal_core::Error),

    /// Invalid edge name
    #[error("Invalid edge name: {0}")]
    InvalidEdgeName(String),

    /// Invalid portal name
    #[error("Invalid portal name: {0}")]
    InvalidPortalName(String),

    // Ephemeral access errors
    /// Rate limited
    #[error("Rate limit exceeded")]
    RateLimited,

    /// Resource not found
    #[error("Not found: {0}")]
    NotFound(String),

    /// Resource already exists
    #[error("Already exists: {0}")]
    AlreadyExists(String),

    /// Access denied
    #[error("Access denied: {0}")]
    AccessDenied(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Configuration(String),
}

/// Result type for portal-hub operations
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let portal_id = uuid::Uuid::new_v4();
        let err = Error::PortalNotFound(portal_id);
        assert!(err.to_string().contains("Portal not found"));
        assert!(err.to_string().contains(&portal_id.to_string()));

        let err = Error::AuthFailed;
        assert_eq!(err.to_string(), "Authentication failed");

        let err = Error::InvalidSignature;
        assert_eq!(err.to_string(), "Invalid signature");

        let err = Error::Storage("test error".into());
        assert!(err.to_string().contains("Storage error"));
        assert!(err.to_string().contains("test error"));

        let err = Error::ChunkTooLarge(5_000_000, 4_000_000);
        assert!(err.to_string().contains("Chunk too large"));
        assert!(err.to_string().contains("5000000"));
        assert!(err.to_string().contains("4000000"));
    }

    #[test]
    fn test_error_variants() {
        let content_id = [1u8; 32];
        let err = Error::ChunkNotFound(content_id);
        assert!(matches!(err, Error::ChunkNotFound(_)));

        let edge_id = uuid::Uuid::new_v4();
        let err = Error::EdgeNotFound(edge_id);
        assert!(matches!(err, Error::EdgeNotFound(_)));

        let portal_id = uuid::Uuid::new_v4();
        let err = Error::ManifestNotFound(portal_id);
        assert!(matches!(err, Error::ManifestNotFound(_)));
    }
}
