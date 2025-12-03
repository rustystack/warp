//! Portal Network - P2P mesh networking for Portal distributed storage
//!
//! This crate provides the networking layer for Portal, implementing:
//! - Virtual IP management in the 10.portal.0.0/16 subnet
//! - Peer-to-peer mesh networking with WireGuard integration
//! - mDNS-based local peer discovery
//! - Hub-based coordination and NAT traversal
//! - Connection mode tracking (direct P2P vs relayed)

pub mod allocator;
pub mod coordinator;
pub mod discovery;
pub mod manager;
pub mod peer;
pub mod types;

pub use types::{
    HubNetConfig, MdnsConfig, NetworkConfig, NetworkEvent, PeerConfig, PeerMetadata, PeerStatus,
    VirtualIp,
};

use thiserror::Error;

/// Portal network errors
#[derive(Debug, Error)]
pub enum PortalNetError {
    /// Invalid virtual IP address (outside 10.0.0.0/16 subnet)
    #[error("invalid virtual IP address: {0}")]
    InvalidVirtualIp(String),

    /// Invalid public key format
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Network I/O error
    #[error("network I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Peer not found
    #[error("peer not found: {0}")]
    PeerNotFound(String),

    /// Configuration error
    #[error("configuration error: {0}")]
    Configuration(String),

    /// mDNS discovery error
    #[error("mDNS error: {0}")]
    Mdns(String),

    /// Hub connection error
    #[error("hub connection error: {0}")]
    HubConnection(String),

    /// Transport layer error (QUIC/WireGuard)
    #[error("transport error: {0}")]
    Transport(String),
}

/// Result type for portal-net operations
pub type Result<T> = std::result::Result<T, PortalNetError>;
