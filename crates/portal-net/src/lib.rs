// Allow pedantic clippy lints for this crate
#![allow(clippy::significant_drop_tightening)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::use_self)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::unused_async)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::redundant_clone)]
#![allow(clippy::redundant_closure)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::collection_is_never_read)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::cast_sign_loss)]
#![allow(unused_must_use)]

//! Portal Network - P2P mesh networking for Portal distributed storage
//!
//! This crate provides the networking layer for Portal, implementing:
//! - Virtual IP management in the 10.portal.0.0/16 subnet
//! - Peer-to-peer mesh networking with `WireGuard` integration
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
