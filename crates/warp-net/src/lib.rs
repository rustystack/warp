//! warp-net: QUIC transport and wire protocol
//!
//! Frame-based protocol over QUIC:
//! - Capability negotiation
//! - Chunk transfer with parallel streams
//! - Deduplication (HAVE/WANT)
//! - Batched acknowledgments

#![warn(missing_docs)]

pub mod codec;
pub mod frames;
pub mod listener;
pub mod pool;
pub mod protocol;
pub mod tls;
pub mod transport;

/// Network error types
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Connection error
    #[error("Connection error: {0}")]
    Connection(String),

    /// Protocol error
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// TLS error
    #[error("TLS error: {0}")]
    Tls(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Configuration(String),
}

/// Result type for network operations
pub type Result<T> = std::result::Result<T, Error>;

// Re-exports for convenience
pub use codec::Frame;
pub use frames::{Capabilities, GpuInfo};
pub use listener::WarpListener;
pub use pool::{FrameBufferPool, PoolStats, PooledBuffer, global_pool};
pub use protocol::{NegotiatedParams, ProtocolState};
#[cfg(any(test, feature = "insecure-tls"))]
pub use tls::client_config_insecure;
pub use tls::{client_config, generate_self_signed, server_config};
pub use transport::{LocalInterface, MultiPathEndpoint, WarpConnection, WarpEndpoint};
