//! NVMe-oF Transport Abstraction Layer
//!
//! This module defines the transport abstraction for NVMe-oF, supporting
//! multiple transport types: TCP, RDMA, and QUIC.

use async_trait::async_trait;
use bytes::Bytes;
use std::fmt;
use std::net::SocketAddr;

use super::capsule::{CommandCapsule, ResponseCapsule};
use super::config::TransportType;
use super::error::NvmeOfResult;

#[cfg(feature = "nvmeof")]
pub mod tcp;

#[cfg(feature = "nvmeof-rdma")]
pub mod rdma;

#[cfg(feature = "nvmeof-quic")]
pub mod quic;

/// Transport capabilities
#[derive(Debug, Clone)]
pub struct TransportCapabilities {
    /// Maximum inline data size
    pub max_inline_data: u32,

    /// Maximum I/O size
    pub max_io_size: u32,

    /// Supports header digest
    pub header_digest: bool,

    /// Supports data digest
    pub data_digest: bool,

    /// Supports zero-copy
    pub zero_copy: bool,

    /// Supports memory registration (RDMA)
    pub memory_registration: bool,

    /// Supports multiple streams (QUIC)
    pub multi_stream: bool,
}

impl Default for TransportCapabilities {
    fn default() -> Self {
        Self {
            max_inline_data: 8192,
            max_io_size: 1024 * 1024,
            header_digest: false,
            data_digest: false,
            zero_copy: false,
            memory_registration: false,
            multi_stream: false,
        }
    }
}

/// Transport address for connection
#[derive(Debug, Clone)]
pub struct TransportAddress {
    /// Transport type
    pub transport: TransportType,

    /// Socket address
    pub addr: SocketAddr,

    /// Additional service identifier (for RDMA GID, etc.)
    pub service_id: Option<String>,
}

impl TransportAddress {
    /// Create a new TCP transport address
    pub fn tcp(addr: SocketAddr) -> Self {
        Self {
            transport: TransportType::Tcp,
            addr,
            service_id: None,
        }
    }

    /// Create a new RDMA transport address
    pub fn rdma(addr: SocketAddr, gid: Option<String>) -> Self {
        Self {
            transport: TransportType::Rdma,
            addr,
            service_id: gid,
        }
    }
}

impl fmt::Display for TransportAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}", self.transport.as_str(), self.addr)
    }
}

/// Transport layer trait for NVMe-oF
///
/// This trait abstracts the underlying transport mechanism, allowing
/// the NVMe-oF target to work with TCP, RDMA, or QUIC.
#[async_trait]
pub trait NvmeOfTransport: Send + Sync + 'static {
    /// Get the transport type
    fn transport_type(&self) -> TransportType;

    /// Get transport capabilities
    fn capabilities(&self) -> TransportCapabilities;

    /// Bind to an address and start listening
    async fn bind(&mut self, addr: SocketAddr) -> NvmeOfResult<()>;

    /// Accept an incoming connection
    async fn accept(&self) -> NvmeOfResult<Box<dyn TransportConnection>>;

    /// Connect to a remote target (for initiator)
    async fn connect(&self, addr: &TransportAddress) -> NvmeOfResult<Box<dyn TransportConnection>>;

    /// Close the transport listener
    async fn close(&self) -> NvmeOfResult<()>;

    /// Get the local address the transport is bound to
    async fn local_addr(&self) -> NvmeOfResult<SocketAddr>;
}

/// Individual transport connection
#[async_trait]
pub trait TransportConnection: Send + Sync {
    /// Get the remote address
    fn remote_addr(&self) -> SocketAddr;

    /// Get the local address
    fn local_addr(&self) -> SocketAddr;

    /// Get the transport type
    fn transport_type(&self) -> TransportType;

    /// Initialize connection as target (perform ICReq/ICResp handshake)
    async fn initialize_as_target(&self) -> NvmeOfResult<()>;

    /// Initialize connection as initiator (perform ICReq/ICResp handshake)
    async fn initialize_as_initiator(&self) -> NvmeOfResult<()>;

    /// Send a command capsule (for initiator)
    async fn send_command(&self, capsule: &CommandCapsule) -> NvmeOfResult<()>;

    /// Receive a command capsule (for target)
    async fn recv_command(&self) -> NvmeOfResult<CommandCapsule>;

    /// Send a response capsule (for target)
    async fn send_response(&self, capsule: &ResponseCapsule) -> NvmeOfResult<()>;

    /// Receive a response capsule (for initiator)
    async fn recv_response(&self) -> NvmeOfResult<ResponseCapsule>;

    /// Send data (for C2H data transfer)
    async fn send_data(&self, data: Bytes, offset: u64) -> NvmeOfResult<()>;

    /// Receive data (for H2C data transfer)
    async fn recv_data(&self, length: usize) -> NvmeOfResult<Bytes>;

    /// Check if connection is still alive
    fn is_connected(&self) -> bool;

    /// Close the connection
    async fn close(&self) -> NvmeOfResult<()>;

    /// Get connection ID
    fn connection_id(&self) -> u64;
}

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Connection is being established
    Connecting,

    /// Initial connection setup (ICReq/ICResp)
    Initializing,

    /// Ready for NVMe commands
    Ready,

    /// Shutting down
    Closing,

    /// Closed
    Closed,

    /// Error state
    Error,
}

impl fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connecting => write!(f, "connecting"),
            Self::Initializing => write!(f, "initializing"),
            Self::Ready => write!(f, "ready"),
            Self::Closing => write!(f, "closing"),
            Self::Closed => write!(f, "closed"),
            Self::Error => write!(f, "error"),
        }
    }
}

/// Transport statistics
#[derive(Debug, Clone, Default)]
pub struct TransportStats {
    /// Total bytes sent
    pub bytes_sent: u64,

    /// Total bytes received
    pub bytes_received: u64,

    /// Commands sent
    pub commands_sent: u64,

    /// Commands received
    pub commands_received: u64,

    /// Responses sent
    pub responses_sent: u64,

    /// Responses received
    pub responses_received: u64,

    /// Errors encountered
    pub errors: u64,

    /// Current queue depth
    pub queue_depth: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_transport_address_display() {
        let addr = TransportAddress::tcp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            4420,
        ));
        assert_eq!(addr.to_string(), "tcp://192.168.1.100:4420");
    }

    #[test]
    fn test_connection_state_display() {
        assert_eq!(ConnectionState::Ready.to_string(), "ready");
        assert_eq!(ConnectionState::Connecting.to_string(), "connecting");
    }
}
