//! QUIC transport implementation using quinn

use crate::codec::Frame;
use crate::frames::Capabilities;
use crate::pool::global_pool;
use crate::protocol::{NegotiatedParams, ProtocolState};
#[cfg(any(test, feature = "insecure-tls"))]
use crate::tls::client_config_insecure;
use crate::tls::{client_config, generate_self_signed, server_config};
use crate::{Error, Result};
use bytes::Bytes;
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Control stream pair - always updated atomically to prevent TOCTOU races
struct ControlStreams {
    send: Option<SendStream>,
    recv: Option<RecvStream>,
}

/// Protocol version
const PROTOCOL_VERSION: u32 = 1;

/// Maximum receive buffer size
const MAX_RECV_BUF: usize = 16 * 1024 * 1024;

/// QUIC connection wrapper
pub struct WarpConnection {
    connection: Connection,
    state: Arc<Mutex<ProtocolState>>,
    local_caps: Capabilities,
    remote_caps: Arc<Mutex<Option<Capabilities>>>,
    params: Arc<Mutex<Option<NegotiatedParams>>>,
    /// Control streams protected by single mutex to prevent TOCTOU races
    control: Arc<Mutex<ControlStreams>>,
}

impl WarpConnection {
    /// Create a new connection wrapper
    fn new(connection: Connection, local_caps: Capabilities) -> Self {
        Self {
            connection,
            state: Arc::new(Mutex::new(ProtocolState::Initial)),
            local_caps,
            remote_caps: Arc::new(Mutex::new(None)),
            params: Arc::new(Mutex::new(None)),
            control: Arc::new(Mutex::new(ControlStreams {
                send: None,
                recv: None,
            })),
        }
    }

    /// Create from quinn connection (public for listener)
    pub fn from_quinn(connection: Connection, local_caps: Capabilities) -> Self {
        Self::new(connection, local_caps)
    }

    /// Get remote address
    pub fn remote_addr(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    /// Get local address (IP only, port unknown)
    pub fn local_ip(&self) -> Option<std::net::IpAddr> {
        self.connection.local_ip()
    }

    /// Get current round-trip time estimate in microseconds
    ///
    /// Returns the smoothed RTT estimate from QUIC congestion control.
    /// This is useful for dynamic path adaptation and congestion detection.
    pub fn rtt_us(&self) -> std::result::Result<u32, Error> {
        let rtt = self.connection.rtt();
        let rtt_us = rtt.as_micros();
        if rtt_us > u32::MAX as u128 {
            // RTT > 71 minutes is unreasonable, clamp to max
            Ok(u32::MAX)
        } else {
            Ok(rtt_us as u32)
        }
    }

    /// Get current protocol state
    pub async fn state(&self) -> ProtocolState {
        *self.state.lock().await
    }

    /// Get negotiated parameters
    pub async fn params(&self) -> Option<NegotiatedParams> {
        self.params.lock().await.clone()
    }

    /// Open a new bidirectional stream
    pub async fn open_stream(&self) -> Result<(SendStream, RecvStream)> {
        self.connection
            .open_bi()
            .await
            .map_err(|e| Error::Connection(format!("Failed to open stream: {}", e)))
    }

    /// Open the control stream (client side)
    ///
    /// Both send and recv are set atomically under a single lock to prevent TOCTOU races.
    async fn open_control_stream(&self) -> Result<()> {
        let (send, recv) = self.open_stream().await?;
        let mut control = self.control.lock().await;
        control.send = Some(send);
        control.recv = Some(recv);
        Ok(())
    }

    /// Accept the control stream (server side)
    ///
    /// Both send and recv are set atomically under a single lock to prevent TOCTOU races.
    async fn accept_control_stream(&self) -> Result<()> {
        let (send, recv) =
            self.connection.accept_bi().await.map_err(|e| {
                Error::Connection(format!("Failed to accept control stream: {}", e))
            })?;
        let mut control = self.control.lock().await;
        control.send = Some(send);
        control.recv = Some(recv);
        Ok(())
    }

    /// Send a frame on the control stream
    pub async fn send_frame(&self, frame: Frame) -> Result<()> {
        // Use pooled buffer to avoid allocation on every frame
        let pool = global_pool();
        let mut pooled_buf = pool.get_medium();
        frame.encode(&mut pooled_buf)?;

        tracing::trace!("Sending frame: {:?}", frame.frame_type());

        let mut control = self.control.lock().await;
        let send = control
            .send
            .as_mut()
            .ok_or_else(|| Error::Protocol("Control stream not open".into()))?;

        send.write_all(&pooled_buf)
            .await
            .map_err(|e| Error::Connection(format!("Failed to send frame: {}", e)))?;

        drop(control);
        // pooled_buf returned to pool on drop

        Ok(())
    }

    /// Receive a frame from the control stream
    pub async fn recv_frame(&self) -> Result<Frame> {
        let mut control = self.control.lock().await;
        let recv = control
            .recv
            .as_mut()
            .ok_or_else(|| Error::Protocol("Control stream not open".into()))?;

        // Use pooled buffer to avoid allocation on every frame
        let pool = global_pool();
        let mut pooled_buf = pool.get_medium();
        loop {
            let chunk = recv
                .read_chunk(MAX_RECV_BUF, true)
                .await
                .map_err(|e| Error::Connection(format!("Failed to receive: {}", e)))?
                .ok_or_else(|| Error::Connection("Connection closed".into()))?;

            pooled_buf.extend_from_slice(&chunk.bytes);

            if let Some(frame) = Frame::decode(&mut pooled_buf)? {
                tracing::trace!("Received frame: {:?}", frame.frame_type());
                // pooled_buf returned to pool on drop
                return Ok(frame);
            }
        }
    }

    /// Perform client-side handshake (opens control stream, sends first)
    pub async fn handshake(&self) -> Result<NegotiatedParams> {
        self.open_control_stream().await?;
        *self.state.lock().await = ProtocolState::Initial;

        self.send_frame(Frame::Hello {
            version: PROTOCOL_VERSION,
        })
        .await?;

        let hello_frame = self.recv_frame().await?;
        match hello_frame {
            Frame::Hello { version } => {
                if version != PROTOCOL_VERSION {
                    return Err(Error::Protocol(format!(
                        "Unsupported protocol version: {}",
                        version
                    )));
                }
            }
            _ => return Err(Error::Protocol("Expected HELLO frame".into())),
        }

        *self.state.lock().await = ProtocolState::HelloExchanged;

        self.send_frame(Frame::Capabilities(self.local_caps.clone()))
            .await?;

        let caps_frame = self.recv_frame().await?;
        let remote_caps = match caps_frame {
            Frame::Capabilities(caps) => caps,
            _ => return Err(Error::Protocol("Expected CAPABILITIES frame".into())),
        };

        let params = NegotiatedParams::negotiate(&self.local_caps, &remote_caps);

        *self.remote_caps.lock().await = Some(remote_caps);
        *self.params.lock().await = Some(params.clone());
        *self.state.lock().await = ProtocolState::Negotiated;

        tracing::info!(
            "Client handshake complete: compression={}, chunk_size={}, streams={}",
            params.compression,
            params.chunk_size,
            params.parallel_streams
        );

        Ok(params)
    }

    /// Perform server-side handshake (accepts control stream, receives first)
    pub async fn handshake_server(&self) -> Result<NegotiatedParams> {
        self.accept_control_stream().await?;
        *self.state.lock().await = ProtocolState::Initial;

        let hello_frame = self.recv_frame().await?;
        match hello_frame {
            Frame::Hello { version } => {
                if version != PROTOCOL_VERSION {
                    return Err(Error::Protocol(format!(
                        "Unsupported protocol version: {}",
                        version
                    )));
                }
            }
            _ => return Err(Error::Protocol("Expected HELLO frame".into())),
        }

        self.send_frame(Frame::Hello {
            version: PROTOCOL_VERSION,
        })
        .await?;

        *self.state.lock().await = ProtocolState::HelloExchanged;

        let caps_frame = self.recv_frame().await?;
        let remote_caps = match caps_frame {
            Frame::Capabilities(caps) => caps,
            _ => return Err(Error::Protocol("Expected CAPABILITIES frame".into())),
        };

        self.send_frame(Frame::Capabilities(self.local_caps.clone()))
            .await?;

        let params = NegotiatedParams::negotiate(&self.local_caps, &remote_caps);

        *self.remote_caps.lock().await = Some(remote_caps);
        *self.params.lock().await = Some(params.clone());
        *self.state.lock().await = ProtocolState::Negotiated;

        tracing::info!(
            "Server handshake complete: compression={}, chunk_size={}, streams={}",
            params.compression,
            params.chunk_size,
            params.parallel_streams
        );

        Ok(params)
    }

    /// Send chunk data on a new stream (zero-copy)
    pub async fn send_chunk(&self, chunk_id: u32, data: Bytes) -> Result<()> {
        let (mut send, _recv) = self.open_stream().await?;

        let frame = Frame::Chunk { chunk_id, data };

        // Use pooled buffer - size based on typical chunk header + small data
        let pool = global_pool();
        let mut pooled_buf = pool.get_large();
        frame.encode(&mut pooled_buf)?;

        send.write_all(&pooled_buf)
            .await
            .map_err(|e| Error::Connection(format!("Failed to send chunk: {}", e)))?;

        send.finish()
            .map_err(|e| Error::Connection(format!("Failed to finish stream: {}", e)))?;

        Ok(())
    }

    /// Receive chunk data from a stream (zero-copy)
    pub async fn recv_chunk(&self) -> Result<(u32, Bytes)> {
        let (_send, mut recv) = self
            .connection
            .accept_bi()
            .await
            .map_err(|e| Error::Connection(format!("Failed to accept stream: {}", e)))?;

        // Use pooled buffer for chunk reception
        let pool = global_pool();
        let mut pooled_buf = pool.get_large();
        loop {
            let chunk = recv
                .read_chunk(MAX_RECV_BUF, true)
                .await
                .map_err(|e| Error::Connection(format!("Failed to receive chunk: {}", e)))?;

            match chunk {
                Some(chunk_data) => {
                    pooled_buf.extend_from_slice(&chunk_data.bytes);

                    if let Some(frame) = Frame::decode(&mut pooled_buf)? {
                        match frame {
                            Frame::Chunk { chunk_id, data } => return Ok((chunk_id, data)),
                            _ => return Err(Error::Protocol("Expected CHUNK frame".into())),
                        }
                    }
                }
                None => {
                    return Err(Error::Connection("Stream closed prematurely".into()));
                }
            }
        }
    }

    /// Send chunk batch on a new stream (zero-copy)
    pub async fn send_chunk_batch(&self, chunks: Vec<(u32, Bytes)>) -> Result<()> {
        let (mut send, _recv) = self.open_stream().await?;

        let frame = Frame::ChunkBatch { chunks };

        // Use pooled buffer - large buffer for batch data
        let pool = global_pool();
        let mut pooled_buf = pool.get_large();
        frame.encode(&mut pooled_buf)?;

        send.write_all(&pooled_buf)
            .await
            .map_err(|e| Error::Connection(format!("Failed to send batch: {}", e)))?;

        send.finish()
            .map_err(|e| Error::Connection(format!("Failed to finish stream: {}", e)))?;

        Ok(())
    }

    /// Close connection gracefully
    pub async fn close(&self) -> Result<()> {
        self.connection.close(0u32.into(), b"normal close");
        Ok(())
    }

    /// Wait for connection to be closed
    pub async fn closed(&self) {
        self.connection.closed().await;
    }
}

/// QUIC endpoint wrapper
pub struct WarpEndpoint {
    endpoint: Endpoint,
    is_server: bool,
    local_caps: Capabilities,
}

impl WarpEndpoint {
    /// Create a client endpoint (insecure, for testing only)
    ///
    /// # Safety
    ///
    /// This function creates a client that skips TLS certificate verification.
    /// It is vulnerable to MITM attacks and should ONLY be used for testing.
    #[cfg(any(test, feature = "insecure-tls"))]
    pub async fn client() -> Result<Self> {
        Self::client_with_caps(Capabilities::default()).await
    }

    /// Create a client endpoint with custom capabilities (insecure, for testing only)
    ///
    /// # Safety
    ///
    /// This function creates a client that skips TLS certificate verification.
    /// It is vulnerable to MITM attacks and should ONLY be used for testing.
    #[cfg(any(test, feature = "insecure-tls"))]
    pub async fn client_with_caps(caps: Capabilities) -> Result<Self> {
        let rustls_config = client_config_insecure()?;
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| Error::Connection(format!("Failed to create client endpoint: {}", e)))?;

        let quinn_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config)
                .map_err(|e| Error::Tls(format!("Failed to create QUIC client config: {}", e)))?,
        ));

        endpoint.set_default_client_config(quinn_config);

        Ok(Self {
            endpoint,
            is_server: false,
            local_caps: caps,
        })
    }

    /// Create a secure client endpoint with custom root certificate store
    ///
    /// This is the recommended way to create a client for production use.
    /// Validates server certificates against the provided root store.
    pub async fn client_secure(roots: rustls::RootCertStore) -> Result<Self> {
        Self::client_secure_with_caps(roots, Capabilities::default()).await
    }

    /// Create a secure client endpoint with custom capabilities and root certificate store
    ///
    /// This is the recommended way to create a client for production use.
    /// Validates server certificates against the provided root store.
    pub async fn client_secure_with_caps(
        roots: rustls::RootCertStore,
        caps: Capabilities,
    ) -> Result<Self> {
        let rustls_config = client_config(roots)?;
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| Error::Connection(format!("Failed to create client endpoint: {}", e)))?;

        let quinn_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config)
                .map_err(|e| Error::Tls(format!("Failed to create QUIC client config: {}", e)))?,
        ));

        endpoint.set_default_client_config(quinn_config);

        Ok(Self {
            endpoint,
            is_server: false,
            local_caps: caps,
        })
    }

    /// Create a server endpoint
    pub async fn server(bind: SocketAddr) -> Result<Self> {
        Self::server_with_caps(bind, Capabilities::default()).await
    }

    /// Create a server endpoint with custom capabilities
    pub async fn server_with_caps(bind: SocketAddr, caps: Capabilities) -> Result<Self> {
        let (cert_chain, key) = generate_self_signed()?;
        let tls_config = server_config(cert_chain, key)?;

        let server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
                .map_err(|e| Error::Tls(format!("Failed to create QUIC config: {}", e)))?,
        ));

        let endpoint = Endpoint::server(server_config, bind)
            .map_err(|e| Error::Connection(format!("Failed to create server endpoint: {}", e)))?;

        Ok(Self {
            endpoint,
            is_server: true,
            local_caps: caps,
        })
    }

    /// Connect to a remote server
    pub async fn connect(&self, addr: SocketAddr, server_name: &str) -> Result<WarpConnection> {
        if self.is_server {
            return Err(Error::Connection(
                "Cannot connect from server endpoint".into(),
            ));
        }

        let connection = self
            .endpoint
            .connect(addr, server_name)
            .map_err(|e| Error::Connection(format!("Failed to connect: {}", e)))?
            .await
            .map_err(|e| Error::Connection(format!("Connection failed: {}", e)))?;

        tracing::info!("Connected to {}", addr);

        Ok(WarpConnection::new(connection, self.local_caps.clone()))
    }

    /// Accept an incoming connection (server only)
    pub async fn accept(&self) -> Result<WarpConnection> {
        if !self.is_server {
            return Err(Error::Connection("Cannot accept on client endpoint".into()));
        }

        let connecting = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| Error::Connection("Endpoint closed".into()))?;

        let connection = connecting
            .await
            .map_err(|e| Error::Connection(format!("Failed to accept connection: {}", e)))?;

        let remote = connection.remote_address();
        tracing::info!("Accepted connection from {}", remote);

        Ok(WarpConnection::new(connection, self.local_caps.clone()))
    }

    /// Get local bound address
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint
            .local_addr()
            .map_err(|e| Error::Connection(format!("Failed to get local address: {}", e)))
    }

    /// Wait for endpoint to be idle
    pub async fn wait_idle(&self) {
        self.endpoint.wait_idle().await;
    }

    /// Close the endpoint
    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"endpoint closed");
    }
}

// ============================================================================
// Multi-Path Network Aggregation Types
// ============================================================================

/// Configuration for a local network interface
///
/// Represents a local IP address that can be used as a source for outgoing
/// connections. Used for multi-path network aggregation where traffic is
/// distributed across multiple physical network interfaces.
#[derive(Debug, Clone)]
pub struct LocalInterface {
    /// Local IP address to bind outgoing connections to
    pub bind_ip: std::net::IpAddr,

    /// Optional human-readable label (e.g., "eth0", "bond0", "10gbe-1")
    pub label: Option<String>,

    /// Optional interface capacity in bits per second
    /// Used for weighted load balancing across interfaces
    pub capacity_bps: Option<u64>,

    /// Whether this interface is currently enabled
    pub enabled: bool,
}

impl LocalInterface {
    /// Create a new local interface configuration
    pub fn new(bind_ip: std::net::IpAddr) -> Self {
        Self {
            bind_ip,
            label: None,
            capacity_bps: None,
            enabled: true,
        }
    }

    /// Builder: set label
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Builder: set capacity
    pub fn with_capacity(mut self, capacity_bps: u64) -> Self {
        self.capacity_bps = Some(capacity_bps);
        self
    }

    /// Builder: set enabled state
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Generate a binding address with ephemeral port
    pub fn bind_addr(&self) -> SocketAddr {
        SocketAddr::new(self.bind_ip, 0)
    }
}

impl std::fmt::Display for LocalInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ref label) = self.label {
            write!(f, "{}({})", label, self.bind_ip)
        } else {
            write!(f, "{}", self.bind_ip)
        }
    }
}

/// Multi-path endpoint manager
///
/// Manages multiple QUIC endpoints, each bound to a different local IP address.
/// This enables multi-path network aggregation where connections can be
/// explicitly routed through specific network interfaces.
///
/// # Example
///
/// ```ignore
/// let interfaces = vec![
///     LocalInterface::new("10.10.10.1".parse().unwrap()).with_label("eth0"),
///     LocalInterface::new("10.10.11.1".parse().unwrap()).with_label("eth1"),
/// ];
///
/// let multi_ep = MultiPathEndpoint::new(interfaces).await?;
///
/// // Connect via specific interface
/// let conn1 = multi_ep.connect_via(
///     "10.10.10.1".parse().unwrap(),
///     "10.10.10.2:51820".parse().unwrap(),
///     "peer1"
/// ).await?;
/// ```
pub struct MultiPathEndpoint {
    /// Map of local IP to quinn Endpoint
    endpoints: std::collections::HashMap<std::net::IpAddr, Endpoint>,

    /// Configuration for each interface
    interfaces: Vec<LocalInterface>,

    /// QUIC client configuration (shared across all endpoints)
    client_config: quinn::ClientConfig,

    /// Local capabilities
    local_caps: Capabilities,
}

impl MultiPathEndpoint {
    /// Create a new multi-path endpoint with the given interfaces (insecure, for testing)
    ///
    /// Each interface gets its own QUIC endpoint bound to that specific IP address.
    /// This ensures outgoing connections use the correct source IP for each path.
    #[cfg(any(test, feature = "insecure-tls"))]
    pub async fn new(interfaces: Vec<LocalInterface>) -> Result<Self> {
        Self::new_with_caps(interfaces, Capabilities::default()).await
    }

    /// Create a new multi-path endpoint with custom capabilities (insecure, for testing)
    #[cfg(any(test, feature = "insecure-tls"))]
    pub async fn new_with_caps(
        interfaces: Vec<LocalInterface>,
        caps: Capabilities,
    ) -> Result<Self> {
        let rustls_config = client_config_insecure()?;
        let quinn_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config)
                .map_err(|e| Error::Tls(format!("Failed to create QUIC client config: {}", e)))?,
        ));

        Self::create_endpoints(interfaces, quinn_config, caps).await
    }

    /// Create a new secure multi-path endpoint with root certificate store
    pub async fn new_secure(
        interfaces: Vec<LocalInterface>,
        roots: rustls::RootCertStore,
    ) -> Result<Self> {
        Self::new_secure_with_caps(interfaces, roots, Capabilities::default()).await
    }

    /// Create a new secure multi-path endpoint with custom capabilities
    pub async fn new_secure_with_caps(
        interfaces: Vec<LocalInterface>,
        roots: rustls::RootCertStore,
        caps: Capabilities,
    ) -> Result<Self> {
        let rustls_config = client_config(roots)?;
        let quinn_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config)
                .map_err(|e| Error::Tls(format!("Failed to create QUIC client config: {}", e)))?,
        ));

        Self::create_endpoints(interfaces, quinn_config, caps).await
    }

    /// Internal helper to create endpoints for each interface
    async fn create_endpoints(
        interfaces: Vec<LocalInterface>,
        quinn_config: quinn::ClientConfig,
        caps: Capabilities,
    ) -> Result<Self> {
        let mut endpoints = std::collections::HashMap::new();

        for iface in &interfaces {
            if !iface.enabled {
                tracing::debug!("Skipping disabled interface: {}", iface);
                continue;
            }

            let bind_addr = iface.bind_addr();
            let mut endpoint = Endpoint::client(bind_addr).map_err(|e| {
                Error::Connection(format!(
                    "Failed to create endpoint bound to {}: {}",
                    bind_addr, e
                ))
            })?;

            endpoint.set_default_client_config(quinn_config.clone());
            endpoints.insert(iface.bind_ip, endpoint);

            tracing::info!(
                "Created multi-path endpoint bound to {} (label: {:?})",
                bind_addr,
                iface.label
            );
        }

        if endpoints.is_empty() {
            return Err(Error::Configuration(
                "No enabled interfaces provided for multi-path endpoint".into(),
            ));
        }

        Ok(Self {
            endpoints,
            interfaces,
            client_config: quinn_config,
            local_caps: caps,
        })
    }

    /// Connect to a remote address using a specific local interface
    ///
    /// This is the key method for multi-path aggregation - it ensures the
    /// connection is bound to the specified local IP, guaranteeing traffic
    /// flows through the correct physical NIC.
    pub async fn connect_via(
        &self,
        local_ip: std::net::IpAddr,
        remote_addr: SocketAddr,
        server_name: &str,
    ) -> Result<WarpConnection> {
        let endpoint = self.endpoints.get(&local_ip).ok_or_else(|| {
            Error::Connection(format!("No endpoint bound to local IP {}", local_ip))
        })?;

        let connection = endpoint
            .connect(remote_addr, server_name)
            .map_err(|e| Error::Connection(format!("Failed to initiate connection: {}", e)))?
            .await
            .map_err(|e| Error::Connection(format!("Connection failed: {}", e)))?;

        tracing::info!(
            "Multi-path connection established: {} -> {}",
            local_ip,
            remote_addr
        );

        Ok(WarpConnection::new(connection, self.local_caps.clone()))
    }

    /// Connect to a remote address using any available interface
    ///
    /// Selects the first available enabled interface. For load balancing,
    /// use `connect_via` with explicit interface selection.
    pub async fn connect(
        &self,
        remote_addr: SocketAddr,
        server_name: &str,
    ) -> Result<WarpConnection> {
        // Use first available interface
        let local_ip = self
            .interfaces
            .iter()
            .find(|i| i.enabled)
            .map(|i| i.bind_ip)
            .ok_or_else(|| Error::Connection("No enabled interfaces available".into()))?;

        self.connect_via(local_ip, remote_addr, server_name).await
    }

    /// Get all available local interface IPs
    pub fn local_ips(&self) -> Vec<std::net::IpAddr> {
        self.endpoints.keys().copied().collect()
    }

    /// Get all configured interfaces
    pub fn interfaces(&self) -> &[LocalInterface] {
        &self.interfaces
    }

    /// Get enabled interface count
    pub fn enabled_interface_count(&self) -> usize {
        self.interfaces.iter().filter(|i| i.enabled).count()
    }

    /// Get interface by IP
    pub fn get_interface(&self, ip: std::net::IpAddr) -> Option<&LocalInterface> {
        self.interfaces.iter().find(|i| i.bind_ip == ip)
    }

    /// Check if an interface is available
    pub fn has_interface(&self, ip: std::net::IpAddr) -> bool {
        self.endpoints.contains_key(&ip)
    }

    /// Add a new interface at runtime
    ///
    /// Creates a new QUIC endpoint bound to the interface's IP address.
    pub async fn add_interface(&mut self, iface: LocalInterface) -> Result<()> {
        if self.endpoints.contains_key(&iface.bind_ip) {
            return Err(Error::Configuration(format!(
                "Interface {} already exists",
                iface.bind_ip
            )));
        }

        if iface.enabled {
            let bind_addr = iface.bind_addr();
            let mut endpoint = Endpoint::client(bind_addr).map_err(|e| {
                Error::Connection(format!(
                    "Failed to create endpoint bound to {}: {}",
                    bind_addr, e
                ))
            })?;

            endpoint.set_default_client_config(self.client_config.clone());
            self.endpoints.insert(iface.bind_ip, endpoint);

            tracing::info!("Added multi-path interface: {}", iface);
        }

        self.interfaces.push(iface);
        Ok(())
    }

    /// Remove an interface at runtime
    ///
    /// Closes the endpoint and removes it from the pool.
    pub fn remove_interface(&mut self, ip: std::net::IpAddr) -> Option<LocalInterface> {
        if let Some(endpoint) = self.endpoints.remove(&ip) {
            endpoint.close(0u32.into(), b"interface removed");
        }

        if let Some(idx) = self.interfaces.iter().position(|i| i.bind_ip == ip) {
            Some(self.interfaces.remove(idx))
        } else {
            None
        }
    }

    /// Close all endpoints
    pub fn close(&self) {
        for endpoint in self.endpoints.values() {
            endpoint.close(0u32.into(), b"multi-path endpoint closed");
        }
    }

    /// Wait for all endpoints to be idle
    pub async fn wait_idle(&self) {
        for endpoint in self.endpoints.values() {
            endpoint.wait_idle().await;
        }
    }
}

impl std::fmt::Debug for MultiPathEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiPathEndpoint")
            .field("interfaces", &self.interfaces)
            .field("endpoint_count", &self.endpoints.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // LocalInterface Tests
    // =========================================================================

    #[test]
    fn test_local_interface_creation() {
        let iface = LocalInterface::new("10.10.10.1".parse().unwrap());
        assert_eq!(
            iface.bind_ip,
            "10.10.10.1".parse::<std::net::IpAddr>().unwrap()
        );
        assert!(iface.enabled);
        assert!(iface.label.is_none());
        assert!(iface.capacity_bps.is_none());
    }

    #[test]
    fn test_local_interface_builders() {
        let iface = LocalInterface::new("192.168.1.100".parse().unwrap())
            .with_label("eth0")
            .with_capacity(10_000_000_000) // 10 Gbps
            .with_enabled(true);

        assert_eq!(
            iface.bind_ip,
            "192.168.1.100".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(iface.label, Some("eth0".to_string()));
        assert_eq!(iface.capacity_bps, Some(10_000_000_000));
        assert!(iface.enabled);
    }

    #[test]
    fn test_local_interface_disabled() {
        let iface = LocalInterface::new("10.0.0.1".parse().unwrap()).with_enabled(false);

        assert!(!iface.enabled);
    }

    #[test]
    fn test_local_interface_bind_addr() {
        let iface = LocalInterface::new("10.10.10.1".parse().unwrap());
        let bind_addr = iface.bind_addr();

        assert_eq!(
            bind_addr.ip(),
            "10.10.10.1".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(bind_addr.port(), 0); // Ephemeral port
    }

    #[test]
    fn test_local_interface_display_with_label() {
        let iface = LocalInterface::new("10.10.10.1".parse().unwrap()).with_label("bond0");

        assert_eq!(format!("{}", iface), "bond0(10.10.10.1)");
    }

    #[test]
    fn test_local_interface_display_without_label() {
        let iface = LocalInterface::new("192.168.1.1".parse().unwrap());

        assert_eq!(format!("{}", iface), "192.168.1.1");
    }

    #[test]
    fn test_local_interface_ipv6() {
        let iface = LocalInterface::new("::1".parse().unwrap()).with_label("lo");

        assert_eq!(iface.bind_ip, "::1".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(format!("{}", iface), "lo(::1)");
    }

    // =========================================================================
    // MultiPathEndpoint Tests
    // =========================================================================

    #[tokio::test]
    async fn test_multipath_endpoint_creation_localhost() {
        // Use localhost since it's always available
        let interfaces = vec![
            LocalInterface::new("127.0.0.1".parse().unwrap())
                .with_label("lo")
                .with_capacity(1_000_000_000),
        ];

        let mp = MultiPathEndpoint::new(interfaces).await;
        assert!(mp.is_ok());

        let mp = mp.unwrap();
        assert_eq!(mp.enabled_interface_count(), 1);
        assert!(mp.has_interface("127.0.0.1".parse().unwrap()));
    }

    #[tokio::test]
    async fn test_multipath_endpoint_local_ips() {
        let interfaces = vec![LocalInterface::new("127.0.0.1".parse().unwrap()).with_label("lo")];

        let mp = MultiPathEndpoint::new(interfaces).await.unwrap();
        let ips = mp.local_ips();

        assert_eq!(ips.len(), 1);
        assert!(ips.contains(&"127.0.0.1".parse().unwrap()));
    }

    #[tokio::test]
    async fn test_multipath_endpoint_interfaces() {
        let interfaces = vec![
            LocalInterface::new("127.0.0.1".parse().unwrap())
                .with_label("lo")
                .with_capacity(1_000_000_000),
        ];

        let mp = MultiPathEndpoint::new(interfaces).await.unwrap();

        assert_eq!(mp.interfaces().len(), 1);
        assert_eq!(mp.interfaces()[0].label, Some("lo".to_string()));
        assert_eq!(mp.interfaces()[0].capacity_bps, Some(1_000_000_000));
    }

    #[tokio::test]
    async fn test_multipath_endpoint_get_interface() {
        let interfaces = vec![LocalInterface::new("127.0.0.1".parse().unwrap()).with_label("lo")];

        let mp = MultiPathEndpoint::new(interfaces).await.unwrap();

        let iface = mp.get_interface("127.0.0.1".parse().unwrap());
        assert!(iface.is_some());
        assert_eq!(iface.unwrap().label, Some("lo".to_string()));

        let missing = mp.get_interface("192.168.1.1".parse().unwrap());
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn test_multipath_endpoint_disabled_interfaces_skipped() {
        let interfaces = vec![
            LocalInterface::new("127.0.0.1".parse().unwrap())
                .with_label("lo")
                .with_enabled(true),
            LocalInterface::new("192.168.99.99".parse().unwrap())
                .with_label("disabled-eth")
                .with_enabled(false), // Disabled - should not create endpoint
        ];

        let mp = MultiPathEndpoint::new(interfaces).await.unwrap();

        // Should only have 1 enabled endpoint
        assert_eq!(mp.enabled_interface_count(), 1);
        assert!(mp.has_interface("127.0.0.1".parse().unwrap()));
        // Disabled interface exists in config but not as endpoint
        assert!(!mp.has_interface("192.168.99.99".parse().unwrap()));
        // But it should still be in interfaces list
        assert_eq!(mp.interfaces().len(), 2);
    }

    #[tokio::test]
    async fn test_multipath_endpoint_no_enabled_interfaces_error() {
        let interfaces =
            vec![LocalInterface::new("10.10.10.1".parse().unwrap()).with_enabled(false)];

        let result = MultiPathEndpoint::new(interfaces).await;
        assert!(result.is_err());

        match result {
            Err(Error::Configuration(msg)) => {
                assert!(msg.contains("No enabled interfaces"));
            }
            _ => panic!("Expected Configuration error"),
        }
    }

    #[tokio::test]
    async fn test_multipath_endpoint_add_interface() {
        let interfaces = vec![LocalInterface::new("127.0.0.1".parse().unwrap()).with_label("lo")];

        let mut mp = MultiPathEndpoint::new(interfaces).await.unwrap();
        assert_eq!(mp.enabled_interface_count(), 1);

        // Add another localhost variant (IPv6)
        let new_iface = LocalInterface::new("::1".parse().unwrap()).with_label("lo6");

        let result = mp.add_interface(new_iface).await;
        assert!(result.is_ok());

        assert_eq!(mp.enabled_interface_count(), 2);
        assert!(mp.has_interface("::1".parse().unwrap()));
    }

    #[tokio::test]
    async fn test_multipath_endpoint_add_duplicate_interface_error() {
        let interfaces = vec![LocalInterface::new("127.0.0.1".parse().unwrap()).with_label("lo")];

        let mut mp = MultiPathEndpoint::new(interfaces).await.unwrap();

        // Try to add duplicate
        let duplicate = LocalInterface::new("127.0.0.1".parse().unwrap()).with_label("lo-dup");

        let result = mp.add_interface(duplicate).await;
        assert!(result.is_err());

        match result {
            Err(Error::Configuration(msg)) => {
                assert!(msg.contains("already exists"));
            }
            _ => panic!("Expected Configuration error"),
        }
    }

    #[tokio::test]
    async fn test_multipath_endpoint_remove_interface() {
        let interfaces = vec![
            LocalInterface::new("127.0.0.1".parse().unwrap()).with_label("lo"),
            LocalInterface::new("::1".parse().unwrap()).with_label("lo6"),
        ];

        let mut mp = MultiPathEndpoint::new(interfaces).await.unwrap();
        assert_eq!(mp.enabled_interface_count(), 2);

        // Remove one interface
        let removed = mp.remove_interface("::1".parse().unwrap());
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().label, Some("lo6".to_string()));

        assert_eq!(mp.enabled_interface_count(), 1);
        assert!(!mp.has_interface("::1".parse().unwrap()));
        assert!(mp.has_interface("127.0.0.1".parse().unwrap()));
    }

    #[tokio::test]
    async fn test_multipath_endpoint_remove_nonexistent() {
        let interfaces = vec![LocalInterface::new("127.0.0.1".parse().unwrap()).with_label("lo")];

        let mut mp = MultiPathEndpoint::new(interfaces).await.unwrap();

        let removed = mp.remove_interface("10.10.10.1".parse().unwrap());
        assert!(removed.is_none());
    }

    #[tokio::test]
    async fn test_multipath_endpoint_connect_via_invalid_interface() {
        let interfaces = vec![LocalInterface::new("127.0.0.1".parse().unwrap()).with_label("lo")];

        let mp = MultiPathEndpoint::new(interfaces).await.unwrap();

        // Try to connect via interface that doesn't exist
        let result = mp
            .connect_via(
                "10.10.10.1".parse().unwrap(),
                "127.0.0.1:12345".parse().unwrap(),
                "localhost",
            )
            .await;

        assert!(result.is_err());
        match result {
            Err(Error::Connection(msg)) => {
                assert!(msg.contains("No endpoint bound to"));
            }
            _ => panic!("Expected Connection error"),
        }
    }

    #[tokio::test]
    async fn test_multipath_endpoint_connect_via_localhost() {
        // Create a server
        let server = WarpEndpoint::server("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let server_addr = server.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let conn = server.accept().await.unwrap();
            conn.handshake_server().await.unwrap();
            conn
        });

        // Create multi-path endpoint with localhost
        let interfaces = vec![LocalInterface::new("127.0.0.1".parse().unwrap()).with_label("lo")];

        let mp = MultiPathEndpoint::new(interfaces).await.unwrap();

        // Connect via specific interface
        let conn = mp
            .connect_via("127.0.0.1".parse().unwrap(), server_addr, "localhost")
            .await
            .unwrap();

        let params = conn.handshake().await.unwrap();
        assert_eq!(params.compression, "zstd");

        let _server_conn = server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_multipath_endpoint_debug_format() {
        let interfaces = vec![
            LocalInterface::new("127.0.0.1".parse().unwrap())
                .with_label("lo")
                .with_capacity(1_000_000_000),
        ];

        let mp = MultiPathEndpoint::new(interfaces).await.unwrap();
        let debug_str = format!("{:?}", mp);

        assert!(debug_str.contains("MultiPathEndpoint"));
        assert!(debug_str.contains("interfaces"));
        assert!(debug_str.contains("endpoint_count"));
    }

    // =========================================================================
    // Original WarpEndpoint Tests
    // =========================================================================

    #[tokio::test]
    async fn test_endpoint_creation() {
        let client = WarpEndpoint::client().await;
        assert!(client.is_ok());

        let server = WarpEndpoint::server("127.0.0.1:0".parse().unwrap()).await;
        assert!(server.is_ok());
    }

    #[tokio::test]
    async fn test_connect_handshake() {
        let server = WarpEndpoint::server("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let server_addr = server.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let conn = server.accept().await.unwrap();
            conn.handshake_server().await.unwrap();
            conn
        });

        let client = WarpEndpoint::client().await.unwrap();
        let conn = client.connect(server_addr, "localhost").await.unwrap();
        let params = conn.handshake().await.unwrap();

        assert_eq!(params.compression, "zstd");
        assert!(params.chunk_size > 0);

        let _server_conn = server_task.await.unwrap();
    }

    #[tokio::test]
    #[ignore = "flaky due to connection timing"]
    async fn test_send_receive_frame() {
        let server = WarpEndpoint::server("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let server_addr = server.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let conn = server.accept().await.unwrap();
            conn.handshake_server().await.unwrap();
            conn.send_frame(Frame::Done).await.unwrap();
            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
            conn
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let client = WarpEndpoint::client().await.unwrap();
        let conn = client.connect(server_addr, "localhost").await.unwrap();
        conn.handshake().await.unwrap();

        let frame = conn.recv_frame().await.unwrap();
        match frame {
            Frame::Done => {}
            _ => panic!("Expected Done frame"),
        }

        let _server_conn = server_task.await.unwrap();
    }
}
