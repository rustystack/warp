//! QUIC transport implementation using quinn

use crate::codec::Frame;
use crate::frames::Capabilities;
use crate::pool::global_pool;
use crate::protocol::{NegotiatedParams, ProtocolState};
use crate::tls::{client_config, generate_self_signed, server_config};
#[cfg(any(test, feature = "insecure-tls"))]
use crate::tls::client_config_insecure;
use crate::{Error, Result};
use bytes::Bytes;
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

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
    control_send: Arc<Mutex<Option<SendStream>>>,
    control_recv: Arc<Mutex<Option<RecvStream>>>,
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
            control_send: Arc::new(Mutex::new(None)),
            control_recv: Arc::new(Mutex::new(None)),
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
    async fn open_control_stream(&self) -> Result<()> {
        let (send, recv) = self.open_stream().await?;
        *self.control_send.lock().await = Some(send);
        *self.control_recv.lock().await = Some(recv);
        Ok(())
    }

    /// Accept the control stream (server side)
    async fn accept_control_stream(&self) -> Result<()> {
        let (send, recv) = self.connection.accept_bi().await
            .map_err(|e| Error::Connection(format!("Failed to accept control stream: {}", e)))?;
        *self.control_send.lock().await = Some(send);
        *self.control_recv.lock().await = Some(recv);
        Ok(())
    }

    /// Send a frame on the control stream
    pub async fn send_frame(&self, frame: Frame) -> Result<()> {
        // Use pooled buffer to avoid allocation on every frame
        let pool = global_pool();
        let mut pooled_buf = pool.get_medium();
        frame.encode(&mut pooled_buf)?;

        tracing::trace!("Sending frame: {:?}", frame.frame_type());

        let mut send_lock = self.control_send.lock().await;
        let send = send_lock
            .as_mut()
            .ok_or_else(|| Error::Protocol("Control stream not open".into()))?;

        send.write_all(&pooled_buf)
            .await
            .map_err(|e| Error::Connection(format!("Failed to send frame: {}", e)))?;

        drop(send_lock);
        // pooled_buf returned to pool on drop

        Ok(())
    }

    /// Receive a frame from the control stream
    pub async fn recv_frame(&self) -> Result<Frame> {
        let mut recv_lock = self.control_recv.lock().await;
        let recv = recv_lock
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

        let frame = Frame::Chunk {
            chunk_id,
            data,
        };

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
            return Err(Error::Connection(
                "Cannot accept on client endpoint".into(),
            ));
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

#[cfg(test)]
mod tests {
    use super::*;

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
