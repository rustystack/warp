//! NVMe-oF TCP Transport Implementation
//!
//! This module implements the NVMe over TCP transport as specified in
//! the NVMe-oF TCP Transport Binding Specification.

use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tracing::{debug, trace};

use super::{
    ConnectionState, NvmeOfTransport, TransportAddress, TransportCapabilities, TransportConnection,
};
use crate::nvmeof::capsule::{CommandCapsule, IcReq, IcResp, PduHeader, PduType, ResponseCapsule};
use crate::nvmeof::command::{NvmeCommand, NvmeCompletion};
use crate::nvmeof::config::{NvmeOfTcpConfig, TransportType};
use crate::nvmeof::error::{NvmeOfError, NvmeOfResult};

/// TCP Transport for NVMe-oF
pub struct TcpTransport {
    /// Configuration
    config: NvmeOfTcpConfig,

    /// TCP listener
    listener: Mutex<Option<TcpListener>>,

    /// Connection counter for IDs
    connection_counter: AtomicU64,
}

impl TcpTransport {
    /// Create a new TCP transport
    pub fn new(config: NvmeOfTcpConfig) -> Self {
        Self {
            config,
            listener: Mutex::new(None),
            connection_counter: AtomicU64::new(0),
        }
    }

    /// Get next connection ID
    fn next_connection_id(&self) -> u64 {
        self.connection_counter.fetch_add(1, Ordering::Relaxed)
    }
}

#[async_trait]
impl NvmeOfTransport for TcpTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::Tcp
    }

    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities {
            max_inline_data: 8192,
            max_io_size: self.config.maxh2cdata,
            header_digest: self.config.header_digest,
            data_digest: self.config.data_digest,
            zero_copy: false,
            memory_registration: false,
            multi_stream: false,
        }
    }

    async fn bind(&mut self, addr: SocketAddr) -> NvmeOfResult<()> {
        let listener = TcpListener::bind(addr).await?;
        debug!("NVMe-oF TCP transport bound to {}", addr);

        let mut guard = self.listener.lock().await;
        *guard = Some(listener);
        Ok(())
    }

    async fn accept(&self) -> NvmeOfResult<Box<dyn TransportConnection>> {
        let guard = self.listener.lock().await;
        let listener = guard
            .as_ref()
            .ok_or_else(|| NvmeOfError::Transport("Transport not bound".to_string()))?;

        let (stream, remote_addr) = listener.accept().await?;
        debug!("Accepted TCP connection from {}", remote_addr);

        // Configure socket
        stream.set_nodelay(self.config.nodelay)?;

        let local_addr = stream.local_addr()?;
        let connection_id = self.next_connection_id();

        let conn = TcpConnection::new(
            stream,
            local_addr,
            remote_addr,
            connection_id,
            self.config.clone(),
        );

        Ok(Box::new(conn))
    }

    async fn connect(&self, addr: &TransportAddress) -> NvmeOfResult<Box<dyn TransportConnection>> {
        let stream =
            tokio::time::timeout(self.config.connect_timeout, TcpStream::connect(addr.addr))
                .await
                .map_err(|_| NvmeOfError::Timeout("Connection timeout".to_string()))??;

        stream.set_nodelay(self.config.nodelay)?;

        let local_addr = stream.local_addr()?;
        let remote_addr = stream.peer_addr()?;
        let connection_id = self.next_connection_id();

        debug!("Connected to NVMe-oF TCP target at {}", remote_addr);

        let conn = TcpConnection::new(
            stream,
            local_addr,
            remote_addr,
            connection_id,
            self.config.clone(),
        );

        Ok(Box::new(conn))
    }

    async fn close(&self) -> NvmeOfResult<()> {
        let mut guard = self.listener.lock().await;
        *guard = None;
        Ok(())
    }

    async fn local_addr(&self) -> NvmeOfResult<SocketAddr> {
        let guard = self.listener.lock().await;
        let listener = guard
            .as_ref()
            .ok_or_else(|| NvmeOfError::Transport("Transport not bound".to_string()))?;
        Ok(listener.local_addr()?)
    }
}

/// TCP Connection implementation
pub struct TcpConnection {
    /// Connection ID
    id: u64,

    /// Local address
    local_addr: SocketAddr,

    /// Remote address
    remote_addr: SocketAddr,

    /// Reader half (buffered)
    reader: Mutex<BufReader<tokio::net::tcp::OwnedReadHalf>>,

    /// Writer half (buffered)
    writer: Mutex<BufWriter<tokio::net::tcp::OwnedWriteHalf>>,

    /// Configuration
    config: NvmeOfTcpConfig,

    /// Connection state
    connected: AtomicBool,

    /// Connection state
    state: parking_lot::RwLock<ConnectionState>,
}

impl TcpConnection {
    /// Create a new TCP connection
    pub fn new(
        stream: TcpStream,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        id: u64,
        config: NvmeOfTcpConfig,
    ) -> Self {
        let (read_half, write_half) = stream.into_split();

        Self {
            id,
            local_addr,
            remote_addr,
            reader: Mutex::new(BufReader::with_capacity(64 * 1024, read_half)),
            writer: Mutex::new(BufWriter::with_capacity(64 * 1024, write_half)),
            config,
            connected: AtomicBool::new(true),
            state: parking_lot::RwLock::new(ConnectionState::Connecting),
        }
    }

    /// Perform ICReq/ICResp handshake (initiator side)
    pub async fn initialize_connection_initiator(&self) -> NvmeOfResult<()> {
        *self.state.write() = ConnectionState::Initializing;

        // Send ICReq
        let icreq = IcReq::new();
        self.send_icreq(&icreq).await?;

        // Receive ICResp
        let _icresp = self.recv_icresp().await?;

        *self.state.write() = ConnectionState::Ready;
        debug!("TCP connection initialized (initiator)");
        Ok(())
    }

    /// Perform ICReq/ICResp handshake (target side)
    pub async fn initialize_connection_target(&self) -> NvmeOfResult<IcReq> {
        *self.state.write() = ConnectionState::Initializing;

        // Receive ICReq
        let icreq = self.recv_icreq().await?;

        // Send ICResp
        let icresp = IcResp::new();
        self.send_icresp(&icresp).await?;

        *self.state.write() = ConnectionState::Ready;
        debug!("TCP connection initialized (target)");
        Ok(icreq)
    }

    /// Send ICReq PDU
    async fn send_icreq(&self, icreq: &IcReq) -> NvmeOfResult<()> {
        let mut buf = BytesMut::with_capacity(128);

        // PDU header (8 bytes)
        let header = PduHeader::new(
            PduType::IcReq,
            32, // 128 bytes / 4
            0,
            128,
        );
        buf.put(header.to_bytes());

        // ICReq data
        buf.put(icreq.to_bytes());

        // Ensure we have 128 bytes total
        buf.resize(128, 0);

        let mut writer = self.writer.lock().await;
        writer.write_all(&buf).await?;
        writer.flush().await?;

        trace!("Sent ICReq PDU");
        Ok(())
    }

    /// Receive ICReq PDU
    async fn recv_icreq(&self) -> NvmeOfResult<IcReq> {
        let mut buf = [0u8; 128];
        let mut reader = self.reader.lock().await;
        reader.read_exact(&mut buf).await?;

        let header = PduHeader::from_bytes(&buf[..8])?;
        if header.pdu_type != PduType::IcReq {
            return Err(NvmeOfError::Protocol(format!(
                "Expected ICReq, got {:?}",
                header.pdu_type
            )));
        }

        let icreq = IcReq::from_bytes(&buf[8..])?;
        trace!("Received ICReq PDU");
        Ok(icreq)
    }

    /// Send ICResp PDU
    async fn send_icresp(&self, icresp: &IcResp) -> NvmeOfResult<()> {
        let mut buf = BytesMut::with_capacity(128);

        let header = PduHeader::new(
            PduType::IcResp,
            32, // 128 bytes / 4
            0,
            128,
        );
        buf.put(header.to_bytes());
        buf.put(icresp.to_bytes());
        buf.resize(128, 0);

        let mut writer = self.writer.lock().await;
        writer.write_all(&buf).await?;
        writer.flush().await?;

        trace!("Sent ICResp PDU");
        Ok(())
    }

    /// Receive ICResp PDU
    async fn recv_icresp(&self) -> NvmeOfResult<IcResp> {
        let mut buf = [0u8; 128];
        let mut reader = self.reader.lock().await;
        reader.read_exact(&mut buf).await?;

        let header = PduHeader::from_bytes(&buf[..8])?;
        if header.pdu_type != PduType::IcResp {
            return Err(NvmeOfError::Protocol(format!(
                "Expected ICResp, got {:?}",
                header.pdu_type
            )));
        }

        // Parse ICResp (we only need basic fields)
        Ok(IcResp::new())
    }

    /// Get connection state
    pub fn state(&self) -> ConnectionState {
        *self.state.read()
    }
}

#[async_trait]
impl TransportConnection for TcpConnection {
    fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    fn transport_type(&self) -> TransportType {
        TransportType::Tcp
    }

    async fn initialize_as_target(&self) -> NvmeOfResult<()> {
        self.initialize_connection_target().await.map(|_| ())
    }

    async fn initialize_as_initiator(&self) -> NvmeOfResult<()> {
        self.initialize_connection_initiator().await
    }

    async fn send_command(&self, capsule: &CommandCapsule) -> NvmeOfResult<()> {
        let cmd_bytes = capsule.to_bytes();
        let plen = 8 + cmd_bytes.len() as u32; // PDU header + capsule

        let mut buf = BytesMut::with_capacity(plen as usize);

        // PDU header
        let pdo = if capsule.data.is_some() {
            // Data offset after command (64 bytes)
            16u8 // 64 / 4
        } else {
            0
        };

        let header = PduHeader::new(
            PduType::CapsuleCmd,
            ((8 + NvmeCommand::SIZE) / 4) as u8, // header + command
            pdo,
            plen,
        );

        buf.put(header.to_bytes());
        buf.put(cmd_bytes);

        let mut writer = self.writer.lock().await;
        writer.write_all(&buf).await?;
        writer.flush().await?;

        trace!("Sent command capsule, cid={}", capsule.command.cid());
        Ok(())
    }

    async fn recv_command(&self) -> NvmeOfResult<CommandCapsule> {
        // Read PDU header
        let mut header_buf = [0u8; 8];
        let mut reader = self.reader.lock().await;
        reader.read_exact(&mut header_buf).await?;

        let header = PduHeader::from_bytes(&header_buf)?;

        if header.pdu_type != PduType::CapsuleCmd {
            return Err(NvmeOfError::Protocol(format!(
                "Expected CapsuleCmd, got {:?}",
                header.pdu_type
            )));
        }

        // Read the rest of the PDU
        let remaining = header.plen as usize - 8;
        let mut pdu_buf = vec![0u8; remaining];
        reader.read_exact(&mut pdu_buf).await?;

        // Parse command
        let capsule = CommandCapsule::from_bytes(&pdu_buf)?;

        trace!("Received command capsule, cid={}", capsule.command.cid());
        Ok(capsule)
    }

    async fn send_response(&self, capsule: &ResponseCapsule) -> NvmeOfResult<()> {
        let resp_bytes = capsule.to_bytes();
        let plen = 8 + resp_bytes.len() as u32;

        let mut buf = BytesMut::with_capacity(plen as usize);

        let header = PduHeader::new(
            PduType::CapsuleResp,
            ((8 + NvmeCompletion::SIZE) / 4) as u8,
            0,
            plen,
        );

        buf.put(header.to_bytes());
        buf.put(resp_bytes);

        let mut writer = self.writer.lock().await;
        writer.write_all(&buf).await?;
        writer.flush().await?;

        trace!("Sent response capsule, cid={}", capsule.completion.cid);
        Ok(())
    }

    async fn recv_response(&self) -> NvmeOfResult<ResponseCapsule> {
        let mut header_buf = [0u8; 8];
        let mut reader = self.reader.lock().await;
        reader.read_exact(&mut header_buf).await?;

        let header = PduHeader::from_bytes(&header_buf)?;

        if header.pdu_type != PduType::CapsuleResp {
            return Err(NvmeOfError::Protocol(format!(
                "Expected CapsuleResp, got {:?}",
                header.pdu_type
            )));
        }

        let remaining = header.plen as usize - 8;
        let mut pdu_buf = vec![0u8; remaining];
        reader.read_exact(&mut pdu_buf).await?;

        let capsule = ResponseCapsule::from_bytes(&pdu_buf)?;

        trace!("Received response capsule, cid={}", capsule.completion.cid);
        Ok(capsule)
    }

    async fn send_data(&self, data: Bytes, offset: u64) -> NvmeOfResult<()> {
        // C2H Data PDU
        let data_len = data.len();
        let plen = 24 + data_len as u32; // PDU header (8) + C2H header (16) + data

        let mut buf = BytesMut::with_capacity(plen as usize);

        // PDU header
        let header = PduHeader::new(PduType::C2HData, 6, 6, plen); // 24 / 4 = 6
        buf.put(header.to_bytes());

        // C2H Data header (16 bytes)
        buf.put_u16_le(0); // CID (will be filled by caller context)
        buf.put_u16_le(0); // TTAG
        buf.put_u32_le(offset as u32); // Data offset
        buf.put_u32_le(data_len as u32); // Data length
        buf.put_u32_le(0); // Reserved

        // Data
        buf.put(data);

        let mut writer = self.writer.lock().await;
        writer.write_all(&buf).await?;
        writer.flush().await?;

        trace!("Sent {} bytes of data at offset {}", data_len, offset);
        Ok(())
    }

    async fn recv_data(&self, _length: usize) -> NvmeOfResult<Bytes> {
        let mut header_buf = [0u8; 8];
        let mut reader = self.reader.lock().await;
        reader.read_exact(&mut header_buf).await?;

        let header = PduHeader::from_bytes(&header_buf)?;

        if header.pdu_type != PduType::H2CData && header.pdu_type != PduType::C2HData {
            return Err(NvmeOfError::Protocol(format!(
                "Expected data PDU, got {:?}",
                header.pdu_type
            )));
        }

        // Read the rest including data header (16 bytes) and data
        let remaining = header.plen as usize - 8;
        let mut pdu_buf = vec![0u8; remaining];
        reader.read_exact(&mut pdu_buf).await?;

        // Skip 16-byte data header, return just the data
        let data = if remaining > 16 {
            Bytes::copy_from_slice(&pdu_buf[16..])
        } else {
            Bytes::new()
        };

        trace!("Received {} bytes of data", data.len());
        Ok(data)
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    async fn close(&self) -> NvmeOfResult<()> {
        *self.state.write() = ConnectionState::Closing;
        self.connected.store(false, Ordering::Relaxed);

        // Flush and shutdown writer
        let mut writer = self.writer.lock().await;
        let _ = writer.flush().await;

        *self.state.write() = ConnectionState::Closed;
        debug!("TCP connection {} closed", self.id);
        Ok(())
    }

    fn connection_id(&self) -> u64 {
        self.id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_tcp_transport_creation() {
        let config = NvmeOfTcpConfig::default();
        let transport = TcpTransport::new(config);
        assert_eq!(transport.transport_type(), TransportType::Tcp);
    }

    #[tokio::test]
    async fn test_tcp_transport_bind() {
        let config = NvmeOfTcpConfig::default();
        let mut transport = TcpTransport::new(config);

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        transport.bind(addr).await.unwrap();

        transport.close().await.unwrap();
    }
}
