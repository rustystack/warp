//! NVMe-oF Transport Client
//!
//! Minimal NVMe-oF TCP transport client for the initiator.
//! This is self-contained to avoid cyclic dependencies with warp-block.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};

use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{debug, trace};

use super::error::{NvmeOfBackendError, NvmeOfBackendResult};

/// NVMe-oF PDU types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PduType {
    ICReq = 0x00,
    ICResp = 0x01,
    H2CTermReq = 0x02,
    C2HTermReq = 0x03,
    CapsuleCmd = 0x04,
    CapsuleResp = 0x05,
    H2CData = 0x06,
    C2HData = 0x07,
    R2T = 0x09,
}

/// NVMe I/O opcodes
#[allow(dead_code)]
pub mod io_opcode {
    pub const FLUSH: u8 = 0x00;
    pub const WRITE: u8 = 0x01;
    pub const READ: u8 = 0x02;
    pub const WRITE_ZEROES: u8 = 0x08;
    pub const DATASET_MANAGEMENT: u8 = 0x09;
}

/// NVMe Fabrics opcodes
#[allow(dead_code)]
pub mod fabrics_opcode {
    pub const PROPERTY_SET: u8 = 0x00;
    pub const CONNECT: u8 = 0x01;
    pub const PROPERTY_GET: u8 = 0x04;
    pub const DISCONNECT: u8 = 0x08;
}

/// NVMe command (64 bytes)
#[derive(Clone)]
pub struct NvmeCommand {
    data: [u8; 64],
}

impl Default for NvmeCommand {
    fn default() -> Self {
        Self::new()
    }
}

impl NvmeCommand {
    pub fn new() -> Self {
        Self { data: [0u8; 64] }
    }

    pub fn opcode(&self) -> u8 {
        self.data[0]
    }

    pub fn set_opcode(&mut self, opcode: u8) {
        self.data[0] = opcode;
    }

    pub fn cid(&self) -> u16 {
        u16::from_le_bytes([self.data[2], self.data[3]])
    }

    pub fn set_cid(&mut self, cid: u16) {
        let bytes = cid.to_le_bytes();
        self.data[2] = bytes[0];
        self.data[3] = bytes[1];
    }

    pub fn nsid(&self) -> u32 {
        u32::from_le_bytes([self.data[4], self.data[5], self.data[6], self.data[7]])
    }

    pub fn set_nsid(&mut self, nsid: u32) {
        let bytes = nsid.to_le_bytes();
        self.data[4..8].copy_from_slice(&bytes);
    }

    /// Set starting LBA (CDW10-CDW11)
    pub fn set_slba(&mut self, slba: u64) {
        let bytes = slba.to_le_bytes();
        self.data[40..48].copy_from_slice(&bytes);
    }

    /// Set number of logical blocks - 1 (CDW12, bits 0-15)
    pub fn set_nlb(&mut self, nlb: u16) {
        let bytes = nlb.to_le_bytes();
        self.data[48] = bytes[0];
        self.data[49] = bytes[1];
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

/// NVMe completion (16 bytes)
#[derive(Clone, Default)]
pub struct NvmeCompletion {
    data: [u8; 16],
}

impl NvmeCompletion {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut data = [0u8; 16];
        data.copy_from_slice(&bytes[..16]);
        Self { data }
    }

    pub fn cid(&self) -> u16 {
        u16::from_le_bytes([self.data[12], self.data[13]])
    }

    pub fn status(&self) -> u16 {
        u16::from_le_bytes([self.data[14], self.data[15]]) >> 1
    }

    pub fn is_success(&self) -> bool {
        self.status() == 0
    }
}

/// Command capsule for sending
pub struct CommandCapsule {
    pub command: NvmeCommand,
    pub data: Option<Bytes>,
}

impl CommandCapsule {
    pub fn new(command: NvmeCommand) -> Self {
        Self {
            command,
            data: None,
        }
    }

    pub fn with_data(command: NvmeCommand, data: Bytes) -> Self {
        Self {
            command,
            data: Some(data),
        }
    }
}

/// Response capsule received
pub struct ResponseCapsule {
    pub completion: NvmeCompletion,
    pub data: Option<Bytes>,
}

/// NVMe-oF TCP transport connection
pub struct TcpConnection {
    reader: Mutex<BufReader<tokio::net::tcp::OwnedReadHalf>>,
    writer: Mutex<BufWriter<tokio::net::tcp::OwnedWriteHalf>>,
    remote_addr: SocketAddr,
    cid_counter: AtomicU16,
    id: u64,
}

static CONN_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

impl TcpConnection {
    /// Connect to an NVMe-oF target
    pub async fn connect(addr: SocketAddr) -> NvmeOfBackendResult<Self> {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| NvmeOfBackendError::Connection(e.to_string()))?;

        stream
            .set_nodelay(true)
            .map_err(|e| NvmeOfBackendError::Connection(e.to_string()))?;

        let remote_addr = stream.peer_addr().unwrap_or(addr);
        let (read_half, write_half) = stream.into_split();

        let conn = Self {
            reader: Mutex::new(BufReader::new(read_half)),
            writer: Mutex::new(BufWriter::new(write_half)),
            remote_addr,
            cid_counter: AtomicU16::new(1),
            id: CONN_ID_COUNTER.fetch_add(1, Ordering::Relaxed),
        };

        debug!("Connected to NVMe-oF target at {}", addr);
        Ok(conn)
    }

    /// Perform ICReq/ICResp handshake
    pub async fn initialize(&self) -> NvmeOfBackendResult<()> {
        // Build ICReq PDU (128 bytes total)
        let mut icreq = BytesMut::with_capacity(128);

        // PDU header (8 bytes)
        icreq.put_u8(PduType::ICReq as u8); // PDU type
        icreq.put_u8(0); // Flags
        icreq.put_u8(0); // Header length (will set)
        icreq.put_u8(0); // PDU-specific (data offset for some PDUs)
        icreq.put_u32_le(128); // PDU length

        // ICReq data (120 bytes)
        icreq.put_u16_le(0); // PFV (PDU Format Version)
        icreq.put_u8(0); // HPDA (Host PDU Data Alignment)
        icreq.put_u8(0); // DGST (Digest Types)
        icreq.put_u32_le(1024 * 1024); // MAXR2T (Max outstanding R2T)
        icreq.put_u16_le(0); // Host ID (will be set by controller)
        icreq.put_u16_le(0); // Reserved

        // Pad to 128 bytes
        while icreq.len() < 128 {
            icreq.put_u8(0);
        }

        // Send ICReq
        {
            let mut writer = self.writer.lock().await;
            writer
                .write_all(&icreq)
                .await
                .map_err(|e| NvmeOfBackendError::Connection(e.to_string()))?;
            writer
                .flush()
                .await
                .map_err(|e| NvmeOfBackendError::Connection(e.to_string()))?;
        }

        // Receive ICResp
        let mut icresp = vec![0u8; 128];
        {
            let mut reader = self.reader.lock().await;
            reader
                .read_exact(&mut icresp)
                .await
                .map_err(|e| NvmeOfBackendError::Connection(e.to_string()))?;
        }

        // Verify ICResp
        if icresp[0] != PduType::ICResp as u8 {
            return Err(NvmeOfBackendError::Protocol(format!(
                "Expected ICResp, got PDU type {}",
                icresp[0]
            )));
        }

        debug!("NVMe-oF handshake complete");
        Ok(())
    }

    /// Allocate next command ID
    fn next_cid(&self) -> u16 {
        self.cid_counter.fetch_add(1, Ordering::Relaxed)
    }

    /// Send a command and receive response
    pub async fn execute(&self, capsule: &mut CommandCapsule) -> NvmeOfBackendResult<ResponseCapsule> {
        // Assign command ID
        let cid = self.next_cid();
        capsule.command.set_cid(cid);

        // Build command PDU
        let data_len = capsule.data.as_ref().map(|d| d.len()).unwrap_or(0);
        let pdu_len = 8 + 64 + data_len; // Header + command + data

        let mut pdu = BytesMut::with_capacity(pdu_len);

        // PDU header (8 bytes)
        pdu.put_u8(PduType::CapsuleCmd as u8);
        pdu.put_u8(0); // Flags
        pdu.put_u8(0); // Header length offset
        pdu.put_u8(if data_len > 0 { 72 } else { 0 }); // Data offset (after header + command)
        pdu.put_u32_le(pdu_len as u32);

        // Command (64 bytes)
        pdu.put_slice(capsule.command.as_bytes());

        // Data if present
        if let Some(data) = &capsule.data {
            pdu.put_slice(data);
        }

        // Send command
        {
            let mut writer = self.writer.lock().await;
            writer
                .write_all(&pdu)
                .await
                .map_err(|e| NvmeOfBackendError::Io(e.to_string()))?;
            writer
                .flush()
                .await
                .map_err(|e| NvmeOfBackendError::Io(e.to_string()))?;
        }

        trace!("Sent command CID={}", cid);

        // Receive response
        let mut resp_header = [0u8; 8];
        {
            let mut reader = self.reader.lock().await;
            reader
                .read_exact(&mut resp_header)
                .await
                .map_err(|e| NvmeOfBackendError::Io(e.to_string()))?;
        }

        let pdu_type = resp_header[0];
        let resp_len = u32::from_le_bytes([resp_header[4], resp_header[5], resp_header[6], resp_header[7]]) as usize;

        if pdu_type != PduType::CapsuleResp as u8 {
            return Err(NvmeOfBackendError::Protocol(format!(
                "Expected CapsuleResp, got PDU type {}",
                pdu_type
            )));
        }

        // Read rest of response (minus header we already read)
        let remaining = resp_len - 8;
        let mut resp_body = vec![0u8; remaining];
        {
            let mut reader = self.reader.lock().await;
            reader
                .read_exact(&mut resp_body)
                .await
                .map_err(|e| NvmeOfBackendError::Io(e.to_string()))?;
        }

        // Parse completion (first 16 bytes of body)
        let completion = NvmeCompletion::from_bytes(&resp_body[..16]);

        // Check for data
        let data = if remaining > 16 {
            Some(Bytes::copy_from_slice(&resp_body[16..]))
        } else {
            None
        };

        trace!("Received response CID={}, status={:#x}", completion.cid(), completion.status());

        Ok(ResponseCapsule { completion, data })
    }

    /// Get connection ID
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Get remote address
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }
}
