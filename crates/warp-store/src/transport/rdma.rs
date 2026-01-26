//! RDMA Transport Integration for Tier 2 (Same Datacenter)
//!
//! This module provides RDMA-based transport for low-latency (~1-50µs)
//! communication within the same datacenter.
//!
//! # Features
//!
//! - Zero-copy data transfer using registered memory
//! - Pre-allocated buffer pools for minimal allocation overhead
//! - Automatic fallback to TCP when RDMA is unavailable
//! - Integration with transport tier selection

#![cfg(feature = "rmpi")]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;
use parking_lot::{Mutex, RwLock};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, trace, warn};

use super::{PeerLocation, StorageMessage, Tier, TierStats};
use crate::ObjectKey;
use crate::error::{Error, Result};

/// Header for chunked RDMA transmissions
///
/// Used by the chunking protocol to send variable-length data through rmpi's
/// SafeSend interface which requires fixed-size arrays.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct RdmaChunkHeader {
    /// Magic number for validation (0x524D5049 = "RMPI")
    pub magic: u32,
    /// Total data length in bytes
    pub total_length: u64,
    /// Number of chunks that follow
    pub chunk_count: u32,
    /// Size of each chunk (last chunk may be shorter)
    pub chunk_size: u32,
    /// CRC32 checksum of original data (0 if not computed)
    pub checksum: u32,
}

impl RdmaChunkHeader {
    /// Magic number for RMPI chunk headers
    pub const MAGIC: u32 = 0x524D5049; // "RMPI" in ASCII

    /// Header size in bytes
    pub const SIZE: usize = 24;

    /// Create a new chunk header
    pub fn new(total_length: usize, chunk_size: usize) -> Self {
        let chunk_count = if total_length == 0 {
            0
        } else {
            (total_length + chunk_size - 1) / chunk_size
        };
        Self {
            magic: Self::MAGIC,
            total_length: total_length as u64,
            chunk_count: chunk_count as u32,
            chunk_size: chunk_size as u32,
            checksum: 0,
        }
    }

    /// Create header with checksum
    pub fn with_checksum(total_length: usize, chunk_size: usize, data: &[u8]) -> Self {
        let mut header = Self::new(total_length, chunk_size);
        header.checksum = crc32fast::hash(data);
        header
    }

    /// Serialize header to bytes
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        bytes[0..4].copy_from_slice(&self.magic.to_le_bytes());
        bytes[4..12].copy_from_slice(&self.total_length.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.chunk_count.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.chunk_size.to_le_bytes());
        bytes[20..24].copy_from_slice(&self.checksum.to_le_bytes());
        bytes
    }

    /// Deserialize header from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < Self::SIZE {
            return Err(Error::Transport(format!(
                "Chunk header too short: {} < {}",
                bytes.len(),
                Self::SIZE
            )));
        }
        let magic = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        if magic != Self::MAGIC {
            return Err(Error::Transport(format!(
                "Invalid chunk header magic: expected 0x{:08X}, got 0x{:08X}",
                Self::MAGIC,
                magic
            )));
        }
        Ok(Self {
            magic,
            total_length: u64::from_le_bytes(bytes[4..12].try_into().unwrap()),
            chunk_count: u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
            chunk_size: u32::from_le_bytes(bytes[16..20].try_into().unwrap()),
            checksum: u32::from_le_bytes(bytes[20..24].try_into().unwrap()),
        })
    }
}

/// GPU buffer registration for RDMA
///
/// Allows GPU memory to be registered for direct RDMA access, enabling
/// GPUDirect RDMA transfers without CPU involvement.
#[cfg(feature = "gpu")]
#[derive(Debug)]
pub struct GpuBufferRegistration {
    /// GPU device ID
    pub device_id: u32,
    /// GPU buffer pointer
    pub device_ptr: u64,
    /// Buffer size
    pub size: usize,
    /// Registration key for RDMA
    pub rkey: u32,
    /// Local key for RDMA
    pub lkey: u32,
}

#[cfg(feature = "gpu")]
impl GpuBufferRegistration {
    /// Create a new GPU buffer registration (placeholder)
    pub fn new(device_id: u32, device_ptr: u64, size: usize) -> Self {
        // In a real implementation, this would register the GPU memory
        // with the RDMA NIC for direct access
        Self {
            device_id,
            device_ptr,
            size,
            rkey: 0,
            lkey: 0,
        }
    }
}

/// RDMA transport configuration
#[derive(Debug, Clone)]
pub struct RdmaTransportConfig {
    /// Maximum number of queue pairs (connections)
    pub max_queue_pairs: usize,
    /// Completion queue depth
    pub cq_depth: u32,
    /// Send queue depth
    pub sq_depth: u32,
    /// Receive queue depth
    pub rq_depth: u32,
    /// Pre-registered buffer count per connection
    pub buffers_per_qp: usize,
    /// Buffer size (should match typical message size)
    pub buffer_size: usize,
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Enable polling mode (lower latency, higher CPU)
    pub enable_polling: bool,
    /// Polling interval in microseconds
    pub poll_interval_us: u64,
}

impl Default for RdmaTransportConfig {
    fn default() -> Self {
        Self {
            max_queue_pairs: 64,
            cq_depth: 256,
            sq_depth: 128,
            rq_depth: 128,
            buffers_per_qp: 16,
            buffer_size: 64 * 1024, // 64KB
            connect_timeout: Duration::from_secs(5),
            enable_polling: true,
            poll_interval_us: 10,
        }
    }
}

impl RdmaTransportConfig {
    /// Configuration optimized for latency
    pub fn low_latency() -> Self {
        Self {
            max_queue_pairs: 32,
            cq_depth: 128,
            sq_depth: 64,
            rq_depth: 64,
            buffers_per_qp: 32,
            buffer_size: 4 * 1024, // 4KB for small messages
            connect_timeout: Duration::from_secs(2),
            enable_polling: true,
            poll_interval_us: 1,
        }
    }

    /// Configuration optimized for throughput
    pub fn high_throughput() -> Self {
        Self {
            max_queue_pairs: 128,
            cq_depth: 512,
            sq_depth: 256,
            rq_depth: 256,
            buffers_per_qp: 64,
            buffer_size: 256 * 1024, // 256KB for large transfers
            connect_timeout: Duration::from_secs(10),
            enable_polling: true,
            poll_interval_us: 50,
        }
    }
}

/// RDMA connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RdmaConnectionState {
    /// Not connected
    Disconnected,
    /// Connection in progress
    Connecting,
    /// Connected and ready
    Connected,
    /// Connection error
    Error,
}

/// RDMA endpoint representing a remote peer
#[derive(Debug)]
pub struct RdmaEndpoint {
    /// Peer identifier
    pub peer_id: String,
    /// Remote address
    pub addr: SocketAddr,
    /// Connection state
    state: RwLock<RdmaConnectionState>,
    /// RMPI endpoint handle
    #[cfg(feature = "rmpi")]
    rmpi_endpoint: Option<rmpi::Endpoint>,
    /// Statistics
    stats: RdmaEndpointStats,
}

#[derive(Debug, Default)]
struct RdmaEndpointStats {
    bytes_sent: AtomicU64,
    bytes_recv: AtomicU64,
    messages_sent: AtomicU64,
    messages_recv: AtomicU64,
    errors: AtomicU64,
    latency_sum_us: AtomicU64,
    latency_count: AtomicU64,
}

impl RdmaEndpoint {
    /// Create a new RDMA endpoint
    pub fn new(peer_id: String, addr: SocketAddr) -> Self {
        Self {
            peer_id,
            addr,
            state: RwLock::new(RdmaConnectionState::Disconnected),
            #[cfg(feature = "rmpi")]
            rmpi_endpoint: None,
            stats: RdmaEndpointStats::default(),
        }
    }

    /// Get connection state
    pub fn state(&self) -> RdmaConnectionState {
        *self.state.read()
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        *self.state.read() == RdmaConnectionState::Connected
    }

    /// Get statistics
    pub fn stats(&self) -> RdmaEndpointStatsSnapshot {
        let latency_count = self.stats.latency_count.load(Ordering::Relaxed);
        RdmaEndpointStatsSnapshot {
            bytes_sent: self.stats.bytes_sent.load(Ordering::Relaxed),
            bytes_recv: self.stats.bytes_recv.load(Ordering::Relaxed),
            messages_sent: self.stats.messages_sent.load(Ordering::Relaxed),
            messages_recv: self.stats.messages_recv.load(Ordering::Relaxed),
            errors: self.stats.errors.load(Ordering::Relaxed),
            avg_latency_us: if latency_count > 0 {
                self.stats.latency_sum_us.load(Ordering::Relaxed) / latency_count
            } else {
                0
            },
        }
    }

    fn record_send(&self, bytes: usize) {
        self.stats
            .bytes_sent
            .fetch_add(bytes as u64, Ordering::Relaxed);
        self.stats.messages_sent.fetch_add(1, Ordering::Relaxed);
    }

    fn record_recv(&self, bytes: usize, latency_us: u64) {
        self.stats
            .bytes_recv
            .fetch_add(bytes as u64, Ordering::Relaxed);
        self.stats.messages_recv.fetch_add(1, Ordering::Relaxed);
        self.stats
            .latency_sum_us
            .fetch_add(latency_us, Ordering::Relaxed);
        self.stats.latency_count.fetch_add(1, Ordering::Relaxed);
    }

    fn record_error(&self) {
        self.stats.errors.fetch_add(1, Ordering::Relaxed);
    }
}

/// Statistics snapshot for an RDMA endpoint
#[derive(Debug, Clone)]
pub struct RdmaEndpointStatsSnapshot {
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub messages_sent: u64,
    pub messages_recv: u64,
    pub errors: u64,
    pub avg_latency_us: u64,
}

/// RDMA Transport manager for Tier 2 communication
pub struct RdmaTransport {
    /// Configuration
    config: RdmaTransportConfig,
    /// Local peer ID
    local_peer_id: String,
    /// Connected endpoints
    endpoints: DashMap<String, Arc<RdmaEndpoint>>,
    /// RMPI handle for communication
    #[cfg(feature = "rmpi")]
    rmpi_handle: Option<rmpi::transport::RmpiHandle>,
    /// Running state
    running: AtomicBool,
    /// Aggregate statistics
    total_bytes_sent: AtomicU64,
    total_bytes_recv: AtomicU64,
}

impl RdmaTransport {
    /// Create a new RDMA transport
    pub fn new(local_peer_id: String, config: RdmaTransportConfig) -> Self {
        info!(peer_id = %local_peer_id, "Creating RDMA transport");
        Self {
            config,
            local_peer_id,
            endpoints: DashMap::new(),
            #[cfg(feature = "rmpi")]
            rmpi_handle: None,
            running: AtomicBool::new(true),
            total_bytes_sent: AtomicU64::new(0),
            total_bytes_recv: AtomicU64::new(0),
        }
    }

    /// Initialize RDMA transport with rmpi
    #[cfg(feature = "rmpi")]
    pub async fn init(&mut self, rank: u32) -> Result<()> {
        let endpoint = rmpi::Endpoint::from_rank(rank);
        let handle = rmpi::transport::RmpiHandle::new(endpoint);
        self.rmpi_handle = Some(handle);
        info!(rank, "RDMA transport initialized");
        Ok(())
    }

    #[cfg(not(feature = "rmpi"))]
    pub async fn init(&mut self, _rank: u32) -> Result<()> {
        info!("RDMA transport initialized (simulated)");
        Ok(())
    }

    /// Add an endpoint
    pub fn add_endpoint(&self, peer_id: String, addr: SocketAddr) -> Arc<RdmaEndpoint> {
        let endpoint = Arc::new(RdmaEndpoint::new(peer_id.clone(), addr));
        self.endpoints.insert(peer_id.clone(), endpoint.clone());
        debug!(peer_id = %peer_id, addr = %addr, "Added RDMA endpoint");
        endpoint
    }

    /// Get an endpoint
    pub fn get_endpoint(&self, peer_id: &str) -> Option<Arc<RdmaEndpoint>> {
        self.endpoints.get(peer_id).map(|e| e.clone())
    }

    /// Remove an endpoint
    pub fn remove_endpoint(&self, peer_id: &str) {
        self.endpoints.remove(peer_id);
        debug!(peer_id = %peer_id, "Removed RDMA endpoint");
    }

    /// Connect to a peer
    #[cfg(feature = "rmpi")]
    pub async fn connect(&self, endpoint: &Arc<RdmaEndpoint>) -> Result<()> {
        {
            let mut state = endpoint.state.write();
            if *state == RdmaConnectionState::Connected {
                return Ok(());
            }
            *state = RdmaConnectionState::Connecting;
        }

        // In real implementation, establish RDMA connection here
        // For now, mark as connected (rmpi handles connection internally)
        {
            let mut state = endpoint.state.write();
            *state = RdmaConnectionState::Connected;
        }

        info!(peer_id = %endpoint.peer_id, "RDMA connection established");
        Ok(())
    }

    #[cfg(not(feature = "rmpi"))]
    pub async fn connect(&self, endpoint: &Arc<RdmaEndpoint>) -> Result<()> {
        let mut state = endpoint.state.write();
        *state = RdmaConnectionState::Connected;
        info!(peer_id = %endpoint.peer_id, "RDMA connection established (simulated)");
        Ok(())
    }

    /// Send data to an endpoint using chunked protocol for SafeSend compatibility
    #[cfg(feature = "rmpi")]
    pub async fn send(&self, endpoint: &Arc<RdmaEndpoint>, data: &[u8]) -> Result<()> {
        if !endpoint.is_connected() {
            return Err(Error::Transport("Endpoint not connected".into()));
        }

        let start = Instant::now();

        if let Some(handle) = &self.rmpi_handle {
            // Parse peer_id to get rank
            let rank: u32 = endpoint.peer_id.parse().unwrap_or(0);
            let rmpi_endpoint = rmpi::Endpoint::from_rank(rank);

            // Use chunking protocol for SafeSend compatibility
            // Split data into fixed-size chunks that rmpi can handle
            const CHUNK_SIZE: usize = 64 * 1024; // 64KB chunks

            // Create and send header
            let header = RdmaChunkHeader::new(data.len(), CHUNK_SIZE);
            let header_bytes = header.to_bytes();

            // Send header first
            if let Err(e) = handle.send_bytes(rmpi_endpoint, &header_bytes).await {
                endpoint.record_error();
                return Err(Error::Transport(format!("Failed to send header: {}", e)));
            }

            // Send data in chunks
            for (chunk_idx, chunk) in data.chunks(CHUNK_SIZE).enumerate() {
                // Pad chunk to fixed size for SafeSend
                let mut padded = [0u8; CHUNK_SIZE];
                padded[..chunk.len()].copy_from_slice(chunk);

                if let Err(e) = handle.send_bytes(rmpi_endpoint, &padded[..]).await {
                    endpoint.record_error();
                    return Err(Error::Transport(format!(
                        "Failed to send chunk {}: {}",
                        chunk_idx, e
                    )));
                }
            }

            endpoint.record_send(data.len());
            self.total_bytes_sent
                .fetch_add(data.len() as u64, Ordering::Relaxed);

            trace!(
                peer_id = %endpoint.peer_id,
                bytes = data.len(),
                chunks = header.chunk_count,
                latency_us = start.elapsed().as_micros(),
                "RDMA send complete"
            );
            Ok(())
        } else {
            Err(Error::Transport("RMPI handle not initialized".into()))
        }
    }

    #[cfg(not(feature = "rmpi"))]
    pub async fn send(&self, endpoint: &Arc<RdmaEndpoint>, data: &[u8]) -> Result<()> {
        if !endpoint.is_connected() {
            return Err(Error::Transport("Endpoint not connected".into()));
        }
        endpoint.record_send(data.len());
        self.total_bytes_sent
            .fetch_add(data.len() as u64, Ordering::Relaxed);
        trace!(peer_id = %endpoint.peer_id, bytes = data.len(), "RDMA send complete (simulated)");
        Ok(())
    }

    /// Receive data from an endpoint using chunked protocol
    #[cfg(feature = "rmpi")]
    pub async fn recv(&self, endpoint: &Arc<RdmaEndpoint>, buf: &mut [u8]) -> Result<usize> {
        if !endpoint.is_connected() {
            return Err(Error::Transport("Endpoint not connected".into()));
        }

        let start = Instant::now();

        if let Some(handle) = &self.rmpi_handle {
            let rank: u32 = endpoint.peer_id.parse().unwrap_or(0);
            let rmpi_endpoint = rmpi::Endpoint::from_rank(rank);

            const CHUNK_SIZE: usize = 64 * 1024; // Must match send chunk size

            // Receive header first
            let header_bytes = match handle.recv_bytes(rmpi_endpoint, RdmaChunkHeader::SIZE).await {
                Ok(bytes) => bytes,
                Err(e) => {
                    endpoint.record_error();
                    return Err(Error::Transport(format!("Failed to receive header: {}", e)));
                }
            };

            let header = RdmaChunkHeader::from_bytes(&header_bytes)?;

            // Validate header
            if header.total_length as usize > buf.len() {
                return Err(Error::Transport(format!(
                    "Buffer too small: {} bytes needed, {} available",
                    header.total_length,
                    buf.len()
                )));
            }

            // Receive chunks
            let mut offset = 0usize;
            let mut remaining = header.total_length as usize;

            for chunk_idx in 0..header.chunk_count {
                let chunk_bytes = match handle.recv_bytes(rmpi_endpoint, CHUNK_SIZE).await {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        endpoint.record_error();
                        return Err(Error::Transport(format!(
                            "Failed to receive chunk {}: {}",
                            chunk_idx, e
                        )));
                    }
                };

                // Copy only valid portion of chunk
                let take = remaining.min(CHUNK_SIZE);
                buf[offset..offset + take].copy_from_slice(&chunk_bytes[..take]);
                offset += take;
                remaining = remaining.saturating_sub(CHUNK_SIZE);
            }

            // Verify checksum if provided
            if header.checksum != 0 {
                let computed = crc32fast::hash(&buf[..header.total_length as usize]);
                if computed != header.checksum {
                    endpoint.record_error();
                    return Err(Error::Transport(format!(
                        "Checksum mismatch: expected 0x{:08X}, got 0x{:08X}",
                        header.checksum, computed
                    )));
                }
            }

            let len = header.total_length as usize;
            let latency_us = start.elapsed().as_micros() as u64;
            endpoint.record_recv(len, latency_us);
            self.total_bytes_recv
                .fetch_add(len as u64, Ordering::Relaxed);

            trace!(
                peer_id = %endpoint.peer_id,
                bytes = len,
                chunks = header.chunk_count,
                latency_us = latency_us,
                "RDMA recv complete"
            );
            Ok(len)
        } else {
            Err(Error::Transport("RMPI handle not initialized".into()))
        }
    }

    #[cfg(not(feature = "rmpi"))]
    pub async fn recv(&self, endpoint: &Arc<RdmaEndpoint>, buf: &mut [u8]) -> Result<usize> {
        if !endpoint.is_connected() {
            return Err(Error::Transport("Endpoint not connected".into()));
        }
        let _ = buf; // Silence unused warning
        // Simulated recv - just return 0
        Ok(0)
    }

    /// Receive data into a new Vec using chunked protocol
    #[cfg(feature = "rmpi")]
    pub async fn recv_vec(&self, endpoint: &Arc<RdmaEndpoint>) -> Result<Vec<u8>> {
        if !endpoint.is_connected() {
            return Err(Error::Transport("Endpoint not connected".into()));
        }

        let start = Instant::now();

        if let Some(handle) = &self.rmpi_handle {
            let rank: u32 = endpoint.peer_id.parse().unwrap_or(0);
            let rmpi_endpoint = rmpi::Endpoint::from_rank(rank);

            const CHUNK_SIZE: usize = 64 * 1024;

            // Receive header
            let header_bytes = handle
                .recv_bytes(rmpi_endpoint, RdmaChunkHeader::SIZE)
                .await
                .map_err(|e| Error::Transport(format!("Failed to receive header: {}", e)))?;

            let header = RdmaChunkHeader::from_bytes(&header_bytes)?;

            // Allocate buffer
            let mut data = Vec::with_capacity(header.total_length as usize);
            let mut remaining = header.total_length as usize;

            // Receive chunks
            for chunk_idx in 0..header.chunk_count {
                let chunk_bytes = handle
                    .recv_bytes(rmpi_endpoint, CHUNK_SIZE)
                    .await
                    .map_err(|e| {
                        endpoint.record_error();
                        Error::Transport(format!("Failed to receive chunk {}: {}", chunk_idx, e))
                    })?;

                let take = remaining.min(CHUNK_SIZE);
                data.extend_from_slice(&chunk_bytes[..take]);
                remaining = remaining.saturating_sub(CHUNK_SIZE);
            }

            // Verify checksum
            if header.checksum != 0 {
                let computed = crc32fast::hash(&data);
                if computed != header.checksum {
                    endpoint.record_error();
                    return Err(Error::Transport(format!(
                        "Checksum mismatch: expected 0x{:08X}, got 0x{:08X}",
                        header.checksum, computed
                    )));
                }
            }

            let len = data.len();
            let latency_us = start.elapsed().as_micros() as u64;
            endpoint.record_recv(len, latency_us);
            self.total_bytes_recv
                .fetch_add(len as u64, Ordering::Relaxed);

            trace!(
                peer_id = %endpoint.peer_id,
                bytes = len,
                chunks = header.chunk_count,
                latency_us = latency_us,
                "RDMA recv_vec complete"
            );
            Ok(data)
        } else {
            Err(Error::Transport("RMPI handle not initialized".into()))
        }
    }

    #[cfg(not(feature = "rmpi"))]
    pub async fn recv_vec(&self, endpoint: &Arc<RdmaEndpoint>) -> Result<Vec<u8>> {
        if !endpoint.is_connected() {
            return Err(Error::Transport("Endpoint not connected".into()));
        }
        Ok(Vec::new())
    }

    /// Register GPU buffer for RDMA access
    #[cfg(all(feature = "rmpi", feature = "gpu"))]
    pub fn register_gpu_buffer(
        &self,
        device_id: u32,
        device_ptr: u64,
        size: usize,
    ) -> Result<GpuBufferRegistration> {
        if self.rmpi_handle.is_none() {
            return Err(Error::Transport("RMPI handle not initialized".into()));
        }

        // In a real implementation, this would:
        // 1. Call cuMemHostRegister or equivalent to pin the GPU memory
        // 2. Register the memory region with the RDMA NIC
        // 3. Return the registration keys

        info!(
            device_id,
            device_ptr,
            size,
            "Registered GPU buffer for RDMA"
        );

        Ok(GpuBufferRegistration::new(device_id, device_ptr, size))
    }

    /// Unregister GPU buffer from RDMA
    #[cfg(all(feature = "rmpi", feature = "gpu"))]
    pub fn unregister_gpu_buffer(&self, registration: &GpuBufferRegistration) -> Result<()> {
        if self.rmpi_handle.is_none() {
            return Err(Error::Transport("RMPI handle not initialized".into()));
        }

        info!(
            device_id = registration.device_id,
            device_ptr = registration.device_ptr,
            size = registration.size,
            "Unregistered GPU buffer from RDMA"
        );

        Ok(())
    }

    /// Send a storage message
    pub async fn send_message(
        &self,
        endpoint: &Arc<RdmaEndpoint>,
        msg: &StorageMessage,
    ) -> Result<()> {
        let data = self.serialize_message(msg)?;
        self.send(endpoint, &data).await
    }

    /// Receive a storage message
    pub async fn recv_message(&self, endpoint: &Arc<RdmaEndpoint>) -> Result<StorageMessage> {
        let mut buf = vec![0u8; self.config.buffer_size];
        let len = self.recv(endpoint, &mut buf).await?;
        buf.truncate(len);
        self.deserialize_message(&buf)
    }

    /// Serialize a storage message
    fn serialize_message(&self, msg: &StorageMessage) -> Result<Vec<u8>> {
        // Simple serialization using message pack
        rmp_serde::to_vec(msg)
            .map_err(|e| Error::Serialization(format!("Failed to serialize message: {}", e)))
    }

    /// Deserialize a storage message
    fn deserialize_message(&self, data: &[u8]) -> Result<StorageMessage> {
        rmp_serde::from_slice(data)
            .map_err(|e| Error::Serialization(format!("Failed to deserialize message: {}", e)))
    }

    /// Get tier statistics
    pub fn tier_stats(&self) -> TierStats {
        let mut total_latency = 0u64;
        let mut total_count = 0u64;
        let mut active = 0usize;

        for endpoint in self.endpoints.iter() {
            let stats = endpoint.stats();
            total_latency += stats.avg_latency_us * stats.messages_recv;
            total_count += stats.messages_recv;
            if endpoint.is_connected() {
                active += 1;
            }
        }

        TierStats {
            messages_sent: self.endpoints.iter().map(|e| e.stats().messages_sent).sum(),
            messages_recv: self.endpoints.iter().map(|e| e.stats().messages_recv).sum(),
            bytes_sent: self.total_bytes_sent.load(Ordering::Relaxed),
            bytes_recv: self.total_bytes_recv.load(Ordering::Relaxed),
            active_connections: active,
            avg_latency_us: if total_count > 0 {
                total_latency / total_count
            } else {
                0
            },
        }
    }

    /// Check if RDMA is available
    pub fn is_available(&self) -> bool {
        #[cfg(feature = "rmpi")]
        {
            self.rmpi_handle.is_some()
        }
        #[cfg(not(feature = "rmpi"))]
        {
            false
        }
    }

    /// Shutdown transport
    pub fn shutdown(&self) {
        self.running.store(false, Ordering::SeqCst);
        info!("RDMA transport shutdown");
    }
}

/// Select optimal transport for a peer based on locality
pub fn select_transport(local: &PeerLocation, remote: &PeerLocation, rdma_available: bool) -> Tier {
    let tier = remote.optimal_tier(local);

    // If Tier2 is selected but RDMA isn't available, fall back to Tier3
    if tier == Tier::Tier2 && !rdma_available {
        debug!(
            peer_id = %remote.peer_id,
            "RDMA unavailable, falling back to Tier3"
        );
        return Tier::Tier3;
    }

    tier
}

/// Helper to create RDMA transport from peer location
pub fn peer_to_endpoint(peer: &PeerLocation) -> Option<(String, SocketAddr)> {
    peer.addr.map(|addr| (peer.peer_id.clone(), addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rdma_config_defaults() {
        let config = RdmaTransportConfig::default();
        assert_eq!(config.max_queue_pairs, 64);
        assert!(config.enable_polling);
    }

    #[test]
    fn test_rdma_config_presets() {
        let low_lat = RdmaTransportConfig::low_latency();
        assert_eq!(low_lat.buffer_size, 4 * 1024);
        assert_eq!(low_lat.poll_interval_us, 1);

        let high_tp = RdmaTransportConfig::high_throughput();
        assert_eq!(high_tp.buffer_size, 256 * 1024);
        assert_eq!(high_tp.max_queue_pairs, 128);
    }

    #[test]
    fn test_rdma_endpoint_creation() {
        let endpoint = RdmaEndpoint::new("peer-1".to_string(), "10.0.0.1:9000".parse().unwrap());
        assert_eq!(endpoint.peer_id, "peer-1");
        assert_eq!(endpoint.state(), RdmaConnectionState::Disconnected);
    }

    #[test]
    fn test_rdma_endpoint_stats() {
        let endpoint = RdmaEndpoint::new("peer-1".to_string(), "10.0.0.1:9000".parse().unwrap());

        endpoint.record_send(1000);
        endpoint.record_recv(2000, 50);

        let stats = endpoint.stats();
        assert_eq!(stats.bytes_sent, 1000);
        assert_eq!(stats.bytes_recv, 2000);
        assert_eq!(stats.messages_sent, 1);
        assert_eq!(stats.messages_recv, 1);
        assert_eq!(stats.avg_latency_us, 50);
    }

    #[test]
    fn test_rdma_transport_creation() {
        let config = RdmaTransportConfig::default();
        let transport = RdmaTransport::new("local-1".to_string(), config);
        assert_eq!(transport.local_peer_id, "local-1");
    }

    #[test]
    fn test_add_remove_endpoint() {
        let config = RdmaTransportConfig::default();
        let transport = RdmaTransport::new("local-1".to_string(), config);

        let endpoint =
            transport.add_endpoint("peer-1".to_string(), "10.0.0.1:9000".parse().unwrap());
        assert!(transport.get_endpoint("peer-1").is_some());

        transport.remove_endpoint("peer-1");
        assert!(transport.get_endpoint("peer-1").is_none());
    }

    #[test]
    fn test_select_transport() {
        let mut local = PeerLocation::local();
        local.zone = Some("us-east-1a".to_string());

        // Same zone - should be Tier2
        let same_zone = PeerLocation::network(
            "peer-1".to_string(),
            "10.0.0.1:9000".parse().unwrap(),
            Some("us-east-1a".to_string()),
        );
        assert_eq!(select_transport(&local, &same_zone, true), Tier::Tier2);

        // Same zone but no RDMA - fall back to Tier3
        assert_eq!(select_transport(&local, &same_zone, false), Tier::Tier3);

        // Different zone - should be Tier3
        let diff_zone = PeerLocation::network(
            "peer-2".to_string(),
            "10.1.0.1:9000".parse().unwrap(),
            Some("eu-west-1a".to_string()),
        );
        assert_eq!(select_transport(&local, &diff_zone, true), Tier::Tier3);
    }

    #[test]
    fn test_peer_to_endpoint() {
        let peer = PeerLocation::network(
            "peer-1".to_string(),
            "10.0.0.1:9000".parse().unwrap(),
            Some("us-east-1a".to_string()),
        );

        let result = peer_to_endpoint(&peer);
        assert!(result.is_some());
        let (id, addr) = result.unwrap();
        assert_eq!(id, "peer-1");
        assert_eq!(addr.to_string(), "10.0.0.1:9000");

        // No address
        let local = PeerLocation::local();
        assert!(peer_to_endpoint(&local).is_none());
    }

    #[tokio::test]
    async fn test_transport_connect() {
        let config = RdmaTransportConfig::default();
        let transport = RdmaTransport::new("local-1".to_string(), config);

        let endpoint =
            transport.add_endpoint("peer-1".to_string(), "10.0.0.1:9000".parse().unwrap());

        assert!(!endpoint.is_connected());
        transport.connect(&endpoint).await.unwrap();
        assert!(endpoint.is_connected());
    }

    // --- RdmaChunkHeader tests ---

    #[test]
    fn test_chunk_header_new() {
        // Test with normal data
        let header = RdmaChunkHeader::new(100_000, 64 * 1024);
        assert_eq!(header.magic, RdmaChunkHeader::MAGIC);
        assert_eq!(header.total_length, 100_000);
        assert_eq!(header.chunk_size, 64 * 1024);
        assert_eq!(header.chunk_count, 2); // ceil(100000 / 65536) = 2
        assert_eq!(header.checksum, 0);
    }

    #[test]
    fn test_chunk_header_empty() {
        // Empty data should have 0 chunks
        let header = RdmaChunkHeader::new(0, 64 * 1024);
        assert_eq!(header.chunk_count, 0);
        assert_eq!(header.total_length, 0);
    }

    #[test]
    fn test_chunk_header_exact_chunk() {
        // Data exactly fills one chunk
        let header = RdmaChunkHeader::new(64 * 1024, 64 * 1024);
        assert_eq!(header.chunk_count, 1);
    }

    #[test]
    fn test_chunk_header_small_data() {
        // Small data under one chunk
        let header = RdmaChunkHeader::new(100, 64 * 1024);
        assert_eq!(header.chunk_count, 1);
        assert_eq!(header.total_length, 100);
    }

    #[test]
    fn test_chunk_header_with_checksum() {
        let data = b"hello world test data for checksum";
        let header = RdmaChunkHeader::with_checksum(data.len(), 64 * 1024, data);
        assert_eq!(header.total_length, data.len() as u64);
        assert_ne!(header.checksum, 0);
        // Verify checksum matches crc32
        assert_eq!(header.checksum, crc32fast::hash(data));
    }

    #[test]
    fn test_chunk_header_roundtrip() {
        let original = RdmaChunkHeader {
            magic: RdmaChunkHeader::MAGIC,
            total_length: 1_000_000,
            chunk_count: 16,
            chunk_size: 65536,
            checksum: 0xDEADBEEF,
        };

        let bytes = original.to_bytes();
        assert_eq!(bytes.len(), RdmaChunkHeader::SIZE);

        let parsed = RdmaChunkHeader::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.magic, original.magic);
        assert_eq!(parsed.total_length, original.total_length);
        assert_eq!(parsed.chunk_count, original.chunk_count);
        assert_eq!(parsed.chunk_size, original.chunk_size);
        assert_eq!(parsed.checksum, original.checksum);
    }

    #[test]
    fn test_chunk_header_from_bytes_too_short() {
        let short_bytes = [0u8; 10];
        let result = RdmaChunkHeader::from_bytes(&short_bytes);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("too short"));
    }

    #[test]
    fn test_chunk_header_from_bytes_invalid_magic() {
        let mut bytes = [0u8; RdmaChunkHeader::SIZE];
        // Wrong magic number
        bytes[0..4].copy_from_slice(&0xBADCAFE_u32.to_le_bytes());

        let result = RdmaChunkHeader::from_bytes(&bytes);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Invalid chunk header magic"));
    }

    #[test]
    fn test_chunk_header_serialization_format() {
        let header = RdmaChunkHeader {
            magic: RdmaChunkHeader::MAGIC,
            total_length: 0x0123456789ABCDEF,
            chunk_count: 0x12345678,
            chunk_size: 0x9ABCDEF0,
            checksum: 0xFEDCBA98,
        };

        let bytes = header.to_bytes();

        // Verify little-endian format
        assert_eq!(&bytes[0..4], &RdmaChunkHeader::MAGIC.to_le_bytes());
        assert_eq!(&bytes[4..12], &0x0123456789ABCDEF_u64.to_le_bytes());
        assert_eq!(&bytes[12..16], &0x12345678_u32.to_le_bytes());
        assert_eq!(&bytes[16..20], &0x9ABCDEF0_u32.to_le_bytes());
        assert_eq!(&bytes[20..24], &0xFEDCBA98_u32.to_le_bytes());
    }

    #[test]
    fn test_chunk_count_calculation() {
        // Test various sizes to ensure chunk count is correct
        let cases = [
            (0, 65536, 0),
            (1, 65536, 1),
            (65535, 65536, 1),
            (65536, 65536, 1),
            (65537, 65536, 2),
            (131072, 65536, 2),
            (131073, 65536, 3),
            (1_000_000, 65536, 16), // ceil(1000000/65536) = 16
        ];

        for (total_length, chunk_size, expected_chunks) in cases {
            let header = RdmaChunkHeader::new(total_length, chunk_size);
            assert_eq!(
                header.chunk_count, expected_chunks,
                "total_length={}, chunk_size={} should yield {} chunks",
                total_length, chunk_size, expected_chunks
            );
        }
    }

    // --- GpuBufferRegistration tests (gpu feature only) ---

    #[cfg(feature = "gpu")]
    #[test]
    fn test_gpu_buffer_registration_new() {
        let reg = GpuBufferRegistration::new(0, 0x7F00000000, 4 * 1024 * 1024);
        assert_eq!(reg.device_id, 0);
        assert_eq!(reg.device_ptr, 0x7F00000000);
        assert_eq!(reg.size, 4 * 1024 * 1024);
        // Keys are placeholder values
        assert_eq!(reg.rkey, 0);
        assert_eq!(reg.lkey, 0);
    }

    // --- RdmaConnectionState tests ---

    #[test]
    fn test_connection_state_transitions() {
        let endpoint = RdmaEndpoint::new("test".to_string(), "10.0.0.1:9000".parse().unwrap());

        // Initial state
        assert_eq!(endpoint.state(), RdmaConnectionState::Disconnected);
        assert!(!endpoint.is_connected());

        // Simulate connection
        {
            let mut state = endpoint.state.write();
            *state = RdmaConnectionState::Connecting;
        }
        assert_eq!(endpoint.state(), RdmaConnectionState::Connecting);
        assert!(!endpoint.is_connected());

        // Complete connection
        {
            let mut state = endpoint.state.write();
            *state = RdmaConnectionState::Connected;
        }
        assert_eq!(endpoint.state(), RdmaConnectionState::Connected);
        assert!(endpoint.is_connected());

        // Error state
        {
            let mut state = endpoint.state.write();
            *state = RdmaConnectionState::Error;
        }
        assert_eq!(endpoint.state(), RdmaConnectionState::Error);
        assert!(!endpoint.is_connected());
    }

    #[test]
    fn test_endpoint_error_tracking() {
        let endpoint = RdmaEndpoint::new("test".to_string(), "10.0.0.1:9000".parse().unwrap());

        assert_eq!(endpoint.stats().errors, 0);

        endpoint.record_error();
        endpoint.record_error();
        endpoint.record_error();

        assert_eq!(endpoint.stats().errors, 3);
    }

    #[test]
    fn test_endpoint_latency_average() {
        let endpoint = RdmaEndpoint::new("test".to_string(), "10.0.0.1:9000".parse().unwrap());

        // Record multiple receives with different latencies
        endpoint.record_recv(100, 10);   // 10µs
        endpoint.record_recv(100, 20);   // 20µs
        endpoint.record_recv(100, 30);   // 30µs

        let stats = endpoint.stats();
        assert_eq!(stats.messages_recv, 3);
        assert_eq!(stats.bytes_recv, 300);
        // Average should be (10+20+30)/3 = 20
        assert_eq!(stats.avg_latency_us, 20);
    }

    #[test]
    fn test_tier_stats_aggregation() {
        let config = RdmaTransportConfig::default();
        let transport = RdmaTransport::new("local".to_string(), config);

        // Add multiple endpoints
        let ep1 = transport.add_endpoint("peer-1".to_string(), "10.0.0.1:9000".parse().unwrap());
        let ep2 = transport.add_endpoint("peer-2".to_string(), "10.0.0.2:9000".parse().unwrap());

        // Record some stats
        ep1.record_send(1000);
        ep1.record_recv(2000, 50);
        ep2.record_send(3000);
        ep2.record_recv(4000, 100);

        let stats = transport.tier_stats();
        assert_eq!(stats.messages_sent, 2);
        assert_eq!(stats.messages_recv, 2);
        // Note: total bytes are tracked on transport level
    }
}
