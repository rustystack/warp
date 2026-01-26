//! WireGuard tunnel management for cross-domain transport
//!
//! Provides secure tunnel infrastructure between storage domains.
//!
//! # Feature Flags
//!
//! - `wireguard`: Basic tunnel management with simulated encryption
//! - `wireguard-native`: Real WireGuard encryption via boringtun-warp

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, mpsc};
use tracing::{debug, info, trace, warn};

#[cfg(feature = "wireguard-native")]
use boringtun_warp::noise::{Tunn, TunnResult};

/// Helper enum for process_incoming results (used with wireguard-native feature)
#[cfg(feature = "wireguard-native")]
enum ProcessResult {
    SendResponse(Bytes),
    Data(Bytes),
    Done { handshake_complete: bool },
    Error(String),
}

use super::DomainId;
use crate::error::{Error, Result};

/// WireGuard configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardConfig {
    /// UDP port to listen on (default: 51820)
    pub listen_port: u16,

    /// Keepalive interval (default: 25 seconds)
    pub keepalive_interval: Duration,

    /// MTU for WireGuard packets (default: 1420)
    pub mtu: u16,

    /// Connection timeout
    pub connect_timeout: Duration,

    /// Maximum concurrent tunnels
    pub max_tunnels: usize,

    /// Handshake timeout
    pub handshake_timeout: Duration,

    /// Maximum handshake retries
    pub max_handshake_retries: u32,
}

impl Default for WireGuardConfig {
    fn default() -> Self {
        Self {
            listen_port: 51820,
            keepalive_interval: Duration::from_secs(25),
            mtu: 1420,
            connect_timeout: Duration::from_secs(10),
            max_tunnels: 64,
            handshake_timeout: Duration::from_secs(5),
            max_handshake_retries: 3,
        }
    }
}

/// Status of a WireGuard tunnel
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TunnelStatus {
    /// Tunnel is being established
    Connecting,
    /// Handshake in progress
    Handshaking,
    /// Tunnel is active and healthy
    Connected,
    /// Tunnel connection failed
    Failed,
    /// Tunnel was closed
    Closed,
    /// Reconnecting after failure
    Reconnecting,
}

/// Statistics for a WireGuard tunnel
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TunnelStats {
    /// Bytes sent through this tunnel
    pub bytes_sent: u64,

    /// Bytes received through this tunnel
    pub bytes_received: u64,

    /// Packets sent
    pub packets_sent: u64,

    /// Packets received
    pub packets_received: u64,

    /// Last handshake time (not serialized)
    #[serde(skip, default)]
    pub last_handshake: Option<Instant>,

    /// Round-trip latency (if measured)
    pub latency_ms: Option<u32>,

    /// Handshake count
    pub handshake_count: u32,

    /// Failed handshake count
    pub failed_handshakes: u32,

    /// Packet loss rate (0.0 - 1.0)
    pub packet_loss_rate: f32,
}

/// Health status for a tunnel
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TunnelHealth {
    /// Tunnel health is unknown
    Unknown,
    /// Tunnel is healthy
    Healthy,
    /// Tunnel is degraded (high latency or packet loss)
    Degraded,
    /// Tunnel is unhealthy
    Unhealthy,
}

impl TunnelStats {
    /// Update latency measurement
    pub fn update_latency(&mut self, latency: Duration) {
        self.latency_ms = Some(latency.as_millis() as u32);
    }

    /// Calculate current health based on stats
    pub fn health(&self) -> TunnelHealth {
        if let Some(latency) = self.latency_ms {
            if latency > 1000 || self.packet_loss_rate > 0.1 {
                return TunnelHealth::Unhealthy;
            }
            if latency > 200 || self.packet_loss_rate > 0.01 {
                return TunnelHealth::Degraded;
            }
            return TunnelHealth::Healthy;
        }
        TunnelHealth::Unknown
    }
}

/// Represents an active WireGuard tunnel to a remote domain
pub struct WireGuardTunnel {
    /// Target domain ID
    pub domain_id: DomainId,

    /// Remote peer's public key
    pub peer_pubkey: [u8; 32],

    /// Remote endpoint
    pub endpoint: SocketAddr,

    /// Virtual IP assigned to this tunnel
    pub virtual_ip: std::net::Ipv4Addr,

    /// Current tunnel status
    pub status: TunnelStatus,

    /// Tunnel statistics
    pub stats: TunnelStats,

    /// When the tunnel was created
    pub created_at: Instant,

    /// Last activity timestamp
    pub last_activity: Instant,

    /// Send channel for outgoing data
    send_tx: mpsc::Sender<Bytes>,

    /// Receive channel for incoming data
    recv_rx: Arc<RwLock<mpsc::Receiver<Bytes>>>,

    /// Real WireGuard tunnel (when wireguard-native feature is enabled)
    #[cfg(feature = "wireguard-native")]
    tunn: Arc<parking_lot::Mutex<Tunn>>,
}

impl std::fmt::Debug for WireGuardTunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireGuardTunnel")
            .field("domain_id", &self.domain_id)
            .field("endpoint", &self.endpoint)
            .field("virtual_ip", &self.virtual_ip)
            .field("status", &self.status)
            .finish()
    }
}

impl WireGuardTunnel {
    /// Create a new tunnel (internal)
    #[cfg(not(feature = "wireguard-native"))]
    fn new(
        domain_id: DomainId,
        peer_pubkey: [u8; 32],
        endpoint: SocketAddr,
        virtual_ip: std::net::Ipv4Addr,
        send_tx: mpsc::Sender<Bytes>,
        recv_rx: mpsc::Receiver<Bytes>,
    ) -> Self {
        let now = Instant::now();
        Self {
            domain_id,
            peer_pubkey,
            endpoint,
            virtual_ip,
            status: TunnelStatus::Connecting,
            stats: TunnelStats::default(),
            created_at: now,
            last_activity: now,
            send_tx,
            recv_rx: Arc::new(RwLock::new(recv_rx)),
        }
    }

    /// Create a new tunnel with real WireGuard encryption (internal)
    #[cfg(feature = "wireguard-native")]
    fn new(
        domain_id: DomainId,
        peer_pubkey: [u8; 32],
        endpoint: SocketAddr,
        virtual_ip: std::net::Ipv4Addr,
        send_tx: mpsc::Sender<Bytes>,
        recv_rx: mpsc::Receiver<Bytes>,
        static_private: x25519_dalek::StaticSecret,
    ) -> Self {
        let now = Instant::now();

        // Create the boringtun tunnel
        let peer_public = boringtun_warp::x25519::PublicKey::from(peer_pubkey);
        let tunn = Tunn::new(
            static_private.into(),
            peer_public,
            None,                         // preshared key
            Some(25),                     // persistent keepalive (25 seconds)
            domain_id.try_into().unwrap_or(0),
        )
        .expect("Failed to create WireGuard tunnel");

        Self {
            domain_id,
            peer_pubkey,
            endpoint,
            virtual_ip,
            status: TunnelStatus::Connecting,
            stats: TunnelStats::default(),
            created_at: now,
            last_activity: now,
            send_tx,
            recv_rx: Arc::new(RwLock::new(recv_rx)),
            tunn: Arc::new(parking_lot::Mutex::new(tunn)),
        }
    }

    /// Check if tunnel is connected
    pub fn is_connected(&self) -> bool {
        self.status == TunnelStatus::Connected
    }

    /// Get tunnel age
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Get time since last activity
    pub fn idle_time(&self) -> Duration {
        self.last_activity.elapsed()
    }

    /// Get tunnel health
    pub fn health(&self) -> TunnelHealth {
        if !self.is_connected() {
            return TunnelHealth::Unhealthy;
        }
        self.stats.health()
    }

    /// Send data through the tunnel
    pub async fn send(&self, data: Bytes) -> Result<()> {
        if !self.is_connected() {
            return Err(Error::WireGuard("tunnel not connected".to_string()));
        }

        self.send_tx
            .send(data)
            .await
            .map_err(|_| Error::WireGuard("send channel closed".to_string()))
    }

    /// Receive data from the tunnel
    pub async fn recv(&self) -> Result<Bytes> {
        let mut rx = self.recv_rx.write().await;
        rx.recv()
            .await
            .ok_or_else(|| Error::WireGuard("receive channel closed".to_string()))
    }

    /// Try to receive data without blocking
    pub async fn try_recv(&self) -> Option<Bytes> {
        let mut rx = self.recv_rx.write().await;
        rx.try_recv().ok()
    }
}

/// X25519 keypair for WireGuard
#[derive(Debug)]
pub struct WireGuardKeyPair {
    /// Private key (32 bytes)
    pub private_key: [u8; 32],

    /// Public key (32 bytes)
    pub public_key: [u8; 32],
}

impl WireGuardKeyPair {
    /// Generate a new random keypair
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut rng = rand::thread_rng();

        let mut private_key = [0u8; 32];
        rng.fill_bytes(&mut private_key);

        // Clamp private key for X25519
        private_key[0] &= 248;
        private_key[31] &= 127;
        private_key[31] |= 64;

        // Derive public key using x25519-dalek
        let secret = x25519_dalek::StaticSecret::from(private_key);
        let public = x25519_dalek::PublicKey::from(&secret);

        Self {
            private_key,
            public_key: public.to_bytes(),
        }
    }

    /// Create from existing private key
    pub fn from_private_key(private_key: [u8; 32]) -> Self {
        let secret = x25519_dalek::StaticSecret::from(private_key);
        let public = x25519_dalek::PublicKey::from(&secret);

        Self {
            private_key,
            public_key: public.to_bytes(),
        }
    }
}

/// Manages WireGuard tunnels for cross-domain communication
pub struct WireGuardTunnelManager {
    /// Active tunnels indexed by domain ID
    tunnels: DashMap<DomainId, Arc<RwLock<WireGuardTunnel>>>,

    /// Local keypair
    keypair: WireGuardKeyPair,

    /// Configuration
    config: WireGuardConfig,

    /// UDP socket for WireGuard (when active)
    socket: RwLock<Option<Arc<UdpSocket>>>,

    /// Virtual IP allocator counter
    vip_counter: std::sync::atomic::AtomicU16,

    /// Health check interval
    health_check_interval: Duration,

    /// Shutdown signal
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
}

impl WireGuardTunnelManager {
    /// Create a new tunnel manager
    pub fn new(config: WireGuardConfig) -> Self {
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
        Self {
            tunnels: DashMap::new(),
            keypair: WireGuardKeyPair::generate(),
            config,
            socket: RwLock::new(None),
            vip_counter: std::sync::atomic::AtomicU16::new(2), // Start at 10.0.0.2
            health_check_interval: Duration::from_secs(10),
            shutdown_tx,
        }
    }

    /// Create with existing keypair
    pub fn with_keypair(config: WireGuardConfig, keypair: WireGuardKeyPair) -> Self {
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
        Self {
            tunnels: DashMap::new(),
            keypair,
            config,
            socket: RwLock::new(None),
            vip_counter: std::sync::atomic::AtomicU16::new(2),
            health_check_interval: Duration::from_secs(10),
            shutdown_tx,
        }
    }

    /// Get our public key
    pub fn public_key(&self) -> &[u8; 32] {
        &self.keypair.public_key
    }

    /// Get the configuration
    pub fn config(&self) -> &WireGuardConfig {
        &self.config
    }

    /// Initialize the WireGuard listener
    pub async fn start(&self) -> Result<()> {
        let addr = SocketAddr::from(([0, 0, 0, 0], self.config.listen_port));
        let socket = UdpSocket::bind(addr)
            .await
            .map_err(|e| Error::WireGuard(format!("failed to bind UDP: {}", e)))?;

        info!(port = self.config.listen_port, "WireGuard listener started");

        *self.socket.write().await = Some(Arc::new(socket));
        Ok(())
    }

    /// Start the background health monitoring task
    pub fn start_health_monitor(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let manager = Arc::clone(self);
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(manager.health_check_interval);

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        manager.check_tunnel_health().await;
                    }
                    _ = shutdown_rx.recv() => {
                        info!("Health monitor shutting down");
                        break;
                    }
                }
            }
        })
    }

    /// Check health of all tunnels
    async fn check_tunnel_health(&self) {
        let stale_threshold = self.config.keepalive_interval * 3;

        for entry in self.tunnels.iter() {
            let domain_id = *entry.key();
            let tunnel = entry.value();
            let mut t = tunnel.write().await;

            if t.is_connected() {
                // Check for stale tunnels
                if t.idle_time() > stale_threshold {
                    warn!(domain_id, "Tunnel appears stale, marking as degraded");
                    t.stats.packet_loss_rate = 0.5; // Mark as degraded
                }

                // Send keepalive
                self.send_keepalive(domain_id, &t).await;
            }
        }
    }

    /// Send keepalive packet to a tunnel
    async fn send_keepalive(&self, domain_id: DomainId, _tunnel: &WireGuardTunnel) {
        debug!(domain_id, "Sending keepalive");
        // In a real implementation, this would send a WireGuard keepalive packet
    }

    /// Stop the WireGuard listener
    pub async fn stop(&self) {
        let _ = self.shutdown_tx.send(());
        *self.socket.write().await = None;

        // Close all tunnels
        self.tunnels.clear();

        info!("WireGuard tunnel manager stopped");
    }

    /// Allocate a virtual IP for a new tunnel
    fn allocate_vip(&self) -> std::net::Ipv4Addr {
        let counter = self
            .vip_counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        // 10.0.x.y where x = counter / 256, y = counter % 256
        std::net::Ipv4Addr::new(10, 0, (counter / 256) as u8, (counter % 256) as u8)
    }

    /// Establish a tunnel to a remote domain
    ///
    /// When `wireguard-native` feature is enabled, uses real WireGuard encryption.
    /// Otherwise uses simulated tunnels for testing.
    #[cfg(not(feature = "wireguard-native"))]
    pub async fn connect(
        &self,
        domain_id: DomainId,
        peer_pubkey: [u8; 32],
        endpoint: SocketAddr,
    ) -> Result<()> {
        if self.tunnels.contains_key(&domain_id) {
            debug!(domain_id, "Tunnel already exists");
            return Ok(());
        }

        if self.tunnels.len() >= self.config.max_tunnels {
            return Err(Error::WireGuard("max tunnels reached".to_string()));
        }

        info!(domain_id, %endpoint, "Establishing WireGuard tunnel (simulated)");

        // Create channels for data transfer
        let (send_tx, _send_rx) = mpsc::channel(1024);
        let (_recv_tx, recv_rx) = mpsc::channel(1024);

        let vip = self.allocate_vip();

        let mut tunnel =
            WireGuardTunnel::new(domain_id, peer_pubkey, endpoint, vip, send_tx, recv_rx);
        tunnel.status = TunnelStatus::Connected;
        tunnel.stats.last_handshake = Some(Instant::now());
        tunnel.stats.handshake_count = 1;

        let tunnel = Arc::new(RwLock::new(tunnel));
        self.tunnels.insert(domain_id, tunnel);

        info!(domain_id, ?vip, "WireGuard tunnel established (simulated)");
        Ok(())
    }

    /// Establish a tunnel to a remote domain with real WireGuard encryption
    #[cfg(feature = "wireguard-native")]
    pub async fn connect(
        &self,
        domain_id: DomainId,
        peer_pubkey: [u8; 32],
        endpoint: SocketAddr,
    ) -> Result<()> {
        if self.tunnels.contains_key(&domain_id) {
            debug!(domain_id, "Tunnel already exists");
            return Ok(());
        }

        if self.tunnels.len() >= self.config.max_tunnels {
            return Err(Error::WireGuard("max tunnels reached".to_string()));
        }

        info!(domain_id, %endpoint, "Establishing WireGuard tunnel (native)");

        // Create channels for data transfer
        let (send_tx, _send_rx) = mpsc::channel(1024);
        let (_recv_tx, recv_rx) = mpsc::channel(1024);

        let vip = self.allocate_vip();

        // Create tunnel with our static key
        let static_private = x25519_dalek::StaticSecret::from(self.keypair.private_key);
        let mut tunnel = WireGuardTunnel::new(
            domain_id,
            peer_pubkey,
            endpoint,
            vip,
            send_tx,
            recv_rx,
            static_private,
        );
        tunnel.status = TunnelStatus::Handshaking;

        let tunnel = Arc::new(RwLock::new(tunnel));
        self.tunnels.insert(domain_id, tunnel.clone());

        // Initiate handshake
        self.initiate_handshake(domain_id, &tunnel).await?;

        info!(domain_id, ?vip, "WireGuard tunnel handshake initiated");
        Ok(())
    }

    /// Initiate WireGuard handshake
    #[cfg(feature = "wireguard-native")]
    async fn initiate_handshake(
        &self,
        domain_id: DomainId,
        tunnel: &Arc<RwLock<WireGuardTunnel>>,
    ) -> Result<()> {
        let mut dst = vec![0u8; 256];

        let (endpoint, data_to_send) = {
            let t = tunnel.read().await;
            let mut tunn = t.tunn.lock();

            match tunn.format_handshake_initiation(&mut dst, false) {
                TunnResult::WriteToNetwork(data) => (t.endpoint, Bytes::copy_from_slice(data)),
                TunnResult::Err(e) => {
                    warn!(domain_id, error = ?e, "Failed to create handshake initiation");
                    return Err(Error::WireGuard(format!("handshake init failed: {:?}", e)));
                }
                _ => return Ok(()),
            }
        };

        // Send handshake initiation via UDP
        self.send_raw(endpoint, &data_to_send).await?;

        debug!(domain_id, "Sent handshake initiation");
        Ok(())
    }

    /// Send raw UDP data
    #[cfg(feature = "wireguard-native")]
    async fn send_raw(&self, endpoint: SocketAddr, data: &[u8]) -> Result<()> {
        let socket = self.socket.read().await;
        if let Some(ref sock) = *socket {
            sock.send_to(data, endpoint)
                .await
                .map_err(|e| Error::WireGuard(format!("send failed: {}", e)))?;
        }
        Ok(())
    }

    /// Perform handshake with retries
    pub async fn connect_with_retry(
        &self,
        domain_id: DomainId,
        peer_pubkey: [u8; 32],
        endpoint: SocketAddr,
    ) -> Result<()> {
        let mut last_error = None;

        for attempt in 0..self.config.max_handshake_retries {
            match self.connect(domain_id, peer_pubkey, endpoint).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    warn!(domain_id, attempt, error = %e, "Handshake attempt failed");
                    last_error = Some(e);

                    // Exponential backoff
                    let delay = Duration::from_millis(100 * 2u64.pow(attempt));
                    tokio::time::sleep(delay).await;
                }
            }
        }

        // Update stats
        if let Some(tunnel) = self.tunnels.get(&domain_id) {
            let mut t = tunnel.write().await;
            t.stats.failed_handshakes += 1;
            t.status = TunnelStatus::Failed;
        }

        Err(last_error.unwrap_or_else(|| Error::WireGuard("handshake failed".to_string())))
    }

    /// Disconnect a tunnel
    pub async fn disconnect(&self, domain_id: DomainId) -> Result<()> {
        let tunnel = self
            .tunnels
            .remove(&domain_id)
            .ok_or_else(|| Error::WireGuard(format!("tunnel {} not found", domain_id)))?;

        {
            let mut t = tunnel.1.write().await;
            t.status = TunnelStatus::Closed;
        }

        info!(domain_id, "WireGuard tunnel disconnected");
        Ok(())
    }

    /// Get or establish a tunnel to a domain
    pub async fn get_or_connect(
        &self,
        domain_id: DomainId,
        peer_pubkey: [u8; 32],
        endpoint: SocketAddr,
    ) -> Result<Arc<RwLock<WireGuardTunnel>>> {
        if let Some(tunnel) = self.tunnels.get(&domain_id) {
            let t = tunnel.read().await;
            if t.is_connected() {
                return Ok(tunnel.clone());
            }
        }

        // Establish new tunnel
        self.connect(domain_id, peer_pubkey, endpoint).await?;

        self.tunnels
            .get(&domain_id)
            .map(|t| t.clone())
            .ok_or_else(|| Error::WireGuard("tunnel creation failed".to_string()))
    }

    /// Get an existing tunnel
    pub fn get_tunnel(&self, domain_id: DomainId) -> Option<Arc<RwLock<WireGuardTunnel>>> {
        self.tunnels.get(&domain_id).map(|t| t.clone())
    }

    /// Check if a tunnel exists and is connected
    pub async fn is_connected(&self, domain_id: DomainId) -> bool {
        if let Some(tunnel) = self.tunnels.get(&domain_id) {
            let t = tunnel.read().await;
            return t.is_connected();
        }
        false
    }

    /// Get tunnel health
    pub async fn tunnel_health(&self, domain_id: DomainId) -> Option<TunnelHealth> {
        if let Some(tunnel) = self.tunnels.get(&domain_id) {
            let t = tunnel.read().await;
            return Some(t.health());
        }
        None
    }

    /// Send data through a tunnel
    pub async fn send(&self, domain_id: DomainId, data: Bytes) -> Result<()> {
        let tunnel = self
            .tunnels
            .get(&domain_id)
            .ok_or_else(|| Error::WireGuard(format!("tunnel {} not found", domain_id)))?;

        let t = tunnel.read().await;
        if !t.is_connected() {
            return Err(Error::WireGuard("tunnel not connected".to_string()));
        }

        t.send(data).await
    }

    /// Receive data from a tunnel
    pub async fn recv(&self, domain_id: DomainId) -> Result<Bytes> {
        let tunnel = self
            .tunnels
            .get(&domain_id)
            .ok_or_else(|| Error::WireGuard(format!("tunnel {} not found", domain_id)))?;

        let t = tunnel.read().await;
        t.recv().await
    }

    /// Process incoming UDP packet (simulated mode)
    #[cfg(not(feature = "wireguard-native"))]
    pub async fn process_incoming(
        &self,
        src: SocketAddr,
        packet: &[u8],
    ) -> Result<Option<(DomainId, Bytes)>> {
        // Find the tunnel for this source
        for entry in self.tunnels.iter() {
            let domain_id = *entry.key();
            let tunnel = entry.value();
            let mut t = tunnel.write().await;

            if t.endpoint == src {
                // In simulated mode, just pass through the data
                t.stats.bytes_received += packet.len() as u64;
                t.stats.packets_received += 1;
                t.last_activity = Instant::now();
                return Ok(Some((domain_id, Bytes::copy_from_slice(packet))));
            }
        }

        Ok(None)
    }

    /// Process incoming UDP packet with real WireGuard decryption
    #[cfg(feature = "wireguard-native")]
    pub async fn process_incoming(
        &self,
        src: SocketAddr,
        packet: &[u8],
    ) -> Result<Option<(DomainId, Bytes)>> {
        // Find the tunnel for this source
        for entry in self.tunnels.iter() {
            let domain_id = *entry.key();
            let tunnel = entry.value();

            // Check if this tunnel matches the source
            let endpoint_matches = {
                let t = tunnel.read().await;
                t.endpoint == src
            };

            if !endpoint_matches {
                continue;
            }

            // Process the packet with the Tunn
            let mut dst = vec![0u8; packet.len() + 32];
            let result = {
                let t = tunnel.read().await;
                let mut tunn = t.tunn.lock();
                // Process and capture the result type and any data we need
                match tunn.decapsulate(Some(src.ip()), packet, &mut dst) {
                    TunnResult::WriteToNetwork(data) => {
                        ProcessResult::SendResponse(Bytes::copy_from_slice(data))
                    }
                    TunnResult::WriteToTunnelV4(data, _) | TunnResult::WriteToTunnelV6(data, _) => {
                        ProcessResult::Data(Bytes::copy_from_slice(data))
                    }
                    TunnResult::Done => {
                        let handshake_complete = tunn.time_since_last_handshake().is_some();
                        ProcessResult::Done { handshake_complete }
                    }
                    TunnResult::Err(e) => ProcessResult::Error(format!("{:?}", e)),
                }
            };

            // Now handle the result with mutable access to tunnel state
            match result {
                ProcessResult::SendResponse(data) => {
                    self.send_raw(src, &data).await?;
                    trace!(domain_id, "Sent WireGuard response");
                    return Ok(None);
                }
                ProcessResult::Data(data) => {
                    let mut t = tunnel.write().await;
                    t.stats.bytes_received += data.len() as u64;
                    t.stats.packets_received += 1;
                    t.last_activity = Instant::now();

                    if t.status == TunnelStatus::Handshaking {
                        t.status = TunnelStatus::Connected;
                        t.stats.last_handshake = Some(Instant::now());
                        t.stats.handshake_count += 1;
                        info!(domain_id, "WireGuard handshake completed");
                    }

                    return Ok(Some((domain_id, data)));
                }
                ProcessResult::Done { handshake_complete } => {
                    if handshake_complete {
                        let mut t = tunnel.write().await;
                        if t.status == TunnelStatus::Handshaking {
                            t.status = TunnelStatus::Connected;
                            t.stats.last_handshake = Some(Instant::now());
                            t.stats.handshake_count += 1;
                            info!(domain_id, "WireGuard handshake completed");
                        }
                    }
                    trace!(domain_id, "WireGuard packet processed (no data)");
                    return Ok(None);
                }
                ProcessResult::Error(e) => {
                    warn!(domain_id, error = %e, "WireGuard decrypt error");
                    let mut t = tunnel.write().await;
                    t.stats.failed_handshakes += 1;
                    return Ok(None);
                }
            }
        }

        Ok(None)
    }


    /// Encrypt and send data through a tunnel
    #[cfg(feature = "wireguard-native")]
    pub async fn send_encrypted(&self, domain_id: DomainId, data: &[u8]) -> Result<()> {
        let tunnel = self
            .tunnels
            .get(&domain_id)
            .ok_or_else(|| Error::WireGuard(format!("tunnel {} not found", domain_id)))?;

        let (endpoint, encrypted) = {
            let t = tunnel.read().await;
            if !t.is_connected() {
                return Err(Error::WireGuard("tunnel not connected".to_string()));
            }

            let mut dst = vec![0u8; data.len() + 64]; // Extra space for WireGuard overhead
            let mut tunn = t.tunn.lock();

            match tunn.encapsulate(data, &mut dst) {
                TunnResult::WriteToNetwork(encrypted_data) => {
                    (t.endpoint, Bytes::copy_from_slice(encrypted_data))
                }
                TunnResult::Err(e) => {
                    return Err(Error::WireGuard(format!("encryption failed: {:?}", e)));
                }
                _ => return Ok(()),
            }
        };

        self.send_raw(endpoint, &encrypted).await?;

        // Update stats
        {
            let mut t = tunnel.write().await;
            t.stats.bytes_sent += data.len() as u64;
            t.stats.packets_sent += 1;
            t.last_activity = Instant::now();
        }

        Ok(())
    }

    /// List all active tunnels
    pub fn list_tunnels(&self) -> Vec<DomainId> {
        self.tunnels.iter().map(|r| *r.key()).collect()
    }

    /// Get tunnel count
    pub fn tunnel_count(&self) -> usize {
        self.tunnels.len()
    }

    /// Get tunnel info for a domain
    pub async fn tunnel_info(&self, domain_id: DomainId) -> Option<TunnelInfo> {
        if let Some(tunnel) = self.tunnels.get(&domain_id) {
            let t = tunnel.read().await;
            return Some(TunnelInfo {
                domain_id: t.domain_id,
                endpoint: t.endpoint,
                virtual_ip: t.virtual_ip,
                status: t.status,
                health: t.health(),
                stats: t.stats.clone(),
                age: t.age(),
                idle_time: t.idle_time(),
            });
        }
        None
    }

    /// Get aggregate statistics
    pub async fn aggregate_stats(&self) -> TunnelStats {
        let mut total = TunnelStats::default();

        for entry in self.tunnels.iter() {
            let t = entry.read().await;
            total.bytes_sent += t.stats.bytes_sent;
            total.bytes_received += t.stats.bytes_received;
            total.packets_sent += t.stats.packets_sent;
            total.packets_received += t.stats.packets_received;
            total.handshake_count += t.stats.handshake_count;
            total.failed_handshakes += t.stats.failed_handshakes;
        }

        total
    }

    /// Run keepalive for all tunnels
    pub async fn keepalive(&self) {
        for entry in self.tunnels.iter() {
            let domain_id = *entry.key();
            let tunnel = entry.value();
            let t = tunnel.read().await;

            if t.is_connected() {
                self.send_keepalive(domain_id, &t).await;
            }
        }
    }

    /// Get all healthy tunnels
    pub async fn healthy_tunnels(&self) -> Vec<DomainId> {
        let mut healthy = Vec::new();

        for entry in self.tunnels.iter() {
            let domain_id = *entry.key();
            let tunnel = entry.value();
            let t = tunnel.read().await;

            if t.health() == TunnelHealth::Healthy {
                healthy.push(domain_id);
            }
        }

        healthy
    }

    /// Reconnect a failed tunnel
    pub async fn reconnect(&self, domain_id: DomainId) -> Result<()> {
        let (peer_pubkey, endpoint) = {
            let tunnel = self
                .tunnels
                .get(&domain_id)
                .ok_or_else(|| Error::WireGuard(format!("tunnel {} not found", domain_id)))?;

            let t = tunnel.read().await;
            (t.peer_pubkey, t.endpoint)
        };

        // Remove old tunnel
        self.tunnels.remove(&domain_id);

        // Reconnect with retry
        self.connect_with_retry(domain_id, peer_pubkey, endpoint)
            .await
    }
}

/// Summary information about a tunnel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelInfo {
    /// Domain ID
    pub domain_id: DomainId,

    /// Remote endpoint
    pub endpoint: SocketAddr,

    /// Virtual IP
    pub virtual_ip: std::net::Ipv4Addr,

    /// Current status
    pub status: TunnelStatus,

    /// Health status
    pub health: TunnelHealth,

    /// Statistics
    pub stats: TunnelStats,

    /// Tunnel age
    #[serde(with = "duration_serde")]
    pub age: Duration,

    /// Time since last activity
    #[serde(with = "duration_serde")]
    pub idle_time: Duration,
}

mod duration_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        duration.as_secs().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = u64::deserialize(deserializer)?;
        Ok(Duration::from_secs(secs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp1 = WireGuardKeyPair::generate();
        let kp2 = WireGuardKeyPair::generate();

        // Keys should be different
        assert_ne!(kp1.private_key, kp2.private_key);
        assert_ne!(kp1.public_key, kp2.public_key);

        // Public key should be derived from private key
        let kp3 = WireGuardKeyPair::from_private_key(kp1.private_key);
        assert_eq!(kp1.public_key, kp3.public_key);
    }

    #[test]
    fn test_config_defaults() {
        let config = WireGuardConfig::default();
        assert_eq!(config.listen_port, 51820);
        assert_eq!(config.mtu, 1420);
        assert_eq!(config.keepalive_interval, Duration::from_secs(25));
        assert_eq!(config.max_handshake_retries, 3);
    }

    // This test only works in simulated mode where tunnels connect immediately
    #[cfg(not(feature = "wireguard-native"))]
    #[tokio::test]
    async fn test_tunnel_manager() {
        let manager = WireGuardTunnelManager::new(WireGuardConfig::default());

        // Connect to a domain
        let peer_pubkey = [1u8; 32];
        let endpoint: SocketAddr = "127.0.0.1:51821".parse().unwrap();

        manager.connect(1, peer_pubkey, endpoint).await.unwrap();

        assert!(manager.is_connected(1).await);
        assert_eq!(manager.tunnel_count(), 1);

        // Check tunnel info
        let info = manager.tunnel_info(1).await.unwrap();
        assert_eq!(info.domain_id, 1);
        assert_eq!(info.endpoint, endpoint);
        assert!(matches!(info.status, TunnelStatus::Connected));

        // Disconnect
        manager.disconnect(1).await.unwrap();
        assert!(!manager.is_connected(1).await);
    }

    // Test that native mode creates tunnels in handshaking state
    #[cfg(feature = "wireguard-native")]
    #[tokio::test]
    async fn test_tunnel_manager() {
        let manager = WireGuardTunnelManager::new(WireGuardConfig::default());

        // Connect to a domain
        let peer_pubkey = [1u8; 32];
        let endpoint: SocketAddr = "127.0.0.1:51821".parse().unwrap();

        manager.connect(1, peer_pubkey, endpoint).await.unwrap();

        // Tunnel exists but may be in handshaking state
        assert_eq!(manager.tunnel_count(), 1);

        // Check tunnel info
        let info = manager.tunnel_info(1).await.unwrap();
        assert_eq!(info.domain_id, 1);
        assert_eq!(info.endpoint, endpoint);
        // In native mode, tunnel starts in Handshaking state
        assert!(matches!(info.status, TunnelStatus::Handshaking));

        // Disconnect
        manager.disconnect(1).await.unwrap();
    }

    #[test]
    fn test_vip_allocation() {
        let manager = WireGuardTunnelManager::new(WireGuardConfig::default());

        let vip1 = manager.allocate_vip();
        let vip2 = manager.allocate_vip();
        let vip3 = manager.allocate_vip();

        assert_eq!(vip1, std::net::Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(vip2, std::net::Ipv4Addr::new(10, 0, 0, 3));
        assert_eq!(vip3, std::net::Ipv4Addr::new(10, 0, 0, 4));
    }

    #[test]
    fn test_tunnel_stats_health() {
        let mut stats = TunnelStats::default();

        // Unknown health without latency
        assert_eq!(stats.health(), TunnelHealth::Unknown);

        // Healthy with low latency
        stats.latency_ms = Some(50);
        stats.packet_loss_rate = 0.0;
        assert_eq!(stats.health(), TunnelHealth::Healthy);

        // Degraded with moderate latency
        stats.latency_ms = Some(300);
        assert_eq!(stats.health(), TunnelHealth::Degraded);

        // Unhealthy with high latency
        stats.latency_ms = Some(1500);
        assert_eq!(stats.health(), TunnelHealth::Unhealthy);

        // Unhealthy with high packet loss
        stats.latency_ms = Some(50);
        stats.packet_loss_rate = 0.2;
        assert_eq!(stats.health(), TunnelHealth::Unhealthy);
    }

    #[tokio::test]
    async fn test_get_or_connect() {
        let manager = WireGuardTunnelManager::new(WireGuardConfig::default());

        let peer_pubkey = [2u8; 32];
        let endpoint: SocketAddr = "127.0.0.1:51822".parse().unwrap();

        // First call creates tunnel
        let tunnel1 = manager
            .get_or_connect(1, peer_pubkey, endpoint)
            .await
            .unwrap();

        // Second call returns existing tunnel
        let tunnel2 = manager
            .get_or_connect(1, peer_pubkey, endpoint)
            .await
            .unwrap();

        // Should be the same tunnel
        assert_eq!(manager.tunnel_count(), 1);

        let t1 = tunnel1.read().await;
        let t2 = tunnel2.read().await;
        assert_eq!(t1.domain_id, t2.domain_id);
    }

    // This test only works in simulated mode where handshakes complete immediately
    #[cfg(not(feature = "wireguard-native"))]
    #[tokio::test]
    async fn test_aggregate_stats() {
        let manager = WireGuardTunnelManager::new(WireGuardConfig::default());

        // Create multiple tunnels
        for i in 1..=3 {
            let peer_pubkey = [i as u8; 32];
            let endpoint: SocketAddr = format!("127.0.0.1:5182{}", i).parse().unwrap();
            manager.connect(i, peer_pubkey, endpoint).await.unwrap();
        }

        let stats = manager.aggregate_stats().await;
        assert_eq!(stats.handshake_count, 3);
    }

    // Native mode test for aggregate stats
    #[cfg(feature = "wireguard-native")]
    #[tokio::test]
    async fn test_aggregate_stats() {
        let manager = WireGuardTunnelManager::new(WireGuardConfig::default());

        // Create multiple tunnels
        for i in 1..=3 {
            let peer_pubkey = [i as u8; 32];
            let endpoint: SocketAddr = format!("127.0.0.1:5182{}", i).parse().unwrap();
            manager.connect(i, peer_pubkey, endpoint).await.unwrap();
        }

        // In native mode, handshakes haven't completed yet
        let stats = manager.aggregate_stats().await;
        assert_eq!(stats.handshake_count, 0);
        assert_eq!(manager.tunnel_count(), 3);
    }

    // This test only works in simulated mode where tunnels are immediately connected
    #[cfg(not(feature = "wireguard-native"))]
    #[tokio::test]
    async fn test_healthy_tunnels() {
        let manager = WireGuardTunnelManager::new(WireGuardConfig::default());

        // Create connected tunnel
        let peer_pubkey = [1u8; 32];
        let endpoint: SocketAddr = "127.0.0.1:51821".parse().unwrap();
        manager.connect(1, peer_pubkey, endpoint).await.unwrap();

        let healthy = manager.healthy_tunnels().await;
        // Note: Without real traffic, health is Unknown, not Healthy
        assert_eq!(healthy.len(), 0);

        // Update stats to make it healthy
        if let Some(tunnel) = manager.tunnels.get(&1) {
            let mut t = tunnel.write().await;
            t.stats.latency_ms = Some(50);
        }

        let healthy = manager.healthy_tunnels().await;
        assert_eq!(healthy.len(), 1);
        assert_eq!(healthy[0], 1);
    }

    // Native mode test for healthy tunnels
    #[cfg(feature = "wireguard-native")]
    #[tokio::test]
    async fn test_healthy_tunnels() {
        let manager = WireGuardTunnelManager::new(WireGuardConfig::default());

        // Create tunnel (will be in handshaking state)
        let peer_pubkey = [1u8; 32];
        let endpoint: SocketAddr = "127.0.0.1:51821".parse().unwrap();
        manager.connect(1, peer_pubkey, endpoint).await.unwrap();

        // Handshaking tunnels are not healthy
        let healthy = manager.healthy_tunnels().await;
        assert_eq!(healthy.len(), 0);

        // Verify tunnel exists
        assert_eq!(manager.tunnel_count(), 1);
    }
}
