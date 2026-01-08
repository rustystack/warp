//! Core types for Portal network
//!
//! This module defines the fundamental types used throughout the Portal networking layer:
//! - Virtual IP addresses in the 10.0.0.0/16 subnet
//! - Peer configuration and metadata
//! - Network events and status tracking
//! - Configuration structures for hub and mDNS

use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::SystemTime;

use crate::{PortalNetError, Result};

/// Virtual IP address in the 10.portal.0.0/16 subnet
///
/// Portal uses the 10.0.0.0/16 private subnet for virtual networking.
/// The hub always uses 10.0.0.1, and peers are assigned addresses
/// in the range 10.0.0.2 to 10.0.255.255.
///
/// # Examples
///
/// ```
/// use portal_net::VirtualIp;
///
/// // Create a virtual IP for host 42
/// let vip = VirtualIp::new(42);
/// assert_eq!(vip.host(), 42);
///
/// // Hub constant
/// assert_eq!(VirtualIp::HUB.host(), 1);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VirtualIp(Ipv4Addr);

impl VirtualIp {
    /// The network prefix for the Portal subnet (10.0)
    const NETWORK_PREFIX: [u8; 2] = [10, 0];

    /// Hub virtual IP address (10.0.0.1)
    pub const HUB: Self = Self(Ipv4Addr::new(10, 0, 0, 1));

    /// Creates a new virtual IP address from a 16-bit host identifier
    ///
    /// The host identifier is split into two octets (high byte and low byte)
    /// and combined with the 10.0 network prefix.
    ///
    /// # Examples
    ///
    /// ```
    /// use portal_net::VirtualIp;
    ///
    /// let vip = VirtualIp::new(0x0102); // Creates 10.0.1.2
    /// assert_eq!(vip.host(), 0x0102);
    /// ```
    #[must_use]
    pub const fn new(host: u16) -> Self {
        let high = (host >> 8) as u8;
        let low = (host & 0xFF) as u8;
        Self(Ipv4Addr::new(10, 0, high, low))
    }

    /// Extracts the 16-bit host identifier from the virtual IP
    ///
    /// # Examples
    ///
    /// ```
    /// use portal_net::VirtualIp;
    ///
    /// let vip = VirtualIp::new(0x1234);
    /// assert_eq!(vip.host(), 0x1234);
    /// ```
    #[must_use]
    pub const fn host(&self) -> u16 {
        let octets = self.0.octets();
        ((octets[2] as u16) << 8) | (octets[3] as u16)
    }

    /// Checks if the IP address is in the Portal subnet (10.0.0.0/16)
    ///
    /// # Examples
    ///
    /// ```
    /// use portal_net::VirtualIp;
    ///
    /// let vip = VirtualIp::new(100);
    /// assert!(vip.is_portal_subnet());
    /// ```
    #[must_use]
    pub const fn is_portal_subnet(&self) -> bool {
        let octets = self.0.octets();
        octets[0] == Self::NETWORK_PREFIX[0] && octets[1] == Self::NETWORK_PREFIX[1]
    }

    /// Returns the underlying IPv4 address
    #[must_use]
    pub const fn as_ipv4(&self) -> Ipv4Addr {
        self.0
    }

    /// Attempts to create a `VirtualIp` from an arbitrary IPv4 address
    ///
    /// # Errors
    ///
    /// Returns an error if the address is not in the 10.0.0.0/16 subnet
    pub fn from_ipv4(addr: Ipv4Addr) -> Result<Self> {
        let vip = Self(addr);
        if vip.is_portal_subnet() {
            Ok(vip)
        } else {
            Err(PortalNetError::InvalidVirtualIp(format!(
                "{addr} is not in the 10.0.0.0/16 subnet"
            )))
        }
    }
}

impl fmt::Display for VirtualIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<VirtualIp> for Ipv4Addr {
    fn from(vip: VirtualIp) -> Self {
        vip.0
    }
}

impl From<VirtualIp> for IpAddr {
    fn from(vip: VirtualIp) -> Self {
        Self::V4(vip.0)
    }
}

/// Peer connection status
///
/// Tracks the current connection mode for a peer in the mesh network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PeerStatus {
    /// Connection status unknown (initial state)
    #[default]
    Unknown,
    /// Peer is online but connection mode not yet determined
    Online,
    /// Peer is offline or unreachable
    Offline,
    /// Direct peer-to-peer connection established (optimal)
    DirectP2P,
    /// Connection relayed through hub (NAT traversal fallback)
    Relayed,
}

impl fmt::Display for PeerStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => write!(f, "unknown"),
            Self::Online => write!(f, "online"),
            Self::Offline => write!(f, "offline"),
            Self::DirectP2P => write!(f, "direct-p2p"),
            Self::Relayed => write!(f, "relayed"),
        }
    }
}

// ============================================================================
// Multi-Path Network Aggregation Types
// ============================================================================

/// Priority for an endpoint (lower value = higher priority)
///
/// Used to indicate preferred vs backup network paths.
/// Default priority is 100 (middle range).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EndpointPriority(pub u8);

impl EndpointPriority {
    /// Highest priority (preferred path)
    pub const PRIMARY: Self = Self(0);
    /// Secondary priority (backup path)
    pub const SECONDARY: Self = Self(50);
    /// Default priority
    pub const DEFAULT: Self = Self(100);
    /// Lowest priority (last resort)
    pub const FALLBACK: Self = Self(255);
}

impl Default for EndpointPriority {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl fmt::Display for EndpointPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Network path identifier
///
/// Deterministic hash from (local_ip, remote_ip) tuple to identify
/// unique physical network paths for multi-path aggregation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PathId(pub u32);

impl PathId {
    /// Generate `PathId` from source and destination IPs
    ///
    /// The same `(local_ip, remote_ip)` pair always produces the same `PathId`.
    #[must_use]
    pub fn from_ips(local: IpAddr, remote: IpAddr) -> Self {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        local.hash(&mut hasher);
        remote.hash(&mut hasher);
        Self(hasher.finish() as u32)
    }
}

impl fmt::Display for PathId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "path:{:08x}", self.0)
    }
}

/// A single network endpoint with metadata for multi-path support
///
/// Represents one possible way to reach a peer, with priority and
/// health tracking for intelligent path selection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerEndpoint {
    /// Network address (IP:port)
    pub addr: SocketAddr,

    /// Priority for this endpoint (lower = preferred)
    pub priority: EndpointPriority,

    /// Whether this endpoint is currently enabled
    pub enabled: bool,

    /// Optional label for identification (e.g., "eth0", "bond0", "datacenter-a")
    pub label: Option<String>,

    /// Last successful connection timestamp (milliseconds since epoch)
    pub last_success_ms: Option<u64>,

    /// Consecutive failure count (for backoff and health tracking)
    pub failure_count: u8,
}

impl PeerEndpoint {
    /// Creates a new endpoint with default settings
    #[must_use]
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            priority: EndpointPriority::default(),
            enabled: true,
            label: None,
            last_success_ms: None,
            failure_count: 0,
        }
    }

    /// Builder: set priority
    #[must_use]
    pub const fn with_priority(mut self, priority: EndpointPriority) -> Self {
        self.priority = priority;
        self
    }

    /// Builder: set label
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Builder: set enabled state
    #[must_use]
    pub const fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Record a successful connection
    pub fn record_success(&mut self) {
        self.last_success_ms = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| {
                    #[allow(clippy::cast_possible_truncation)]
                    {
                        d.as_millis() as u64
                    }
                }),
        );
        self.failure_count = 0;
    }

    /// Record a failed connection attempt
    pub fn record_failure(&mut self) {
        self.failure_count = self.failure_count.saturating_add(1);
    }

    /// Check if this endpoint is healthy (enabled with low failure count)
    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        self.enabled && self.failure_count < 3
    }
}

impl fmt::Display for PeerEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref label) = self.label {
            write!(f, "{}@{}", label, self.addr)
        } else {
            write!(f, "{}", self.addr)
        }
    }
}

/// Peer configuration
///
/// Contains the essential configuration needed to establish a `WireGuard`
/// connection with a peer in the mesh network.
///
/// Supports multiple endpoints per peer for multi-path network aggregation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerConfig {
    /// `WireGuard` public key (X25519)
    pub public_key: [u8; 32],

    /// Virtual IP address assigned to this peer
    pub virtual_ip: VirtualIp,

    /// Network endpoints for this peer (supports multi-path aggregation)
    ///
    /// Multiple endpoints allow connecting via different network paths
    /// for increased throughput and redundancy.
    pub endpoints: Vec<PeerEndpoint>,

    /// Persistent keepalive interval in seconds (0 to disable)
    pub keepalive: u16,

    /// List of IP addresses allowed from this peer (routing table)
    pub allowed_ips: Vec<IpAddr>,
}

impl PeerConfig {
    /// Creates a new peer configuration with default settings
    #[must_use]
    pub fn new(public_key: [u8; 32], virtual_ip: VirtualIp) -> Self {
        Self {
            public_key,
            virtual_ip,
            endpoints: Vec::new(),
            keepalive: 25, // Default 25 second keepalive
            allowed_ips: vec![virtual_ip.into()],
        }
    }

    /// Creates a new peer configuration with a single endpoint
    #[must_use]
    pub fn with_endpoint(
        public_key: [u8; 32],
        virtual_ip: VirtualIp,
        endpoint: SocketAddr,
    ) -> Self {
        Self {
            public_key,
            virtual_ip,
            endpoints: vec![PeerEndpoint::new(endpoint)],
            keepalive: 25,
            allowed_ips: vec![virtual_ip.into()],
        }
    }

    /// Returns the public key as a hex string
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key)
    }

    /// Returns the primary (highest priority) endpoint address
    ///
    /// This is a backwards-compatible method for code that expects
    /// a single endpoint. Returns the enabled endpoint with lowest
    /// priority value (highest priority).
    pub fn endpoint(&self) -> Option<SocketAddr> {
        self.endpoints
            .iter()
            .filter(|e| e.enabled)
            .min_by_key(|e| e.priority)
            .map(|e| e.addr)
    }

    /// Returns all enabled endpoints sorted by priority (lowest value first)
    pub fn active_endpoints(&self) -> Vec<&PeerEndpoint> {
        let mut eps: Vec<_> = self.endpoints.iter().filter(|e| e.enabled).collect();
        eps.sort_by_key(|e| e.priority);
        eps
    }

    /// Returns all healthy endpoints (enabled with low failure count) sorted by priority
    pub fn healthy_endpoints(&self) -> Vec<&PeerEndpoint> {
        let mut eps: Vec<_> = self.endpoints.iter().filter(|e| e.is_healthy()).collect();
        eps.sort_by_key(|e| e.priority);
        eps
    }

    /// Add an endpoint to this peer
    ///
    /// Returns true if added, false if an endpoint with that address already exists.
    pub fn add_endpoint(&mut self, endpoint: PeerEndpoint) -> bool {
        if self.endpoints.iter().any(|e| e.addr == endpoint.addr) {
            false
        } else {
            self.endpoints.push(endpoint);
            true
        }
    }

    /// Remove an endpoint by address
    ///
    /// Returns the removed endpoint, or None if not found.
    pub fn remove_endpoint(&mut self, addr: SocketAddr) -> Option<PeerEndpoint> {
        if let Some(idx) = self.endpoints.iter().position(|e| e.addr == addr) {
            Some(self.endpoints.remove(idx))
        } else {
            None
        }
    }

    /// Get a mutable reference to an endpoint by address
    pub fn get_endpoint_mut(&mut self, addr: SocketAddr) -> Option<&mut PeerEndpoint> {
        self.endpoints.iter_mut().find(|e| e.addr == addr)
    }

    /// Check if this peer has any healthy endpoints
    pub fn has_healthy_endpoint(&self) -> bool {
        self.endpoints.iter().any(|e| e.is_healthy())
    }

    /// Get the number of enabled endpoints
    pub fn endpoint_count(&self) -> usize {
        self.endpoints.iter().filter(|e| e.enabled).count()
    }
}

/// Peer metadata with statistics
///
/// Extends PeerConfig with runtime state including connection statistics
/// and status tracking.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerMetadata {
    /// Base peer configuration
    pub config: PeerConfig,

    /// Timestamp of last successful WireGuard handshake
    pub last_handshake: Option<SystemTime>,

    /// Total bytes transmitted to this peer
    pub tx_bytes: u64,

    /// Total bytes received from this peer
    pub rx_bytes: u64,

    /// Current connection status
    pub status: PeerStatus,
}

impl PeerMetadata {
    /// Creates new peer metadata from configuration
    pub fn new(config: PeerConfig) -> Self {
        PeerMetadata {
            config,
            last_handshake: None,
            tx_bytes: 0,
            rx_bytes: 0,
            status: PeerStatus::Unknown,
        }
    }

    /// Checks if the peer is considered active (recent handshake)
    ///
    /// A peer is active if a handshake occurred within the last 180 seconds.
    pub fn is_active(&self) -> bool {
        if let Some(last) = self.last_handshake {
            if let Ok(duration) = SystemTime::now().duration_since(last) {
                return duration.as_secs() < 180;
            }
        }
        false
    }

    /// Updates connection statistics
    pub fn update_stats(&mut self, tx_bytes: u64, rx_bytes: u64) {
        self.tx_bytes = tx_bytes;
        self.rx_bytes = rx_bytes;
    }

    /// Updates the last handshake timestamp
    pub fn update_handshake(&mut self) {
        self.last_handshake = Some(SystemTime::now());
    }
}

impl Default for PeerMetadata {
    fn default() -> Self {
        PeerMetadata {
            config: PeerConfig {
                public_key: [0u8; 32],
                virtual_ip: VirtualIp::HUB,
                endpoints: Vec::new(),
                keepalive: 25,
                allowed_ips: vec![],
            },
            last_handshake: None,
            tx_bytes: 0,
            rx_bytes: 0,
            status: PeerStatus::Unknown,
        }
    }
}

/// Network events
///
/// Events emitted by the network layer to notify about topology changes,
/// peer lifecycle, and connection status updates.
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// A new peer has joined the network
    PeerJoined {
        /// WireGuard public key of the peer
        public_key: [u8; 32],
        /// Virtual IP address assigned to the peer
        virtual_ip: VirtualIp,
    },

    /// A peer has left the network
    PeerLeft {
        /// WireGuard public key of the peer that left
        public_key: [u8; 32],
    },

    /// A peer's endpoint has been updated
    EndpointUpdated {
        /// WireGuard public key of the peer
        public_key: [u8; 32],
        /// New network endpoint address
        endpoint: SocketAddr,
    },

    /// A peer was discovered on the local network via mDNS
    LanPeerDiscovered {
        /// WireGuard public key of the discovered peer
        public_key: [u8; 32],
        /// Local network address of the peer
        local_addr: SocketAddr,
    },

    /// A peer's connection mode has changed (e.g., relayed -> direct P2P)
    ConnectionModeChanged {
        /// WireGuard public key of the peer
        public_key: [u8; 32],
        /// New connection status
        status: PeerStatus,
    },

    /// A new endpoint was added to a peer (multi-path support)
    EndpointAdded {
        /// WireGuard public key of the peer
        public_key: [u8; 32],
        /// Endpoint that was added
        endpoint: PeerEndpoint,
    },

    /// An endpoint was removed from a peer (multi-path support)
    EndpointRemoved {
        /// WireGuard public key of the peer
        public_key: [u8; 32],
        /// Address of the endpoint that was removed
        endpoint_addr: SocketAddr,
    },

    /// A local interface was added for multi-path connections
    LocalInterfaceAdded {
        /// IP address bound to the local interface
        bind_ip: std::net::IpAddr,
        /// Optional label for the interface
        label: Option<String>,
    },

    /// A local interface was removed
    LocalInterfaceRemoved {
        /// IP address of the removed interface
        bind_ip: std::net::IpAddr,
    },

    /// Health status changed for a specific path (local_ip × remote_ip pair)
    PathHealthChanged {
        /// Unique identifier for this network path
        path_id: PathId,
        /// Local IP address used for this path
        local_ip: std::net::IpAddr,
        /// Remote endpoint address
        remote_addr: SocketAddr,
        /// Health score in range [0.0, 1.0]
        health: f32,
    },
}

impl NetworkEvent {
    /// Returns the public key associated with this event, if applicable
    pub fn public_key(&self) -> Option<&[u8; 32]> {
        match self {
            NetworkEvent::PeerJoined { public_key, .. }
            | NetworkEvent::PeerLeft { public_key }
            | NetworkEvent::EndpointUpdated { public_key, .. }
            | NetworkEvent::LanPeerDiscovered { public_key, .. }
            | NetworkEvent::ConnectionModeChanged { public_key, .. }
            | NetworkEvent::EndpointAdded { public_key, .. }
            | NetworkEvent::EndpointRemoved { public_key, .. } => Some(public_key),
            NetworkEvent::LocalInterfaceAdded { .. }
            | NetworkEvent::LocalInterfaceRemoved { .. }
            | NetworkEvent::PathHealthChanged { .. } => None,
        }
    }
}

/// mDNS configuration
///
/// Settings for local network peer discovery using multicast DNS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MdnsConfig {
    /// Enable mDNS discovery
    pub enabled: bool,

    /// Service name for mDNS announcements
    pub service_name: String,

    /// How often to announce our presence (seconds)
    pub announce_interval_secs: u64,

    /// How often to scan for peers (seconds)
    pub scan_interval_secs: u64,
}

impl Default for MdnsConfig {
    fn default() -> Self {
        MdnsConfig {
            enabled: true,
            service_name: "_portal._udp.local".to_string(),
            announce_interval_secs: 60,
            scan_interval_secs: 30,
        }
    }
}

/// Hub network configuration
///
/// Configuration for connecting to the Portal hub, which provides
/// peer coordination and acts as a relay for NAT traversal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubNetConfig {
    /// Hub's WireGuard public key
    pub public_key: [u8; 32],

    /// Hub's network endpoint
    pub endpoint: SocketAddr,

    /// Hub's virtual IP (always 10.0.0.1)
    pub virtual_ip: VirtualIp,

    /// Heartbeat interval for hub connection (seconds)
    pub heartbeat_secs: u64,
}

impl HubNetConfig {
    /// Creates a new hub configuration
    pub fn new(public_key: [u8; 32], endpoint: SocketAddr) -> Self {
        HubNetConfig {
            public_key,
            endpoint,
            virtual_ip: VirtualIp::HUB,
            heartbeat_secs: 30,
        }
    }
}

/// Network configuration
///
/// Complete configuration for the Portal network layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Local WireGuard listen port
    pub listen_port: u16,

    /// Our virtual IP address (assigned by hub if None)
    pub virtual_ip: Option<VirtualIp>,

    /// Hub configuration
    pub hub: HubNetConfig,

    /// mDNS discovery configuration
    pub mdns: MdnsConfig,
}

impl NetworkConfig {
    /// Creates a new network configuration
    pub fn new(listen_port: u16, hub: HubNetConfig) -> Self {
        NetworkConfig {
            listen_port,
            virtual_ip: None,
            hub,
            mdns: MdnsConfig::default(),
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        NetworkConfig {
            listen_port: 51820,
            virtual_ip: None,
            hub: HubNetConfig {
                public_key: [0u8; 32],
                endpoint: "127.0.0.1:51820".parse().unwrap(),
                virtual_ip: VirtualIp::HUB,
                heartbeat_secs: 30,
            },
            mdns: MdnsConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_virtual_ip_new() {
        // Test basic creation
        let vip = VirtualIp::new(42);
        assert_eq!(vip.as_ipv4(), Ipv4Addr::new(10, 0, 0, 42));

        // Test with larger host ID
        let vip = VirtualIp::new(0x1234);
        assert_eq!(vip.as_ipv4(), Ipv4Addr::new(10, 0, 0x12, 0x34));

        // Test edge cases
        let vip = VirtualIp::new(0);
        assert_eq!(vip.as_ipv4(), Ipv4Addr::new(10, 0, 0, 0));

        let vip = VirtualIp::new(0xFFFF);
        assert_eq!(vip.as_ipv4(), Ipv4Addr::new(10, 0, 255, 255));
    }

    #[test]
    fn test_virtual_ip_host() {
        // Test extraction
        let vip = VirtualIp::new(42);
        assert_eq!(vip.host(), 42);

        let vip = VirtualIp::new(0x1234);
        assert_eq!(vip.host(), 0x1234);

        // Test roundtrip
        for host in [0, 1, 100, 256, 1000, 0xFFFF] {
            let vip = VirtualIp::new(host);
            assert_eq!(vip.host(), host);
        }
    }

    #[test]
    fn test_virtual_ip_hub_constant() {
        assert_eq!(VirtualIp::HUB.as_ipv4(), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(VirtualIp::HUB.host(), 1);
    }

    #[test]
    fn test_virtual_ip_subnet_check() {
        // Valid Portal subnet IPs
        assert!(VirtualIp::new(1).is_portal_subnet());
        assert!(VirtualIp::new(100).is_portal_subnet());
        assert!(VirtualIp::new(0xFFFF).is_portal_subnet());
        assert!(VirtualIp::HUB.is_portal_subnet());

        // Test from_ipv4
        assert!(VirtualIp::from_ipv4(Ipv4Addr::new(10, 0, 1, 1)).is_ok());
        assert!(VirtualIp::from_ipv4(Ipv4Addr::new(10, 0, 255, 255)).is_ok());

        // Invalid IPs (not in 10.0.0.0/16)
        assert!(VirtualIp::from_ipv4(Ipv4Addr::new(10, 1, 0, 1)).is_err());
        assert!(VirtualIp::from_ipv4(Ipv4Addr::new(192, 168, 1, 1)).is_err());
        assert!(VirtualIp::from_ipv4(Ipv4Addr::new(172, 16, 0, 1)).is_err());
    }

    #[test]
    fn test_virtual_ip_serialize() {
        let vip = VirtualIp::new(0x1234);

        // JSON serialization
        let json = serde_json::to_string(&vip).unwrap();
        let deserialized: VirtualIp = serde_json::from_str(&json).unwrap();
        assert_eq!(vip, deserialized);

        // MessagePack serialization
        let msgpack = rmp_serde::to_vec(&vip).unwrap();
        let deserialized: VirtualIp = rmp_serde::from_slice(&msgpack).unwrap();
        assert_eq!(vip, deserialized);

        // Test with HUB constant
        let json = serde_json::to_string(&VirtualIp::HUB).unwrap();
        let deserialized: VirtualIp = serde_json::from_str(&json).unwrap();
        assert_eq!(VirtualIp::HUB, deserialized);
    }

    #[test]
    fn test_peer_status_serialize() {
        let statuses = vec![
            PeerStatus::Unknown,
            PeerStatus::Online,
            PeerStatus::Offline,
            PeerStatus::DirectP2P,
            PeerStatus::Relayed,
        ];

        for status in statuses {
            // JSON roundtrip
            let json = serde_json::to_string(&status).unwrap();
            let deserialized: PeerStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, deserialized);

            // MessagePack roundtrip
            let msgpack = rmp_serde::to_vec(&status).unwrap();
            let deserialized: PeerStatus = rmp_serde::from_slice(&msgpack).unwrap();
            assert_eq!(status, deserialized);
        }
    }

    #[test]
    fn test_peer_config_serialize() {
        let public_key = [42u8; 32];
        let vip = VirtualIp::new(100);
        let endpoint: SocketAddr = "192.168.1.100:51820".parse().unwrap();

        let config = PeerConfig {
            public_key,
            virtual_ip: vip,
            endpoints: vec![PeerEndpoint::new(endpoint)],
            keepalive: 25,
            allowed_ips: vec![vip.into()],
        };

        // JSON roundtrip
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: PeerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.public_key, deserialized.public_key);
        assert_eq!(config.virtual_ip, deserialized.virtual_ip);
        assert_eq!(config.endpoint(), deserialized.endpoint());
        assert_eq!(config.keepalive, deserialized.keepalive);
        assert_eq!(config.allowed_ips.len(), deserialized.allowed_ips.len());

        // MessagePack roundtrip
        let msgpack = rmp_serde::to_vec(&config).unwrap();
        let deserialized: PeerConfig = rmp_serde::from_slice(&msgpack).unwrap();
        assert_eq!(config.public_key, deserialized.public_key);
        assert_eq!(config.virtual_ip, deserialized.virtual_ip);
    }

    #[test]
    fn test_network_config_default() {
        let config = NetworkConfig::default();

        assert_eq!(config.listen_port, 51820);
        assert!(config.virtual_ip.is_none());
        assert_eq!(config.hub.virtual_ip, VirtualIp::HUB);
        assert_eq!(config.hub.heartbeat_secs, 30);
        assert!(config.mdns.enabled);
        assert_eq!(config.mdns.service_name, "_portal._udp.local");
        assert_eq!(config.mdns.announce_interval_secs, 60);
        assert_eq!(config.mdns.scan_interval_secs, 30);
    }

    #[test]
    fn test_virtual_ip_display() {
        let vip = VirtualIp::new(0x1234);
        assert_eq!(format!("{}", vip), "10.0.18.52");

        assert_eq!(format!("{}", VirtualIp::HUB), "10.0.0.1");

        let vip = VirtualIp::new(100);
        assert_eq!(format!("{}", vip), "10.0.0.100");
    }

    #[test]
    fn test_peer_metadata_default() {
        let metadata = PeerMetadata::default();

        assert_eq!(metadata.config.public_key, [0u8; 32]);
        assert_eq!(metadata.config.virtual_ip, VirtualIp::HUB);
        assert!(metadata.last_handshake.is_none());
        assert_eq!(metadata.tx_bytes, 0);
        assert_eq!(metadata.rx_bytes, 0);
        assert_eq!(metadata.status, PeerStatus::Unknown);
    }

    #[test]
    fn test_peer_config_new() {
        let public_key = [1u8; 32];
        let vip = VirtualIp::new(50);

        let config = PeerConfig::new(public_key, vip);

        assert_eq!(config.public_key, public_key);
        assert_eq!(config.virtual_ip, vip);
        assert!(config.endpoint().is_none()); // No endpoints by default
        assert!(config.endpoints.is_empty());
        assert_eq!(config.keepalive, 25);
        assert_eq!(config.allowed_ips.len(), 1);
        assert_eq!(config.allowed_ips[0], IpAddr::from(vip));
    }

    #[test]
    fn test_peer_config_public_key_hex() {
        let public_key = [0xAB; 32];
        let config = PeerConfig::new(public_key, VirtualIp::new(1));

        let hex = config.public_key_hex();
        assert_eq!(hex.len(), 64); // 32 bytes = 64 hex chars
        assert!(hex.chars().all(|c| "0123456789abcdef".contains(c)));
    }

    #[test]
    fn test_peer_metadata_new() {
        let public_key = [2u8; 32];
        let vip = VirtualIp::new(75);
        let config = PeerConfig::new(public_key, vip);

        let metadata = PeerMetadata::new(config.clone());

        assert_eq!(metadata.config.public_key, config.public_key);
        assert_eq!(metadata.config.virtual_ip, config.virtual_ip);
        assert!(metadata.last_handshake.is_none());
        assert_eq!(metadata.tx_bytes, 0);
        assert_eq!(metadata.rx_bytes, 0);
        assert_eq!(metadata.status, PeerStatus::Unknown);
    }

    #[test]
    fn test_peer_metadata_is_active() {
        let config = PeerConfig::new([3u8; 32], VirtualIp::new(10));
        let mut metadata = PeerMetadata::new(config);

        // Initially not active
        assert!(!metadata.is_active());

        // Update handshake
        metadata.update_handshake();
        assert!(metadata.is_active());

        // Test with old timestamp (simulate 200 seconds ago)
        use std::time::Duration;
        if let Some(old_time) = SystemTime::now().checked_sub(Duration::from_secs(200)) {
            metadata.last_handshake = Some(old_time);
            assert!(!metadata.is_active());
        }
    }

    #[test]
    fn test_peer_metadata_update_stats() {
        let config = PeerConfig::new([4u8; 32], VirtualIp::new(20));
        let mut metadata = PeerMetadata::new(config);

        metadata.update_stats(1024, 2048);
        assert_eq!(metadata.tx_bytes, 1024);
        assert_eq!(metadata.rx_bytes, 2048);

        metadata.update_stats(4096, 8192);
        assert_eq!(metadata.tx_bytes, 4096);
        assert_eq!(metadata.rx_bytes, 8192);
    }

    #[test]
    fn test_peer_status_default() {
        assert_eq!(PeerStatus::default(), PeerStatus::Unknown);
    }

    #[test]
    fn test_peer_status_display() {
        assert_eq!(format!("{}", PeerStatus::Unknown), "unknown");
        assert_eq!(format!("{}", PeerStatus::Online), "online");
        assert_eq!(format!("{}", PeerStatus::Offline), "offline");
        assert_eq!(format!("{}", PeerStatus::DirectP2P), "direct-p2p");
        assert_eq!(format!("{}", PeerStatus::Relayed), "relayed");
    }

    #[test]
    fn test_network_event_public_key() {
        let pk = [5u8; 32];
        let vip = VirtualIp::new(30);

        let event1 = NetworkEvent::PeerJoined {
            public_key: pk,
            virtual_ip: vip,
        };
        assert_eq!(event1.public_key(), Some(&pk));

        let event2 = NetworkEvent::PeerLeft { public_key: pk };
        assert_eq!(event2.public_key(), Some(&pk));

        let event3 = NetworkEvent::EndpointUpdated {
            public_key: pk,
            endpoint: "192.168.1.1:51820".parse().unwrap(),
        };
        assert_eq!(event3.public_key(), Some(&pk));

        let event4 = NetworkEvent::LanPeerDiscovered {
            public_key: pk,
            local_addr: "192.168.1.2:51820".parse().unwrap(),
        };
        assert_eq!(event4.public_key(), Some(&pk));

        let event5 = NetworkEvent::ConnectionModeChanged {
            public_key: pk,
            status: PeerStatus::DirectP2P,
        };
        assert_eq!(event5.public_key(), Some(&pk));

        // Test events that don't have public keys
        let event6 = NetworkEvent::LocalInterfaceAdded {
            bind_ip: "10.10.10.1".parse().unwrap(),
            label: Some("eth0".to_string()),
        };
        assert_eq!(event6.public_key(), None);

        let event7 = NetworkEvent::PathHealthChanged {
            path_id: PathId(12345),
            local_ip: "10.10.10.1".parse().unwrap(),
            remote_addr: "10.10.10.2:12345".parse().unwrap(),
            health: 0.95,
        };
        assert_eq!(event7.public_key(), None);
    }

    #[test]
    fn test_mdns_config_default() {
        let config = MdnsConfig::default();

        assert!(config.enabled);
        assert_eq!(config.service_name, "_portal._udp.local");
        assert_eq!(config.announce_interval_secs, 60);
        assert_eq!(config.scan_interval_secs, 30);
    }

    #[test]
    fn test_hub_net_config_new() {
        let public_key = [6u8; 32];
        let endpoint = "192.168.1.100:51820".parse().unwrap();

        let config = HubNetConfig::new(public_key, endpoint);

        assert_eq!(config.public_key, public_key);
        assert_eq!(config.endpoint, endpoint);
        assert_eq!(config.virtual_ip, VirtualIp::HUB);
        assert_eq!(config.heartbeat_secs, 30);
    }

    #[test]
    fn test_network_config_new() {
        let public_key = [7u8; 32];
        let endpoint = "192.168.1.200:51820".parse().unwrap();
        let hub = HubNetConfig::new(public_key, endpoint);

        let config = NetworkConfig::new(12345, hub.clone());

        assert_eq!(config.listen_port, 12345);
        assert!(config.virtual_ip.is_none());
        assert_eq!(config.hub.public_key, hub.public_key);
        assert_eq!(config.hub.endpoint, hub.endpoint);
        assert!(config.mdns.enabled);
    }

    #[test]
    fn test_virtual_ip_conversions() {
        let vip = VirtualIp::new(0x0A0B);

        // Test Into<Ipv4Addr>
        let ipv4: Ipv4Addr = vip.into();
        assert_eq!(ipv4, Ipv4Addr::new(10, 0, 0x0A, 0x0B));

        // Test Into<IpAddr>
        let ip: IpAddr = vip.into();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0x0A, 0x0B)));
    }

    #[test]
    fn test_network_config_serialization() {
        let config = NetworkConfig::default();

        // JSON roundtrip
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: NetworkConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.listen_port, deserialized.listen_port);
        assert_eq!(config.hub.heartbeat_secs, deserialized.hub.heartbeat_secs);

        // MessagePack roundtrip
        let msgpack = rmp_serde::to_vec(&config).unwrap();
        let deserialized: NetworkConfig = rmp_serde::from_slice(&msgpack).unwrap();
        assert_eq!(config.listen_port, deserialized.listen_port);
    }

    #[test]
    fn test_hub_net_config_serialization() {
        let public_key = [8u8; 32];
        let endpoint = "192.168.1.1:51820".parse().unwrap();
        let config = HubNetConfig::new(public_key, endpoint);

        // JSON roundtrip
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: HubNetConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.public_key, deserialized.public_key);
        assert_eq!(config.endpoint, deserialized.endpoint);
        assert_eq!(config.virtual_ip, deserialized.virtual_ip);

        // MessagePack roundtrip
        let msgpack = rmp_serde::to_vec(&config).unwrap();
        let deserialized: HubNetConfig = rmp_serde::from_slice(&msgpack).unwrap();
        assert_eq!(config.public_key, deserialized.public_key);
    }

    #[test]
    fn test_mdns_config_serialization() {
        let config = MdnsConfig::default();

        // JSON roundtrip
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: MdnsConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.enabled, deserialized.enabled);
        assert_eq!(config.service_name, deserialized.service_name);

        // MessagePack roundtrip
        let msgpack = rmp_serde::to_vec(&config).unwrap();
        let deserialized: MdnsConfig = rmp_serde::from_slice(&msgpack).unwrap();
        assert_eq!(config.enabled, deserialized.enabled);
    }

    #[test]
    fn test_virtual_ip_edge_cases() {
        // Test minimum and maximum host values
        let min_vip = VirtualIp::new(u16::MIN);
        assert_eq!(min_vip.host(), 0);
        assert_eq!(min_vip.as_ipv4(), Ipv4Addr::new(10, 0, 0, 0));

        let max_vip = VirtualIp::new(u16::MAX);
        assert_eq!(max_vip.host(), 65535);
        assert_eq!(max_vip.as_ipv4(), Ipv4Addr::new(10, 0, 255, 255));
    }

    #[test]
    fn test_peer_config_with_multiple_allowed_ips() {
        let public_key = [9u8; 32];
        let vip = VirtualIp::new(40);
        let mut config = PeerConfig::new(public_key, vip);

        // Add additional allowed IPs
        config
            .allowed_ips
            .push(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)));
        config
            .allowed_ips
            .push(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0)));

        assert_eq!(config.allowed_ips.len(), 3);

        // Test serialization with multiple IPs
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: PeerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.allowed_ips.len(), 3);
    }

    // ========================================================================
    // Multi-Path Network Aggregation Tests
    // ========================================================================

    #[test]
    fn test_endpoint_priority_constants() {
        assert!(EndpointPriority::PRIMARY < EndpointPriority::SECONDARY);
        assert!(EndpointPriority::SECONDARY < EndpointPriority::DEFAULT);
        assert!(EndpointPriority::DEFAULT < EndpointPriority::FALLBACK);

        assert_eq!(EndpointPriority::PRIMARY.0, 0);
        assert_eq!(EndpointPriority::SECONDARY.0, 50);
        assert_eq!(EndpointPriority::DEFAULT.0, 100);
        assert_eq!(EndpointPriority::FALLBACK.0, 255);
    }

    #[test]
    fn test_endpoint_priority_default() {
        let priority = EndpointPriority::default();
        assert_eq!(priority, EndpointPriority::DEFAULT);
    }

    #[test]
    fn test_endpoint_priority_display() {
        assert_eq!(format!("{}", EndpointPriority::PRIMARY), "0");
        assert_eq!(format!("{}", EndpointPriority::DEFAULT), "100");
    }

    #[test]
    fn test_path_id_from_ips() {
        let local1: IpAddr = "192.168.1.10".parse().unwrap();
        let remote1: IpAddr = "10.0.0.1".parse().unwrap();
        let local2: IpAddr = "192.168.2.10".parse().unwrap();
        let remote2: IpAddr = "10.0.0.2".parse().unwrap();

        // Same IPs should produce same PathId
        let path1a = PathId::from_ips(local1, remote1);
        let path1b = PathId::from_ips(local1, remote1);
        assert_eq!(path1a, path1b);

        // Different IPs should produce different PathIds
        let path2 = PathId::from_ips(local1, remote2);
        let path3 = PathId::from_ips(local2, remote1);
        let path4 = PathId::from_ips(local2, remote2);

        assert_ne!(path1a, path2);
        assert_ne!(path1a, path3);
        assert_ne!(path2, path3);
        assert_ne!(path3, path4);
    }

    #[test]
    fn test_path_id_display() {
        let path = PathId(0x12345678);
        assert_eq!(format!("{}", path), "path:12345678");
    }

    #[test]
    fn test_peer_endpoint_new() {
        let addr: SocketAddr = "192.168.1.100:51820".parse().unwrap();
        let ep = PeerEndpoint::new(addr);

        assert_eq!(ep.addr, addr);
        assert_eq!(ep.priority, EndpointPriority::DEFAULT);
        assert!(ep.enabled);
        assert!(ep.label.is_none());
        assert!(ep.last_success_ms.is_none());
        assert_eq!(ep.failure_count, 0);
    }

    #[test]
    fn test_peer_endpoint_builders() {
        let addr: SocketAddr = "192.168.1.100:51820".parse().unwrap();
        let ep = PeerEndpoint::new(addr)
            .with_priority(EndpointPriority::PRIMARY)
            .with_label("eth0")
            .with_enabled(false);

        assert_eq!(ep.priority, EndpointPriority::PRIMARY);
        assert_eq!(ep.label, Some("eth0".to_string()));
        assert!(!ep.enabled);
    }

    #[test]
    fn test_peer_endpoint_health_tracking() {
        let addr: SocketAddr = "192.168.1.100:51820".parse().unwrap();
        let mut ep = PeerEndpoint::new(addr);

        // Initially healthy
        assert!(ep.is_healthy());
        assert_eq!(ep.failure_count, 0);

        // Record failures
        ep.record_failure();
        assert_eq!(ep.failure_count, 1);
        assert!(ep.is_healthy());

        ep.record_failure();
        ep.record_failure();
        assert_eq!(ep.failure_count, 3);
        assert!(!ep.is_healthy()); // 3 failures = unhealthy

        // Record success resets failure count
        ep.record_success();
        assert_eq!(ep.failure_count, 0);
        assert!(ep.is_healthy());
        assert!(ep.last_success_ms.is_some());
    }

    #[test]
    fn test_peer_endpoint_display() {
        let addr: SocketAddr = "192.168.1.100:51820".parse().unwrap();

        let ep1 = PeerEndpoint::new(addr);
        assert_eq!(format!("{}", ep1), "192.168.1.100:51820");

        let ep2 = PeerEndpoint::new(addr).with_label("eth0");
        assert_eq!(format!("{}", ep2), "eth0@192.168.1.100:51820");
    }

    #[test]
    fn test_peer_endpoint_serialize() {
        let addr: SocketAddr = "192.168.1.100:51820".parse().unwrap();
        let ep = PeerEndpoint::new(addr)
            .with_priority(EndpointPriority::SECONDARY)
            .with_label("bond0");

        // JSON roundtrip
        let json = serde_json::to_string(&ep).unwrap();
        let deserialized: PeerEndpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(ep.addr, deserialized.addr);
        assert_eq!(ep.priority, deserialized.priority);
        assert_eq!(ep.label, deserialized.label);

        // MessagePack roundtrip
        let msgpack = rmp_serde::to_vec(&ep).unwrap();
        let deserialized: PeerEndpoint = rmp_serde::from_slice(&msgpack).unwrap();
        assert_eq!(ep.addr, deserialized.addr);
    }

    #[test]
    fn test_peer_config_with_endpoint() {
        let public_key = [10u8; 32];
        let vip = VirtualIp::new(50);
        let endpoint: SocketAddr = "192.168.1.100:51820".parse().unwrap();

        let config = PeerConfig::with_endpoint(public_key, vip, endpoint);

        assert_eq!(config.public_key, public_key);
        assert_eq!(config.virtual_ip, vip);
        assert_eq!(config.endpoints.len(), 1);
        assert_eq!(config.endpoint(), Some(endpoint));
    }

    #[test]
    fn test_peer_config_multi_endpoint() {
        let public_key = [11u8; 32];
        let vip = VirtualIp::new(60);
        let mut config = PeerConfig::new(public_key, vip);

        let ep1: SocketAddr = "10.10.10.2:51820".parse().unwrap();
        let ep2: SocketAddr = "10.10.11.2:51820".parse().unwrap();

        // Add endpoints with different priorities
        config.add_endpoint(
            PeerEndpoint::new(ep1)
                .with_priority(EndpointPriority::SECONDARY)
                .with_label("eth1"),
        );
        config.add_endpoint(
            PeerEndpoint::new(ep2)
                .with_priority(EndpointPriority::PRIMARY)
                .with_label("eth0"),
        );

        assert_eq!(config.endpoints.len(), 2);

        // endpoint() returns highest priority (lowest value)
        assert_eq!(config.endpoint(), Some(ep2));

        // active_endpoints() returns sorted by priority
        let active = config.active_endpoints();
        assert_eq!(active.len(), 2);
        assert_eq!(active[0].addr, ep2); // PRIMARY first
        assert_eq!(active[1].addr, ep1); // SECONDARY second
    }

    #[test]
    fn test_peer_config_add_remove_endpoint() {
        let public_key = [12u8; 32];
        let vip = VirtualIp::new(70);
        let mut config = PeerConfig::new(public_key, vip);

        let ep1: SocketAddr = "192.168.1.100:51820".parse().unwrap();
        let ep2: SocketAddr = "192.168.2.100:51820".parse().unwrap();

        // Add first endpoint
        assert!(config.add_endpoint(PeerEndpoint::new(ep1)));
        assert_eq!(config.endpoints.len(), 1);

        // Try to add duplicate
        assert!(!config.add_endpoint(PeerEndpoint::new(ep1)));
        assert_eq!(config.endpoints.len(), 1);

        // Add second endpoint
        assert!(config.add_endpoint(PeerEndpoint::new(ep2)));
        assert_eq!(config.endpoints.len(), 2);

        // Remove first endpoint
        let removed = config.remove_endpoint(ep1);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().addr, ep1);
        assert_eq!(config.endpoints.len(), 1);

        // Try to remove non-existent
        assert!(config.remove_endpoint(ep1).is_none());
    }

    #[test]
    fn test_peer_config_healthy_endpoints() {
        let public_key = [13u8; 32];
        let vip = VirtualIp::new(80);
        let mut config = PeerConfig::new(public_key, vip);

        let ep1: SocketAddr = "192.168.1.100:51820".parse().unwrap();
        let ep2: SocketAddr = "192.168.2.100:51820".parse().unwrap();

        config.add_endpoint(PeerEndpoint::new(ep1));
        config.add_endpoint(PeerEndpoint::new(ep2));

        // All healthy initially
        assert_eq!(config.healthy_endpoints().len(), 2);
        assert!(config.has_healthy_endpoint());

        // Make one unhealthy
        if let Some(ep) = config.get_endpoint_mut(ep1) {
            ep.record_failure();
            ep.record_failure();
            ep.record_failure();
        }

        assert_eq!(config.healthy_endpoints().len(), 1);
        assert!(config.has_healthy_endpoint());

        // Make both unhealthy
        if let Some(ep) = config.get_endpoint_mut(ep2) {
            ep.record_failure();
            ep.record_failure();
            ep.record_failure();
        }

        assert_eq!(config.healthy_endpoints().len(), 0);
        assert!(!config.has_healthy_endpoint());
    }

    #[test]
    fn test_peer_config_endpoint_count() {
        let public_key = [14u8; 32];
        let vip = VirtualIp::new(90);
        let mut config = PeerConfig::new(public_key, vip);

        assert_eq!(config.endpoint_count(), 0);

        let ep1: SocketAddr = "192.168.1.100:51820".parse().unwrap();
        let ep2: SocketAddr = "192.168.2.100:51820".parse().unwrap();

        config.add_endpoint(PeerEndpoint::new(ep1));
        assert_eq!(config.endpoint_count(), 1);

        config.add_endpoint(PeerEndpoint::new(ep2).with_enabled(false));
        assert_eq!(config.endpoint_count(), 1); // disabled not counted

        // Enable second endpoint
        if let Some(ep) = config.get_endpoint_mut(ep2) {
            ep.enabled = true;
        }
        assert_eq!(config.endpoint_count(), 2);
    }

    #[test]
    fn test_peer_config_multi_endpoint_serialize() {
        let public_key = [15u8; 32];
        let vip = VirtualIp::new(100);
        let mut config = PeerConfig::new(public_key, vip);

        config.add_endpoint(
            PeerEndpoint::new("10.10.10.2:51820".parse().unwrap())
                .with_priority(EndpointPriority::PRIMARY)
                .with_label("eth0"),
        );
        config.add_endpoint(
            PeerEndpoint::new("10.10.11.2:51820".parse().unwrap())
                .with_priority(EndpointPriority::SECONDARY)
                .with_label("eth1"),
        );

        // JSON roundtrip
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: PeerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.endpoints.len(), deserialized.endpoints.len());
        assert_eq!(config.endpoint(), deserialized.endpoint());

        // MessagePack roundtrip
        let msgpack = rmp_serde::to_vec(&config).unwrap();
        let deserialized: PeerConfig = rmp_serde::from_slice(&msgpack).unwrap();
        assert_eq!(config.endpoints.len(), deserialized.endpoints.len());
    }
}
