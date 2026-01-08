//! HPC-Channels transport integration for warp-store
//!
//! Provides automatic transport tier selection based on data locality:
//! - Tier 0: Same process (tokio mpsc, <1µs)
//! - Tier 1: Same machine (Unix socket/io_uring/kqueue, ~2-10µs)
//! - Tier 2: Same datacenter (RDMA/AF_XDP, ~1-50µs)
//! - Tier 3: Cross-site (WireGuard, ~50µs+)
//!
//! # Example
//!
//! ```ignore
//! use warp_store::transport::{TransportConfig, StorageTransport};
//!
//! let config = TransportConfig::auto_detect();
//! let transport = StorageTransport::new(config).await?;
//!
//! // Tier is automatically selected based on data location
//! let data = transport.get("bucket", "key", Some(peer_location)).await?;
//! ```

/// RDMA transport implementation for Tier 2 (same datacenter) communication
#[cfg(feature = "rmpi")]
pub mod rdma;

#[cfg(feature = "rmpi")]
pub use rdma::{
    RdmaConnectionState, RdmaEndpoint, RdmaEndpointStatsSnapshot, RdmaTransport,
    RdmaTransportConfig, peer_to_endpoint, select_transport,
};

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use bytes::Bytes;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tracing::{debug, trace};

use crate::ObjectKey;

/// Transport tier identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tier {
    /// Same process - tokio mpsc channels (<1µs)
    Tier0,
    /// Same machine - Unix socket, io_uring, kqueue (~2-10µs)
    Tier1,
    /// Same datacenter - RDMA, AF_XDP, CXL (~1-50µs)
    Tier2,
    /// Cross-site - WireGuard tunnels (~50µs+)
    Tier3,
}

impl Tier {
    /// Get the expected latency range for this tier
    pub fn latency_range(&self) -> (Duration, Duration) {
        match self {
            Tier::Tier0 => (Duration::from_nanos(100), Duration::from_micros(1)),
            Tier::Tier1 => (Duration::from_micros(2), Duration::from_micros(10)),
            Tier::Tier2 => (Duration::from_micros(1), Duration::from_micros(100)),
            Tier::Tier3 => (Duration::from_micros(50), Duration::from_millis(100)),
        }
    }

    /// Get the typical bandwidth for this tier
    pub fn bandwidth_hint(&self) -> u64 {
        match self {
            Tier::Tier0 => 100_000_000_000, // 100 GB/s (memory bandwidth)
            Tier::Tier1 => 10_000_000_000,  // 10 GB/s (local socket)
            Tier::Tier2 => 50_000_000_000,  // 50 GB/s (RDMA)
            Tier::Tier3 => 1_000_000_000,   // 1 GB/s (WireGuard)
        }
    }
}

/// Location information for a peer/storage node
#[derive(Debug, Clone)]
pub struct PeerLocation {
    /// Unique peer identifier
    pub peer_id: String,

    /// Process ID (for same-process detection)
    pub pid: Option<u32>,

    /// Unix socket path (for same-machine communication)
    pub socket_path: Option<PathBuf>,

    /// Network address
    pub addr: Option<SocketAddr>,

    /// Datacenter zone
    pub zone: Option<String>,

    /// Geographic region
    pub region: Option<String>,

    /// WireGuard public key (for cross-site tunnels)
    pub wg_pubkey: Option<[u8; 32]>,
}

impl PeerLocation {
    /// Create a local peer location (same process)
    pub fn local() -> Self {
        Self {
            peer_id: format!("local-{}", std::process::id()),
            pid: Some(std::process::id()),
            socket_path: None,
            addr: None,
            zone: None,
            region: None,
            wg_pubkey: None,
        }
    }

    /// Create a peer location for same-machine communication
    pub fn same_machine(socket_path: PathBuf) -> Self {
        Self {
            peer_id: format!("local-{}", socket_path.display()),
            pid: None,
            socket_path: Some(socket_path),
            addr: None,
            zone: None,
            region: None,
            wg_pubkey: None,
        }
    }

    /// Create a peer location for network communication
    pub fn network(peer_id: String, addr: SocketAddr, zone: Option<String>) -> Self {
        Self {
            peer_id,
            pid: None,
            socket_path: None,
            addr: Some(addr),
            zone,
            region: None,
            wg_pubkey: None,
        }
    }

    /// Determine optimal tier for communicating with this peer
    pub fn optimal_tier(&self, local: &PeerLocation) -> Tier {
        // Same process?
        if let (Some(local_pid), Some(peer_pid)) = (local.pid, self.pid) {
            if local_pid == peer_pid {
                return Tier::Tier0;
            }
        }

        // Same machine? (socket path available)
        if self.socket_path.is_some() {
            return Tier::Tier1;
        }

        // Same zone?
        if let (Some(local_zone), Some(peer_zone)) = (&local.zone, &self.zone) {
            if local_zone == peer_zone {
                return Tier::Tier2;
            }
        }

        // Cross-site (default)
        Tier::Tier3
    }
}

/// Transport configuration
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Maximum connections per tier
    pub max_connections_per_tier: usize,

    /// Connection idle timeout
    pub connection_idle_timeout: Duration,

    /// Enable automatic fallback to higher tiers
    pub enable_fallback: bool,

    /// Prefer lower latency tiers
    pub prefer_lower_latency: bool,

    /// Local peer location
    pub local_peer: PeerLocation,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            max_connections_per_tier: 100,
            connection_idle_timeout: Duration::from_secs(300),
            enable_fallback: true,
            prefer_lower_latency: true,
            local_peer: PeerLocation::local(),
        }
    }
}

impl TransportConfig {
    /// Create configuration with auto-detected local peer
    pub fn auto_detect() -> Self {
        Self::default()
    }

    /// Set the local zone for tier selection
    pub fn with_zone(mut self, zone: impl Into<String>) -> Self {
        self.local_peer.zone = Some(zone.into());
        self
    }

    /// Set the local region
    pub fn with_region(mut self, region: impl Into<String>) -> Self {
        self.local_peer.region = Some(region.into());
        self
    }
}

/// Statistics for a transport tier
#[derive(Debug, Clone, Default)]
pub struct TierStats {
    /// Total messages sent
    pub messages_sent: u64,
    /// Total messages received
    pub messages_recv: u64,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_recv: u64,
    /// Active connections
    pub active_connections: usize,
    /// Average latency in microseconds
    pub avg_latency_us: u64,
}

/// Storage message types for transport
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageMessage {
    /// Get object request
    Get {
        /// Bucket name
        bucket: String,
        /// Object key
        key: String,
        /// Request identifier for matching responses
        request_id: u64,
    },
    /// Get response with data
    GetResponse {
        /// Request identifier for matching responses
        request_id: u64,
        /// Object data if found
        #[serde(with = "optional_bytes")]
        data: Option<Bytes>,
        /// Error message if operation failed
        error: Option<String>,
    },
    /// Put object request
    Put {
        /// Bucket name
        bucket: String,
        /// Object key
        key: String,
        /// Object data to store
        #[serde(with = "bytes_serde")]
        data: Bytes,
        /// Request identifier for matching responses
        request_id: u64,
    },
    /// Put response
    PutResponse {
        /// Request identifier for matching responses
        request_id: u64,
        /// Whether the operation succeeded
        success: bool,
        /// Error message if operation failed
        error: Option<String>,
    },
    /// Delete object request
    Delete {
        /// Bucket name
        bucket: String,
        /// Object key
        key: String,
        /// Request identifier for matching responses
        request_id: u64,
    },
    /// Delete response
    DeleteResponse {
        /// Request identifier for matching responses
        request_id: u64,
        /// Whether the operation succeeded
        success: bool,
        /// Error message if operation failed
        error: Option<String>,
    },
    /// Chunk transfer (for large objects)
    Chunk {
        /// Request identifier for matching responses
        request_id: u64,
        /// Zero-based chunk index
        chunk_index: u32,
        /// Total number of chunks
        total_chunks: u32,
        /// Chunk data
        #[serde(with = "bytes_serde")]
        data: Bytes,
    },
}

/// Helper module for serializing Bytes
mod bytes_serde {
    use bytes::Bytes;
    use serde::{Deserializer, Serializer};

    /// Serialize Bytes as byte array
    pub fn serialize<S>(value: &Bytes, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }

    /// Deserialize byte array into Bytes
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Bytes, D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec: Vec<u8> = serde_bytes::deserialize(deserializer)?;
        Ok(Bytes::from(vec))
    }
}

/// Helper module for serializing Option<Bytes>
mod optional_bytes {
    use bytes::Bytes;
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialize optional Bytes as optional byte array
    pub fn serialize<S>(value: &Option<Bytes>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => serializer.serialize_some(&bytes.to_vec()),
            None => serializer.serialize_none(),
        }
    }

    /// Deserialize optional byte array into optional Bytes
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Bytes>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<Vec<u8>> = Option::deserialize(deserializer)?;
        Ok(opt.map(Bytes::from))
    }
}

/// Route entry for object location
#[derive(Debug, Clone)]
pub struct ObjectRoute {
    /// Peer locations where object is stored
    pub locations: Vec<PeerLocation>,
    /// Preferred tier (cached from first lookup)
    pub preferred_tier: Option<Tier>,
    /// Last access timestamp
    pub last_access: std::time::Instant,
}

/// Storage transport layer
///
/// Automatically selects optimal transport tier based on data locality.
pub struct StorageTransport {
    /// Configuration
    config: TransportConfig,

    /// Route table: bucket/key -> locations
    routes: DashMap<String, ObjectRoute>,

    /// Per-tier statistics
    stats: DashMap<Tier, TierStats>,

    /// Request ID counter
    next_request_id: std::sync::atomic::AtomicU64,
}

impl StorageTransport {
    /// Create a new storage transport
    pub fn new(config: TransportConfig) -> Self {
        debug!(
            zone = ?config.local_peer.zone,
            "Initializing storage transport"
        );

        Self {
            config,
            routes: DashMap::new(),
            stats: DashMap::new(),
            next_request_id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Register a route for an object
    pub fn add_route(&self, key: &ObjectKey, location: PeerLocation) {
        let route_key = format!("{}/{}", key.bucket(), key.key());
        let tier = location.optimal_tier(&self.config.local_peer);

        self.routes
            .entry(route_key)
            .and_modify(|route| {
                // Add location if not already present
                if !route
                    .locations
                    .iter()
                    .any(|l| l.peer_id == location.peer_id)
                {
                    route.locations.push(location.clone());
                }
                route.last_access = std::time::Instant::now();
            })
            .or_insert_with(|| ObjectRoute {
                locations: vec![location],
                preferred_tier: Some(tier),
                last_access: std::time::Instant::now(),
            });

        trace!(key = %key, tier = ?tier, "Added object route");
    }

    /// Get the optimal tier for an object
    pub fn get_tier(&self, key: &ObjectKey) -> Option<Tier> {
        let route_key = format!("{}/{}", key.bucket(), key.key());

        self.routes.get(&route_key).and_then(|route| {
            // Find lowest latency tier among available locations
            if self.config.prefer_lower_latency {
                route
                    .locations
                    .iter()
                    .map(|loc| loc.optimal_tier(&self.config.local_peer))
                    .min_by_key(|tier| match tier {
                        Tier::Tier0 => 0,
                        Tier::Tier1 => 1,
                        Tier::Tier2 => 2,
                        Tier::Tier3 => 3,
                    })
            } else {
                route.preferred_tier
            }
        })
    }

    /// Get all locations for an object
    pub fn get_locations(&self, key: &ObjectKey) -> Vec<PeerLocation> {
        let route_key = format!("{}/{}", key.bucket(), key.key());

        self.routes
            .get(&route_key)
            .map(|route| route.locations.clone())
            .unwrap_or_default()
    }

    /// Remove a route
    pub fn remove_route(&self, key: &ObjectKey) {
        let route_key = format!("{}/{}", key.bucket(), key.key());
        self.routes.remove(&route_key);
    }

    /// Get statistics for a tier
    pub fn tier_stats(&self, tier: Tier) -> TierStats {
        self.stats.get(&tier).map(|s| s.clone()).unwrap_or_default()
    }

    /// Get all tier statistics
    pub fn all_stats(&self) -> HashMap<Tier, TierStats> {
        self.stats
            .iter()
            .map(|entry| (*entry.key(), entry.value().clone()))
            .collect()
    }

    /// Record a send operation
    pub fn record_send(&self, tier: Tier, bytes: usize) {
        self.stats
            .entry(tier)
            .and_modify(|s| {
                s.messages_sent += 1;
                s.bytes_sent += bytes as u64;
            })
            .or_insert_with(|| TierStats {
                messages_sent: 1,
                bytes_sent: bytes as u64,
                ..Default::default()
            });
    }

    /// Record a receive operation
    pub fn record_recv(&self, tier: Tier, bytes: usize, latency_us: u64) {
        self.stats
            .entry(tier)
            .and_modify(|s| {
                s.messages_recv += 1;
                s.bytes_recv += bytes as u64;
                // Rolling average
                s.avg_latency_us =
                    (s.avg_latency_us * (s.messages_recv - 1) + latency_us) / s.messages_recv;
            })
            .or_insert_with(|| TierStats {
                messages_recv: 1,
                bytes_recv: bytes as u64,
                avg_latency_us: latency_us,
                ..Default::default()
            });
    }

    /// Generate a unique request ID
    pub fn next_request_id(&self) -> u64 {
        self.next_request_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// Get the local peer location
    pub fn local_peer(&self) -> &PeerLocation {
        &self.config.local_peer
    }

    /// Check if fallback is enabled
    pub fn fallback_enabled(&self) -> bool {
        self.config.enable_fallback
    }

    /// Prune stale routes (not accessed within timeout)
    pub fn prune_stale_routes(&self, max_age: Duration) {
        let now = std::time::Instant::now();
        self.routes
            .retain(|_, route| now.duration_since(route.last_access) < max_age);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier_selection_same_process() {
        let local = PeerLocation::local();
        let mut peer = PeerLocation::local();
        peer.pid = local.pid; // Same PID

        assert_eq!(peer.optimal_tier(&local), Tier::Tier0);
    }

    #[test]
    fn test_tier_selection_same_machine() {
        let local = PeerLocation::local();
        let peer = PeerLocation::same_machine("/tmp/warp.sock".into());

        assert_eq!(peer.optimal_tier(&local), Tier::Tier1);
    }

    #[test]
    fn test_tier_selection_same_zone() {
        let mut local = PeerLocation::local();
        local.zone = Some("us-east-1a".to_string());

        let peer = PeerLocation::network(
            "peer-1".to_string(),
            "10.0.0.1:9000".parse().unwrap(),
            Some("us-east-1a".to_string()),
        );

        assert_eq!(peer.optimal_tier(&local), Tier::Tier2);
    }

    #[test]
    fn test_tier_selection_cross_site() {
        let mut local = PeerLocation::local();
        local.zone = Some("us-east-1a".to_string());

        let peer = PeerLocation::network(
            "peer-1".to_string(),
            "10.0.0.1:9000".parse().unwrap(),
            Some("eu-west-1a".to_string()),
        );

        assert_eq!(peer.optimal_tier(&local), Tier::Tier3);
    }

    #[test]
    fn test_transport_routes() {
        let config = TransportConfig::default();
        let transport = StorageTransport::new(config);

        let key = ObjectKey::new("bucket", "key").unwrap();
        let location = PeerLocation::same_machine("/tmp/test.sock".into());

        transport.add_route(&key, location);

        assert_eq!(transport.get_tier(&key), Some(Tier::Tier1));
        assert_eq!(transport.get_locations(&key).len(), 1);
    }

    #[test]
    fn test_tier_stats() {
        let config = TransportConfig::default();
        let transport = StorageTransport::new(config);

        transport.record_send(Tier::Tier2, 1000);
        transport.record_recv(Tier::Tier2, 2000, 50);

        let stats = transport.tier_stats(Tier::Tier2);
        assert_eq!(stats.messages_sent, 1);
        assert_eq!(stats.messages_recv, 1);
        assert_eq!(stats.bytes_sent, 1000);
        assert_eq!(stats.bytes_recv, 2000);
        assert_eq!(stats.avg_latency_us, 50);
    }

    #[test]
    fn test_latency_ranges() {
        assert!(Tier::Tier0.latency_range().1 < Tier::Tier1.latency_range().0);
        assert!(Tier::Tier2.latency_range().1 < Tier::Tier3.latency_range().1);
    }

    #[test]
    fn test_bandwidth_hints() {
        assert!(Tier::Tier0.bandwidth_hint() > Tier::Tier1.bandwidth_hint());
        assert!(Tier::Tier1.bandwidth_hint() < Tier::Tier2.bandwidth_hint());
        assert!(Tier::Tier2.bandwidth_hint() > Tier::Tier3.bandwidth_hint());
    }
}
