//! Foundational types for edge intelligence
//!
//! This module defines the core types used throughout the edge intelligence layer:
//! - `EdgeId`: Unique edge identifiers derived from public keys
//! - `EdgeType`: Device category (Server, Desktop, Mobile, `IoT`)
//! - `EdgeStatus`: Connection status (Online, Offline, Degraded, Throttled)
//! - `EdgeCapabilities`: Static edge properties (storage, bandwidth)
//! - `EdgeState`: Dynamic runtime state (status, last seen, battery)
//! - `EdgeInfo`: Complete edge record combining all information

use portal_net::VirtualIp;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Unique edge identifier derived from public key
///
/// `EdgeId` is a newtype wrapper around a 32-byte public key that serves
/// as a unique identifier for edge devices in the network.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EdgeId([u8; 32]);

impl EdgeId {
    /// Creates a new `EdgeId` from a public key
    #[must_use]
    pub const fn new(public_key: [u8; 32]) -> Self {
        Self(public_key)
    }

    /// Returns a reference to the underlying byte array
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Converts the `EdgeId` to a hexadecimal string
    #[must_use]
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

impl std::fmt::Debug for EdgeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EdgeId({}...)", &self.to_hex()[..16])
    }
}

impl std::fmt::Display for EdgeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.to_hex()[..16])
    }
}

/// Edge device category
///
/// Classifies edge devices by their expected characteristics and capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum EdgeType {
    /// Always-on server with high bandwidth and storage
    Server,
    /// Desktop computer with intermittent availability and medium bandwidth
    #[default]
    Desktop,
    /// Mobile device with battery constraints
    Mobile,
    /// `IoT` device with storage and compute constraints
    IoT,
}

impl std::fmt::Display for EdgeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Server => write!(f, "server"),
            Self::Desktop => write!(f, "desktop"),
            Self::Mobile => write!(f, "mobile"),
            Self::IoT => write!(f, "iot"),
        }
    }
}

/// Current connection status of an edge
///
/// Tracks the real-time connectivity and performance state of an edge device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum EdgeStatus {
    /// Edge is online and responsive
    Online,
    /// Edge is offline or unreachable
    #[default]
    Offline,
    /// Edge is responding but performance is degraded
    Degraded,
    /// Edge has bandwidth constraints active
    Throttled,
}

impl std::fmt::Display for EdgeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Online => write!(f, "online"),
            Self::Offline => write!(f, "offline"),
            Self::Degraded => write!(f, "degraded"),
            Self::Throttled => write!(f, "throttled"),
        }
    }
}

/// Static edge capabilities and configuration
///
/// Describes the fixed characteristics and resource limits of an edge device.
/// These values typically don't change during runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeCapabilities {
    /// Maximum storage capacity in bytes
    pub max_storage: u64,
    /// Currently used storage in bytes
    pub used_storage: u64,
    /// Maximum upload bandwidth in bytes/sec (0 = unlimited)
    pub max_upload_bandwidth: u64,
    /// Maximum download bandwidth in bytes/sec (0 = unlimited)
    pub max_download_bandwidth: u64,
    /// Maximum number of concurrent transfers
    pub max_concurrent_transfers: u16,
    /// Type of edge device
    pub edge_type: EdgeType,
    /// Protocol version supported by this edge
    pub protocol_version: u16,
}

impl EdgeCapabilities {
    /// Creates new edge capabilities with default values
    #[must_use]
    pub const fn new(max_storage: u64, edge_type: EdgeType) -> Self {
        Self {
            max_storage,
            used_storage: 0,
            max_upload_bandwidth: 0,
            max_download_bandwidth: 0,
            max_concurrent_transfers: 10,
            edge_type,
            protocol_version: 1,
        }
    }

    /// Returns the available storage in bytes
    #[must_use]
    pub const fn available_storage(&self) -> u64 {
        self.max_storage.saturating_sub(self.used_storage)
    }

    /// Returns the storage utilization as a percentage (0.0 to 1.0)
    #[must_use]
    pub fn storage_utilization(&self) -> f64 {
        if self.max_storage == 0 {
            return 0.0;
        }
        (self.used_storage as f64) / (self.max_storage as f64)
    }

    /// Checks if the edge has sufficient storage for a given size
    #[must_use]
    pub const fn has_storage(&self, required: u64) -> bool {
        self.available_storage() >= required
    }
}

impl Default for EdgeCapabilities {
    fn default() -> Self {
        Self::new(10_737_418_240, EdgeType::default()) // 10GB default
    }
}

/// Dynamic runtime state of an edge
///
/// Tracks the current operational state and metrics of an edge device.
/// These values change frequently during runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeState {
    /// Current connection status
    pub status: EdgeStatus,
    /// Last time edge was seen online
    pub last_seen: SystemTime,
    /// Number of chunks stored on this edge
    pub chunk_count: u32,
    /// Number of active transfers in progress
    pub active_transfers: u16,
    /// Battery level percentage (0-100), None if not battery powered
    pub battery_level: Option<u8>,
    /// Whether the connection is metered (e.g., cellular)
    pub is_metered: bool,
}

impl EdgeState {
    /// Creates a new edge state with the given status
    #[must_use]
    pub fn new(status: EdgeStatus) -> Self {
        Self {
            status,
            last_seen: SystemTime::now(),
            chunk_count: 0,
            active_transfers: 0,
            battery_level: None,
            is_metered: false,
        }
    }

    /// Checks if the edge is available for transfers (online or degraded)
    #[must_use]
    pub const fn is_available(&self) -> bool {
        matches!(self.status, EdgeStatus::Online | EdgeStatus::Degraded)
    }

    /// Checks if the edge has capacity for additional transfers
    #[must_use]
    pub const fn has_capacity(&self, max_concurrent: u16) -> bool {
        self.active_transfers < max_concurrent
    }

    /// Returns the duration since the edge was last seen
    #[must_use]
    pub fn time_since_seen(&self) -> std::time::Duration {
        SystemTime::now()
            .duration_since(self.last_seen)
            .unwrap_or(std::time::Duration::from_secs(0))
    }

    /// Updates the last seen timestamp to now
    pub fn update_last_seen(&mut self) {
        self.last_seen = SystemTime::now();
    }
}

impl Default for EdgeState {
    fn default() -> Self {
        Self::new(EdgeStatus::default())
    }
}

/// Complete edge record combining all information
///
/// `EdgeInfo` aggregates static capabilities, dynamic state, and network
/// configuration for a single edge device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeInfo {
    /// Unique edge identifier
    pub id: EdgeId,
    /// Virtual IP address in the Portal network
    pub virtual_ip: VirtualIp,
    /// Static edge capabilities
    pub capabilities: EdgeCapabilities,
    /// Dynamic edge state
    pub state: EdgeState,
    /// Timestamp when edge was registered
    pub registered_at: SystemTime,
}

impl EdgeInfo {
    /// Creates a new `EdgeInfo` record
    #[must_use]
    pub fn new(
        id: EdgeId,
        virtual_ip: VirtualIp,
        capabilities: EdgeCapabilities,
        state: EdgeState,
    ) -> Self {
        Self {
            id,
            virtual_ip,
            capabilities,
            state,
            registered_at: SystemTime::now(),
        }
    }

    /// Updates the edge state
    pub const fn update_state(&mut self, state: EdgeState) {
        self.state = state;
    }

    /// Checks if the edge record is stale (not seen recently)
    #[must_use]
    pub fn is_stale(&self, threshold: std::time::Duration) -> bool {
        self.state.time_since_seen() > threshold
    }

    /// Returns the storage utilization percentage (0.0 to 1.0)
    #[must_use]
    pub fn storage_utilization(&self) -> f64 {
        self.capabilities.storage_utilization()
    }

    /// Checks if the edge is available for data transfers
    #[must_use]
    pub const fn is_available(&self) -> bool {
        self.state.is_available()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edge_id_operations() {
        let public_key = [42u8; 32];
        let edge_id = EdgeId::new(public_key);
        assert_eq!(edge_id.as_bytes(), &public_key);
        assert_eq!(edge_id.as_bytes().len(), 32);

        let hex = EdgeId::new([0xAB; 32]).to_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| "0123456789abcdef".contains(c)));
        assert_eq!(hex, "ab".repeat(32));

        let id1 = EdgeId::new([1u8; 32]);
        let id2 = EdgeId::new([1u8; 32]);
        let id3 = EdgeId::new([2u8; 32]);
        assert_eq!(id1, id2);
        assert_ne!(id1, id3);

        let id_copy = id1;
        let id_clone = id1.clone();
        assert_eq!(id1, id_copy);
        assert_eq!(id1, id_clone);
    }

    #[test]
    fn test_edge_id_hash() {
        use std::collections::HashSet;

        let id1 = EdgeId::new([1u8; 32]);
        let id2 = EdgeId::new([2u8; 32]);
        let id3 = EdgeId::new([1u8; 32]);

        let mut set = HashSet::new();
        set.insert(id1);
        set.insert(id2);
        set.insert(id3);

        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_edge_id_serialize() {
        let edge_id = EdgeId::new([0x42; 32]);
        let json = serde_json::to_string(&edge_id).unwrap();
        let deserialized: EdgeId = serde_json::from_str(&json).unwrap();
        assert_eq!(edge_id, deserialized);

        let msgpack = rmp_serde::to_vec(&edge_id).unwrap();
        let deserialized: EdgeId = rmp_serde::from_slice(&msgpack).unwrap();
        assert_eq!(edge_id, deserialized);
    }

    #[test]
    fn test_edge_type_operations() {
        assert_ne!(EdgeType::Server, EdgeType::Desktop);
        assert_ne!(EdgeType::Mobile, EdgeType::IoT);
        assert_eq!(format!("{}", EdgeType::Server), "server");
        assert_eq!(format!("{}", EdgeType::Desktop), "desktop");
        assert_eq!(format!("{}", EdgeType::Mobile), "mobile");
        assert_eq!(format!("{}", EdgeType::IoT), "iot");
        assert_eq!(EdgeType::default(), EdgeType::Desktop);
    }

    #[test]
    fn test_edge_type_serialize() {
        for edge_type in [
            EdgeType::Server,
            EdgeType::Desktop,
            EdgeType::Mobile,
            EdgeType::IoT,
        ] {
            let json = serde_json::to_string(&edge_type).unwrap();
            assert_eq!(edge_type, serde_json::from_str(&json).unwrap());
            let msgpack = rmp_serde::to_vec(&edge_type).unwrap();
            assert_eq!(edge_type, rmp_serde::from_slice(&msgpack).unwrap());
        }
    }

    #[test]
    fn test_edge_status_operations() {
        assert_ne!(EdgeStatus::Online, EdgeStatus::Offline);
        assert_ne!(EdgeStatus::Degraded, EdgeStatus::Throttled);
        assert_eq!(format!("{}", EdgeStatus::Online), "online");
        assert_eq!(format!("{}", EdgeStatus::Offline), "offline");
        assert_eq!(format!("{}", EdgeStatus::Degraded), "degraded");
        assert_eq!(format!("{}", EdgeStatus::Throttled), "throttled");
        assert_eq!(EdgeStatus::default(), EdgeStatus::Offline);
    }

    #[test]
    fn test_edge_status_serialize() {
        for status in [
            EdgeStatus::Online,
            EdgeStatus::Offline,
            EdgeStatus::Degraded,
            EdgeStatus::Throttled,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            assert_eq!(status, serde_json::from_str(&json).unwrap());
            let msgpack = rmp_serde::to_vec(&status).unwrap();
            assert_eq!(status, rmp_serde::from_slice(&msgpack).unwrap());
        }
    }

    #[test]
    fn test_edge_capabilities_new_and_default() {
        let caps = EdgeCapabilities::new(1_000_000_000, EdgeType::Desktop);
        assert_eq!(caps.max_storage, 1_000_000_000);
        assert_eq!(caps.used_storage, 0);
        assert_eq!(caps.edge_type, EdgeType::Desktop);
        assert_eq!(caps.protocol_version, 1);
        assert_eq!(caps.max_concurrent_transfers, 10);

        let default_caps = EdgeCapabilities::default();
        assert_eq!(default_caps.max_storage, 10_737_418_240);
        assert_eq!(default_caps.used_storage, 0);
        assert_eq!(default_caps.edge_type, EdgeType::Desktop);
    }

    #[test]
    fn test_edge_capabilities_storage() {
        let mut caps = EdgeCapabilities::new(1000, EdgeType::Desktop);
        assert_eq!(caps.available_storage(), 1000);
        assert_eq!(caps.storage_utilization(), 0.0);
        assert!(caps.has_storage(500));
        assert!(caps.has_storage(1000));
        assert!(!caps.has_storage(1001));

        caps.used_storage = 250;
        assert_eq!(caps.available_storage(), 750);
        assert_eq!(caps.storage_utilization(), 0.25);

        caps.used_storage = 500;
        assert_eq!(caps.storage_utilization(), 0.5);

        caps.used_storage = 1000;
        assert_eq!(caps.available_storage(), 0);
        assert_eq!(caps.storage_utilization(), 1.0);

        caps.used_storage = 1200;
        assert_eq!(caps.available_storage(), 0);

        let mut zero_caps = EdgeCapabilities::new(0, EdgeType::Desktop);
        zero_caps.used_storage = 100;
        assert_eq!(zero_caps.storage_utilization(), 0.0);
    }

    #[test]
    fn test_edge_capabilities_serialize() {
        let caps = EdgeCapabilities::new(5_000_000_000, EdgeType::Server);
        let json = serde_json::to_string(&caps).unwrap();
        assert_eq!(caps, serde_json::from_str(&json).unwrap());
        let msgpack = rmp_serde::to_vec(&caps).unwrap();
        assert_eq!(caps, rmp_serde::from_slice(&msgpack).unwrap());
    }

    #[test]
    fn test_edge_state_new_and_default() {
        let state = EdgeState::new(EdgeStatus::Online);
        assert_eq!(state.status, EdgeStatus::Online);
        assert_eq!(state.chunk_count, 0);
        assert_eq!(state.active_transfers, 0);
        assert_eq!(state.battery_level, None);
        assert!(!state.is_metered);

        let default_state = EdgeState::default();
        assert_eq!(default_state.status, EdgeStatus::Offline);
        assert_eq!(default_state.chunk_count, 0);
    }

    #[test]
    fn test_edge_state_availability_and_capacity() {
        assert!(EdgeState::new(EdgeStatus::Online).is_available());
        assert!(EdgeState::new(EdgeStatus::Degraded).is_available());
        assert!(!EdgeState::new(EdgeStatus::Offline).is_available());
        assert!(!EdgeState::new(EdgeStatus::Throttled).is_available());

        let mut state = EdgeState::new(EdgeStatus::Online);
        state.active_transfers = 5;
        assert!(state.has_capacity(10));
        assert!(state.has_capacity(6));
        assert!(!state.has_capacity(5));
        assert!(!state.has_capacity(3));
    }

    #[test]
    fn test_edge_state_timing() {
        use std::thread;
        use std::time::Duration;

        let state = EdgeState::new(EdgeStatus::Online);
        assert!(state.time_since_seen() < Duration::from_secs(1));

        let mut state2 = EdgeState::new(EdgeStatus::Online);
        thread::sleep(Duration::from_millis(10));
        state2.update_last_seen();
        assert!(state2.time_since_seen() < Duration::from_millis(5));
    }

    #[test]
    fn test_edge_state_battery_level() {
        let mut state = EdgeState::new(EdgeStatus::Online);
        assert_eq!(state.battery_level, None);
        state.battery_level = Some(75);
        assert_eq!(state.battery_level, Some(75));
        state.battery_level = Some(0);
        assert_eq!(state.battery_level, Some(0));
        state.battery_level = Some(100);
        assert_eq!(state.battery_level, Some(100));
    }

    #[test]
    fn test_edge_state_serialize() {
        let state = EdgeState::new(EdgeStatus::Online);
        let json = serde_json::to_string(&state).unwrap();
        let deserialized: EdgeState = serde_json::from_str(&json).unwrap();
        assert_eq!(state.status, deserialized.status);
        let msgpack = rmp_serde::to_vec(&state).unwrap();
        let deserialized: EdgeState = rmp_serde::from_slice(&msgpack).unwrap();
        assert_eq!(state.status, deserialized.status);
    }

    #[test]
    fn test_edge_info_new_and_update() {
        let edge_id = EdgeId::new([1u8; 32]);
        let vip = VirtualIp::new(100);
        let caps = EdgeCapabilities::new(1_000_000_000, EdgeType::Desktop);
        let state = EdgeState::new(EdgeStatus::Online);

        let mut info = EdgeInfo::new(edge_id, vip, caps.clone(), state.clone());
        assert_eq!(info.id, edge_id);
        assert_eq!(info.virtual_ip, vip);
        assert_eq!(info.capabilities, caps);
        assert_eq!(info.state.status, state.status);

        let new_state = EdgeState::new(EdgeStatus::Degraded);
        info.update_state(new_state);
        assert_eq!(info.state.status, EdgeStatus::Degraded);
    }

    #[test]
    fn test_edge_info_state_checks() {
        use std::time::Duration;

        let edge_id = EdgeId::new([3u8; 32]);
        let vip = VirtualIp::new(75);
        let mut caps = EdgeCapabilities::new(1000, EdgeType::Desktop);
        caps.used_storage = 250;
        let state = EdgeState::new(EdgeStatus::Online);

        let info = EdgeInfo::new(edge_id, vip, caps, state);
        assert!(!info.is_stale(Duration::from_secs(60)));
        assert!(!info.is_stale(Duration::from_secs(1)));
        assert_eq!(info.storage_utilization(), 0.25);
        assert!(info.is_available());

        let offline_info = EdgeInfo::new(
            edge_id,
            vip,
            EdgeCapabilities::new(1_000_000_000, EdgeType::Server),
            EdgeState::new(EdgeStatus::Offline),
        );
        assert!(!offline_info.is_available());
    }

    #[test]
    fn test_edge_info_serialize() {
        let edge_id = EdgeId::new([6u8; 32]);
        let vip = VirtualIp::new(40);
        let caps = EdgeCapabilities::new(5_000_000_000, EdgeType::Desktop);
        let state = EdgeState::new(EdgeStatus::Online);
        let info = EdgeInfo::new(edge_id, vip, caps, state);

        let json = serde_json::to_string(&info).unwrap();
        let deserialized: EdgeInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(info.id, deserialized.id);
        assert_eq!(info.virtual_ip, deserialized.virtual_ip);

        let msgpack = rmp_serde::to_vec(&info).unwrap();
        let deserialized: EdgeInfo = rmp_serde::from_slice(&msgpack).unwrap();
        assert_eq!(info.id, deserialized.id);
    }

    #[test]
    fn test_edge_id_debug_display() {
        let edge_id = EdgeId::new([0xFF; 32]);
        assert!(format!("{:?}", edge_id).contains("EdgeId"));
        assert_eq!(format!("{}", edge_id).len(), 16);
    }

    #[test]
    fn test_edge_capabilities_custom_bandwidth() {
        let mut caps = EdgeCapabilities::new(1_000_000_000, EdgeType::Server);
        caps.max_upload_bandwidth = 10_000_000;
        caps.max_download_bandwidth = 50_000_000;
        assert_eq!(caps.max_upload_bandwidth, 10_000_000);
        assert_eq!(caps.max_download_bandwidth, 50_000_000);
    }

    #[test]
    fn test_edge_state_metered_connection() {
        let mut state = EdgeState::new(EdgeStatus::Online);
        assert!(!state.is_metered);
        state.is_metered = true;
        assert!(state.is_metered);
    }

    #[test]
    fn test_edge_info_complete_lifecycle() {
        let edge_id = EdgeId::new([7u8; 32]);
        let vip = VirtualIp::new(200);
        let mut caps = EdgeCapabilities::new(10_000_000_000, EdgeType::Server);
        caps.max_upload_bandwidth = 100_000_000;
        caps.max_concurrent_transfers = 50;

        let mut state = EdgeState::new(EdgeStatus::Online);
        state.chunk_count = 100;
        state.active_transfers = 5;

        let mut info = EdgeInfo::new(edge_id, vip, caps, state);

        assert_eq!(info.state.chunk_count, 100);
        assert!(info.is_available());

        info.capabilities.used_storage = 2_000_000_000;
        assert_eq!(info.storage_utilization(), 0.2);

        let degraded_state = EdgeState::new(EdgeStatus::Degraded);
        info.update_state(degraded_state);
        assert!(info.is_available());
    }
}
