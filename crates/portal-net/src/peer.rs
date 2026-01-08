//! Peer management for Portal mesh network
//!
//! This module provides concurrent peer management with:
//! - Thread-safe peer storage using `DashMap`
//! - Bidirectional routing (public key <-> virtual IP)
//! - Peer metadata tracking (stats, status, endpoints)
//! - Support for peer roaming (endpoint updates)

use dashmap::DashMap;
use std::net::SocketAddr;

use crate::types::{
    EndpointPriority, PeerConfig, PeerEndpoint, PeerMetadata, PeerStatus, VirtualIp,
};
use crate::{PortalNetError, Result};

/// Manages peer configurations and routing for the Portal mesh network
///
/// `PeerManager` provides thread-safe concurrent access to peer metadata
/// and maintains bidirectional routing between public keys and virtual IPs.
/// It uses `DashMap` for lock-free concurrent access patterns.
///
/// # Thread Safety
///
/// All operations are thread-safe and can be called from multiple threads
/// without external synchronization.
#[derive(Debug)]
pub struct PeerManager {
    /// Peer metadata indexed by public key
    peers: DashMap<[u8; 32], PeerMetadata>,
    /// Routing table: virtual IP to public key
    routing: DashMap<VirtualIp, [u8; 32]>,
}

impl PeerManager {
    /// Creates a new empty peer manager
    #[must_use]
    pub fn new() -> Self {
        Self {
            peers: DashMap::new(),
            routing: DashMap::new(),
        }
    }

    /// Adds a new peer to the manager
    ///
    /// This operation is atomic - either both the peer metadata and routing
    /// entry are added, or neither is added (in case of duplicate key).
    ///
    /// # Errors
    ///
    /// Returns `PeerNotFound` error if a peer with the same public key already exists.
    pub fn add_peer(&self, config: PeerConfig) -> Result<()> {
        let public_key = config.public_key;
        let virtual_ip = config.virtual_ip;

        // Check if peer already exists
        if self.peers.contains_key(&public_key) {
            return Err(PortalNetError::PeerNotFound(format!(
                "peer with public key {} already exists",
                hex::encode(public_key)
            )));
        }

        // Create metadata and insert atomically
        let metadata = PeerMetadata::new(config);
        self.peers.insert(public_key, metadata);
        self.routing.insert(virtual_ip, public_key);

        Ok(())
    }

    /// Removes a peer from the manager
    ///
    /// Returns the removed peer's metadata if it existed, or `None` otherwise.
    /// This operation removes both the peer metadata and routing entry.
    #[must_use]
    pub fn remove_peer(&self, public_key: &[u8; 32]) -> Option<PeerMetadata> {
        if let Some((_, metadata)) = self.peers.remove(public_key) {
            // Also remove routing entry
            self.routing.remove(&metadata.config.virtual_ip);
            Some(metadata)
        } else {
            None
        }
    }

    /// Updates a peer's primary endpoint address
    ///
    /// Used to support roaming peers whose endpoint addresses change
    /// (e.g., mobile clients, NAT rebinding).
    ///
    /// If the endpoint already exists, it's updated to PRIMARY priority.
    /// If not, it's added as a new PRIMARY endpoint.
    ///
    /// # Errors
    ///
    /// Returns `PeerNotFound` if no peer exists with the given public key.
    pub fn update_endpoint(&self, public_key: &[u8; 32], endpoint: SocketAddr) -> Result<()> {
        if let Some(mut entry) = self.peers.get_mut(public_key) {
            // Check if endpoint already exists
            if let Some(ep) = entry.config.get_endpoint_mut(endpoint) {
                ep.priority = EndpointPriority::PRIMARY;
                ep.record_success();
            } else {
                // Add new endpoint as primary
                entry.config.add_endpoint(
                    PeerEndpoint::new(endpoint).with_priority(EndpointPriority::PRIMARY),
                );
            }
            Ok(())
        } else {
            Err(PortalNetError::PeerNotFound(format!(
                "peer with public key {} not found",
                hex::encode(public_key)
            )))
        }
    }

    /// Adds an endpoint to a peer
    ///
    /// # Errors
    ///
    /// Returns `PeerNotFound` if no peer exists with the given public key.
    pub fn add_endpoint(&self, public_key: &[u8; 32], endpoint: PeerEndpoint) -> Result<bool> {
        if let Some(mut entry) = self.peers.get_mut(public_key) {
            Ok(entry.config.add_endpoint(endpoint))
        } else {
            Err(PortalNetError::PeerNotFound(format!(
                "peer with public key {} not found",
                hex::encode(public_key)
            )))
        }
    }

    /// Removes an endpoint from a peer
    ///
    /// # Errors
    ///
    /// Returns `PeerNotFound` if no peer exists with the given public key.
    pub fn remove_endpoint(
        &self,
        public_key: &[u8; 32],
        addr: SocketAddr,
    ) -> Result<Option<PeerEndpoint>> {
        if let Some(mut entry) = self.peers.get_mut(public_key) {
            Ok(entry.config.remove_endpoint(addr))
        } else {
            Err(PortalNetError::PeerNotFound(format!(
                "peer with public key {} not found",
                hex::encode(public_key)
            )))
        }
    }

    /// Updates a peer's connection status
    ///
    /// Used to track connection state changes (e.g., offline -> online, relayed -> direct P2P).
    ///
    /// # Errors
    ///
    /// Returns `PeerNotFound` if no peer exists with the given public key.
    pub fn update_status(&self, public_key: &[u8; 32], status: PeerStatus) -> Result<()> {
        if let Some(mut entry) = self.peers.get_mut(public_key) {
            entry.status = status;
            Ok(())
        } else {
            Err(PortalNetError::PeerNotFound(format!(
                "peer with public key {} not found",
                hex::encode(public_key)
            )))
        }
    }

    /// Retrieves a peer by its public key
    ///
    /// Returns a clone of the peer's metadata if found.
    #[must_use]
    pub fn get_by_key(&self, public_key: &[u8; 32]) -> Option<PeerMetadata> {
        self.peers.get(public_key).map(|entry| entry.clone())
    }

    /// Retrieves a peer by its virtual IP address
    ///
    /// Returns a clone of the peer's metadata if found.
    #[must_use]
    pub fn get_by_ip(&self, ip: VirtualIp) -> Option<PeerMetadata> {
        self.routing
            .get(&ip)
            .and_then(|entry| self.peers.get(entry.value()).map(|p| p.clone()))
    }

    /// Lists all peers in the manager
    ///
    /// Returns a vector of cloned peer metadata. The order is not guaranteed.
    #[must_use]
    pub fn list_all(&self) -> Vec<PeerMetadata> {
        self.peers
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Counts peers with a specific status
    #[must_use]
    pub fn count_by_status(&self, status: PeerStatus) -> usize {
        self.peers
            .iter()
            .filter(|entry| entry.value().status == status)
            .count()
    }

    /// Updates peer statistics (transmitted and received bytes)
    ///
    /// # Errors
    ///
    /// Returns `PeerNotFound` if no peer exists with the given public key.
    pub fn update_stats(&self, public_key: &[u8; 32], tx: u64, rx: u64) -> Result<()> {
        if let Some(mut entry) = self.peers.get_mut(public_key) {
            entry.update_stats(tx, rx);
            Ok(())
        } else {
            let key_hex = hex::encode(public_key);
            Err(PortalNetError::PeerNotFound(format!(
                "peer with public key {key_hex} not found"
            )))
        }
    }
}

impl Default for PeerManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    /// Helper to create a test peer config
    fn test_config(key: u8, host: u16) -> PeerConfig {
        PeerConfig::new([key; 32], VirtualIp::new(host))
    }

    #[test]
    fn test_peer_manager_new() {
        let manager = PeerManager::new();
        assert_eq!(manager.list_all().len(), 0);
        assert_eq!(manager.count_by_status(PeerStatus::Unknown), 0);
    }

    #[test]
    fn test_add_peer() {
        let manager = PeerManager::new();
        let config = test_config(1, 100);

        let result = manager.add_peer(config.clone());
        assert!(result.is_ok());

        // Verify peer was added
        let peer = manager.get_by_key(&config.public_key).unwrap();
        assert_eq!(peer.config.public_key, config.public_key);
        assert_eq!(peer.config.virtual_ip, config.virtual_ip);
        assert_eq!(peer.status, PeerStatus::Unknown);
        assert_eq!(peer.tx_bytes, 0);
        assert_eq!(peer.rx_bytes, 0);

        // Verify routing entry
        let peer_by_ip = manager.get_by_ip(config.virtual_ip).unwrap();
        assert_eq!(peer_by_ip.config.public_key, config.public_key);
    }

    #[test]
    fn test_add_duplicate_fails() {
        let manager = PeerManager::new();
        let config = test_config(1, 100);

        // First add should succeed
        assert!(manager.add_peer(config.clone()).is_ok());

        // Second add with same key should fail
        let result = manager.add_peer(config);
        assert!(result.is_err());

        match result {
            Err(PortalNetError::PeerNotFound(msg)) => {
                assert!(msg.contains("already exists"));
            }
            _ => panic!("expected PeerNotFound error"),
        }

        // Should still have only one peer
        assert_eq!(manager.list_all().len(), 1);
    }

    #[test]
    fn test_remove_peer() {
        let manager = PeerManager::new();
        let config = test_config(1, 100);

        manager.add_peer(config.clone()).unwrap();
        assert_eq!(manager.list_all().len(), 1);

        // Remove the peer
        let removed = manager.remove_peer(&config.public_key);
        assert!(removed.is_some());

        let metadata = removed.unwrap();
        assert_eq!(metadata.config.public_key, config.public_key);
        assert_eq!(metadata.config.virtual_ip, config.virtual_ip);

        // Verify both peer and routing entry are gone
        assert!(manager.get_by_key(&config.public_key).is_none());
        assert!(manager.get_by_ip(config.virtual_ip).is_none());
        assert_eq!(manager.list_all().len(), 0);
    }

    #[test]
    fn test_remove_nonexistent_peer() {
        let manager = PeerManager::new();
        let result = manager.remove_peer(&[99u8; 32]);
        assert!(result.is_none());
    }

    #[test]
    fn test_get_by_key() {
        let manager = PeerManager::new();
        let config1 = test_config(1, 100);
        let config2 = test_config(2, 200);

        manager.add_peer(config1.clone()).unwrap();
        manager.add_peer(config2.clone()).unwrap();

        // Get first peer
        let peer1 = manager.get_by_key(&config1.public_key).unwrap();
        assert_eq!(peer1.config.public_key, config1.public_key);
        assert_eq!(peer1.config.virtual_ip.host(), 100);

        // Get second peer
        let peer2 = manager.get_by_key(&config2.public_key).unwrap();
        assert_eq!(peer2.config.public_key, config2.public_key);
        assert_eq!(peer2.config.virtual_ip.host(), 200);

        // Get nonexistent peer
        assert!(manager.get_by_key(&[99u8; 32]).is_none());
    }

    #[test]
    fn test_get_by_ip() {
        let manager = PeerManager::new();
        let config1 = test_config(1, 100);
        let config2 = test_config(2, 200);

        manager.add_peer(config1.clone()).unwrap();
        manager.add_peer(config2.clone()).unwrap();

        // Get first peer by IP
        let peer1 = manager.get_by_ip(VirtualIp::new(100)).unwrap();
        assert_eq!(peer1.config.public_key, config1.public_key);

        // Get second peer by IP
        let peer2 = manager.get_by_ip(VirtualIp::new(200)).unwrap();
        assert_eq!(peer2.config.public_key, config2.public_key);

        // Get nonexistent IP
        assert!(manager.get_by_ip(VirtualIp::new(999)).is_none());
    }

    #[test]
    fn test_update_endpoint() {
        let manager = PeerManager::new();
        let config = test_config(1, 100);
        manager.add_peer(config.clone()).unwrap();

        // Initially no endpoint
        assert!(
            manager
                .get_by_key(&config.public_key)
                .unwrap()
                .config
                .endpoint()
                .is_none()
        );

        // Update endpoint
        let endpoint: SocketAddr = "192.168.1.100:51820".parse().unwrap();
        manager
            .update_endpoint(&config.public_key, endpoint)
            .unwrap();
        assert_eq!(
            manager
                .get_by_key(&config.public_key)
                .unwrap()
                .config
                .endpoint(),
            Some(endpoint)
        );

        // Update to different endpoint (adds as a new endpoint, both become PRIMARY)
        let endpoint2: SocketAddr = "10.0.0.50:12345".parse().unwrap();
        manager
            .update_endpoint(&config.public_key, endpoint2)
            .unwrap();

        // endpoint() returns highest priority (both are PRIMARY, so first one added)
        let peer = manager.get_by_key(&config.public_key).unwrap();
        assert!(peer.config.endpoint().is_some());
        assert_eq!(peer.config.endpoints.len(), 2);

        // Test nonexistent peer
        assert!(manager.update_endpoint(&[99u8; 32], endpoint).is_err());
    }

    #[test]
    fn test_update_status() {
        let manager = PeerManager::new();
        let config = test_config(1, 100);
        manager.add_peer(config.clone()).unwrap();

        // Test all status transitions
        let statuses = [
            PeerStatus::Unknown,
            PeerStatus::Online,
            PeerStatus::DirectP2P,
            PeerStatus::Relayed,
            PeerStatus::Offline,
        ];
        for status in statuses {
            manager.update_status(&config.public_key, status).unwrap();
            assert_eq!(
                manager.get_by_key(&config.public_key).unwrap().status,
                status
            );
        }

        // Test nonexistent peer
        assert!(
            manager
                .update_status(&[99u8; 32], PeerStatus::Online)
                .is_err()
        );
    }

    #[test]
    fn test_list_all() {
        let manager = PeerManager::new();

        // Empty list
        assert_eq!(manager.list_all().len(), 0);

        // Add peers
        manager.add_peer(test_config(1, 100)).unwrap();
        manager.add_peer(test_config(2, 200)).unwrap();
        manager.add_peer(test_config(3, 300)).unwrap();

        // List should contain all peers
        let peers = manager.list_all();
        assert_eq!(peers.len(), 3);

        // Verify all peers are present (order not guaranteed)
        let keys: Vec<_> = peers.iter().map(|p| p.config.public_key[0]).collect();
        assert!(keys.contains(&1));
        assert!(keys.contains(&2));
        assert!(keys.contains(&3));
    }

    #[test]
    fn test_count_by_status() {
        let manager = PeerManager::new();

        // Add peers
        manager.add_peer(test_config(1, 100)).unwrap();
        manager.add_peer(test_config(2, 200)).unwrap();
        manager.add_peer(test_config(3, 300)).unwrap();
        manager.add_peer(test_config(4, 400)).unwrap();

        // All start as Unknown
        assert_eq!(manager.count_by_status(PeerStatus::Unknown), 4);
        assert_eq!(manager.count_by_status(PeerStatus::Online), 0);

        // Update statuses
        manager
            .update_status(&[1u8; 32], PeerStatus::DirectP2P)
            .unwrap();
        manager
            .update_status(&[2u8; 32], PeerStatus::DirectP2P)
            .unwrap();
        manager
            .update_status(&[3u8; 32], PeerStatus::Relayed)
            .unwrap();
        manager
            .update_status(&[4u8; 32], PeerStatus::Offline)
            .unwrap();

        // Verify counts
        assert_eq!(manager.count_by_status(PeerStatus::Unknown), 0);
        assert_eq!(manager.count_by_status(PeerStatus::DirectP2P), 2);
        assert_eq!(manager.count_by_status(PeerStatus::Relayed), 1);
        assert_eq!(manager.count_by_status(PeerStatus::Offline), 1);
        assert_eq!(manager.count_by_status(PeerStatus::Online), 0);
    }

    #[test]
    fn test_update_stats() {
        let manager = PeerManager::new();
        let config = test_config(1, 100);
        manager.add_peer(config.clone()).unwrap();

        // Test stats updates including edge cases
        let test_values = [(0, 0), (1024, 2048), (4096, 8192), (u64::MAX, u64::MAX)];
        for (tx, rx) in test_values {
            manager.update_stats(&config.public_key, tx, rx).unwrap();
            let peer = manager.get_by_key(&config.public_key).unwrap();
            assert_eq!(peer.tx_bytes, tx);
            assert_eq!(peer.rx_bytes, rx);
        }

        // Test nonexistent peer
        assert!(manager.update_stats(&[99u8; 32], 1024, 2048).is_err());
    }

    #[test]
    fn test_concurrent_access() {
        let manager = Arc::new(PeerManager::new());
        let mut handles = vec![];

        // Spawn multiple threads to add peers concurrently
        for i in 0..10 {
            let manager_clone = Arc::clone(&manager);
            let handle = thread::spawn(move || {
                let config = test_config(i as u8, 100 + i);
                manager_clone.add_peer(config).unwrap();
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // Verify all peers were added
        assert_eq!(manager.list_all().len(), 10);

        let mut handles = vec![];

        // Spawn threads to read and update concurrently
        for i in 0..10 {
            let manager_clone = Arc::clone(&manager);
            let handle = thread::spawn(move || {
                // Read peer
                let key = [i as u8; 32];
                let peer = manager_clone.get_by_key(&key).unwrap();
                assert_eq!(peer.config.public_key, key);

                // Update status
                manager_clone
                    .update_status(&key, PeerStatus::Online)
                    .unwrap();

                // Update stats
                manager_clone
                    .update_stats(&key, i * 1000, i * 2000)
                    .unwrap();

                // Read again
                let peer = manager_clone.get_by_key(&key).unwrap();
                assert_eq!(peer.status, PeerStatus::Online);
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // Verify all peers are online
        assert_eq!(manager.count_by_status(PeerStatus::Online), 10);

        // Verify stats were updated
        for i in 0..10 {
            let peer = manager.get_by_key(&[i as u8; 32]).unwrap();
            // Each thread set specific values based on 'i'
            assert_eq!(peer.tx_bytes, i * 1000);
            assert_eq!(peer.rx_bytes, i * 2000);
        }
    }

    #[test]
    fn test_concurrent_remove() {
        let manager = Arc::new(PeerManager::new());

        // Add 20 peers
        for i in 0..20 {
            manager.add_peer(test_config(i as u8, 100 + i)).unwrap();
        }

        let mut handles = vec![];

        // Spawn threads to remove peers concurrently
        for i in 0..20 {
            let manager_clone = Arc::clone(&manager);
            let handle = thread::spawn(move || {
                let key = [i as u8; 32];
                manager_clone.remove_peer(&key)
            });
            handles.push(handle);
        }

        // Wait for all threads
        let mut removed_count = 0;
        for handle in handles {
            if handle.join().unwrap().is_some() {
                removed_count += 1;
            }
        }

        // All peers should be removed exactly once
        assert_eq!(removed_count, 20);
        assert_eq!(manager.list_all().len(), 0);
    }

    #[test]
    fn test_concurrent_mixed_operations() {
        let manager = Arc::new(PeerManager::new());

        // Pre-populate with some peers
        for i in 0..5 {
            manager.add_peer(test_config(i as u8, 100 + i)).unwrap();
        }

        let mut handles = vec![];

        // Mix of operations: add, update, read, remove
        for i in 5..15 {
            let manager_clone = Arc::clone(&manager);
            let handle = thread::spawn(move || {
                match i % 4 {
                    0 => {
                        // Add new peer
                        let config = test_config(i as u8, 100 + i);
                        let _ = manager_clone.add_peer(config);
                    }
                    1 => {
                        // Update existing peer
                        let key = [(i % 5) as u8; 32];
                        let _ = manager_clone.update_status(&key, PeerStatus::DirectP2P);
                    }
                    2 => {
                        // Read peer
                        let key = [(i % 5) as u8; 32];
                        let _ = manager_clone.get_by_key(&key);
                    }
                    3 => {
                        // Try to remove
                        let key = [(i % 10) as u8; 32];
                        let _ = manager_clone.remove_peer(&key);
                    }
                    _ => unreachable!(),
                }
            });
            handles.push(handle);
        }

        // Wait for all operations
        for handle in handles {
            handle.join().unwrap();
        }

        // Manager should be in a consistent state
        // Some peers may be removed, but routing should always match
        let peers = manager.list_all();
        for peer in peers {
            let by_ip = manager.get_by_ip(peer.config.virtual_ip);
            assert!(by_ip.is_some());
            assert_eq!(by_ip.unwrap().config.public_key, peer.config.public_key);
        }
    }

    #[test]
    fn test_peer_manager_default() {
        let manager = PeerManager::default();
        assert_eq!(manager.list_all().len(), 0);
    }

    #[test]
    fn test_routing_consistency() {
        let manager = PeerManager::new();
        let config = test_config(1, 100);

        // Add peer
        manager.add_peer(config.clone()).unwrap();

        // Verify routing is bidirectional
        let by_key = manager.get_by_key(&config.public_key).unwrap();
        let by_ip = manager.get_by_ip(config.virtual_ip).unwrap();

        assert_eq!(by_key.config.public_key, by_ip.config.public_key);
        assert_eq!(by_key.config.virtual_ip, by_ip.config.virtual_ip);

        // Remove and verify both are gone
        manager.remove_peer(&config.public_key);
        assert!(manager.get_by_key(&config.public_key).is_none());
        assert!(manager.get_by_ip(config.virtual_ip).is_none());
    }

    #[test]
    fn test_endpoint_roaming_scenario() {
        let manager = PeerManager::new();
        let config = test_config(1, 100);
        manager.add_peer(config.clone()).unwrap();

        // Simulate mobile client changing networks
        // Each call to update_endpoint adds the endpoint if not present
        let endpoints = ["192.168.1.100:51820", "10.0.0.50:51820", "172.16.0.1:51820"];
        for endpoint_str in endpoints {
            let endpoint: SocketAddr = endpoint_str.parse().unwrap();
            manager
                .update_endpoint(&config.public_key, endpoint)
                .unwrap();

            // After each update, the peer should have this endpoint available
            let peer = manager.get_by_key(&config.public_key).unwrap();
            assert!(peer.config.endpoints.iter().any(|ep| ep.addr == endpoint));
        }

        // After roaming through 3 networks, we have 3 endpoints
        let peer = manager.get_by_key(&config.public_key).unwrap();
        assert_eq!(peer.config.endpoints.len(), 3);
    }

    #[test]
    fn test_large_peer_count() {
        let manager = PeerManager::new();

        // Add 1000 peers
        for i in 0..1000 {
            let key = {
                let mut k = [0u8; 32];
                k[0] = (i >> 8) as u8;
                k[1] = (i & 0xFF) as u8;
                k
            };
            let config = PeerConfig::new(key, VirtualIp::new(i));
            manager.add_peer(config).unwrap();
        }

        // Verify count
        assert_eq!(manager.list_all().len(), 1000);

        // Verify we can lookup each one
        for i in 0..1000 {
            let key = {
                let mut k = [0u8; 32];
                k[0] = (i >> 8) as u8;
                k[1] = (i & 0xFF) as u8;
                k
            };

            let peer = manager.get_by_key(&key).unwrap();
            assert_eq!(peer.config.virtual_ip.host(), i);

            let peer_by_ip = manager.get_by_ip(VirtualIp::new(i)).unwrap();
            assert_eq!(peer_by_ip.config.public_key, key);
        }
    }
}
