//! Chunk replication across Portal mesh peers
//!
//! Provides automatic chunk replication for fault tolerance:
//! - Configurable replication factor
//! - Peer discovery and health monitoring
//! - Background replication worker
//! - Anti-entropy repair

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use portal_core::ContentId;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::Result;
use crate::storage::HubStorage;

/// Replication configuration
#[derive(Debug, Clone)]
pub struct ReplicationConfig {
    /// Target replication factor (how many copies of each chunk)
    pub replication_factor: usize,
    /// How often to check for under-replicated chunks
    pub check_interval: Duration,
    /// Timeout for peer communication
    pub peer_timeout: Duration,
    /// Maximum concurrent replications
    pub max_concurrent: usize,
}

impl Default for ReplicationConfig {
    fn default() -> Self {
        Self {
            replication_factor: 3,
            check_interval: Duration::from_secs(60),
            peer_timeout: Duration::from_secs(10),
            max_concurrent: 10,
        }
    }
}

/// Peer information
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Peer address
    pub addr: SocketAddr,
    /// Peer ID (derived from public key)
    pub id: String,
    /// Last successful communication
    pub last_seen: chrono::DateTime<chrono::Utc>,
    /// Whether peer is currently healthy
    pub healthy: bool,
    /// Number of chunks this peer has
    pub chunk_count: usize,
}

impl PeerInfo {
    /// Create a new peer info
    #[must_use]
    pub fn new(addr: SocketAddr, id: String) -> Self {
        Self {
            addr,
            id,
            last_seen: chrono::Utc::now(),
            healthy: true,
            chunk_count: 0,
        }
    }

    /// Mark peer as seen
    pub fn mark_seen(&mut self) {
        self.last_seen = chrono::Utc::now();
        self.healthy = true;
    }

    /// Check if peer is stale (hasn't been seen recently)
    #[must_use]
    pub fn is_stale(&self, threshold: Duration) -> bool {
        let age = chrono::Utc::now() - self.last_seen;
        age > chrono::TimeDelta::from_std(threshold).unwrap_or(chrono::TimeDelta::MAX)
    }
}

/// Chunk location tracking
#[derive(Debug, Clone, Default)]
pub struct ChunkLocations {
    /// Set of peer IDs that have this chunk
    pub peers: HashSet<String>,
}

impl ChunkLocations {
    /// Add a peer that has this chunk
    pub fn add_peer(&mut self, peer_id: String) {
        self.peers.insert(peer_id);
    }

    /// Remove a peer
    pub fn remove_peer(&mut self, peer_id: &str) {
        self.peers.remove(peer_id);
    }

    /// Get replication count
    #[must_use]
    pub fn replication_count(&self) -> usize {
        self.peers.len()
    }
}

/// Replication request
#[derive(Debug, Clone)]
pub struct ReplicationRequest {
    /// Chunk to replicate
    pub content_id: ContentId,
    /// Source peer (if known)
    pub source: Option<String>,
    /// Target peer
    pub target: String,
}

/// Manages chunk replication across the mesh
///
/// # Concurrency Model
///
/// Uses a mix of `DashMap` (lock-free sharded hash map) and `RwLock`:
/// - `peers` and `locations` use `DashMap` for concurrent read/write access
/// - `pending` uses `RwLock` for ordered batch processing
///
/// Operations may see eventual consistency:
/// - Peer health and chunk location updates propagate asynchronously
/// - Replication decisions are based on point-in-time snapshots
/// - The anti-entropy repair process handles temporary inconsistencies
/// - Over-replication is preferred over under-replication for durability
pub struct ReplicationManager {
    /// Configuration
    config: ReplicationConfig,
    /// Local storage
    storage: Arc<HubStorage>,
    /// Known peers
    peers: DashMap<String, PeerInfo>,
    /// Chunk locations (which peers have which chunks)
    locations: DashMap<ContentId, ChunkLocations>,
    /// Local peer ID
    local_id: String,
    /// Pending replication requests
    pending: Arc<RwLock<Vec<ReplicationRequest>>>,
    /// Shutdown signal
    shutdown: tokio::sync::broadcast::Sender<()>,
}

impl ReplicationManager {
    /// Create a new replication manager
    #[must_use]
    pub fn new(storage: Arc<HubStorage>, config: ReplicationConfig, local_id: String) -> Self {
        let (shutdown, _) = tokio::sync::broadcast::channel(1);

        Self {
            config,
            storage,
            peers: DashMap::new(),
            locations: DashMap::new(),
            local_id,
            pending: Arc::new(RwLock::new(Vec::new())),
            shutdown,
        }
    }

    /// Register a peer
    pub fn add_peer(&self, peer_id: &str, addr: SocketAddr) {
        let peer = PeerInfo::new(addr, peer_id.to_string());
        self.peers.insert(peer_id.to_string(), peer);
        info!(peer_id, addr = %addr, "Added peer");
    }

    /// Remove a peer
    pub fn remove_peer(&self, peer_id: &str) {
        self.peers.remove(peer_id);

        // Remove peer from all chunk locations
        for mut entry in self.locations.iter_mut() {
            entry.value_mut().remove_peer(peer_id);
        }

        info!(peer_id, "Removed peer");
    }

    /// Mark peer as seen (heartbeat)
    pub fn peer_heartbeat(&self, peer_id: &str) {
        if let Some(mut peer) = self.peers.get_mut(peer_id) {
            peer.mark_seen();
        }
    }

    /// Get healthy peers
    #[must_use]
    pub fn healthy_peers(&self) -> Vec<PeerInfo> {
        self.peers
            .iter()
            .filter(|p| p.healthy && !p.is_stale(self.config.peer_timeout * 3))
            .map(|p| p.value().clone())
            .collect()
    }

    /// Record that a peer has a chunk
    pub fn record_chunk_location(&self, content_id: ContentId, peer_id: String) {
        self.locations
            .entry(content_id)
            .or_default()
            .add_peer(peer_id);
    }

    /// Record that we have a chunk locally
    pub fn record_local_chunk(&self, content_id: ContentId) {
        self.record_chunk_location(content_id, self.local_id.clone());
    }

    /// Get chunks that are under-replicated
    #[must_use]
    pub fn under_replicated_chunks(&self) -> Vec<(ContentId, usize)> {
        self.locations
            .iter()
            .filter_map(|entry| {
                let count = entry.value().replication_count();
                if count < self.config.replication_factor {
                    Some((*entry.key(), count))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Get chunks that are over-replicated (for cleanup)
    #[must_use]
    pub fn over_replicated_chunks(&self) -> Vec<(ContentId, usize)> {
        self.locations
            .iter()
            .filter_map(|entry| {
                let count = entry.value().replication_count();
                if count > self.config.replication_factor + 1 {
                    Some((*entry.key(), count))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Schedule replication for a chunk
    pub async fn schedule_replication(&self, content_id: ContentId, target: String) {
        let request = ReplicationRequest {
            content_id,
            source: Some(self.local_id.clone()),
            target,
        };

        let mut pending = self.pending.write().await;
        pending.push(request);
    }

    /// Process pending replications
    pub async fn process_pending(&self) -> usize {
        let mut pending = self.pending.write().await;
        let count = pending.len().min(self.config.max_concurrent);

        if count == 0 {
            return 0;
        }

        let to_process: Vec<_> = pending.drain(..count).collect();
        drop(pending); // Release lock

        let mut completed = 0;
        for request in to_process {
            if self.replicate_chunk(&request).is_ok() {
                completed += 1;
            }
        }

        completed
    }

    /// Replicate a chunk to a peer
    fn replicate_chunk(&self, request: &ReplicationRequest) -> Result<()> {
        // Get the chunk data from local storage
        let data = self.storage.get_chunk(&request.content_id)?;

        // Get target peer address
        let peer = self
            .peers
            .get(&request.target)
            .ok_or_else(|| crate::Error::EdgeNotFound(uuid::Uuid::nil()))?;

        // In a real implementation, this would send the chunk to the peer
        // via HTTP or a custom protocol
        debug!(
            chunk = hex::encode(request.content_id),
            target = %peer.addr,
            size = data.len(),
            "Would replicate chunk to peer"
        );

        // Record the location
        self.record_chunk_location(request.content_id, request.target.clone());

        Ok(())
    }

    /// Run anti-entropy repair
    ///
    /// Compares chunk inventories with peers and repairs any differences
    pub async fn anti_entropy_repair(&self) -> usize {
        let under_replicated = self.under_replicated_chunks();
        let healthy_peers = self.healthy_peers();

        if under_replicated.is_empty() || healthy_peers.is_empty() {
            return 0;
        }

        let mut scheduled = 0;

        for (content_id, current_count) in under_replicated {
            let needed = self.config.replication_factor - current_count;

            // Get peers that don't have this chunk
            let existing_peers: HashSet<_> = self
                .locations
                .get(&content_id)
                .as_ref()
                .map(|l| l.peers.clone())
                .unwrap_or_default();

            let available_peers: Vec<_> = healthy_peers
                .iter()
                .filter(|p| !existing_peers.contains(&p.id))
                .take(needed)
                .collect();

            for peer in available_peers {
                self.schedule_replication(content_id, peer.id.clone()).await;
                scheduled += 1;
            }
        }

        if scheduled > 0 {
            info!(scheduled, "Scheduled anti-entropy repairs");
        }

        scheduled
    }

    /// Start the background replication worker
    #[must_use]
    pub fn start_worker(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let manager = self.clone();
        let mut shutdown = self.shutdown.subscribe();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(manager.config.check_interval);

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        // Check peer health
                        manager.check_peer_health();

                        // Process pending replications
                        let processed = manager.process_pending().await;
                        if processed > 0 {
                            debug!(processed, "Processed replication requests");
                        }

                        // Run anti-entropy repair
                        let repairs = manager.anti_entropy_repair().await;
                        if repairs > 0 {
                            debug!(repairs, "Scheduled anti-entropy repairs");
                        }
                    }
                    _ = shutdown.recv() => {
                        info!("Replication worker shutting down");
                        break;
                    }
                }
            }
        })
    }

    /// Check peer health and mark stale peers
    fn check_peer_health(&self) {
        let stale_threshold = self.config.peer_timeout * 3;

        for mut peer in self.peers.iter_mut() {
            if peer.is_stale(stale_threshold) && peer.healthy {
                peer.healthy = false;
                warn!(peer_id = %peer.id, "Peer marked unhealthy (stale)");
            }
        }
    }

    /// Shutdown the replication manager
    pub fn shutdown(&self) {
        let _ = self.shutdown.send(());
    }

    /// Get replication statistics
    #[must_use]
    pub fn stats(&self) -> ReplicationStats {
        let under_replicated = self.under_replicated_chunks().len();
        let over_replicated = self.over_replicated_chunks().len();
        let total_chunks = self.locations.len();
        let healthy_peers = self.healthy_peers().len();
        let total_peers = self.peers.len();

        ReplicationStats {
            total_chunks,
            under_replicated,
            over_replicated,
            healthy_peers,
            total_peers,
            replication_factor: self.config.replication_factor,
        }
    }
}

/// Replication statistics
#[derive(Debug, Clone)]
pub struct ReplicationStats {
    /// Total chunks tracked
    pub total_chunks: usize,
    /// Chunks below replication factor
    pub under_replicated: usize,
    /// Chunks above replication factor
    pub over_replicated: usize,
    /// Number of healthy peers
    pub healthy_peers: usize,
    /// Total number of peers
    pub total_peers: usize,
    /// Target replication factor
    pub replication_factor: usize,
}

impl ReplicationStats {
    /// Check if replication is healthy
    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        self.under_replicated == 0 && self.healthy_peers >= self.replication_factor
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_manager() -> Arc<ReplicationManager> {
        let storage = Arc::new(HubStorage::new());
        let config = ReplicationConfig {
            replication_factor: 2,
            check_interval: Duration::from_secs(1),
            peer_timeout: Duration::from_secs(5),
            max_concurrent: 5,
        };

        Arc::new(ReplicationManager::new(
            storage,
            config,
            "local".to_string(),
        ))
    }

    #[test]
    fn test_add_remove_peer() {
        let manager = create_test_manager();

        manager.add_peer("peer1", "127.0.0.1:8080".parse().unwrap());
        assert_eq!(manager.peers.len(), 1);

        manager.add_peer("peer2", "127.0.0.1:8081".parse().unwrap());
        assert_eq!(manager.peers.len(), 2);

        manager.remove_peer("peer1");
        assert_eq!(manager.peers.len(), 1);
    }

    #[test]
    fn test_chunk_locations() {
        let manager = create_test_manager();
        let content_id = [1u8; 32];

        manager.record_local_chunk(content_id);
        assert_eq!(
            manager
                .locations
                .get(&content_id)
                .unwrap()
                .replication_count(),
            1
        );

        manager.record_chunk_location(content_id, "peer1".to_string());
        assert_eq!(
            manager
                .locations
                .get(&content_id)
                .unwrap()
                .replication_count(),
            2
        );
    }

    #[test]
    fn test_under_replicated_detection() {
        let manager = create_test_manager();

        // With replication_factor = 2, a chunk with 1 copy is under-replicated
        let content_id = [2u8; 32];
        manager.record_local_chunk(content_id);

        let under = manager.under_replicated_chunks();
        assert_eq!(under.len(), 1);
        assert_eq!(under[0].0, content_id);
        assert_eq!(under[0].1, 1); // current count

        // Add another replica
        manager.record_chunk_location(content_id, "peer1".to_string());

        // Now it should be properly replicated
        let under = manager.under_replicated_chunks();
        assert_eq!(under.len(), 0);
    }

    #[test]
    fn test_healthy_peers() {
        let manager = create_test_manager();

        manager.add_peer("peer1", "127.0.0.1:8080".parse().unwrap());
        manager.add_peer("peer2", "127.0.0.1:8081".parse().unwrap());

        let healthy = manager.healthy_peers();
        assert_eq!(healthy.len(), 2);
    }

    #[test]
    fn test_replication_stats() {
        let manager = create_test_manager();

        // Add peers
        manager.add_peer("peer1", "127.0.0.1:8080".parse().unwrap());

        // Add chunks
        let chunk1 = [1u8; 32];
        let chunk2 = [2u8; 32];

        manager.record_local_chunk(chunk1);
        manager.record_local_chunk(chunk2);
        manager.record_chunk_location(chunk1, "peer1".to_string());

        let stats = manager.stats();
        assert_eq!(stats.total_chunks, 2);
        assert_eq!(stats.total_peers, 1);
        assert_eq!(stats.under_replicated, 1); // chunk2 only has 1 replica
    }

    #[test]
    fn test_peer_heartbeat() {
        let manager = create_test_manager();

        manager.add_peer("peer1", "127.0.0.1:8080".parse().unwrap());

        let initial_time = manager.peers.get("peer1").unwrap().last_seen;

        std::thread::sleep(std::time::Duration::from_millis(10));
        manager.peer_heartbeat("peer1");

        let new_time = manager.peers.get("peer1").unwrap().last_seen;
        assert!(new_time > initial_time);
    }

    #[tokio::test]
    async fn test_schedule_replication() {
        let manager = create_test_manager();
        let content_id = [3u8; 32];

        manager
            .schedule_replication(content_id, "peer1".to_string())
            .await;

        let pending = manager.pending.read().await;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].content_id, content_id);
        assert_eq!(pending[0].target, "peer1");
    }
}
