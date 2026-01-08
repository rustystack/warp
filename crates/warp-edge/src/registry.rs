//! Edge registry with concurrent access
//!
//! Provides thread-safe storage and management of edge nodes in the distributed
//! storage network. The registry maintains bidirectional lookups (by `EdgeId` and
//! `VirtualIp`) and supports concurrent access through `DashMap`.

use crate::types::{EdgeId, EdgeInfo, EdgeState, EdgeStatus};
use crate::{EdgeError, Result};
use dashmap::DashMap;
use portal_net::VirtualIp;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// Immutable snapshot of the edge registry at a point in time
#[derive(Debug, Clone)]
pub struct EdgeSnapshot {
    /// All edges at snapshot time
    pub edges: Vec<EdgeInfo>,
    /// Snapshot timestamp
    pub timestamp: SystemTime,
    /// Total storage capacity across all edges (bytes)
    pub total_storage_capacity: u64,
    /// Total storage used across all edges (bytes)
    pub total_storage_used: u64,
}

impl EdgeSnapshot {
    /// Returns the number of edges in the snapshot
    #[must_use]
    pub fn count(&self) -> usize {
        self.edges.len()
    }

    /// Returns the number of online edges
    #[must_use]
    pub fn count_online(&self) -> usize {
        self.edges
            .iter()
            .filter(|e| e.state.status == EdgeStatus::Online)
            .count()
    }

    /// Returns total available storage across all edges
    #[must_use]
    pub const fn total_available_storage(&self) -> u64 {
        self.total_storage_capacity
            .saturating_sub(self.total_storage_used)
    }

    /// Returns average storage utilization (0.0 to 1.0)
    #[must_use]
    pub fn average_utilization(&self) -> f64 {
        if self.total_storage_capacity == 0 {
            return 0.0;
        }
        self.total_storage_used as f64 / self.total_storage_capacity as f64
    }
}

/// Thread-safe edge registry
///
/// Maintains a registry of all known edge nodes with efficient lookups by
/// `EdgeId` and `VirtualIp`. All operations are thread-safe and lock-free.
#[derive(Debug, Clone)]
pub struct EdgeRegistry {
    /// Primary storage: `EdgeId` -> `EdgeInfo`
    edges: Arc<DashMap<EdgeId, EdgeInfo>>,
    /// Reverse lookup: `VirtualIp` -> `EdgeId`
    by_ip: Arc<DashMap<VirtualIp, EdgeId>>,
}

impl EdgeRegistry {
    /// Creates a new empty edge registry
    #[must_use]
    pub fn new() -> Self {
        Self {
            edges: Arc::new(DashMap::new()),
            by_ip: Arc::new(DashMap::new()),
        }
    }

    /// Registers a new edge in the registry
    ///
    /// Returns an error if an edge with the same ID or `VirtualIp` already exists.
    pub fn register(&self, edge: EdgeInfo) -> Result<()> {
        // Check for duplicate EdgeId
        if self.edges.contains_key(&edge.id) {
            return Err(EdgeError::EdgeNotFound(format!(
                "edge {} already registered",
                edge.id
            )));
        }

        // Check for duplicate VirtualIp
        if self.by_ip.contains_key(&edge.virtual_ip) {
            return Err(EdgeError::InvalidVirtualIp(format!(
                "virtual IP {} already in use",
                edge.virtual_ip
            )));
        }

        // Insert into both maps
        let edge_id = edge.id;
        let virtual_ip = edge.virtual_ip;

        self.edges.insert(edge_id, edge);
        self.by_ip.insert(virtual_ip, edge_id);

        Ok(())
    }

    /// Unregisters an edge from the registry
    ///
    /// Returns the `EdgeInfo` if found, None otherwise.
    #[must_use]
    pub fn unregister(&self, edge_id: &EdgeId) -> Option<EdgeInfo> {
        if let Some((_, edge)) = self.edges.remove(edge_id) {
            // Remove from IP lookup
            self.by_ip.remove(&edge.virtual_ip);
            Some(edge)
        } else {
            None
        }
    }

    /// Gets an edge by ID
    #[must_use]
    pub fn get(&self, edge_id: &EdgeId) -> Option<EdgeInfo> {
        self.edges.get(edge_id).map(|r| r.value().clone())
    }

    /// Gets an edge by virtual IP
    #[must_use]
    pub fn get_by_ip(&self, vip: VirtualIp) -> Option<EdgeInfo> {
        self.by_ip
            .get(&vip)
            .and_then(|edge_id| self.edges.get(edge_id.value()).map(|r| r.value().clone()))
    }

    /// Checks if an edge is registered
    #[must_use]
    pub fn contains(&self, edge_id: &EdgeId) -> bool {
        self.edges.contains_key(edge_id)
    }

    /// Updates the state of an edge
    pub fn update_state(&self, edge_id: &EdgeId, state: EdgeState) -> Result<()> {
        self.edges
            .get_mut(edge_id)
            .map(|mut edge| {
                edge.state = state;
            })
            .ok_or_else(|| EdgeError::EdgeNotFound(format!("edge {edge_id} not found")))
    }

    /// Updates the `last_seen` timestamp for an edge
    pub fn update_last_seen(&self, edge_id: &EdgeId) -> Result<()> {
        self.edges
            .get_mut(edge_id)
            .map(|mut edge| {
                edge.state.last_seen = SystemTime::now();
            })
            .ok_or_else(|| EdgeError::EdgeNotFound(format!("edge {edge_id} not found")))
    }

    /// Marks an edge as offline
    pub fn mark_offline(&self, edge_id: &EdgeId) -> Result<()> {
        self.edges
            .get_mut(edge_id)
            .map(|mut edge| {
                edge.state.status = EdgeStatus::Offline;
            })
            .ok_or_else(|| EdgeError::EdgeNotFound(format!("edge {edge_id} not found")))
    }

    /// Marks an edge as online
    pub fn mark_online(&self, edge_id: &EdgeId) -> Result<()> {
        self.edges
            .get_mut(edge_id)
            .map(|mut edge| {
                edge.state.status = EdgeStatus::Online;
                edge.state.last_seen = SystemTime::now();
            })
            .ok_or_else(|| EdgeError::EdgeNotFound(format!("edge {edge_id} not found")))
    }

    /// Lists all edges
    #[must_use]
    pub fn list_all(&self) -> Vec<EdgeInfo> {
        self.edges.iter().map(|r| r.value().clone()).collect()
    }

    /// Lists edges with a specific status
    #[must_use]
    pub fn list_by_status(&self, status: EdgeStatus) -> Vec<EdgeInfo> {
        self.edges
            .iter()
            .filter(|r| r.value().state.status == status)
            .map(|r| r.value().clone())
            .collect()
    }

    /// Lists all online edges
    #[must_use]
    pub fn list_online(&self) -> Vec<EdgeInfo> {
        self.list_by_status(EdgeStatus::Online)
    }

    /// Returns the total number of registered edges
    #[must_use]
    pub fn count(&self) -> usize {
        self.edges.len()
    }

    /// Returns the number of online edges
    #[must_use]
    pub fn count_online(&self) -> usize {
        self.edges
            .iter()
            .filter(|r| r.value().state.status == EdgeStatus::Online)
            .count()
    }

    /// Prunes stale edges (not seen within timeout)
    ///
    /// Returns the list of `EdgeIds` that were pruned.
    #[must_use]
    pub fn prune_stale(&self, timeout: Duration) -> Vec<EdgeId> {
        let now = SystemTime::now();
        let mut pruned = Vec::new();

        // Collect stale edge IDs first to avoid holding locks
        let stale_ids: Vec<EdgeId> = self
            .edges
            .iter()
            .filter_map(|r| {
                let edge = r.value();
                if let Ok(elapsed) = now.duration_since(edge.state.last_seen) {
                    if elapsed > timeout {
                        return Some(edge.id);
                    }
                }
                None
            })
            .collect();

        // Remove stale edges
        for edge_id in stale_ids {
            if let Some(edge) = self.unregister(&edge_id) {
                pruned.push(edge.id);
            }
        }

        pruned
    }

    /// Creates an immutable snapshot of the current registry state
    #[must_use]
    pub fn snapshot(&self) -> EdgeSnapshot {
        let edges: Vec<EdgeInfo> = self.list_all();

        let (total_capacity, total_used) = edges.iter().fold((0u64, 0u64), |(cap, used), edge| {
            (
                cap.saturating_add(edge.capabilities.max_storage),
                used.saturating_add(edge.capabilities.used_storage),
            )
        });

        EdgeSnapshot {
            edges,
            timestamp: SystemTime::now(),
            total_storage_capacity: total_capacity,
            total_storage_used: total_used,
        }
    }
}

impl Default for EdgeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::EdgeCapabilities;
    use std::thread;

    fn create_test_edge(id_byte: u8, vip_host: u16) -> EdgeInfo {
        EdgeInfo::new(
            EdgeId::new([id_byte; 32]),
            VirtualIp::new(vip_host),
            EdgeCapabilities::default(),
            EdgeState::new(EdgeStatus::Online),
        )
    }

    #[test]
    fn test_registry_new() {
        let registry = EdgeRegistry::new();
        assert_eq!(registry.count(), 0);
        assert_eq!(registry.count_online(), 0);
    }

    #[test]
    fn test_registry_default() {
        let registry = EdgeRegistry::default();
        assert_eq!(registry.count(), 0);
    }

    #[test]
    fn test_register_edge() {
        let registry = EdgeRegistry::new();
        let edge = create_test_edge(1, 100);

        let result = registry.register(edge.clone());
        assert!(result.is_ok());
        assert_eq!(registry.count(), 1);

        let retrieved = registry.get(&edge.id);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, edge.id);
    }

    #[test]
    fn test_register_duplicate_edge_id() {
        let registry = EdgeRegistry::new();
        let edge1 = create_test_edge(1, 100);
        let edge2 = create_test_edge(1, 101);

        assert!(registry.register(edge1).is_ok());
        let result = registry.register(edge2);
        assert!(result.is_err());
        assert_eq!(registry.count(), 1);
    }

    #[test]
    fn test_register_duplicate_virtual_ip() {
        let registry = EdgeRegistry::new();
        let edge1 = create_test_edge(1, 100);
        let edge2 = create_test_edge(2, 100);

        assert!(registry.register(edge1).is_ok());
        let result = registry.register(edge2);
        assert!(result.is_err());
        assert_eq!(registry.count(), 1);
    }

    #[test]
    fn test_unregister_edge() {
        let registry = EdgeRegistry::new();
        let edge = create_test_edge(1, 100);
        let edge_id = edge.id;

        assert!(registry.register(edge).is_ok());
        assert_eq!(registry.count(), 1);

        let removed = registry.unregister(&edge_id);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().id, edge_id);
        assert_eq!(registry.count(), 0);
    }

    #[test]
    fn test_unregister_nonexistent_edge() {
        let registry = EdgeRegistry::new();
        let edge_id = EdgeId::new([99; 32]);

        let removed = registry.unregister(&edge_id);
        assert!(removed.is_none());
    }

    #[test]
    fn test_get_edge() {
        let registry = EdgeRegistry::new();
        let edge = create_test_edge(1, 100);
        let edge_id = edge.id;

        assert!(registry.register(edge).is_ok());

        let retrieved = registry.get(&edge_id);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, edge_id);
    }

    #[test]
    fn test_get_nonexistent_edge() {
        let registry = EdgeRegistry::new();
        let edge_id = EdgeId::new([99; 32]);

        let retrieved = registry.get(&edge_id);
        assert!(retrieved.is_none());
    }

    #[test]
    fn test_get_by_ip() {
        let registry = EdgeRegistry::new();
        let edge = create_test_edge(1, 100);
        let vip = edge.virtual_ip;

        assert!(registry.register(edge.clone()).is_ok());

        let retrieved = registry.get_by_ip(vip);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, edge.id);
    }

    #[test]
    fn test_get_by_ip_nonexistent() {
        let registry = EdgeRegistry::new();
        let vip = VirtualIp::new(999);

        let retrieved = registry.get_by_ip(vip);
        assert!(retrieved.is_none());
    }

    #[test]
    fn test_contains() {
        let registry = EdgeRegistry::new();
        let edge = create_test_edge(1, 100);
        let edge_id = edge.id;

        assert!(!registry.contains(&edge_id));
        assert!(registry.register(edge).is_ok());
        assert!(registry.contains(&edge_id));
    }

    #[test]
    fn test_update_state() {
        let registry = EdgeRegistry::new();
        let edge = create_test_edge(1, 100);
        let edge_id = edge.id;

        assert!(registry.register(edge).is_ok());

        let mut new_state = EdgeState::new(EdgeStatus::Online);
        new_state.status = EdgeStatus::Degraded;
        new_state.chunk_count = 42;

        let result = registry.update_state(&edge_id, new_state.clone());
        assert!(result.is_ok());

        let retrieved = registry.get(&edge_id).unwrap();
        assert_eq!(retrieved.state.status, EdgeStatus::Degraded);
        assert_eq!(retrieved.state.chunk_count, 42);
    }

    #[test]
    fn test_update_state_nonexistent() {
        let registry = EdgeRegistry::new();
        let edge_id = EdgeId::new([99; 32]);
        let state = EdgeState::new(EdgeStatus::Online);

        let result = registry.update_state(&edge_id, state);
        assert!(result.is_err());
    }

    #[test]
    fn test_update_last_seen() {
        let registry = EdgeRegistry::new();
        let edge = create_test_edge(1, 100);
        let edge_id = edge.id;

        assert!(registry.register(edge).is_ok());

        let old_time = registry.get(&edge_id).unwrap().state.last_seen;
        thread::sleep(Duration::from_millis(10));

        let result = registry.update_last_seen(&edge_id);
        assert!(result.is_ok());

        let new_time = registry.get(&edge_id).unwrap().state.last_seen;
        assert!(new_time > old_time);
    }

    #[test]
    fn test_update_last_seen_nonexistent() {
        let registry = EdgeRegistry::new();
        let edge_id = EdgeId::new([99; 32]);

        let result = registry.update_last_seen(&edge_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_mark_offline() {
        let registry = EdgeRegistry::new();
        let edge = create_test_edge(1, 100);
        let edge_id = edge.id;

        assert!(registry.register(edge).is_ok());
        assert_eq!(
            registry.get(&edge_id).unwrap().state.status,
            EdgeStatus::Online
        );

        let result = registry.mark_offline(&edge_id);
        assert!(result.is_ok());
        assert_eq!(
            registry.get(&edge_id).unwrap().state.status,
            EdgeStatus::Offline
        );
    }

    #[test]
    fn test_mark_offline_nonexistent() {
        let registry = EdgeRegistry::new();
        let edge_id = EdgeId::new([99; 32]);

        let result = registry.mark_offline(&edge_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_mark_online() {
        let registry = EdgeRegistry::new();
        let mut edge = create_test_edge(1, 100);
        edge.state.status = EdgeStatus::Offline;
        let edge_id = edge.id;

        assert!(registry.register(edge).is_ok());
        assert_eq!(
            registry.get(&edge_id).unwrap().state.status,
            EdgeStatus::Offline
        );

        let result = registry.mark_online(&edge_id);
        assert!(result.is_ok());
        assert_eq!(
            registry.get(&edge_id).unwrap().state.status,
            EdgeStatus::Online
        );
    }

    #[test]
    fn test_mark_online_nonexistent() {
        let registry = EdgeRegistry::new();
        let edge_id = EdgeId::new([99; 32]);

        let result = registry.mark_online(&edge_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_list_all() {
        let registry = EdgeRegistry::new();

        assert_eq!(registry.list_all().len(), 0);

        for i in 1..=5 {
            assert!(
                registry
                    .register(create_test_edge(i, 100 + i as u16))
                    .is_ok()
            );
        }

        let all = registry.list_all();
        assert_eq!(all.len(), 5);
    }

    #[test]
    fn test_list_by_status() {
        let registry = EdgeRegistry::new();

        // Register 3 online edges
        for i in 1..=3 {
            assert!(
                registry
                    .register(create_test_edge(i, 100 + i as u16))
                    .is_ok()
            );
        }

        // Register 2 offline edges
        for i in 4..=5 {
            let mut edge = create_test_edge(i, 100 + i as u16);
            edge.state.status = EdgeStatus::Offline;
            assert!(registry.register(edge).is_ok());
        }

        let online = registry.list_by_status(EdgeStatus::Online);
        assert_eq!(online.len(), 3);

        let offline = registry.list_by_status(EdgeStatus::Offline);
        assert_eq!(offline.len(), 2);
    }

    #[test]
    fn test_list_online() {
        let registry = EdgeRegistry::new();

        for i in 1..=3 {
            assert!(
                registry
                    .register(create_test_edge(i, 100 + i as u16))
                    .is_ok()
            );
        }

        for i in 4..=5 {
            let mut edge = create_test_edge(i, 100 + i as u16);
            edge.state.status = EdgeStatus::Offline;
            assert!(registry.register(edge).is_ok());
        }

        let online = registry.list_online();
        assert_eq!(online.len(), 3);
    }

    #[test]
    fn test_count() {
        let registry = EdgeRegistry::new();
        assert_eq!(registry.count(), 0);

        for i in 1..=10 {
            assert!(
                registry
                    .register(create_test_edge(i, 100 + i as u16))
                    .is_ok()
            );
        }

        assert_eq!(registry.count(), 10);
    }

    #[test]
    fn test_count_online() {
        let registry = EdgeRegistry::new();

        for i in 1..=7 {
            assert!(
                registry
                    .register(create_test_edge(i, 100 + i as u16))
                    .is_ok()
            );
        }

        for i in 8..=10 {
            let mut edge = create_test_edge(i, 100 + i as u16);
            edge.state.status = EdgeStatus::Offline;
            assert!(registry.register(edge).is_ok());
        }

        assert_eq!(registry.count_online(), 7);
    }

    #[test]
    fn test_prune_stale() {
        let registry = EdgeRegistry::new();

        // Add fresh edges
        for i in 1..=3 {
            assert!(
                registry
                    .register(create_test_edge(i, 100 + i as u16))
                    .is_ok()
            );
        }

        // Add stale edges
        for i in 4..=6 {
            let mut edge = create_test_edge(i, 100 + i as u16);
            edge.state.last_seen = SystemTime::now()
                .checked_sub(Duration::from_secs(120))
                .unwrap();
            assert!(registry.register(edge).is_ok());
        }

        assert_eq!(registry.count(), 6);

        let pruned = registry.prune_stale(Duration::from_secs(60));
        assert_eq!(pruned.len(), 3);
        assert_eq!(registry.count(), 3);
    }

    #[test]
    fn test_prune_stale_empty() {
        let registry = EdgeRegistry::new();

        for i in 1..=3 {
            assert!(
                registry
                    .register(create_test_edge(i, 100 + i as u16))
                    .is_ok()
            );
        }

        let pruned = registry.prune_stale(Duration::from_secs(60));
        assert_eq!(pruned.len(), 0);
        assert_eq!(registry.count(), 3);
    }

    #[test]
    fn test_snapshot() {
        let registry = EdgeRegistry::new();

        for i in 1..=5 {
            assert!(
                registry
                    .register(create_test_edge(i, 100 + i as u16))
                    .is_ok()
            );
        }

        let snapshot = registry.snapshot();
        assert_eq!(snapshot.count(), 5);
        assert_eq!(snapshot.count_online(), 5);
        assert!(snapshot.total_storage_capacity > 0);
    }

    #[test]
    fn test_snapshot_empty() {
        let registry = EdgeRegistry::new();
        let snapshot = registry.snapshot();

        assert_eq!(snapshot.count(), 0);
        assert_eq!(snapshot.count_online(), 0);
        assert_eq!(snapshot.total_storage_capacity, 0);
        assert_eq!(snapshot.total_storage_used, 0);
    }

    #[test]
    fn test_snapshot_storage_calculations() {
        let registry = EdgeRegistry::new();

        for i in 1..=3 {
            let mut edge = create_test_edge(i, 100 + i as u16);
            edge.capabilities.used_storage = 20 * 1024 * 1024 * 1024; // 20 GB used
            assert!(registry.register(edge).is_ok());
        }

        let snapshot = registry.snapshot();
        let expected_capacity = 3 * EdgeCapabilities::default().max_storage;
        assert_eq!(snapshot.total_storage_capacity, expected_capacity);
        assert_eq!(snapshot.total_storage_used, 3 * 20 * 1024 * 1024 * 1024);

        let expected_available = expected_capacity.saturating_sub(3 * 20 * 1024 * 1024 * 1024);
        assert_eq!(snapshot.total_available_storage(), expected_available);
    }

    #[test]
    fn test_snapshot_utilization_empty() {
        let registry = EdgeRegistry::new();
        let snapshot = registry.snapshot();
        assert_eq!(snapshot.average_utilization(), 0.0);
    }

    #[test]
    fn test_concurrent_register() {
        let registry = EdgeRegistry::new();
        let registry_clone = registry.clone();

        let handle = thread::spawn(move || {
            for i in 1..=50 {
                let edge = create_test_edge(i, 100 + i as u16);
                let _ = registry_clone.register(edge);
            }
        });

        for i in 51..=100 {
            let edge = create_test_edge(i, 100 + i as u16);
            let _ = registry.register(edge);
        }

        handle.join().unwrap();
        assert_eq!(registry.count(), 100);
    }

    #[test]
    fn test_concurrent_read_write() {
        let registry = EdgeRegistry::new();

        // Pre-populate
        for i in 1..=10 {
            assert!(
                registry
                    .register(create_test_edge(i, 100 + i as u16))
                    .is_ok()
            );
        }

        let registry_read = registry.clone();
        let registry_write = registry.clone();

        let reader = thread::spawn(move || {
            for _ in 0..100 {
                let _ = registry_read.list_all();
                let _ = registry_read.count();
            }
        });

        let writer = thread::spawn(move || {
            for i in 1..=10 {
                let edge_id = EdgeId::new([i; 32]);
                let _ = registry_write.update_last_seen(&edge_id);
            }
        });

        reader.join().unwrap();
        writer.join().unwrap();
    }

    #[test]
    fn test_concurrent_unregister() {
        let registry = EdgeRegistry::new();

        for i in 1..=100 {
            assert!(
                registry
                    .register(create_test_edge(i, 100 + i as u16))
                    .is_ok()
            );
        }

        let registry_clone = registry.clone();

        let handle = thread::spawn(move || {
            for i in 1..=50 {
                let edge_id = EdgeId::new([i; 32]);
                let _ = registry_clone.unregister(&edge_id);
            }
        });

        for i in 51..=100 {
            let edge_id = EdgeId::new([i; 32]);
            let _ = registry.unregister(&edge_id);
        }

        handle.join().unwrap();
        assert_eq!(registry.count(), 0);
    }

    #[test]
    fn test_unregister_removes_ip_lookup() {
        let registry = EdgeRegistry::new();
        let edge = create_test_edge(1, 100);
        let edge_id = edge.id;
        let vip = edge.virtual_ip;

        assert!(registry.register(edge).is_ok());
        assert!(registry.get_by_ip(vip).is_some());

        registry.unregister(&edge_id);
        assert!(registry.get_by_ip(vip).is_none());
    }

    #[test]
    fn test_multiple_status_types() {
        let registry = EdgeRegistry::new();

        let mut edge1 = create_test_edge(1, 100);
        edge1.state.status = EdgeStatus::Online;
        assert!(registry.register(edge1).is_ok());

        let mut edge2 = create_test_edge(2, 101);
        edge2.state.status = EdgeStatus::Offline;
        assert!(registry.register(edge2).is_ok());

        let mut edge3 = create_test_edge(3, 102);
        edge3.state.status = EdgeStatus::Degraded;
        assert!(registry.register(edge3).is_ok());

        let mut edge4 = create_test_edge(4, 103);
        edge4.state.status = EdgeStatus::Throttled;
        assert!(registry.register(edge4).is_ok());

        assert_eq!(registry.list_by_status(EdgeStatus::Online).len(), 1);
        assert_eq!(registry.list_by_status(EdgeStatus::Offline).len(), 1);
        assert_eq!(registry.list_by_status(EdgeStatus::Degraded).len(), 1);
        assert_eq!(registry.list_by_status(EdgeStatus::Throttled).len(), 1);
    }
}
