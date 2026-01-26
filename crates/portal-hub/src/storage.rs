//! In-memory storage for Portal Hub
//!
//! This module provides thread-safe in-memory storage for portals, chunks, manifests,
//! and edge registrations. Uses `DashMap` for concurrent access without locks.
//!
//! # Storage Layout
//!
//! - Portals: Metadata and ACLs indexed by `PortalId`
//! - Chunks: Encrypted content indexed by `ContentId` (BLAKE3 hash)
//! - Manifests: Encrypted manifests indexed by `PortalId`
//! - Edges: Registered edge devices indexed by edge UUID
//!
//! # Thread Safety
//!
//! All storage operations are thread-safe and lock-free using `DashMap`.

use crate::{Error, Result};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use ed25519_dalek::VerifyingKey;
use portal_core::{AccessControlList, ContentId, Portal, PortalId};
use uuid::Uuid;

/// Stored portal with metadata
#[derive(Debug, Clone)]
pub struct StoredPortal {
    /// The portal instance
    pub portal: Portal,
    /// Access control list
    pub acl: AccessControlList,
    /// Owner's public key
    pub owner_key: VerifyingKey,
}

impl StoredPortal {
    /// Create a new stored portal
    #[must_use]
    pub const fn new(portal: Portal, acl: AccessControlList, owner_key: VerifyingKey) -> Self {
        Self {
            portal,
            acl,
            owner_key,
        }
    }
}

/// Registered edge information
#[derive(Debug, Clone)]
pub struct EdgeInfo {
    /// Unique edge identifier
    pub id: Uuid,
    /// Edge's public key for authentication
    pub public_key: VerifyingKey,
    /// Human-readable edge name
    pub name: String,
    /// Last seen timestamp
    pub last_seen: DateTime<Utc>,
}

impl EdgeInfo {
    /// Create a new edge info
    #[must_use]
    pub fn new(id: Uuid, public_key: VerifyingKey, name: String) -> Self {
        Self {
            id,
            public_key,
            name,
            last_seen: Utc::now(),
        }
    }

    /// Update last seen timestamp
    pub fn update_last_seen(&mut self) {
        self.last_seen = Utc::now();
    }
}

/// In-memory Hub storage
///
/// Thread-safe storage using `DashMap` for concurrent access.
/// All operations are atomic and lock-free.
pub struct HubStorage {
    /// Portal metadata indexed by `PortalId`
    portals: DashMap<PortalId, StoredPortal>,
    /// Encrypted chunks indexed by `ContentId`
    chunks: DashMap<ContentId, Vec<u8>>,
    /// Encrypted manifests indexed by `PortalId`
    manifests: DashMap<PortalId, Vec<u8>>,
    /// Edge registrations indexed by edge UUID
    edges: DashMap<Uuid, EdgeInfo>,
}

impl HubStorage {
    /// Create a new empty storage instance
    #[must_use]
    pub fn new() -> Self {
        Self {
            portals: DashMap::new(),
            chunks: DashMap::new(),
            manifests: DashMap::new(),
            edges: DashMap::new(),
        }
    }

    // ========== Edge Operations ==========

    /// Register a new edge device
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidEdgeName` if the name is empty
    pub fn register_edge(
        &self,
        edge_id: Uuid,
        public_key: VerifyingKey,
        name: String,
    ) -> Result<EdgeInfo> {
        if name.trim().is_empty() {
            return Err(Error::InvalidEdgeName("Edge name cannot be empty".into()));
        }

        let edge_info = EdgeInfo::new(edge_id, public_key, name);
        self.edges.insert(edge_id, edge_info.clone());
        Ok(edge_info)
    }

    /// Get edge information by ID
    ///
    /// # Errors
    ///
    /// Returns `Error::EdgeNotFound` if the edge doesn't exist
    pub fn get_edge(&self, edge_id: &Uuid) -> Result<EdgeInfo> {
        self.edges
            .get(edge_id)
            .map(|e| e.value().clone())
            .ok_or(Error::EdgeNotFound(*edge_id))
    }

    /// Update edge last seen timestamp
    ///
    /// # Errors
    ///
    /// Returns `Error::EdgeNotFound` if the edge doesn't exist
    pub fn update_edge_last_seen(&self, edge_id: &Uuid) -> Result<()> {
        self.edges
            .get_mut(edge_id)
            .map(|mut e| e.value_mut().update_last_seen())
            .ok_or(Error::EdgeNotFound(*edge_id))
    }

    /// List all registered edges
    #[must_use]
    pub fn list_edges(&self) -> Vec<EdgeInfo> {
        self.edges.iter().map(|e| e.value().clone()).collect()
    }

    // ========== Portal Operations ==========

    /// Store a new portal
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidPortalName` if the portal name is empty
    pub fn store_portal(&self, stored_portal: StoredPortal) -> Result<()> {
        if stored_portal.portal.name.trim().is_empty() {
            return Err(Error::InvalidPortalName(
                "Portal name cannot be empty".into(),
            ));
        }

        self.portals.insert(stored_portal.portal.id, stored_portal);
        Ok(())
    }

    /// Get portal by ID
    ///
    /// # Errors
    ///
    /// Returns `Error::PortalNotFound` if the portal doesn't exist
    pub fn get_portal(&self, portal_id: &PortalId) -> Result<StoredPortal> {
        self.portals
            .get(portal_id)
            .map(|p| p.value().clone())
            .ok_or(Error::PortalNotFound(*portal_id))
    }

    /// Update an existing portal
    ///
    /// # Errors
    ///
    /// Returns `Error::PortalNotFound` if the portal doesn't exist
    pub fn update_portal(&self, portal_id: &PortalId, stored_portal: StoredPortal) -> Result<()> {
        if !self.portals.contains_key(portal_id) {
            return Err(Error::PortalNotFound(*portal_id));
        }
        self.portals.insert(*portal_id, stored_portal);
        Ok(())
    }

    /// Delete a portal
    ///
    /// # Errors
    ///
    /// Returns `Error::PortalNotFound` if the portal doesn't exist
    pub fn delete_portal(&self, portal_id: &PortalId) -> Result<StoredPortal> {
        self.portals
            .remove(portal_id)
            .map(|(_, p)| p)
            .ok_or(Error::PortalNotFound(*portal_id))
    }

    /// List all portals
    #[must_use]
    pub fn list_portals(&self) -> Vec<StoredPortal> {
        self.portals.iter().map(|p| p.value().clone()).collect()
    }

    // ========== Chunk Operations ==========

    /// Store an encrypted chunk
    ///
    /// # Arguments
    ///
    /// * `content_id` - BLAKE3 hash of the plaintext content
    /// * `encrypted_data` - The encrypted chunk data
    pub fn store_chunk(&self, content_id: ContentId, encrypted_data: &[u8]) {
        self.chunks.insert(content_id, encrypted_data.to_vec());
    }

    /// Get an encrypted chunk
    ///
    /// # Errors
    ///
    /// Returns `Error::ChunkNotFound` if the chunk doesn't exist
    pub fn get_chunk(&self, content_id: &ContentId) -> Result<Vec<u8>> {
        self.chunks
            .get(content_id)
            .map(|c| c.value().clone())
            .ok_or(Error::ChunkNotFound(*content_id))
    }

    /// Check if a chunk exists
    #[must_use]
    pub fn has_chunk(&self, content_id: &ContentId) -> bool {
        self.chunks.contains_key(content_id)
    }

    /// Check which chunks exist from a list
    #[must_use]
    pub fn check_chunks(&self, content_ids: &[ContentId]) -> Vec<ContentId> {
        content_ids
            .iter()
            .filter(|cid| self.has_chunk(cid))
            .copied()
            .collect()
    }

    /// Delete a chunk
    ///
    /// # Errors
    ///
    /// Returns `Error::ChunkNotFound` if the chunk doesn't exist
    pub fn delete_chunk(&self, content_id: &ContentId) -> Result<Vec<u8>> {
        self.chunks
            .remove(content_id)
            .map(|(_, c)| c)
            .ok_or(Error::ChunkNotFound(*content_id))
    }

    /// Get total number of chunks stored
    #[must_use]
    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }

    // ========== Manifest Operations ==========

    /// Store an encrypted manifest
    pub fn store_manifest(&self, portal_id: PortalId, encrypted_manifest: &[u8]) {
        self.manifests
            .insert(portal_id, encrypted_manifest.to_vec());
    }

    /// Get an encrypted manifest
    ///
    /// # Errors
    ///
    /// Returns `Error::ManifestNotFound` if the manifest doesn't exist
    pub fn get_manifest(&self, portal_id: &PortalId) -> Result<Vec<u8>> {
        self.manifests
            .get(portal_id)
            .map(|m| m.value().clone())
            .ok_or(Error::ManifestNotFound(*portal_id))
    }

    /// Check if a manifest exists
    #[must_use]
    pub fn has_manifest(&self, portal_id: &PortalId) -> bool {
        self.manifests.contains_key(portal_id)
    }

    /// Delete a manifest
    ///
    /// # Errors
    ///
    /// Returns `Error::ManifestNotFound` if the manifest doesn't exist
    pub fn delete_manifest(&self, portal_id: &PortalId) -> Result<Vec<u8>> {
        self.manifests
            .remove(portal_id)
            .map(|(_, m)| m)
            .ok_or(Error::ManifestNotFound(*portal_id))
    }

    // ========== Statistics ==========

    /// Get storage statistics
    #[must_use]
    pub fn stats(&self) -> StorageStats {
        StorageStats {
            portal_count: self.portals.len(),
            chunk_count: self.chunks.len(),
            manifest_count: self.manifests.len(),
            edge_count: self.edges.len(),
            total_chunk_bytes: self.chunks.iter().map(|c| c.value().len()).sum(),
            total_manifest_bytes: self.manifests.iter().map(|m| m.value().len()).sum(),
        }
    }
}

impl Default for HubStorage {
    fn default() -> Self {
        Self::new()
    }
}

/// Storage statistics
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageStats {
    /// Number of portals stored
    pub portal_count: usize,
    /// Number of chunks stored
    pub chunk_count: usize,
    /// Number of manifests stored
    pub manifest_count: usize,
    /// Number of registered edges
    pub edge_count: usize,
    /// Total bytes used by chunks
    pub total_chunk_bytes: usize,
    /// Total bytes used by manifests
    pub total_manifest_bytes: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use portal_core::Portal;
    use rand::rngs::OsRng;

    fn create_test_key() -> (SigningKey, VerifyingKey) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    fn create_test_portal(owner: VerifyingKey) -> Portal {
        Portal::new("Test Portal".to_string(), owner)
    }

    fn create_test_content_id(seed: u8) -> ContentId {
        [seed; 32]
    }

    #[test]
    fn test_storage_new() {
        let storage = HubStorage::new();
        let stats = storage.stats();
        assert_eq!(stats.portal_count, 0);
        assert_eq!(stats.chunk_count, 0);
        assert_eq!(stats.manifest_count, 0);
        assert_eq!(stats.edge_count, 0);
    }

    #[test]
    fn test_register_edge() {
        let storage = HubStorage::new();
        let (_, pub_key) = create_test_key();
        let edge_id = Uuid::new_v4();

        let edge = storage
            .register_edge(edge_id, pub_key, "Test Edge".to_string())
            .expect("Failed to register edge");

        assert_eq!(edge.id, edge_id);
        assert_eq!(edge.public_key, pub_key);
        assert_eq!(edge.name, "Test Edge");
    }

    #[test]
    fn test_register_edge_empty_name() {
        let storage = HubStorage::new();
        let (_, pub_key) = create_test_key();
        let edge_id = Uuid::new_v4();

        let result = storage.register_edge(edge_id, pub_key, "".to_string());
        assert!(matches!(result, Err(Error::InvalidEdgeName(_))));

        let result = storage.register_edge(edge_id, pub_key, "   ".to_string());
        assert!(matches!(result, Err(Error::InvalidEdgeName(_))));
    }

    #[test]
    fn test_get_edge() {
        let storage = HubStorage::new();
        let (_, pub_key) = create_test_key();
        let edge_id = Uuid::new_v4();

        storage
            .register_edge(edge_id, pub_key, "Test Edge".to_string())
            .unwrap();

        let edge = storage.get_edge(&edge_id).expect("Failed to get edge");
        assert_eq!(edge.id, edge_id);
        assert_eq!(edge.name, "Test Edge");
    }

    #[test]
    fn test_get_edge_not_found() {
        let storage = HubStorage::new();
        let edge_id = Uuid::new_v4();

        let result = storage.get_edge(&edge_id);
        assert!(matches!(result, Err(Error::EdgeNotFound(_))));
    }

    #[test]
    fn test_update_edge_last_seen() {
        let storage = HubStorage::new();
        let (_, pub_key) = create_test_key();
        let edge_id = Uuid::new_v4();

        storage
            .register_edge(edge_id, pub_key, "Test Edge".to_string())
            .unwrap();

        let initial = storage.get_edge(&edge_id).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));

        storage
            .update_edge_last_seen(&edge_id)
            .expect("Failed to update last seen");

        let updated = storage.get_edge(&edge_id).unwrap();
        assert!(updated.last_seen > initial.last_seen);
    }

    #[test]
    fn test_list_edges() {
        let storage = HubStorage::new();
        let (_, pub_key1) = create_test_key();
        let (_, pub_key2) = create_test_key();

        let edge_id1 = Uuid::new_v4();
        let edge_id2 = Uuid::new_v4();

        storage
            .register_edge(edge_id1, pub_key1, "Edge 1".to_string())
            .unwrap();
        storage
            .register_edge(edge_id2, pub_key2, "Edge 2".to_string())
            .unwrap();

        let edges = storage.list_edges();
        assert_eq!(edges.len(), 2);
        assert!(edges.iter().any(|e| e.id == edge_id1));
        assert!(edges.iter().any(|e| e.id == edge_id2));
    }

    #[test]
    fn test_store_portal() {
        let storage = HubStorage::new();
        let (_, owner_key) = create_test_key();
        let portal = create_test_portal(owner_key);
        let acl = AccessControlList::new();

        let stored_portal = StoredPortal::new(portal.clone(), acl, owner_key);
        storage
            .store_portal(stored_portal)
            .expect("Failed to store portal");

        let retrieved = storage
            .get_portal(&portal.id)
            .expect("Failed to get portal");
        assert_eq!(retrieved.portal.id, portal.id);
        assert_eq!(retrieved.portal.name, portal.name);
    }

    #[test]
    fn test_store_portal_empty_name() {
        let storage = HubStorage::new();
        let (_, owner_key) = create_test_key();
        let mut portal = create_test_portal(owner_key);
        portal.name = "".to_string();
        let acl = AccessControlList::new();

        let stored_portal = StoredPortal::new(portal, acl, owner_key);
        let result = storage.store_portal(stored_portal);
        assert!(matches!(result, Err(Error::InvalidPortalName(_))));
    }

    #[test]
    fn test_get_portal_not_found() {
        let storage = HubStorage::new();
        let portal_id = Uuid::new_v4();

        let result = storage.get_portal(&portal_id);
        assert!(matches!(result, Err(Error::PortalNotFound(_))));
    }

    #[test]
    fn test_update_portal() {
        let storage = HubStorage::new();
        let (_, owner_key) = create_test_key();
        let portal = create_test_portal(owner_key);
        let acl = AccessControlList::new();

        let stored_portal = StoredPortal::new(portal.clone(), acl.clone(), owner_key);
        storage.store_portal(stored_portal).unwrap();

        // Update portal name
        let mut updated_portal = portal;
        updated_portal.name = "Updated Portal".to_string();
        let updated_stored = StoredPortal::new(updated_portal.clone(), acl, owner_key);

        storage
            .update_portal(&updated_portal.id, updated_stored)
            .expect("Failed to update portal");

        let retrieved = storage.get_portal(&updated_portal.id).unwrap();
        assert_eq!(retrieved.portal.name, "Updated Portal");
    }

    #[test]
    fn test_update_portal_not_found() {
        let storage = HubStorage::new();
        let (_, owner_key) = create_test_key();
        let portal = create_test_portal(owner_key);
        let acl = AccessControlList::new();

        let stored_portal = StoredPortal::new(portal.clone(), acl, owner_key);
        let result = storage.update_portal(&portal.id, stored_portal);
        assert!(matches!(result, Err(Error::PortalNotFound(_))));
    }

    #[test]
    fn test_delete_portal() {
        let storage = HubStorage::new();
        let (_, owner_key) = create_test_key();
        let portal = create_test_portal(owner_key);
        let acl = AccessControlList::new();

        let stored_portal = StoredPortal::new(portal.clone(), acl, owner_key);
        storage.store_portal(stored_portal).unwrap();

        let deleted = storage
            .delete_portal(&portal.id)
            .expect("Failed to delete portal");
        assert_eq!(deleted.portal.id, portal.id);

        let result = storage.get_portal(&portal.id);
        assert!(matches!(result, Err(Error::PortalNotFound(_))));
    }

    #[test]
    fn test_list_portals() {
        let storage = HubStorage::new();
        let (_, owner_key1) = create_test_key();
        let (_, owner_key2) = create_test_key();

        let portal1 = create_test_portal(owner_key1);
        let portal2 = create_test_portal(owner_key2);

        storage
            .store_portal(StoredPortal::new(
                portal1.clone(),
                AccessControlList::new(),
                owner_key1,
            ))
            .unwrap();
        storage
            .store_portal(StoredPortal::new(
                portal2.clone(),
                AccessControlList::new(),
                owner_key2,
            ))
            .unwrap();

        let portals = storage.list_portals();
        assert_eq!(portals.len(), 2);
        assert!(portals.iter().any(|p| p.portal.id == portal1.id));
        assert!(portals.iter().any(|p| p.portal.id == portal2.id));
    }

    #[test]
    fn test_store_chunk() {
        let storage = HubStorage::new();
        let content_id = create_test_content_id(1);
        let data = vec![1, 2, 3, 4, 5];

        storage.store_chunk(content_id, &data);

        let retrieved = storage.get_chunk(&content_id).expect("Failed to get chunk");
        assert_eq!(retrieved, data);
    }

    #[test]
    fn test_get_chunk_not_found() {
        let storage = HubStorage::new();
        let content_id = create_test_content_id(1);

        let result = storage.get_chunk(&content_id);
        assert!(matches!(result, Err(Error::ChunkNotFound(_))));
    }

    #[test]
    fn test_has_chunk() {
        let storage = HubStorage::new();
        let content_id = create_test_content_id(1);

        assert!(!storage.has_chunk(&content_id));

        storage.store_chunk(content_id, &[1, 2, 3]);
        assert!(storage.has_chunk(&content_id));
    }

    #[test]
    fn test_check_chunks() {
        let storage = HubStorage::new();
        let cid1 = create_test_content_id(1);
        let cid2 = create_test_content_id(2);
        let cid3 = create_test_content_id(3);

        storage.store_chunk(cid1, &[1]);
        storage.store_chunk(cid3, &[3]);

        let existing = storage.check_chunks(&[cid1, cid2, cid3]);
        assert_eq!(existing.len(), 2);
        assert!(existing.contains(&cid1));
        assert!(existing.contains(&cid3));
        assert!(!existing.contains(&cid2));
    }

    #[test]
    fn test_delete_chunk() {
        let storage = HubStorage::new();
        let content_id = create_test_content_id(1);
        let data = vec![1, 2, 3, 4, 5];

        storage.store_chunk(content_id, &data);
        let deleted = storage
            .delete_chunk(&content_id)
            .expect("Failed to delete chunk");
        assert_eq!(deleted, data);

        let result = storage.get_chunk(&content_id);
        assert!(matches!(result, Err(Error::ChunkNotFound(_))));
    }

    #[test]
    fn test_chunk_count() {
        let storage = HubStorage::new();
        assert_eq!(storage.chunk_count(), 0);

        storage.store_chunk(create_test_content_id(1), &[1]);
        assert_eq!(storage.chunk_count(), 1);

        storage.store_chunk(create_test_content_id(2), &[2]);
        assert_eq!(storage.chunk_count(), 2);

        // Overwriting doesn't increase count
        storage.store_chunk(create_test_content_id(1), &[1, 1]);
        assert_eq!(storage.chunk_count(), 2);
    }

    #[test]
    fn test_store_manifest() {
        let storage = HubStorage::new();
        let portal_id = Uuid::new_v4();
        let manifest_data = vec![1, 2, 3, 4, 5];

        storage.store_manifest(portal_id, &manifest_data);

        let retrieved = storage
            .get_manifest(&portal_id)
            .expect("Failed to get manifest");
        assert_eq!(retrieved, manifest_data);
    }

    #[test]
    fn test_get_manifest_not_found() {
        let storage = HubStorage::new();
        let portal_id = Uuid::new_v4();

        let result = storage.get_manifest(&portal_id);
        assert!(matches!(result, Err(Error::ManifestNotFound(_))));
    }

    #[test]
    fn test_has_manifest() {
        let storage = HubStorage::new();
        let portal_id = Uuid::new_v4();

        assert!(!storage.has_manifest(&portal_id));

        storage.store_manifest(portal_id, &[1, 2, 3]);
        assert!(storage.has_manifest(&portal_id));
    }

    #[test]
    fn test_delete_manifest() {
        let storage = HubStorage::new();
        let portal_id = Uuid::new_v4();
        let data = vec![1, 2, 3, 4, 5];

        storage.store_manifest(portal_id, &data);
        let deleted = storage
            .delete_manifest(&portal_id)
            .expect("Failed to delete manifest");
        assert_eq!(deleted, data);

        let result = storage.get_manifest(&portal_id);
        assert!(matches!(result, Err(Error::ManifestNotFound(_))));
    }

    #[test]
    fn test_storage_stats() {
        let storage = HubStorage::new();
        let (_, owner_key) = create_test_key();
        let (_, edge_key) = create_test_key();

        // Add portal
        let portal = create_test_portal(owner_key);
        storage
            .store_portal(StoredPortal::new(
                portal.clone(),
                AccessControlList::new(),
                owner_key,
            ))
            .unwrap();

        // Add chunks
        storage.store_chunk(create_test_content_id(1), &[1, 2, 3]); // 3 bytes
        storage.store_chunk(create_test_content_id(2), &[4, 5, 6, 7]); // 4 bytes

        // Add manifest
        storage.store_manifest(portal.id, &[8, 9, 10, 11, 12]); // 5 bytes

        // Add edge
        storage
            .register_edge(Uuid::new_v4(), edge_key, "Test Edge".to_string())
            .unwrap();

        let stats = storage.stats();
        assert_eq!(stats.portal_count, 1);
        assert_eq!(stats.chunk_count, 2);
        assert_eq!(stats.manifest_count, 1);
        assert_eq!(stats.edge_count, 1);
        assert_eq!(stats.total_chunk_bytes, 7);
        assert_eq!(stats.total_manifest_bytes, 5);
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let storage = Arc::new(HubStorage::new());
        let mut handles = vec![];

        // Spawn multiple threads storing chunks
        for i in 0..10 {
            let storage_clone = Arc::clone(&storage);
            let handle = thread::spawn(move || {
                let content_id = create_test_content_id(i);
                let data = vec![i; 10];
                storage_clone.store_chunk(content_id, &data);
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // Verify all chunks were stored
        assert_eq!(storage.chunk_count(), 10);
        for i in 0..10 {
            let content_id = create_test_content_id(i);
            assert!(storage.has_chunk(&content_id));
        }
    }

    #[test]
    fn test_stored_portal_new() {
        let (_, owner_key) = create_test_key();
        let portal = create_test_portal(owner_key);
        let acl = AccessControlList::new();

        let stored = StoredPortal::new(portal.clone(), acl, owner_key);
        assert_eq!(stored.portal.id, portal.id);
        assert_eq!(stored.owner_key, owner_key);
    }

    #[test]
    fn test_edge_info_new() {
        let (_, pub_key) = create_test_key();
        let edge_id = Uuid::new_v4();
        let name = "Test Edge".to_string();

        let edge = EdgeInfo::new(edge_id, pub_key, name.clone());
        assert_eq!(edge.id, edge_id);
        assert_eq!(edge.public_key, pub_key);
        assert_eq!(edge.name, name);
    }

    #[test]
    fn test_edge_info_update_last_seen() {
        let (_, pub_key) = create_test_key();
        let mut edge = EdgeInfo::new(Uuid::new_v4(), pub_key, "Test".to_string());

        let initial = edge.last_seen;
        std::thread::sleep(std::time::Duration::from_millis(10));

        edge.update_last_seen();
        assert!(edge.last_seen > initial);
    }
}
