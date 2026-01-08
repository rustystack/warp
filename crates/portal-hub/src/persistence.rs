//! Persistent storage for Portal Hub
//!
//! Provides disk-backed storage using sled embedded database.
//! Supports the same operations as in-memory `HubStorage`.

use std::path::Path;
use std::sync::Arc;

use portal_core::{AccessControlList, ContentId, Portal, PortalId};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::storage::{EdgeInfo, StorageStats, StoredPortal};
use crate::{Error, Result};

/// Tree names for sled storage
const PORTALS_TREE: &str = "portals";
const CHUNKS_TREE: &str = "chunks";
const MANIFESTS_TREE: &str = "manifests";
const EDGES_TREE: &str = "edges";
const METADATA_TREE: &str = "metadata";
const CHUNK_REFS_TREE: &str = "chunk_refs"; // Reference counting for GC

/// Serializable version of `StoredPortal` for persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedPortal {
    /// Portal ID
    portal_id: PortalId,
    /// Portal name
    portal_name: String,
    /// Owner public key bytes
    owner_key_bytes: [u8; 32],
    /// Portal creation timestamp
    created_at: chrono::DateTime<chrono::Utc>,
    /// Portal update timestamp
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl PersistedPortal {
    fn from_stored(stored: &StoredPortal) -> Self {
        Self {
            portal_id: stored.portal.id,
            portal_name: stored.portal.name.clone(),
            owner_key_bytes: stored.owner_key.to_bytes(),
            created_at: stored.portal.created_at,
            updated_at: stored.portal.updated_at,
        }
    }

    fn to_stored(&self) -> Result<StoredPortal> {
        use ed25519_dalek::VerifyingKey;

        let owner_key = VerifyingKey::from_bytes(&self.owner_key_bytes)
            .map_err(|e| Error::Storage(format!("Invalid owner key: {e}")))?;

        // Use Portal::new to create a proper portal with all fields
        let portal = Portal::new(self.portal_name.clone(), owner_key);

        Ok(StoredPortal {
            portal,
            acl: AccessControlList::new(),
            owner_key,
        })
    }
}

/// Serializable version of `EdgeInfo` for persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedEdge {
    id: Uuid,
    public_key_bytes: [u8; 32],
    name: String,
    last_seen: chrono::DateTime<chrono::Utc>,
}

impl PersistedEdge {
    fn from_edge(edge: &EdgeInfo) -> Self {
        Self {
            id: edge.id,
            public_key_bytes: edge.public_key.to_bytes(),
            name: edge.name.clone(),
            last_seen: edge.last_seen,
        }
    }

    fn to_edge(&self) -> Result<EdgeInfo> {
        use ed25519_dalek::VerifyingKey;

        let public_key = VerifyingKey::from_bytes(&self.public_key_bytes)
            .map_err(|e| Error::Storage(format!("Invalid edge key: {e}")))?;

        Ok(EdgeInfo {
            id: self.id,
            public_key,
            name: self.name.clone(),
            last_seen: self.last_seen,
        })
    }
}

/// Chunk reference count for garbage collection
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChunkRef {
    /// Number of objects referencing this chunk
    ref_count: u32,
    /// Size in bytes
    size: u32,
    /// When the chunk was stored
    stored_at: chrono::DateTime<chrono::Utc>,
}

/// Persistent Hub storage backed by sled
pub struct PersistentStorage {
    /// Sled database instance
    db: sled::Db,
    /// Portal tree
    portals: sled::Tree,
    /// Chunks tree
    chunks: sled::Tree,
    /// Manifests tree
    manifests: sled::Tree,
    /// Edges tree
    edges: sled::Tree,
    /// Metadata tree
    #[allow(dead_code)]
    metadata: sled::Tree,
    /// Chunk reference counts
    chunk_refs: sled::Tree,
}

impl PersistentStorage {
    /// Open or create persistent storage at the given path
    ///
    /// # Errors
    ///
    /// Returns an error if the database or any tree fails to open
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let db = sled::open(path.as_ref())
            .map_err(|e| Error::Storage(format!("Failed to open database: {e}")))?;

        let portals = db
            .open_tree(PORTALS_TREE)
            .map_err(|e| Error::Storage(format!("Failed to open portals tree: {e}")))?;

        let chunks = db
            .open_tree(CHUNKS_TREE)
            .map_err(|e| Error::Storage(format!("Failed to open chunks tree: {e}")))?;

        let manifests = db
            .open_tree(MANIFESTS_TREE)
            .map_err(|e| Error::Storage(format!("Failed to open manifests tree: {e}")))?;

        let edges = db
            .open_tree(EDGES_TREE)
            .map_err(|e| Error::Storage(format!("Failed to open edges tree: {e}")))?;

        let metadata = db
            .open_tree(METADATA_TREE)
            .map_err(|e| Error::Storage(format!("Failed to open metadata tree: {e}")))?;

        let chunk_refs = db
            .open_tree(CHUNK_REFS_TREE)
            .map_err(|e| Error::Storage(format!("Failed to open chunk_refs tree: {e}")))?;

        info!(
            path = %path.as_ref().display(),
            "Opened persistent storage"
        );

        Ok(Self {
            db,
            portals,
            chunks,
            manifests,
            edges,
            metadata,
            chunk_refs,
        })
    }

    /// Flush all pending writes to disk
    ///
    /// # Errors
    ///
    /// Returns an error if flushing to disk fails
    pub fn flush(&self) -> Result<()> {
        self.db
            .flush()
            .map_err(|e| Error::Storage(format!("Failed to flush: {e}")))?;
        Ok(())
    }

    // ========== Edge Operations ==========

    /// Register a new edge device
    ///
    /// # Errors
    ///
    /// Returns an error if the edge name is empty or storage operation fails
    pub fn register_edge(
        &self,
        edge_id: Uuid,
        public_key: ed25519_dalek::VerifyingKey,
        name: String,
    ) -> Result<EdgeInfo> {
        if name.trim().is_empty() {
            return Err(Error::InvalidEdgeName("Edge name cannot be empty".into()));
        }

        let edge_info = EdgeInfo::new(edge_id, public_key, name);
        let persisted = PersistedEdge::from_edge(&edge_info);
        let data = rmp_serde::to_vec(&persisted)
            .map_err(|e| Error::Serialization(format!("Failed to serialize edge: {e}")))?;

        self.edges
            .insert(edge_id.as_bytes(), data)
            .map_err(|e| Error::Storage(format!("Failed to store edge: {e}")))?;

        debug!(edge_id = %edge_id, name = %edge_info.name, "Registered edge");
        Ok(edge_info)
    }

    /// Get edge information by ID
    ///
    /// # Errors
    ///
    /// Returns an error if the edge is not found or deserialization fails
    pub fn get_edge(&self, edge_id: &Uuid) -> Result<EdgeInfo> {
        let data = self
            .edges
            .get(edge_id.as_bytes())
            .map_err(|e| Error::Storage(format!("Failed to get edge: {e}")))?
            .ok_or(Error::EdgeNotFound(*edge_id))?;

        let persisted: PersistedEdge = rmp_serde::from_slice(&data)
            .map_err(|e| Error::Serialization(format!("Failed to deserialize edge: {e}")))?;

        persisted.to_edge()
    }

    /// Update edge last seen timestamp
    ///
    /// # Errors
    ///
    /// Returns an error if the edge is not found or storage operation fails
    pub fn update_edge_last_seen(&self, edge_id: &Uuid) -> Result<()> {
        let mut edge = self.get_edge(edge_id)?;
        edge.update_last_seen();

        let persisted = PersistedEdge::from_edge(&edge);
        let data = rmp_serde::to_vec(&persisted)
            .map_err(|e| Error::Serialization(format!("Failed to serialize edge: {e}")))?;

        self.edges
            .insert(edge_id.as_bytes(), data)
            .map_err(|e| Error::Storage(format!("Failed to update edge: {e}")))?;

        Ok(())
    }

    /// List all registered edges
    #[must_use]
    pub fn list_edges(&self) -> Vec<EdgeInfo> {
        self.edges
            .iter()
            .filter_map(|result| {
                result.ok().and_then(|(_, data)| {
                    rmp_serde::from_slice::<PersistedEdge>(&data)
                        .ok()
                        .and_then(|p| p.to_edge().ok())
                })
            })
            .collect()
    }

    // ========== Portal Operations ==========

    /// Store a new portal
    ///
    /// # Errors
    ///
    /// Returns an error if the portal name is empty or storage operation fails
    pub fn store_portal(&self, stored_portal: &StoredPortal) -> Result<()> {
        if stored_portal.portal.name.trim().is_empty() {
            return Err(Error::InvalidPortalName(
                "Portal name cannot be empty".into(),
            ));
        }

        let persisted = PersistedPortal::from_stored(stored_portal);
        let data = rmp_serde::to_vec(&persisted)
            .map_err(|e| Error::Serialization(format!("Failed to serialize portal: {e}")))?;

        self.portals
            .insert(stored_portal.portal.id.as_bytes(), data)
            .map_err(|e| Error::Storage(format!("Failed to store portal: {e}")))?;

        debug!(portal_id = %stored_portal.portal.id, "Stored portal");
        Ok(())
    }

    /// Get portal by ID
    ///
    /// # Errors
    ///
    /// Returns an error if the portal is not found or deserialization fails
    pub fn get_portal(&self, portal_id: &PortalId) -> Result<StoredPortal> {
        let data = self
            .portals
            .get(portal_id.as_bytes())
            .map_err(|e| Error::Storage(format!("Failed to get portal: {e}")))?
            .ok_or(Error::PortalNotFound(*portal_id))?;

        let persisted: PersistedPortal = rmp_serde::from_slice(&data)
            .map_err(|e| Error::Serialization(format!("Failed to deserialize portal: {e}")))?;

        persisted.to_stored()
    }

    /// Delete a portal
    ///
    /// # Errors
    ///
    /// Returns an error if the portal is not found or storage operation fails
    pub fn delete_portal(&self, portal_id: &PortalId) -> Result<StoredPortal> {
        let portal = self.get_portal(portal_id)?;

        self.portals
            .remove(portal_id.as_bytes())
            .map_err(|e| Error::Storage(format!("Failed to delete portal: {e}")))?;

        debug!(portal_id = %portal_id, "Deleted portal");
        Ok(portal)
    }

    /// List all portals
    #[must_use]
    pub fn list_portals(&self) -> Vec<StoredPortal> {
        self.portals
            .iter()
            .filter_map(|result| {
                result.ok().and_then(|(_, data)| {
                    rmp_serde::from_slice::<PersistedPortal>(&data)
                        .ok()
                        .and_then(|p| p.to_stored().ok())
                })
            })
            .collect()
    }

    // ========== Chunk Operations ==========

    /// Store an encrypted chunk with reference counting
    pub fn store_chunk(&self, content_id: ContentId, encrypted_data: &[u8]) {
        #[allow(clippy::cast_possible_truncation)]
        let size = encrypted_data.len() as u32;

        // Store the chunk data
        if let Err(e) = self.chunks.insert(content_id, encrypted_data) {
            warn!(chunk = hex::encode(content_id), error = %e, "Failed to store chunk");
            return;
        }

        // Update reference count
        let chunk_ref = ChunkRef {
            ref_count: 1,
            size,
            stored_at: chrono::Utc::now(),
        };

        if let Ok(data) = rmp_serde::to_vec(&chunk_ref) {
            let _ = self.chunk_refs.insert(content_id, data.as_slice());
        }

        debug!(chunk = hex::encode(content_id), size, "Stored chunk");
    }

    /// Get an encrypted chunk
    ///
    /// # Errors
    ///
    /// Returns an error if the chunk is not found or storage operation fails
    pub fn get_chunk(&self, content_id: &ContentId) -> Result<Vec<u8>> {
        self.chunks
            .get(content_id)
            .map_err(|e| Error::Storage(format!("Failed to get chunk: {e}")))?
            .map(|ivec| ivec.to_vec())
            .ok_or(Error::ChunkNotFound(*content_id))
    }

    /// Check if a chunk exists
    #[must_use]
    pub fn has_chunk(&self, content_id: &ContentId) -> bool {
        self.chunks.contains_key(content_id).unwrap_or(false)
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
    /// Returns an error if the chunk is not found or storage operation fails
    pub fn delete_chunk(&self, content_id: &ContentId) -> Result<Vec<u8>> {
        let data = self
            .chunks
            .remove(content_id)
            .map_err(|e| Error::Storage(format!("Failed to delete chunk: {e}")))?
            .map(|ivec| ivec.to_vec())
            .ok_or(Error::ChunkNotFound(*content_id))?;

        // Remove reference count
        let _ = self.chunk_refs.remove(content_id);

        debug!(chunk = hex::encode(content_id), "Deleted chunk");
        Ok(data)
    }

    /// Increment reference count for a chunk
    ///
    /// # Errors
    ///
    /// Returns an error if storage operation or serialization fails
    pub fn inc_chunk_ref(&self, content_id: &ContentId) -> Result<()> {
        if let Some(data) = self
            .chunk_refs
            .get(content_id)
            .map_err(|e| Error::Storage(format!("Failed to get chunk ref: {e}")))?
        {
            let mut chunk_ref: ChunkRef = rmp_serde::from_slice(&data)
                .map_err(|e| Error::Serialization(format!("Invalid chunk ref: {e}")))?;

            chunk_ref.ref_count += 1;

            let new_data = rmp_serde::to_vec(&chunk_ref)
                .map_err(|e| Error::Serialization(format!("Failed to serialize: {e}")))?;

            self.chunk_refs
                .insert(content_id, new_data.as_slice())
                .map_err(|e| Error::Storage(format!("Failed to update chunk ref: {e}")))?;
        }
        Ok(())
    }

    /// Decrement reference count for a chunk (returns true if chunk should be deleted)
    ///
    /// # Errors
    ///
    /// Returns an error if storage operation or serialization fails
    pub fn dec_chunk_ref(&self, content_id: &ContentId) -> Result<bool> {
        if let Some(data) = self
            .chunk_refs
            .get(content_id)
            .map_err(|e| Error::Storage(format!("Failed to get chunk ref: {e}")))?
        {
            let mut chunk_ref: ChunkRef = rmp_serde::from_slice(&data)
                .map_err(|e| Error::Serialization(format!("Invalid chunk ref: {e}")))?;

            chunk_ref.ref_count = chunk_ref.ref_count.saturating_sub(1);

            // Always update the database with the new ref count
            let new_data = rmp_serde::to_vec(&chunk_ref)
                .map_err(|e| Error::Serialization(format!("Failed to serialize: {e}")))?;

            self.chunk_refs
                .insert(content_id, new_data.as_slice())
                .map_err(|e| Error::Storage(format!("Failed to update chunk ref: {e}")))?;

            if chunk_ref.ref_count == 0 {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Get total number of chunks stored
    #[must_use]
    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }

    // ========== Manifest Operations ==========

    /// Store an encrypted manifest
    pub fn store_manifest(&self, portal_id: PortalId, encrypted_manifest: &[u8]) {
        if let Err(e) = self
            .manifests
            .insert(portal_id.as_bytes(), encrypted_manifest)
        {
            warn!(portal_id = %portal_id, error = %e, "Failed to store manifest");
        } else {
            debug!(portal_id = %portal_id, "Stored manifest");
        }
    }

    /// Get an encrypted manifest
    ///
    /// # Errors
    ///
    /// Returns an error if the manifest is not found or storage operation fails
    pub fn get_manifest(&self, portal_id: &PortalId) -> Result<Vec<u8>> {
        self.manifests
            .get(portal_id.as_bytes())
            .map_err(|e| Error::Storage(format!("Failed to get manifest: {e}")))?
            .map(|ivec| ivec.to_vec())
            .ok_or(Error::ManifestNotFound(*portal_id))
    }

    /// Check if a manifest exists
    #[must_use]
    pub fn has_manifest(&self, portal_id: &PortalId) -> bool {
        self.manifests
            .contains_key(portal_id.as_bytes())
            .unwrap_or(false)
    }

    /// Delete a manifest
    ///
    /// # Errors
    ///
    /// Returns an error if the manifest is not found or storage operation fails
    pub fn delete_manifest(&self, portal_id: &PortalId) -> Result<Vec<u8>> {
        self.manifests
            .remove(portal_id.as_bytes())
            .map_err(|e| Error::Storage(format!("Failed to delete manifest: {e}")))?
            .map(|ivec| ivec.to_vec())
            .ok_or(Error::ManifestNotFound(*portal_id))
    }

    // ========== Garbage Collection ==========

    /// Run garbage collection to remove orphaned chunks
    ///
    /// Returns the number of chunks deleted
    ///
    /// # Errors
    ///
    /// Returns an error if storage operation fails during garbage collection
    pub fn gc(&self) -> Result<usize> {
        let mut deleted = 0;

        // Find chunks with zero references
        let orphans: Vec<ContentId> = self
            .chunk_refs
            .iter()
            .filter_map(|result| {
                result.ok().and_then(|(key, data)| {
                    let chunk_ref: ChunkRef = rmp_serde::from_slice(&data).ok()?;
                    if chunk_ref.ref_count == 0 {
                        let mut id = [0u8; 32];
                        id.copy_from_slice(&key);
                        Some(id)
                    } else {
                        None
                    }
                })
            })
            .collect();

        // Delete orphaned chunks
        for content_id in orphans {
            if self.delete_chunk(&content_id).is_ok() {
                deleted += 1;
            }
        }

        if deleted > 0 {
            info!(deleted, "Garbage collection completed");
        }

        Ok(deleted)
    }

    /// Get orphan chunk count (for monitoring)
    #[must_use]
    pub fn orphan_count(&self) -> usize {
        self.chunk_refs
            .iter()
            .filter(|result| {
                result.as_ref().ok().is_some_and(|(_, data)| {
                    rmp_serde::from_slice::<ChunkRef>(data).is_ok_and(|r| r.ref_count == 0)
                })
            })
            .count()
    }

    // ========== Statistics ==========

    /// Get storage statistics
    #[must_use]
    pub fn stats(&self) -> StorageStats {
        let total_chunk_bytes: usize = self
            .chunks
            .iter()
            .filter_map(|result| result.ok().map(|(_, v)| v.len()))
            .sum();

        let total_manifest_bytes: usize = self
            .manifests
            .iter()
            .filter_map(|result| result.ok().map(|(_, v)| v.len()))
            .sum();

        StorageStats {
            portal_count: self.portals.len(),
            chunk_count: self.chunks.len(),
            manifest_count: self.manifests.len(),
            edge_count: self.edges.len(),
            total_chunk_bytes,
            total_manifest_bytes,
        }
    }

    /// Get database size on disk in bytes
    #[must_use]
    pub fn disk_size(&self) -> u64 {
        self.db.size_on_disk().unwrap_or(0)
    }
}

/// Wrapper that provides both in-memory and persistent storage
pub enum HybridStorage {
    /// In-memory storage (fast, non-persistent)
    Memory(Arc<crate::HubStorage>),
    /// Persistent storage (slower, durable)
    Persistent(Arc<PersistentStorage>),
}

impl HybridStorage {
    /// Create in-memory storage
    #[must_use]
    pub fn memory() -> Self {
        Self::Memory(Arc::new(crate::HubStorage::new()))
    }

    /// Create persistent storage
    ///
    /// # Errors
    ///
    /// Returns an error if opening the persistent storage fails
    pub fn persistent(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self::Persistent(Arc::new(PersistentStorage::open(path)?)))
    }

    /// Store a chunk
    pub fn store_chunk(&self, content_id: ContentId, data: &[u8]) {
        match self {
            Self::Memory(s) => s.store_chunk(content_id, data),
            Self::Persistent(s) => s.store_chunk(content_id, data),
        }
    }

    /// Get a chunk
    ///
    /// # Errors
    ///
    /// Returns an error if the chunk is not found
    pub fn get_chunk(&self, content_id: &ContentId) -> Result<Vec<u8>> {
        match self {
            Self::Memory(s) => s.get_chunk(content_id),
            Self::Persistent(s) => s.get_chunk(content_id),
        }
    }

    /// Check if a chunk exists
    #[must_use]
    pub fn has_chunk(&self, content_id: &ContentId) -> bool {
        match self {
            Self::Memory(s) => s.has_chunk(content_id),
            Self::Persistent(s) => s.has_chunk(content_id),
        }
    }

    /// Get chunk count
    #[must_use]
    pub fn chunk_count(&self) -> usize {
        match self {
            Self::Memory(s) => s.chunk_count(),
            Self::Persistent(s) => s.chunk_count(),
        }
    }

    /// Get stats
    #[must_use]
    pub fn stats(&self) -> StorageStats {
        match self {
            Self::Memory(s) => s.stats(),
            Self::Persistent(s) => s.stats(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn create_test_key() -> (SigningKey, ed25519_dalek::VerifyingKey) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    #[test]
    fn test_persistent_storage_chunks() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = PersistentStorage::open(temp_dir.path()).unwrap();

        let content_id = [42u8; 32];
        let data = vec![1, 2, 3, 4, 5];

        // Store chunk
        storage.store_chunk(content_id, data.clone());
        assert!(storage.has_chunk(&content_id));

        // Retrieve chunk
        let retrieved = storage.get_chunk(&content_id).unwrap();
        assert_eq!(retrieved, data);

        // Count
        assert_eq!(storage.chunk_count(), 1);

        // Delete
        let deleted = storage.delete_chunk(&content_id).unwrap();
        assert_eq!(deleted, data);
        assert!(!storage.has_chunk(&content_id));
    }

    #[test]
    fn test_persistent_storage_edges() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = PersistentStorage::open(temp_dir.path()).unwrap();

        let (_, pub_key) = create_test_key();
        let edge_id = Uuid::new_v4();

        // Register edge
        let edge = storage
            .register_edge(edge_id, pub_key, "Test Edge".to_string())
            .unwrap();

        assert_eq!(edge.id, edge_id);
        assert_eq!(edge.name, "Test Edge");

        // Get edge
        let retrieved = storage.get_edge(&edge_id).unwrap();
        assert_eq!(retrieved.id, edge_id);

        // List edges
        let edges = storage.list_edges();
        assert_eq!(edges.len(), 1);
    }

    #[test]
    fn test_persistent_storage_manifests() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = PersistentStorage::open(temp_dir.path()).unwrap();

        let portal_id = Uuid::new_v4();
        let manifest_data = vec![1, 2, 3, 4, 5];

        // Store manifest
        storage.store_manifest(portal_id, &manifest_data);
        assert!(storage.has_manifest(&portal_id));

        // Retrieve manifest
        let retrieved = storage.get_manifest(&portal_id).unwrap();
        assert_eq!(retrieved, manifest_data);

        // Delete manifest
        let deleted = storage.delete_manifest(&portal_id).unwrap();
        assert_eq!(deleted, manifest_data);
        assert!(!storage.has_manifest(&portal_id));
    }

    #[test]
    fn test_persistent_storage_gc() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = PersistentStorage::open(temp_dir.path()).unwrap();

        // Store a chunk
        let content_id = [99u8; 32];
        storage.store_chunk(content_id, vec![1, 2, 3]);

        // Decrement reference to 0
        let should_delete = storage.dec_chunk_ref(&content_id).unwrap();
        assert!(should_delete);

        // Run GC
        let deleted = storage.gc().unwrap();
        assert_eq!(deleted, 1);
        assert!(!storage.has_chunk(&content_id));
    }

    #[test]
    fn test_persistent_storage_persistence() {
        let temp_dir = tempfile::tempdir().unwrap();
        let content_id = [77u8; 32];
        let data = vec![10, 20, 30];

        // Store data and close
        {
            let storage = PersistentStorage::open(temp_dir.path()).unwrap();
            storage.store_chunk(content_id, data.clone());
            storage.flush().unwrap();
        }

        // Reopen and verify data persisted
        {
            let storage = PersistentStorage::open(temp_dir.path()).unwrap();
            assert!(storage.has_chunk(&content_id));
            let retrieved = storage.get_chunk(&content_id).unwrap();
            assert_eq!(retrieved, data);
        }
    }

    #[test]
    fn test_hybrid_storage() {
        // Test memory mode
        let mem = HybridStorage::memory();
        let content_id = [1u8; 32];
        mem.store_chunk(content_id, vec![1, 2, 3]);
        assert!(mem.has_chunk(&content_id));

        // Test persistent mode
        let temp_dir = tempfile::tempdir().unwrap();
        let persistent = HybridStorage::persistent(temp_dir.path()).unwrap();
        persistent.store_chunk(content_id, vec![4, 5, 6]);
        assert!(persistent.has_chunk(&content_id));
    }
}
