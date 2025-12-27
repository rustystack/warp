//! Chunk Registry for content-addressed deduplication
//!
//! The registry tracks all chunks across versions with reference counting
//! to enable efficient garbage collection of unreferenced chunks.

use crate::chunk::{ChunkId, ChunkWeight};
use crate::tree::VersionId;
use crate::{Error, Result};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

/// Storage location for a chunk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageLocation {
    /// Stored in memory
    Memory,

    /// Stored in a file at offset
    File {
        /// Path to the file
        path: String,
        /// Offset within the file
        offset: u64,
    },

    /// Stored in external storage (S3, etc.)
    External {
        /// Storage backend identifier
        backend: String,
        /// Key/path in the backend
        key: String,
    },
}

/// Metadata for a stored chunk
#[derive(Debug)]
pub struct ChunkMetadata {
    /// Chunk ID (content hash)
    pub id: ChunkId,

    /// Original uncompressed size
    pub size: usize,

    /// Compressed size (if compressed)
    pub compressed_size: Option<usize>,

    /// Chunk weight for priority decisions
    pub weight: ChunkWeight,

    /// Reference count (atomic for thread safety)
    ref_count: AtomicU32,

    /// First version that introduced this chunk
    pub first_seen: VersionId,

    /// Where the chunk data is stored
    pub location: StorageLocation,
}

impl ChunkMetadata {
    /// Create new metadata
    pub fn new(
        id: ChunkId,
        size: usize,
        weight: ChunkWeight,
        first_seen: VersionId,
        location: StorageLocation,
    ) -> Self {
        Self {
            id,
            size,
            compressed_size: None,
            weight,
            ref_count: AtomicU32::new(1),
            first_seen,
            location,
        }
    }

    /// Get current reference count
    pub fn ref_count(&self) -> u32 {
        self.ref_count.load(Ordering::SeqCst)
    }

    /// Increment reference count
    pub fn inc_ref(&self) -> u32 {
        self.ref_count.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Decrement reference count, returns new count
    pub fn dec_ref(&self) -> u32 {
        let prev = self.ref_count.fetch_sub(1, Ordering::SeqCst);
        if prev == 0 {
            // Underflow - reset to 0
            self.ref_count.store(0, Ordering::SeqCst);
            0
        } else {
            prev - 1
        }
    }

    /// Check if chunk is referenced
    pub fn is_referenced(&self) -> bool {
        self.ref_count() > 0
    }

    /// Set compressed size
    pub fn set_compressed_size(&mut self, size: usize) {
        self.compressed_size = Some(size);
    }

    /// Get storage efficiency (compressed/original ratio)
    pub fn compression_ratio(&self) -> f64 {
        if let Some(compressed) = self.compressed_size {
            compressed as f64 / self.size as f64
        } else {
            1.0
        }
    }
}

/// Trait for chunk data storage backends
pub trait ChunkStore: Send + Sync {
    /// Store chunk data, returns storage location
    fn store(&self, id: &ChunkId, data: &[u8]) -> Result<StorageLocation>;

    /// Retrieve chunk data
    fn retrieve(&self, id: &ChunkId, location: &StorageLocation) -> Result<Vec<u8>>;

    /// Delete chunk data
    fn delete(&self, id: &ChunkId, location: &StorageLocation) -> Result<()>;

    /// Check if chunk exists
    fn exists(&self, id: &ChunkId, location: &StorageLocation) -> bool;
}

/// In-memory chunk store for testing
#[derive(Default)]
pub struct MemoryChunkStore {
    chunks: DashMap<ChunkId, Vec<u8>>,
}

impl MemoryChunkStore {
    /// Create a new in-memory store
    pub fn new() -> Self {
        Self::default()
    }

    /// Get number of stored chunks
    pub fn len(&self) -> usize {
        self.chunks.len()
    }

    /// Check if store is empty
    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    /// Get total bytes stored
    pub fn total_bytes(&self) -> usize {
        self.chunks.iter().map(|e| e.value().len()).sum()
    }
}

impl ChunkStore for MemoryChunkStore {
    fn store(&self, id: &ChunkId, data: &[u8]) -> Result<StorageLocation> {
        self.chunks.insert(*id, data.to_vec());
        Ok(StorageLocation::Memory)
    }

    fn retrieve(&self, id: &ChunkId, _location: &StorageLocation) -> Result<Vec<u8>> {
        self.chunks
            .get(id)
            .map(|v| v.clone())
            .ok_or_else(|| Error::Internal(format!("Chunk not found: {:?}", id)))
    }

    fn delete(&self, id: &ChunkId, _location: &StorageLocation) -> Result<()> {
        self.chunks.remove(id);
        Ok(())
    }

    fn exists(&self, id: &ChunkId, _location: &StorageLocation) -> bool {
        self.chunks.contains_key(id)
    }
}

/// Central registry for chunk deduplication
pub struct ChunkRegistry {
    /// Chunk metadata indexed by ID
    chunks: DashMap<ChunkId, ChunkMetadata>,

    /// Chunks belonging to each version
    version_chunks: DashMap<VersionId, HashSet<ChunkId>>,

    /// Storage backend
    storage: Arc<dyn ChunkStore>,
}

impl ChunkRegistry {
    /// Create a new registry with the given storage backend
    pub fn new(storage: Arc<dyn ChunkStore>) -> Self {
        Self {
            chunks: DashMap::new(),
            version_chunks: DashMap::new(),
            storage,
        }
    }

    /// Create a registry with in-memory storage (for testing)
    pub fn in_memory() -> Self {
        Self::new(Arc::new(MemoryChunkStore::new()))
    }

    /// Register a chunk, returns true if this is a new chunk
    pub fn register(
        &self,
        id: ChunkId,
        data: &[u8],
        weight: ChunkWeight,
        version: VersionId,
    ) -> Result<bool> {
        // Check if chunk already exists
        if let Some(existing) = self.chunks.get(&id) {
            // Increment reference count
            existing.inc_ref();

            // Add to version's chunk set
            self.version_chunks
                .entry(version)
                .or_default()
                .insert(id);

            return Ok(false); // Not a new chunk
        }

        // Store the chunk data
        let location = self.storage.store(&id, data)?;

        // Create metadata
        let metadata = ChunkMetadata::new(id, data.len(), weight, version, location);

        // Insert into registry
        self.chunks.insert(id, metadata);

        // Add to version's chunk set
        self.version_chunks
            .entry(version)
            .or_default()
            .insert(id);

        Ok(true) // New chunk
    }

    /// Register multiple chunks from a version
    pub fn register_version(
        &self,
        version: VersionId,
        chunks: &[(ChunkId, &[u8], ChunkWeight)],
    ) -> Result<RegistrationStats> {
        let mut stats = RegistrationStats::default();

        for (id, data, weight) in chunks {
            let is_new = self.register(*id, data, *weight, version)?;
            if is_new {
                stats.new_chunks += 1;
                stats.new_bytes += data.len();
            } else {
                stats.dedup_chunks += 1;
                stats.dedup_bytes += data.len();
            }
        }

        Ok(stats)
    }

    /// Unregister a version, decrements ref counts
    pub fn unregister_version(&self, version: VersionId) -> Result<Vec<ChunkId>> {
        let mut unreferenced = Vec::new();

        if let Some((_, chunk_ids)) = self.version_chunks.remove(&version) {
            for id in chunk_ids {
                if let Some(metadata) = self.chunks.get(&id) {
                    let new_count = metadata.dec_ref();
                    if new_count == 0 {
                        unreferenced.push(id);
                    }
                }
            }
        }

        Ok(unreferenced)
    }

    /// Get chunk metadata
    pub fn get(&self, id: &ChunkId) -> Option<dashmap::mapref::one::Ref<'_, ChunkId, ChunkMetadata>> {
        self.chunks.get(id)
    }

    /// Retrieve chunk data
    pub fn retrieve(&self, id: &ChunkId) -> Result<Vec<u8>> {
        let metadata = self
            .chunks
            .get(id)
            .ok_or_else(|| Error::Internal(format!("Chunk not found: {:?}", id)))?;

        self.storage.retrieve(id, &metadata.location)
    }

    /// Check if chunk exists
    pub fn contains(&self, id: &ChunkId) -> bool {
        self.chunks.contains_key(id)
    }

    /// Get total number of unique chunks
    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }

    /// Get number of tracked versions
    pub fn version_count(&self) -> usize {
        self.version_chunks.len()
    }

    /// Get chunks for a version
    pub fn version_chunks(&self, version: VersionId) -> Option<HashSet<ChunkId>> {
        self.version_chunks.get(&version).map(|v| v.clone())
    }

    /// Get unreferenced chunks (ref_count == 0)
    pub fn unreferenced_chunks(&self) -> Vec<ChunkId> {
        self.chunks
            .iter()
            .filter(|e| !e.value().is_referenced())
            .map(|e| *e.key())
            .collect()
    }

    /// Get storage statistics
    pub fn stats(&self) -> RegistryStats {
        let mut stats = RegistryStats::default();

        for entry in self.chunks.iter() {
            let meta = entry.value();
            stats.total_chunks += 1;
            stats.total_bytes += meta.size;

            if let Some(compressed) = meta.compressed_size {
                stats.compressed_bytes += compressed;
            } else {
                stats.compressed_bytes += meta.size;
            }

            stats.total_refs += meta.ref_count() as usize;

            if !meta.is_referenced() {
                stats.unreferenced_chunks += 1;
            }
        }

        stats.versions = self.version_chunks.len();
        stats
    }

    /// Delete unreferenced chunks from storage
    pub fn collect_garbage(&self) -> Result<GcStats> {
        let unreferenced = self.unreferenced_chunks();
        let mut stats = GcStats::default();

        for id in unreferenced {
            if let Some((_, metadata)) = self.chunks.remove(&id) {
                // Delete from storage
                if let Err(e) = self.storage.delete(&id, &metadata.location) {
                    tracing::warn!("Failed to delete chunk {:?}: {}", id, e);
                    stats.errors += 1;
                    // Re-insert the metadata since deletion failed
                    self.chunks.insert(id, metadata);
                } else {
                    stats.chunks_deleted += 1;
                    stats.bytes_freed += metadata.size;
                }
            }
        }

        Ok(stats)
    }
}

/// Statistics from registering chunks
#[derive(Debug, Default, Clone)]
pub struct RegistrationStats {
    /// Number of new (unique) chunks
    pub new_chunks: usize,
    /// Bytes in new chunks
    pub new_bytes: usize,
    /// Number of deduplicated chunks
    pub dedup_chunks: usize,
    /// Bytes saved through deduplication
    pub dedup_bytes: usize,
}

impl RegistrationStats {
    /// Calculate deduplication ratio
    pub fn dedup_ratio(&self) -> f64 {
        let total = self.new_bytes + self.dedup_bytes;
        if total == 0 {
            return 0.0;
        }
        self.dedup_bytes as f64 / total as f64
    }
}

/// Registry statistics
#[derive(Debug, Default, Clone)]
pub struct RegistryStats {
    /// Total unique chunks
    pub total_chunks: usize,
    /// Total bytes (uncompressed)
    pub total_bytes: usize,
    /// Total bytes (compressed)
    pub compressed_bytes: usize,
    /// Total reference count across all chunks
    pub total_refs: usize,
    /// Number of tracked versions
    pub versions: usize,
    /// Chunks with zero references
    pub unreferenced_chunks: usize,
}

impl RegistryStats {
    /// Average references per chunk
    pub fn avg_refs(&self) -> f64 {
        if self.total_chunks == 0 {
            0.0
        } else {
            self.total_refs as f64 / self.total_chunks as f64
        }
    }

    /// Compression ratio
    pub fn compression_ratio(&self) -> f64 {
        if self.total_bytes == 0 {
            1.0
        } else {
            self.compressed_bytes as f64 / self.total_bytes as f64
        }
    }
}

/// Garbage collection statistics
#[derive(Debug, Default, Clone)]
pub struct GcStats {
    /// Chunks deleted
    pub chunks_deleted: usize,
    /// Bytes freed
    pub bytes_freed: usize,
    /// Errors during deletion
    pub errors: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_chunk(data: &[u8]) -> (ChunkId, ChunkWeight) {
        let id = ChunkId::from_data(data);
        let weight = ChunkWeight::from_data(data);
        (id, weight)
    }

    #[test]
    fn test_chunk_metadata() {
        let (id, weight) = test_chunk(b"test data");
        let version = VersionId::new(1);

        let meta = ChunkMetadata::new(id, 9, weight, version, StorageLocation::Memory);

        assert_eq!(meta.ref_count(), 1);
        assert!(meta.is_referenced());

        assert_eq!(meta.inc_ref(), 2);
        assert_eq!(meta.ref_count(), 2);

        assert_eq!(meta.dec_ref(), 1);
        assert_eq!(meta.ref_count(), 1);

        assert_eq!(meta.dec_ref(), 0);
        assert!(!meta.is_referenced());
    }

    #[test]
    fn test_memory_store() {
        let store = MemoryChunkStore::new();
        let (id, _) = test_chunk(b"test data");
        let data = b"test data";

        // Store
        let location = store.store(&id, data).unwrap();
        assert!(store.exists(&id, &location));
        assert_eq!(store.len(), 1);

        // Retrieve
        let retrieved = store.retrieve(&id, &location).unwrap();
        assert_eq!(retrieved, data);

        // Delete
        store.delete(&id, &location).unwrap();
        assert!(!store.exists(&id, &location));
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_registry_register() {
        let registry = ChunkRegistry::in_memory();
        let version = VersionId::new(1);
        let data = b"test chunk data";
        let (id, weight) = test_chunk(data);

        // First registration - new chunk
        let is_new = registry.register(id, data, weight, version).unwrap();
        assert!(is_new);
        assert_eq!(registry.chunk_count(), 1);

        // Second registration - deduplicated
        let version2 = VersionId::new(2);
        let is_new = registry.register(id, data, weight, version2).unwrap();
        assert!(!is_new);
        assert_eq!(registry.chunk_count(), 1); // Still 1 chunk

        // Ref count should be 2
        let meta = registry.get(&id).unwrap();
        assert_eq!(meta.ref_count(), 2);
    }

    #[test]
    fn test_registry_dedup() {
        let registry = ChunkRegistry::in_memory();
        let version = VersionId::new(1);

        let chunks: Vec<(ChunkId, &[u8], ChunkWeight)> = vec![
            {
                let data = b"chunk 1";
                let (id, w) = test_chunk(data);
                (id, data.as_slice(), w)
            },
            {
                let data = b"chunk 2";
                let (id, w) = test_chunk(data);
                (id, data.as_slice(), w)
            },
            {
                // Duplicate of chunk 1
                let data = b"chunk 1";
                let (id, w) = test_chunk(data);
                (id, data.as_slice(), w)
            },
        ];

        let stats = registry.register_version(version, &chunks).unwrap();

        assert_eq!(stats.new_chunks, 2); // Only 2 unique
        assert_eq!(stats.dedup_chunks, 1); // 1 deduplicated
        assert_eq!(registry.chunk_count(), 2);
    }

    #[test]
    fn test_registry_unregister() {
        let registry = ChunkRegistry::in_memory();
        let version1 = VersionId::new(1);
        let version2 = VersionId::new(2);
        let data = b"shared chunk";
        let (id, weight) = test_chunk(data);

        // Register in two versions
        registry.register(id, data, weight, version1).unwrap();
        registry.register(id, data, weight, version2).unwrap();

        // Unregister version1
        let unreferenced = registry.unregister_version(version1).unwrap();
        assert!(unreferenced.is_empty()); // Still referenced by version2

        // Unregister version2
        let unreferenced = registry.unregister_version(version2).unwrap();
        assert_eq!(unreferenced.len(), 1);
        assert_eq!(unreferenced[0], id);
    }

    #[test]
    fn test_garbage_collection() {
        let registry = ChunkRegistry::in_memory();
        let version = VersionId::new(1);
        let data = b"chunk data";
        let (id, weight) = test_chunk(data);

        // Register chunk
        registry.register(id, data, weight, version).unwrap();
        assert_eq!(registry.chunk_count(), 1);

        // Unregister version
        registry.unregister_version(version).unwrap();

        // Collect garbage
        let gc_stats = registry.collect_garbage().unwrap();
        assert_eq!(gc_stats.chunks_deleted, 1);
        assert_eq!(gc_stats.bytes_freed, data.len());
        assert_eq!(registry.chunk_count(), 0);
    }

    #[test]
    fn test_registry_stats() {
        let registry = ChunkRegistry::in_memory();
        let version1 = VersionId::new(1);
        let version2 = VersionId::new(2);

        let data1 = b"chunk one";
        let data2 = b"chunk two";
        let (id1, w1) = test_chunk(data1);
        let (id2, w2) = test_chunk(data2);

        registry.register(id1, data1, w1, version1).unwrap();
        registry.register(id2, data2, w2, version1).unwrap();
        registry.register(id1, data1, w1, version2).unwrap(); // Dedup

        let stats = registry.stats();
        assert_eq!(stats.total_chunks, 2);
        assert_eq!(stats.total_bytes, data1.len() + data2.len());
        assert_eq!(stats.total_refs, 3); // id1 has 2 refs, id2 has 1
        assert_eq!(stats.versions, 2);
        assert_eq!(stats.unreferenced_chunks, 0);
    }

    #[test]
    fn test_retrieve_chunk() {
        let registry = ChunkRegistry::in_memory();
        let version = VersionId::new(1);
        let data = b"retrievable chunk";
        let (id, weight) = test_chunk(data);

        registry.register(id, data, weight, version).unwrap();

        let retrieved = registry.retrieve(&id).unwrap();
        assert_eq!(retrieved, data);
    }
}
