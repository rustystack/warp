//! Bidirectional chunk-edge availability mapping
//!
//! Provides high-performance, thread-safe tracking of which chunks are stored on which edges,
//! enabling efficient replica location and under-replication detection. Designed to scale to
//! millions of chunks across thousands of edges.
//!
//! # Architecture
//!
//! Uses bidirectional `DashMap` indices for lock-free concurrent access:
//! - Forward index: `chunk_hash` -> edges storing it
//! - Reverse index: `edge_id` -> chunks it stores
//!
//! Both maps stay synchronized through atomic operations, ensuring consistency without
//! global locks. Each map entry uses `DashSet` for efficient set operations.

use crate::types::EdgeId;
use dashmap::{DashMap, DashSet};

/// Type alias for chunk hashes (BLAKE3 32-byte hash)
pub type ChunkHash = [u8; 32];

/// Location information for a chunk
#[derive(Debug, Clone)]
pub struct ChunkLocation {
    /// The chunk's hash
    pub chunk_hash: ChunkHash,
    /// All edges storing this chunk
    pub edge_ids: Vec<EdgeId>,
    /// Number of replicas
    pub replica_count: usize,
}

/// Bidirectional chunk-edge availability map
///
/// Maintains synchronized forward and reverse indices for efficient lookups
/// in both directions. All operations are lock-free and thread-safe.
///
/// # Performance Characteristics
///
/// - Add/remove: O(1) amortized
/// - Lookups: O(1) for finding edges/chunks
/// - Batch operations: O(n) where n is batch size
/// - Memory: ~64 bytes per unique chunk-edge relationship
pub struct ChunkAvailabilityMap {
    /// Forward index: `chunk_hash` -> edges storing it
    chunk_to_edges: DashMap<ChunkHash, DashSet<EdgeId>>,
    /// Reverse index: `edge_id` -> chunks it stores
    edge_to_chunks: DashMap<EdgeId, DashSet<ChunkHash>>,
}

impl ChunkAvailabilityMap {
    /// Create a new empty availability map
    #[must_use]
    pub fn new() -> Self {
        Self {
            chunk_to_edges: DashMap::new(),
            edge_to_chunks: DashMap::new(),
        }
    }

    /// Add a chunk-edge relationship
    ///
    /// Records that `edge` stores `chunk`. If the relationship already exists,
    /// this is a no-op. Thread-safe and lock-free.
    pub fn add_chunk(&self, chunk: ChunkHash, edge: EdgeId) {
        // Add to forward index
        self.chunk_to_edges.entry(chunk).or_default().insert(edge);

        // Add to reverse index
        self.edge_to_chunks.entry(edge).or_default().insert(chunk);
    }

    /// Remove a chunk-edge relationship
    ///
    /// Removes the record that `edge` stores `chunk`. Returns true if the
    /// relationship existed and was removed, false otherwise.
    #[must_use]
    pub fn remove_chunk(&self, chunk: &ChunkHash, edge: &EdgeId) -> bool {
        let mut removed = false;

        // Remove from forward index
        if let Some(edges) = self.chunk_to_edges.get(chunk) {
            removed = edges.remove(edge).is_some();
            // Clean up empty entry
            if edges.is_empty() {
                drop(edges);
                self.chunk_to_edges.remove(chunk);
            }
        }

        // Remove from reverse index
        if let Some(chunks) = self.edge_to_chunks.get(edge) {
            chunks.remove(chunk);
            // Clean up empty entry
            if chunks.is_empty() {
                drop(chunks);
                self.edge_to_chunks.remove(edge);
            }
        }

        removed
    }

    /// Remove all chunks for an edge
    ///
    /// Removes all chunk-edge relationships for the given edge.
    /// Returns the list of chunks that were removed.
    /// Useful when an edge disconnects or fails.
    #[must_use]
    pub fn remove_all_for_edge(&self, edge: &EdgeId) -> Vec<ChunkHash> {
        if let Some((_, chunk_set)) = self.edge_to_chunks.remove(edge) {
            let chunks: Vec<ChunkHash> = chunk_set.iter().map(|r| *r.key()).collect();

            // Remove edge from forward index for each chunk
            for chunk in &chunks {
                if let Some(edges) = self.chunk_to_edges.get(chunk) {
                    edges.remove(edge);
                    // Clean up empty entries
                    if edges.is_empty() {
                        drop(edges);
                        self.chunk_to_edges.remove(chunk);
                    }
                }
            }

            chunks
        } else {
            Vec::new()
        }
    }

    /// Get all edges storing a chunk
    ///
    /// Returns a vector of edge IDs that store the given chunk.
    /// Returns an empty vector if the chunk is not found.
    #[must_use]
    pub fn get_edges(&self, chunk: &ChunkHash) -> Vec<EdgeId> {
        self.chunk_to_edges
            .get(chunk)
            .map(|edges| edges.iter().map(|r| *r.key()).collect())
            .unwrap_or_default()
    }

    /// Get the replica count for a chunk
    ///
    /// Returns the number of edges storing this chunk.
    #[must_use]
    pub fn replica_count(&self, chunk: &ChunkHash) -> usize {
        self.chunk_to_edges
            .get(chunk)
            .map_or(0, |edges| edges.len())
    }

    /// Check if a chunk exists in the map
    #[must_use]
    pub fn has_chunk(&self, chunk: &ChunkHash) -> bool {
        self.chunk_to_edges.contains_key(chunk)
    }

    /// Get all chunks stored on an edge
    ///
    /// Returns a vector of chunk hashes stored on the given edge.
    /// Returns an empty vector if the edge is not found.
    #[must_use]
    pub fn get_chunks(&self, edge: &EdgeId) -> Vec<ChunkHash> {
        self.edge_to_chunks
            .get(edge)
            .map(|chunks| chunks.iter().map(|r| *r.key()).collect())
            .unwrap_or_default()
    }

    /// Get the number of chunks stored on an edge
    #[must_use]
    pub fn edge_chunk_count(&self, edge: &EdgeId) -> usize {
        self.edge_to_chunks
            .get(edge)
            .map_or(0, |chunks| chunks.len())
    }

    /// Add multiple chunks for an edge efficiently
    ///
    /// Batch operation that adds multiple chunk-edge relationships.
    /// More efficient than calling `add_chunk` in a loop.
    pub fn add_chunks_batch(&self, chunks: &[ChunkHash], edge: EdgeId) {
        if chunks.is_empty() {
            return;
        }

        // Get or create reverse index entry once
        let edge_chunks = self.edge_to_chunks.entry(edge).or_default();

        for chunk in chunks {
            // Add to reverse index
            edge_chunks.insert(*chunk);

            // Add to forward index
            self.chunk_to_edges.entry(*chunk).or_default().insert(edge);
        }
    }

    /// Remove multiple chunks for an edge efficiently
    ///
    /// Batch operation that removes multiple chunk-edge relationships.
    /// More efficient than calling `remove_chunk` in a loop.
    pub fn remove_chunks_batch(&self, chunks: &[ChunkHash], edge: &EdgeId) {
        if chunks.is_empty() {
            return;
        }

        // Get reverse index entry
        let edge_chunks = match self.edge_to_chunks.get(edge) {
            Some(chunks) => chunks,
            None => return,
        };

        for chunk in chunks {
            // Remove from reverse index
            edge_chunks.remove(chunk);

            // Remove from forward index
            if let Some(edges) = self.chunk_to_edges.get(chunk) {
                edges.remove(edge);
                // Clean up empty entries
                if edges.is_empty() {
                    drop(edges);
                    self.chunk_to_edges.remove(chunk);
                }
            }
        }

        // Clean up empty edge entry
        if edge_chunks.is_empty() {
            drop(edge_chunks);
            self.edge_to_chunks.remove(edge);
        }
    }

    /// Get the total number of unique chunks
    #[must_use]
    pub fn total_unique_chunks(&self) -> usize {
        self.chunk_to_edges.len()
    }

    /// Get the total number of chunk replicas across all edges
    ///
    /// This counts all chunk-edge relationships, so a chunk stored on
    /// 3 edges contributes 3 to the total.
    #[must_use]
    pub fn total_replicas(&self) -> usize {
        self.chunk_to_edges
            .iter()
            .map(|entry| entry.value().len())
            .sum()
    }

    /// Calculate average replication factor
    ///
    /// Returns the mean number of replicas per chunk.
    /// Returns 0.0 if no chunks exist.
    #[must_use]
    pub fn average_replication(&self) -> f64 {
        let total_chunks = self.total_unique_chunks();
        if total_chunks == 0 {
            return 0.0;
        }
        self.total_replicas() as f64 / total_chunks as f64
    }

    /// Find chunks with fewer than minimum replicas
    ///
    /// Returns chunk hashes for all chunks that have fewer than
    /// `min_replicas` copies stored.
    #[must_use]
    pub fn find_under_replicated(&self, min_replicas: usize) -> Vec<ChunkHash> {
        self.chunk_to_edges
            .iter()
            .filter_map(|entry| {
                if entry.value().len() < min_replicas {
                    Some(*entry.key())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Find chunks with exactly one replica
    ///
    /// Convenience method for finding critically under-replicated chunks.
    #[must_use]
    pub fn find_single_replica(&self) -> Vec<ChunkHash> {
        self.find_under_replicated(2)
    }

    /// Get full location information for a chunk
    ///
    /// Returns complete information about where a chunk is stored,
    /// or None if the chunk doesn't exist.
    #[must_use]
    pub fn get_location(&self, chunk: &ChunkHash) -> Option<ChunkLocation> {
        self.chunk_to_edges.get(chunk).map(|edges| {
            let edge_ids: Vec<EdgeId> = edges.iter().map(|r| *r.key()).collect();
            let replica_count = edge_ids.len();
            ChunkLocation {
                chunk_hash: *chunk,
                edge_ids,
                replica_count,
            }
        })
    }
}

impl Default for ChunkAvailabilityMap {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    fn test_chunk(n: u8) -> ChunkHash {
        let mut hash = [0u8; 32];
        hash[0] = n;
        hash
    }

    fn test_edge(n: u8) -> EdgeId {
        let mut key = [0u8; 32];
        key[0] = n;
        EdgeId::new(key)
    }

    #[test]
    fn test_new_map_is_empty() {
        let map = ChunkAvailabilityMap::new();
        assert_eq!(map.total_unique_chunks(), 0);
        assert_eq!(map.total_replicas(), 0);
        assert_eq!(map.average_replication(), 0.0);
    }

    #[test]
    fn test_add_single_chunk() {
        let map = ChunkAvailabilityMap::new();
        let chunk = test_chunk(1);
        let edge = test_edge(1);

        map.add_chunk(chunk, edge);

        assert!(map.has_chunk(&chunk));
        assert_eq!(map.replica_count(&chunk), 1);
        assert_eq!(map.get_edges(&chunk), vec![edge]);
        assert_eq!(map.get_chunks(&edge), vec![chunk]);
        assert_eq!(map.total_unique_chunks(), 1);
        assert_eq!(map.total_replicas(), 1);
    }

    #[test]
    fn test_add_multiple_edges_same_chunk() {
        let map = ChunkAvailabilityMap::new();
        let chunk = test_chunk(1);
        let edge1 = test_edge(1);
        let edge2 = test_edge(2);
        let edge3 = test_edge(3);

        map.add_chunk(chunk, edge1);
        map.add_chunk(chunk, edge2);
        map.add_chunk(chunk, edge3);

        assert_eq!(map.replica_count(&chunk), 3);
        assert_eq!(map.total_unique_chunks(), 1);
        assert_eq!(map.total_replicas(), 3);

        let edges = map.get_edges(&chunk);
        assert_eq!(edges.len(), 3);
        assert!(edges.contains(&edge1));
        assert!(edges.contains(&edge2));
        assert!(edges.contains(&edge3));
    }

    #[test]
    fn test_add_multiple_chunks_same_edge() {
        let map = ChunkAvailabilityMap::new();
        let chunk1 = test_chunk(1);
        let chunk2 = test_chunk(2);
        let chunk3 = test_chunk(3);
        let edge = test_edge(1);

        map.add_chunk(chunk1, edge);
        map.add_chunk(chunk2, edge);
        map.add_chunk(chunk3, edge);

        assert_eq!(map.edge_chunk_count(&edge), 3);
        assert_eq!(map.total_unique_chunks(), 3);
        assert_eq!(map.total_replicas(), 3);

        let chunks = map.get_chunks(&edge);
        assert_eq!(chunks.len(), 3);
        assert!(chunks.contains(&chunk1));
        assert!(chunks.contains(&chunk2));
        assert!(chunks.contains(&chunk3));
    }

    #[test]
    fn test_add_duplicate_is_idempotent() {
        let map = ChunkAvailabilityMap::new();
        let chunk = test_chunk(1);
        let edge = test_edge(1);

        map.add_chunk(chunk, edge);
        map.add_chunk(chunk, edge);
        map.add_chunk(chunk, edge);

        assert_eq!(map.replica_count(&chunk), 1);
        assert_eq!(map.edge_chunk_count(&edge), 1);
        assert_eq!(map.total_unique_chunks(), 1);
        assert_eq!(map.total_replicas(), 1);
    }

    #[test]
    fn test_remove_chunk() {
        let map = ChunkAvailabilityMap::new();
        let chunk = test_chunk(1);
        let edge = test_edge(1);

        map.add_chunk(chunk, edge);
        assert!(map.has_chunk(&chunk));

        let removed = map.remove_chunk(&chunk, &edge);
        assert!(removed);
        assert!(!map.has_chunk(&chunk));
        assert_eq!(map.replica_count(&chunk), 0);
        assert_eq!(map.edge_chunk_count(&edge), 0);
        assert_eq!(map.total_unique_chunks(), 0);
    }

    #[test]
    fn test_remove_nonexistent_chunk() {
        let map = ChunkAvailabilityMap::new();
        let chunk = test_chunk(1);
        let edge = test_edge(1);

        let removed = map.remove_chunk(&chunk, &edge);
        assert!(!removed);
    }

    #[test]
    fn test_remove_one_replica_keeps_others() {
        let map = ChunkAvailabilityMap::new();
        let chunk = test_chunk(1);
        let edge1 = test_edge(1);
        let edge2 = test_edge(2);
        let edge3 = test_edge(3);

        map.add_chunk(chunk, edge1);
        map.add_chunk(chunk, edge2);
        map.add_chunk(chunk, edge3);

        map.remove_chunk(&chunk, &edge2);

        assert_eq!(map.replica_count(&chunk), 2);
        let edges = map.get_edges(&chunk);
        assert!(edges.contains(&edge1));
        assert!(!edges.contains(&edge2));
        assert!(edges.contains(&edge3));
    }

    #[test]
    fn test_remove_all_for_edge() {
        let map = ChunkAvailabilityMap::new();
        let chunk1 = test_chunk(1);
        let chunk2 = test_chunk(2);
        let chunk3 = test_chunk(3);
        let edge = test_edge(1);
        let other_edge = test_edge(2);

        map.add_chunk(chunk1, edge);
        map.add_chunk(chunk2, edge);
        map.add_chunk(chunk3, edge);
        map.add_chunk(chunk1, other_edge);

        let removed = map.remove_all_for_edge(&edge);

        assert_eq!(removed.len(), 3);
        assert!(removed.contains(&chunk1));
        assert!(removed.contains(&chunk2));
        assert!(removed.contains(&chunk3));
        assert_eq!(map.edge_chunk_count(&edge), 0);

        // chunk1 should still exist on other_edge
        assert_eq!(map.replica_count(&chunk1), 1);
        assert_eq!(map.get_edges(&chunk1), vec![other_edge]);

        // chunk2 and chunk3 should be completely removed
        assert!(!map.has_chunk(&chunk2));
        assert!(!map.has_chunk(&chunk3));
    }

    #[test]
    fn test_remove_all_for_nonexistent_edge() {
        let map = ChunkAvailabilityMap::new();
        let edge = test_edge(1);

        let removed = map.remove_all_for_edge(&edge);
        assert!(removed.is_empty());
    }

    #[test]
    fn test_get_edges_nonexistent() {
        let map = ChunkAvailabilityMap::new();
        let chunk = test_chunk(1);

        let edges = map.get_edges(&chunk);
        assert!(edges.is_empty());
    }

    #[test]
    fn test_get_chunks_nonexistent() {
        let map = ChunkAvailabilityMap::new();
        let edge = test_edge(1);

        let chunks = map.get_chunks(&edge);
        assert!(chunks.is_empty());
    }

    #[test]
    fn test_batch_add_chunks() {
        let map = ChunkAvailabilityMap::new();
        let chunks = vec![test_chunk(1), test_chunk(2), test_chunk(3)];
        let edge = test_edge(1);

        map.add_chunks_batch(&chunks, edge);

        assert_eq!(map.edge_chunk_count(&edge), 3);
        assert_eq!(map.total_unique_chunks(), 3);
        for chunk in &chunks {
            assert!(map.has_chunk(chunk));
            assert_eq!(map.replica_count(chunk), 1);
        }
    }

    #[test]
    fn test_batch_add_empty() {
        let map = ChunkAvailabilityMap::new();
        let chunks: Vec<ChunkHash> = vec![];
        let edge = test_edge(1);

        map.add_chunks_batch(&chunks, edge);

        assert_eq!(map.edge_chunk_count(&edge), 0);
        assert_eq!(map.total_unique_chunks(), 0);
    }

    #[test]
    fn test_batch_remove_chunks() {
        let map = ChunkAvailabilityMap::new();
        let chunks = vec![test_chunk(1), test_chunk(2), test_chunk(3)];
        let edge = test_edge(1);

        map.add_chunks_batch(&chunks, edge);
        map.remove_chunks_batch(&chunks, &edge);

        assert_eq!(map.edge_chunk_count(&edge), 0);
        assert_eq!(map.total_unique_chunks(), 0);
        for chunk in &chunks {
            assert!(!map.has_chunk(chunk));
        }
    }

    #[test]
    fn test_batch_remove_empty() {
        let map = ChunkAvailabilityMap::new();
        let chunks: Vec<ChunkHash> = vec![];
        let edge = test_edge(1);

        map.remove_chunks_batch(&chunks, &edge);
        assert_eq!(map.total_unique_chunks(), 0);
    }

    #[test]
    fn test_batch_remove_nonexistent_edge() {
        let map = ChunkAvailabilityMap::new();
        let chunks = vec![test_chunk(1), test_chunk(2)];
        let edge = test_edge(1);

        map.remove_chunks_batch(&chunks, &edge);
        assert_eq!(map.total_unique_chunks(), 0);
    }

    #[test]
    fn test_total_unique_chunks() {
        let map = ChunkAvailabilityMap::new();

        map.add_chunk(test_chunk(1), test_edge(1));
        assert_eq!(map.total_unique_chunks(), 1);

        map.add_chunk(test_chunk(1), test_edge(2));
        assert_eq!(map.total_unique_chunks(), 1);

        map.add_chunk(test_chunk(2), test_edge(1));
        assert_eq!(map.total_unique_chunks(), 2);
    }

    #[test]
    fn test_total_replicas() {
        let map = ChunkAvailabilityMap::new();

        map.add_chunk(test_chunk(1), test_edge(1));
        assert_eq!(map.total_replicas(), 1);

        map.add_chunk(test_chunk(1), test_edge(2));
        assert_eq!(map.total_replicas(), 2);

        map.add_chunk(test_chunk(2), test_edge(1));
        assert_eq!(map.total_replicas(), 3);

        map.add_chunk(test_chunk(2), test_edge(2));
        assert_eq!(map.total_replicas(), 4);
    }

    #[test]
    fn test_average_replication() {
        let map = ChunkAvailabilityMap::new();

        assert_eq!(map.average_replication(), 0.0);

        map.add_chunk(test_chunk(1), test_edge(1));
        assert_eq!(map.average_replication(), 1.0);

        map.add_chunk(test_chunk(1), test_edge(2));
        assert_eq!(map.average_replication(), 2.0);

        map.add_chunk(test_chunk(2), test_edge(1));
        assert_eq!(map.average_replication(), 1.5);
    }

    #[test]
    fn test_find_under_replicated() {
        let map = ChunkAvailabilityMap::new();
        let chunk1 = test_chunk(1);
        let chunk2 = test_chunk(2);
        let chunk3 = test_chunk(3);

        map.add_chunk(chunk1, test_edge(1));
        map.add_chunk(chunk2, test_edge(1));
        map.add_chunk(chunk2, test_edge(2));
        map.add_chunk(chunk3, test_edge(1));
        map.add_chunk(chunk3, test_edge(2));
        map.add_chunk(chunk3, test_edge(3));

        let under = map.find_under_replicated(3);
        assert_eq!(under.len(), 2);
        assert!(under.contains(&chunk1));
        assert!(under.contains(&chunk2));
        assert!(!under.contains(&chunk3));
    }

    #[test]
    fn test_find_single_replica() {
        let map = ChunkAvailabilityMap::new();
        let chunk1 = test_chunk(1);
        let chunk2 = test_chunk(2);

        map.add_chunk(chunk1, test_edge(1));
        map.add_chunk(chunk2, test_edge(1));
        map.add_chunk(chunk2, test_edge(2));

        let single = map.find_single_replica();
        assert_eq!(single.len(), 1);
        assert!(single.contains(&chunk1));
    }

    #[test]
    fn test_get_location() {
        let map = ChunkAvailabilityMap::new();
        let chunk = test_chunk(1);
        let edge1 = test_edge(1);
        let edge2 = test_edge(2);

        assert!(map.get_location(&chunk).is_none());

        map.add_chunk(chunk, edge1);
        map.add_chunk(chunk, edge2);

        let location = map.get_location(&chunk).unwrap();
        assert_eq!(location.chunk_hash, chunk);
        assert_eq!(location.replica_count, 2);
        assert_eq!(location.edge_ids.len(), 2);
        assert!(location.edge_ids.contains(&edge1));
        assert!(location.edge_ids.contains(&edge2));
    }

    #[test]
    fn test_concurrent_add_same_chunk() {
        let map = Arc::new(ChunkAvailabilityMap::new());
        let chunk = test_chunk(1);

        let handles: Vec<_> = (0..10)
            .map(|i| {
                let map = Arc::clone(&map);
                thread::spawn(move || {
                    let edge = test_edge(i);
                    map.add_chunk(chunk, edge);
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(map.replica_count(&chunk), 10);
        assert_eq!(map.total_unique_chunks(), 1);
        assert_eq!(map.total_replicas(), 10);
    }

    #[test]
    fn test_concurrent_add_different_chunks() {
        let map = Arc::new(ChunkAvailabilityMap::new());
        let edge = test_edge(1);

        let handles: Vec<_> = (0..10)
            .map(|i| {
                let map = Arc::clone(&map);
                thread::spawn(move || {
                    let chunk = test_chunk(i);
                    map.add_chunk(chunk, edge);
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(map.edge_chunk_count(&edge), 10);
        assert_eq!(map.total_unique_chunks(), 10);
        assert_eq!(map.total_replicas(), 10);
    }

    #[test]
    fn test_concurrent_add_and_remove() {
        let map = Arc::new(ChunkAvailabilityMap::new());
        let chunk = test_chunk(1);

        let add_handles: Vec<_> = (0..5)
            .map(|i| {
                let map = Arc::clone(&map);
                thread::spawn(move || {
                    let edge = test_edge(i);
                    map.add_chunk(chunk, edge);
                })
            })
            .collect();

        for handle in add_handles {
            handle.join().unwrap();
        }

        let remove_handles: Vec<_> = (0..3)
            .map(|i| {
                let map = Arc::clone(&map);
                thread::spawn(move || {
                    let edge = test_edge(i);
                    map.remove_chunk(&chunk, &edge);
                })
            })
            .collect();

        for handle in remove_handles {
            handle.join().unwrap();
        }

        assert_eq!(map.replica_count(&chunk), 2);
    }

    #[test]
    fn test_default_trait() {
        let map: ChunkAvailabilityMap = Default::default();
        assert_eq!(map.total_unique_chunks(), 0);
    }

    #[test]
    fn test_edge_id_equality() {
        let edge1 = test_edge(1);
        let edge2 = test_edge(1);
        let edge3 = test_edge(2);

        assert_eq!(edge1, edge2);
        assert_ne!(edge1, edge3);
    }

    #[test]
    fn test_chunk_location_clone() {
        let location = ChunkLocation {
            chunk_hash: test_chunk(1),
            edge_ids: vec![test_edge(1), test_edge(2)],
            replica_count: 2,
        };

        let cloned = location.clone();
        assert_eq!(cloned.chunk_hash, location.chunk_hash);
        assert_eq!(cloned.replica_count, location.replica_count);
        assert_eq!(cloned.edge_ids.len(), location.edge_ids.len());
    }
}
