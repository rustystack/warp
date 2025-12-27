//! Delta computation between versions
//!
//! Provides efficient delta computation between ChonkerTree versions
//! for incremental synchronization and storage.

use crate::chunk::ChunkId;
use crate::tree::{ChonkerTree, VersionId};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Represents the difference between two versions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delta {
    /// Source version
    pub from_version: VersionId,

    /// Target version
    pub to_version: VersionId,

    /// Chunks added in target (need to be sent/stored)
    pub added: Vec<ChunkId>,

    /// Chunks removed from source (can be garbage collected)
    pub removed: Vec<ChunkId>,

    /// Chunks that moved position but are unchanged
    pub moved: Vec<ChunkMove>,

    /// Chunks unchanged between versions
    pub unchanged: Vec<ChunkId>,

    /// Summary statistics
    pub stats: DeltaStats,
}

/// A chunk that moved position
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkMove {
    /// Chunk ID
    pub chunk_id: ChunkId,

    /// Old byte offset
    pub old_offset: usize,

    /// New byte offset
    pub new_offset: usize,
}

/// Statistics about a delta
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeltaStats {
    /// Total chunks in source
    pub source_chunks: usize,

    /// Total chunks in target
    pub target_chunks: usize,

    /// Number of added chunks
    pub added_count: usize,

    /// Number of removed chunks
    pub removed_count: usize,

    /// Number of moved chunks
    pub moved_count: usize,

    /// Number of unchanged chunks
    pub unchanged_count: usize,

    /// Bytes added
    pub bytes_added: usize,

    /// Bytes removed
    pub bytes_removed: usize,

    /// Deduplication ratio (0.0 = no sharing, 1.0 = identical)
    pub dedup_ratio: f64,
}

impl Delta {
    /// Compute the delta between two trees
    pub fn compute(from: &ChonkerTree, to: &ChonkerTree) -> Self {
        let from_ids = from.all_chunk_ids();
        let to_ids = to.all_chunk_ids();

        // Find added and removed chunks
        let added: Vec<ChunkId> = to_ids.difference(&from_ids).copied().collect();
        let removed: Vec<ChunkId> = from_ids.difference(&to_ids).copied().collect();
        let unchanged: Vec<ChunkId> = from_ids.intersection(&to_ids).copied().collect();

        // Build offset maps for move detection
        let from_offsets = Self::build_offset_map(from);
        let to_offsets = Self::build_offset_map(to);

        // Detect moves (chunks present in both but at different offsets)
        let moved: Vec<ChunkMove> = unchanged
            .iter()
            .filter_map(|id| {
                let old_offset = from_offsets.get(id)?;
                let new_offset = to_offsets.get(id)?;
                if old_offset != new_offset {
                    Some(ChunkMove {
                        chunk_id: *id,
                        old_offset: *old_offset,
                        new_offset: *new_offset,
                    })
                } else {
                    None
                }
            })
            .collect();

        // Compute statistics
        let stats = DeltaStats {
            source_chunks: from_ids.len(),
            target_chunks: to_ids.len(),
            added_count: added.len(),
            removed_count: removed.len(),
            moved_count: moved.len(),
            unchanged_count: unchanged.len(),
            bytes_added: Self::compute_bytes(to, &added),
            bytes_removed: Self::compute_bytes(from, &removed),
            dedup_ratio: Self::compute_dedup_ratio(&unchanged, &added, &removed),
        };

        Delta {
            from_version: from.version_id,
            to_version: to.version_id,
            added,
            removed,
            moved,
            unchanged,
            stats,
        }
    }

    /// Build a map of chunk ID to byte offset
    fn build_offset_map(tree: &ChonkerTree) -> HashMap<ChunkId, usize> {
        let mut map = HashMap::new();
        for id in tree.leaf_ids() {
            if let Some(node) = tree.get(&id) {
                map.insert(id, node.data_range.start);
            }
        }
        map
    }

    /// Compute total bytes for a set of chunks
    fn compute_bytes(tree: &ChonkerTree, chunk_ids: &[ChunkId]) -> usize {
        chunk_ids
            .iter()
            .filter_map(|id| tree.get(id))
            .map(|node| node.size())
            .sum()
    }

    /// Compute deduplication ratio
    fn compute_dedup_ratio(
        unchanged: &[ChunkId],
        added: &[ChunkId],
        removed: &[ChunkId],
    ) -> f64 {
        let total = unchanged.len() + added.len() + removed.len();
        if total == 0 {
            return 1.0;
        }
        unchanged.len() as f64 / total as f64
    }

    /// Check if there are any changes
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }

    /// Get total number of changes
    pub fn change_count(&self) -> usize {
        self.added.len() + self.removed.len()
    }

    /// Get the set of chunks that need to be transferred
    /// (added chunks that aren't available at the destination)
    pub fn transfer_set(&self) -> &[ChunkId] {
        &self.added
    }

    /// Invert the delta (swap from/to)
    pub fn invert(&self) -> Self {
        Delta {
            from_version: self.to_version,
            to_version: self.from_version,
            added: self.removed.clone(),
            removed: self.added.clone(),
            moved: self
                .moved
                .iter()
                .map(|m| ChunkMove {
                    chunk_id: m.chunk_id,
                    old_offset: m.new_offset,
                    new_offset: m.old_offset,
                })
                .collect(),
            unchanged: self.unchanged.clone(),
            stats: DeltaStats {
                source_chunks: self.stats.target_chunks,
                target_chunks: self.stats.source_chunks,
                added_count: self.stats.removed_count,
                removed_count: self.stats.added_count,
                moved_count: self.stats.moved_count,
                unchanged_count: self.stats.unchanged_count,
                bytes_added: self.stats.bytes_removed,
                bytes_removed: self.stats.bytes_added,
                dedup_ratio: self.stats.dedup_ratio,
            },
        }
    }
}

impl DeltaStats {
    /// Check if versions are identical
    pub fn is_identical(&self) -> bool {
        self.added_count == 0 && self.removed_count == 0
    }

    /// Get the change ratio (how much changed)
    pub fn change_ratio(&self) -> f64 {
        1.0 - self.dedup_ratio
    }
}

/// Builder for creating deltas with additional options
#[derive(Debug, Clone)]
pub struct DeltaBuilder {
    /// Whether to track chunk moves
    track_moves: bool,

    /// Whether to compute byte statistics
    compute_bytes: bool,

    /// Filter for which chunk types to include
    include_internal: bool,
}

impl Default for DeltaBuilder {
    fn default() -> Self {
        Self {
            track_moves: true,
            compute_bytes: true,
            include_internal: false,
        }
    }
}

impl DeltaBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Disable move tracking (faster)
    pub fn without_moves(mut self) -> Self {
        self.track_moves = false;
        self
    }

    /// Disable byte statistics (faster)
    pub fn without_bytes(mut self) -> Self {
        self.compute_bytes = false;
        self
    }

    /// Include internal nodes in delta
    pub fn include_internal(mut self) -> Self {
        self.include_internal = true;
        self
    }

    /// Compute delta with configured options
    pub fn compute(&self, from: &ChonkerTree, to: &ChonkerTree) -> Delta {
        let from_ids: HashSet<ChunkId> = if self.include_internal {
            from.all_chunk_ids()
        } else {
            from.leaf_ids().into_iter().collect()
        };

        let to_ids: HashSet<ChunkId> = if self.include_internal {
            to.all_chunk_ids()
        } else {
            to.leaf_ids().into_iter().collect()
        };

        let added: Vec<ChunkId> = to_ids.difference(&from_ids).copied().collect();
        let removed: Vec<ChunkId> = from_ids.difference(&to_ids).copied().collect();
        let unchanged: Vec<ChunkId> = from_ids.intersection(&to_ids).copied().collect();

        let moved = if self.track_moves {
            let from_offsets = Delta::build_offset_map(from);
            let to_offsets = Delta::build_offset_map(to);

            unchanged
                .iter()
                .filter_map(|id| {
                    let old_offset = from_offsets.get(id)?;
                    let new_offset = to_offsets.get(id)?;
                    if old_offset != new_offset {
                        Some(ChunkMove {
                            chunk_id: *id,
                            old_offset: *old_offset,
                            new_offset: *new_offset,
                        })
                    } else {
                        None
                    }
                })
                .collect()
        } else {
            Vec::new()
        };

        let (bytes_added, bytes_removed) = if self.compute_bytes {
            (
                Delta::compute_bytes(to, &added),
                Delta::compute_bytes(from, &removed),
            )
        } else {
            (0, 0)
        };

        let stats = DeltaStats {
            source_chunks: from_ids.len(),
            target_chunks: to_ids.len(),
            added_count: added.len(),
            removed_count: removed.len(),
            moved_count: moved.len(),
            unchanged_count: unchanged.len(),
            bytes_added,
            bytes_removed,
            dedup_ratio: Delta::compute_dedup_ratio(&unchanged, &added, &removed),
        };

        Delta {
            from_version: from.version_id,
            to_version: to.version_id,
            added,
            removed,
            moved,
            unchanged,
            stats,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ChonkersConfig;

    fn make_tree(data: &[u8]) -> ChonkerTree {
        ChonkerTree::from_data(data, ChonkersConfig::default()).unwrap()
    }

    #[test]
    fn test_delta_identical() {
        let data = b"identical data for both versions";
        let tree1 = make_tree(data);
        let tree2 = make_tree(data);

        let delta = Delta::compute(&tree1, &tree2);

        assert!(delta.stats.dedup_ratio > 0.5);
        assert_eq!(delta.stats.added_count, delta.added.len());
        assert_eq!(delta.stats.removed_count, delta.removed.len());
    }

    #[test]
    fn test_delta_different() {
        let tree1 = make_tree(b"first version data");
        let tree2 = make_tree(b"second version data");

        let delta = Delta::compute(&tree1, &tree2);

        assert!(!delta.is_empty());
        assert!(delta.change_count() > 0);
    }

    #[test]
    fn test_delta_invert() {
        let tree1 = make_tree(b"original data");
        let tree2 = make_tree(b"modified data");

        let delta = Delta::compute(&tree1, &tree2);
        let inverted = delta.invert();

        assert_eq!(delta.from_version, inverted.to_version);
        assert_eq!(delta.to_version, inverted.from_version);
        assert_eq!(delta.added, inverted.removed);
        assert_eq!(delta.removed, inverted.added);
    }

    #[test]
    fn test_delta_stats() {
        let tree1 = make_tree(b"data version one");
        let tree2 = make_tree(b"data version two plus extra");

        let delta = Delta::compute(&tree1, &tree2);

        assert_eq!(
            delta.stats.unchanged_count,
            delta.unchanged.len()
        );
        assert_eq!(delta.stats.added_count, delta.added.len());
        assert_eq!(delta.stats.removed_count, delta.removed.len());
    }

    #[test]
    fn test_delta_builder_without_moves() {
        let tree1 = make_tree(b"some data here");
        let tree2 = make_tree(b"some different data");

        let delta = DeltaBuilder::new()
            .without_moves()
            .compute(&tree1, &tree2);

        assert!(delta.moved.is_empty());
    }

    #[test]
    fn test_delta_builder_without_bytes() {
        let tree1 = make_tree(b"data version one");
        let tree2 = make_tree(b"data version two");

        let delta = DeltaBuilder::new()
            .without_bytes()
            .compute(&tree1, &tree2);

        assert_eq!(delta.stats.bytes_added, 0);
        assert_eq!(delta.stats.bytes_removed, 0);
    }

    #[test]
    fn test_delta_empty_trees() {
        let config = ChonkersConfig::default();
        let tree1 = ChonkerTree::new(config.clone());
        let tree2 = ChonkerTree::new(config);

        let delta = Delta::compute(&tree1, &tree2);

        assert!(delta.is_empty());
        assert!(delta.stats.is_identical());
    }

    #[test]
    fn test_transfer_set() {
        let tree1 = make_tree(b"original");
        let tree2 = make_tree(b"modified version");

        let delta = Delta::compute(&tree1, &tree2);
        let transfer = delta.transfer_set();

        assert_eq!(transfer.len(), delta.added.len());
    }
}
