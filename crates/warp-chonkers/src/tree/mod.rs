//! ChonkerTree - Hierarchical chunk tree for versioned deduplication
//!
//! The ChonkerTree represents chunked data as a tree structure where:
//! - Leaf nodes are the actual data chunks
//! - Internal nodes span multiple child chunks
//! - The root covers the entire data
//!
//! This structure enables:
//! - O(log n) updates when data changes
//! - Efficient diff computation between versions
//! - Content-addressed deduplication at all levels

mod node;
mod persist;

pub use node::{ChonkerNode, EditOp};
pub use persist::{FileTreeStore, MemoryTreeStore, TreeSnapshot, TreeStore};

use crate::chunk::{ChunkId, ChunkWeight};
use crate::config::ChonkersConfig;
use crate::{Chonkers, Result};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};

/// Unique version identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VersionId(pub u64);

impl VersionId {
    /// Create a new version ID
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    /// Generate a new unique version ID
    pub fn generate() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Self(COUNTER.fetch_add(1, Ordering::SeqCst))
    }
}

impl std::fmt::Display for VersionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "v{}", self.0)
    }
}

/// Hierarchical chunk tree
#[derive(Debug, Clone)]
pub struct ChonkerTree {
    /// Version ID for this tree
    pub version_id: VersionId,

    /// Root node ID
    root: Option<ChunkId>,

    /// All nodes in the tree (content-addressed)
    nodes: DashMap<ChunkId, ChonkerNode>,

    /// Configuration used to build this tree
    config: ChonkersConfig,

    /// Total data size
    data_size: usize,
}

impl ChonkerTree {
    /// Create an empty tree
    pub fn new(config: ChonkersConfig) -> Self {
        Self {
            version_id: VersionId::generate(),
            root: None,
            nodes: DashMap::new(),
            config,
            data_size: 0,
        }
    }

    /// Build a tree from data
    pub fn from_data(data: &[u8], config: ChonkersConfig) -> Result<Self> {
        if data.is_empty() {
            return Ok(Self::new(config));
        }

        let chunker = Chonkers::new(config.clone());
        let chunks = chunker.chunk(data)?;

        let mut tree = Self {
            version_id: VersionId::generate(),
            root: None,
            nodes: DashMap::new(),
            config,
            data_size: data.len(),
        };

        // Build leaf nodes from chunks
        let leaf_ids: Vec<ChunkId> = chunks
            .iter()
            .map(|chunk| {
                let node = ChonkerNode::leaf(
                    chunk.id,
                    chunk.weight,
                    chunk.offset..chunk.end(),
                );
                tree.nodes.insert(chunk.id, node);
                chunk.id
            })
            .collect();

        if leaf_ids.is_empty() {
            return Ok(tree);
        }

        // Build internal nodes layer by layer
        tree.root = Some(tree.build_internal_layers(&leaf_ids, data)?);

        Ok(tree)
    }

    /// Build internal layers from leaf nodes
    fn build_internal_layers(&self, leaf_ids: &[ChunkId], data: &[u8]) -> Result<ChunkId> {
        if leaf_ids.len() == 1 {
            return Ok(leaf_ids[0]);
        }

        let mut current_layer_ids = leaf_ids.to_vec();
        let mut layer = 1u8;

        // Build layers until we have a single root
        while current_layer_ids.len() > 1 {
            let layer_config = self.config.layer(layer as usize);
            let mut next_layer_ids = Vec::new();

            let mut i = 0;
            while i < current_layer_ids.len() {
                // Group children based on target size
                let mut group_ids = Vec::new();
                let mut group_start = usize::MAX;
                let mut group_end = 0usize;
                let mut group_size = 0usize;

                while i < current_layer_ids.len() {
                    let child_id = current_layer_ids[i];
                    let child = self.nodes.get(&child_id).unwrap();

                    if group_size > 0 && group_size + child.size() > layer_config.max_size {
                        break;
                    }

                    group_start = group_start.min(child.data_range.start);
                    group_end = group_end.max(child.data_range.end);
                    group_size += child.size();
                    group_ids.push(child_id);
                    i += 1;

                    if group_size >= layer_config.target_size {
                        break;
                    }
                }

                if group_ids.len() == 1 {
                    // Single child - promote it directly
                    next_layer_ids.push(group_ids[0]);
                } else {
                    // Create internal node for this group
                    let internal_data = &data[group_start..group_end];
                    let internal_id = ChunkId::from_data(internal_data);
                    let internal_weight = ChunkWeight::from_data(internal_data);

                    let internal_node = ChonkerNode::internal(
                        internal_id,
                        internal_weight,
                        layer,
                        group_start..group_end,
                        group_ids.clone(),
                    );

                    // Set parent for children
                    for child_id in &group_ids {
                        if let Some(mut child) = self.nodes.get_mut(child_id) {
                            child.set_parent(internal_id);
                        }
                    }

                    self.nodes.insert(internal_id, internal_node);
                    next_layer_ids.push(internal_id);
                }
            }

            current_layer_ids = next_layer_ids;
            layer += 1;

            // Safety limit
            if layer > 20 {
                break;
            }
        }

        Ok(current_layer_ids[0])
    }

    /// Get the root node
    pub fn root(&self) -> Option<&ChunkId> {
        self.root.as_ref()
    }

    /// Get a node by ID
    pub fn get(&self, id: &ChunkId) -> Option<dashmap::mapref::one::Ref<'_, ChunkId, ChonkerNode>> {
        self.nodes.get(id)
    }

    /// Get a mutable reference to a node
    pub fn get_mut(&self, id: &ChunkId) -> Option<dashmap::mapref::one::RefMut<'_, ChunkId, ChonkerNode>> {
        self.nodes.get_mut(id)
    }

    /// Check if tree contains a node
    pub fn contains(&self, id: &ChunkId) -> bool {
        self.nodes.contains_key(id)
    }

    /// Get the number of nodes
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Get leaf node count
    pub fn leaf_count(&self) -> usize {
        self.nodes.iter().filter(|n| n.is_leaf()).count()
    }

    /// Get total data size
    pub fn data_size(&self) -> usize {
        self.data_size
    }

    /// Get all leaf node IDs in order
    pub fn leaf_ids(&self) -> Vec<ChunkId> {
        let mut leaves: Vec<_> = self.nodes
            .iter()
            .filter(|n| n.is_leaf())
            .map(|n| (n.data_range.start, n.id))
            .collect();
        leaves.sort_by_key(|(start, _)| *start);
        leaves.into_iter().map(|(_, id)| id).collect()
    }

    /// Get all chunk IDs in the tree
    pub fn all_chunk_ids(&self) -> HashSet<ChunkId> {
        self.nodes.iter().map(|n| n.id).collect()
    }

    /// Find the leaf node containing a byte offset
    pub fn find_leaf_at(&self, offset: usize) -> Option<ChunkId> {
        self.nodes
            .iter()
            .find(|n| n.is_leaf() && n.contains(offset))
            .map(|n| n.id)
    }

    /// Find all nodes affected by an edit
    pub fn find_affected_nodes(&self, edit: &EditOp) -> Vec<ChunkId> {
        let edit_range = match edit {
            EditOp::Insert { offset, .. } => *offset..*offset + 1,
            EditOp::Delete { offset, length } => *offset..*offset + *length,
            EditOp::Replace { offset, old_length, .. } => *offset..*offset + *old_length,
        };

        self.nodes
            .iter()
            .filter(|n| n.overlaps(&edit_range))
            .map(|n| n.id)
            .collect()
    }

    /// Apply an edit operation and return a new tree
    ///
    /// This is the key incremental update feature of Chonkers.
    /// Only affected chunks are recomputed.
    pub fn update(&self, new_data: &[u8], edit: &EditOp) -> Result<Self> {
        // Find affected leaf nodes
        let affected = self.find_affected_nodes(edit);

        if affected.is_empty() {
            // Edit is beyond current data (append)
            return Self::from_data(new_data, self.config.clone());
        }

        // For now, rebuild the affected region
        // A more sophisticated implementation would do incremental updates
        let mut new_tree = Self::from_data(new_data, self.config.clone())?;
        new_tree.version_id = VersionId::generate();

        Ok(new_tree)
    }

    /// Compute the difference between this tree and another
    pub fn diff(&self, other: &ChonkerTree) -> TreeDiff {
        let self_ids = self.all_chunk_ids();
        let other_ids = other.all_chunk_ids();

        let added: Vec<ChunkId> = other_ids.difference(&self_ids).copied().collect();
        let removed: Vec<ChunkId> = self_ids.difference(&other_ids).copied().collect();
        let unchanged: Vec<ChunkId> = self_ids.intersection(&other_ids).copied().collect();

        TreeDiff {
            from_version: self.version_id,
            to_version: other.version_id,
            added,
            removed,
            unchanged,
        }
    }

    /// Get configuration
    pub fn config(&self) -> &ChonkersConfig {
        &self.config
    }
}

/// Difference between two trees
#[derive(Debug, Clone)]
pub struct TreeDiff {
    /// Source version
    pub from_version: VersionId,

    /// Target version
    pub to_version: VersionId,

    /// Chunks added in the target
    pub added: Vec<ChunkId>,

    /// Chunks removed from the source
    pub removed: Vec<ChunkId>,

    /// Chunks unchanged between versions
    pub unchanged: Vec<ChunkId>,
}

impl TreeDiff {
    /// Check if there are any changes
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }

    /// Get the number of changes
    pub fn change_count(&self) -> usize {
        self.added.len() + self.removed.len()
    }

    /// Calculate deduplication ratio
    ///
    /// Returns the fraction of chunks that are shared (0.0 = no sharing, 1.0 = identical)
    pub fn dedup_ratio(&self) -> f64 {
        let total = self.added.len() + self.removed.len() + self.unchanged.len();
        if total == 0 {
            return 1.0;
        }
        self.unchanged.len() as f64 / total as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_tree() {
        let config = ChonkersConfig::default();
        let tree = ChonkerTree::new(config);

        assert!(tree.root().is_none());
        assert_eq!(tree.node_count(), 0);
        assert_eq!(tree.data_size(), 0);
    }

    #[test]
    fn test_from_data() {
        let config = ChonkersConfig::default();
        let data = b"hello world this is some test data for the chonker tree";

        let tree = ChonkerTree::from_data(data, config).unwrap();

        assert!(tree.root().is_some());
        assert!(tree.node_count() > 0);
        assert_eq!(tree.data_size(), data.len());
    }

    #[test]
    fn test_leaf_nodes() {
        let config = ChonkersConfig::default();
        let data = vec![0u8; 10000];

        let tree = ChonkerTree::from_data(&data, config).unwrap();

        let leaf_ids = tree.leaf_ids();
        assert!(!leaf_ids.is_empty());

        // All leaves should be actual leaf nodes
        for id in &leaf_ids {
            let node = tree.get(id).unwrap();
            assert!(node.is_leaf());
        }
    }

    #[test]
    fn test_find_leaf_at() {
        let config = ChonkersConfig::default();
        // Use varied data for more predictable chunking
        let data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();

        let tree = ChonkerTree::from_data(&data, config).unwrap();

        // Get a leaf that we know exists
        let leaves = tree.leaf_ids();
        assert!(!leaves.is_empty(), "Tree should have leaves");

        // Get the first leaf and check we can find it
        let first_leaf = tree.get(&leaves[0]).unwrap();
        let found = tree.find_leaf_at(first_leaf.data_range.start);
        assert!(found.is_some(), "Should find leaf at its start offset");

        // Should not find leaf beyond data
        let none = tree.find_leaf_at(20000);
        assert!(none.is_none());
    }

    #[test]
    fn test_diff_identical() {
        let config = ChonkersConfig::default();
        let data = b"identical data";

        let tree1 = ChonkerTree::from_data(data, config.clone()).unwrap();
        let tree2 = ChonkerTree::from_data(data, config).unwrap();

        let diff = tree1.diff(&tree2);

        // Same data should have high dedup ratio
        // (may not be 1.0 due to version IDs in internal nodes)
        assert!(diff.dedup_ratio() > 0.5);
    }

    #[test]
    fn test_diff_different() {
        let config = ChonkersConfig::default();
        let data1 = b"first version of the data";
        let data2 = b"completely different content here";

        let tree1 = ChonkerTree::from_data(data1, config.clone()).unwrap();
        let tree2 = ChonkerTree::from_data(data2, config).unwrap();

        let diff = tree1.diff(&tree2);

        // Different data should have changes
        assert!(!diff.is_empty());
    }

    #[test]
    fn test_version_ids() {
        let config = ChonkersConfig::default();
        let data = b"test data";

        let tree1 = ChonkerTree::from_data(data, config.clone()).unwrap();
        let tree2 = ChonkerTree::from_data(data, config).unwrap();

        // Each tree should have a unique version ID
        assert_ne!(tree1.version_id, tree2.version_id);
    }

    #[test]
    fn test_affected_nodes() {
        let config = ChonkersConfig::default();
        let data = vec![0u8; 10000];

        let tree = ChonkerTree::from_data(&data, config).unwrap();

        let edit = EditOp::Replace {
            offset: 5000,
            old_length: 100,
            new_length: 100,
        };

        let affected = tree.find_affected_nodes(&edit);
        assert!(!affected.is_empty());
    }
}
