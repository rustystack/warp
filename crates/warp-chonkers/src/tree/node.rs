//! ChonkerNode - Hierarchical chunk representation
//!
//! Each node in the ChonkerTree represents a chunk at a specific layer.
//! Nodes form a tree structure where higher layers contain larger chunks
//! that span multiple lower-layer chunks.

use crate::chunk::{ChunkId, ChunkWeight};
use serde::{Deserialize, Serialize};
use std::ops::Range;

/// A node in the ChonkerTree hierarchy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChonkerNode {
    /// Content-addressed chunk ID
    pub id: ChunkId,

    /// Priority weight for boundary decisions
    pub weight: ChunkWeight,

    /// Layer index (0 = leaf, higher = coarser)
    pub layer: u8,

    /// Byte range in the original data [start, end)
    pub data_range: Range<usize>,

    /// Children node IDs (empty for leaf nodes)
    pub children: Vec<ChunkId>,

    /// Parent node ID (None for root)
    pub parent: Option<ChunkId>,

    /// Whether this node has been modified since last sync
    pub dirty: bool,
}

impl ChonkerNode {
    /// Create a new leaf node
    pub fn leaf(id: ChunkId, weight: ChunkWeight, data_range: Range<usize>) -> Self {
        Self {
            id,
            weight,
            layer: 0,
            data_range,
            children: Vec::new(),
            parent: None,
            dirty: true,
        }
    }

    /// Create a new internal node
    pub fn internal(
        id: ChunkId,
        weight: ChunkWeight,
        layer: u8,
        data_range: Range<usize>,
        children: Vec<ChunkId>,
    ) -> Self {
        Self {
            id,
            weight,
            layer,
            data_range,
            children,
            parent: None,
            dirty: true,
        }
    }

    /// Check if this is a leaf node
    pub fn is_leaf(&self) -> bool {
        self.children.is_empty()
    }

    /// Check if this is a root node
    pub fn is_root(&self) -> bool {
        self.parent.is_none()
    }

    /// Get the size of data covered by this node
    pub fn size(&self) -> usize {
        self.data_range.end - self.data_range.start
    }

    /// Check if this node contains a byte offset
    pub fn contains(&self, offset: usize) -> bool {
        self.data_range.contains(&offset)
    }

    /// Check if this node overlaps with a byte range
    pub fn overlaps(&self, range: &Range<usize>) -> bool {
        self.data_range.start < range.end && range.start < self.data_range.end
    }

    /// Set the parent node
    pub fn set_parent(&mut self, parent_id: ChunkId) {
        self.parent = Some(parent_id);
        self.dirty = true;
    }

    /// Mark as clean (synced)
    pub fn mark_clean(&mut self) {
        self.dirty = false;
    }

    /// Add a child node
    pub fn add_child(&mut self, child_id: ChunkId) {
        self.children.push(child_id);
        self.dirty = true;
    }

    /// Remove a child node
    pub fn remove_child(&mut self, child_id: &ChunkId) -> bool {
        if let Some(pos) = self.children.iter().position(|id| id == child_id) {
            self.children.remove(pos);
            self.dirty = true;
            true
        } else {
            false
        }
    }
}

impl PartialEq for ChonkerNode {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for ChonkerNode {}

impl std::hash::Hash for ChonkerNode {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.0.hash(state);
    }
}

/// Edit operation on the tree
#[derive(Debug, Clone)]
pub enum EditOp {
    /// Insert bytes at offset
    Insert {
        /// Byte offset where insertion happens
        offset: usize,
        /// Number of bytes inserted
        length: usize,
    },

    /// Delete bytes starting at offset
    Delete {
        /// Byte offset where deletion starts
        offset: usize,
        /// Number of bytes deleted
        length: usize,
    },

    /// Replace bytes in a range
    Replace {
        /// Start offset of replacement
        offset: usize,
        /// Original length being replaced
        old_length: usize,
        /// New length after replacement
        new_length: usize,
    },
}

impl EditOp {
    /// Get the offset where the edit starts
    pub fn offset(&self) -> usize {
        match self {
            EditOp::Insert { offset, .. } => *offset,
            EditOp::Delete { offset, .. } => *offset,
            EditOp::Replace { offset, .. } => *offset,
        }
    }

    /// Calculate how this edit affects offsets after the edit point
    pub fn offset_delta(&self) -> isize {
        match self {
            EditOp::Insert { length, .. } => *length as isize,
            EditOp::Delete { length, .. } => -(*length as isize),
            EditOp::Replace {
                old_length,
                new_length,
                ..
            } => *new_length as isize - *old_length as isize,
        }
    }

    /// Check if an offset is affected by this edit
    pub fn affects_offset(&self, offset: usize) -> bool {
        offset >= self.offset()
    }

    /// Check if a range is affected by this edit
    pub fn affects_range(&self, range: &Range<usize>) -> bool {
        match self {
            EditOp::Insert { offset, .. } => *offset <= range.end,
            EditOp::Delete { offset, length } => {
                let delete_end = offset + length;
                *offset < range.end && delete_end > range.start
            }
            EditOp::Replace {
                offset, old_length, ..
            } => {
                let replace_end = offset + old_length;
                *offset < range.end && replace_end > range.start
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_id() -> ChunkId {
        ChunkId::from_data(b"test")
    }

    #[test]
    fn test_leaf_node() {
        let node = ChonkerNode::leaf(test_id(), ChunkWeight::new(100), 0..1000);

        assert!(node.is_leaf());
        assert!(node.is_root());
        assert_eq!(node.layer, 0);
        assert_eq!(node.size(), 1000);
    }

    #[test]
    fn test_internal_node() {
        let child1 = ChunkId::from_data(b"child1");
        let child2 = ChunkId::from_data(b"child2");

        let node = ChonkerNode::internal(
            test_id(),
            ChunkWeight::new(200),
            1,
            0..2000,
            vec![child1, child2],
        );

        assert!(!node.is_leaf());
        assert_eq!(node.children.len(), 2);
        assert_eq!(node.layer, 1);
    }

    #[test]
    fn test_contains() {
        let node = ChonkerNode::leaf(test_id(), ChunkWeight::new(100), 100..200);

        assert!(!node.contains(99));
        assert!(node.contains(100));
        assert!(node.contains(150));
        assert!(node.contains(199));
        assert!(!node.contains(200));
    }

    #[test]
    fn test_overlaps() {
        let node = ChonkerNode::leaf(test_id(), ChunkWeight::new(100), 100..200);

        assert!(!node.overlaps(&(0..100)));
        assert!(node.overlaps(&(50..150)));
        assert!(node.overlaps(&(100..200)));
        assert!(node.overlaps(&(150..250)));
        assert!(!node.overlaps(&(200..300)));
    }

    #[test]
    fn test_edit_op_insert() {
        let edit = EditOp::Insert {
            offset: 100,
            length: 50,
        };

        assert_eq!(edit.offset(), 100);
        assert_eq!(edit.offset_delta(), 50);
        assert!(!edit.affects_offset(99));
        assert!(edit.affects_offset(100));
        assert!(edit.affects_offset(200));
    }

    #[test]
    fn test_edit_op_delete() {
        let edit = EditOp::Delete {
            offset: 100,
            length: 50,
        };

        assert_eq!(edit.offset(), 100);
        assert_eq!(edit.offset_delta(), -50);
        assert!(edit.affects_range(&(50..150)));
        assert!(edit.affects_range(&(100..200)));
        assert!(!edit.affects_range(&(150..200)));
    }

    #[test]
    fn test_parent_child() {
        let parent_id = ChunkId::from_data(b"parent");
        let child_id = ChunkId::from_data(b"child");

        let mut node = ChonkerNode::leaf(test_id(), ChunkWeight::new(100), 0..100);
        assert!(node.is_root());

        node.set_parent(parent_id);
        assert!(!node.is_root());
        assert_eq!(node.parent, Some(parent_id));

        node.add_child(child_id);
        assert!(!node.is_leaf());
        assert_eq!(node.children.len(), 1);

        assert!(node.remove_child(&child_id));
        assert!(node.is_leaf());
    }
}
