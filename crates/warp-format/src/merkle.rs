//! Merkle implementation
//!
//! This module provides two Merkle tree implementations:
//! - `MerkleTree`: Standard tree that stores all nodes in memory
//! - `SparseMerkleTree`: Lazy tree with caching for large archives (millions of chunks)

use rayon::prelude::*;
use std::collections::{HashMap, VecDeque};
use std::sync::RwLock;

/// Merkle tree for content verification
pub struct MerkleTree {
    /// Leaf hashes (chunk hashes)
    leaves: Vec<[u8; 32]>,
    /// Internal nodes (computed)
    nodes: Vec<[u8; 32]>,
}

impl MerkleTree {
    /// Create a new Merkle tree from chunk hashes
    pub fn from_leaves(leaves: Vec<[u8; 32]>) -> Self {
        let nodes = Self::build_tree(&leaves);
        Self { leaves, nodes }
    }

    /// Get the root hash
    pub fn root(&self) -> [u8; 32] {
        self.nodes.last().copied().unwrap_or([0u8; 32])
    }

    /// Generate a proof for a specific leaf
    ///
    /// Returns a vector of sibling hashes along the path from leaf to root.
    /// These are the hashes needed to reconstruct the root given the leaf.
    pub fn proof(&self, leaf_index: usize) -> Vec<[u8; 32]> {
        if leaf_index >= self.leaves.len() {
            return Vec::new();
        }

        let mut proof = Vec::new();
        let mut index = leaf_index;
        let mut level_start = 0;
        let mut level_size = self.leaves.len();

        // Walk up the tree, collecting sibling hashes
        while level_size > 1 {
            // Find the sibling index
            let sibling_index = if index % 2 == 0 {
                // Left child, sibling is right
                index + 1
            } else {
                // Right child, sibling is left
                index - 1
            };

            // Get the sibling hash
            let sibling_node_index = level_start + sibling_index;
            if sibling_index < level_size {
                proof.push(self.nodes[sibling_node_index]);
            } else {
                // Odd number of nodes - duplicate the last one
                proof.push(self.nodes[level_start + index]);
            }

            // Move to parent level
            index /= 2;
            level_start += level_size;
            level_size = (level_size + 1) / 2;
        }

        proof
    }

    /// Verify a proof
    ///
    /// Given a leaf hash, a proof (sibling path), the expected root,
    /// and the leaf index, verify that the leaf belongs to the tree.
    pub fn verify_proof(
        leaf: &[u8; 32],
        proof: &[[u8; 32]],
        root: &[u8; 32],
        leaf_index: usize,
    ) -> bool {
        let mut current_hash = *leaf;
        let mut current_index = leaf_index;

        // Walk up the tree, combining with siblings
        for sibling in proof {
            current_hash = if current_index % 2 == 0 {
                // Current is left, sibling is right
                hash_pair(&current_hash, sibling)
            } else {
                // Current is right, sibling is left
                hash_pair(sibling, &current_hash)
            };
            current_index /= 2;
        }

        // Check if we reached the expected root
        current_hash == *root
    }

    fn build_tree(leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
        if leaves.is_empty() {
            return vec![[0u8; 32]];
        }

        let mut nodes = leaves.to_vec();
        let mut level_start = 0;
        let mut level_size = leaves.len();

        while level_size > 1 {
            let next_level_size = (level_size + 1) / 2;

            for i in 0..next_level_size {
                let left_idx = level_start + i * 2;
                let right_idx = left_idx + 1;

                let left = nodes[left_idx];
                let right = if right_idx < level_start + level_size {
                    nodes[right_idx]
                } else {
                    left // Duplicate last node if odd
                };

                nodes.push(hash_pair(&left, &right));
            }

            level_start += level_size;
            level_size = next_level_size;
        }

        nodes
    }
}

fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(left);
    combined[32..].copy_from_slice(right);
    warp_hash::hash(&combined)
}

// ============================================================================
// Sparse Merkle Tree Implementation
// ============================================================================

/// LRU cache for intermediate Merkle tree nodes
///
/// Stores computed internal nodes keyed by (level, index) to avoid
/// recomputation during repeated verifications.
struct NodeCache {
    /// Cached nodes: (level, index) -> hash
    nodes: HashMap<(usize, usize), [u8; 32]>,
    /// Maximum number of entries to cache
    max_size: usize,
    /// Access order for LRU eviction (front = LRU, back = MRU)
    /// Using VecDeque for O(1) pop_front during eviction
    access_order: VecDeque<(usize, usize)>,
}

impl NodeCache {
    /// Create a new cache with the specified maximum size
    fn new(max_size: usize) -> Self {
        Self {
            nodes: HashMap::with_capacity(max_size),
            max_size,
            access_order: VecDeque::with_capacity(max_size),
        }
    }

    /// Get a node from cache, updating access order
    fn get(&mut self, key: &(usize, usize)) -> Option<[u8; 32]> {
        if let Some(&hash) = self.nodes.get(key) {
            // Move to back of access order (most recently used)
            // VecDeque::remove is O(n) but shifts from closer end
            if let Some(pos) = self.access_order.iter().position(|k| k == key) {
                self.access_order.remove(pos);
                self.access_order.push_back(*key);
            }
            Some(hash)
        } else {
            None
        }
    }

    /// Insert a node into cache, evicting LRU if necessary
    fn insert(&mut self, key: (usize, usize), hash: [u8; 32]) {
        // Check if already present
        if self.nodes.contains_key(&key) {
            // Update and move to back
            self.nodes.insert(key, hash);
            if let Some(pos) = self.access_order.iter().position(|k| *k == key) {
                self.access_order.remove(pos);
            }
            self.access_order.push_back(key);
            return;
        }

        // Evict LRU if at capacity - O(1) with VecDeque
        while self.nodes.len() >= self.max_size && !self.access_order.is_empty() {
            if let Some(lru_key) = self.access_order.pop_front() {
                self.nodes.remove(&lru_key);
            }
        }

        // Insert new entry
        self.nodes.insert(key, hash);
        self.access_order.push_back(key);
    }

    /// Get cache hit statistics
    #[allow(dead_code)]
    fn len(&self) -> usize {
        self.nodes.len()
    }
}

/// Compact Merkle proof for single chunk verification
///
/// Contains only the sibling hashes needed to reconstruct the path
/// from a leaf to the root.
#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// Sibling hashes from leaf to root
    pub siblings: Vec<[u8; 32]>,
    /// Index of the leaf being proven
    pub leaf_index: usize,
    /// Direction bits: false = current is left, true = current is right
    pub directions: Vec<bool>,
}

impl MerkleProof {
    /// Verify this proof against a leaf hash and expected root
    pub fn verify(&self, leaf_hash: &[u8; 32], expected_root: &[u8; 32]) -> bool {
        if self.siblings.len() != self.directions.len() {
            return false;
        }

        let mut current = *leaf_hash;

        for (sibling, &is_right) in self.siblings.iter().zip(self.directions.iter()) {
            current = if is_right {
                // Current node is right child
                hash_pair(sibling, &current)
            } else {
                // Current node is left child
                hash_pair(&current, sibling)
            };
        }

        current == *expected_root
    }

    /// Get the number of levels in this proof (tree height)
    pub fn height(&self) -> usize {
        self.siblings.len()
    }
}

/// Sparse Merkle tree with lazy computation and caching
///
/// Unlike `MerkleTree` which stores all internal nodes, `SparseMerkleTree`
/// only stores leaf hashes and computes/caches internal nodes on demand.
/// This is more memory-efficient for large archives with millions of chunks.
///
/// # Performance Characteristics
/// - Construction: O(n) with parallel root computation
/// - Memory: O(n) for leaves + O(cache_size) for internal nodes
/// - Single verification: O(log n)
/// - Proof generation: O(log n)
///
/// # Example
/// ```
/// use warp_format::merkle::SparseMerkleTree;
///
/// let leaves: Vec<[u8; 32]> = (0..1000)
///     .map(|i| {
///         let mut h = [0u8; 32];
///         h[0] = i as u8;
///         h
///     })
///     .collect();
///
/// let tree = SparseMerkleTree::from_leaves(leaves);
///
/// // Verify a single chunk
/// let mut test_hash = [0u8; 32];
/// test_hash[0] = 42;
/// assert!(tree.verify_chunk(42, &test_hash));
/// ```
pub struct SparseMerkleTree {
    /// Leaf hashes (always stored)
    leaves: Vec<[u8; 32]>,
    /// Cached intermediate nodes
    cache: RwLock<NodeCache>,
    /// Pre-computed root hash
    root: [u8; 32],
    /// Tree height (log2 of leaf count, rounded up)
    height: usize,
}

impl SparseMerkleTree {
    /// Create a sparse Merkle tree from leaf hashes
    ///
    /// Uses parallel computation for the root hash, which provides
    /// significant speedup for large numbers of leaves.
    pub fn from_leaves(leaves: Vec<[u8; 32]>) -> Self {
        Self::from_leaves_with_cache_size(leaves, 1000)
    }

    /// Create a sparse Merkle tree with a custom cache size
    ///
    /// Larger cache sizes improve repeated verification performance
    /// at the cost of memory.
    pub fn from_leaves_with_cache_size(leaves: Vec<[u8; 32]>, cache_size: usize) -> Self {
        let height = if leaves.is_empty() {
            0
        } else {
            (leaves.len() as f64).log2().ceil() as usize
        };

        let root = Self::compute_root_parallel(&leaves);

        Self {
            leaves,
            cache: RwLock::new(NodeCache::new(cache_size)),
            root,
            height,
        }
    }

    /// Get the root hash
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Get the number of leaves
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    /// Get the tree height
    pub fn height(&self) -> usize {
        self.height
    }

    /// Verify a single chunk without full tree traversal
    ///
    /// This is O(log n) - only computes the path from leaf to root.
    pub fn verify_chunk(&self, index: usize, chunk_hash: &[u8; 32]) -> bool {
        if index >= self.leaves.len() {
            return false;
        }

        // Check leaf hash matches
        if self.leaves[index] != *chunk_hash {
            return false;
        }

        // Generate proof and verify
        let proof = self.generate_proof(index);
        proof.verify(chunk_hash, &self.root)
    }

    /// Generate a compact proof for a leaf
    ///
    /// The proof contains only the sibling hashes needed to reconstruct
    /// the path from leaf to root.
    pub fn generate_proof(&self, leaf_index: usize) -> MerkleProof {
        if leaf_index >= self.leaves.len() {
            return MerkleProof {
                siblings: Vec::new(),
                leaf_index,
                directions: Vec::new(),
            };
        }

        let mut siblings = Vec::with_capacity(self.height);
        let mut directions = Vec::with_capacity(self.height);
        let mut index = leaf_index;
        let mut level_size = self.leaves.len();

        for level in 0..self.height {
            if level_size <= 1 {
                break;
            }

            // Determine if current is left or right child
            let is_right = index % 2 == 1;
            directions.push(is_right);

            // Get sibling index
            let sibling_index = if is_right { index - 1 } else { index + 1 };

            // Get sibling hash
            let sibling_hash = if sibling_index < level_size {
                self.get_node_at_level(level, sibling_index)
            } else {
                // Odd number of nodes - sibling is same as current
                self.get_node_at_level(level, index)
            };

            siblings.push(sibling_hash);

            // Move to parent
            index /= 2;
            level_size = (level_size + 1) / 2;
        }

        MerkleProof {
            siblings,
            leaf_index,
            directions,
        }
    }

    /// Randomly verify a sample of chunks for integrity checking
    ///
    /// Returns (verified_count, total_sampled).
    pub fn verify_random_sample(&self, sample_size: usize) -> (usize, usize) {
        use rand::seq::SliceRandom;

        if self.leaves.is_empty() {
            return (0, 0);
        }

        let actual_sample = sample_size.min(self.leaves.len());
        let mut rng = rand::thread_rng();

        // Select random indices
        let indices: Vec<usize> = (0..self.leaves.len())
            .collect::<Vec<_>>()
            .choose_multiple(&mut rng, actual_sample)
            .copied()
            .collect();

        let verified = indices
            .iter()
            .filter(|&&i| self.verify_chunk(i, &self.leaves[i]))
            .count();

        (verified, actual_sample)
    }

    /// Convert to legacy MerkleTree (for compatibility)
    pub fn to_legacy(&self) -> MerkleTree {
        MerkleTree::from_leaves(self.leaves.clone())
    }

    /// Get a node at a specific level and index
    ///
    /// Level 0 = leaves, level 1 = first internal level, etc.
    fn get_node_at_level(&self, level: usize, index: usize) -> [u8; 32] {
        // Level 0 is leaves
        if level == 0 {
            return self.leaves.get(index).copied().unwrap_or([0u8; 32]);
        }

        // Check cache
        {
            let mut cache = self.cache.write().unwrap();
            if let Some(hash) = cache.get(&(level, index)) {
                return hash;
            }
        }

        // Compute the node
        let level_below_size = self.size_at_level(level - 1);
        let left_idx = index * 2;
        let right_idx = left_idx + 1;

        let left = self.get_node_at_level(level - 1, left_idx);
        let right = if right_idx < level_below_size {
            self.get_node_at_level(level - 1, right_idx)
        } else {
            left // Duplicate for odd count
        };

        let hash = hash_pair(&left, &right);

        // Cache the result
        {
            let mut cache = self.cache.write().unwrap();
            cache.insert((level, index), hash);
        }

        hash
    }

    /// Get the number of nodes at a given level
    fn size_at_level(&self, level: usize) -> usize {
        let mut size = self.leaves.len();
        for _ in 0..level {
            size = (size + 1) / 2;
        }
        size
    }

    /// Compute root hash using parallel reduction
    fn compute_root_parallel(leaves: &[[u8; 32]]) -> [u8; 32] {
        if leaves.is_empty() {
            return [0u8; 32];
        }

        if leaves.len() == 1 {
            return leaves[0];
        }

        // Use rayon for parallel computation
        let mut level: Vec<[u8; 32]> = leaves.to_vec();

        while level.len() > 1 {
            // Pad to even length if needed
            if level.len() % 2 == 1 {
                let last = *level.last().unwrap();
                level.push(last);
            }

            // Parallel hash of pairs
            level = level
                .par_chunks(2)
                .map(|pair| hash_pair(&pair[0], &pair[1]))
                .collect();
        }

        level[0]
    }
}

impl MerkleTree {
    /// Convert to sparse Merkle tree
    pub fn to_sparse(self) -> SparseMerkleTree {
        SparseMerkleTree::from_leaves(self.leaves)
    }

    /// Get the leaves
    pub fn leaves(&self) -> &[[u8; 32]] {
        &self.leaves
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_leaf() {
        let leaf = [1u8; 32];
        let tree = MerkleTree::from_leaves(vec![leaf]);
        assert_eq!(tree.root(), leaf);
    }

    #[test]
    fn test_two_leaves() {
        let leaf1 = [1u8; 32];
        let leaf2 = [2u8; 32];
        let tree = MerkleTree::from_leaves(vec![leaf1, leaf2]);

        // Root should be hash of both leaves
        let expected_root = hash_pair(&leaf1, &leaf2);
        assert_eq!(tree.root(), expected_root);
    }

    #[test]
    fn test_proof_single_leaf() {
        let leaf = [1u8; 32];
        let tree = MerkleTree::from_leaves(vec![leaf]);
        let proof = tree.proof(0);

        // Single leaf has no siblings in proof
        assert_eq!(proof.len(), 0);
        assert!(MerkleTree::verify_proof(&leaf, &proof, &tree.root(), 0));
    }

    #[test]
    fn test_proof_two_leaves() {
        let leaf1 = [1u8; 32];
        let leaf2 = [2u8; 32];
        let tree = MerkleTree::from_leaves(vec![leaf1, leaf2]);

        // Proof for leaf 0 should contain leaf 1 as sibling
        let proof0 = tree.proof(0);
        assert_eq!(proof0.len(), 1);
        assert_eq!(proof0[0], leaf2);
        assert!(MerkleTree::verify_proof(&leaf1, &proof0, &tree.root(), 0));

        // Proof for leaf 1 should contain leaf 0 as sibling
        let proof1 = tree.proof(1);
        assert_eq!(proof1.len(), 1);
        assert_eq!(proof1[0], leaf1);
        assert!(MerkleTree::verify_proof(&leaf2, &proof1, &tree.root(), 1));
    }

    #[test]
    fn test_proof_four_leaves() {
        let leaves: Vec<[u8; 32]> = (0..4)
            .map(|i| {
                let mut arr = [0u8; 32];
                arr[0] = i;
                arr
            })
            .collect();

        let tree = MerkleTree::from_leaves(leaves.clone());

        // Verify proof for each leaf
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.proof(i);
            // 4 leaves = depth 2, so proof should have 2 siblings
            assert_eq!(proof.len(), 2);
            assert!(MerkleTree::verify_proof(leaf, &proof, &tree.root(), i));
        }
    }

    #[test]
    fn test_proof_odd_leaves() {
        let leaves: Vec<[u8; 32]> = (0..5)
            .map(|i| {
                let mut arr = [0u8; 32];
                arr[0] = i;
                arr
            })
            .collect();

        let tree = MerkleTree::from_leaves(leaves.clone());

        // Verify proof for each leaf
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.proof(i);
            assert!(MerkleTree::verify_proof(leaf, &proof, &tree.root(), i));
        }
    }

    #[test]
    fn test_invalid_proof() {
        let leaf1 = [1u8; 32];
        let leaf2 = [2u8; 32];
        let tree = MerkleTree::from_leaves(vec![leaf1, leaf2]);

        let proof = tree.proof(0);

        // Wrong leaf should fail
        let wrong_leaf = [3u8; 32];
        assert!(!MerkleTree::verify_proof(&wrong_leaf, &proof, &tree.root(), 0));

        // Wrong root should fail
        let wrong_root = [0u8; 32];
        assert!(!MerkleTree::verify_proof(&leaf1, &proof, &wrong_root, 0));

        // Wrong index should fail
        assert!(!MerkleTree::verify_proof(&leaf1, &proof, &tree.root(), 1));
    }

    #[test]
    fn test_empty_tree() {
        let tree = MerkleTree::from_leaves(vec![]);
        assert_eq!(tree.root(), [0u8; 32]);
    }

    #[test]
    fn test_proof_out_of_bounds() {
        let leaf = [1u8; 32];
        let tree = MerkleTree::from_leaves(vec![leaf]);
        let proof = tree.proof(10);
        assert_eq!(proof.len(), 0);
    }

    #[test]
    fn test_hash_pair_deterministic() {
        let left = [1u8; 32];
        let right = [2u8; 32];

        let hash1 = hash_pair(&left, &right);
        let hash2 = hash_pair(&left, &right);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_pair_order_matters() {
        let left = [1u8; 32];
        let right = [2u8; 32];

        let hash_lr = hash_pair(&left, &right);
        let hash_rl = hash_pair(&right, &left);

        assert_ne!(hash_lr, hash_rl);
    }

    // =========================================================================
    // SparseMerkleTree Tests
    // =========================================================================

    #[test]
    fn test_sparse_single_leaf() {
        let leaf = [1u8; 32];
        let tree = SparseMerkleTree::from_leaves(vec![leaf]);
        assert_eq!(tree.root(), leaf);
        assert_eq!(tree.leaf_count(), 1);
        assert_eq!(tree.height(), 0);
    }

    #[test]
    fn test_sparse_two_leaves() {
        let leaf1 = [1u8; 32];
        let leaf2 = [2u8; 32];
        let tree = SparseMerkleTree::from_leaves(vec![leaf1, leaf2]);

        // Root should be hash of both leaves
        let expected_root = hash_pair(&leaf1, &leaf2);
        assert_eq!(tree.root(), expected_root);
        assert_eq!(tree.leaf_count(), 2);
        assert_eq!(tree.height(), 1);
    }

    #[test]
    fn test_sparse_root_matches_legacy() {
        // Test that sparse and legacy trees produce same root
        let leaves: Vec<[u8; 32]> = (0..100)
            .map(|i| {
                let mut arr = [0u8; 32];
                arr[0] = i as u8;
                arr[1] = (i >> 8) as u8;
                arr
            })
            .collect();

        let legacy = MerkleTree::from_leaves(leaves.clone());
        let sparse = SparseMerkleTree::from_leaves(leaves);

        assert_eq!(legacy.root(), sparse.root());
    }

    #[test]
    fn test_sparse_verify_chunk() {
        let leaves: Vec<[u8; 32]> = (0..16)
            .map(|i| {
                let mut arr = [0u8; 32];
                arr[0] = i;
                arr
            })
            .collect();

        let tree = SparseMerkleTree::from_leaves(leaves.clone());

        // Verify all chunks
        for (i, leaf) in leaves.iter().enumerate() {
            assert!(tree.verify_chunk(i, leaf), "Chunk {} should verify", i);
        }

        // Wrong hash should fail
        let wrong = [0xffu8; 32];
        assert!(!tree.verify_chunk(0, &wrong));

        // Out of bounds should fail
        assert!(!tree.verify_chunk(100, &leaves[0]));
    }

    #[test]
    fn test_sparse_generate_proof() {
        let leaves: Vec<[u8; 32]> = (0..8)
            .map(|i| {
                let mut arr = [0u8; 32];
                arr[0] = i;
                arr
            })
            .collect();

        let tree = SparseMerkleTree::from_leaves(leaves.clone());

        // Test proof for each leaf
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.generate_proof(i);

            // 8 leaves = height 3
            assert_eq!(proof.height(), 3);
            assert_eq!(proof.leaf_index, i);

            // Verify the proof
            assert!(
                proof.verify(leaf, &tree.root()),
                "Proof for leaf {} should verify",
                i
            );
        }
    }

    #[test]
    fn test_sparse_proof_invalid() {
        let leaves: Vec<[u8; 32]> = (0..4)
            .map(|i| {
                let mut arr = [0u8; 32];
                arr[0] = i;
                arr
            })
            .collect();

        let tree = SparseMerkleTree::from_leaves(leaves.clone());
        let proof = tree.generate_proof(0);

        // Wrong leaf
        let wrong_leaf = [0xffu8; 32];
        assert!(!proof.verify(&wrong_leaf, &tree.root()));

        // Wrong root
        let wrong_root = [0xffu8; 32];
        assert!(!proof.verify(&leaves[0], &wrong_root));
    }

    #[test]
    fn test_sparse_odd_leaves() {
        // Test odd number of leaves (requires duplication handling)
        let leaves: Vec<[u8; 32]> = (0..7)
            .map(|i| {
                let mut arr = [0u8; 32];
                arr[0] = i;
                arr
            })
            .collect();

        let legacy = MerkleTree::from_leaves(leaves.clone());
        let sparse = SparseMerkleTree::from_leaves(leaves.clone());

        // Roots should match
        assert_eq!(legacy.root(), sparse.root());

        // All chunks should verify
        for (i, leaf) in leaves.iter().enumerate() {
            assert!(sparse.verify_chunk(i, leaf));
        }
    }

    #[test]
    fn test_sparse_empty() {
        let tree = SparseMerkleTree::from_leaves(vec![]);
        assert_eq!(tree.root(), [0u8; 32]);
        assert_eq!(tree.leaf_count(), 0);
        assert_eq!(tree.height(), 0);
    }

    #[test]
    fn test_sparse_random_sample() {
        let leaves: Vec<[u8; 32]> = (0..100)
            .map(|i| {
                let mut arr = [0u8; 32];
                arr[0] = i as u8;
                arr
            })
            .collect();

        let tree = SparseMerkleTree::from_leaves(leaves);

        // Sample should verify
        let (verified, sampled) = tree.verify_random_sample(10);
        assert_eq!(verified, sampled);
        assert!(sampled <= 10);
    }

    #[test]
    fn test_sparse_to_legacy_conversion() {
        let leaves: Vec<[u8; 32]> = (0..16)
            .map(|i| {
                let mut arr = [0u8; 32];
                arr[0] = i;
                arr
            })
            .collect();

        let sparse = SparseMerkleTree::from_leaves(leaves.clone());
        let legacy = sparse.to_legacy();

        assert_eq!(sparse.root(), legacy.root());
    }

    #[test]
    fn test_legacy_to_sparse_conversion() {
        let leaves: Vec<[u8; 32]> = (0..16)
            .map(|i| {
                let mut arr = [0u8; 32];
                arr[0] = i;
                arr
            })
            .collect();

        let legacy = MerkleTree::from_leaves(leaves.clone());
        let sparse = legacy.to_sparse();

        // Create a fresh legacy tree to compare roots
        let legacy2 = MerkleTree::from_leaves(leaves);
        assert_eq!(legacy2.root(), sparse.root());
    }

    #[test]
    fn test_sparse_large_tree() {
        // Test with 1000 leaves
        let leaves: Vec<[u8; 32]> = (0..1000)
            .map(|i| {
                let mut arr = [0u8; 32];
                arr[0] = (i % 256) as u8;
                arr[1] = ((i >> 8) % 256) as u8;
                arr
            })
            .collect();

        let legacy = MerkleTree::from_leaves(leaves.clone());
        let sparse = SparseMerkleTree::from_leaves(leaves.clone());

        // Roots should match
        assert_eq!(legacy.root(), sparse.root());

        // Height should be ceil(log2(1000)) = 10
        assert_eq!(sparse.height(), 10);

        // Verify a few random chunks
        assert!(sparse.verify_chunk(0, &leaves[0]));
        assert!(sparse.verify_chunk(499, &leaves[499]));
        assert!(sparse.verify_chunk(999, &leaves[999]));
    }

    #[test]
    fn test_node_cache_lru() {
        let mut cache = NodeCache::new(3);

        // Insert 3 items
        cache.insert((0, 0), [1u8; 32]);
        cache.insert((0, 1), [2u8; 32]);
        cache.insert((1, 0), [3u8; 32]);

        assert_eq!(cache.len(), 3);

        // Access (0, 0) to make it recently used
        let _ = cache.get(&(0, 0));

        // Insert 4th item - should evict (0, 1) which is LRU
        cache.insert((1, 1), [4u8; 32]);

        assert_eq!(cache.len(), 3);
        assert!(cache.get(&(0, 0)).is_some()); // Recently accessed
        assert!(cache.get(&(0, 1)).is_none()); // Evicted
        assert!(cache.get(&(1, 0)).is_some());
        assert!(cache.get(&(1, 1)).is_some());
    }

    #[test]
    fn test_merkle_proof_struct() {
        let proof = MerkleProof {
            siblings: vec![[1u8; 32], [2u8; 32]],
            leaf_index: 0,
            directions: vec![false, false],
        };

        assert_eq!(proof.height(), 2);
        assert_eq!(proof.leaf_index, 0);

        // Mismatched lengths should fail verify
        let bad_proof = MerkleProof {
            siblings: vec![[1u8; 32]],
            leaf_index: 0,
            directions: vec![false, false], // 2 directions but 1 sibling
        };

        assert!(!bad_proof.verify(&[0u8; 32], &[0u8; 32]));
    }
}
