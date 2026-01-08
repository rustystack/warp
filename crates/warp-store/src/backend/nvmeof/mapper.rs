//! Object-to-Block Mapping
//!
//! Maps object storage keys to NVMe LBA (Logical Block Address) ranges.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tracing::{debug, trace};

use super::config::AllocationStrategy;
use super::error::{NvmeOfBackendError, NvmeOfBackendResult};

/// Object location in NVMe storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectLocation {
    /// Target ID (NQN)
    pub target_id: String,

    /// Namespace ID
    pub namespace_id: u32,

    /// Extents (for fragmented/large objects)
    pub extents: Vec<ObjectExtent>,

    /// Total object size in bytes
    pub size: u64,

    /// Content hash (for integrity verification)
    pub content_hash: [u8; 32],

    /// Creation timestamp
    pub created_at: u64,

    /// Last modified timestamp
    pub modified_at: u64,
}

impl ObjectLocation {
    /// Get total block count
    pub fn total_blocks(&self) -> u64 {
        self.extents.iter().map(|e| e.block_count as u64).sum()
    }

    /// Check if object is contiguous
    pub fn is_contiguous(&self) -> bool {
        if self.extents.len() <= 1 {
            return true;
        }

        // Check if extents are adjacent
        for i in 1..self.extents.len() {
            let prev = &self.extents[i - 1];
            let curr = &self.extents[i];

            if prev.start_lba + prev.block_count as u64 != curr.start_lba {
                return false;
            }
        }

        true
    }
}

/// A single extent (contiguous block range) of an object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectExtent {
    /// Starting LBA
    pub start_lba: u64,

    /// Number of blocks
    pub block_count: u32,

    /// Offset within the object (for fragmented objects)
    pub object_offset: u64,
}

impl ObjectExtent {
    /// Create a new extent
    pub fn new(start_lba: u64, block_count: u32, object_offset: u64) -> Self {
        Self {
            start_lba,
            block_count,
            object_offset,
        }
    }

    /// End LBA (exclusive)
    pub fn end_lba(&self) -> u64 {
        self.start_lba + self.block_count as u64
    }

    /// Check if this extent overlaps with another
    pub fn overlaps(&self, other: &ObjectExtent) -> bool {
        self.start_lba < other.end_lba() && other.start_lba < self.end_lba()
    }
}

/// Block allocation info for a namespace
#[derive(Debug)]
struct NamespaceAllocator {
    /// Namespace ID
    nsid: u32,

    /// Target NQN
    target_nqn: String,

    /// Total blocks in namespace
    total_blocks: u64,

    /// Free blocks
    free_blocks: AtomicU64,

    /// Next free LBA hint
    next_free_lba: AtomicU64,

    /// Free list (start_lba -> block_count)
    free_list: RwLock<Vec<(u64, u64)>>,
}

impl NamespaceAllocator {
    fn new(nsid: u32, target_nqn: String, total_blocks: u64) -> Self {
        Self {
            nsid,
            target_nqn,
            total_blocks,
            free_blocks: AtomicU64::new(total_blocks),
            next_free_lba: AtomicU64::new(0),
            free_list: RwLock::new(vec![(0, total_blocks)]),
        }
    }

    /// Allocate contiguous blocks
    fn allocate(&self, block_count: u64) -> Option<u64> {
        let mut free_list = self.free_list.write();

        // Find first fit
        for i in 0..free_list.len() {
            let (start, count) = free_list[i];
            if count >= block_count {
                // Found a suitable region
                if count == block_count {
                    free_list.remove(i);
                } else {
                    free_list[i] = (start + block_count, count - block_count);
                }

                self.free_blocks.fetch_sub(block_count, Ordering::Relaxed);
                return Some(start);
            }
        }

        None
    }

    /// Free blocks
    fn free(&self, start_lba: u64, block_count: u64) {
        let mut free_list = self.free_list.write();

        // Add to free list (simplified - could merge adjacent regions)
        free_list.push((start_lba, block_count));
        self.free_blocks.fetch_add(block_count, Ordering::Relaxed);

        // Sort and merge (simplified)
        free_list.sort_by_key(|(start, _)| *start);
    }

    /// Get free block count
    fn free_block_count(&self) -> u64 {
        self.free_blocks.load(Ordering::Relaxed)
    }
}

/// Object-to-block mapper
pub struct ObjectBlockMapper {
    /// Block size
    block_size: u32,

    /// Allocation strategy
    strategy: AllocationStrategy,

    /// Namespace allocators
    allocators: RwLock<HashMap<(String, u32), Arc<NamespaceAllocator>>>,

    /// Current round-robin index
    rr_index: AtomicU64,
}

impl ObjectBlockMapper {
    /// Create a new mapper
    pub fn new(block_size: u32, strategy: AllocationStrategy) -> Self {
        Self {
            block_size,
            strategy,
            allocators: RwLock::new(HashMap::new()),
            rr_index: AtomicU64::new(0),
        }
    }

    /// Register a namespace
    pub fn register_namespace(&self, target_nqn: &str, nsid: u32, total_blocks: u64) {
        let key = (target_nqn.to_string(), nsid);
        let allocator = Arc::new(NamespaceAllocator::new(
            nsid,
            target_nqn.to_string(),
            total_blocks,
        ));

        self.allocators.write().insert(key, allocator);
        debug!(
            "Registered namespace: target={}, nsid={}, blocks={}",
            target_nqn, nsid, total_blocks
        );
    }

    /// Unregister a namespace
    pub fn unregister_namespace(&self, target_nqn: &str, nsid: u32) {
        let key = (target_nqn.to_string(), nsid);
        self.allocators.write().remove(&key);
    }

    /// Calculate blocks needed for size
    pub fn blocks_for_size(&self, size: u64) -> u64 {
        (size + self.block_size as u64 - 1) / self.block_size as u64
    }

    /// Allocate blocks for an object
    pub fn allocate(
        &self,
        object_size: u64,
        content_hash: [u8; 32],
    ) -> NvmeOfBackendResult<ObjectLocation> {
        let blocks_needed = self.blocks_for_size(object_size);

        let allocators = self.allocators.read();
        if allocators.is_empty() {
            return Err(NvmeOfBackendError::AllocationFailed(
                "No namespaces registered".to_string(),
            ));
        }

        // Select namespace based on strategy
        let allocator = match self.strategy {
            AllocationStrategy::FirstFit => {
                // Find first namespace with enough space
                allocators
                    .values()
                    .find(|a| a.free_block_count() >= blocks_needed)
            }
            AllocationStrategy::BestFit => {
                // Find namespace with smallest sufficient space
                allocators
                    .values()
                    .filter(|a| a.free_block_count() >= blocks_needed)
                    .min_by_key(|a| a.free_block_count())
            }
            AllocationStrategy::RoundRobin => {
                // Round-robin selection
                let idx = self.rr_index.fetch_add(1, Ordering::Relaxed);
                let values: Vec<_> = allocators.values().collect();
                if values.is_empty() {
                    None
                } else {
                    let selected = values[idx as usize % values.len()];
                    if selected.free_block_count() >= blocks_needed {
                        Some(selected)
                    } else {
                        // Fall back to first fit if round-robin selection doesn't have space
                        allocators
                            .values()
                            .find(|a| a.free_block_count() >= blocks_needed)
                    }
                }
            }
            AllocationStrategy::Striped => {
                // For striped, we'd split across namespaces
                // Simplified: just use first-fit for now
                allocators
                    .values()
                    .find(|a| a.free_block_count() >= blocks_needed)
            }
        };

        let allocator = allocator.ok_or_else(|| {
            NvmeOfBackendError::AllocationFailed("Insufficient space".to_string())
        })?;

        // Allocate blocks
        let start_lba = allocator
            .allocate(blocks_needed)
            .ok_or_else(|| NvmeOfBackendError::AllocationFailed("Fragmentation".to_string()))?;

        let extent = ObjectExtent::new(start_lba, blocks_needed as u32, 0);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let location = ObjectLocation {
            target_id: allocator.target_nqn.clone(),
            namespace_id: allocator.nsid,
            extents: vec![extent],
            size: object_size,
            content_hash,
            created_at: now,
            modified_at: now,
        };

        trace!(
            "Allocated {} blocks at LBA {} for object (size={})",
            blocks_needed, start_lba, object_size
        );

        Ok(location)
    }

    /// Free blocks for an object
    pub fn free(&self, location: &ObjectLocation) -> NvmeOfBackendResult<()> {
        let key = (location.target_id.clone(), location.namespace_id);
        let allocators = self.allocators.read();

        let allocator = allocators
            .get(&key)
            .ok_or_else(|| NvmeOfBackendError::NamespaceNotFound(location.namespace_id))?;

        for extent in &location.extents {
            allocator.free(extent.start_lba, extent.block_count as u64);
        }

        trace!(
            "Freed {} blocks for object (size={})",
            location.total_blocks(),
            location.size
        );

        Ok(())
    }

    /// Get total free space across all namespaces
    pub fn total_free_space(&self) -> u64 {
        let allocators = self.allocators.read();
        allocators
            .values()
            .map(|a| a.free_block_count() * self.block_size as u64)
            .sum()
    }

    /// Get statistics
    pub fn stats(&self) -> MapperStats {
        let allocators = self.allocators.read();
        let mut stats = MapperStats::default();

        for allocator in allocators.values() {
            stats.total_blocks += allocator.total_blocks;
            stats.free_blocks += allocator.free_block_count();
            stats.namespaces += 1;
        }

        stats.block_size = self.block_size;
        stats
    }
}

/// Mapper statistics
#[derive(Debug, Clone, Default)]
pub struct MapperStats {
    /// Block size
    pub block_size: u32,

    /// Total blocks across all namespaces
    pub total_blocks: u64,

    /// Free blocks across all namespaces
    pub free_blocks: u64,

    /// Number of namespaces
    pub namespaces: u32,
}

impl MapperStats {
    /// Get utilization percentage
    pub fn utilization(&self) -> f64 {
        if self.total_blocks == 0 {
            return 0.0;
        }
        let used = self.total_blocks - self.free_blocks;
        (used as f64 / self.total_blocks as f64) * 100.0
    }

    /// Get total capacity in bytes
    pub fn total_capacity(&self) -> u64 {
        self.total_blocks * self.block_size as u64
    }

    /// Get free space in bytes
    pub fn free_space(&self) -> u64 {
        self.free_blocks * self.block_size as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_object_extent() {
        let extent = ObjectExtent::new(100, 50, 0);
        assert_eq!(extent.start_lba, 100);
        assert_eq!(extent.block_count, 50);
        assert_eq!(extent.end_lba(), 150);
    }

    #[test]
    fn test_extent_overlap() {
        let e1 = ObjectExtent::new(100, 50, 0);
        let e2 = ObjectExtent::new(140, 50, 0);
        let e3 = ObjectExtent::new(200, 50, 0);

        assert!(e1.overlaps(&e2));
        assert!(!e1.overlaps(&e3));
    }

    #[test]
    fn test_mapper_allocation() {
        let mapper = ObjectBlockMapper::new(4096, AllocationStrategy::FirstFit);

        mapper.register_namespace("nqn.2024-01.io.warp:test", 1, 1000);

        let hash = [0u8; 32];
        let location = mapper.allocate(4096 * 10, hash).unwrap();

        assert_eq!(location.namespace_id, 1);
        assert_eq!(location.extents.len(), 1);
        assert_eq!(location.extents[0].block_count, 10);

        // Free and reallocate
        mapper.free(&location).unwrap();

        let location2 = mapper.allocate(4096 * 5, hash).unwrap();
        assert_eq!(location2.extents[0].block_count, 5);
    }

    #[test]
    fn test_mapper_stats() {
        let mapper = ObjectBlockMapper::new(4096, AllocationStrategy::FirstFit);

        mapper.register_namespace("nqn.2024-01.io.warp:test", 1, 1000);
        mapper.register_namespace("nqn.2024-01.io.warp:test", 2, 2000);

        let stats = mapper.stats();
        assert_eq!(stats.total_blocks, 3000);
        assert_eq!(stats.free_blocks, 3000);
        assert_eq!(stats.namespaces, 2);
        assert_eq!(stats.utilization(), 0.0);
    }
}
