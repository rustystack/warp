//! Block extent mapping
//!
//! Maps virtual block addresses (LBAs) to storage objects.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;
use parking_lot::RwLock;

/// Block extent - a contiguous range of blocks mapped to storage
#[derive(Debug, Clone)]
pub struct BlockExtent {
    /// Virtual offset (LBA * block_size)
    pub offset: u64,
    /// Length in bytes
    pub length: u64,
    /// Object key in warp-store
    pub object_key: String,
    /// Offset within the object
    pub object_offset: u64,
    /// Flags
    pub flags: ExtentFlags,
}

impl BlockExtent {
    /// Create a new extent
    pub fn new(
        offset: u64,
        length: u64,
        object_key: impl Into<String>,
        object_offset: u64,
    ) -> Self {
        Self {
            offset,
            length,
            object_key: object_key.into(),
            object_offset,
            flags: ExtentFlags::default(),
        }
    }

    /// Create a hole (unallocated) extent
    pub fn hole(offset: u64, length: u64) -> Self {
        Self {
            offset,
            length,
            object_key: String::new(),
            object_offset: 0,
            flags: ExtentFlags::HOLE,
        }
    }

    /// Check if this is a hole
    pub fn is_hole(&self) -> bool {
        self.flags.is_hole()
    }

    /// Check if this is shared (COW)
    pub fn is_shared(&self) -> bool {
        self.flags.is_shared()
    }

    /// Get the end offset
    pub fn end(&self) -> u64 {
        self.offset + self.length
    }

    /// Check if offset falls within this extent
    pub fn contains(&self, offset: u64) -> bool {
        offset >= self.offset && offset < self.end()
    }

    /// Check if this extent overlaps with a range
    pub fn overlaps(&self, start: u64, end: u64) -> bool {
        self.offset < end && self.end() > start
    }

    /// Split extent at offset, returning the part after
    pub fn split_at(&mut self, split_offset: u64) -> Option<BlockExtent> {
        if split_offset <= self.offset || split_offset >= self.end() {
            return None;
        }

        let second_length = self.end() - split_offset;
        let second_object_offset = self.object_offset + (split_offset - self.offset);

        let second = BlockExtent {
            offset: split_offset,
            length: second_length,
            object_key: self.object_key.clone(),
            object_offset: second_object_offset,
            flags: self.flags,
        };

        self.length = split_offset - self.offset;
        Some(second)
    }
}

/// Extent flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExtentFlags(u32);

impl ExtentFlags {
    /// Extent is a hole (unallocated)
    pub const HOLE: Self = Self(0x01);
    /// Extent is shared (copy-on-write)
    pub const SHARED: Self = Self(0x02);
    /// Extent is dirty (needs flush)
    pub const DIRTY: Self = Self(0x04);
    /// Extent data is zeroed
    pub const ZEROED: Self = Self(0x08);

    /// Create new flags
    pub fn new(flags: u32) -> Self {
        Self(flags)
    }

    /// Get raw value
    pub fn bits(&self) -> u32 {
        self.0
    }

    /// Check if hole flag is set
    pub fn is_hole(&self) -> bool {
        self.0 & Self::HOLE.0 != 0
    }

    /// Check if shared flag is set
    pub fn is_shared(&self) -> bool {
        self.0 & Self::SHARED.0 != 0
    }

    /// Check if dirty flag is set
    pub fn is_dirty(&self) -> bool {
        self.0 & Self::DIRTY.0 != 0
    }

    /// Check if zeroed flag is set
    pub fn is_zeroed(&self) -> bool {
        self.0 & Self::ZEROED.0 != 0
    }

    /// Set shared flag
    pub fn set_shared(&mut self) {
        self.0 |= Self::SHARED.0;
    }

    /// Set dirty flag
    pub fn set_dirty(&mut self) {
        self.0 |= Self::DIRTY.0;
    }

    /// Clear dirty flag
    pub fn clear_dirty(&mut self) {
        self.0 &= !Self::DIRTY.0;
    }
}

/// Extent map - maps virtual addresses to extents
#[derive(Debug)]
pub struct ExtentMap {
    /// Extents indexed by start offset
    extents: RwLock<BTreeMap<u64, BlockExtent>>,
    /// Total virtual size
    size: u64,
    /// Total allocated bytes
    allocated: AtomicU64,
}

impl ExtentMap {
    /// Create a new extent map
    pub fn new(size: u64) -> Self {
        Self {
            extents: RwLock::new(BTreeMap::new()),
            size,
            allocated: AtomicU64::new(0),
        }
    }

    /// Get the virtual size
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Get total allocated bytes
    pub fn allocated(&self) -> u64 {
        self.allocated.load(Ordering::Relaxed)
    }

    /// Look up extent containing offset
    pub fn lookup(&self, offset: u64) -> Option<BlockExtent> {
        let extents = self.extents.read();

        // Find the extent that starts at or before this offset
        if let Some((&start, extent)) = extents.range(..=offset).next_back() {
            if extent.contains(offset) {
                return Some(extent.clone());
            }
        }

        None
    }

    /// Look up all extents overlapping a range
    pub fn lookup_range(&self, start: u64, end: u64) -> Vec<BlockExtent> {
        let extents = self.extents.read();
        let mut result = Vec::new();

        // Find extents that might overlap
        for (_, extent) in extents.range(..end) {
            if extent.overlaps(start, end) {
                result.push(extent.clone());
            }
        }

        result
    }

    /// Insert or update an extent
    pub fn insert(&self, extent: BlockExtent) {
        let mut extents = self.extents.write();

        // Remove any overlapping extents
        let start = extent.offset;
        let end = extent.end();
        let mut to_remove = Vec::new();

        for (&offset, existing) in extents.range(..end) {
            if existing.overlaps(start, end) {
                to_remove.push(offset);
            }
        }

        for offset in to_remove {
            if let Some(removed) = extents.remove(&offset) {
                if !removed.is_hole() {
                    self.allocated
                        .fetch_sub(removed.length, Ordering::Relaxed);
                }
            }
        }

        // Track allocation
        if !extent.is_hole() {
            self.allocated.fetch_add(extent.length, Ordering::Relaxed);
        }

        extents.insert(extent.offset, extent);
    }

    /// Remove extents in a range (create holes)
    pub fn remove_range(&self, start: u64, end: u64) {
        let mut extents = self.extents.write();

        let mut to_remove = Vec::new();
        let mut to_add = Vec::new();

        for (&offset, extent) in extents.range(..end) {
            if !extent.overlaps(start, end) {
                continue;
            }

            to_remove.push(offset);

            // Handle partial overlap at start
            if extent.offset < start {
                let mut before = extent.clone();
                before.length = start - extent.offset;
                to_add.push(before);
            }

            // Handle partial overlap at end
            if extent.end() > end {
                let mut after = extent.clone();
                after.offset = end;
                after.object_offset = extent.object_offset + (end - extent.offset);
                after.length = extent.end() - end;
                to_add.push(after);
            }
        }

        for offset in to_remove {
            if let Some(removed) = extents.remove(&offset) {
                if !removed.is_hole() {
                    self.allocated
                        .fetch_sub(removed.length, Ordering::Relaxed);
                }
            }
        }

        for extent in to_add {
            if !extent.is_hole() {
                self.allocated.fetch_add(extent.length, Ordering::Relaxed);
            }
            extents.insert(extent.offset, extent);
        }
    }

    /// Clone extent map for COW snapshot
    pub fn clone_for_snapshot(&self) -> Self {
        let extents = self.extents.read();
        let mut new_extents = BTreeMap::new();

        for (offset, extent) in extents.iter() {
            let mut new_extent = extent.clone();
            new_extent.flags.set_shared();
            new_extents.insert(*offset, new_extent);
        }

        Self {
            extents: RwLock::new(new_extents),
            size: self.size,
            allocated: AtomicU64::new(self.allocated.load(Ordering::Relaxed)),
        }
    }

    /// Get number of extents
    pub fn extent_count(&self) -> usize {
        self.extents.read().len()
    }

    /// Iterate over all extents
    pub fn iter(&self) -> Vec<BlockExtent> {
        self.extents.read().values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extent_basic() {
        let extent = BlockExtent::new(0, 4096, "obj1", 0);
        assert!(!extent.is_hole());
        assert!(extent.contains(0));
        assert!(extent.contains(4095));
        assert!(!extent.contains(4096));
    }

    #[test]
    fn test_extent_hole() {
        let extent = BlockExtent::hole(0, 4096);
        assert!(extent.is_hole());
    }

    #[test]
    fn test_extent_overlap() {
        let extent = BlockExtent::new(1000, 2000, "obj1", 0);
        assert!(extent.overlaps(500, 1500));  // Overlaps start
        assert!(extent.overlaps(2000, 4000)); // Overlaps end
        assert!(extent.overlaps(1500, 2500)); // Fully inside
        assert!(extent.overlaps(500, 4000));  // Fully covers
        assert!(!extent.overlaps(0, 1000));   // Before
        assert!(!extent.overlaps(3000, 4000)); // After
    }

    #[test]
    fn test_extent_split() {
        let mut extent = BlockExtent::new(0, 4096, "obj1", 0);
        let second = extent.split_at(2048).unwrap();

        assert_eq!(extent.offset, 0);
        assert_eq!(extent.length, 2048);
        assert_eq!(second.offset, 2048);
        assert_eq!(second.length, 2048);
        assert_eq!(second.object_offset, 2048);
    }

    #[test]
    fn test_extent_map_lookup() {
        let map = ExtentMap::new(1024 * 1024);

        map.insert(BlockExtent::new(0, 4096, "obj1", 0));
        map.insert(BlockExtent::new(8192, 4096, "obj2", 0));

        assert!(map.lookup(0).is_some());
        assert!(map.lookup(2048).is_some());
        assert!(map.lookup(4096).is_none()); // Hole
        assert!(map.lookup(8192).is_some());
    }

    #[test]
    fn test_extent_map_range() {
        let map = ExtentMap::new(1024 * 1024);

        map.insert(BlockExtent::new(0, 4096, "obj1", 0));
        map.insert(BlockExtent::new(4096, 4096, "obj2", 0));
        map.insert(BlockExtent::new(8192, 4096, "obj3", 0));

        let extents = map.lookup_range(2048, 6144);
        assert_eq!(extents.len(), 2); // obj1 and obj2
    }

    #[test]
    fn test_extent_map_allocation_tracking() {
        let map = ExtentMap::new(1024 * 1024);

        map.insert(BlockExtent::new(0, 4096, "obj1", 0));
        assert_eq!(map.allocated(), 4096);

        map.insert(BlockExtent::new(4096, 4096, "obj2", 0));
        assert_eq!(map.allocated(), 8192);

        map.remove_range(0, 4096);
        assert_eq!(map.allocated(), 4096);
    }

    #[test]
    fn test_extent_map_snapshot() {
        let map = ExtentMap::new(1024 * 1024);
        map.insert(BlockExtent::new(0, 4096, "obj1", 0));

        let snapshot_map = map.clone_for_snapshot();

        let extent = snapshot_map.lookup(0).unwrap();
        assert!(extent.is_shared());
    }
}
