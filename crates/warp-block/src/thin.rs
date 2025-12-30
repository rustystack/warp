//! Thin provisioning support
//!
//! Implements thin provisioning with allocate-on-write semantics.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use parking_lot::RwLock;

use crate::config::{ThinPoolConfig, ThinVolumeConfig};
use crate::error::{BlockError, BlockResult};
use crate::extent::{BlockExtent, ExtentMap};
use crate::volume::{Volume, VolumeId, VolumeState};

/// Thin pool - manages chunk allocation across volumes
#[derive(Debug)]
pub struct ThinPool {
    /// Pool name
    pub name: String,
    /// Pool configuration
    pub config: ThinPoolConfig,
    /// Total allocated chunks
    allocated_chunks: AtomicU64,
    /// Chunk allocator
    chunk_allocator: ChunkAllocator,
    /// Volumes in this pool
    volumes: DashMap<VolumeId, ThinVolume>,
}

impl ThinPool {
    /// Create a new thin pool
    pub fn new(config: ThinPoolConfig) -> Self {
        let name = config.name.clone();
        let chunk_allocator = ChunkAllocator::new(config.chunk_size);

        Self {
            name,
            config,
            allocated_chunks: AtomicU64::new(0),
            chunk_allocator,
            volumes: DashMap::new(),
        }
    }

    /// Get pool name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get chunk size
    pub fn chunk_size(&self) -> u64 {
        self.config.chunk_size
    }

    /// Get total allocated bytes
    pub fn allocated_bytes(&self) -> u64 {
        self.allocated_chunks.load(Ordering::Relaxed) * self.config.chunk_size
    }

    /// Get max size (0 = unlimited)
    pub fn max_size(&self) -> u64 {
        self.config.max_size
    }

    /// Check if pool is at or over the low watermark
    pub fn is_low_space(&self) -> bool {
        if self.config.max_size == 0 {
            return false;
        }
        let used_percent = (self.allocated_bytes() * 100) / self.config.max_size;
        used_percent >= self.config.low_watermark as u64
    }

    /// Check if pool is at or over the critical watermark
    pub fn is_critical_space(&self) -> bool {
        if self.config.max_size == 0 {
            return false;
        }
        let used_percent = (self.allocated_bytes() * 100) / self.config.max_size;
        used_percent >= self.config.critical_watermark as u64
    }

    /// Allocate a chunk
    pub fn allocate_chunk(&self) -> BlockResult<ChunkId> {
        // Check space limits
        if self.config.max_size > 0 {
            let new_allocated = self.allocated_bytes() + self.config.chunk_size;
            if new_allocated > self.config.max_size {
                return Err(BlockError::OutOfSpace);
            }
        }

        let chunk_id = self.chunk_allocator.allocate();
        self.allocated_chunks.fetch_add(1, Ordering::Relaxed);
        Ok(chunk_id)
    }

    /// Free a chunk
    pub fn free_chunk(&self, chunk_id: ChunkId) {
        self.chunk_allocator.free(chunk_id);
        self.allocated_chunks.fetch_sub(1, Ordering::Relaxed);
    }

    /// Create a new volume in this pool
    pub fn create_volume(&self, config: ThinVolumeConfig) -> BlockResult<VolumeId> {
        let volume_id = VolumeId::generate();
        let volume = ThinVolume::new(volume_id, config, self.config.chunk_size);
        self.volumes.insert(volume_id, volume);
        Ok(volume_id)
    }

    /// Get a volume by ID
    pub fn get_volume(&self, id: &VolumeId) -> Option<dashmap::mapref::one::Ref<VolumeId, ThinVolume>> {
        self.volumes.get(id)
    }

    /// Get a mutable volume reference
    pub fn get_volume_mut(
        &self,
        id: &VolumeId,
    ) -> Option<dashmap::mapref::one::RefMut<VolumeId, ThinVolume>> {
        self.volumes.get_mut(id)
    }

    /// Remove a volume
    pub fn remove_volume(&self, id: &VolumeId) -> Option<ThinVolume> {
        self.volumes.remove(id).map(|(_, v)| v)
    }

    /// List all volumes
    pub fn list_volumes(&self) -> Vec<VolumeId> {
        self.volumes.iter().map(|e| *e.key()).collect()
    }

    /// Get object key for a chunk
    pub fn chunk_object_key(&self, chunk_id: &ChunkId) -> String {
        format!("{}/chunks/{:016x}", self.config.bucket, chunk_id.0)
    }
}

/// Chunk ID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChunkId(pub u64);

impl ChunkId {
    /// Create from raw value
    pub fn from_raw(val: u64) -> Self {
        Self(val)
    }

    /// Get raw value
    pub fn raw(&self) -> u64 {
        self.0
    }
}

/// Chunk allocator
#[derive(Debug)]
struct ChunkAllocator {
    /// Next chunk ID
    next_id: AtomicU64,
    /// Chunk size
    chunk_size: u64,
    /// Free list (recycled chunk IDs)
    free_list: RwLock<Vec<ChunkId>>,
}

impl ChunkAllocator {
    /// Create a new allocator
    fn new(chunk_size: u64) -> Self {
        Self {
            next_id: AtomicU64::new(1),
            chunk_size,
            free_list: RwLock::new(Vec::new()),
        }
    }

    /// Allocate a chunk ID
    fn allocate(&self) -> ChunkId {
        // Try to recycle from free list
        if let Some(id) = self.free_list.write().pop() {
            return id;
        }

        // Allocate new
        ChunkId(self.next_id.fetch_add(1, Ordering::SeqCst))
    }

    /// Free a chunk ID (add to free list)
    fn free(&self, id: ChunkId) {
        self.free_list.write().push(id);
    }
}

/// Thin volume - a thin-provisioned virtual block device
#[derive(Debug)]
pub struct ThinVolume {
    /// Volume ID
    pub id: VolumeId,
    /// Volume name
    pub name: String,
    /// Virtual size
    pub virtual_size: u64,
    /// Block size
    pub block_size: u32,
    /// Chunk size (from pool)
    pub chunk_size: u64,
    /// Read-only flag
    pub read_only: bool,
    /// Volume state
    pub state: VolumeState,
    /// Extent map
    pub extents: ExtentMap,
    /// Snapshot parent (if this is a snapshot)
    pub parent: Option<VolumeId>,
    /// Child snapshots
    pub children: RwLock<Vec<VolumeId>>,
    /// Active connections
    pub connections: AtomicU64,
}

impl ThinVolume {
    /// Create a new thin volume
    pub fn new(id: VolumeId, config: ThinVolumeConfig, chunk_size: u64) -> Self {
        Self {
            id,
            name: config.name,
            virtual_size: config.virtual_size,
            block_size: config.block_size,
            chunk_size,
            read_only: config.read_only,
            state: VolumeState::Active,
            extents: ExtentMap::new(config.virtual_size),
            parent: None,
            children: RwLock::new(Vec::new()),
            connections: AtomicU64::new(0),
        }
    }

    /// Get volume ID
    pub fn id(&self) -> VolumeId {
        self.id
    }

    /// Get volume name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get virtual size
    pub fn size(&self) -> u64 {
        self.virtual_size
    }

    /// Get allocated bytes
    pub fn allocated(&self) -> u64 {
        self.extents.allocated()
    }

    /// Check if volume is read-only
    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    /// Check if volume is a snapshot
    pub fn is_snapshot(&self) -> bool {
        self.parent.is_some()
    }

    /// Get connection count
    pub fn connection_count(&self) -> u64 {
        self.connections.load(Ordering::Relaxed)
    }

    /// Increment connections
    pub fn connect(&self) {
        self.connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement connections
    pub fn disconnect(&self) {
        self.connections.fetch_sub(1, Ordering::Relaxed);
    }

    /// Read from volume
    pub fn read(&self, offset: u64, length: u32) -> BlockResult<ReadResult> {
        if offset + length as u64 > self.virtual_size {
            return Err(BlockError::InvalidOffset {
                offset,
                size: self.virtual_size,
            });
        }

        let end = offset + length as u64;
        let extents = self.extents.lookup_range(offset, end);

        if extents.is_empty() {
            // All zeros (hole)
            return Ok(ReadResult::Zero { length });
        }

        // Build list of data ranges to read
        let mut ranges = Vec::new();
        let mut current_offset = offset;

        for extent in extents {
            // Handle gap before extent (hole)
            if current_offset < extent.offset {
                let hole_len = (extent.offset - current_offset) as u32;
                ranges.push(DataRange::Zero {
                    offset: current_offset,
                    length: hole_len,
                });
                current_offset = extent.offset;
            }

            // Handle extent data
            let extent_start = current_offset.max(extent.offset);
            let extent_end = end.min(extent.end());
            let data_offset = extent.object_offset + (extent_start - extent.offset);

            if extent.is_hole() {
                ranges.push(DataRange::Zero {
                    offset: extent_start,
                    length: (extent_end - extent_start) as u32,
                });
            } else {
                ranges.push(DataRange::Data {
                    offset: extent_start,
                    length: (extent_end - extent_start) as u32,
                    object_key: extent.object_key.clone(),
                    object_offset: data_offset,
                });
            }

            current_offset = extent_end;
        }

        // Handle trailing hole
        if current_offset < end {
            ranges.push(DataRange::Zero {
                offset: current_offset,
                length: (end - current_offset) as u32,
            });
        }

        Ok(ReadResult::Ranges(ranges))
    }

    /// Write to volume (returns chunks that need to be written)
    pub fn write(&self, offset: u64, length: u32) -> BlockResult<WriteResult> {
        if self.read_only {
            return Err(BlockError::ReadOnly);
        }

        if offset + length as u64 > self.virtual_size {
            return Err(BlockError::InvalidOffset {
                offset,
                size: self.virtual_size,
            });
        }

        // Check for COW (if extent is shared)
        let extents = self.extents.lookup_range(offset, offset + length as u64);
        let needs_cow = extents.iter().any(|e| e.is_shared());

        Ok(WriteResult {
            offset,
            length,
            needs_cow,
        })
    }

    /// Add a child snapshot reference
    pub fn add_child(&self, child_id: VolumeId) {
        self.children.write().push(child_id);
    }

    /// Remove a child snapshot reference
    pub fn remove_child(&self, child_id: &VolumeId) {
        self.children.write().retain(|id| id != child_id);
    }

    /// Check if volume has children
    pub fn has_children(&self) -> bool {
        !self.children.read().is_empty()
    }
}

impl Volume for ThinVolume {
    fn id(&self) -> VolumeId {
        self.id
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn size(&self) -> u64 {
        self.virtual_size
    }

    fn block_size(&self) -> u32 {
        self.block_size
    }

    fn is_read_only(&self) -> bool {
        self.read_only
    }

    fn state(&self) -> VolumeState {
        self.state
    }
}

/// Result of a read operation
#[derive(Debug)]
pub enum ReadResult {
    /// All zeros
    Zero { length: u32 },
    /// Data ranges to read
    Ranges(Vec<DataRange>),
}

/// A range of data to read
#[derive(Debug, Clone)]
pub enum DataRange {
    /// Zero-filled range
    Zero { offset: u64, length: u32 },
    /// Data from object storage
    Data {
        offset: u64,
        length: u32,
        object_key: String,
        object_offset: u64,
    },
}

/// Result of a write operation
#[derive(Debug)]
pub struct WriteResult {
    /// Offset
    pub offset: u64,
    /// Length
    pub length: u32,
    /// Whether COW is needed
    pub needs_cow: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thin_pool_creation() {
        let config = ThinPoolConfig::new("test-pool", "test-bucket");
        let pool = ThinPool::new(config);

        assert_eq!(pool.name(), "test-pool");
        assert_eq!(pool.allocated_bytes(), 0);
    }

    #[test]
    fn test_chunk_allocation() {
        let config = ThinPoolConfig::new("test-pool", "test-bucket");
        let pool = ThinPool::new(config);

        let chunk1 = pool.allocate_chunk().unwrap();
        let chunk2 = pool.allocate_chunk().unwrap();

        assert_ne!(chunk1, chunk2);
        assert_eq!(pool.allocated_bytes(), 2 * pool.chunk_size());
    }

    #[test]
    fn test_chunk_free() {
        let config = ThinPoolConfig::new("test-pool", "test-bucket");
        let pool = ThinPool::new(config);

        let chunk = pool.allocate_chunk().unwrap();
        assert_eq!(pool.allocated_bytes(), pool.chunk_size());

        pool.free_chunk(chunk);
        assert_eq!(pool.allocated_bytes(), 0);
    }

    #[test]
    fn test_thin_volume() {
        let config = ThinVolumeConfig::new("test-vol", "pool", 1024 * 1024 * 1024);
        let id = VolumeId::generate();
        let volume = ThinVolume::new(id, config, 64 * 1024);

        assert_eq!(volume.size(), 1024 * 1024 * 1024);
        assert_eq!(volume.allocated(), 0);
        assert!(!volume.is_read_only());
    }

    #[test]
    fn test_thin_volume_read_hole() {
        let config = ThinVolumeConfig::new("test-vol", "pool", 1024 * 1024);
        let id = VolumeId::generate();
        let volume = ThinVolume::new(id, config, 64 * 1024);

        let result = volume.read(0, 4096).unwrap();
        match result {
            ReadResult::Zero { length } => assert_eq!(length, 4096),
            _ => panic!("Expected zero result"),
        }
    }

    #[test]
    fn test_thin_volume_read_only() {
        let config = ThinVolumeConfig::new("test-vol", "pool", 1024 * 1024).read_only();
        let id = VolumeId::generate();
        let volume = ThinVolume::new(id, config, 64 * 1024);

        let result = volume.write(0, 4096);
        assert!(matches!(result, Err(BlockError::ReadOnly)));
    }
}
