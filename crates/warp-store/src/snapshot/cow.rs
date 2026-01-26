//! Copy-on-Write block management for efficient snapshots

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use dashmap::DashMap;
use parking_lot::RwLock;
use tracing::{debug, info};

/// Unique identifier for a COW block
pub type BlockId = u64;

/// State of a COW block
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockState {
    /// Block contains data
    Active,
    /// Block is being written
    Writing,
    /// Block is pending deletion (refcount = 0)
    PendingDelete,
    /// Block has been deleted
    Deleted,
}

/// Reference to a COW block
#[derive(Debug, Clone)]
pub struct BlockRef {
    /// Block ID
    pub block_id: BlockId,
    /// Offset within the block
    pub offset: u64,
    /// Length of data
    pub length: u64,
    /// Generation (for versioning)
    pub generation: u64,
}

impl BlockRef {
    /// Create a new block reference
    pub fn new(block_id: BlockId, offset: u64, length: u64) -> Self {
        Self {
            block_id,
            offset,
            length,
            generation: 0,
        }
    }

    /// Create a full block reference
    pub fn full_block(block_id: BlockId, length: u64) -> Self {
        Self::new(block_id, 0, length)
    }
}

/// A copy-on-write block
#[derive(Debug, Clone)]
pub struct CowBlock {
    /// Block ID
    pub id: BlockId,

    /// Block state
    pub state: BlockState,

    /// Reference count
    pub ref_count: u64,

    /// Block size in bytes
    pub size: u64,

    /// Content checksum
    pub checksum: [u8; 32],

    /// When block was created
    pub created_at: SystemTime,

    /// Last access time
    pub last_accessed: Option<SystemTime>,

    /// Storage location (backend-specific)
    pub storage_path: String,

    /// Inline data (for small blocks)
    pub inline_data: Option<Vec<u8>>,

    /// Compression type
    pub compression: Option<String>,

    /// Original size before compression
    pub original_size: u64,
}

impl CowBlock {
    /// Create a new COW block
    pub fn new(size: u64, checksum: [u8; 32], storage_path: impl Into<String>) -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);

        Self {
            id: NEXT_ID.fetch_add(1, Ordering::SeqCst),
            state: BlockState::Active,
            ref_count: 1,
            size,
            checksum,
            created_at: SystemTime::now(),
            last_accessed: None,
            storage_path: storage_path.into(),
            inline_data: None,
            compression: None,
            original_size: size,
        }
    }

    /// Create a block with inline data
    pub fn with_inline_data(data: Vec<u8>, checksum: [u8; 32]) -> Self {
        let size = data.len() as u64;
        Self {
            id: {
                static NEXT_ID: AtomicU64 = AtomicU64::new(1);
                NEXT_ID.fetch_add(1, Ordering::SeqCst)
            },
            state: BlockState::Active,
            ref_count: 1,
            size,
            checksum,
            created_at: SystemTime::now(),
            last_accessed: None,
            storage_path: String::new(),
            inline_data: Some(data),
            compression: None,
            original_size: size,
        }
    }

    /// Check if block can be deleted
    pub fn can_delete(&self) -> bool {
        self.ref_count == 0 && self.state == BlockState::Active
    }

    /// Check if data is inline
    pub fn is_inline(&self) -> bool {
        self.inline_data.is_some()
    }

    /// Get compression ratio
    pub fn compression_ratio(&self) -> f64 {
        if self.original_size == 0 {
            return 1.0;
        }
        self.size as f64 / self.original_size as f64
    }
}

/// Configuration for COW manager
#[derive(Debug, Clone)]
pub struct CowConfig {
    /// Block size
    pub block_size: usize,

    /// Enable deduplication
    pub dedup_enabled: bool,

    /// Maximum inline data size (store small data directly)
    pub inline_data_threshold: usize,

    /// Enable compression
    pub compression_enabled: bool,

    /// Compression algorithm
    pub compression_type: String,

    /// Background cleanup interval
    pub cleanup_interval: Duration,

    /// Maximum blocks to cleanup per cycle
    pub cleanup_batch_size: usize,
}

impl Default for CowConfig {
    /// Creates a default COW configuration with sensible defaults.
    ///
    /// Defaults:
    /// - Block size: 64KB
    /// - Deduplication: enabled
    /// - Inline data threshold: 4KB
    /// - Compression: disabled
    /// - Compression type: lz4
    /// - Cleanup interval: 60 seconds
    /// - Cleanup batch size: 1000 blocks
    fn default() -> Self {
        Self {
            block_size: 64 * 1024, // 64KB blocks
            dedup_enabled: true,
            inline_data_threshold: 4096, // 4KB
            compression_enabled: false,
            compression_type: "lz4".to_string(),
            cleanup_interval: Duration::from_secs(60),
            cleanup_batch_size: 1000,
        }
    }
}

/// Statistics for COW operations
#[derive(Debug, Clone, Default)]
pub struct CowStats {
    /// Total blocks created
    pub blocks_created: u64,
    /// Total blocks deleted
    pub blocks_deleted: u64,
    /// Current active blocks
    pub active_blocks: u64,
    /// Total bytes stored
    pub total_bytes: u64,
    /// Bytes saved by dedup
    pub dedup_bytes_saved: u64,
    /// Dedup hit count
    pub dedup_hits: u64,
    /// Bytes saved by compression
    pub compression_bytes_saved: u64,
    /// Inline blocks count
    pub inline_blocks: u64,
}

/// Manages copy-on-write blocks
pub struct CowManager {
    /// Configuration
    config: CowConfig,

    /// All blocks by ID
    blocks: DashMap<BlockId, CowBlock>,

    /// Checksum to block ID index (for dedup)
    checksum_index: DashMap<[u8; 32], BlockId>,

    /// Pending deletes
    pending_deletes: RwLock<Vec<BlockId>>,

    /// Statistics
    stats: RwLock<CowStats>,
}

impl CowManager {
    /// Create a new COW manager
    pub fn new(config: CowConfig) -> Self {
        Self {
            config,
            blocks: DashMap::new(),
            checksum_index: DashMap::new(),
            pending_deletes: RwLock::new(Vec::new()),
            stats: RwLock::new(CowStats::default()),
        }
    }

    /// Allocate a new block or return existing deduplicated block
    pub fn allocate_block(&self, data: &[u8], checksum: [u8; 32]) -> BlockRef {
        // Check for dedup hit
        if self.config.dedup_enabled {
            if let Some(existing_id) = self.checksum_index.get(&checksum) {
                // Found existing block with same content
                if let Some(mut block) = self.blocks.get_mut(&existing_id) {
                    block.ref_count += 1;
                    block.last_accessed = Some(SystemTime::now());

                    // Update stats
                    {
                        let mut stats = self.stats.write();
                        stats.dedup_hits += 1;
                        stats.dedup_bytes_saved += data.len() as u64;
                    }

                    debug!(block_id = *existing_id, "Dedup hit, reusing existing block");

                    return BlockRef::full_block(*existing_id, data.len() as u64);
                }
            }
        }

        // Create new block
        let block = if data.len() <= self.config.inline_data_threshold {
            // Store inline
            let block = CowBlock::with_inline_data(data.to_vec(), checksum);
            {
                let mut stats = self.stats.write();
                stats.inline_blocks += 1;
            }
            block
        } else {
            // Store externally
            let storage_path = format!(
                "blocks/{:016x}",
                checksum[0..8]
                    .iter()
                    .fold(0u64, |acc, &b| (acc << 8) | b as u64)
            );
            CowBlock::new(data.len() as u64, checksum, storage_path)
        };

        let block_id = block.id;
        let block_size = block.size;

        // Index by checksum for dedup
        if self.config.dedup_enabled {
            self.checksum_index.insert(checksum, block_id);
        }

        // Store the block
        self.blocks.insert(block_id, block);

        // Update stats
        {
            let mut stats = self.stats.write();
            stats.blocks_created += 1;
            stats.active_blocks += 1;
            stats.total_bytes += block_size;
        }

        debug!(block_id, size = block_size, "Created new block");

        BlockRef::full_block(block_id, block_size)
    }

    /// Increment reference count for a block
    pub fn add_ref(&self, block_id: BlockId) -> Result<(), String> {
        if let Some(mut block) = self.blocks.get_mut(&block_id) {
            block.ref_count += 1;
            block.last_accessed = Some(SystemTime::now());
            Ok(())
        } else {
            Err(format!("Block {} not found", block_id))
        }
    }

    /// Decrement reference count for a block
    pub fn release_ref(&self, block_id: BlockId) -> Result<(), String> {
        if let Some(mut block) = self.blocks.get_mut(&block_id) {
            if block.ref_count == 0 {
                return Err(format!("Block {} already has zero references", block_id));
            }

            block.ref_count -= 1;

            if block.ref_count == 0 {
                // Schedule for deletion
                self.pending_deletes.write().push(block_id);
            }

            Ok(())
        } else {
            Err(format!("Block {} not found", block_id))
        }
    }

    /// Get a block by ID
    pub fn get_block(&self, block_id: BlockId) -> Option<CowBlock> {
        self.blocks.get(&block_id).map(|b| {
            // Update last accessed
            // Note: This is a read operation, so we don't update in real impl
            b.clone()
        })
    }

    /// Get block data (for inline blocks)
    pub fn get_block_data(&self, block_id: BlockId) -> Option<Vec<u8>> {
        self.blocks
            .get(&block_id)
            .and_then(|b| b.inline_data.clone())
    }

    /// Copy block on write - create a new block with modified data
    pub fn copy_on_write(
        &self,
        block_id: BlockId,
        new_data: &[u8],
        new_checksum: [u8; 32],
    ) -> Result<BlockRef, String> {
        // Verify source block exists
        if !self.blocks.contains_key(&block_id) {
            return Err(format!("Source block {} not found", block_id));
        }

        // Release reference to old block
        self.release_ref(block_id)?;

        // Allocate new block with new data
        Ok(self.allocate_block(new_data, new_checksum))
    }

    /// Run cleanup of unreferenced blocks
    pub fn cleanup(&self) -> usize {
        let mut to_delete: Vec<BlockId> = Vec::new();

        // Get pending deletes
        {
            let mut pending = self.pending_deletes.write();
            to_delete.append(&mut pending);
        }

        // Limit batch size
        to_delete.truncate(self.config.cleanup_batch_size);

        let mut deleted = 0;

        for block_id in to_delete {
            if let Some(block) = self.blocks.get(&block_id) {
                // Double-check ref count
                if block.ref_count == 0 {
                    let checksum = block.checksum;
                    let size = block.size;
                    drop(block);

                    // Remove from checksum index
                    self.checksum_index.remove(&checksum);

                    // Remove block
                    self.blocks.remove(&block_id);

                    // Update stats
                    {
                        let mut stats = self.stats.write();
                        stats.blocks_deleted += 1;
                        stats.active_blocks = stats.active_blocks.saturating_sub(1);
                        stats.total_bytes = stats.total_bytes.saturating_sub(size);
                    }

                    deleted += 1;
                    debug!(block_id, "Deleted unreferenced block");
                }
            }
        }

        if deleted > 0 {
            info!(deleted, "Cleaned up unreferenced blocks");
        }

        deleted
    }

    /// Get statistics
    pub fn stats(&self) -> CowStats {
        self.stats.read().clone()
    }

    /// Get block count
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Get total bytes stored
    pub fn total_bytes(&self) -> u64 {
        self.stats.read().total_bytes
    }

    /// Calculate dedup ratio
    pub fn dedup_ratio(&self) -> f64 {
        let stats = self.stats.read();
        let total_referenced = stats.total_bytes + stats.dedup_bytes_saved;
        if total_referenced == 0 {
            return 1.0;
        }
        stats.total_bytes as f64 / total_referenced as f64
    }

    /// Get blocks by state
    pub fn blocks_by_state(&self, state: BlockState) -> Vec<BlockId> {
        self.blocks
            .iter()
            .filter(|r| r.state == state)
            .map(|r| r.id)
            .collect()
    }

    /// Find block by checksum
    pub fn find_by_checksum(&self, checksum: &[u8; 32]) -> Option<BlockId> {
        self.checksum_index.get(checksum).map(|r| *r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_checksum(seed: u8) -> [u8; 32] {
        let mut checksum = [0u8; 32];
        for (i, byte) in checksum.iter_mut().enumerate() {
            *byte = seed.wrapping_add(i as u8);
        }
        checksum
    }

    #[test]
    fn test_allocate_block() {
        let manager = CowManager::new(CowConfig::default());

        let data = b"Hello, World!";
        let checksum = test_checksum(1);

        let block_ref = manager.allocate_block(data, checksum);

        assert!(manager.get_block(block_ref.block_id).is_some());
        assert_eq!(block_ref.length, data.len() as u64);
    }

    #[test]
    fn test_deduplication() {
        let manager = CowManager::new(CowConfig {
            dedup_enabled: true,
            ..Default::default()
        });

        let data = b"Same data content";
        let checksum = test_checksum(2);

        let block1 = manager.allocate_block(data, checksum);
        let block2 = manager.allocate_block(data, checksum);

        // Should reuse same block
        assert_eq!(block1.block_id, block2.block_id);

        // Ref count should be 2
        let block = manager.get_block(block1.block_id).unwrap();
        assert_eq!(block.ref_count, 2);

        // Stats should show dedup hit
        let stats = manager.stats();
        assert_eq!(stats.dedup_hits, 1);
    }

    #[test]
    fn test_inline_data() {
        let config = CowConfig {
            inline_data_threshold: 1024,
            ..Default::default()
        };
        let manager = CowManager::new(config);

        // Small data - should be inline
        let small_data = b"small";
        let small_block = manager.allocate_block(small_data, test_checksum(3));
        assert!(manager.get_block(small_block.block_id).unwrap().is_inline());

        // Large data - should not be inline
        let large_data = vec![0u8; 2048];
        let large_block = manager.allocate_block(&large_data, test_checksum(4));
        assert!(!manager.get_block(large_block.block_id).unwrap().is_inline());
    }

    #[test]
    fn test_reference_counting() {
        let manager = CowManager::new(CowConfig::default());

        let data = b"Test data";
        let block_ref = manager.allocate_block(data, test_checksum(5));
        let block_id = block_ref.block_id;

        // Initial ref count is 1
        assert_eq!(manager.get_block(block_id).unwrap().ref_count, 1);

        // Add reference
        manager.add_ref(block_id).unwrap();
        assert_eq!(manager.get_block(block_id).unwrap().ref_count, 2);

        // Release reference
        manager.release_ref(block_id).unwrap();
        assert_eq!(manager.get_block(block_id).unwrap().ref_count, 1);

        // Release last reference - should be scheduled for deletion
        manager.release_ref(block_id).unwrap();
        assert_eq!(manager.get_block(block_id).unwrap().ref_count, 0);
    }

    #[test]
    fn test_cleanup() {
        let manager = CowManager::new(CowConfig::default());

        let data = b"Test data for cleanup";
        let block_ref = manager.allocate_block(data, test_checksum(6));
        let block_id = block_ref.block_id;

        // Release reference
        manager.release_ref(block_id).unwrap();

        // Block still exists
        assert!(manager.get_block(block_id).is_some());

        // Run cleanup
        let deleted = manager.cleanup();
        assert_eq!(deleted, 1);

        // Block should be gone
        assert!(manager.get_block(block_id).is_none());
    }

    #[test]
    fn test_copy_on_write() {
        let manager = CowManager::new(CowConfig::default());

        let original_data = b"Original data";
        let block_ref = manager.allocate_block(original_data, test_checksum(7));
        let original_id = block_ref.block_id;

        // Add another reference (simulate snapshot)
        manager.add_ref(original_id).unwrap();

        // Copy on write
        let new_data = b"Modified data";
        let new_ref = manager
            .copy_on_write(original_id, new_data, test_checksum(8))
            .unwrap();

        // New block should be different
        assert_ne!(new_ref.block_id, original_id);

        // Original block should still exist with ref count 1 (snapshot still holds it)
        let original = manager.get_block(original_id).unwrap();
        assert_eq!(original.ref_count, 1);
    }
}
