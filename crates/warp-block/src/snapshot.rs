//! Block device snapshots
//!
//! Implements copy-on-write (COW) snapshots for thin volumes.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;

use crate::config::ThinVolumeConfig;
use crate::error::{BlockError, BlockResult};
use crate::extent::ExtentMap;
use crate::thin::{ThinPool, ThinVolume};
use crate::volume::{VolumeId, VolumeState};

/// Block snapshot
#[derive(Debug)]
pub struct BlockSnapshot {
    /// Snapshot ID
    pub id: VolumeId,
    /// Snapshot name
    pub name: String,
    /// Source volume ID
    pub source_id: VolumeId,
    /// Creation timestamp (unix epoch seconds)
    pub created_at: u64,
    /// Snapshot extent map (shared with source at creation)
    pub extents: ExtentMap,
    /// Virtual size (same as source at creation)
    pub size: u64,
    /// State
    pub state: SnapshotState,
}

impl BlockSnapshot {
    /// Create a new snapshot from a volume
    pub fn from_volume(name: impl Into<String>, source: &ThinVolume) -> Self {
        let id = VolumeId::generate();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Clone the extent map with shared flag
        let extents = source.extents.clone_for_snapshot();

        Self {
            id,
            name: name.into(),
            source_id: source.id,
            created_at: now,
            extents,
            size: source.virtual_size,
            state: SnapshotState::Active,
        }
    }

    /// Get snapshot ID
    pub fn id(&self) -> VolumeId {
        self.id
    }

    /// Get snapshot name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get source volume ID
    pub fn source_id(&self) -> VolumeId {
        self.source_id
    }

    /// Get creation time
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Get size
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Get allocated bytes
    pub fn allocated(&self) -> u64 {
        self.extents.allocated()
    }

    /// Check if snapshot is active
    pub fn is_active(&self) -> bool {
        self.state == SnapshotState::Active
    }
}

/// Snapshot state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotState {
    /// Snapshot is active
    Active,
    /// Snapshot is being created
    Creating,
    /// Snapshot is being deleted
    Deleting,
    /// Snapshot is invalid (source was modified without COW)
    Invalid,
}

/// Snapshot manager
#[derive(Debug)]
pub struct SnapshotManager {
    /// Snapshots by ID
    snapshots: DashMap<VolumeId, BlockSnapshot>,
    /// Snapshots by source volume
    by_source: DashMap<VolumeId, Vec<VolumeId>>,
}

impl SnapshotManager {
    /// Create a new snapshot manager
    pub fn new() -> Self {
        Self {
            snapshots: DashMap::new(),
            by_source: DashMap::new(),
        }
    }

    /// Create a snapshot
    pub fn create_snapshot(
        &self,
        name: impl Into<String>,
        source: &ThinVolume,
    ) -> BlockResult<VolumeId> {
        let snapshot = BlockSnapshot::from_volume(name, source);
        let id = snapshot.id;

        // Track by source volume
        self.by_source
            .entry(source.id)
            .or_default()
            .push(id);

        self.snapshots.insert(id, snapshot);
        Ok(id)
    }

    /// Get a snapshot
    pub fn get_snapshot(&self, id: &VolumeId) -> Option<dashmap::mapref::one::Ref<VolumeId, BlockSnapshot>> {
        self.snapshots.get(id)
    }

    /// Delete a snapshot
    pub fn delete_snapshot(&self, id: &VolumeId) -> BlockResult<()> {
        if let Some((_, snapshot)) = self.snapshots.remove(id) {
            // Remove from source tracking
            if let Some(mut snapshots) = self.by_source.get_mut(&snapshot.source_id) {
                snapshots.retain(|s| s != id);
            }
            Ok(())
        } else {
            Err(BlockError::SnapshotNotFound(format!("{}", id)))
        }
    }

    /// Get all snapshots for a source volume
    pub fn get_snapshots_for_volume(&self, source_id: &VolumeId) -> Vec<VolumeId> {
        self.by_source
            .get(source_id)
            .map(|v| v.clone())
            .unwrap_or_default()
    }

    /// List all snapshots
    pub fn list_snapshots(&self) -> Vec<SnapshotInfo> {
        self.snapshots
            .iter()
            .map(|entry| {
                let snapshot = entry.value();
                SnapshotInfo {
                    id: snapshot.id,
                    name: snapshot.name.clone(),
                    source_id: snapshot.source_id,
                    created_at: snapshot.created_at,
                    size: snapshot.size,
                    allocated: snapshot.allocated(),
                    state: snapshot.state,
                }
            })
            .collect()
    }

    /// Check if a volume has snapshots
    pub fn has_snapshots(&self, source_id: &VolumeId) -> bool {
        self.by_source
            .get(source_id)
            .map(|v| !v.is_empty())
            .unwrap_or(false)
    }
}

impl Default for SnapshotManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot information
#[derive(Debug, Clone)]
pub struct SnapshotInfo {
    /// Snapshot ID
    pub id: VolumeId,
    /// Snapshot name
    pub name: String,
    /// Source volume ID
    pub source_id: VolumeId,
    /// Creation timestamp
    pub created_at: u64,
    /// Virtual size
    pub size: u64,
    /// Allocated bytes
    pub allocated: u64,
    /// Snapshot state
    pub state: SnapshotState,
}

impl SnapshotInfo {
    /// Get savings (difference between size and allocated)
    pub fn savings(&self) -> u64 {
        self.size.saturating_sub(self.allocated)
    }

    /// Get savings percentage
    pub fn savings_percent(&self) -> f64 {
        if self.size == 0 {
            0.0
        } else {
            (self.savings() as f64 / self.size as f64) * 100.0
        }
    }
}

/// COW (Copy-on-Write) manager
#[derive(Debug)]
pub struct CowManager {
    /// Pending COW operations
    pending: DashMap<(VolumeId, u64), CowOperation>,
}

impl CowManager {
    /// Create a new COW manager
    pub fn new() -> Self {
        Self {
            pending: DashMap::new(),
        }
    }

    /// Check if COW is needed for a write
    pub fn needs_cow(&self, volume_id: VolumeId, offset: u64, length: u64, extents: &ExtentMap) -> bool {
        // Check if any extent in the write range is shared
        let end = offset + length;
        for extent in extents.lookup_range(offset, end) {
            if extent.is_shared() {
                return true;
            }
        }
        false
    }

    /// Record a pending COW operation
    pub fn start_cow(&self, volume_id: VolumeId, offset: u64, length: u64) {
        let op = CowOperation {
            volume_id,
            offset,
            length,
            state: CowState::Pending,
        };
        self.pending.insert((volume_id, offset), op);
    }

    /// Complete a COW operation
    pub fn complete_cow(&self, volume_id: VolumeId, offset: u64) {
        self.pending.remove(&(volume_id, offset));
    }

    /// Get pending COW operations for a volume
    pub fn pending_for_volume(&self, volume_id: VolumeId) -> Vec<CowOperation> {
        self.pending
            .iter()
            .filter(|e| e.key().0 == volume_id)
            .map(|e| e.value().clone())
            .collect()
    }
}

impl Default for CowManager {
    fn default() -> Self {
        Self::new()
    }
}

/// COW operation
#[derive(Debug, Clone)]
pub struct CowOperation {
    /// Volume ID
    pub volume_id: VolumeId,
    /// Offset
    pub offset: u64,
    /// Length
    pub length: u64,
    /// State
    pub state: CowState,
}

/// COW operation state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CowState {
    /// Pending (not started)
    Pending,
    /// In progress
    InProgress,
    /// Complete
    Complete,
    /// Failed
    Failed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ThinVolumeConfig;

    fn create_test_volume() -> ThinVolume {
        let config = ThinVolumeConfig::new("test-vol", "pool", 1024 * 1024 * 1024);
        let id = VolumeId::generate();
        ThinVolume::new(id, config, 64 * 1024)
    }

    #[test]
    fn test_snapshot_creation() {
        let volume = create_test_volume();
        let snapshot = BlockSnapshot::from_volume("snap-1", &volume);

        assert_eq!(snapshot.source_id(), volume.id);
        assert_eq!(snapshot.size(), volume.size());
        assert!(snapshot.is_active());
    }

    #[test]
    fn test_snapshot_manager() {
        let mgr = SnapshotManager::new();
        let volume = create_test_volume();

        let snap_id = mgr.create_snapshot("snap-1", &volume).unwrap();
        assert!(mgr.get_snapshot(&snap_id).is_some());
        assert!(mgr.has_snapshots(&volume.id));

        let snapshots = mgr.get_snapshots_for_volume(&volume.id);
        assert_eq!(snapshots.len(), 1);

        mgr.delete_snapshot(&snap_id).unwrap();
        assert!(mgr.get_snapshot(&snap_id).is_none());
        assert!(!mgr.has_snapshots(&volume.id));
    }

    #[test]
    fn test_snapshot_info_savings() {
        let info = SnapshotInfo {
            id: VolumeId::generate(),
            name: "test".to_string(),
            source_id: VolumeId::generate(),
            created_at: 0,
            size: 1000,
            allocated: 250,
            state: SnapshotState::Active,
        };

        assert_eq!(info.savings(), 750);
        assert_eq!(info.savings_percent(), 75.0);
    }

    #[test]
    fn test_cow_manager() {
        let mgr = CowManager::new();
        let volume_id = VolumeId::generate();

        mgr.start_cow(volume_id, 0, 4096);
        let pending = mgr.pending_for_volume(volume_id);
        assert_eq!(pending.len(), 1);

        mgr.complete_cow(volume_id, 0);
        let pending = mgr.pending_for_volume(volume_id);
        assert_eq!(pending.len(), 0);
    }
}
