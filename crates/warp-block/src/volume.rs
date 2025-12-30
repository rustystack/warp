//! Volume management
//!
//! Defines the volume trait and common volume types.

use std::sync::atomic::{AtomicU64, Ordering};

/// Volume ID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VolumeId(u64);

impl VolumeId {
    /// Generate a new unique volume ID
    pub fn generate() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Self(COUNTER.fetch_add(1, Ordering::SeqCst))
    }

    /// Create from raw value
    pub fn from_raw(val: u64) -> Self {
        Self(val)
    }

    /// Get raw value
    pub fn raw(&self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for VolumeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "vol-{:08x}", self.0)
    }
}

/// Volume state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeState {
    /// Volume is active and usable
    Active,
    /// Volume is being created
    Creating,
    /// Volume is being deleted
    Deleting,
    /// Volume is degraded (some data may be unavailable)
    Degraded,
    /// Volume is faulted (unusable)
    Faulted,
    /// Volume is suspended (I/O paused)
    Suspended,
}

impl VolumeState {
    /// Check if volume is usable for I/O
    pub fn is_usable(&self) -> bool {
        matches!(self, Self::Active | Self::Degraded)
    }

    /// Check if volume is transitioning
    pub fn is_transitioning(&self) -> bool {
        matches!(self, Self::Creating | Self::Deleting)
    }
}

impl std::fmt::Display for VolumeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Creating => write!(f, "creating"),
            Self::Deleting => write!(f, "deleting"),
            Self::Degraded => write!(f, "degraded"),
            Self::Faulted => write!(f, "faulted"),
            Self::Suspended => write!(f, "suspended"),
        }
    }
}

/// Volume trait - common interface for all volume types
pub trait Volume: Send + Sync {
    /// Get volume ID
    fn id(&self) -> VolumeId;

    /// Get volume name
    fn name(&self) -> &str;

    /// Get virtual size in bytes
    fn size(&self) -> u64;

    /// Get block size
    fn block_size(&self) -> u32;

    /// Check if volume is read-only
    fn is_read_only(&self) -> bool;

    /// Get volume state
    fn state(&self) -> VolumeState;
}

/// Volume statistics
#[derive(Debug, Clone, Default)]
pub struct VolumeStats {
    /// Total read operations
    pub read_ops: u64,
    /// Total write operations
    pub write_ops: u64,
    /// Total bytes read
    pub bytes_read: u64,
    /// Total bytes written
    pub bytes_written: u64,
    /// Total flush operations
    pub flush_ops: u64,
    /// Total trim operations
    pub trim_ops: u64,
    /// Read errors
    pub read_errors: u64,
    /// Write errors
    pub write_errors: u64,
}

impl VolumeStats {
    /// Create new empty stats
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a read
    pub fn record_read(&mut self, bytes: u64) {
        self.read_ops += 1;
        self.bytes_read += bytes;
    }

    /// Record a write
    pub fn record_write(&mut self, bytes: u64) {
        self.write_ops += 1;
        self.bytes_written += bytes;
    }

    /// Record a flush
    pub fn record_flush(&mut self) {
        self.flush_ops += 1;
    }

    /// Record a trim
    pub fn record_trim(&mut self) {
        self.trim_ops += 1;
    }

    /// Record a read error
    pub fn record_read_error(&mut self) {
        self.read_errors += 1;
    }

    /// Record a write error
    pub fn record_write_error(&mut self) {
        self.write_errors += 1;
    }
}

/// Volume info (for listing/display)
#[derive(Debug, Clone)]
pub struct VolumeInfo {
    /// Volume ID
    pub id: VolumeId,
    /// Volume name
    pub name: String,
    /// Virtual size
    pub size: u64,
    /// Allocated bytes
    pub allocated: u64,
    /// Block size
    pub block_size: u32,
    /// Read-only flag
    pub read_only: bool,
    /// Volume state
    pub state: VolumeState,
    /// Pool name (for thin volumes)
    pub pool: Option<String>,
    /// Snapshot parent (if this is a snapshot)
    pub parent: Option<VolumeId>,
    /// Child count
    pub child_count: usize,
    /// Connection count
    pub connections: u64,
}

impl VolumeInfo {
    /// Get utilization percentage
    pub fn utilization(&self) -> f64 {
        if self.size == 0 {
            0.0
        } else {
            (self.allocated as f64 / self.size as f64) * 100.0
        }
    }

    /// Format size as human-readable string
    pub fn size_human(&self) -> String {
        format_bytes(self.size)
    }

    /// Format allocated as human-readable string
    pub fn allocated_human(&self) -> String {
        format_bytes(self.allocated)
    }
}

/// Format bytes as human-readable string
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.2} TiB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GiB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MiB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KiB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_volume_id() {
        let id1 = VolumeId::generate();
        let id2 = VolumeId::generate();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_volume_state() {
        assert!(VolumeState::Active.is_usable());
        assert!(VolumeState::Degraded.is_usable());
        assert!(!VolumeState::Faulted.is_usable());
        assert!(VolumeState::Creating.is_transitioning());
    }

    #[test]
    fn test_volume_stats() {
        let mut stats = VolumeStats::new();
        stats.record_read(4096);
        stats.record_write(8192);
        stats.record_flush();

        assert_eq!(stats.read_ops, 1);
        assert_eq!(stats.write_ops, 1);
        assert_eq!(stats.bytes_read, 4096);
        assert_eq!(stats.bytes_written, 8192);
        assert_eq!(stats.flush_ops, 1);
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(100), "100 B");
        assert_eq!(format_bytes(1536), "1.50 KiB");
        assert_eq!(format_bytes(1024 * 1024 * 2), "2.00 MiB");
        assert_eq!(format_bytes(1024 * 1024 * 1024 * 10), "10.00 GiB");
    }

    #[test]
    fn test_volume_info_utilization() {
        let info = VolumeInfo {
            id: VolumeId::generate(),
            name: "test".to_string(),
            size: 100,
            allocated: 25,
            block_size: 4096,
            read_only: false,
            state: VolumeState::Active,
            pool: None,
            parent: None,
            child_count: 0,
            connections: 0,
        };

        assert_eq!(info.utilization(), 25.0);
    }
}
