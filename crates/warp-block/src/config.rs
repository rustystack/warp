//! Block device configuration
//!
//! Configuration types for the NBD block device gateway.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

/// Block device server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockConfig {
    /// TCP bind address for NBD server
    pub bind_addr: SocketAddr,
    /// Maximum concurrent clients
    pub max_clients: usize,
    /// Default block size
    pub default_block_size: u32,
    /// Enable write-back caching
    pub write_cache: bool,
    /// Flush interval (ms) for write cache
    pub flush_interval_ms: u64,
    /// Enable TRIM/discard support
    pub trim_enabled: bool,
    /// Enable fast-zero support
    pub fast_zero_enabled: bool,
}

impl Default for BlockConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:10809".parse().unwrap(),
            max_clients: 100,
            default_block_size: 4096,
            write_cache: true,
            flush_interval_ms: 1000,
            trim_enabled: true,
            fast_zero_enabled: true,
        }
    }
}

impl BlockConfig {
    /// Create a new configuration with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Set bind address
    pub fn bind(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = addr;
        self
    }

    /// Set max clients
    pub fn max_clients(mut self, count: usize) -> Self {
        self.max_clients = count;
        self
    }

    /// Set block size
    pub fn block_size(mut self, size: u32) -> Self {
        self.default_block_size = size;
        self
    }

    /// Disable write cache
    pub fn no_write_cache(mut self) -> Self {
        self.write_cache = false;
        self
    }

    /// Disable TRIM
    pub fn no_trim(mut self) -> Self {
        self.trim_enabled = false;
        self
    }
}

/// Thin pool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThinPoolConfig {
    /// Pool name
    pub name: String,
    /// warp-store bucket for data chunks
    pub bucket: String,
    /// Chunk size (bytes) - allocation unit
    pub chunk_size: u64,
    /// Maximum pool size (bytes) - 0 for unlimited
    pub max_size: u64,
    /// Low watermark (percentage) for alerts
    pub low_watermark: u8,
    /// Critical watermark (percentage)
    pub critical_watermark: u8,
    /// Enable zero-on-allocate (default false for performance)
    pub zero_on_allocate: bool,
    /// Enable compression
    pub compression: bool,
}

impl Default for ThinPoolConfig {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            bucket: "warp-block".to_string(),
            chunk_size: 64 * 1024, // 64 KB
            max_size: 0,           // Unlimited
            low_watermark: 80,
            critical_watermark: 95,
            zero_on_allocate: false,
            compression: true,
        }
    }
}

impl ThinPoolConfig {
    /// Create a new pool configuration
    pub fn new(name: impl Into<String>, bucket: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            bucket: bucket.into(),
            ..Default::default()
        }
    }

    /// Set chunk size
    pub fn chunk_size(mut self, size: u64) -> Self {
        self.chunk_size = size;
        self
    }

    /// Set max size
    pub fn max_size(mut self, size: u64) -> Self {
        self.max_size = size;
        self
    }

    /// Enable zero-on-allocate
    pub fn zero_on_allocate(mut self) -> Self {
        self.zero_on_allocate = true;
        self
    }

    /// Disable compression
    pub fn no_compression(mut self) -> Self {
        self.compression = false;
        self
    }
}

/// Thin volume configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThinVolumeConfig {
    /// Volume name
    pub name: String,
    /// Pool name
    pub pool: String,
    /// Virtual size (bytes) - can exceed pool capacity
    pub virtual_size: u64,
    /// Block size (bytes) - for NBD clients
    pub block_size: u32,
    /// Read-only volume
    pub read_only: bool,
    /// Snapshot parent (if this is a snapshot)
    pub snapshot_of: Option<String>,
    /// Enable cache
    pub cache_enabled: bool,
    /// Cache size (bytes)
    pub cache_size: u64,
}

impl Default for ThinVolumeConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            pool: "default".to_string(),
            virtual_size: 0,
            block_size: 4096,
            read_only: false,
            snapshot_of: None,
            cache_enabled: true,
            cache_size: 64 * 1024 * 1024, // 64 MB
        }
    }
}

impl ThinVolumeConfig {
    /// Create a new volume configuration
    pub fn new(name: impl Into<String>, pool: impl Into<String>, virtual_size: u64) -> Self {
        Self {
            name: name.into(),
            pool: pool.into(),
            virtual_size,
            ..Default::default()
        }
    }

    /// Set block size
    pub fn block_size(mut self, size: u32) -> Self {
        self.block_size = size;
        self
    }

    /// Make read-only
    pub fn read_only(mut self) -> Self {
        self.read_only = true;
        self
    }

    /// Create as snapshot of another volume
    pub fn snapshot_of(mut self, parent: impl Into<String>) -> Self {
        self.snapshot_of = Some(parent.into());
        self.read_only = true; // Snapshots are read-only by default
        self
    }

    /// Disable cache
    pub fn no_cache(mut self) -> Self {
        self.cache_enabled = false;
        self
    }

    /// Set cache size
    pub fn cache_size(mut self, size: u64) -> Self {
        self.cache_size = size;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_config() {
        let config = BlockConfig::new()
            .bind("0.0.0.0:12345".parse().unwrap())
            .block_size(512)
            .no_trim();

        assert_eq!(config.bind_addr.port(), 12345);
        assert_eq!(config.default_block_size, 512);
        assert!(!config.trim_enabled);
    }

    #[test]
    fn test_thin_pool_config() {
        let config = ThinPoolConfig::new("test-pool", "test-bucket")
            .chunk_size(128 * 1024)
            .max_size(1024 * 1024 * 1024);

        assert_eq!(config.name, "test-pool");
        assert_eq!(config.bucket, "test-bucket");
        assert_eq!(config.chunk_size, 128 * 1024);
        assert_eq!(config.max_size, 1024 * 1024 * 1024);
    }

    #[test]
    fn test_thin_volume_config() {
        let config = ThinVolumeConfig::new("my-volume", "default", 10 * 1024 * 1024 * 1024)
            .block_size(512)
            .cache_size(128 * 1024 * 1024);

        assert_eq!(config.name, "my-volume");
        assert_eq!(config.virtual_size, 10 * 1024 * 1024 * 1024);
        assert_eq!(config.block_size, 512);
    }

    #[test]
    fn test_snapshot_config() {
        let config = ThinVolumeConfig::new("snap-1", "default", 10 * 1024 * 1024 * 1024)
            .snapshot_of("original");

        assert!(config.read_only);
        assert_eq!(config.snapshot_of, Some("original".to_string()));
    }
}
