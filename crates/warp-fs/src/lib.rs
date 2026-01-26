#![allow(clippy::collapsible_if)]
#![allow(clippy::await_holding_lock)]
#![allow(clippy::significant_drop_tightening)]
#![allow(clippy::field_reassign_with_default)]
#![allow(dead_code)]

//! # warp-fs: POSIX Filesystem Layer for WARP Storage
//!
//! Mount warp-store as a local filesystem using FUSE.
//!
//! ## Features
//!
//! - **POSIX Compliance**: Standard file operations (read, write, mkdir, etc.)
//! - **High Performance**: Multi-tier caching (inode, dentry, data)
//! - **Seamless Integration**: Built on warp-store for distributed storage
//! - **Lazy Loading**: Only fetch data when accessed
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use warp_fs::{WarpFs, WarpFsConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), warp_fs::Error> {
//!     // Create filesystem backed by warp-store
//!     let config = WarpFsConfig::default();
//!     let fs = WarpFs::new(config).await?;
//!
//!     // Mount at /mnt/warp (blocks until unmounted)
//!     fs.mount("/mnt/warp").await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────┐
//! │           FUSE Interface            │
//! │  (lookup, read, write, readdir...)  │
//! └──────────────┬──────────────────────┘
//!                │
//! ┌──────────────▼──────────────────────┐
//! │          VFS Abstraction            │
//! │  (path resolution, inode mapping)   │
//! └──────────────┬──────────────────────┘
//!                │
//! ┌──────────────▼──────────────────────┐
//! │         Caching Layer               │
//! │  (inode, dentry, data caches)       │
//! └──────────────┬──────────────────────┘
//!                │
//! ┌──────────────▼──────────────────────┐
//! │      warp-store Backend             │
//! │  (object storage operations)        │
//! └─────────────────────────────────────┘
//! ```

#![warn(missing_docs)]

pub mod cache;
pub mod error;
pub mod fuse_ops;
pub mod inode;
pub mod metadata;
pub mod vfs;

pub use error::{Error, Result};
pub use inode::{Inode, InodeKind};
pub use metadata::{DataExtent, DirectoryEntry, FileType, InodeMetadata};
pub use vfs::VirtualFilesystem;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info};
use warp_store::{Store, StoreConfig};

/// Configuration for the WARP filesystem
#[derive(Debug, Clone)]
pub struct WarpFsConfig {
    /// warp-store configuration
    pub store_config: StoreConfig,

    /// Bucket to mount (objects become files under this bucket)
    pub bucket: String,

    /// Maximum entries in inode cache
    pub inode_cache_size: usize,

    /// Maximum entries in dentry cache
    pub dentry_cache_size: usize,

    /// Maximum bytes in data cache
    pub data_cache_bytes: usize,

    /// Cache entry TTL
    pub cache_ttl: Duration,

    /// Writeback delay before flushing to storage
    pub writeback_delay: Duration,

    /// Enable direct I/O (bypass page cache)
    pub direct_io: bool,

    /// Default file permissions (octal)
    pub default_file_mode: u32,

    /// Default directory permissions (octal)
    pub default_dir_mode: u32,

    /// UID for all files (None = use calling process UID)
    pub uid: Option<u32>,

    /// GID for all files (None = use calling process GID)
    pub gid: Option<u32>,

    /// Block size for filesystem (default: 4KB)
    pub block_size: u32,
}

impl Default for WarpFsConfig {
    fn default() -> Self {
        Self {
            store_config: StoreConfig::default(),
            bucket: "warp-fs".to_string(),
            inode_cache_size: 100_000,
            dentry_cache_size: 100_000,
            data_cache_bytes: 1024 * 1024 * 1024, // 1GB
            cache_ttl: Duration::from_secs(60),
            writeback_delay: Duration::from_millis(100),
            direct_io: false,
            default_file_mode: 0o644,
            default_dir_mode: 0o755,
            uid: None,
            gid: None,
            block_size: 4096,
        }
    }
}

/// The WARP FUSE filesystem
///
/// This is the main entry point for mounting a warp-store bucket
/// as a POSIX filesystem.
pub struct WarpFs {
    /// Configuration
    config: WarpFsConfig,

    /// Virtual filesystem layer
    vfs: Arc<VirtualFilesystem>,

    /// The underlying warp-store
    store: Arc<Store>,
}

impl WarpFs {
    /// Create a new WARP filesystem
    pub async fn new(config: WarpFsConfig) -> Result<Self> {
        info!(bucket = %config.bucket, "Initializing WARP filesystem");

        // Initialize warp-store
        let store = Store::new(config.store_config.clone()).await?;
        let store = Arc::new(store);

        // Ensure the bucket exists
        let buckets = store.list_buckets().await;
        if !buckets.contains(&config.bucket) {
            debug!(bucket = %config.bucket, "Creating filesystem bucket");
            store
                .create_bucket(&config.bucket, warp_store::BucketConfig::default())
                .await?;
        }

        // Initialize the VFS
        let vfs = VirtualFilesystem::new(
            store.clone(),
            config.bucket.clone(),
            config.inode_cache_size,
            config.dentry_cache_size,
            config.data_cache_bytes,
            config.cache_ttl,
        )
        .await?;

        Ok(Self {
            config,
            vfs: Arc::new(vfs),
            store,
        })
    }

    /// Mount the filesystem at the given path
    ///
    /// This blocks until the filesystem is unmounted.
    pub fn mount<P: AsRef<Path>>(&self, mountpoint: P) -> Result<()> {
        let mountpoint = mountpoint.as_ref();
        info!(path = %mountpoint.display(), "Mounting WARP filesystem");

        // Build FUSE mount options
        let options = vec![
            fuser::MountOption::FSName("warp-fs".to_string()),
            fuser::MountOption::Subtype("warp".to_string()),
            fuser::MountOption::DefaultPermissions,
        ];

        if self.config.direct_io {
            // Note: Direct I/O is handled per-open, not as mount option
            debug!("Direct I/O mode enabled");
        }

        // Create the FUSE filesystem handler
        let fuse_fs = fuse_ops::WarpFuseFs::new(self.vfs.clone(), self.config.clone());

        // Mount (this blocks)
        fuser::mount2(fuse_fs, mountpoint, &options)?;

        info!(path = %mountpoint.display(), "WARP filesystem unmounted");
        Ok(())
    }

    /// Mount the filesystem in the background
    ///
    /// Returns a handle that can be used to unmount.
    pub fn mount_background<P: AsRef<Path>>(&self, mountpoint: P) -> Result<MountHandle> {
        let mountpoint = mountpoint.as_ref().to_path_buf();
        info!(path = %mountpoint.display(), "Mounting WARP filesystem in background");

        let options = vec![
            fuser::MountOption::FSName("warp-fs".to_string()),
            fuser::MountOption::Subtype("warp".to_string()),
            fuser::MountOption::DefaultPermissions,
            fuser::MountOption::AutoUnmount,
        ];

        let fuse_fs = fuse_ops::WarpFuseFs::new(self.vfs.clone(), self.config.clone());

        let session = fuser::Session::new(fuse_fs, &mountpoint, &options)?;
        let session_guard = session.spawn()?;

        Ok(MountHandle {
            mountpoint,
            _session: session_guard,
        })
    }

    /// Get reference to the underlying store
    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    /// Get reference to the VFS layer
    pub fn vfs(&self) -> &Arc<VirtualFilesystem> {
        &self.vfs
    }

    /// Get filesystem statistics
    pub fn stats(&self) -> FsStats {
        self.vfs.stats()
    }
}

/// Handle for a background-mounted filesystem
pub struct MountHandle {
    mountpoint: std::path::PathBuf,
    _session: fuser::BackgroundSession,
}

impl MountHandle {
    /// Get the mount point path
    pub fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }
}

impl Drop for MountHandle {
    fn drop(&mut self) {
        debug!(path = %self.mountpoint.display(), "Unmounting WARP filesystem");
    }
}

/// Filesystem statistics
#[derive(Debug, Clone, Default)]
pub struct FsStats {
    /// Total objects in the filesystem
    pub total_objects: u64,

    /// Total bytes stored
    pub total_bytes: u64,

    /// Inode cache hits
    pub inode_cache_hits: u64,

    /// Inode cache misses
    pub inode_cache_misses: u64,

    /// Dentry cache hits
    pub dentry_cache_hits: u64,

    /// Dentry cache misses
    pub dentry_cache_misses: u64,

    /// Data cache hits
    pub data_cache_hits: u64,

    /// Data cache misses
    pub data_cache_misses: u64,

    /// Read operations
    pub reads: u64,

    /// Write operations
    pub writes: u64,

    /// Bytes read
    pub bytes_read: u64,

    /// Bytes written
    pub bytes_written: u64,
}

// Re-export fuser types for convenience
pub use fuser::FileType as FuseFileType;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_config_default() {
        let config = WarpFsConfig::default();
        assert_eq!(config.bucket, "warp-fs");
        assert_eq!(config.block_size, 4096);
        assert_eq!(config.default_file_mode, 0o644);
    }
}
