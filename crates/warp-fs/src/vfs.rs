//! Virtual Filesystem abstraction layer
//!
//! Provides the bridge between FUSE operations and warp-store.

use crate::FsStats;
use crate::cache::CacheManager;
use crate::error::{Error, Result};
use crate::inode::{Ino, Inode, InodeAllocator, ROOT_INO};
use crate::metadata::{
    DataExtent, DirectoryContents, DirectoryEntry, FileType, InodeMetadata, Superblock,
};

use dashmap::DashMap;
use parking_lot::RwLock;
use std::ffi::OsStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tracing::{debug, info};
use warp_store::{ObjectData, ObjectKey, Store};

/// Metadata bucket prefix
const META_PREFIX: &str = "__warp_fs_meta__";

/// Virtual filesystem layer
///
/// Manages the mapping between POSIX filesystem semantics and warp-store objects.
pub struct VirtualFilesystem {
    /// The underlying warp-store
    store: Arc<Store>,

    /// The bucket containing file data
    bucket: String,

    /// Cache manager
    cache: CacheManager,

    /// Superblock
    superblock: RwLock<Superblock>,

    /// Inode allocator
    inode_alloc: InodeAllocator,

    /// Open file handles: handle_id -> (ino, flags)
    open_files: DashMap<u64, OpenFile>,

    /// Next file handle ID
    next_fh: AtomicU64,

    /// Block size
    block_size: u32,

    /// UID/GID for new files (defaults to calling process)
    default_uid: u32,
    default_gid: u32,

    /// Statistics
    stats: RwLock<VfsStats>,
}

/// An open file
#[derive(Debug)]
struct OpenFile {
    ino: u64,
    flags: i32,
    /// Current file position
    pos: AtomicU64,
}

/// VFS statistics
#[derive(Debug, Default)]
struct VfsStats {
    reads: u64,
    writes: u64,
    bytes_read: u64,
    bytes_written: u64,
}

impl VirtualFilesystem {
    /// Create a new VFS
    pub async fn new(
        store: Arc<Store>,
        bucket: String,
        inode_cache_size: usize,
        dentry_cache_size: usize,
        data_cache_bytes: usize,
        cache_ttl: Duration,
    ) -> Result<Self> {
        info!(bucket = %bucket, "Initializing VFS");

        // Load or create superblock
        let superblock = Self::load_or_create_superblock(&store, &bucket).await?;
        let next_ino = superblock.next_ino;

        // SAFETY: libc::getuid() is always safe - returns process's real UID with no side effects.
        let uid = unsafe { libc::getuid() };
        // SAFETY: libc::getgid() is always safe - returns process's real GID with no side effects.
        let gid = unsafe { libc::getgid() };

        let vfs = Self {
            store,
            bucket,
            cache: CacheManager::new(
                inode_cache_size,
                dentry_cache_size,
                data_cache_bytes,
                cache_ttl,
            ),
            superblock: RwLock::new(superblock),
            inode_alloc: InodeAllocator::new(next_ino),
            open_files: DashMap::new(),
            next_fh: AtomicU64::new(1),
            block_size: 4096,
            default_uid: uid,
            default_gid: gid,
            stats: RwLock::new(VfsStats::default()),
        };

        // Ensure root directory exists
        vfs.ensure_root().await?;

        Ok(vfs)
    }

    /// Load or create the superblock
    async fn load_or_create_superblock(store: &Store, bucket: &str) -> Result<Superblock> {
        let key = ObjectKey::new(bucket, format!("{}/superblock", META_PREFIX))?;

        match store.get(&key).await {
            Ok(data) => {
                let sb = Superblock::from_bytes(data.as_ref())?;
                sb.validate()?;
                debug!("Loaded existing superblock");
                Ok(sb)
            }
            Err(_) => {
                // Create new superblock
                let sb = Superblock::new(4096, "warp-fs".to_string());
                let data = ObjectData::from(sb.to_bytes()?);
                store.put(&key, data).await?;
                info!("Created new filesystem");
                Ok(sb)
            }
        }
    }

    /// Ensure the root directory exists
    async fn ensure_root(&self) -> Result<()> {
        if self.load_inode(ROOT_INO).await.is_err() {
            debug!("Creating root directory");
            let meta = InodeMetadata::root(self.default_uid, self.default_gid, 0o755);
            self.save_inode(&meta).await?;

            // Create empty directory contents
            let contents = DirectoryContents::new(ROOT_INO, ROOT_INO);
            self.save_directory(&contents).await?;
        }
        Ok(())
    }

    // =========================================================================
    // Inode Operations
    // =========================================================================

    /// Load an inode from storage or cache
    pub async fn load_inode(&self, ino: Ino) -> Result<Arc<RwLock<Inode>>> {
        // Check cache first
        if let Some(inode) = self.cache.inodes.get(ino) {
            return Ok(inode);
        }

        // Load from storage
        let key = ObjectKey::new(&self.bucket, format!("{}/inodes/{}", META_PREFIX, ino))?;
        let data = self
            .store
            .get(&key)
            .await
            .map_err(|_| Error::InodeNotFound(ino))?;

        let meta = InodeMetadata::from_bytes(data.as_ref())?;
        let inode = Inode::new(meta);

        Ok(self.cache.inodes.insert(ino, inode))
    }

    /// Save an inode to storage
    pub async fn save_inode(&self, meta: &InodeMetadata) -> Result<()> {
        let key = ObjectKey::new(&self.bucket, format!("{}/inodes/{}", META_PREFIX, meta.ino))?;
        let data = ObjectData::from(meta.to_bytes()?);
        self.store.put(&key, data).await?;
        Ok(())
    }

    /// Delete an inode from storage
    async fn delete_inode(&self, ino: Ino) -> Result<()> {
        let key = ObjectKey::new(&self.bucket, format!("{}/inodes/{}", META_PREFIX, ino))?;
        self.store.delete(&key).await?;
        self.cache.invalidate_inode(ino);
        Ok(())
    }

    /// Allocate a new inode number
    pub fn alloc_ino(&self) -> Ino {
        self.inode_alloc.alloc()
    }

    // =========================================================================
    // Directory Operations
    // =========================================================================

    /// Load directory contents
    pub async fn load_directory(&self, ino: Ino) -> Result<DirectoryContents> {
        let key = ObjectKey::new(&self.bucket, format!("{}/dirs/{}", META_PREFIX, ino))?;

        match self.store.get(&key).await {
            Ok(data) => DirectoryContents::from_bytes(data.as_ref()),
            Err(_) => {
                // Return empty directory for new dirs
                let parent = if ino == ROOT_INO { ROOT_INO } else { ino };
                Ok(DirectoryContents::new(ino, parent))
            }
        }
    }

    /// Save directory contents
    pub async fn save_directory(&self, contents: &DirectoryContents) -> Result<()> {
        let key = ObjectKey::new(
            &self.bucket,
            format!("{}/dirs/{}", META_PREFIX, contents.self_ino),
        )?;
        let data = ObjectData::from(contents.to_bytes()?);
        self.store.put(&key, data).await?;

        // Invalidate dentry cache for this directory
        self.cache.dentries.invalidate_parent(contents.self_ino);

        Ok(())
    }

    /// Delete directory contents from storage
    async fn delete_directory(&self, ino: Ino) -> Result<()> {
        let key = ObjectKey::new(&self.bucket, format!("{}/dirs/{}", META_PREFIX, ino))?;
        let _ = self.store.delete(&key).await; // Ignore if not exists
        self.cache.dentries.invalidate_parent(ino);
        Ok(())
    }

    /// Look up a name in a directory
    pub async fn lookup(&self, parent_ino: Ino, name: &OsStr) -> Result<Arc<RwLock<Inode>>> {
        let name = name
            .to_str()
            .ok_or_else(|| Error::InvalidFileName(format!("{:?}", name)))?;

        // Check dentry cache
        if let Some(entry) = self.cache.dentries.get(parent_ino, name) {
            return self.load_inode(entry.ino).await;
        }

        // Load directory
        let dir = self.load_directory(parent_ino).await?;

        // Find entry
        if let Some(entry) = dir.get(name) {
            // Cache it
            self.cache
                .dentries
                .insert(parent_ino, name, entry.ino, entry.file_type);
            self.load_inode(entry.ino).await
        } else {
            // Negative cache
            self.cache.dentries.insert_negative(parent_ino, name);
            Err(Error::FileNotFound(name.to_string()))
        }
    }

    // =========================================================================
    // File Creation/Deletion
    // =========================================================================

    /// Create a new file
    pub async fn create_file(
        &self,
        parent_ino: Ino,
        name: &OsStr,
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> Result<Arc<RwLock<Inode>>> {
        let name = name
            .to_str()
            .ok_or_else(|| Error::InvalidFileName(format!("{:?}", name)))?;

        // Check if already exists
        let mut dir = self.load_directory(parent_ino).await?;
        if dir.get(name).is_some() {
            return Err(Error::FileExists(name.to_string()));
        }

        // Allocate inode
        let ino = self.alloc_ino();
        let meta = InodeMetadata::new_file(ino, mode, uid, gid);

        // Save inode
        self.save_inode(&meta).await?;

        // Add to directory
        dir.add(DirectoryEntry::new(
            name.to_string(),
            ino,
            FileType::RegularFile,
        ));
        self.save_directory(&dir).await?;

        // Update parent mtime
        if let Ok(parent) = self.load_inode(parent_ino).await {
            parent.write().metadata_mut().touch_mtime();
        }

        // Update superblock
        {
            let mut sb = self.superblock.write();
            sb.next_ino = self.inode_alloc.peek();
            sb.inode_count += 1;
        }

        // Cache and return
        let inode = Inode::new(meta);
        Ok(self.cache.inodes.insert(ino, inode))
    }

    /// Create a new directory
    pub async fn create_dir(
        &self,
        parent_ino: Ino,
        name: &OsStr,
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> Result<Arc<RwLock<Inode>>> {
        let name = name
            .to_str()
            .ok_or_else(|| Error::InvalidFileName(format!("{:?}", name)))?;

        // Check if already exists
        let mut parent_dir = self.load_directory(parent_ino).await?;
        if parent_dir.get(name).is_some() {
            return Err(Error::FileExists(name.to_string()));
        }

        // Allocate inode
        let ino = self.alloc_ino();
        let meta = InodeMetadata::new_directory(ino, mode, uid, gid);

        // Save inode
        self.save_inode(&meta).await?;

        // Create empty directory contents
        let contents = DirectoryContents::new(ino, parent_ino);
        self.save_directory(&contents).await?;

        // Add to parent directory
        parent_dir.add(DirectoryEntry::new(
            name.to_string(),
            ino,
            FileType::Directory,
        ));
        self.save_directory(&parent_dir).await?;

        // Update parent nlink and mtime
        if let Ok(parent) = self.load_inode(parent_ino).await {
            let mut parent_guard = parent.write();
            let meta = parent_guard.metadata_mut();
            meta.nlink += 1;
            meta.touch_mtime();
        }

        // Cache and return
        let inode = Inode::new(meta);
        Ok(self.cache.inodes.insert(ino, inode))
    }

    /// Unlink a file (remove directory entry)
    pub async fn unlink(&self, parent_ino: Ino, name: &OsStr) -> Result<()> {
        let name = name
            .to_str()
            .ok_or_else(|| Error::InvalidFileName(format!("{:?}", name)))?;

        // Load directory
        let mut dir = self.load_directory(parent_ino).await?;

        // Find and remove entry
        let entry = dir
            .remove(name)
            .ok_or_else(|| Error::FileNotFound(name.to_string()))?;

        // Can't unlink directories with unlink
        if entry.file_type == FileType::Directory {
            return Err(Error::IsADirectory(name.to_string()));
        }

        // Save updated directory
        self.save_directory(&dir).await?;

        // Decrement nlink
        let should_delete = if let Ok(inode) = self.load_inode(entry.ino).await {
            let mut guard = inode.write();
            {
                let meta = guard.metadata_mut();
                meta.nlink = meta.nlink.saturating_sub(1);
            }

            let nlink = guard.metadata().nlink;
            let open_count = guard.open_count();

            if nlink == 0 && open_count == 0 {
                true
            } else if nlink == 0 {
                guard.mark_unlinked();
                false
            } else {
                // Save updated nlink
                drop(guard);
                let guard = inode.read();
                self.save_inode(guard.metadata()).await?;
                false
            }
        } else {
            false
        };

        // Delete inode if no more links and not open
        if should_delete {
            self.delete_file_data(entry.ino).await?;
            self.delete_inode(entry.ino).await?;
        }

        // Invalidate dentry cache
        self.cache.invalidate_dentry(parent_ino, name);

        Ok(())
    }

    /// Remove a directory
    pub async fn rmdir(&self, parent_ino: Ino, name: &OsStr) -> Result<()> {
        let name = name
            .to_str()
            .ok_or_else(|| Error::InvalidFileName(format!("{:?}", name)))?;

        // Load parent directory
        let mut parent_dir = self.load_directory(parent_ino).await?;

        // Find entry
        let entry = parent_dir
            .get(name)
            .ok_or_else(|| Error::DirectoryNotFound(name.to_string()))?
            .clone();

        if entry.file_type != FileType::Directory {
            return Err(Error::NotADirectory(name.to_string()));
        }

        // Check if empty
        let contents = self.load_directory(entry.ino).await?;
        if !contents.is_empty() {
            return Err(Error::DirectoryNotEmpty(name.to_string()));
        }

        // Remove from parent
        parent_dir.remove(name);
        self.save_directory(&parent_dir).await?;

        // Delete directory contents and inode
        self.delete_directory(entry.ino).await?;
        self.delete_inode(entry.ino).await?;

        // Update parent nlink
        if let Ok(parent) = self.load_inode(parent_ino).await {
            let mut guard = parent.write();
            let meta = guard.metadata_mut();
            meta.nlink = meta.nlink.saturating_sub(1);
            meta.touch_mtime();
        }

        self.cache.invalidate_dentry(parent_ino, name);

        Ok(())
    }

    // =========================================================================
    // File Data Operations
    // =========================================================================

    /// Read file data
    pub async fn read(&self, ino: Ino, offset: u64, size: u32) -> Result<Vec<u8>> {
        // Check data cache first
        if let Some(data) = self.cache.data.read(ino, offset, size as usize) {
            let mut stats = self.stats.write();
            stats.reads += 1;
            stats.bytes_read += data.len() as u64;
            return Ok(data);
        }

        // Load from storage
        let inode = self.load_inode(ino).await?;
        let guard = inode.read();

        if !guard.is_file() {
            return Err(Error::NotAFile(format!("inode {}", ino)));
        }

        let file_size = guard.size();
        if offset >= file_size {
            return Ok(Vec::new());
        }

        let meta = guard.metadata();
        let actual_size = ((file_size - offset) as u32).min(size);

        // Read from extents
        let mut result = Vec::with_capacity(actual_size as usize);

        for extent in &meta.data_extents {
            if extent.contains(offset) || extent.overlaps(offset, actual_size as u64) {
                let key = ObjectKey::new(&self.bucket, &extent.object_key)?;
                let data = self.store.get(&key).await?;

                // Calculate what portion of this extent we need
                let extent_start = extent.file_offset;
                let extent_end = extent.file_offset + extent.length;

                let read_start = offset.max(extent_start);
                let read_end = (offset + actual_size as u64).min(extent_end);

                if read_start < read_end {
                    let obj_offset = (read_start - extent_start + extent.object_offset) as usize;
                    let len = (read_end - read_start) as usize;

                    if obj_offset + len <= data.len() {
                        result.extend_from_slice(&data.as_ref()[obj_offset..obj_offset + len]);
                    }
                }
            }
        }

        // Cache the data
        if !result.is_empty() {
            self.cache.data.insert(ino, offset, &result);
        }

        let mut stats = self.stats.write();
        stats.reads += 1;
        stats.bytes_read += result.len() as u64;

        Ok(result)
    }

    /// Write file data
    pub async fn write(&self, ino: Ino, offset: u64, data: &[u8]) -> Result<u32> {
        let inode = self.load_inode(ino).await?;

        {
            let guard = inode.read();
            if !guard.is_file() {
                return Err(Error::NotAFile(format!("inode {}", ino)));
            }
        }

        // Generate object key for this write
        let object_key = format!("data/{}/{}", ino, offset);
        let key = ObjectKey::new(&self.bucket, &object_key)?;

        // Write to storage
        self.store
            .put(&key, ObjectData::from(data.to_vec()))
            .await?;

        // Update inode metadata
        {
            let mut guard = inode.write();
            let meta = guard.metadata_mut();

            // Add or update extent
            let extent = DataExtent::new(offset, data.len() as u64, object_key, 0);

            // Simple strategy: replace overlapping extents
            meta.data_extents
                .retain(|e| !e.overlaps(offset, data.len() as u64));
            meta.data_extents.push(extent);

            // Update size if needed
            let new_size = offset + data.len() as u64;
            if new_size > meta.size {
                meta.size = new_size;
            }

            meta.touch_mtime();
        }

        // Cache the written data
        self.cache.data.insert(ino, offset, data);

        // Flush inode to storage
        {
            let guard = inode.read();
            self.save_inode(guard.metadata()).await?;
        }

        let mut stats = self.stats.write();
        stats.writes += 1;
        stats.bytes_written += data.len() as u64;

        Ok(data.len() as u32)
    }

    /// Delete all data for a file
    async fn delete_file_data(&self, ino: Ino) -> Result<()> {
        // Load inode to get extents
        if let Ok(inode) = self.load_inode(ino).await {
            let guard = inode.read();
            for extent in &guard.metadata().data_extents {
                let key = ObjectKey::new(&self.bucket, &extent.object_key)?;
                let _ = self.store.delete(&key).await; // Ignore errors
            }
        }

        self.cache.data.invalidate_inode(ino);
        Ok(())
    }

    // =========================================================================
    // File Handle Operations
    // =========================================================================

    /// Open a file and return a file handle
    pub fn open(&self, ino: Ino, flags: i32) -> Result<u64> {
        let fh = self.next_fh.fetch_add(1, Ordering::SeqCst);

        self.open_files.insert(
            fh,
            OpenFile {
                ino,
                flags,
                pos: AtomicU64::new(0),
            },
        );

        // Increment open count on inode
        if let Some(inode) = self.cache.inodes.get(ino) {
            inode.read().open();
        }

        debug!(ino, fh, flags, "Opened file");
        Ok(fh)
    }

    /// Close a file handle
    pub async fn close(&self, fh: u64) -> Result<()> {
        if let Some((_, file)) = self.open_files.remove(&fh) {
            // Decrement open count
            if let Some(inode) = self.cache.inodes.get(file.ino) {
                let guard = inode.read();
                guard.close();

                // Check if we should delete
                if guard.is_unlinked() && guard.open_count() == 0 {
                    drop(guard);
                    self.delete_file_data(file.ino).await?;
                    self.delete_inode(file.ino).await?;
                }
            }
            debug!(fh, "Closed file");
        }
        Ok(())
    }

    /// Get file for a handle
    pub fn get_file(&self, fh: u64) -> Result<Ino> {
        self.open_files
            .get(&fh)
            .map(|f| f.ino)
            .ok_or(Error::InvalidFileHandle(fh))
    }

    // =========================================================================
    // Statistics
    // =========================================================================

    /// Get filesystem statistics
    pub fn stats(&self) -> FsStats {
        let vfs_stats = self.stats.read();
        let cache_stats = self.cache.stats();
        let sb = self.superblock.read();

        FsStats {
            total_objects: sb.inode_count,
            total_bytes: sb.total_bytes,
            inode_cache_hits: cache_stats.inode_hits,
            inode_cache_misses: cache_stats.inode_misses,
            dentry_cache_hits: cache_stats.dentry_hits,
            dentry_cache_misses: cache_stats.dentry_misses,
            data_cache_hits: cache_stats.data_hits,
            data_cache_misses: cache_stats.data_misses,
            reads: vfs_stats.reads,
            writes: vfs_stats.writes,
            bytes_read: vfs_stats.bytes_read,
            bytes_written: vfs_stats.bytes_written,
        }
    }

    /// Get the block size
    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    /// Get default UID
    pub fn default_uid(&self) -> u32 {
        self.default_uid
    }

    /// Get default GID
    pub fn default_gid(&self) -> u32 {
        self.default_gid
    }

    /// Sync all dirty data to storage
    pub async fn sync(&self) -> Result<()> {
        // Sync dirty inodes
        let dirty = self.cache.inodes.get_dirty();
        for (_ino, inode) in dirty {
            let guard = inode.read();
            self.save_inode(guard.metadata()).await?;
            drop(guard);
            inode.write().mark_clean();
        }

        // Sync superblock
        let sb = self.superblock.read().clone();
        let key = ObjectKey::new(&self.bucket, format!("{}/superblock", META_PREFIX))?;
        let data = ObjectData::from(sb.to_bytes()?);
        self.store.put(&key, data).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests would require setting up a mock store
    // These are placeholder tests
    #[test]
    fn test_meta_prefix() {
        assert_eq!(META_PREFIX, "__warp_fs_meta__");
    }
}
