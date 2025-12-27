//! Chonkers-based storage backend with versioned deduplication
//!
//! This backend uses the Chonkers algorithm for content-defined chunking with:
//! - Provable bounds on chunk sizes
//! - Edit locality (single byte edit affects ≤7 chunk boundaries)
//! - Content-addressed deduplication across versions
//!
//! ## Storage Layout
//!
//! ```text
//! root/
//! ├── chunks/                 # Raw chunk data by ChunkId
//! │   └── ab/cd/abcd1234...   # Sharded by first 4 hex chars
//! ├── trees/                  # ChonkerTree metadata by VersionId
//! │   └── 12345678.tree
//! ├── buckets/
//! │   └── bucket-name/
//! │       └── objects/
//! │           └── path/to/key.idx   # ObjectIndex (chunk IDs + metadata)
//! └── registry.msgpack        # ChunkRegistry state
//! ```

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tracing::{debug, trace};

use warp_chonkers::{
    ChunkId, ChunkRegistry, Chonkers, ChonkersConfig, MemoryChunkStore,
    MemoryTreeStore, TreeStore, VersionId, VersionTimeline,
};

use super::{MultipartUpload, PartInfo, StorageBackend};
use crate::key::ObjectKey;
use crate::object::{
    ListOptions, ObjectData, ObjectEntry, ObjectList, ObjectMeta, PutOptions, StorageClass,
};
use crate::{Error, Result};

/// Index entry for an object stored with Chonkers
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ObjectIndex {
    /// Object metadata
    meta: ObjectMeta,

    /// Chunk IDs that make up this object (in order)
    chunk_ids: Vec<ChunkId>,

    /// Tree version for this object
    tree_version: VersionId,

    /// Total uncompressed size
    data_size: usize,
}

/// Bucket metadata
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct BucketMeta {
    /// Bucket name
    name: String,

    /// Creation time
    created_at: chrono::DateTime<chrono::Utc>,

    /// Object count
    object_count: u64,

    /// Total size
    total_size: u64,
}

/// Chonkers-based storage backend
///
/// Provides versioned, deduplicated object storage using the Chonkers algorithm.
pub struct ChonkersBackend {
    /// Root directory for storage
    root: PathBuf,

    /// Chonkers chunker instance
    chunker: Chonkers,

    /// Chunk registry for deduplication
    chunk_registry: Arc<ChunkRegistry>,

    /// Tree store for persistence
    tree_store: Arc<dyn TreeStore>,

    /// Version timeline (optional, for version management)
    #[allow(dead_code)]
    timeline: Arc<VersionTimeline>,

    /// In-memory cache of bucket metadata
    buckets: DashMap<String, BucketMeta>,

    /// Chunk data cache (ChunkId -> raw data)
    chunk_cache: DashMap<ChunkId, Vec<u8>>,
}

impl ChonkersBackend {
    /// Create a new Chonkers backend
    pub async fn new(root: &Path) -> Result<Self> {
        Self::with_config(root, ChonkersConfig::default()).await
    }

    /// Create a new Chonkers backend with custom configuration
    pub async fn with_config(root: &Path, config: ChonkersConfig) -> Result<Self> {
        // Create directory structure
        let chunks_dir = root.join("chunks");
        let trees_dir = root.join("trees");
        let buckets_dir = root.join("buckets");

        fs::create_dir_all(&chunks_dir).await?;
        fs::create_dir_all(&trees_dir).await?;
        fs::create_dir_all(&buckets_dir).await?;

        // Create chunker
        let chunker = Chonkers::new(config.clone());

        // Create chunk store and registry
        let chunk_store = Arc::new(MemoryChunkStore::new());
        let chunk_registry = Arc::new(ChunkRegistry::new(chunk_store));

        // Create tree store
        let tree_store: Arc<dyn TreeStore> = Arc::new(MemoryTreeStore::new());

        // Create version timeline
        let timeline = Arc::new(VersionTimeline::new(
            config,
            chunk_registry.clone(),
            tree_store.clone(),
        ));

        debug!(root = %root.display(), "Initialized Chonkers backend");

        Ok(Self {
            root: root.to_path_buf(),
            chunker,
            chunk_registry,
            tree_store,
            timeline,
            buckets: DashMap::new(),
            chunk_cache: DashMap::new(),
        })
    }

    /// Get the path to bucket directory
    fn bucket_path(&self, bucket: &str) -> PathBuf {
        self.root.join("buckets").join(bucket)
    }

    /// Get the path to object index
    fn index_path(&self, key: &ObjectKey) -> PathBuf {
        self.bucket_path(key.bucket())
            .join("objects")
            .join(format!("{}.idx", key.key()))
    }

    /// Get the path to a chunk file
    fn chunk_path(&self, chunk_id: &ChunkId) -> PathBuf {
        // Use full hex encoding of the chunk ID
        let hex = hex::encode(&chunk_id.0);
        // Shard by first 2 hex chars for better filesystem distribution
        self.root
            .join("chunks")
            .join(&hex[0..2])
            .join(&hex[2..4])
            .join(&hex)
    }

    /// Ensure parent directories exist
    async fn ensure_parent(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }
        Ok(())
    }

    /// Store a chunk to disk
    async fn store_chunk(&self, chunk_id: &ChunkId, data: &[u8]) -> Result<()> {
        let path = self.chunk_path(chunk_id);

        // Check if already exists (dedup)
        if path.exists() {
            trace!(chunk_id = %chunk_id.short_hex(), "Chunk already exists, skipping");
            return Ok(());
        }

        self.ensure_parent(&path).await?;

        // Write atomically
        let temp_path = path.with_extension("tmp");
        let mut file = fs::File::create(&temp_path).await?;
        file.write_all(data).await?;
        file.sync_all().await?;
        fs::rename(&temp_path, &path).await?;

        // Update cache
        self.chunk_cache.insert(chunk_id.clone(), data.to_vec());

        trace!(chunk_id = %chunk_id.short_hex(), size = data.len(), "Stored chunk");
        Ok(())
    }

    /// Load a chunk from disk or cache
    async fn load_chunk(&self, chunk_id: &ChunkId) -> Result<Vec<u8>> {
        // Check cache first
        if let Some(data) = self.chunk_cache.get(chunk_id) {
            return Ok(data.clone());
        }

        // Load from disk
        let path = self.chunk_path(chunk_id);
        match fs::read(&path).await {
            Ok(data) => {
                // Update cache
                self.chunk_cache.insert(chunk_id.clone(), data.clone());
                Ok(data)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(Error::Backend(format!(
                "Chunk not found: {}",
                chunk_id.short_hex()
            ))),
            Err(e) => Err(e.into()),
        }
    }

    /// Delete a chunk from disk
    async fn delete_chunk(&self, chunk_id: &ChunkId) -> Result<()> {
        let path = self.chunk_path(chunk_id);
        self.chunk_cache.remove(chunk_id);

        match fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()), // Already deleted
            Err(e) => Err(e.into()),
        }
    }

    /// Get deduplication statistics
    pub fn dedup_stats(&self) -> DedupStats {
        DedupStats {
            total_chunks: self.chunk_cache.len(),
            unique_chunks: self.chunk_registry.chunk_count(),
            cache_size_bytes: self
                .chunk_cache
                .iter()
                .map(|e| e.value().len())
                .sum(),
        }
    }

    /// Run garbage collection on unreferenced chunks
    pub async fn run_gc(&self) -> Result<GcResult> {
        let stats = self.chunk_registry.collect_garbage()
            .map_err(|e| Error::Backend(format!("Garbage collection failed: {}", e)))?;

        // Delete unreferenced chunks from disk
        // Note: In production, we'd track which chunks were collected
        // For now, we just return the stats

        Ok(GcResult {
            chunks_collected: stats.chunks_deleted,
            bytes_freed: stats.bytes_freed,
        })
    }
}

/// Deduplication statistics
#[derive(Debug, Clone)]
pub struct DedupStats {
    /// Total chunks in cache
    pub total_chunks: usize,

    /// Unique chunks in registry
    pub unique_chunks: usize,

    /// Cache size in bytes
    pub cache_size_bytes: usize,
}

/// Garbage collection result
#[derive(Debug, Clone)]
pub struct GcResult {
    /// Number of chunks collected
    pub chunks_collected: usize,

    /// Bytes freed
    pub bytes_freed: usize,
}

#[async_trait]
impl StorageBackend for ChonkersBackend {
    async fn get(&self, key: &ObjectKey) -> Result<ObjectData> {
        let index_path = self.index_path(key);
        trace!(path = %index_path.display(), "Reading object index");

        // Read object index
        let index_bytes = match fs::read(&index_path).await {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::ObjectNotFound {
                    bucket: key.bucket().to_string(),
                    key: key.key().to_string(),
                });
            }
            Err(e) => return Err(e.into()),
        };

        let index: ObjectIndex = rmp_serde::from_slice(&index_bytes)?;

        // Reconstruct data from chunks
        let mut data = Vec::with_capacity(index.data_size);
        for chunk_id in &index.chunk_ids {
            let chunk_data = self.load_chunk(chunk_id).await?;
            data.extend_from_slice(&chunk_data);
        }

        // Verify integrity
        let hash = blake3::hash(&data);
        if *hash.as_bytes() != index.meta.content_hash {
            return Err(Error::Backend(format!(
                "Data integrity check failed for {}/{}",
                key.bucket(),
                key.key()
            )));
        }

        Ok(ObjectData::from(data))
    }

    async fn put(
        &self,
        key: &ObjectKey,
        data: ObjectData,
        opts: PutOptions,
    ) -> Result<ObjectMeta> {
        let index_path = self.index_path(key);
        trace!(path = %index_path.display(), size = data.len(), "Writing object");

        // Check if_none_match condition
        if opts.if_none_match && index_path.exists() {
            return Err(Error::PermissionDenied(
                "object already exists and if_none_match is set".to_string(),
            ));
        }

        // Chunk the data using Chonkers
        let data_bytes = data.as_ref();
        let chunks = self
            .chunker
            .chunk(data_bytes)
            .map_err(|e| Error::Backend(format!("Chunking failed: {}", e)))?;

        // Store each chunk and collect IDs
        let mut chunk_ids = Vec::with_capacity(chunks.len());
        for chunk in &chunks {
            let chunk_data = &data_bytes[chunk.offset..chunk.offset + chunk.length];

            // Store chunk (handles dedup internally)
            self.store_chunk(&chunk.id, chunk_data).await?;

            // Register with chunk registry for reference counting
            let _ = self.chunk_registry.register(
                chunk.id.clone(),
                chunk_data,
                chunk.weight,
                VersionId::new(0), // We could use a proper version here
            );

            chunk_ids.push(chunk.id.clone());
        }

        // Create metadata
        let mut meta = ObjectMeta::new(&data);
        meta.version_id = Some(crate::version::VersionId::new());

        if let Some(ct) = opts.content_type {
            meta = meta.with_content_type(ct);
        }
        for (k, v) in opts.metadata {
            meta = meta.with_metadata(k, v);
        }

        // Create object index
        let index = ObjectIndex {
            meta: meta.clone(),
            chunk_ids,
            tree_version: VersionId::new(0), // Could track tree version here
            data_size: data.len(),
        };

        // Write index
        self.ensure_parent(&index_path).await?;
        let index_bytes = rmp_serde::to_vec(&index)?;

        let temp_path = index_path.with_extension("tmp");
        let mut file = fs::File::create(&temp_path).await?;
        file.write_all(&index_bytes).await?;
        file.sync_all().await?;
        fs::rename(&temp_path, &index_path).await?;

        // Update bucket stats
        if let Some(mut bucket) = self.buckets.get_mut(key.bucket()) {
            bucket.object_count += 1;
            bucket.total_size += data.len() as u64;
        }

        debug!(
            bucket = key.bucket(),
            key = key.key(),
            size = data.len(),
            chunks = index.chunk_ids.len(),
            "Stored object with Chonkers"
        );

        Ok(meta)
    }

    async fn delete(&self, key: &ObjectKey) -> Result<()> {
        let index_path = self.index_path(key);
        trace!(path = %index_path.display(), "Deleting object");

        // Read index to get chunk IDs
        let index_bytes = match fs::read(&index_path).await {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::ObjectNotFound {
                    bucket: key.bucket().to_string(),
                    key: key.key().to_string(),
                });
            }
            Err(e) => return Err(e.into()),
        };

        let index: ObjectIndex = rmp_serde::from_slice(&index_bytes)?;

        // Decrement reference counts for chunks
        for chunk_id in &index.chunk_ids {
            if let Some(metadata) = self.chunk_registry.get(chunk_id) {
                metadata.dec_ref();
            }
        }

        // Remove index file
        fs::remove_file(&index_path).await?;

        // Update bucket stats
        if let Some(mut bucket) = self.buckets.get_mut(key.bucket()) {
            bucket.object_count = bucket.object_count.saturating_sub(1);
            bucket.total_size = bucket.total_size.saturating_sub(index.data_size as u64);
        }

        debug!(
            bucket = key.bucket(),
            key = key.key(),
            "Deleted object"
        );

        Ok(())
    }

    async fn list(&self, bucket: &str, prefix: &str, opts: ListOptions) -> Result<ObjectList> {
        let objects_dir = self.bucket_path(bucket).join("objects");

        if !objects_dir.exists() {
            return Err(Error::BucketNotFound(bucket.to_string()));
        }

        let mut objects = Vec::new();
        let mut common_prefixes = Vec::new();

        // Walk directory recursively
        let mut stack = vec![objects_dir.clone()];
        while let Some(dir) = stack.pop() {
            let mut entries = match fs::read_dir(&dir).await {
                Ok(e) => e,
                Err(_) => continue,
            };

            while let Ok(Some(entry)) = entries.next_entry().await {
                let path = entry.path();
                let file_type = match entry.file_type().await {
                    Ok(ft) => ft,
                    Err(_) => continue,
                };

                if file_type.is_dir() {
                    stack.push(path);
                    continue;
                }

                // Only process .idx files
                if path.extension().map(|e| e != "idx").unwrap_or(true) {
                    continue;
                }

                // Get relative key (remove .idx extension)
                let rel_path = path.strip_prefix(&objects_dir).unwrap_or(&path);
                let key = rel_path
                    .to_string_lossy()
                    .trim_end_matches(".idx")
                    .to_string();

                // Filter by prefix
                if !key.starts_with(prefix) {
                    continue;
                }

                // Filter by start_after
                if let Some(ref start_after) = opts.start_after {
                    if &key <= start_after {
                        continue;
                    }
                }

                // Handle delimiter for common prefixes
                if let Some(ref delim) = opts.delimiter {
                    let after_prefix = &key[prefix.len()..];
                    if let Some(pos) = after_prefix.find(delim) {
                        let common_prefix = format!("{}{}{}", prefix, &after_prefix[..pos], delim);
                        if !common_prefixes.contains(&common_prefix) {
                            common_prefixes.push(common_prefix);
                        }
                        continue;
                    }
                }

                // Read index for metadata
                if let Ok(index_bytes) = fs::read(&path).await {
                    if let Ok(index) = rmp_serde::from_slice::<ObjectIndex>(&index_bytes) {
                        objects.push(ObjectEntry {
                            key,
                            size: index.meta.size,
                            last_modified: index.meta.modified_at,
                            etag: index.meta.etag.clone(),
                            storage_class: StorageClass::Standard,
                            version_id: index.meta.version_id.map(|v| v),
                            is_latest: true,
                        });
                    }
                }
            }
        }

        // Sort by key
        objects.sort_by(|a, b| a.key.cmp(&b.key));

        // Apply max_keys limit
        let is_truncated = objects.len() > opts.max_keys;
        objects.truncate(opts.max_keys);

        let key_count = objects.len();

        Ok(ObjectList {
            objects,
            common_prefixes,
            next_continuation_token: None,
            is_truncated,
            key_count,
        })
    }

    async fn head(&self, key: &ObjectKey) -> Result<ObjectMeta> {
        let index_path = self.index_path(key);

        // Read object index
        let index_bytes = match fs::read(&index_path).await {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::ObjectNotFound {
                    bucket: key.bucket().to_string(),
                    key: key.key().to_string(),
                });
            }
            Err(e) => return Err(e.into()),
        };

        let index: ObjectIndex = rmp_serde::from_slice(&index_bytes)?;
        Ok(index.meta)
    }

    async fn create_bucket(&self, name: &str) -> Result<()> {
        let bucket_path = self.bucket_path(name);
        let objects_path = bucket_path.join("objects");

        fs::create_dir_all(&objects_path).await?;

        // Create bucket metadata
        let meta = BucketMeta {
            name: name.to_string(),
            created_at: Utc::now(),
            object_count: 0,
            total_size: 0,
        };

        self.buckets.insert(name.to_string(), meta);

        debug!(bucket = name, "Created bucket");
        Ok(())
    }

    async fn delete_bucket(&self, name: &str) -> Result<()> {
        let bucket_path = self.bucket_path(name);

        if !bucket_path.exists() {
            return Err(Error::BucketNotFound(name.to_string()));
        }

        fs::remove_dir_all(&bucket_path).await?;
        self.buckets.remove(name);

        debug!(bucket = name, "Deleted bucket");
        Ok(())
    }

    async fn bucket_exists(&self, name: &str) -> Result<bool> {
        Ok(self.bucket_path(name).exists())
    }

    async fn create_multipart(&self, key: &ObjectKey) -> Result<MultipartUpload> {
        // Verify bucket exists
        if !self.bucket_exists(key.bucket()).await? {
            return Err(Error::BucketNotFound(key.bucket().to_string()));
        }

        let upload_id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now();

        // Create upload directory
        let upload_dir = self.bucket_path(key.bucket()).join(".uploads").join(&upload_id);
        fs::create_dir_all(&upload_dir).await?;

        debug!(
            bucket = key.bucket(),
            key = key.key(),
            upload_id = %upload_id,
            "Created multipart upload"
        );

        Ok(MultipartUpload {
            upload_id,
            key: key.clone(),
            created_at: now,
        })
    }

    async fn upload_part(
        &self,
        upload: &MultipartUpload,
        part_number: u32,
        data: ObjectData,
    ) -> Result<PartInfo> {
        if part_number == 0 || part_number > 10000 {
            return Err(Error::Backend(format!(
                "Invalid part number: {}. Must be between 1 and 10000",
                part_number
            )));
        }

        let upload_dir = self
            .bucket_path(upload.key.bucket())
            .join(".uploads")
            .join(&upload.upload_id);

        if !upload_dir.exists() {
            return Err(Error::Backend(format!(
                "Upload {} not found",
                upload.upload_id
            )));
        }

        // Compute etag
        let hash = blake3::hash(data.as_ref());
        let etag = format!("\"{}\"", hex::encode(&hash.as_bytes()[..16]));
        let size = data.len() as u64;

        // Write part data
        let part_path = upload_dir.join(format!("part.{:05}", part_number));
        fs::write(&part_path, data.as_ref()).await?;

        trace!(
            upload_id = %upload.upload_id,
            part_number,
            size,
            "Uploaded part"
        );

        Ok(PartInfo {
            part_number,
            etag,
            size,
        })
    }

    async fn complete_multipart(
        &self,
        upload: &MultipartUpload,
        parts: Vec<PartInfo>,
    ) -> Result<ObjectMeta> {
        let upload_dir = self
            .bucket_path(upload.key.bucket())
            .join(".uploads")
            .join(&upload.upload_id);

        if !upload_dir.exists() {
            return Err(Error::Backend(format!(
                "Upload {} not found",
                upload.upload_id
            )));
        }

        // Sort parts and assemble data
        let mut sorted_parts = parts;
        sorted_parts.sort_by_key(|p| p.part_number);

        let mut assembled = Vec::new();
        for part in &sorted_parts {
            let part_path = upload_dir.join(format!("part.{:05}", part.part_number));
            if !part_path.exists() {
                return Err(Error::Backend(format!(
                    "Part {} not found for upload {}",
                    part.part_number, upload.upload_id
                )));
            }
            let part_data = fs::read(&part_path).await?;
            assembled.extend_from_slice(&part_data);
        }

        // Store the final object using Chonkers chunking
        let data = ObjectData::from(assembled);
        let meta = self.put(&upload.key, data, PutOptions::default()).await?;

        // Clean up upload directory
        fs::remove_dir_all(&upload_dir).await?;

        debug!(
            upload_id = %upload.upload_id,
            parts = sorted_parts.len(),
            size = meta.size,
            "Completed multipart upload"
        );

        Ok(meta)
    }

    async fn abort_multipart(&self, upload: &MultipartUpload) -> Result<()> {
        let upload_dir = self
            .bucket_path(upload.key.bucket())
            .join(".uploads")
            .join(&upload.upload_id);

        if !upload_dir.exists() {
            return Err(Error::Backend(format!(
                "Upload {} not found",
                upload.upload_id
            )));
        }

        fs::remove_dir_all(&upload_dir).await?;

        debug!(
            upload_id = %upload.upload_id,
            "Aborted multipart upload"
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_chonkers_backend_basic() {
        let temp_dir = tempfile::tempdir().unwrap();
        let backend = ChonkersBackend::new(temp_dir.path()).await.unwrap();

        // Create bucket
        backend.create_bucket("test").await.unwrap();
        assert!(backend.bucket_exists("test").await.unwrap());

        // Put object
        let key = ObjectKey::new("test", "hello.txt").unwrap();
        let data = ObjectData::from(b"Hello, World!".to_vec());
        let meta = backend
            .put(&key, data.clone(), PutOptions::default())
            .await
            .unwrap();

        assert_eq!(meta.size, 13);

        // Get object
        let retrieved = backend.get(&key).await.unwrap();
        assert_eq!(retrieved.as_ref(), b"Hello, World!");

        // Head object
        let head_meta = backend.head(&key).await.unwrap();
        assert_eq!(head_meta.size, 13);

        // Delete object
        backend.delete(&key).await.unwrap();

        // Get should fail
        assert!(backend.get(&key).await.is_err());

        // Delete bucket
        backend.delete_bucket("test").await.unwrap();
        assert!(!backend.bucket_exists("test").await.unwrap());
    }

    #[tokio::test]
    async fn test_chonkers_backend_dedup() {
        let temp_dir = tempfile::tempdir().unwrap();
        let backend = ChonkersBackend::new(temp_dir.path()).await.unwrap();

        backend.create_bucket("test").await.unwrap();

        // Store same data twice with different keys
        let data = ObjectData::from(b"Duplicate content for deduplication test".to_vec());

        let key1 = ObjectKey::new("test", "file1.txt").unwrap();
        let key2 = ObjectKey::new("test", "file2.txt").unwrap();

        backend
            .put(&key1, data.clone(), PutOptions::default())
            .await
            .unwrap();
        backend
            .put(&key2, data.clone(), PutOptions::default())
            .await
            .unwrap();

        // Both should be retrievable
        let retrieved1 = backend.get(&key1).await.unwrap();
        let retrieved2 = backend.get(&key2).await.unwrap();

        assert_eq!(retrieved1.as_ref(), retrieved2.as_ref());
    }

    #[tokio::test]
    async fn test_chonkers_backend_large_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let backend = ChonkersBackend::new(temp_dir.path()).await.unwrap();

        backend.create_bucket("test").await.unwrap();

        // Create a larger file that will be chunked
        let large_data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
        let key = ObjectKey::new("test", "large.bin").unwrap();

        backend
            .put(&key, ObjectData::from(large_data.clone()), PutOptions::default())
            .await
            .unwrap();

        // Retrieve and verify
        let retrieved = backend.get(&key).await.unwrap();
        assert_eq!(retrieved.as_ref(), large_data.as_slice());
    }

    #[tokio::test]
    async fn test_chonkers_backend_list() {
        let temp_dir = tempfile::tempdir().unwrap();
        let backend = ChonkersBackend::new(temp_dir.path()).await.unwrap();

        backend.create_bucket("test").await.unwrap();

        // Create multiple objects
        for i in 0..5 {
            let key = ObjectKey::new("test", &format!("data/{}.txt", i)).unwrap();
            let data = ObjectData::from(format!("content {}", i).into_bytes());
            backend.put(&key, data, PutOptions::default()).await.unwrap();
        }

        // List all
        let list = backend
            .list("test", "", ListOptions::default())
            .await
            .unwrap();
        assert_eq!(list.key_count, 5);

        // List with prefix
        let list = backend
            .list("test", "data/", ListOptions::default())
            .await
            .unwrap();
        assert_eq!(list.key_count, 5);
    }

    #[tokio::test]
    async fn test_chonkers_backend_multipart() {
        let temp_dir = tempfile::tempdir().unwrap();
        let backend = ChonkersBackend::new(temp_dir.path()).await.unwrap();

        backend.create_bucket("test").await.unwrap();

        let key = ObjectKey::new("test", "multipart.bin").unwrap();

        // Create multipart upload
        let upload = backend.create_multipart(&key).await.unwrap();

        // Upload parts
        let part1 = backend
            .upload_part(&upload, 1, ObjectData::from(b"Hello, ".to_vec()))
            .await
            .unwrap();
        let part2 = backend
            .upload_part(&upload, 2, ObjectData::from(b"World!".to_vec()))
            .await
            .unwrap();

        // Complete upload
        let meta = backend
            .complete_multipart(&upload, vec![part1, part2])
            .await
            .unwrap();
        assert_eq!(meta.size, 13);

        // Verify object
        let data = backend.get(&key).await.unwrap();
        assert_eq!(data.as_ref(), b"Hello, World!");
    }
}
