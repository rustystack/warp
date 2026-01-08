//! Local filesystem storage backend
//!
//! Stores objects on the local filesystem with the following layout:
//! ```text
//! root/
//! ├── buckets/
//! │   ├── bucket-name/
//! │   │   ├── .meta/
//! │   │   │   ├── config.msgpack    # bucket config
//! │   │   │   └── objects/          # object metadata
//! │   │   │       └── path/to/key.meta
//! │   │   └── data/
//! │   │       └── path/to/key       # object data
//! ```

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use chrono::Utc;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tracing::{debug, trace};

use super::{
    ChunkedStream, HpcStorageBackend, MultipartUpload, PartInfo, StorageBackend, StorageProof,
};
use crate::key::ObjectKey;
use crate::object::{
    ListOptions, ObjectData, ObjectEntry, ObjectList, ObjectMeta, PutOptions, StorageClass,
};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};

/// Metadata for a multipart upload
#[derive(Debug, Clone, Serialize, Deserialize)]
struct UploadMeta {
    /// Object key
    bucket: String,
    key: String,
    /// Upload ID
    upload_id: String,
    /// Creation timestamp
    created_at: chrono::DateTime<chrono::Utc>,
}

/// Local filesystem storage backend
pub struct LocalBackend {
    /// Root directory for storage
    root: PathBuf,
}

impl LocalBackend {
    /// Create a new local backend
    pub async fn new(root: &Path) -> Result<Self> {
        debug_assert!(!root.as_os_str().is_empty(), "root path must not be empty");

        // Create root directories
        let buckets_dir = root.join("buckets");
        fs::create_dir_all(&buckets_dir).await?;

        debug!(root = %root.display(), "Initialized local backend");

        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    /// Get the path to bucket directory
    fn bucket_path(&self, bucket: &str) -> PathBuf {
        self.root.join("buckets").join(bucket)
    }

    /// Get the path to object data
    fn data_path(&self, key: &ObjectKey) -> PathBuf {
        self.bucket_path(key.bucket()).join("data").join(key.key())
    }

    /// Get the path to object metadata
    fn meta_path(&self, key: &ObjectKey) -> PathBuf {
        self.bucket_path(key.bucket())
            .join(".meta")
            .join("objects")
            .join(format!("{}.meta", key.key()))
    }

    /// Ensure parent directories exist
    async fn ensure_parent(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }
        Ok(())
    }

    /// Get the path to multipart uploads directory
    fn uploads_path(&self, bucket: &str) -> PathBuf {
        self.bucket_path(bucket).join(".uploads")
    }

    /// Get the path to a specific upload directory
    fn upload_path(&self, key: &ObjectKey, upload_id: &str) -> PathBuf {
        self.uploads_path(key.bucket()).join(upload_id)
    }

    /// Get the path to a part file
    fn part_path(&self, key: &ObjectKey, upload_id: &str, part_number: u32) -> PathBuf {
        self.upload_path(key, upload_id)
            .join(format!("part.{:05}", part_number))
    }

    /// Get the path to upload metadata
    fn upload_meta_path(&self, key: &ObjectKey, upload_id: &str) -> PathBuf {
        self.upload_path(key, upload_id).join("meta.msgpack")
    }

    /// Generate a unique upload ID
    fn generate_upload_id() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("{:032x}", timestamp)
    }
}

#[async_trait]
impl StorageBackend for LocalBackend {
    async fn get(&self, key: &ObjectKey) -> Result<ObjectData> {
        let path = self.data_path(key);
        trace!(path = %path.display(), "Reading object");

        match fs::read(&path).await {
            Ok(data) => Ok(ObjectData::from(data)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(Error::ObjectNotFound {
                bucket: key.bucket().to_string(),
                key: key.key().to_string(),
            }),
            Err(e) => Err(e.into()),
        }
    }

    async fn put(&self, key: &ObjectKey, data: ObjectData, opts: PutOptions) -> Result<ObjectMeta> {
        let data_path = self.data_path(key);
        let meta_path = self.meta_path(key);

        trace!(path = %data_path.display(), size = data.len(), "Writing object");

        // Check if_none_match condition
        if opts.if_none_match && data_path.exists() {
            return Err(Error::PermissionDenied(
                "object already exists and if_none_match is set".to_string(),
            ));
        }

        // Ensure directories exist
        self.ensure_parent(&data_path).await?;
        self.ensure_parent(&meta_path).await?;

        // Create metadata with storage class
        let mut meta = ObjectMeta::with_storage_class(&data, opts.storage_class);
        if let Some(ct) = opts.content_type {
            meta = meta.with_content_type(ct);
        }
        for (k, v) in opts.metadata {
            meta = meta.with_metadata(k, v);
        }

        // Write data atomically (write to temp, then rename)
        let temp_path = data_path.with_extension("tmp");
        let mut file = fs::File::create(&temp_path).await?;
        file.write_all(data.as_ref()).await?;
        file.sync_all().await?;
        fs::rename(&temp_path, &data_path).await?;

        // Write metadata
        let meta_bytes = rmp_serde::to_vec(&meta)?;
        fs::write(&meta_path, &meta_bytes).await?;

        Ok(meta)
    }

    async fn delete(&self, key: &ObjectKey) -> Result<()> {
        let data_path = self.data_path(key);
        let meta_path = self.meta_path(key);

        trace!(path = %data_path.display(), "Deleting object");

        // Remove data file
        match fs::remove_file(&data_path).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::ObjectNotFound {
                    bucket: key.bucket().to_string(),
                    key: key.key().to_string(),
                });
            }
            Err(e) => return Err(e.into()),
        }

        // Remove metadata file (ignore if not found)
        let _ = fs::remove_file(&meta_path).await;

        Ok(())
    }

    async fn list(&self, bucket: &str, prefix: &str, opts: ListOptions) -> Result<ObjectList> {
        let data_dir = self.bucket_path(bucket).join("data");

        if !data_dir.exists() {
            return Err(Error::BucketNotFound(bucket.to_string()));
        }

        let mut objects = Vec::new();
        let mut common_prefixes = Vec::new();

        // Walk directory recursively
        let mut stack = vec![data_dir.clone()];
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

                // Get relative key
                let rel_path = path.strip_prefix(&data_dir).unwrap_or(&path);
                let key = rel_path.to_string_lossy().to_string();

                // Filter by prefix
                if !key.starts_with(prefix) {
                    if file_type.is_dir() {
                        stack.push(path);
                    }
                    continue;
                }

                // Filter by start_after
                if let Some(ref start_after) = opts.start_after {
                    if &key <= start_after {
                        if file_type.is_dir() {
                            stack.push(path);
                        }
                        continue;
                    }
                }

                if file_type.is_dir() {
                    // Handle delimiter for common prefixes
                    if let Some(ref delim) = opts.delimiter {
                        let after_prefix = &key[prefix.len()..];
                        if let Some(pos) = after_prefix.find(delim) {
                            let common_prefix =
                                format!("{}{}{}", prefix, &after_prefix[..pos], delim);
                            if !common_prefixes.contains(&common_prefix) {
                                common_prefixes.push(common_prefix);
                            }
                            continue;
                        }
                    }
                    stack.push(path);
                } else {
                    // It's a file
                    let file_metadata = entry.metadata().await?;
                    let modified = file_metadata
                        .modified()
                        .map(chrono::DateTime::<Utc>::from)
                        .unwrap_or_else(|_| Utc::now());

                    // Try to read object metadata for storage class and etag
                    let obj_key = ObjectKey::new(bucket, &key)
                        .unwrap_or_else(|_| ObjectKey::new(bucket, "unknown").unwrap());
                    let meta_path = self.meta_path(&obj_key);
                    let (etag, storage_class) = if let Ok(meta_bytes) = fs::read(&meta_path).await {
                        if let Ok(meta) = rmp_serde::from_slice::<ObjectMeta>(&meta_bytes) {
                            (meta.etag, meta.storage_class)
                        } else {
                            (String::new(), StorageClass::Standard)
                        }
                    } else {
                        (String::new(), StorageClass::Standard)
                    };

                    objects.push(ObjectEntry {
                        key,
                        size: file_metadata.len(),
                        last_modified: modified,
                        etag,
                        storage_class,
                        version_id: None,
                        is_latest: true,
                    });
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
            next_continuation_token: None, // Simplified - no pagination yet
            is_truncated,
            key_count,
        })
    }

    async fn head(&self, key: &ObjectKey) -> Result<ObjectMeta> {
        let meta_path = self.meta_path(key);
        let data_path = self.data_path(key);

        // Try to read metadata file first
        if let Ok(meta_bytes) = fs::read(&meta_path).await {
            if let Ok(meta) = rmp_serde::from_slice::<ObjectMeta>(&meta_bytes) {
                return Ok(meta);
            }
        }

        // Fall back to reading the data file and computing metadata
        match fs::metadata(&data_path).await {
            Ok(_file_meta) => {
                let data = fs::read(&data_path).await?;
                let object_data = ObjectData::from(data);
                Ok(ObjectMeta::new(&object_data))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(Error::ObjectNotFound {
                bucket: key.bucket().to_string(),
                key: key.key().to_string(),
            }),
            Err(e) => Err(e.into()),
        }
    }

    async fn create_bucket(&self, name: &str) -> Result<()> {
        let bucket_path = self.bucket_path(name);
        let data_path = bucket_path.join("data");
        let meta_path = bucket_path.join(".meta").join("objects");

        fs::create_dir_all(&data_path).await?;
        fs::create_dir_all(&meta_path).await?;

        debug!(bucket = name, "Created bucket");
        Ok(())
    }

    async fn delete_bucket(&self, name: &str) -> Result<()> {
        let bucket_path = self.bucket_path(name);

        if !bucket_path.exists() {
            return Err(Error::BucketNotFound(name.to_string()));
        }

        fs::remove_dir_all(&bucket_path).await?;

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

        let upload_id = Self::generate_upload_id();
        let now = chrono::Utc::now();

        // Create upload directory
        let upload_dir = self.upload_path(key, &upload_id);
        fs::create_dir_all(&upload_dir).await?;

        // Save upload metadata
        let meta = UploadMeta {
            bucket: key.bucket().to_string(),
            key: key.key().to_string(),
            upload_id: upload_id.clone(),
            created_at: now,
        };
        let meta_path = self.upload_meta_path(key, &upload_id);
        let meta_bytes = rmp_serde::to_vec(&meta)?;
        fs::write(&meta_path, &meta_bytes).await?;

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
        // Validate part number (S3 uses 1-10000)
        if part_number == 0 || part_number > 10000 {
            return Err(Error::Backend(format!(
                "Invalid part number: {}. Must be between 1 and 10000",
                part_number
            )));
        }

        // Check upload exists
        let upload_dir = self.upload_path(&upload.key, &upload.upload_id);
        if !upload_dir.exists() {
            return Err(Error::Backend(format!(
                "Upload {} not found",
                upload.upload_id
            )));
        }

        // Compute etag (hash of part data)
        let hash = blake3::hash(data.as_ref());
        let etag = format!("\"{}\"", hash.to_hex());
        let size = data.len() as u64;

        // Write part data
        let part_path = self.part_path(&upload.key, &upload.upload_id, part_number);
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
        let upload_dir = self.upload_path(&upload.key, &upload.upload_id);
        if !upload_dir.exists() {
            return Err(Error::Backend(format!(
                "Upload {} not found",
                upload.upload_id
            )));
        }

        // Verify all parts exist and collect them in order
        let mut sorted_parts = parts.clone();
        sorted_parts.sort_by_key(|p| p.part_number);

        // Assemble data from parts
        let mut assembled = Vec::new();
        for part in &sorted_parts {
            let part_path = self.part_path(&upload.key, &upload.upload_id, part.part_number);
            if !part_path.exists() {
                return Err(Error::Backend(format!(
                    "Part {} not found for upload {}",
                    part.part_number, upload.upload_id
                )));
            }
            let part_data = fs::read(&part_path).await?;
            assembled.extend_from_slice(&part_data);
        }

        // Write the final object
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
        let upload_dir = self.upload_path(&upload.key, &upload.upload_id);

        if !upload_dir.exists() {
            return Err(Error::Backend(format!(
                "Upload {} not found",
                upload.upload_id
            )));
        }

        // Remove entire upload directory
        fs::remove_dir_all(&upload_dir).await?;

        debug!(
            upload_id = %upload.upload_id,
            "Aborted multipart upload"
        );

        Ok(())
    }
}

#[async_trait]
impl HpcStorageBackend for LocalBackend {
    async fn verified_get(&self, key: &ObjectKey) -> Result<(ObjectData, StorageProof)> {
        let data = self.get(key).await?;

        // Compute BLAKE3 hash as proof
        let hash = blake3::hash(data.as_ref());
        let proof = StorageProof {
            root: *hash.as_bytes(),
            path: vec![],
            leaf_index: 0,
        };

        Ok((data, proof))
    }

    async fn stream_chunked(&self, key: &ObjectKey, chunk_size: usize) -> Result<ChunkedStream> {
        let data = self.get(key).await?;
        Ok(ChunkedStream::from_data(data, chunk_size))
    }

    #[cfg(feature = "gpu")]
    async fn pinned_store(
        &self,
        key: &ObjectKey,
        gpu_buffer: &warp_gpu::GpuBuffer<u8>,
    ) -> Result<ObjectMeta> {
        // For local backend, copy from GPU to CPU then store
        let buffer = gpu_buffer
            .copy_to_host()
            .map_err(|e| crate::Error::Backend(format!("GPU copy failed: {}", e)))?;

        let data = ObjectData::from(buffer);
        self.put(key, data, PutOptions::default()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_local_backend_basic() {
        let temp_dir = tempfile::tempdir().unwrap();
        let backend = LocalBackend::new(temp_dir.path()).await.unwrap();

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
    async fn test_local_backend_list() {
        let temp_dir = tempfile::tempdir().unwrap();
        let backend = LocalBackend::new(temp_dir.path()).await.unwrap();

        backend.create_bucket("test").await.unwrap();

        // Create multiple objects
        for i in 0..5 {
            let key = ObjectKey::new("test", &format!("data/{}.txt", i)).unwrap();
            let data = ObjectData::from(format!("content {}", i).into_bytes());
            backend
                .put(&key, data, PutOptions::default())
                .await
                .unwrap();
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
    async fn test_local_backend_verified_get() {
        let temp_dir = tempfile::tempdir().unwrap();
        let backend = LocalBackend::new(temp_dir.path()).await.unwrap();

        backend.create_bucket("test").await.unwrap();

        let key = ObjectKey::new("test", "file.bin").unwrap();
        let data = ObjectData::from(b"test data for verification".to_vec());
        backend
            .put(&key, data, PutOptions::default())
            .await
            .unwrap();

        // Get with proof
        let (retrieved, proof) = backend.verified_get(&key).await.unwrap();

        // Verify the proof
        assert!(proof.verify(retrieved.as_ref()));
        assert!(!proof.verify(b"wrong data"));
    }

    #[tokio::test]
    async fn test_local_backend_stream() {
        let temp_dir = tempfile::tempdir().unwrap();
        let backend = LocalBackend::new(temp_dir.path()).await.unwrap();

        backend.create_bucket("test").await.unwrap();

        let key = ObjectKey::new("test", "large.bin").unwrap();
        let data = ObjectData::from(vec![42u8; 1000]);
        backend
            .put(&key, data, PutOptions::default())
            .await
            .unwrap();

        // Stream in chunks
        let mut stream = backend.stream_chunked(&key, 100).await.unwrap();
        let mut chunk_count = 0;
        let mut total_bytes = 0;

        while let Some(chunk) = stream.next_chunk() {
            chunk_count += 1;
            total_bytes += chunk.len();
            assert!(chunk.iter().all(|&b| b == 42));
        }

        assert_eq!(chunk_count, 10);
        assert_eq!(total_bytes, 1000);
    }

    #[tokio::test]
    async fn test_multipart_upload_basic() {
        let temp_dir = tempfile::tempdir().unwrap();
        let backend = LocalBackend::new(temp_dir.path()).await.unwrap();

        backend.create_bucket("test").await.unwrap();

        let key = ObjectKey::new("test", "multipart.bin").unwrap();

        // Create multipart upload
        let upload = backend.create_multipart(&key).await.unwrap();
        assert!(!upload.upload_id.is_empty());
        assert_eq!(upload.key.bucket(), "test");
        assert_eq!(upload.key.key(), "multipart.bin");

        // Upload parts
        let part1 = backend
            .upload_part(&upload, 1, ObjectData::from(b"Hello, ".to_vec()))
            .await
            .unwrap();
        let part2 = backend
            .upload_part(&upload, 2, ObjectData::from(b"World!".to_vec()))
            .await
            .unwrap();

        assert_eq!(part1.part_number, 1);
        assert_eq!(part1.size, 7);
        assert_eq!(part2.part_number, 2);
        assert_eq!(part2.size, 6);

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

    #[tokio::test]
    async fn test_multipart_upload_out_of_order() {
        let temp_dir = tempfile::tempdir().unwrap();
        let backend = LocalBackend::new(temp_dir.path()).await.unwrap();

        backend.create_bucket("test").await.unwrap();

        let key = ObjectKey::new("test", "outoforder.bin").unwrap();

        // Create upload
        let upload = backend.create_multipart(&key).await.unwrap();

        // Upload parts out of order
        let part3 = backend
            .upload_part(&upload, 3, ObjectData::from(b"C".to_vec()))
            .await
            .unwrap();
        let part1 = backend
            .upload_part(&upload, 1, ObjectData::from(b"A".to_vec()))
            .await
            .unwrap();
        let part2 = backend
            .upload_part(&upload, 2, ObjectData::from(b"B".to_vec()))
            .await
            .unwrap();

        // Complete - parts should be sorted
        let meta = backend
            .complete_multipart(&upload, vec![part3, part1, part2])
            .await
            .unwrap();
        assert_eq!(meta.size, 3);

        // Verify correct order
        let data = backend.get(&key).await.unwrap();
        assert_eq!(data.as_ref(), b"ABC");
    }

    #[tokio::test]
    async fn test_multipart_upload_abort() {
        let temp_dir = tempfile::tempdir().unwrap();
        let backend = LocalBackend::new(temp_dir.path()).await.unwrap();

        backend.create_bucket("test").await.unwrap();

        let key = ObjectKey::new("test", "aborted.bin").unwrap();

        // Create upload
        let upload = backend.create_multipart(&key).await.unwrap();

        // Upload a part
        backend
            .upload_part(&upload, 1, ObjectData::from(b"data".to_vec()))
            .await
            .unwrap();

        // Abort upload
        backend.abort_multipart(&upload).await.unwrap();

        // Object should not exist
        assert!(backend.get(&key).await.is_err());

        // Trying to abort again should fail
        assert!(backend.abort_multipart(&upload).await.is_err());
    }

    #[tokio::test]
    async fn test_multipart_upload_large() {
        let temp_dir = tempfile::tempdir().unwrap();
        let backend = LocalBackend::new(temp_dir.path()).await.unwrap();

        backend.create_bucket("test").await.unwrap();

        let key = ObjectKey::new("test", "large_multipart.bin").unwrap();

        // Create upload
        let upload = backend.create_multipart(&key).await.unwrap();

        // Upload 10 parts of 100KB each = 1MB total
        let mut parts = Vec::new();
        for i in 1..=10 {
            let data: Vec<u8> = (0..100_000).map(|j| ((i + j) % 256) as u8).collect();
            let part = backend
                .upload_part(&upload, i as u32, ObjectData::from(data))
                .await
                .unwrap();
            assert_eq!(part.size, 100_000);
            parts.push(part);
        }

        // Complete upload
        let meta = backend.complete_multipart(&upload, parts).await.unwrap();
        assert_eq!(meta.size, 1_000_000);

        // Verify object
        let data = backend.get(&key).await.unwrap();
        assert_eq!(data.len(), 1_000_000);
    }
}
