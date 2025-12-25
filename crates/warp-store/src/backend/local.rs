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

use super::{StorageBackend, HpcStorageBackend, StorageProof, ChunkedStream};
use crate::key::ObjectKey;
use crate::object::{ListOptions, ObjectData, ObjectEntry, ObjectList, ObjectMeta, PutOptions, StorageClass};
use crate::{Error, Result};

/// Local filesystem storage backend
pub struct LocalBackend {
    /// Root directory for storage
    root: PathBuf,
}

impl LocalBackend {
    /// Create a new local backend
    pub async fn new(root: &Path) -> Result<Self> {
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
}

#[async_trait]
impl StorageBackend for LocalBackend {
    async fn get(&self, key: &ObjectKey) -> Result<ObjectData> {
        let path = self.data_path(key);
        trace!(path = %path.display(), "Reading object");

        match fs::read(&path).await {
            Ok(data) => Ok(ObjectData::from(data)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(Error::ObjectNotFound {
                    bucket: key.bucket().to_string(),
                    key: key.key().to_string(),
                })
            }
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
                "object already exists and if_none_match is set".to_string()
            ));
        }

        // Ensure directories exist
        self.ensure_parent(&data_path).await?;
        self.ensure_parent(&meta_path).await?;

        // Create metadata
        let mut meta = ObjectMeta::new(&data);
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
                            let common_prefix = format!("{}{}{}", prefix, &after_prefix[..pos], delim);
                            if !common_prefixes.contains(&common_prefix) {
                                common_prefixes.push(common_prefix);
                            }
                            continue;
                        }
                    }
                    stack.push(path);
                } else {
                    // It's a file
                    let metadata = entry.metadata().await?;
                    let modified = metadata.modified()
                        .map(|t| chrono::DateTime::<Utc>::from(t))
                        .unwrap_or_else(|_| Utc::now());

                    objects.push(ObjectEntry {
                        key,
                        size: metadata.len(),
                        last_modified: modified,
                        etag: String::new(), // Would need to read metadata file
                        storage_class: StorageClass::Standard,
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
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(Error::ObjectNotFound {
                    bucket: key.bucket().to_string(),
                    key: key.key().to_string(),
                })
            }
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
        gpu_ptr: warp_gpu::GpuPtr,
        size: usize,
    ) -> Result<ObjectMeta> {
        // For local backend, copy from GPU to CPU then store
        let mut buffer = vec![0u8; size];
        gpu_ptr.copy_to_host(&mut buffer)?;

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
        let meta = backend.put(&key, data.clone(), PutOptions::default()).await.unwrap();

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
            backend.put(&key, data, PutOptions::default()).await.unwrap();
        }

        // List all
        let list = backend.list("test", "", ListOptions::default()).await.unwrap();
        assert_eq!(list.key_count, 5);

        // List with prefix
        let list = backend.list("test", "data/", ListOptions::default()).await.unwrap();
        assert_eq!(list.key_count, 5);
    }

    #[tokio::test]
    async fn test_local_backend_verified_get() {
        let temp_dir = tempfile::tempdir().unwrap();
        let backend = LocalBackend::new(temp_dir.path()).await.unwrap();

        backend.create_bucket("test").await.unwrap();

        let key = ObjectKey::new("test", "file.bin").unwrap();
        let data = ObjectData::from(b"test data for verification".to_vec());
        backend.put(&key, data, PutOptions::default()).await.unwrap();

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
        backend.put(&key, data, PutOptions::default()).await.unwrap();

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
}
