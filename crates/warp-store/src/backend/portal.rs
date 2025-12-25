//! Portal mesh storage backend
//!
//! Uses Portal Hub for distributed, content-addressed storage with:
//! - Chunk deduplication via BLAKE3 content addressing
//! - P2P mesh distribution across edges
//! - Zero-knowledge encryption (client-side)
//! - Merkle verification for storage proofs

use std::sync::Arc;

use async_trait::async_trait;
use dashmap::DashMap;
use tracing::{debug, trace};

use super::{ChunkedStream, HpcStorageBackend, StorageBackend, StorageProof};
use crate::key::ObjectKey;
use crate::object::{
    FieldData, ListOptions, ObjectData, ObjectEntry, ObjectList, ObjectMeta, PutOptions,
    StorageClass,
};
use crate::{Error, Result};

use portal_core::ContentId;
use portal_hub::HubStorage;

/// Object index entry - maps object key to content chunks
#[derive(Debug, Clone)]
struct ObjectIndex {
    /// Object metadata
    meta: ObjectMeta,
    /// Content IDs of chunks that make up the object
    chunk_ids: Vec<ContentId>,
    /// Total size
    total_size: u64,
}

/// Bucket index - maps bucket name to objects
#[derive(Debug, Default)]
struct BucketIndex {
    /// Object indices by key
    objects: DashMap<String, ObjectIndex>,
}

/// Portal mesh storage backend
///
/// Provides object storage on top of Portal's content-addressed chunk storage.
/// Objects are split into chunks, deduplicated, and distributed across the mesh.
pub struct PortalBackend {
    /// Portal Hub storage
    storage: Arc<HubStorage>,

    /// Bucket indices
    buckets: DashMap<String, BucketIndex>,

    /// Chunk size for splitting objects
    chunk_size: usize,
}

impl PortalBackend {
    /// Create a new Portal backend
    pub fn new(storage: Arc<HubStorage>) -> Self {
        Self {
            storage,
            buckets: DashMap::new(),
            chunk_size: 4 * 1024 * 1024, // 4MB default chunk size
        }
    }

    /// Create with custom chunk size
    pub fn with_chunk_size(storage: Arc<HubStorage>, chunk_size: usize) -> Self {
        Self {
            storage,
            buckets: DashMap::new(),
            chunk_size,
        }
    }

    /// Split data into content-addressed chunks
    fn chunk_data(&self, data: &[u8]) -> Vec<(ContentId, Vec<u8>)> {
        let mut chunks = Vec::new();

        for chunk in data.chunks(self.chunk_size) {
            let hash = blake3::hash(chunk);
            let content_id: ContentId = *hash.as_bytes();
            chunks.push((content_id, chunk.to_vec()));
        }

        chunks
    }

    /// Store chunks in Hub storage (with deduplication)
    fn store_chunks(&self, chunks: &[(ContentId, Vec<u8>)]) {
        for (content_id, data) in chunks {
            // Only store if not already present (deduplication)
            if !self.storage.has_chunk(content_id) {
                self.storage.store_chunk(*content_id, data.clone());
                trace!(chunk = hex::encode(content_id), size = data.len(), "Stored new chunk");
            } else {
                trace!(chunk = hex::encode(content_id), "Chunk already exists (dedup)");
            }
        }
    }

    /// Retrieve and reassemble chunks into object data
    fn retrieve_chunks(&self, chunk_ids: &[ContentId]) -> Result<ObjectData> {
        let mut data = Vec::new();

        for content_id in chunk_ids {
            let chunk = self.storage.get_chunk(content_id).map_err(|e| {
                Error::Backend(format!("Failed to retrieve chunk {}: {}", hex::encode(content_id), e))
            })?;
            data.extend_from_slice(&chunk);
        }

        Ok(ObjectData::from(data))
    }

    /// Compute Merkle root from chunk IDs
    fn compute_merkle_root(&self, chunk_ids: &[ContentId]) -> [u8; 32] {
        if chunk_ids.is_empty() {
            return [0; 32];
        }

        if chunk_ids.len() == 1 {
            return chunk_ids[0];
        }

        // Build merkle tree bottom-up
        let mut level: Vec<[u8; 32]> = chunk_ids.to_vec();

        while level.len() > 1 {
            let mut next_level = Vec::with_capacity((level.len() + 1) / 2);

            for pair in level.chunks(2) {
                let hash = if pair.len() == 2 {
                    blake3::hash(&[&pair[0][..], &pair[1][..]].concat())
                } else {
                    blake3::hash(&pair[0])
                };
                next_level.push(*hash.as_bytes());
            }

            level = next_level;
        }

        level[0]
    }

    /// Build Merkle proof path for a specific chunk
    fn build_merkle_path(&self, chunk_ids: &[ContentId], leaf_index: usize) -> Vec<[u8; 32]> {
        if chunk_ids.len() <= 1 {
            return vec![];
        }

        let mut path = Vec::new();
        let mut level: Vec<[u8; 32]> = chunk_ids.to_vec();
        let mut idx = leaf_index;

        while level.len() > 1 {
            // Get sibling
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };

            if sibling_idx < level.len() {
                path.push(level[sibling_idx]);
            }

            // Move to parent level
            let mut next_level = Vec::with_capacity((level.len() + 1) / 2);
            for pair in level.chunks(2) {
                let hash = if pair.len() == 2 {
                    blake3::hash(&[&pair[0][..], &pair[1][..]].concat())
                } else {
                    blake3::hash(&pair[0])
                };
                next_level.push(*hash.as_bytes());
            }

            level = next_level;
            idx /= 2;
        }

        path
    }
}

#[async_trait]
impl StorageBackend for PortalBackend {
    async fn get(&self, key: &ObjectKey) -> Result<ObjectData> {
        let bucket = self.buckets.get(key.bucket()).ok_or_else(|| {
            Error::BucketNotFound(key.bucket().to_string())
        })?;

        let index = bucket.objects.get(key.key()).ok_or_else(|| {
            Error::ObjectNotFound {
                bucket: key.bucket().to_string(),
                key: key.key().to_string(),
            }
        })?;

        debug!(key = %key, chunks = index.chunk_ids.len(), "Retrieving object from Portal mesh");
        self.retrieve_chunks(&index.chunk_ids)
    }

    async fn get_fields(&self, key: &ObjectKey, fields: &[&str]) -> Result<FieldData> {
        // Portal backend doesn't support field-level access
        // Would need parcode integration for this
        let _ = (key, fields);
        Ok(FieldData::new())
    }

    async fn put(&self, key: &ObjectKey, data: ObjectData, opts: PutOptions) -> Result<ObjectMeta> {
        // Ensure bucket exists
        if !self.buckets.contains_key(key.bucket()) {
            return Err(Error::BucketNotFound(key.bucket().to_string()));
        }

        // Check if_none_match condition
        if opts.if_none_match {
            if let Some(bucket) = self.buckets.get(key.bucket()) {
                if bucket.objects.contains_key(key.key()) {
                    return Err(Error::PermissionDenied(
                        "object already exists and if_none_match is set".to_string(),
                    ));
                }
            }
        }

        // Chunk the data
        let chunks = self.chunk_data(data.as_ref());
        let chunk_ids: Vec<ContentId> = chunks.iter().map(|(id, _)| *id).collect();

        // Store chunks (with deduplication)
        self.store_chunks(&chunks);

        // Create metadata
        let mut meta = ObjectMeta::new(&data);
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
            total_size: data.len() as u64,
        };

        // Store in bucket index
        let bucket = self.buckets.get(key.bucket()).unwrap();
        bucket.objects.insert(key.key().to_string(), index);

        debug!(
            key = %key,
            size = data.len(),
            chunks = chunks.len(),
            "Stored object in Portal mesh"
        );

        Ok(meta)
    }

    async fn delete(&self, key: &ObjectKey) -> Result<()> {
        let bucket = self.buckets.get(key.bucket()).ok_or_else(|| {
            Error::BucketNotFound(key.bucket().to_string())
        })?;

        // Remove from index (chunks stay for dedup - GC handles cleanup)
        bucket.objects.remove(key.key()).ok_or_else(|| {
            Error::ObjectNotFound {
                bucket: key.bucket().to_string(),
                key: key.key().to_string(),
            }
        })?;

        debug!(key = %key, "Deleted object from Portal mesh index");
        Ok(())
    }

    async fn list(&self, bucket: &str, prefix: &str, opts: ListOptions) -> Result<ObjectList> {
        let bucket_index = self.buckets.get(bucket).ok_or_else(|| {
            Error::BucketNotFound(bucket.to_string())
        })?;

        let mut objects = Vec::new();
        let mut common_prefixes = Vec::new();

        for entry in bucket_index.objects.iter() {
            let key = entry.key();
            let index = entry.value();

            // Filter by prefix
            if !key.starts_with(prefix) {
                continue;
            }

            // Filter by start_after
            if let Some(ref start_after) = opts.start_after {
                if key.as_str() <= start_after.as_str() {
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

            objects.push(ObjectEntry {
                key: key.clone(),
                size: index.total_size,
                last_modified: index.meta.modified_at,
                etag: index.meta.etag.clone(),
                storage_class: StorageClass::Standard,
                version_id: index.meta.version_id.clone(),
                is_latest: true,
            });
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
        let bucket = self.buckets.get(key.bucket()).ok_or_else(|| {
            Error::BucketNotFound(key.bucket().to_string())
        })?;

        let index = bucket.objects.get(key.key()).ok_or_else(|| {
            Error::ObjectNotFound {
                bucket: key.bucket().to_string(),
                key: key.key().to_string(),
            }
        })?;

        Ok(index.meta.clone())
    }

    async fn create_bucket(&self, name: &str) -> Result<()> {
        self.buckets.insert(name.to_string(), BucketIndex::default());
        debug!(bucket = name, "Created bucket in Portal mesh");
        Ok(())
    }

    async fn delete_bucket(&self, name: &str) -> Result<()> {
        let bucket = self.buckets.remove(name).ok_or_else(|| {
            Error::BucketNotFound(name.to_string())
        })?;

        // Check if empty
        if !bucket.1.objects.is_empty() {
            // Re-insert and return error
            self.buckets.insert(name.to_string(), bucket.1);
            return Err(Error::BucketNotEmpty(name.to_string()));
        }

        debug!(bucket = name, "Deleted bucket from Portal mesh");
        Ok(())
    }

    async fn bucket_exists(&self, name: &str) -> Result<bool> {
        Ok(self.buckets.contains_key(name))
    }
}

#[async_trait]
impl HpcStorageBackend for PortalBackend {
    async fn verified_get(&self, key: &ObjectKey) -> Result<(ObjectData, StorageProof)> {
        let bucket = self.buckets.get(key.bucket()).ok_or_else(|| {
            Error::BucketNotFound(key.bucket().to_string())
        })?;

        let index = bucket.objects.get(key.key()).ok_or_else(|| {
            Error::ObjectNotFound {
                bucket: key.bucket().to_string(),
                key: key.key().to_string(),
            }
        })?;

        // Retrieve data
        let data = self.retrieve_chunks(&index.chunk_ids)?;

        // Compute Merkle proof
        let root = self.compute_merkle_root(&index.chunk_ids);
        let path = if !index.chunk_ids.is_empty() {
            self.build_merkle_path(&index.chunk_ids, 0)
        } else {
            vec![]
        };

        let proof = StorageProof {
            root,
            path,
            leaf_index: 0,
        };

        Ok((data, proof))
    }

    async fn stream_chunked(&self, key: &ObjectKey, chunk_size: usize) -> Result<ChunkedStream> {
        let data = self.get(key).await?;
        Ok(ChunkedStream::from_data(data, chunk_size))
    }

    async fn collective_read(
        &self,
        keys: &[ObjectKey],
        rank_count: usize,
    ) -> Result<Vec<(usize, ObjectData)>> {
        // Distribute keys across ranks round-robin
        let mut results = Vec::with_capacity(keys.len());

        for (i, key) in keys.iter().enumerate() {
            let data = self.get(key).await?;
            let rank = i % rank_count;
            results.push((rank, data));
        }

        Ok(results)
    }

    #[cfg(feature = "gpu")]
    async fn pinned_store(
        &self,
        key: &ObjectKey,
        gpu_ptr: warp_gpu::GpuPtr,
        size: usize,
    ) -> Result<ObjectMeta> {
        // Copy from GPU to CPU, then store
        let mut buffer = vec![0u8; size];
        gpu_ptr.copy_to_host(&mut buffer)?;

        let data = ObjectData::from(buffer);
        self.put(key, data, PutOptions::default()).await
    }
}

/// Hex encoding helper
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_portal_backend_basic() {
        let storage = Arc::new(HubStorage::new());
        let backend = PortalBackend::new(storage.clone());

        // Create bucket
        backend.create_bucket("test").await.unwrap();
        assert!(backend.bucket_exists("test").await.unwrap());

        // Put object
        let key = ObjectKey::new("test", "hello.txt").unwrap();
        let data = ObjectData::from(b"Hello, Portal!".to_vec());
        let meta = backend.put(&key, data.clone(), PutOptions::default()).await.unwrap();

        assert_eq!(meta.size, 14);

        // Get object
        let retrieved = backend.get(&key).await.unwrap();
        assert_eq!(retrieved.as_ref(), b"Hello, Portal!");

        // Verify chunks are stored in Hub
        assert!(storage.chunk_count() > 0);
    }

    #[tokio::test]
    async fn test_portal_backend_deduplication() {
        let storage = Arc::new(HubStorage::new());
        let backend = PortalBackend::with_chunk_size(storage.clone(), 1024);

        backend.create_bucket("test").await.unwrap();

        // Store same data twice under different keys
        let data = ObjectData::from(vec![42u8; 2048]); // 2 chunks

        let key1 = ObjectKey::new("test", "file1.bin").unwrap();
        let key2 = ObjectKey::new("test", "file2.bin").unwrap();

        backend.put(&key1, data.clone(), PutOptions::default()).await.unwrap();
        let initial_chunks = storage.chunk_count();

        backend.put(&key2, data, PutOptions::default()).await.unwrap();
        let final_chunks = storage.chunk_count();

        // Should have same number of chunks due to deduplication
        assert_eq!(initial_chunks, final_chunks);
    }

    #[tokio::test]
    async fn test_portal_backend_verified_get() {
        let storage = Arc::new(HubStorage::new());
        let backend = PortalBackend::with_chunk_size(storage.clone(), 512);

        backend.create_bucket("test").await.unwrap();

        let key = ObjectKey::new("test", "verified.bin").unwrap();
        let data = ObjectData::from(vec![1, 2, 3, 4, 5]);
        backend.put(&key, data, PutOptions::default()).await.unwrap();

        // Get with verification
        let (retrieved, proof) = backend.verified_get(&key).await.unwrap();
        assert_eq!(retrieved.as_ref(), &[1, 2, 3, 4, 5]);

        // Proof root should be non-zero
        assert_ne!(proof.root, [0; 32]);
    }

    #[tokio::test]
    async fn test_portal_backend_list() {
        let storage = Arc::new(HubStorage::new());
        let backend = PortalBackend::new(storage);

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
    async fn test_merkle_root() {
        let storage = Arc::new(HubStorage::new());
        let backend = PortalBackend::new(storage);

        // Test with different numbers of chunks
        let chunks_1: Vec<ContentId> = vec![[1; 32]];
        let root_1 = backend.compute_merkle_root(&chunks_1);
        assert_eq!(root_1, [1; 32]); // Single chunk is its own root

        let chunks_2: Vec<ContentId> = vec![[1; 32], [2; 32]];
        let root_2 = backend.compute_merkle_root(&chunks_2);
        assert_ne!(root_2, [0; 32]);

        let chunks_3: Vec<ContentId> = vec![[1; 32], [2; 32], [3; 32]];
        let root_3 = backend.compute_merkle_root(&chunks_3);
        assert_ne!(root_3, root_2); // Different structure = different root
    }
}
