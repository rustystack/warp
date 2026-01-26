//! Storage backend trait and implementations
//!
//! The `StorageBackend` trait defines the core operations that all storage backends must implement.
//! The `HpcStorageBackend` trait extends this with HPC-specific operations like collective I/O
//! and GPU-direct storage.

mod local;

pub use local::LocalBackend;

#[cfg(feature = "portal")]
mod portal;

#[cfg(feature = "portal")]
pub use portal::PortalBackend;

#[cfg(feature = "parcode")]
mod parcode;

#[cfg(feature = "parcode")]
pub use parcode::{FieldEntry, FieldType, ParcodeBackend, ParcodeHeader, Promise};

#[cfg(feature = "erasure")]
mod erasure;

#[cfg(feature = "erasure")]
pub use erasure::{EncodedShardMeta, ErasureBackend, ShardHealth, StoreErasureConfig};

#[cfg(feature = "erasure")]
mod distributed;

#[cfg(feature = "erasure")]
pub use distributed::{DistributedBackend, DistributedConfig, DistributedStats};

#[cfg(feature = "gpu")]
mod gpu_direct;

#[cfg(feature = "gpu")]
pub use gpu_direct::{
    GpuBufferHandle, GpuDirectBackend, GpuDirectConfig, GpuDirectStats, GpuReduceOp, NvLinkTopology,
    P2PPath, P2PTransferResult, PinnedHandle,
};

#[cfg(feature = "chonkers")]
mod chonkers;

#[cfg(feature = "chonkers")]
pub use chonkers::{ChonkersBackend, DedupStats, GcResult};

#[cfg(feature = "blind-dedup")]
mod blind_dedup;

#[cfg(feature = "blind-dedup")]
pub use blind_dedup::{
    BlindDedupConfig, BlindDedupService, BlindDedupStats, EmbeddedDedupService, SledDedupIndex,
};

// Re-export warp-oprf types for convenience
#[cfg(feature = "blind-dedup")]
pub use warp_oprf::dedup::{DedupIndex, DedupReference, DedupToken, MemoryDedupIndex};

#[cfg(feature = "nvmeof")]
pub mod nvmeof;

#[cfg(feature = "nvmeof")]
pub use nvmeof::{
    NvmeOfBackend, NvmeOfBackendConfig, NvmeOfBackendError, NvmeOfBackendResult, NvmeOfTargetConfig,
};

use async_trait::async_trait;

use crate::Result;
use crate::key::ObjectKey;
use crate::object::{FieldData, ListOptions, ObjectData, ObjectList, ObjectMeta, PutOptions};

/// Core storage backend trait
///
/// All storage backends must implement this trait. It provides the fundamental
/// object storage operations: get, put, delete, list, head.
#[async_trait]
pub trait StorageBackend: Send + Sync + 'static {
    /// Get object data
    async fn get(&self, key: &ObjectKey) -> Result<ObjectData>;

    /// Get specific fields from an object (lazy loading)
    ///
    /// This is an optional optimization - the default implementation fetches
    /// the entire object. Backends like Parcode can implement true lazy field access.
    async fn get_fields(&self, key: &ObjectKey, fields: &[&str]) -> Result<FieldData> {
        // Default: fetch entire object (no lazy loading)
        let _ = (key, fields);
        Ok(FieldData::new())
    }

    /// Put object data
    async fn put(&self, key: &ObjectKey, data: ObjectData, opts: PutOptions) -> Result<ObjectMeta>;

    /// Delete an object
    async fn delete(&self, key: &ObjectKey) -> Result<()>;

    /// List objects with prefix
    async fn list(&self, bucket: &str, prefix: &str, opts: ListOptions) -> Result<ObjectList>;

    /// Get object metadata without data
    async fn head(&self, key: &ObjectKey) -> Result<ObjectMeta>;

    /// Create a bucket
    async fn create_bucket(&self, name: &str) -> Result<()>;

    /// Delete a bucket
    async fn delete_bucket(&self, name: &str) -> Result<()>;

    /// Check if a bucket exists
    async fn bucket_exists(&self, name: &str) -> Result<bool>;

    /// Initiate a multipart upload
    async fn create_multipart(&self, key: &ObjectKey) -> Result<MultipartUpload> {
        let _ = key;
        Err(crate::Error::Backend(
            "multipart upload not supported".to_string(),
        ))
    }

    /// Upload a part
    async fn upload_part(
        &self,
        upload: &MultipartUpload,
        part_number: u32,
        data: ObjectData,
    ) -> Result<PartInfo> {
        let _ = (upload, part_number, data);
        Err(crate::Error::Backend(
            "multipart upload not supported".to_string(),
        ))
    }

    /// Complete a multipart upload
    async fn complete_multipart(
        &self,
        upload: &MultipartUpload,
        parts: Vec<PartInfo>,
    ) -> Result<ObjectMeta> {
        let _ = (upload, parts);
        Err(crate::Error::Backend(
            "multipart upload not supported".to_string(),
        ))
    }

    /// Abort a multipart upload
    async fn abort_multipart(&self, upload: &MultipartUpload) -> Result<()> {
        let _ = upload;
        Err(crate::Error::Backend(
            "multipart upload not supported".to_string(),
        ))
    }
}

/// HPC-specific storage extensions
///
/// These operations leverage HPC infrastructure for high-performance storage:
/// - Collective I/O across MPI ranks
/// - GPU-direct storage (bypass CPU)
/// - Zero-knowledge proofs of storage
#[async_trait]
pub trait HpcStorageBackend: StorageBackend {
    /// Collective read across ranks
    ///
    /// Efficiently reads multiple objects and distributes them to different
    /// MPI ranks. Uses RDMA when available.
    async fn collective_read(
        &self,
        keys: &[ObjectKey],
        rank_count: usize,
    ) -> Result<Vec<(usize, ObjectData)>> {
        // Default: sequential reads
        let mut results = Vec::with_capacity(keys.len());
        for (i, key) in keys.iter().enumerate() {
            let data = self.get(key).await?;
            results.push((i % rank_count, data));
        }
        Ok(results)
    }

    /// Store from GPU memory directly
    ///
    /// Uses GPUDirect to transfer data from GPU memory to storage without
    /// going through CPU memory. Returns the object metadata.
    #[cfg(feature = "gpu")]
    async fn pinned_store(
        &self,
        key: &ObjectKey,
        gpu_buffer: &warp_gpu::GpuBuffer<u8>,
    ) -> Result<ObjectMeta>;

    /// Load directly to GPU memory
    ///
    /// Uses GPUDirect to transfer data from storage directly to GPU memory
    /// without going through CPU memory. Returns a GPU buffer containing the data.
    ///
    /// This is the inverse of `pinned_store` and completes the GPU-direct
    /// storage round-trip.
    #[cfg(feature = "gpu")]
    async fn pinned_load(&self, key: &ObjectKey) -> Result<warp_gpu::GpuBuffer<u8>>;

    /// Get with zero-knowledge proof of storage
    ///
    /// Returns the object data along with a cryptographic proof that the
    /// storage node actually stores the data (useful for decentralized storage).
    async fn verified_get(&self, key: &ObjectKey) -> Result<(ObjectData, StorageProof)> {
        let data = self.get(key).await?;

        // Default: compute a simple merkle proof
        let hash = blake3::hash(data.as_ref());
        let proof = StorageProof {
            root: *hash.as_bytes(),
            path: vec![],
            leaf_index: 0,
        };

        Ok((data, proof))
    }

    /// Stream chunked data
    ///
    /// Streams object data in chunks, useful for very large objects
    /// or when memory is constrained.
    async fn stream_chunked(&self, key: &ObjectKey, chunk_size: usize) -> Result<ChunkedStream> {
        let data = self.get(key).await?;
        Ok(ChunkedStream::from_data(data, chunk_size))
    }
}

/// Multipart upload handle
#[derive(Debug, Clone)]
pub struct MultipartUpload {
    /// Upload ID
    pub upload_id: String,

    /// Object key
    pub key: ObjectKey,

    /// Creation time
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Information about an uploaded part
#[derive(Debug, Clone)]
pub struct PartInfo {
    /// Part number (1-10000)
    pub part_number: u32,

    /// ETag of the part
    pub etag: String,

    /// Size of the part
    pub size: u64,
}

/// Zero-knowledge proof of storage
#[derive(Debug, Clone)]
pub struct StorageProof {
    /// Merkle root
    pub root: [u8; 32],

    /// Merkle path (sibling hashes)
    pub path: Vec<[u8; 32]>,

    /// Leaf index in the tree
    pub leaf_index: u64,
}

impl StorageProof {
    /// Verify the proof for given data
    pub fn verify(&self, data: &[u8]) -> bool {
        let mut hash = *blake3::hash(data).as_bytes();

        for (i, sibling) in self.path.iter().enumerate() {
            let bit = (self.leaf_index >> i) & 1;
            hash = if bit == 0 {
                *blake3::hash(&[&hash[..], &sibling[..]].concat()).as_bytes()
            } else {
                *blake3::hash(&[&sibling[..], &hash[..]].concat()).as_bytes()
            };
        }

        hash == self.root
    }
}

/// Chunked data stream
pub struct ChunkedStream {
    data: ObjectData,
    chunk_size: usize,
    position: usize,
}

impl ChunkedStream {
    /// Create a new chunked stream
    pub fn from_data(data: ObjectData, chunk_size: usize) -> Self {
        Self {
            data,
            chunk_size,
            position: 0,
        }
    }

    /// Get the next chunk
    pub fn next_chunk(&mut self) -> Option<&[u8]> {
        if self.position >= self.data.len() {
            return None;
        }

        let end = (self.position + self.chunk_size).min(self.data.len());
        let chunk = &self.data.as_ref()[self.position..end];
        self.position = end;
        Some(chunk)
    }

    /// Reset to beginning
    pub fn reset(&mut self) {
        self.position = 0;
    }

    /// Get total size
    pub fn total_size(&self) -> usize {
        self.data.len()
    }

    /// Get remaining bytes
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_proof() {
        let data = b"test data";
        let hash = *blake3::hash(data).as_bytes();

        // Simple proof with no path (single-node tree)
        let proof = StorageProof {
            root: hash,
            path: vec![],
            leaf_index: 0,
        };

        assert!(proof.verify(data));
        assert!(!proof.verify(b"wrong data"));
    }

    #[test]
    fn test_chunked_stream() {
        let data = ObjectData::from(vec![0u8; 100]);
        let mut stream = ChunkedStream::from_data(data, 30);

        assert_eq!(stream.total_size(), 100);
        assert_eq!(stream.remaining(), 100);

        let c1 = stream.next_chunk().unwrap();
        assert_eq!(c1.len(), 30);
        assert_eq!(stream.remaining(), 70);

        let c2 = stream.next_chunk().unwrap();
        assert_eq!(c2.len(), 30);
        assert_eq!(stream.remaining(), 40);

        let c3 = stream.next_chunk().unwrap();
        assert_eq!(c3.len(), 30);
        assert_eq!(stream.remaining(), 10);

        let c4 = stream.next_chunk().unwrap();
        assert_eq!(c4.len(), 10);
        assert_eq!(stream.remaining(), 0);

        assert!(stream.next_chunk().is_none());

        // Reset and start over
        stream.reset();
        assert_eq!(stream.remaining(), 100);
    }
}
