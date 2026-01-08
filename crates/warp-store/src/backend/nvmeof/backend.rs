//! NVMe-oF Storage Backend
//!
//! Implements StorageBackend using NVMe-oF targets.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use tracing::{debug, info};

use super::client::NvmeOfClient;
use super::config::NvmeOfBackendConfig;
use super::error::NvmeOfBackendResult;
use super::mapper::{ObjectBlockMapper, ObjectLocation};
use super::metadata::MetadataStore;

use crate::Result;
use crate::backend::StorageBackend;
use crate::key::ObjectKey;
use crate::object::{
    FieldData, ListOptions, ObjectData, ObjectEntry, ObjectList, ObjectMeta, PutOptions,
    StorageClass,
};

/// NVMe-oF storage backend
///
/// Stores objects on remote NVMe-oF targets.
pub struct NvmeOfBackend {
    /// Configuration
    config: NvmeOfBackendConfig,

    /// NVMe-oF client
    client: Arc<NvmeOfClient>,

    /// Object-to-block mapper
    mapper: Arc<ObjectBlockMapper>,

    /// Metadata store
    metadata: Arc<MetadataStore>,
}

impl NvmeOfBackend {
    /// Create a new NVMe-oF backend
    pub async fn new(config: NvmeOfBackendConfig) -> NvmeOfBackendResult<Self> {
        let client = Arc::new(NvmeOfClient::new(config.clone()).await?);
        let mapper = Arc::new(ObjectBlockMapper::new(
            config.block_size,
            config.allocation_strategy,
        ));
        let metadata = Arc::new(MetadataStore::new(config.metadata_backend.clone())?);

        info!(
            "NVMe-oF backend created with {} targets",
            config.targets.len()
        );

        // Register namespaces with mapper
        // In real implementation, we'd query each target for namespace info
        for target in &config.targets {
            if let Some(nsid) = target.namespace_id {
                // Placeholder: register with assumed size
                mapper.register_namespace(&target.nqn, nsid, 1_000_000_000); // 1B blocks
            }
        }

        Ok(Self {
            config,
            client,
            mapper,
            metadata,
        })
    }

    /// Get the client
    pub fn client(&self) -> &Arc<NvmeOfClient> {
        &self.client
    }

    /// Get the mapper
    pub fn mapper(&self) -> &Arc<ObjectBlockMapper> {
        &self.mapper
    }

    /// Get the metadata store
    pub fn metadata(&self) -> &Arc<MetadataStore> {
        &self.metadata
    }

    /// Read object data from NVMe
    async fn read_object(&self, location: &ObjectLocation) -> NvmeOfBackendResult<ObjectData> {
        let mut data = Vec::with_capacity(location.size as usize);

        for extent in &location.extents {
            let extent_data = self
                .client
                .read(
                    &location.target_id,
                    location.namespace_id,
                    extent.start_lba,
                    extent.block_count,
                )
                .await?;

            // Calculate actual bytes for this extent
            let extent_size = (extent.block_count as u64 * self.config.block_size as u64)
                .min(location.size - extent.object_offset);

            data.extend_from_slice(&extent_data[..extent_size as usize]);
        }

        Ok(ObjectData::from(data))
    }

    /// Write object data to NVMe
    async fn write_object(
        &self,
        location: &ObjectLocation,
        data: &[u8],
    ) -> NvmeOfBackendResult<()> {
        for extent in &location.extents {
            let start = extent.object_offset as usize;
            let end = start + (extent.block_count as usize * self.config.block_size as usize);
            let end = end.min(data.len());

            if start >= data.len() {
                break;
            }

            // Pad to block boundary if needed
            let extent_data =
                if end - start < extent.block_count as usize * self.config.block_size as usize {
                    let mut padded =
                        vec![0u8; extent.block_count as usize * self.config.block_size as usize];
                    padded[..end - start].copy_from_slice(&data[start..end]);
                    Bytes::from(padded)
                } else {
                    Bytes::copy_from_slice(&data[start..end])
                };

            self.client
                .write(
                    &location.target_id,
                    location.namespace_id,
                    extent.start_lba,
                    extent_data,
                )
                .await?;
        }

        Ok(())
    }
}

#[async_trait]
impl StorageBackend for NvmeOfBackend {
    async fn get(&self, key: &ObjectKey) -> Result<ObjectData> {
        let entry = self
            .metadata
            .get_object(key)
            .ok_or_else(|| crate::Error::ObjectNotFound {
                bucket: key.bucket().to_string(),
                key: key.key().to_string(),
            })?;

        let data = self.read_object(&entry.location).await?;
        Ok(data)
    }

    async fn get_fields(&self, _key: &ObjectKey, _fields: &[&str]) -> Result<FieldData> {
        // NVMe-oF doesn't support lazy field loading
        // Could implement by reading specific byte ranges if we stored field offsets
        Ok(FieldData::new())
    }

    async fn put(&self, key: &ObjectKey, data: ObjectData, opts: PutOptions) -> Result<ObjectMeta> {
        // Check bucket exists
        if !self.metadata.bucket_exists(key.bucket()) {
            return Err(crate::Error::BucketNotFound(key.bucket().to_string()));
        }

        // Compute content hash
        let hash = blake3::hash(data.as_ref());
        let content_hash = *hash.as_bytes();

        // Allocate blocks
        let location = self.mapper.allocate(data.len() as u64, content_hash)?;

        // Write data to NVMe
        self.write_object(&location, data.as_ref()).await?;

        // Flush to ensure durability
        self.client
            .flush(&location.target_id, location.namespace_id)
            .await?;

        // Create metadata
        let now = chrono::Utc::now();
        let meta = ObjectMeta {
            size: data.len() as u64,
            content_hash,
            etag: format!("\"{}\"", hex::encode(&content_hash[..16])),
            content_type: opts.content_type,
            created_at: now,
            modified_at: now,
            version_id: None,
            user_metadata: opts.metadata,
            is_delete_marker: false,
            storage_class: StorageClass::Standard,
        };

        // Store metadata
        self.metadata.put_object(key, location, meta.clone())?;

        debug!(
            "Put object {}/{} (size={})",
            key.bucket(),
            key.key(),
            data.len()
        );
        Ok(meta)
    }

    async fn delete(&self, key: &ObjectKey) -> Result<()> {
        // Get and remove metadata
        let entry = self.metadata.delete_object(key)?;

        // Free blocks
        self.mapper.free(&entry.location)?;

        // Optionally TRIM the blocks
        for extent in &entry.location.extents {
            let _ = self
                .client
                .trim(
                    &entry.location.target_id,
                    entry.location.namespace_id,
                    extent.start_lba,
                    extent.block_count,
                )
                .await;
        }

        debug!("Deleted object {}/{}", key.bucket(), key.key());
        Ok(())
    }

    async fn list(&self, bucket: &str, prefix: &str, opts: ListOptions) -> Result<ObjectList> {
        if !self.metadata.bucket_exists(bucket) {
            return Err(crate::Error::BucketNotFound(bucket.to_string()));
        }

        let max_keys = opts.max_keys;
        let (entries, next_token) = self.metadata.list_objects(
            bucket,
            prefix,
            max_keys,
            opts.continuation_token.as_deref(),
        );

        let objects: Vec<_> = entries
            .into_iter()
            .map(|e| ObjectEntry {
                key: e.key.key().to_string(),
                size: e.meta.size,
                last_modified: e.meta.modified_at,
                etag: e.meta.etag,
                storage_class: StorageClass::Standard,
                version_id: e.meta.version_id,
                is_latest: true,
            })
            .collect();

        Ok(ObjectList {
            objects: objects.clone(),
            common_prefixes: Vec::new(),
            next_continuation_token: next_token,
            is_truncated: objects.len() >= max_keys,
            key_count: objects.len(),
        })
    }

    async fn head(&self, key: &ObjectKey) -> Result<ObjectMeta> {
        let entry = self
            .metadata
            .get_object(key)
            .ok_or_else(|| crate::Error::ObjectNotFound {
                bucket: key.bucket().to_string(),
                key: key.key().to_string(),
            })?;

        Ok(entry.meta)
    }

    async fn create_bucket(&self, name: &str) -> Result<()> {
        self.metadata.create_bucket(name)?;
        info!("Created bucket: {}", name);
        Ok(())
    }

    async fn delete_bucket(&self, name: &str) -> Result<()> {
        self.metadata.delete_bucket(name)?;
        info!("Deleted bucket: {}", name);
        Ok(())
    }

    async fn bucket_exists(&self, name: &str) -> Result<bool> {
        Ok(self.metadata.bucket_exists(name))
    }
}

#[cfg(test)]
mod tests {
    use super::super::config::NvmeOfTargetConfig;
    use super::*;

    async fn test_backend() -> NvmeOfBackend {
        let config = NvmeOfBackendConfig {
            targets: vec![NvmeOfTargetConfig {
                nqn: "nqn.2024-01.io.warp:test".to_string(),
                addresses: vec!["127.0.0.1:4420".parse().unwrap()],
                namespace_id: Some(1),
                ..Default::default()
            }],
            ..Default::default()
        };

        NvmeOfBackend::new(config).await.unwrap()
    }

    #[tokio::test]
    async fn test_backend_creation() {
        let backend = test_backend().await;
        assert_eq!(backend.client.targets().len(), 1);
    }

    #[tokio::test]
    async fn test_bucket_operations() {
        let backend = test_backend().await;

        // Create bucket
        backend.create_bucket("test-bucket").await.unwrap();
        assert!(backend.bucket_exists("test-bucket").await.unwrap());

        // Delete bucket
        backend.delete_bucket("test-bucket").await.unwrap();
        assert!(!backend.bucket_exists("test-bucket").await.unwrap());
    }
}
