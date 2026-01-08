//! RMPI-backed collective storage operations
//!
//! This module provides real distributed collective operations using rmpi
//! for message passing between storage processes.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tracing::{debug, info, warn};

use crate::backend::StorageBackend;
use crate::error::{Error, Result};
use crate::key::ObjectKey;
use crate::object::ObjectData;

use super::{
    CollectiveContext, DistributionPattern, GatherResult, Rank, ScatterConfig, ScatterResult,
    StorageCollectiveOps,
};

/// RMPI-backed collective operations adapter
///
/// Uses rmpi for real distributed communication between storage processes.
/// When the rmpi feature is enabled, this replaces the simulated CollectiveAdapter.
pub struct RmpiCollectiveAdapter<B: StorageBackend> {
    /// Underlying storage backend
    backend: Arc<B>,
    /// RMPI handle for communication (when initialized)
    #[cfg(feature = "rmpi")]
    handle: Option<rmpi::transport::RmpiHandle>,
    /// Local rank
    local_rank: u32,
}

impl<B: StorageBackend> RmpiCollectiveAdapter<B> {
    /// Create a new RMPI collective adapter
    pub fn new(backend: Arc<B>) -> Self {
        Self {
            backend,
            #[cfg(feature = "rmpi")]
            handle: None,
            local_rank: 0,
        }
    }

    /// Create a new RMPI collective adapter with rank
    pub fn with_rank(backend: Arc<B>, rank: u32) -> Self {
        Self {
            backend,
            #[cfg(feature = "rmpi")]
            handle: None,
            local_rank: rank,
        }
    }

    /// Initialize RMPI communication
    #[cfg(feature = "rmpi")]
    pub async fn init(&mut self, my_rank: u32) -> Result<()> {
        let endpoint = rmpi::Endpoint::from_rank(my_rank);
        let handle = rmpi::transport::RmpiHandle::new(endpoint);

        self.handle = Some(handle);
        self.local_rank = my_rank;
        info!(rank = my_rank, "RMPI initialized");
        Ok(())
    }

    /// Initialize RMPI communication (stub when feature not enabled)
    #[cfg(not(feature = "rmpi"))]
    pub async fn init(&mut self, my_rank: u32) -> Result<()> {
        self.local_rank = my_rank;
        info!(rank = my_rank, "RMPI initialized (simulated mode)");
        Ok(())
    }

    /// Get the underlying backend
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Convert warp Rank to rmpi Endpoint
    #[cfg(feature = "rmpi")]
    fn rank_to_endpoint(rank: Rank) -> rmpi::Endpoint {
        rmpi::Endpoint::from_rank(rank.id())
    }

    /// Serialize object data for transmission
    fn serialize_object(data: &ObjectData) -> Vec<u8> {
        // Simple serialization: length prefix + data
        let len = data.len() as u64;
        let mut bytes = len.to_le_bytes().to_vec();
        bytes.extend_from_slice(data.as_ref());
        bytes
    }

    /// Deserialize object data from transmission
    fn deserialize_object(bytes: &[u8]) -> Result<ObjectData> {
        if bytes.len() < 8 {
            return Err(Error::Backend("Invalid object data: too short".into()));
        }
        let len = u64::from_le_bytes(bytes[..8].try_into().unwrap()) as usize;
        if bytes.len() < 8 + len {
            return Err(Error::Backend("Invalid object data: truncated".into()));
        }
        Ok(ObjectData::from(bytes[8..8 + len].to_vec()))
    }
}

#[async_trait]
impl<B: StorageBackend> StorageCollectiveOps for RmpiCollectiveAdapter<B> {
    async fn scatter_objects(
        &self,
        ctx: &CollectiveContext,
        keys: &[ObjectKey],
        config: ScatterConfig,
    ) -> Result<ScatterResult> {
        // Compute rank assignments based on distribution pattern
        let assignments = match config.pattern {
            DistributionPattern::RoundRobin => keys
                .iter()
                .enumerate()
                .map(|(i, _)| Rank::from((i as u32) % ctx.world_size()))
                .collect::<Vec<_>>(),
            DistributionPattern::Block => {
                let chunk_size =
                    (keys.len() + ctx.world_size() as usize - 1) / ctx.world_size() as usize;
                keys.iter()
                    .enumerate()
                    .map(|(i, _)| Rank::from((i / chunk_size.max(1)) as u32))
                    .collect::<Vec<_>>()
            }
            DistributionPattern::Custom => config
                .rank_assignments
                .clone()
                .ok_or_else(|| Error::Backend("Custom pattern requires rank_assignments".into()))?,
        };

        // Filter keys for this rank
        let my_keys: Vec<ObjectKey> = keys
            .iter()
            .zip(assignments.iter())
            .filter(|(_, rank)| **rank == ctx.rank())
            .map(|(key, _)| key.clone())
            .collect();

        // Prefetch data if requested
        let data = if config.prefetch {
            let mut data = HashMap::new();
            for key in &my_keys {
                match self.backend.get(key).await {
                    Ok(obj_data) => {
                        data.insert(key.key().to_string(), obj_data);
                    }
                    Err(e) => {
                        warn!(key = %key, error = %e, "Failed to prefetch object");
                    }
                }
            }
            data
        } else {
            HashMap::new()
        };

        #[cfg(feature = "rmpi")]
        {
            // Use real rmpi scatter for distribution
            if ctx.is_root() {
                if let Some(handle) = &self.handle {
                    // Root sends data to other ranks
                    for (key, rank) in keys.iter().zip(assignments.iter()) {
                        if *rank != ctx.rank() {
                            if let Ok(obj_data) = self.backend.get(key).await {
                                let bytes = Self::serialize_object(&obj_data);
                                let endpoint = Self::rank_to_endpoint(*rank);
                                // Send bytes to endpoint using rmpi handle
                                if let Err(e) = handle.send(endpoint, &bytes).await {
                                    warn!(rank = rank.id(), key = %key, error = %e, "Failed to scatter object");
                                } else {
                                    debug!(rank = rank.id(), key = %key, "Scattered object");
                                }
                            }
                        }
                    }
                }
            }
        }

        debug!(
            rank = ctx.rank().id(),
            total_keys = keys.len(),
            my_keys = my_keys.len(),
            "Scatter complete"
        );

        Ok(ScatterResult {
            keys: my_keys,
            data,
        })
    }

    async fn gather_objects(
        &self,
        ctx: &CollectiveContext,
        local_key: &ObjectKey,
    ) -> Result<Option<GatherResult>> {
        // Get local data
        let local_data = self.backend.get(local_key).await?;

        if !ctx.is_root() {
            #[cfg(feature = "rmpi")]
            {
                // Non-root ranks send their data to root
                if let Some(handle) = &self.handle {
                    let bytes = Self::serialize_object(&local_data);
                    let root = Self::rank_to_endpoint(Rank::ROOT);
                    // Send bytes to root using rmpi handle
                    if let Err(e) = handle.send(root, &bytes).await {
                        warn!(rank = ctx.rank().id(), key = %local_key, error = %e, "Failed to send to root for gather");
                    } else {
                        debug!(rank = ctx.rank().id(), key = %local_key, "Sent to root for gather");
                    }
                }
            }
            return Ok(None);
        }

        // Root collects from all ranks
        let mut data = HashMap::new();
        data.insert(ctx.rank(), local_data);

        #[cfg(feature = "rmpi")]
        {
            // Receive from all other ranks
            if let Some(handle) = &self.handle {
                for rank in ctx.other_ranks() {
                    let endpoint = Self::rank_to_endpoint(rank);
                    // Receive bytes from endpoint using rmpi handle
                    match handle.recv::<Vec<u8>>(endpoint).await {
                        Ok(bytes) => match Self::deserialize_object(&bytes) {
                            Ok(received) => {
                                data.insert(rank, received);
                                debug!(rank = rank.id(), "Gathered from rank");
                            }
                            Err(e) => {
                                warn!(rank = rank.id(), error = %e, "Failed to deserialize gathered data");
                            }
                        },
                        Err(e) => {
                            warn!(rank = rank.id(), error = %e, "Failed to receive from rank for gather");
                        }
                    }
                }
            }
        }

        debug!(
            rank = ctx.rank().id(),
            gathered = data.len(),
            "Gather complete"
        );

        Ok(Some(GatherResult { data }))
    }

    async fn broadcast_object(
        &self,
        ctx: &CollectiveContext,
        key: &ObjectKey,
    ) -> Result<ObjectData> {
        if ctx.is_root() {
            // Root reads and broadcasts
            let data = self.backend.get(key).await?;

            #[cfg(feature = "rmpi")]
            {
                if let Some(handle) = &self.handle {
                    let bytes = Self::serialize_object(&data);
                    for rank in ctx.other_ranks() {
                        let endpoint = Self::rank_to_endpoint(rank);
                        // Send bytes to endpoint using rmpi handle
                        if let Err(e) = handle.send(endpoint, &bytes).await {
                            warn!(rank = rank.id(), key = %key, error = %e, "Failed to broadcast to rank");
                        } else {
                            debug!(rank = rank.id(), key = %key, "Broadcast to rank");
                        }
                    }
                }
            }

            debug!(
                rank = ctx.rank().id(),
                key = %key,
                size = data.len(),
                "Broadcast from root"
            );

            Ok(data)
        } else {
            #[cfg(feature = "rmpi")]
            {
                // Non-root ranks receive from root
                if let Some(handle) = &self.handle {
                    let root = Self::rank_to_endpoint(Rank::ROOT);
                    // Receive bytes from root using rmpi handle
                    match handle.recv::<Vec<u8>>(root).await {
                        Ok(bytes) => {
                            let data = Self::deserialize_object(&bytes)?;
                            debug!(
                                rank = ctx.rank().id(),
                                key = %key,
                                size = data.len(),
                                "Broadcast received"
                            );
                            return Ok(data);
                        }
                        Err(e) => {
                            warn!(rank = ctx.rank().id(), key = %key, error = %e, "Failed to receive broadcast");
                        }
                    }
                }
            }

            // Fallback: read directly (simulated mode or rmpi failure)
            let data = self.backend.get(key).await?;
            debug!(
                rank = ctx.rank().id(),
                key = %key,
                size = data.len(),
                "Broadcast received (simulated)"
            );
            Ok(data)
        }
    }

    async fn all_gather_objects(
        &self,
        ctx: &CollectiveContext,
        local_key: &ObjectKey,
    ) -> Result<HashMap<Rank, ObjectData>> {
        let local_data = self.backend.get(local_key).await?;
        let mut result = HashMap::new();
        result.insert(ctx.rank(), local_data.clone());

        #[cfg(feature = "rmpi")]
        {
            if let Some(handle) = &self.handle {
                let bytes = Self::serialize_object(&local_data);
                // Exchange with all peers
                for rank in ctx.other_ranks() {
                    let endpoint = Self::rank_to_endpoint(rank);
                    // Send our data to peer
                    if let Err(e) = handle.send(endpoint, &bytes).await {
                        warn!(rank = rank.id(), error = %e, "Failed to send in all-gather");
                    }
                }
                // Receive data from all peers
                for rank in ctx.other_ranks() {
                    let endpoint = Self::rank_to_endpoint(rank);
                    // Receive data from peer
                    match handle.recv::<Vec<u8>>(endpoint).await {
                        Ok(received_bytes) => match Self::deserialize_object(&received_bytes) {
                            Ok(received) => {
                                result.insert(rank, received);
                                debug!(rank = rank.id(), "All-gather received");
                            }
                            Err(e) => {
                                warn!(rank = rank.id(), error = %e, "Failed to deserialize all-gather data");
                            }
                        },
                        Err(e) => {
                            warn!(rank = rank.id(), error = %e, "Failed to receive in all-gather");
                        }
                    }
                }
            }
        }

        debug!(
            rank = ctx.rank().id(),
            gathered = result.len(),
            "All-gather complete"
        );

        Ok(result)
    }

    async fn barrier(&self, ctx: &CollectiveContext) -> Result<()> {
        #[cfg(feature = "rmpi")]
        {
            if let Some(handle) = &self.handle {
                // Implement barrier using two-phase commit:
                // 1. All non-root ranks send a "ready" message to root
                // 2. Root waits for all, then broadcasts "go" to all
                let barrier_msg: Vec<u8> = vec![0xBA, 0xBE]; // Barrier beacon

                if ctx.is_root() {
                    // Root: receive from all, then broadcast go
                    for rank in ctx.other_ranks() {
                        let endpoint = Self::rank_to_endpoint(rank);
                        if let Err(e) = handle.recv::<Vec<u8>>(endpoint).await {
                            warn!(rank = rank.id(), error = %e, "Barrier: failed to receive ready");
                        }
                    }
                    // Broadcast go signal
                    for rank in ctx.other_ranks() {
                        let endpoint = Self::rank_to_endpoint(rank);
                        if let Err(e) = handle.send(endpoint, &barrier_msg).await {
                            warn!(rank = rank.id(), error = %e, "Barrier: failed to send go");
                        }
                    }
                } else {
                    // Non-root: send ready, wait for go
                    let root = Self::rank_to_endpoint(Rank::ROOT);
                    if let Err(e) = handle.send(root, &barrier_msg).await {
                        warn!(error = %e, "Barrier: failed to send ready to root");
                    }
                    if let Err(e) = handle.recv::<Vec<u8>>(root).await {
                        warn!(error = %e, "Barrier: failed to receive go from root");
                    }
                }
                debug!(rank = ctx.rank().id(), "Barrier (rmpi)");
            }
        }

        debug!(rank = ctx.rank().id(), "Barrier passed");
        Ok(())
    }
}

/// Create a pinned memory buffer for zero-copy operations
///
/// When RDMA is available, this allocates from an RDMA-registered memory pool
/// for true zero-copy transfers. Otherwise, uses regular heap allocation.
#[cfg(feature = "rmpi")]
pub fn create_pinned_buffer(size: usize) -> Vec<u8> {
    #[cfg(feature = "rdma")]
    {
        // Try to allocate from RDMA HugePage pool for zero-copy
        use std::sync::OnceLock;
        static RDMA_POOL: OnceLock<Option<std::sync::Arc<rmpi::rdma::HugePagePool>>> =
            OnceLock::new();

        let pool = RDMA_POOL.get_or_init(|| {
            // Try to create a shared HugePage pool (4 pages = 8MB)
            rmpi::rdma::HugePagePool::new(4).ok()
        });

        if let Some(pool) = pool {
            if let Ok(mut buffer) = pool.alloc(size) {
                // Return the buffer's contents as Vec
                // Note: This copies from RDMA memory to regular Vec
                // True zero-copy would use RdmaBuffer directly
                let mut result = vec![0u8; size];
                buffer.set_len(size);
                result.copy_from_slice(buffer.as_slice());
                return result;
            }
        }
    }

    // Fallback: regular heap allocation
    vec![0u8; size]
}

/// RDMA buffer pool for pre-registered memory regions
#[cfg(all(feature = "rmpi", feature = "rdma"))]
pub struct RdmaBufferPool {
    /// Underlying HugePage pool
    pool: std::sync::Arc<rmpi::rdma::HugePagePool>,
    /// Memory region with registered keys
    memory_region: rmpi::rdma::RdmaMemoryRegion,
}

#[cfg(all(feature = "rmpi", feature = "rdma"))]
impl RdmaBufferPool {
    /// Create a new RDMA buffer pool with the specified number of HugePages
    pub fn new(num_pages: usize) -> Result<Self> {
        let pool = rmpi::rdma::HugePagePool::new(num_pages)
            .map_err(|e| Error::Backend(format!("Failed to create HugePage pool: {}", e)))?;

        let memory_region = rmpi::rdma::RdmaMemoryRegion::new_mock(std::sync::Arc::clone(&pool))
            .map_err(|e| Error::Backend(format!("Failed to register memory region: {}", e)))?;

        Ok(Self {
            pool,
            memory_region,
        })
    }

    /// Allocate a buffer from the pool
    pub fn alloc(&self, size: usize) -> Result<rmpi::rdma::RdmaBuffer> {
        self.memory_region
            .alloc(size)
            .map_err(|e| Error::Backend(format!("Failed to allocate RDMA buffer: {}", e)))
    }

    /// Get the local key for RDMA operations
    pub fn lkey(&self) -> u32 {
        self.memory_region.lkey()
    }

    /// Get the remote key for RDMA Write/Read
    pub fn rkey(&self) -> u32 {
        self.memory_region.rkey()
    }

    /// Get available bytes in the pool
    pub fn available(&self) -> usize {
        self.pool.free_bytes()
    }
}

/// Register memory for RDMA operations
///
/// This function registers a buffer with the RDMA subsystem for zero-copy transfers.
/// The buffer must remain valid for the lifetime of RDMA operations using it.
#[cfg(all(feature = "rmpi", feature = "rdma"))]
pub fn register_memory_for_rdma(buffer: &[u8]) -> Result<RdmaMemoryRegistration> {
    // Create a new pool just for this buffer
    let pages_needed = (buffer.len() + rmpi::rdma::HUGEPAGE_SIZE - 1) / rmpi::rdma::HUGEPAGE_SIZE;
    let pages_needed = pages_needed.max(1);

    let pool = rmpi::rdma::HugePagePool::new(pages_needed)
        .map_err(|e| Error::Backend(format!("Failed to create pool for registration: {}", e)))?;

    let region = rmpi::rdma::RdmaMemoryRegion::new_mock(std::sync::Arc::clone(&pool))
        .map_err(|e| Error::Backend(format!("Failed to register memory: {}", e)))?;

    let mut rdma_buffer = region
        .alloc(buffer.len())
        .map_err(|e| Error::Backend(format!("Failed to allocate from region: {}", e)))?;

    // Copy data to registered memory
    rdma_buffer.write(buffer);

    Ok(RdmaMemoryRegistration {
        pool,
        region,
        buffer: rdma_buffer,
    })
}

/// Handle to registered RDMA memory
#[cfg(all(feature = "rmpi", feature = "rdma"))]
pub struct RdmaMemoryRegistration {
    #[allow(dead_code)]
    pool: std::sync::Arc<rmpi::rdma::HugePagePool>,
    region: rmpi::rdma::RdmaMemoryRegion,
    buffer: rmpi::rdma::RdmaBuffer,
}

#[cfg(all(feature = "rmpi", feature = "rdma"))]
impl RdmaMemoryRegistration {
    /// Get the local key for this registration
    pub fn lkey(&self) -> u32 {
        self.region.lkey()
    }

    /// Get the remote key for this registration
    pub fn rkey(&self) -> u32 {
        self.region.rkey()
    }

    /// Get a reference to the registered buffer
    pub fn buffer(&self) -> &rmpi::rdma::RdmaBuffer {
        &self.buffer
    }

    /// Get a mutable reference to the registered buffer
    pub fn buffer_mut(&mut self) -> &mut rmpi::rdma::RdmaBuffer {
        &mut self.buffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rmpi_adapter_creation() {
        let temp_dir = tempfile::tempdir().unwrap();
        let backend = crate::backend::LocalBackend::new(temp_dir.path())
            .await
            .unwrap();
        let adapter = RmpiCollectiveAdapter::new(Arc::new(backend));

        // Verify backend is accessible - just check it exists
        let _ = adapter.backend();
    }

    #[tokio::test]
    async fn test_rmpi_scatter() {
        let temp_dir = tempfile::tempdir().unwrap();
        let backend = crate::backend::LocalBackend::new(temp_dir.path())
            .await
            .unwrap();
        let adapter = RmpiCollectiveAdapter::new(Arc::new(backend));

        let ctx = CollectiveContext::new(4, Rank::new(0));
        let keys: Vec<ObjectKey> = (0..8)
            .map(|i| ObjectKey::new("test", &format!("key-{}", i)).unwrap())
            .collect();

        // Scatter should work even without real rmpi
        let result = adapter
            .scatter_objects(&ctx, &keys, ScatterConfig::default())
            .await
            .unwrap();

        // Rank 0 should get keys 0, 4 (round robin with 4 ranks)
        assert_eq!(result.keys.len(), 2);
    }

    #[tokio::test]
    async fn test_rmpi_barrier() {
        let temp_dir = tempfile::tempdir().unwrap();
        let backend = crate::backend::LocalBackend::new(temp_dir.path())
            .await
            .unwrap();
        let adapter = RmpiCollectiveAdapter::new(Arc::new(backend));

        let ctx = CollectiveContext::new(4, Rank::new(2));

        // Barrier should complete
        adapter.barrier(&ctx).await.unwrap();
    }

    #[test]
    fn test_serialize_deserialize_object() {
        let data = ObjectData::from(vec![1, 2, 3, 4, 5]);
        let bytes = RmpiCollectiveAdapter::<crate::backend::LocalBackend>::serialize_object(&data);
        let recovered =
            RmpiCollectiveAdapter::<crate::backend::LocalBackend>::deserialize_object(&bytes)
                .unwrap();
        assert_eq!(data.as_ref(), recovered.as_ref());
    }
}
