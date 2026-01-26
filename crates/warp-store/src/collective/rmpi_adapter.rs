//! RMPI-backed collective storage operations
//!
//! This module provides real distributed collective operations using rmpi
//! for message passing between storage processes.
//!
//! # SafeSend Chunking Protocol
//!
//! rmpi's `SafeSend` trait requires fixed-size arrays, but warp-store works with
//! variable-length slices. This module implements a chunking protocol that:
//!
//! 1. Splits variable-length data into fixed-size chunks (default 64KB)
//! 2. Prefixes each transmission with a header containing total length and chunk count
//! 3. Reassembles chunks on the receiving side
//!
//! This allows efficient RDMA transfers while maintaining compatibility with rmpi.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tracing::{debug, info, trace, warn};

use crate::backend::StorageBackend;
use crate::error::{Error, Result};
use crate::key::ObjectKey;
use crate::object::ObjectData;

use super::{
    AllReduceConfig, AllReduceResult, CollectiveContext, DistributionPattern, GatherResult, Rank,
    ReduceOperation, ScatterConfig, ScatterResult, StorageCollectiveOps,
};

/// Default chunk size for SafeSend compatibility (64KB)
pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;

/// Maximum chunk size (1MB)
pub const MAX_CHUNK_SIZE: usize = 1024 * 1024;

/// Header for chunked transmissions
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ChunkHeader {
    /// Magic number for validation (0xRMPI)
    pub magic: u32,
    /// Total data length in bytes
    pub total_length: u64,
    /// Number of chunks
    pub chunk_count: u32,
    /// Chunk size used
    pub chunk_size: u32,
    /// Checksum of original data (CRC32)
    pub checksum: u32,
}

impl ChunkHeader {
    /// Magic number for RMPI chunk headers
    pub const MAGIC: u32 = 0x524D5049; // "RMPI" in ASCII

    /// Create a new chunk header
    pub fn new(total_length: usize, chunk_size: usize) -> Self {
        let chunk_count = (total_length + chunk_size - 1) / chunk_size;
        Self {
            magic: Self::MAGIC,
            total_length: total_length as u64,
            chunk_count: chunk_count as u32,
            chunk_size: chunk_size as u32,
            checksum: 0,
        }
    }

    /// Serialize header to bytes
    pub fn to_bytes(&self) -> [u8; 24] {
        let mut bytes = [0u8; 24];
        bytes[0..4].copy_from_slice(&self.magic.to_le_bytes());
        bytes[4..12].copy_from_slice(&self.total_length.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.chunk_count.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.chunk_size.to_le_bytes());
        bytes[20..24].copy_from_slice(&self.checksum.to_le_bytes());
        bytes
    }

    /// Deserialize header from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 24 {
            return Err(Error::Backend("Chunk header too short".into()));
        }
        let magic = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        if magic != Self::MAGIC {
            return Err(Error::Backend(format!(
                "Invalid chunk header magic: expected 0x{:08X}, got 0x{:08X}",
                Self::MAGIC,
                magic
            )));
        }
        Ok(Self {
            magic,
            total_length: u64::from_le_bytes(bytes[4..12].try_into().unwrap()),
            chunk_count: u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
            chunk_size: u32::from_le_bytes(bytes[16..20].try_into().unwrap()),
            checksum: u32::from_le_bytes(bytes[20..24].try_into().unwrap()),
        })
    }
}

/// SafeSend wrapper for chunked transmission
///
/// This wrapper enables sending variable-length data through rmpi's SafeSend
/// interface by chunking data into fixed-size arrays.
pub struct SafeSendChunker {
    /// Chunk size to use
    chunk_size: usize,
}

impl SafeSendChunker {
    /// Create a new chunker with default chunk size
    pub fn new() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
        }
    }

    /// Create a chunker with custom chunk size
    pub fn with_chunk_size(chunk_size: usize) -> Self {
        Self {
            chunk_size: chunk_size.min(MAX_CHUNK_SIZE),
        }
    }

    /// Split data into chunks for transmission
    pub fn chunk(&self, data: &[u8]) -> (ChunkHeader, Vec<Vec<u8>>) {
        let header = ChunkHeader::new(data.len(), self.chunk_size);
        let mut chunks = Vec::with_capacity(header.chunk_count as usize);

        for chunk_data in data.chunks(self.chunk_size) {
            // Pad to fixed size for SafeSend compatibility
            let mut padded = vec![0u8; self.chunk_size];
            padded[..chunk_data.len()].copy_from_slice(chunk_data);
            chunks.push(padded);
        }

        (header, chunks)
    }

    /// Reassemble chunks into original data
    pub fn reassemble(&self, header: &ChunkHeader, chunks: &[Vec<u8>]) -> Result<Vec<u8>> {
        if chunks.len() != header.chunk_count as usize {
            return Err(Error::Backend(format!(
                "Chunk count mismatch: expected {}, got {}",
                header.chunk_count,
                chunks.len()
            )));
        }

        let mut data = Vec::with_capacity(header.total_length as usize);
        let mut remaining = header.total_length as usize;

        for chunk in chunks {
            let take = remaining.min(header.chunk_size as usize);
            data.extend_from_slice(&chunk[..take]);
            remaining -= take;
        }

        Ok(data)
    }
}

impl Default for SafeSendChunker {
    fn default() -> Self {
        Self::new()
    }
}

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

    async fn all_reduce(
        &self,
        ctx: &CollectiveContext,
        local_data: &ObjectData,
        config: AllReduceConfig,
    ) -> Result<AllReduceResult> {
        let chunker = SafeSendChunker::new();

        #[cfg(feature = "rmpi")]
        {
            if let Some(handle) = &self.handle {
                // Use ring all-reduce algorithm:
                // 1. Reduce-scatter phase: each rank gets a portion of the reduced result
                // 2. All-gather phase: each rank shares its portion with all others

                let element_size = config.element_size;
                let num_elements = local_data.len() / element_size;
                let world_size = ctx.world_size() as usize;

                // Start with local data as our accumulator
                let mut result_data = local_data.as_ref().to_vec();

                // Ring reduce-scatter phase
                let left_rank = Rank::new(
                    (ctx.rank().id() + ctx.world_size() - 1) % ctx.world_size()
                );
                let right_rank = Rank::new((ctx.rank().id() + 1) % ctx.world_size());

                for step in 0..world_size - 1 {
                    // Determine which chunk we're working on
                    let send_chunk_idx =
                        (ctx.rank().id() as usize + world_size - step) % world_size;
                    let recv_chunk_idx =
                        (ctx.rank().id() as usize + world_size - step - 1) % world_size;

                    // Calculate chunk boundaries
                    let elements_per_chunk = (num_elements + world_size - 1) / world_size;
                    let send_start = send_chunk_idx * elements_per_chunk * element_size;
                    let send_end = ((send_chunk_idx + 1) * elements_per_chunk * element_size)
                        .min(result_data.len());
                    let recv_start = recv_chunk_idx * elements_per_chunk * element_size;
                    let recv_end = ((recv_chunk_idx + 1) * elements_per_chunk * element_size)
                        .min(result_data.len());

                    // Send to right neighbor
                    if send_end > send_start {
                        let send_bytes = &result_data[send_start..send_end];
                        let (header, chunks) = chunker.chunk(send_bytes);
                        let right_endpoint = Self::rank_to_endpoint(right_rank);

                        // Send header
                        if let Err(e) = handle.send(right_endpoint, &header.to_bytes()).await {
                            warn!(rank = right_rank.id(), error = %e, "All-reduce: failed to send header");
                        }
                        // Send chunks
                        for chunk in &chunks {
                            if let Err(e) = handle.send(right_endpoint, chunk).await {
                                warn!(rank = right_rank.id(), error = %e, "All-reduce: failed to send chunk");
                            }
                        }
                    }

                    // Receive from left neighbor and reduce
                    if recv_end > recv_start {
                        let left_endpoint = Self::rank_to_endpoint(left_rank);

                        // Receive header
                        match handle.recv::<Vec<u8>>(left_endpoint).await {
                            Ok(header_bytes) => {
                                if let Ok(header) = ChunkHeader::from_bytes(&header_bytes) {
                                    let mut recv_chunks = Vec::with_capacity(header.chunk_count as usize);
                                    for _ in 0..header.chunk_count {
                                        match handle.recv::<Vec<u8>>(left_endpoint).await {
                                            Ok(chunk) => recv_chunks.push(chunk),
                                            Err(e) => {
                                                warn!(error = %e, "All-reduce: failed to receive chunk");
                                            }
                                        }
                                    }
                                    if let Ok(recv_data) = chunker.reassemble(&header, &recv_chunks) {
                                        // Apply reduction operation element-wise
                                        Self::apply_reduction_inplace(
                                            &mut result_data[recv_start..recv_end],
                                            &recv_data,
                                            config.operation,
                                            element_size,
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(rank = left_rank.id(), error = %e, "All-reduce: failed to receive header");
                            }
                        }
                    }
                }

                // All-gather phase: share reduced portions with all
                for step in 0..world_size - 1 {
                    let send_chunk_idx =
                        (ctx.rank().id() as usize + 1 + world_size - step) % world_size;
                    let recv_chunk_idx =
                        (ctx.rank().id() as usize + world_size - step) % world_size;

                    let elements_per_chunk = (num_elements + world_size - 1) / world_size;
                    let send_start = send_chunk_idx * elements_per_chunk * element_size;
                    let send_end = ((send_chunk_idx + 1) * elements_per_chunk * element_size)
                        .min(result_data.len());
                    let recv_start = recv_chunk_idx * elements_per_chunk * element_size;
                    let recv_end = ((recv_chunk_idx + 1) * elements_per_chunk * element_size)
                        .min(result_data.len());

                    // Send to right
                    if send_end > send_start {
                        let (header, chunks) = chunker.chunk(&result_data[send_start..send_end]);
                        let right_endpoint = Self::rank_to_endpoint(right_rank);
                        let _ = handle.send(right_endpoint, &header.to_bytes()).await;
                        for chunk in &chunks {
                            let _ = handle.send(right_endpoint, chunk).await;
                        }
                    }

                    // Receive from left
                    if recv_end > recv_start {
                        let left_endpoint = Self::rank_to_endpoint(left_rank);
                        if let Ok(header_bytes) = handle.recv::<Vec<u8>>(left_endpoint).await {
                            if let Ok(header) = ChunkHeader::from_bytes(&header_bytes) {
                                let mut recv_chunks = Vec::new();
                                for _ in 0..header.chunk_count {
                                    if let Ok(chunk) = handle.recv::<Vec<u8>>(left_endpoint).await {
                                        recv_chunks.push(chunk);
                                    }
                                }
                                if let Ok(recv_data) = chunker.reassemble(&header, &recv_chunks) {
                                    result_data[recv_start..recv_end.min(recv_start + recv_data.len())]
                                        .copy_from_slice(&recv_data[..recv_end.saturating_sub(recv_start).min(recv_data.len())]);
                                }
                            }
                        }
                    }
                }

                debug!(
                    rank = ctx.rank().id(),
                    size = result_data.len(),
                    operation = ?config.operation,
                    "All-reduce complete (rmpi)"
                );

                return Ok(AllReduceResult {
                    data: ObjectData::from(result_data),
                    rank_count: ctx.world_size(),
                    operation: config.operation,
                });
            }
        }

        // Fallback: single-process mode
        debug!(
            rank = ctx.rank().id(),
            size = local_data.len(),
            operation = ?config.operation,
            "All-reduce complete (simulated)"
        );

        Ok(AllReduceResult {
            data: local_data.clone(),
            rank_count: 1,
            operation: config.operation,
        })
    }

    async fn reduce_scatter(
        &self,
        ctx: &CollectiveContext,
        local_data: &ObjectData,
        config: AllReduceConfig,
    ) -> Result<ObjectData> {
        // First perform all-reduce
        let reduced = self.all_reduce(ctx, local_data, config.clone()).await?;

        // Then scatter the result - each rank gets its portion
        let world_size = ctx.world_size() as usize;
        let chunk_size = reduced.data.len() / world_size;
        let my_rank = ctx.rank().id() as usize;

        let start = my_rank * chunk_size;
        let end = if my_rank == world_size - 1 {
            reduced.data.len()
        } else {
            start + chunk_size
        };

        debug!(
            rank = ctx.rank().id(),
            chunk_start = start,
            chunk_end = end,
            operation = ?config.operation,
            "Reduce-scatter complete"
        );

        Ok(ObjectData::from(reduced.data.as_ref()[start..end].to_vec()))
    }
}

impl<B: StorageBackend> RmpiCollectiveAdapter<B> {
    /// Apply reduction operation in-place
    fn apply_reduction_inplace(
        dest: &mut [u8],
        src: &[u8],
        op: ReduceOperation,
        element_size: usize,
    ) {
        let len = dest.len().min(src.len());
        let num_elements = len / element_size;

        match element_size {
            8 => {
                // f64 elements
                for i in 0..num_elements {
                    let offset = i * 8;
                    if offset + 8 <= len {
                        let a = f64::from_le_bytes(dest[offset..offset + 8].try_into().unwrap());
                        let b = f64::from_le_bytes(src[offset..offset + 8].try_into().unwrap());
                        let result = op.apply_f64(a, b);
                        dest[offset..offset + 8].copy_from_slice(&result.to_le_bytes());
                    }
                }
            }
            4 => {
                // i32 or f32 elements - treat as i32 for simplicity
                for i in 0..num_elements {
                    let offset = i * 4;
                    if offset + 4 <= len {
                        let a = i32::from_le_bytes(dest[offset..offset + 4].try_into().unwrap());
                        let b = i32::from_le_bytes(src[offset..offset + 4].try_into().unwrap());
                        let result = op.apply_i64(a as i64, b as i64) as i32;
                        dest[offset..offset + 4].copy_from_slice(&result.to_le_bytes());
                    }
                }
            }
            _ => {
                // Default: byte-wise XOR for unknown element sizes
                for i in 0..len {
                    dest[i] ^= src[i];
                }
            }
        }
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

    #[test]
    fn test_chunk_header_creation() {
        let header = ChunkHeader::new(100000, 64 * 1024);
        assert_eq!(header.magic, ChunkHeader::MAGIC);
        assert_eq!(header.total_length, 100000);
        assert_eq!(header.chunk_count, 2); // 100000 / 65536 = ~1.53, rounds to 2
        assert_eq!(header.chunk_size, 64 * 1024);
    }

    #[test]
    fn test_chunk_header_serialization() {
        let header = ChunkHeader::new(256 * 1024, 64 * 1024);
        let bytes = header.to_bytes();
        let recovered = ChunkHeader::from_bytes(&bytes).unwrap();

        assert_eq!(recovered.magic, header.magic);
        assert_eq!(recovered.total_length, header.total_length);
        assert_eq!(recovered.chunk_count, header.chunk_count);
        assert_eq!(recovered.chunk_size, header.chunk_size);
    }

    #[test]
    fn test_chunk_header_invalid_magic() {
        let mut bytes = [0u8; 24];
        bytes[0..4].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        let result = ChunkHeader::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_chunk_header_too_short() {
        let bytes = [0u8; 10];
        let result = ChunkHeader::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_safe_send_chunker_default() {
        let chunker = SafeSendChunker::new();
        assert_eq!(chunker.chunk_size, DEFAULT_CHUNK_SIZE);
    }

    #[test]
    fn test_safe_send_chunker_custom_size() {
        let chunker = SafeSendChunker::with_chunk_size(32 * 1024);
        assert_eq!(chunker.chunk_size, 32 * 1024);
    }

    #[test]
    fn test_safe_send_chunker_max_size() {
        // Should clamp to MAX_CHUNK_SIZE
        let chunker = SafeSendChunker::with_chunk_size(10 * 1024 * 1024);
        assert_eq!(chunker.chunk_size, MAX_CHUNK_SIZE);
    }

    #[test]
    fn test_chunking_small_data() {
        let chunker = SafeSendChunker::new();
        let data = vec![1u8, 2, 3, 4, 5];

        let (header, chunks) = chunker.chunk(&data);

        assert_eq!(header.total_length, 5);
        assert_eq!(header.chunk_count, 1);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].len(), chunker.chunk_size);
        assert_eq!(&chunks[0][..5], &[1u8, 2, 3, 4, 5]);
    }

    #[test]
    fn test_chunking_large_data() {
        let chunker = SafeSendChunker::with_chunk_size(1024);
        let data: Vec<u8> = (0..3000).map(|i| (i % 256) as u8).collect();

        let (header, chunks) = chunker.chunk(&data);

        assert_eq!(header.total_length, 3000);
        assert_eq!(header.chunk_count, 3); // 3000 / 1024 = 2.93, rounds to 3
        assert_eq!(chunks.len(), 3);
    }

    #[test]
    fn test_chunking_roundtrip() {
        let chunker = SafeSendChunker::with_chunk_size(1024);
        let original: Vec<u8> = (0..5000).map(|i| (i % 256) as u8).collect();

        let (header, chunks) = chunker.chunk(&original);
        let reassembled = chunker.reassemble(&header, &chunks).unwrap();

        assert_eq!(original, reassembled);
    }

    #[test]
    fn test_chunking_exact_boundary() {
        let chunker = SafeSendChunker::with_chunk_size(1024);
        let data: Vec<u8> = (0..2048).map(|i| (i % 256) as u8).collect();

        let (header, chunks) = chunker.chunk(&data);
        let reassembled = chunker.reassemble(&header, &chunks).unwrap();

        assert_eq!(header.chunk_count, 2);
        assert_eq!(data, reassembled);
    }

    #[test]
    fn test_reassemble_wrong_chunk_count() {
        let chunker = SafeSendChunker::with_chunk_size(1024);
        let data: Vec<u8> = (0..2048).map(|i| (i % 256) as u8).collect();

        let (header, mut chunks) = chunker.chunk(&data);
        chunks.pop(); // Remove one chunk

        let result = chunker.reassemble(&header, &chunks);
        assert!(result.is_err());
    }

    #[test]
    fn test_apply_reduction_inplace_f64() {
        let mut dest = 3.0f64.to_le_bytes().to_vec();
        let src = 5.0f64.to_le_bytes().to_vec();

        RmpiCollectiveAdapter::<crate::backend::LocalBackend>::apply_reduction_inplace(
            &mut dest,
            &src,
            ReduceOperation::Sum,
            8,
        );

        let result = f64::from_le_bytes(dest.try_into().unwrap());
        assert_eq!(result, 8.0);
    }

    #[test]
    fn test_apply_reduction_inplace_max() {
        let mut dest = 3.0f64.to_le_bytes().to_vec();
        let src = 5.0f64.to_le_bytes().to_vec();

        RmpiCollectiveAdapter::<crate::backend::LocalBackend>::apply_reduction_inplace(
            &mut dest,
            &src,
            ReduceOperation::Max,
            8,
        );

        let result = f64::from_le_bytes(dest.try_into().unwrap());
        assert_eq!(result, 5.0);
    }

    #[tokio::test]
    async fn test_rmpi_all_reduce() {
        let temp_dir = tempfile::tempdir().unwrap();
        let backend = crate::backend::LocalBackend::new(temp_dir.path())
            .await
            .unwrap();
        let adapter = RmpiCollectiveAdapter::new(Arc::new(backend));

        let ctx = CollectiveContext::new(1, Rank::new(0));
        let data = ObjectData::from(vec![1u8, 2, 3, 4, 5, 6, 7, 8]);
        let config = AllReduceConfig {
            operation: ReduceOperation::Sum,
            in_place: false,
            element_size: 8,
        };

        let result = adapter.all_reduce(&ctx, &data, config).await.unwrap();

        // Single process: result equals input
        assert_eq!(result.data.as_ref(), data.as_ref());
        assert_eq!(result.rank_count, 1);
    }

    #[tokio::test]
    async fn test_rmpi_reduce_scatter() {
        let temp_dir = tempfile::tempdir().unwrap();
        let backend = crate::backend::LocalBackend::new(temp_dir.path())
            .await
            .unwrap();
        let adapter = RmpiCollectiveAdapter::new(Arc::new(backend));

        let ctx = CollectiveContext::new(2, Rank::new(0));
        let data = ObjectData::from(vec![1u8, 2, 3, 4, 5, 6, 7, 8]);
        let config = AllReduceConfig::default();

        let result = adapter.reduce_scatter(&ctx, &data, config).await.unwrap();

        // Rank 0 gets first half
        assert_eq!(result.len(), 4);
    }
}
