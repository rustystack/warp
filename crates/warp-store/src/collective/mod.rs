//! Collective storage operations for HPC workloads
//!
//! This module provides collective I/O patterns that operate across multiple
//! ranks/processes, enabling efficient distributed storage access:
//!
//! - **Scatter Objects**: Distribute objects from root to all ranks
//! - **Gather Objects**: Collect objects from all ranks to root
//! - **Broadcast Object**: Send single object to all ranks
//! - **All-Gather**: Gather objects and redistribute to all
//!
//! These operations are designed to integrate with rmpi for type-safe
//! message passing when the `rmpi` feature is enabled.
//!
//! # Feature Flags
//!
//! - `rmpi`: Enable real distributed collective operations using rmpi
//!
//! # Example
//!
//! ```ignore
//! use warp_store::collective::{Rank, CollectiveContext, StorageCollectiveOps};
//!
//! // Create a collective context for 4 ranks
//! let ctx = CollectiveContext::new(4, Rank::new(0)); // This is rank 0
//!
//! // Scatter objects to all ranks
//! let keys = vec![
//!     ObjectKey::new("bucket", "shard-0")?,
//!     ObjectKey::new("bucket", "shard-1")?,
//!     ObjectKey::new("bucket", "shard-2")?,
//!     ObjectKey::new("bucket", "shard-3")?,
//! ];
//!
//! let my_data = store.scatter_objects(&ctx, &keys).await?;
//! ```

#[cfg(feature = "rmpi")]
pub mod rmpi_adapter;
#[cfg(feature = "rmpi")]
pub use rmpi_adapter::RmpiCollectiveAdapter;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::{debug, trace, warn};

use crate::backend::StorageBackend;
use crate::error::{Error, Result};
use crate::key::ObjectKey;
use crate::object::ObjectData;

/// Rank identifier for collective operations
///
/// Represents a participant in collective storage operations.
/// Maps to MPI rank concept for distributed computing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Rank(pub u32);

impl Rank {
    /// Create a new rank
    pub fn new(id: u32) -> Self {
        Self(id)
    }

    /// Get the rank ID
    pub fn id(&self) -> u32 {
        self.0
    }

    /// Root rank (rank 0)
    pub const ROOT: Rank = Rank(0);
}

impl From<u32> for Rank {
    fn from(id: u32) -> Self {
        Rank(id)
    }
}

impl From<usize> for Rank {
    fn from(id: usize) -> Self {
        Rank(id as u32)
    }
}

/// Collective operation context
///
/// Represents the communication group for collective operations,
/// similar to an MPI communicator.
#[derive(Debug, Clone)]
pub struct CollectiveContext {
    /// Total number of ranks in this context
    world_size: u32,
    /// This process's rank
    my_rank: Rank,
    /// Rank to peer ID mapping (for transport)
    rank_peers: HashMap<Rank, String>,
}

impl CollectiveContext {
    /// Create a new collective context
    pub fn new(world_size: u32, my_rank: Rank) -> Self {
        Self {
            world_size,
            my_rank,
            rank_peers: HashMap::new(),
        }
    }

    /// Create a collective context with peer mappings
    pub fn with_peers(world_size: u32, my_rank: Rank, rank_peers: HashMap<Rank, String>) -> Self {
        Self {
            world_size,
            my_rank,
            rank_peers,
        }
    }

    /// Get the world size (total number of ranks)
    pub fn world_size(&self) -> u32 {
        self.world_size
    }

    /// Get this process's rank
    pub fn rank(&self) -> Rank {
        self.my_rank
    }

    /// Check if this is the root rank
    pub fn is_root(&self) -> bool {
        self.my_rank == Rank::ROOT
    }

    /// Get all ranks in this context
    pub fn all_ranks(&self) -> impl Iterator<Item = Rank> {
        (0..self.world_size).map(Rank)
    }

    /// Get all other ranks (excluding self)
    pub fn other_ranks(&self) -> impl Iterator<Item = Rank> + '_ {
        (0..self.world_size)
            .map(Rank)
            .filter(move |r| *r != self.my_rank)
    }

    /// Get peer ID for a rank
    pub fn peer_id(&self, rank: Rank) -> Option<&str> {
        self.rank_peers.get(&rank).map(|s| s.as_str())
    }

    /// Register a peer for a rank
    pub fn register_peer(&mut self, rank: Rank, peer_id: String) {
        self.rank_peers.insert(rank, peer_id);
    }
}

/// Distribution pattern for scatter operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistributionPattern {
    /// Round-robin: objects distributed evenly across ranks
    RoundRobin,
    /// Block: contiguous chunks to each rank
    Block,
    /// Custom: use provided rank assignments
    Custom,
}

/// Scatter configuration
#[derive(Debug, Clone)]
pub struct ScatterConfig {
    /// Distribution pattern
    pub pattern: DistributionPattern,
    /// Optional: custom rank assignments (key index -> rank)
    pub rank_assignments: Option<Vec<Rank>>,
    /// Prefetch data before scatter
    pub prefetch: bool,
}

impl Default for ScatterConfig {
    fn default() -> Self {
        Self {
            pattern: DistributionPattern::RoundRobin,
            rank_assignments: None,
            prefetch: true,
        }
    }
}

/// Result of a scatter operation
#[derive(Debug)]
pub struct ScatterResult {
    /// Keys assigned to this rank
    pub keys: Vec<ObjectKey>,
    /// Data for each key (if prefetched)
    pub data: HashMap<String, ObjectData>,
}

/// Result of a gather operation
#[derive(Debug)]
pub struct GatherResult {
    /// Data gathered from all ranks, keyed by rank
    pub data: HashMap<Rank, ObjectData>,
}

/// Collective storage operations trait
///
/// Defines collective I/O patterns for distributed storage access.
/// Can be implemented by different backends to leverage
/// transport-specific optimizations (RDMA, GPUDirect, etc.).
#[async_trait]
pub trait StorageCollectiveOps: Send + Sync {
    /// Scatter objects from root to all ranks
    ///
    /// The root reads all objects and distributes them to ranks
    /// based on the distribution pattern.
    async fn scatter_objects(
        &self,
        ctx: &CollectiveContext,
        keys: &[ObjectKey],
        config: ScatterConfig,
    ) -> Result<ScatterResult>;

    /// Gather objects from all ranks to root
    ///
    /// Each rank provides an object, root collects all.
    async fn gather_objects(
        &self,
        ctx: &CollectiveContext,
        local_key: &ObjectKey,
    ) -> Result<Option<GatherResult>>;

    /// Broadcast an object from root to all ranks
    ///
    /// Root reads the object and broadcasts to all other ranks.
    async fn broadcast_object(
        &self,
        ctx: &CollectiveContext,
        key: &ObjectKey,
    ) -> Result<ObjectData>;

    /// All-gather: each rank contributes, all receive complete set
    ///
    /// Every rank provides an object key, all ranks receive all objects.
    async fn all_gather_objects(
        &self,
        ctx: &CollectiveContext,
        local_key: &ObjectKey,
    ) -> Result<HashMap<Rank, ObjectData>>;

    /// Barrier: wait for all ranks to reach this point
    async fn barrier(&self, ctx: &CollectiveContext) -> Result<()>;
}

/// Collective operations adapter for storage backends
///
/// Wraps a StorageBackend to provide collective operations.
/// Uses local simulation when running single-process.
pub struct CollectiveAdapter<B: StorageBackend> {
    backend: Arc<B>,
}

impl<B: StorageBackend> CollectiveAdapter<B> {
    /// Create a new collective adapter
    pub fn new(backend: Arc<B>) -> Self {
        Self { backend }
    }

    /// Get the underlying backend
    pub fn backend(&self) -> &B {
        &self.backend
    }
}

#[async_trait]
impl<B: StorageBackend> StorageCollectiveOps for CollectiveAdapter<B> {
    async fn scatter_objects(
        &self,
        ctx: &CollectiveContext,
        keys: &[ObjectKey],
        config: ScatterConfig,
    ) -> Result<ScatterResult> {
        // Compute rank assignments
        let assignments = match config.pattern {
            DistributionPattern::RoundRobin => keys
                .iter()
                .enumerate()
                .map(|(i, _)| Rank::from((i as u32) % ctx.world_size()))
                .collect::<Vec<_>>(),
            DistributionPattern::Block => {
                let chunk_size = keys.len().div_ceil(ctx.world_size() as usize);
                keys.iter()
                    .enumerate()
                    .map(|(i, _)| Rank::from((i / chunk_size) as u32))
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

        // Optionally prefetch data
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
        // In single-process mode, only root gets the result
        if !ctx.is_root() {
            // Non-root ranks just provide their data
            // In a real MPI context, this would send to root
            let _ = self.backend.get(local_key).await?;
            return Ok(None);
        }

        // Root collects from all (in single-process, just reads the local key)
        let mut data = HashMap::new();
        let local_data = self.backend.get(local_key).await?;
        data.insert(ctx.rank(), local_data);

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
        // All ranks read the same object
        // In a real MPI context, only root would read and broadcast
        let data = self.backend.get(key).await?;

        debug!(
            rank = ctx.rank().id(),
            key = %key,
            size = data.len(),
            "Broadcast complete"
        );

        Ok(data)
    }

    async fn all_gather_objects(
        &self,
        ctx: &CollectiveContext,
        local_key: &ObjectKey,
    ) -> Result<HashMap<Rank, ObjectData>> {
        // In single-process mode, just read local
        let mut result = HashMap::new();
        let local_data = self.backend.get(local_key).await?;
        result.insert(ctx.rank(), local_data);

        debug!(
            rank = ctx.rank().id(),
            gathered = result.len(),
            "All-gather complete"
        );

        Ok(result)
    }

    async fn barrier(&self, ctx: &CollectiveContext) -> Result<()> {
        // In single-process mode, barrier is a no-op
        trace!(rank = ctx.rank().id(), "Barrier passed");
        Ok(())
    }
}

/// Reduction operations for collective reduce
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReduceOperation {
    /// Sum all values
    Sum,
    /// Find maximum
    Max,
    /// Find minimum
    Min,
    /// Multiply all values
    Product,
    /// Bitwise AND
    BitAnd,
    /// Bitwise OR
    BitOr,
    /// Bitwise XOR
    BitXor,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rank_creation() {
        let rank = Rank::new(5);
        assert_eq!(rank.id(), 5);
        assert_eq!(rank, Rank::from(5u32));
        assert_eq!(rank, Rank::from(5usize));
    }

    #[test]
    fn test_collective_context() {
        let ctx = CollectiveContext::new(4, Rank::new(2));

        assert_eq!(ctx.world_size(), 4);
        assert_eq!(ctx.rank(), Rank::new(2));
        assert!(!ctx.is_root());

        let root_ctx = CollectiveContext::new(4, Rank::ROOT);
        assert!(root_ctx.is_root());

        let all_ranks: Vec<Rank> = ctx.all_ranks().collect();
        assert_eq!(all_ranks, vec![Rank(0), Rank(1), Rank(2), Rank(3)]);

        let other_ranks: Vec<Rank> = ctx.other_ranks().collect();
        assert_eq!(other_ranks, vec![Rank(0), Rank(1), Rank(3)]);
    }

    #[test]
    fn test_distribution_patterns() {
        let keys: Vec<usize> = (0..10).collect();
        let world_size = 4u32;

        // Round robin: 0,1,2,3,0,1,2,3,0,1
        let round_robin: Vec<u32> = keys.iter().map(|i| (*i as u32) % world_size).collect();
        assert_eq!(round_robin, vec![0, 1, 2, 3, 0, 1, 2, 3, 0, 1]);

        // Block: ceil(10/4) = 3 per chunk
        // 0,0,0,1,1,1,2,2,2,3
        let chunk_size = (keys.len() + world_size as usize - 1) / world_size as usize;
        let block: Vec<u32> = keys.iter().map(|i| (*i / chunk_size) as u32).collect();
        assert_eq!(block, vec![0, 0, 0, 1, 1, 1, 2, 2, 2, 3]);
    }

    #[tokio::test]
    async fn test_collective_adapter() {
        // Create a temporary backend
        let temp_dir = tempfile::tempdir().unwrap();
        let backend = crate::backend::LocalBackend::new(temp_dir.path())
            .await
            .unwrap();
        let adapter = CollectiveAdapter::new(Arc::new(backend));

        let ctx = CollectiveContext::new(4, Rank::new(0));

        // Test barrier (no-op in single process)
        adapter.barrier(&ctx).await.unwrap();
    }

    #[test]
    fn test_scatter_config_default() {
        let config = ScatterConfig::default();
        assert_eq!(config.pattern, DistributionPattern::RoundRobin);
        assert!(config.prefetch);
        assert!(config.rank_assignments.is_none());
    }
}
