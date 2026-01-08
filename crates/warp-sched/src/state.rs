//! GPU state buffer management for chunk scheduling
//!
//! Provides CPU and GPU-accelerated state management for millions of chunks
//! and thousands of edges with efficient indexing and batch updates.

use crate::{ChunkId, ChunkState, ChunkStatus, EdgeIdx, EdgeStateGpu, Result, SchedError};
use dashmap::DashMap;
use std::time::SystemTime;

/// Point-in-time snapshot of scheduler state
#[derive(Debug, Clone)]
pub struct StateSnapshot {
    /// All chunk states
    pub chunks: Vec<ChunkState>,
    /// All edge states
    pub edges: Vec<EdgeStateGpu>,
    /// Snapshot timestamp
    pub timestamp: SystemTime,
    /// Number of chunks
    pub chunk_count: usize,
    /// Number of edges
    pub edge_count: usize,
}

/// Update for a single chunk state
#[derive(Debug, Clone)]
pub struct ChunkStateUpdate {
    /// Chunk ID to update
    pub chunk_id: ChunkId,
    /// New status (if changing)
    pub status: Option<ChunkStatus>,
    /// New replica count (if changing)
    pub replica_count: Option<u8>,
    /// New priority (if changing)
    pub priority: Option<u8>,
}

/// CPU-only state buffer management
///
/// Uses vectors and `DashMap` for concurrent access without GPU overhead.
/// Suitable for smaller deployments or as a fallback implementation.
pub struct CpuStateBuffers {
    /// Chunk states (indexed by internal ID)
    chunks: Vec<Option<ChunkState>>,
    /// Edge states (indexed by `EdgeIdx`)
    edges: Vec<Option<EdgeStateGpu>>,
    /// Replica map: `chunk_id` -> edges that have this chunk
    replica_map: Vec<Vec<EdgeIdx>>,
    /// Hash lookup: Blake3 hash -> internal chunk id
    chunk_index: DashMap<[u8; 32], u32>,
    /// Edge lookup: edge GPU index -> our index
    edge_index: DashMap<u32, u32>,
    /// Maximum chunks
    max_chunks: usize,
    /// Maximum edges
    max_edges: usize,
    /// Next available chunk slot
    next_chunk_id: u32,
    /// Next available edge slot
    next_edge_idx: u32,
}

impl CpuStateBuffers {
    /// Create new CPU state buffers
    ///
    /// # Arguments
    /// * `max_chunks` - Maximum number of chunks to track
    /// * `max_edges` - Maximum number of edges to track
    #[must_use]
    pub fn new(max_chunks: usize, max_edges: usize) -> Self {
        Self {
            chunks: vec![None; max_chunks],
            edges: vec![None; max_edges],
            replica_map: vec![Vec::new(); max_chunks],
            chunk_index: DashMap::new(),
            edge_index: DashMap::new(),
            max_chunks,
            max_edges,
            next_chunk_id: 0,
            next_edge_idx: 0,
        }
    }

    /// Add a new chunk to state
    ///
    /// # Arguments
    /// * `state` - Chunk state to add
    ///
    /// # Returns
    /// Internal chunk ID for future lookups
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Chunk with the same hash already exists
    /// - Chunk buffer is full
    pub fn add_chunk(&mut self, state: ChunkState) -> Result<u32> {
        let hash = state.hash;

        // Check if already exists
        if self.chunk_index.contains_key(&hash) {
            return Err(SchedError::InvalidState("chunk already exists".to_string()));
        }

        // Find next available slot
        let id = self.next_chunk_id;
        if id as usize >= self.max_chunks {
            return Err(SchedError::BufferOverflow("chunk buffer full".to_string()));
        }

        self.chunks[id as usize] = Some(state);
        self.chunk_index.insert(hash, id);
        self.next_chunk_id += 1;

        Ok(id)
    }

    /// Get chunk state by internal ID
    #[must_use]
    pub fn get_chunk(&self, id: u32) -> Option<&ChunkState> {
        self.chunks.get(id as usize)?.as_ref()
    }

    /// Update chunk state
    ///
    /// # Errors
    ///
    /// Returns an error if chunk with the given ID is not found
    pub fn update_chunk(&mut self, id: u32, update: ChunkStateUpdate) -> Result<()> {
        let chunk = self
            .chunks
            .get_mut(id as usize)
            .and_then(|c| c.as_mut())
            .ok_or_else(|| SchedError::InvalidState("chunk not found".to_string()))?;

        if let Some(status) = update.status {
            chunk.status = status;
        }
        if let Some(replica_count) = update.replica_count {
            chunk.replica_count = replica_count;
        }
        if let Some(priority) = update.priority {
            chunk.priority = priority;
        }

        chunk.update_timestamp();
        Ok(())
    }

    /// Remove chunk from state
    pub fn remove_chunk(&mut self, id: u32) -> Option<ChunkState> {
        let chunk = self.chunks.get_mut(id as usize)?.take()?;
        self.chunk_index.remove(&chunk.hash);
        self.replica_map[id as usize].clear();
        Some(chunk)
    }

    /// Add edge to state
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Edge with the same ID already exists
    /// - Edge buffer is full
    pub fn add_edge(&mut self, edge_id: u32, state: EdgeStateGpu) -> Result<EdgeIdx> {
        // Check if already exists
        if self.edge_index.contains_key(&edge_id) {
            return Err(SchedError::InvalidState("edge already exists".to_string()));
        }

        let idx = self.next_edge_idx;
        if idx as usize >= self.max_edges {
            return Err(SchedError::BufferOverflow("edge buffer full".to_string()));
        }

        self.edges[idx as usize] = Some(state);
        self.edge_index.insert(edge_id, idx);
        self.next_edge_idx += 1;

        Ok(EdgeIdx(idx))
    }

    /// Get edge state by index
    #[must_use]
    pub fn get_edge(&self, idx: EdgeIdx) -> Option<&EdgeStateGpu> {
        self.edges.get(idx.0 as usize)?.as_ref()
    }

    /// Update edge state
    ///
    /// # Errors
    ///
    /// Returns an error if edge with the given index is not found
    pub fn update_edge(&mut self, idx: EdgeIdx, state: EdgeStateGpu) -> Result<()> {
        let edge = self
            .edges
            .get_mut(idx.0 as usize)
            .and_then(|e| e.as_mut())
            .ok_or_else(|| SchedError::InvalidState("edge not found".to_string()))?;

        *edge = state;
        Ok(())
    }

    /// Remove edge from state
    pub fn remove_edge(&mut self, idx: EdgeIdx) -> Option<EdgeStateGpu> {
        let edge = self.edges.get_mut(idx.0 as usize)?.take()?;
        self.edge_index.remove(&edge.edge_idx.0);
        Some(edge)
    }

    /// Add replica location for a chunk
    pub fn add_replica(&mut self, chunk_id: u32, edge_idx: EdgeIdx) {
        if let Some(replicas) = self.replica_map.get_mut(chunk_id as usize) {
            if !replicas.contains(&edge_idx) {
                replicas.push(edge_idx);
            }
        }
    }

    /// Remove replica location for a chunk
    pub fn remove_replica(&mut self, chunk_id: u32, edge_idx: EdgeIdx) {
        if let Some(replicas) = self.replica_map.get_mut(chunk_id as usize) {
            replicas.retain(|&idx| idx != edge_idx);
        }
    }

    /// Get all replica locations for a chunk
    #[must_use]
    pub fn get_replicas(&self, chunk_id: u32) -> &[EdgeIdx] {
        self.replica_map
            .get(chunk_id as usize)
            .map_or(&[], std::vec::Vec::as_slice)
    }

    /// Batch update chunks
    ///
    /// # Errors
    ///
    /// Returns an error if any chunk in the batch is not found
    pub fn update_chunks_batch(&mut self, updates: &[ChunkStateUpdate]) -> Result<()> {
        for update in updates {
            // Find internal ID from ChunkId
            let id = update.chunk_id.0 as u32;

            if id as usize >= self.chunks.len() || self.chunks[id as usize].is_none() {
                return Err(SchedError::InvalidState("chunk not found".to_string()));
            }

            self.update_chunk(id, update.clone())?;
        }
        Ok(())
    }

    /// Batch update edges
    ///
    /// # Errors
    ///
    /// Returns an error if any edge in the batch is not found
    pub fn update_edges_batch(&mut self, edges: &[(u32, EdgeStateGpu)]) -> Result<()> {
        for (edge_id, state) in edges {
            let idx = self
                .edge_index
                .get(edge_id)
                .map(|v| EdgeIdx(*v))
                .ok_or_else(|| SchedError::InvalidState("edge not found".to_string()))?;

            self.update_edge(idx, *state)?;
        }
        Ok(())
    }

    /// Get number of chunks
    #[must_use]
    pub fn chunk_count(&self) -> usize {
        self.chunks.iter().filter(|c| c.is_some()).count()
    }

    /// Get number of edges
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edges.iter().filter(|e| e.is_some()).count()
    }

    /// Create snapshot of current state
    #[must_use]
    pub fn snapshot(&self) -> StateSnapshot {
        StateSnapshot {
            chunks: self.chunks.iter().filter_map(|c| *c).collect(),
            edges: self.edges.iter().filter_map(|e| *e).collect(),
            timestamp: SystemTime::now(),
            chunk_count: self.chunk_count(),
            edge_count: self.edge_count(),
        }
    }

    /// Find chunk by hash
    #[must_use]
    pub fn find_chunk(&self, hash: &[u8; 32]) -> Option<u32> {
        self.chunk_index.get(hash).map(|v| *v)
    }

    /// Find edge by ID
    #[must_use]
    pub fn find_edge(&self, edge_id: u32) -> Option<EdgeIdx> {
        self.edge_index.get(&edge_id).map(|v| EdgeIdx(*v))
    }
}

/// GPU-accelerated state buffers
///
/// Currently wraps `CpuStateBuffers` but designed for future GPU implementation
/// using cudarc for device memory management and kernel launches.
pub struct GpuStateBuffers {
    /// CPU fallback implementation
    inner: CpuStateBuffers,
    // Future GPU fields:
    // device: Option<Arc<CudaDevice>>,
    // chunk_buffer: Option<CudaSlice<ChunkState>>,
    // edge_buffer: Option<CudaSlice<EdgeStateGpu>>,
}

impl GpuStateBuffers {
    /// Create new GPU state buffers (currently uses CPU fallback)
    #[must_use]
    pub fn new(max_chunks: usize, max_edges: usize) -> Self {
        Self {
            inner: CpuStateBuffers::new(max_chunks, max_edges),
        }
    }

    /// Add chunk (delegates to CPU implementation)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Chunk with the same hash already exists
    /// - Chunk buffer is full
    pub fn add_chunk(&mut self, state: ChunkState) -> Result<u32> {
        self.inner.add_chunk(state)
    }

    /// Get chunk (delegates to CPU implementation)
    #[must_use]
    pub fn get_chunk(&self, id: u32) -> Option<&ChunkState> {
        self.inner.get_chunk(id)
    }

    /// Update chunk (delegates to CPU implementation)
    ///
    /// # Errors
    ///
    /// Returns an error if chunk with the given ID is not found
    pub fn update_chunk(&mut self, id: u32, update: ChunkStateUpdate) -> Result<()> {
        self.inner.update_chunk(id, update)
    }

    /// Remove chunk (delegates to CPU implementation)
    pub fn remove_chunk(&mut self, id: u32) -> Option<ChunkState> {
        self.inner.remove_chunk(id)
    }

    /// Add edge (delegates to CPU implementation)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Edge with the same ID already exists
    /// - Edge buffer is full
    pub fn add_edge(&mut self, edge_id: u32, state: EdgeStateGpu) -> Result<EdgeIdx> {
        self.inner.add_edge(edge_id, state)
    }

    /// Get edge (delegates to CPU implementation)
    #[must_use]
    pub fn get_edge(&self, idx: EdgeIdx) -> Option<&EdgeStateGpu> {
        self.inner.get_edge(idx)
    }

    /// Update edge (delegates to CPU implementation)
    ///
    /// # Errors
    ///
    /// Returns an error if edge with the given index is not found
    pub fn update_edge(&mut self, idx: EdgeIdx, state: EdgeStateGpu) -> Result<()> {
        self.inner.update_edge(idx, state)
    }

    /// Remove edge (delegates to CPU implementation)
    pub fn remove_edge(&mut self, idx: EdgeIdx) -> Option<EdgeStateGpu> {
        self.inner.remove_edge(idx)
    }

    /// Add replica (delegates to CPU implementation)
    pub fn add_replica(&mut self, chunk_id: u32, edge_idx: EdgeIdx) {
        self.inner.add_replica(chunk_id, edge_idx);
    }

    /// Remove replica (delegates to CPU implementation)
    pub fn remove_replica(&mut self, chunk_id: u32, edge_idx: EdgeIdx) {
        self.inner.remove_replica(chunk_id, edge_idx);
    }

    /// Get replicas (delegates to CPU implementation)
    #[must_use]
    pub fn get_replicas(&self, chunk_id: u32) -> &[EdgeIdx] {
        self.inner.get_replicas(chunk_id)
    }

    /// Batch update chunks (delegates to CPU implementation)
    ///
    /// # Errors
    ///
    /// Returns an error if any chunk in the batch is not found
    pub fn update_chunks_batch(&mut self, updates: &[ChunkStateUpdate]) -> Result<()> {
        self.inner.update_chunks_batch(updates)
    }

    /// Batch update edges (delegates to CPU implementation)
    ///
    /// # Errors
    ///
    /// Returns an error if any edge in the batch is not found
    pub fn update_edges_batch(&mut self, edges: &[(u32, EdgeStateGpu)]) -> Result<()> {
        self.inner.update_edges_batch(edges)
    }

    /// Get chunk count (delegates to CPU implementation)
    #[must_use]
    pub fn chunk_count(&self) -> usize {
        self.inner.chunk_count()
    }

    /// Get edge count (delegates to CPU implementation)
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.inner.edge_count()
    }

    /// Create snapshot (delegates to CPU implementation)
    #[must_use]
    pub fn snapshot(&self) -> StateSnapshot {
        self.inner.snapshot()
    }

    /// Find chunk by hash (delegates to CPU implementation)
    #[must_use]
    pub fn find_chunk(&self, hash: &[u8; 32]) -> Option<u32> {
        self.inner.find_chunk(hash)
    }

    /// Find edge by ID (delegates to CPU implementation)
    #[must_use]
    pub fn find_edge(&self, edge_id: u32) -> Option<EdgeIdx> {
        self.inner.find_edge(edge_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_chunk_state(id: u8, size: u32, priority: u8) -> ChunkState {
        ChunkState::new([id; 32], size, priority, 3)
    }

    fn make_edge_state(idx: u32, bandwidth: u64, health: f32) -> EdgeStateGpu {
        EdgeStateGpu::new(EdgeIdx(idx), bandwidth, 10_000, health, 10)
    }

    #[test]
    fn test_cpu_buffers_creation() {
        let buffers = CpuStateBuffers::new(1000, 100);
        assert_eq!(buffers.chunk_count(), 0);
        assert_eq!(buffers.edge_count(), 0);
        assert_eq!(buffers.max_chunks, 1000);
        assert_eq!(buffers.max_edges, 100);
    }

    #[test]
    fn test_add_and_get_chunk() {
        let mut buffers = CpuStateBuffers::new(10, 10);
        let chunk = make_chunk_state(1, 1024, 128);

        let id = buffers.add_chunk(chunk).unwrap();
        assert_eq!(id, 0);
        assert_eq!(buffers.chunk_count(), 1);

        let retrieved = buffers.get_chunk(id).unwrap();
        assert_eq!(retrieved.hash, chunk.hash);
        assert_eq!(retrieved.status, ChunkStatus::Idle);
    }

    #[test]
    fn test_add_duplicate_chunk_fails() {
        let mut buffers = CpuStateBuffers::new(10, 10);
        let chunk = make_chunk_state(1, 1024, 128);

        buffers.add_chunk(chunk).unwrap();
        let result = buffers.add_chunk(chunk);
        assert!(result.is_err());
    }

    #[test]
    fn test_update_chunk() {
        let mut buffers = CpuStateBuffers::new(10, 10);
        let chunk = make_chunk_state(1, 1024, 128);
        let id = buffers.add_chunk(chunk).unwrap();

        let update = ChunkStateUpdate {
            chunk_id: ChunkId(id as u64),
            status: Some(ChunkStatus::InTransfer),
            replica_count: Some(2),
            priority: Some(200),
        };

        buffers.update_chunk(id, update).unwrap();

        let updated = buffers.get_chunk(id).unwrap();
        assert_eq!(updated.status, ChunkStatus::InTransfer);
        assert_eq!(updated.replica_count, 2);
        assert_eq!(updated.priority, 200);
    }

    #[test]
    fn test_remove_chunk() {
        let mut buffers = CpuStateBuffers::new(10, 10);
        let chunk = make_chunk_state(1, 1024, 128);
        let id = buffers.add_chunk(chunk).unwrap();

        let removed = buffers.remove_chunk(id).unwrap();
        assert_eq!(removed.hash, chunk.hash);
        assert_eq!(buffers.chunk_count(), 0);
        assert!(buffers.get_chunk(id).is_none());
    }

    #[test]
    fn test_add_and_get_edge() {
        let mut buffers = CpuStateBuffers::new(10, 10);
        let edge = make_edge_state(100, 1_000_000_000, 0.95);

        let idx = buffers.add_edge(100, edge).unwrap();
        assert_eq!(idx.0, 0);
        assert_eq!(buffers.edge_count(), 1);

        let retrieved = buffers.get_edge(idx).unwrap();
        assert_eq!(retrieved.edge_idx.0, 100);
        assert_eq!(retrieved.available_bandwidth_bps, 1_000_000_000);
    }

    #[test]
    fn test_add_duplicate_edge_fails() {
        let mut buffers = CpuStateBuffers::new(10, 10);
        let edge = make_edge_state(100, 1_000_000_000, 0.95);

        buffers.add_edge(100, edge).unwrap();
        let result = buffers.add_edge(100, edge);
        assert!(result.is_err());
    }

    #[test]
    fn test_update_edge() {
        let mut buffers = CpuStateBuffers::new(10, 10);
        let edge = make_edge_state(100, 1_000_000_000, 0.95);
        let idx = buffers.add_edge(100, edge).unwrap();

        let new_edge = make_edge_state(100, 2_000_000_000, 0.80);
        buffers.update_edge(idx, new_edge).unwrap();

        let updated = buffers.get_edge(idx).unwrap();
        assert_eq!(updated.available_bandwidth_bps, 2_000_000_000);
        let health = updated.health_score_f32();
        assert!((health - 0.80).abs() < 0.01);
    }

    #[test]
    fn test_remove_edge() {
        let mut buffers = CpuStateBuffers::new(10, 10);
        let edge = make_edge_state(100, 1_000_000_000, 0.95);
        let idx = buffers.add_edge(100, edge).unwrap();

        let removed = buffers.remove_edge(idx).unwrap();
        assert_eq!(removed.edge_idx.0, 100);
        assert_eq!(buffers.edge_count(), 0);
        assert!(buffers.get_edge(idx).is_none());
    }

    #[test]
    fn test_replica_map_add() {
        let mut buffers = CpuStateBuffers::new(10, 10);
        let chunk = make_chunk_state(1, 1024, 128);
        let chunk_id = buffers.add_chunk(chunk).unwrap();

        buffers.add_replica(chunk_id, EdgeIdx(0));
        buffers.add_replica(chunk_id, EdgeIdx(1));

        let replicas = buffers.get_replicas(chunk_id);
        assert_eq!(replicas.len(), 2);
        assert!(replicas.contains(&EdgeIdx(0)));
        assert!(replicas.contains(&EdgeIdx(1)));
    }

    #[test]
    fn test_replica_map_remove() {
        let mut buffers = CpuStateBuffers::new(10, 10);
        let chunk = make_chunk_state(1, 1024, 128);
        let chunk_id = buffers.add_chunk(chunk).unwrap();

        buffers.add_replica(chunk_id, EdgeIdx(0));
        buffers.add_replica(chunk_id, EdgeIdx(1));
        buffers.remove_replica(chunk_id, EdgeIdx(0));

        let replicas = buffers.get_replicas(chunk_id);
        assert_eq!(replicas.len(), 1);
        assert_eq!(replicas[0], EdgeIdx(1));
    }

    #[test]
    fn test_replica_map_no_duplicates() {
        let mut buffers = CpuStateBuffers::new(10, 10);
        let chunk = make_chunk_state(1, 1024, 128);
        let chunk_id = buffers.add_chunk(chunk).unwrap();

        buffers.add_replica(chunk_id, EdgeIdx(0));
        buffers.add_replica(chunk_id, EdgeIdx(0));

        let replicas = buffers.get_replicas(chunk_id);
        assert_eq!(replicas.len(), 1);
    }

    #[test]
    fn test_batch_update_chunks() {
        let mut buffers = CpuStateBuffers::new(10, 10);

        let chunk1 = make_chunk_state(1, 1024, 128);
        let chunk2 = make_chunk_state(2, 2048, 128);
        let id1 = buffers.add_chunk(chunk1).unwrap();
        let id2 = buffers.add_chunk(chunk2).unwrap();

        let updates = vec![
            ChunkStateUpdate {
                chunk_id: ChunkId(id1 as u64),
                status: Some(ChunkStatus::InTransfer),
                replica_count: None,
                priority: None,
            },
            ChunkStateUpdate {
                chunk_id: ChunkId(id2 as u64),
                status: Some(ChunkStatus::Completed),
                replica_count: None,
                priority: None,
            },
        ];

        buffers.update_chunks_batch(&updates).unwrap();

        assert_eq!(
            buffers.get_chunk(id1).unwrap().status,
            ChunkStatus::InTransfer
        );
        assert_eq!(
            buffers.get_chunk(id2).unwrap().status,
            ChunkStatus::Completed
        );
    }

    #[test]
    fn test_batch_update_edges() {
        let mut buffers = CpuStateBuffers::new(10, 10);

        let edge1 = make_edge_state(100, 1_000_000_000, 0.95);
        let edge2 = make_edge_state(200, 2_000_000_000, 0.90);
        buffers.add_edge(100, edge1).unwrap();
        buffers.add_edge(200, edge2).unwrap();

        let updates = vec![
            (100, make_edge_state(100, 1_500_000_000, 0.85)),
            (200, make_edge_state(200, 2_500_000_000, 0.75)),
        ];

        buffers.update_edges_batch(&updates).unwrap();

        assert_eq!(
            buffers
                .get_edge(EdgeIdx(0))
                .unwrap()
                .available_bandwidth_bps,
            1_500_000_000
        );
        assert_eq!(
            buffers
                .get_edge(EdgeIdx(1))
                .unwrap()
                .available_bandwidth_bps,
            2_500_000_000
        );
    }

    #[test]
    fn test_snapshot() {
        let mut buffers = CpuStateBuffers::new(10, 10);

        let chunk = make_chunk_state(1, 1024, 128);
        let edge = make_edge_state(100, 1_000_000_000, 0.95);

        buffers.add_chunk(chunk).unwrap();
        buffers.add_edge(100, edge).unwrap();

        let snapshot = buffers.snapshot();
        assert_eq!(snapshot.chunk_count, 1);
        assert_eq!(snapshot.edge_count, 1);
        assert_eq!(snapshot.chunks.len(), 1);
        assert_eq!(snapshot.edges.len(), 1);
    }

    #[test]
    fn test_find_chunk_by_hash() {
        let mut buffers = CpuStateBuffers::new(10, 10);
        let chunk = make_chunk_state(1, 1024, 128);
        let hash = chunk.hash;

        let id = buffers.add_chunk(chunk).unwrap();
        let found_id = buffers.find_chunk(&hash).unwrap();
        assert_eq!(found_id, id);
    }

    #[test]
    fn test_find_edge_by_id() {
        let mut buffers = CpuStateBuffers::new(10, 10);
        let edge = make_edge_state(100, 1_000_000_000, 0.95);

        let idx = buffers.add_edge(100, edge).unwrap();
        let found_idx = buffers.find_edge(100).unwrap();
        assert_eq!(found_idx, idx);
    }

    #[test]
    fn test_capacity_limit_chunks() {
        let mut buffers = CpuStateBuffers::new(2, 10);

        buffers.add_chunk(make_chunk_state(1, 1024, 128)).unwrap();
        buffers.add_chunk(make_chunk_state(2, 2048, 128)).unwrap();

        let result = buffers.add_chunk(make_chunk_state(3, 4096, 128));
        assert!(result.is_err());
    }

    #[test]
    fn test_capacity_limit_edges() {
        let mut buffers = CpuStateBuffers::new(10, 2);

        buffers
            .add_edge(100, make_edge_state(100, 1_000_000_000, 0.95))
            .unwrap();
        buffers
            .add_edge(200, make_edge_state(200, 2_000_000_000, 0.90))
            .unwrap();

        let result = buffers.add_edge(300, make_edge_state(300, 3_000_000_000, 0.85));
        assert!(result.is_err());
    }

    #[test]
    fn test_update_nonexistent_chunk_fails() {
        let mut buffers = CpuStateBuffers::new(10, 10);

        let update = ChunkStateUpdate {
            chunk_id: ChunkId(99),
            status: Some(ChunkStatus::Completed),
            replica_count: None,
            priority: None,
        };

        let result = buffers.update_chunk(99, update);
        assert!(result.is_err());
    }

    #[test]
    fn test_update_nonexistent_edge_fails() {
        let mut buffers = CpuStateBuffers::new(10, 10);
        let edge = make_edge_state(999, 1_000_000_000, 0.95);

        let result = buffers.update_edge(EdgeIdx(999), edge);
        assert!(result.is_err());
    }

    // GPU wrapper tests

    #[test]
    fn test_gpu_buffers_creation() {
        let buffers = GpuStateBuffers::new(1000, 100);
        assert_eq!(buffers.chunk_count(), 0);
        assert_eq!(buffers.edge_count(), 0);
    }

    #[test]
    fn test_gpu_buffers_add_chunk() {
        let mut buffers = GpuStateBuffers::new(10, 10);
        let chunk = make_chunk_state(1, 1024, 128);

        let id = buffers.add_chunk(chunk).unwrap();
        let retrieved = buffers.get_chunk(id).unwrap();
        assert_eq!(retrieved.hash, chunk.hash);
    }

    #[test]
    fn test_gpu_buffers_add_edge() {
        let mut buffers = GpuStateBuffers::new(10, 10);
        let edge = make_edge_state(100, 1_000_000_000, 0.95);

        let idx = buffers.add_edge(100, edge).unwrap();
        let retrieved = buffers.get_edge(idx).unwrap();
        assert_eq!(retrieved.edge_idx.0, 100);
    }

    #[test]
    fn test_gpu_buffers_replica_operations() {
        let mut buffers = GpuStateBuffers::new(10, 10);
        let chunk = make_chunk_state(1, 1024, 128);
        let chunk_id = buffers.add_chunk(chunk).unwrap();

        buffers.add_replica(chunk_id, EdgeIdx(0));
        buffers.add_replica(chunk_id, EdgeIdx(1));

        let replicas = buffers.get_replicas(chunk_id);
        assert_eq!(replicas.len(), 2);
    }

    #[test]
    fn test_gpu_buffers_snapshot() {
        let mut buffers = GpuStateBuffers::new(10, 10);
        buffers.add_chunk(make_chunk_state(1, 1024, 128)).unwrap();
        buffers
            .add_edge(100, make_edge_state(100, 1_000_000_000, 0.95))
            .unwrap();

        let snapshot = buffers.snapshot();
        assert_eq!(snapshot.chunk_count, 1);
        assert_eq!(snapshot.edge_count, 1);
    }
}
