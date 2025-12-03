//! K-best path selection for chunk scheduling
//!
//! Selects the top K source edges for each chunk based on costs from the cost matrix.
//! Supports configurable filtering by maximum cost and diversity weighting.

use crate::cost::{CostMatrix, CpuCostMatrix};
use crate::{ChunkId, CpuStateBuffers, EdgeIdx};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

/// Configuration for K-best path selection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathConfig {
    /// Number of best paths to select per chunk (K). Must be >= 1.
    pub k: usize,
    /// Maximum acceptable cost for path selection (default 1.0)
    pub max_cost: f32,
    /// Weight for edge diversity scoring (0.0-1.0)
    pub diversity_weight: f32,
}

impl Default for PathConfig {
    fn default() -> Self {
        Self { k: 3, max_cost: 1.0, diversity_weight: 0.1 }
    }
}

impl PathConfig {
    /// Create a new PathConfig with specified parameters
    /// # Panics
    /// Panics if k == 0
    pub fn new(k: usize, max_cost: f32, diversity_weight: f32) -> Self {
        assert!(k > 0, "k must be at least 1");
        Self { k, max_cost, diversity_weight: diversity_weight.clamp(0.0, 1.0) }
    }

    /// Create config for high redundancy (k=5)
    pub fn high_redundancy() -> Self {
        Self { k: 5, max_cost: 1.0, diversity_weight: 0.15 }
    }

    /// Create config for low latency (k=1, strict max_cost)
    pub fn low_latency() -> Self {
        Self { k: 1, max_cost: 0.5, diversity_weight: 0.0 }
    }

    /// Create config for balanced performance (k=3, moderate filtering)
    pub fn balanced() -> Self {
        Self { k: 3, max_cost: 0.8, diversity_weight: 0.1 }
    }

    /// Set the K value
    pub fn with_k(mut self, k: usize) -> Self {
        assert!(k > 0, "k must be at least 1");
        self.k = k;
        self
    }

    /// Set the max cost threshold
    pub fn with_max_cost(mut self, max_cost: f32) -> Self {
        self.max_cost = max_cost;
        self
    }

    /// Set the diversity weight
    pub fn with_diversity_weight(mut self, weight: f32) -> Self {
        self.diversity_weight = weight.clamp(0.0, 1.0);
        self
    }
}

/// Result of path selection for a single chunk
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PathSelection {
    /// Chunk identifier
    pub chunk_id: ChunkId,
    /// Selected edges with their costs, sorted by cost (lowest first)
    pub selected_edges: Vec<(EdgeIdx, f32)>,
    /// Total aggregate cost of all selected edges
    pub total_cost: f32,
}

impl PathSelection {
    /// Create a new PathSelection
    pub fn new(chunk_id: ChunkId, selected_edges: Vec<(EdgeIdx, f32)>) -> Self {
        let total_cost = selected_edges.iter().map(|(_, cost)| cost).sum();
        Self { chunk_id, selected_edges, total_cost }
    }

    /// Create an empty selection (no valid paths)
    pub fn empty(chunk_id: ChunkId) -> Self {
        Self { chunk_id, selected_edges: Vec::new(), total_cost: 0.0 }
    }

    /// Get the number of selected edges
    #[inline]
    pub fn edge_count(&self) -> usize { self.selected_edges.len() }

    /// Check if any paths were selected
    #[inline]
    pub fn has_paths(&self) -> bool { !self.selected_edges.is_empty() }

    /// Get the best (lowest cost) edge, if any
    pub fn best_edge(&self) -> Option<(EdgeIdx, f32)> { self.selected_edges.first().copied() }

    /// Get just the edge indices without costs
    pub fn edge_indices(&self) -> Vec<EdgeIdx> {
        self.selected_edges.iter().map(|(idx, _)| *idx).collect()
    }

    /// Get the average cost of selected edges
    pub fn average_cost(&self) -> f32 {
        if self.selected_edges.is_empty() { 0.0 } else { self.total_cost / self.selected_edges.len() as f32 }
    }
}

/// Batch of path selections for multiple chunks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectionBatch {
    /// Vector of path selections
    pub selections: Vec<PathSelection>,
    /// Generation number for versioning
    pub generation: u64,
    /// Timestamp in milliseconds since epoch
    pub timestamp_ms: u64,
}

impl SelectionBatch {
    /// Create a new SelectionBatch
    pub fn new(selections: Vec<PathSelection>, generation: u64) -> Self {
        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::ZERO)
            .as_millis() as u64;
        Self { selections, generation, timestamp_ms }
    }

    /// Create an empty batch
    pub fn empty(generation: u64) -> Self { Self::new(Vec::new(), generation) }

    /// Get the number of selections in the batch
    #[inline]
    pub fn len(&self) -> usize { self.selections.len() }

    /// Check if the batch is empty
    #[inline]
    pub fn is_empty(&self) -> bool { self.selections.is_empty() }

    /// Get the number of selections with valid paths
    pub fn valid_selection_count(&self) -> usize {
        self.selections.iter().filter(|s| s.has_paths()).count()
    }

    /// Get total aggregate cost across all selections
    pub fn total_cost(&self) -> f32 { self.selections.iter().map(|s| s.total_cost).sum() }

    /// Get average cost per selection (excluding empty selections)
    pub fn average_cost_per_selection(&self) -> f32 {
        let valid = self.valid_selection_count();
        if valid == 0 { 0.0 } else { self.total_cost() / valid as f32 }
    }
}

impl Default for SelectionBatch {
    fn default() -> Self { Self::empty(0) }
}

/// CPU implementation of K-best path selector
pub struct CpuPathSelector {
    config: PathConfig,
}

impl CpuPathSelector {
    /// Create a new CPU path selector
    pub fn new(config: PathConfig) -> Self { Self { config } }

    /// Select K-best paths for a single chunk
    pub fn select(&self, chunk_id: ChunkId, cost_matrix: &CpuCostMatrix) -> PathSelection {
        let mut valid_edges = cost_matrix.get_valid_edges(chunk_id);
        valid_edges.retain(|(_, cost)| *cost <= self.config.max_cost);
        valid_edges.truncate(self.config.k);
        PathSelection::new(chunk_id, valid_edges)
    }

    /// Select K-best paths for multiple chunks in parallel
    pub fn select_batch(&self, chunk_ids: &[ChunkId], cost_matrix: &CpuCostMatrix) -> SelectionBatch {
        let selections: Vec<PathSelection> = chunk_ids
            .par_iter()
            .map(|&chunk_id| self.select(chunk_id, cost_matrix))
            .collect();
        SelectionBatch::new(selections, 0)
    }

    /// Select K-best paths for all chunks in state
    pub fn select_all(&self, cost_matrix: &CpuCostMatrix, state: &CpuStateBuffers) -> SelectionBatch {
        let chunk_count = state.chunk_count();
        let chunk_ids: Vec<ChunkId> = (0..chunk_count)
            .filter_map(|i| state.get_chunk(i as u32).map(|_| ChunkId(i as u64)))
            .collect();
        self.select_batch(&chunk_ids, cost_matrix)
    }

    /// Get the current configuration
    pub fn config(&self) -> &PathConfig { &self.config }

    /// Update the configuration
    pub fn set_config(&mut self, config: PathConfig) { self.config = config; }
}

/// GPU-accelerated path selector (currently delegates to CPU)
pub struct PathSelector {
    cpu: CpuPathSelector,
}

impl PathSelector {
    /// Create a new GPU path selector
    pub fn new(config: PathConfig) -> Self { Self { cpu: CpuPathSelector::new(config) } }

    /// Create from existing CPU selector
    pub fn from_cpu(cpu: CpuPathSelector) -> Self { Self { cpu } }

    /// Select K-best paths for a single chunk (delegates to CPU)
    pub fn select(&self, chunk_id: ChunkId, cost_matrix: &CostMatrix) -> PathSelection {
        self.cpu.select(chunk_id, self.get_cpu_matrix(cost_matrix))
    }

    /// Select K-best paths for multiple chunks (delegates to CPU)
    pub fn select_batch(&self, chunk_ids: &[ChunkId], cost_matrix: &CostMatrix) -> SelectionBatch {
        self.cpu.select_batch(chunk_ids, self.get_cpu_matrix(cost_matrix))
    }

    /// Select K-best paths for all chunks (delegates to CPU)
    pub fn select_all(&self, cost_matrix: &CostMatrix, state: &CpuStateBuffers) -> SelectionBatch {
        self.cpu.select_all(self.get_cpu_matrix(cost_matrix), state)
    }

    /// Get configuration
    pub fn config(&self) -> &PathConfig { self.cpu.config() }

    /// Update configuration
    pub fn set_config(&mut self, config: PathConfig) { self.cpu.set_config(config); }

    /// Get CPU selector reference
    pub fn cpu(&self) -> &CpuPathSelector { &self.cpu }

    /// Helper to extract CPU matrix from GPU wrapper
    #[inline]
    fn get_cpu_matrix<'a>(&self, cost_matrix: &'a CostMatrix) -> &'a CpuCostMatrix {
        // SAFETY: CostMatrix wraps CpuCostMatrix as first field
        unsafe { &*(cost_matrix as *const CostMatrix as *const CpuCostMatrix) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cost::CostConfig;
    use crate::{ChunkState, EdgeStateGpu};

    fn make_test_state(num_chunks: usize, num_edges: usize) -> CpuStateBuffers {
        let mut state = CpuStateBuffers::new(num_chunks, num_edges);
        for i in 0..num_chunks {
            let mut hash = [0u8; 32];
            hash[0] = i as u8;
            state.add_chunk(ChunkState::new(hash, 1024 * 1024, 128, 3)).unwrap();
        }
        for i in 0..num_edges {
            let bw = 1_000_000_000 - (i as u64 * 100_000_000);
            let rtt = 10_000 + (i as u32 * 5_000);
            let health = (0.95 - (i as f32 * 0.1)).max(0.1);
            state.add_edge(i as u32, EdgeStateGpu::new(EdgeIdx(i as u32), bw, rtt, health, 10)).unwrap();
        }
        state
    }

    #[test]
    fn test_path_config() {
        // Default values
        let config = PathConfig::default();
        assert_eq!(config.k, 3);
        assert_eq!(config.max_cost, 1.0);
        assert_eq!(config.diversity_weight, 0.1);

        // Custom config
        let config = PathConfig::new(5, 0.8, 0.2);
        assert_eq!(config.k, 5);
        assert_eq!(config.max_cost, 0.8);
        assert_eq!(config.diversity_weight, 0.2);

        // Presets
        assert_eq!(PathConfig::high_redundancy().k, 5);
        assert_eq!(PathConfig::low_latency().k, 1);
        assert_eq!(PathConfig::balanced().k, 3);

        // Builder pattern
        let config = PathConfig::default().with_k(7).with_max_cost(0.6).with_diversity_weight(0.25);
        assert_eq!(config.k, 7);
        assert_eq!(config.max_cost, 0.6);
        assert_eq!(config.diversity_weight, 0.25);

        // Diversity weight clamping
        assert_eq!(PathConfig::new(3, 1.0, 1.5).diversity_weight, 1.0);
        assert_eq!(PathConfig::new(3, 1.0, -0.5).diversity_weight, 0.0);
    }

    #[test]
    #[should_panic(expected = "k must be at least 1")]
    fn test_path_config_zero_k() { PathConfig::new(0, 1.0, 0.1); }

    #[test]
    fn test_path_config_serialization() {
        let config = PathConfig::new(4, 0.75, 0.15);
        let serialized = rmp_serde::to_vec(&config).unwrap();
        let de: PathConfig = rmp_serde::from_slice(&serialized).unwrap();
        assert_eq!(de.k, config.k);
        assert_eq!(de.max_cost, config.max_cost);
    }

    #[test]
    fn test_path_selection() {
        let edges = vec![(EdgeIdx(0), 0.1), (EdgeIdx(1), 0.2), (EdgeIdx(2), 0.3)];
        let sel = PathSelection::new(ChunkId(42), edges.clone());
        assert_eq!(sel.chunk_id, ChunkId(42));
        assert_eq!(sel.selected_edges, edges);
        assert!((sel.total_cost - 0.6).abs() < 0.001);
        assert_eq!(sel.edge_count(), 3);
        assert!(sel.has_paths());
        assert_eq!(sel.best_edge(), Some((EdgeIdx(0), 0.1)));
        assert_eq!(sel.edge_indices(), vec![EdgeIdx(0), EdgeIdx(1), EdgeIdx(2)]);
        assert!((sel.average_cost() - 0.2).abs() < 0.001);

        // Empty selection
        let empty = PathSelection::empty(ChunkId(10));
        assert!(!empty.has_paths());
        assert!(empty.best_edge().is_none());
        assert_eq!(empty.average_cost(), 0.0);
    }

    #[test]
    fn test_path_selection_serialization() {
        let sel = PathSelection::new(ChunkId(123), vec![(EdgeIdx(5), 0.25), (EdgeIdx(10), 0.35)]);
        let serialized = rmp_serde::to_vec(&sel).unwrap();
        let de: PathSelection = rmp_serde::from_slice(&serialized).unwrap();
        assert_eq!(de.chunk_id, sel.chunk_id);
        assert_eq!(de.selected_edges, sel.selected_edges);
    }

    #[test]
    fn test_selection_batch() {
        let sels = vec![
            PathSelection::new(ChunkId(0), vec![(EdgeIdx(0), 0.1)]),
            PathSelection::empty(ChunkId(1)),
            PathSelection::new(ChunkId(2), vec![(EdgeIdx(2), 0.3)]),
        ];
        let batch = SelectionBatch::new(sels, 42);
        assert_eq!(batch.generation, 42);
        assert_eq!(batch.len(), 3);
        assert!(!batch.is_empty());
        assert_eq!(batch.valid_selection_count(), 2);
        assert!((batch.total_cost() - 0.4).abs() < 0.001);
        assert!((batch.average_cost_per_selection() - 0.2).abs() < 0.001);

        // Empty batch
        let empty = SelectionBatch::empty(10);
        assert!(empty.is_empty());
        assert_eq!(SelectionBatch::default().generation, 0);
    }

    #[test]
    fn test_selection_batch_serialization() {
        let batch = SelectionBatch::new(vec![PathSelection::new(ChunkId(0), vec![(EdgeIdx(0), 0.1)])], 99);
        let serialized = rmp_serde::to_vec(&batch).unwrap();
        let de: SelectionBatch = rmp_serde::from_slice(&serialized).unwrap();
        assert_eq!(de.generation, batch.generation);
    }

    #[test]
    fn test_cpu_path_selector_basic() {
        let selector = CpuPathSelector::new(PathConfig::new(2, 1.0, 0.0));
        let mut matrix = CpuCostMatrix::new(1, 3, CostConfig::default());
        let mut state = make_test_state(1, 3);
        for i in 0..3 { state.add_replica(0, EdgeIdx(i)); }
        matrix.compute(&state);

        let sel = selector.select(ChunkId(0), &matrix);
        assert_eq!(sel.chunk_id, ChunkId(0));
        assert_eq!(sel.edge_count(), 2);
        assert!(sel.has_paths());
    }

    #[test]
    fn test_cpu_path_selector_empty_and_no_valid() {
        let selector = CpuPathSelector::new(PathConfig::default());
        let matrix = CpuCostMatrix::new(1, 3, CostConfig::default());
        // No replicas added, so no valid edges
        let sel = selector.select(ChunkId(0), &matrix);
        assert!(!sel.has_paths());
        assert_eq!(sel.edge_count(), 0);
    }

    #[test]
    fn test_cpu_path_selector_k_greater_than_available() {
        let selector = CpuPathSelector::new(PathConfig::new(10, 1.0, 0.0));
        let mut matrix = CpuCostMatrix::new(1, 3, CostConfig::default());
        let mut state = make_test_state(1, 3);
        for i in 0..3 { state.add_replica(0, EdgeIdx(i)); }
        matrix.compute(&state);

        let sel = selector.select(ChunkId(0), &matrix);
        assert_eq!(sel.edge_count(), 3); // Limited by available
    }

    #[test]
    fn test_cpu_path_selector_max_cost_filtering() {
        let selector = CpuPathSelector::new(PathConfig::new(5, 0.3, 0.0));
        let mut matrix = CpuCostMatrix::new(1, 5, CostConfig::default());
        let mut state = make_test_state(1, 5);
        for i in 0..5 { state.add_replica(0, EdgeIdx(i)); }
        matrix.compute(&state);

        let sel = selector.select(ChunkId(0), &matrix);
        for (_, cost) in &sel.selected_edges { assert!(*cost <= 0.3); }
    }

    #[test]
    fn test_cpu_path_selector_edges_sorted() {
        let selector = CpuPathSelector::new(PathConfig::new(5, 1.0, 0.0));
        let mut matrix = CpuCostMatrix::new(1, 5, CostConfig::default());
        let mut state = make_test_state(1, 5);
        for i in 0..5 { state.add_replica(0, EdgeIdx(i)); }
        matrix.compute(&state);

        let sel = selector.select(ChunkId(0), &matrix);
        for i in 0..sel.edge_count().saturating_sub(1) {
            assert!(sel.selected_edges[i].1 <= sel.selected_edges[i + 1].1);
        }
    }

    #[test]
    fn test_cpu_path_selector_batch() {
        let selector = CpuPathSelector::new(PathConfig::new(2, 1.0, 0.0));
        let mut matrix = CpuCostMatrix::new(3, 4, CostConfig::default());
        let mut state = make_test_state(3, 4);
        for chunk in 0..3 { for edge in 0..3 { state.add_replica(chunk, EdgeIdx(edge)); } }
        matrix.compute(&state);

        let batch = selector.select_batch(&[ChunkId(0), ChunkId(1), ChunkId(2)], &matrix);
        assert_eq!(batch.len(), 3);
        assert_eq!(batch.valid_selection_count(), 3);

        // Empty batch
        assert!(selector.select_batch(&[], &matrix).is_empty());
    }

    #[test]
    fn test_cpu_path_selector_batch_parallel() {
        let selector = CpuPathSelector::new(PathConfig::new(3, 1.0, 0.0));
        let mut matrix = CpuCostMatrix::new(100, 10, CostConfig::default());
        let mut state = make_test_state(100, 10);
        for chunk in 0..100 { for edge in 0..5 { state.add_replica(chunk, EdgeIdx(edge)); } }
        matrix.compute(&state);

        let chunk_ids: Vec<ChunkId> = (0..100).map(ChunkId).collect();
        let batch = selector.select_batch(&chunk_ids, &matrix);
        assert_eq!(batch.len(), 100);
    }

    #[test]
    fn test_cpu_path_selector_select_all() {
        let selector = CpuPathSelector::new(PathConfig::new(3, 1.0, 0.0));
        let mut matrix = CpuCostMatrix::new(5, 4, CostConfig::default());
        let mut state = make_test_state(5, 4);
        for chunk in 0..5 { for edge in 0..3 { state.add_replica(chunk as u32, EdgeIdx(edge)); } }
        matrix.compute(&state);

        let batch = selector.select_all(&matrix, &state);
        assert_eq!(batch.len(), 5);

        // Empty state
        let empty_state = CpuStateBuffers::new(10, 5);
        let empty_matrix = CpuCostMatrix::new(10, 5, CostConfig::default());
        assert!(selector.select_all(&empty_matrix, &empty_state).is_empty());
    }

    #[test]
    fn test_cpu_path_selector_config() {
        let mut selector = CpuPathSelector::new(PathConfig::new(3, 0.8, 0.1));
        assert_eq!(selector.config().k, 3);
        selector.set_config(PathConfig::new(5, 0.9, 0.2));
        assert_eq!(selector.config().k, 5);
    }

    #[test]
    fn test_path_selector_gpu_wrapper() {
        let selector = PathSelector::new(PathConfig::default());
        assert_eq!(selector.config().k, 3);

        let cpu = CpuPathSelector::new(PathConfig::new(4, 0.7, 0.15));
        let selector = PathSelector::from_cpu(cpu);
        assert_eq!(selector.config().k, 4);
        assert_eq!(selector.cpu().config().k, 4);
    }

    #[test]
    fn test_path_selector_delegation() {
        let selector = PathSelector::new(PathConfig::new(2, 1.0, 0.0));
        let mut matrix = CostMatrix::new(2, 3, CostConfig::default());
        let mut state = make_test_state(2, 3);
        for chunk in 0..2 { for edge in 0..3 { state.add_replica(chunk, EdgeIdx(edge)); } }
        matrix.compute(&state);

        // select
        let sel = selector.select(ChunkId(0), &matrix);
        assert!(sel.edge_count() <= 2);

        // select_batch
        let batch = selector.select_batch(&[ChunkId(0), ChunkId(1)], &matrix);
        assert_eq!(batch.len(), 2);

        // select_all
        let batch = selector.select_all(&matrix, &state);
        assert_eq!(batch.len(), 2);
    }

    #[test]
    fn test_path_selector_set_config() {
        let mut selector = PathSelector::new(PathConfig::default());
        selector.set_config(PathConfig::new(7, 0.6, 0.3));
        assert_eq!(selector.config().k, 7);
        assert_eq!(selector.config().max_cost, 0.6);
    }

    #[test]
    fn test_full_pipeline() {
        let selector = CpuPathSelector::new(PathConfig::new(3, 1.0, 0.0));
        let mut state = CpuStateBuffers::new(1, 5);
        state.add_chunk(ChunkState::new([42; 32], 1024 * 1024, 128, 3)).unwrap();
        for i in 0..5 {
            state.add_edge(i, EdgeStateGpu::new(EdgeIdx(i), 1_000_000_000, 10_000 + i * 1000, 0.95, 10)).unwrap();
            state.add_replica(0, EdgeIdx(i));
        }
        let mut matrix = CpuCostMatrix::new(1, 5, CostConfig::default());
        matrix.compute(&state);

        let sel = selector.select(ChunkId(0), &matrix);
        assert!(sel.has_paths());
        assert_eq!(sel.edge_count(), 3);
    }

    #[test]
    fn test_respects_edge_availability() {
        let selector = CpuPathSelector::new(PathConfig::new(5, 1.0, 0.0));
        let mut state = CpuStateBuffers::new(1, 3);
        state.add_chunk(ChunkState::new([1; 32], 1024, 128, 3)).unwrap();
        for i in 0..3 {
            let mut edge = EdgeStateGpu::new(EdgeIdx(i), 1_000_000_000, 10_000, 0.95, 10);
            if i == 1 { edge.status = 0; } // Offline
            state.add_edge(i, edge).unwrap();
            state.add_replica(0, EdgeIdx(i));
        }
        let mut matrix = CpuCostMatrix::new(1, 3, CostConfig::default());
        matrix.compute(&state);

        let sel = selector.select(ChunkId(0), &matrix);
        assert_eq!(sel.edge_count(), 2);
        for (edge_idx, _) in &sel.selected_edges { assert_ne!(edge_idx.0, 1); }
    }
}
