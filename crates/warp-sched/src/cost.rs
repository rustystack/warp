//! Cost matrix computation for chunk scheduling
//!
//! Computes transfer costs for all (chunk, edge) pairs based on bandwidth,
//! RTT, health, and load balancing metrics. Supports both CPU and GPU
//! computation paths with configurable cost function weights.
//!
//! # Dynamic Metrics Integration
//!
//! The cost function can incorporate real-time throughput and RTT measurements
//! via `DynamicEdgeMetrics`. When dynamic metrics are available:
//! - Saturated paths (high throughput/capacity ratio) receive cost penalties
//! - Paths with increasing RTT (congestion signal) receive cost penalties
//! - This enables adaptive load balancing away from congested paths

use crate::{ChunkId, CpuStateBuffers, DynamicEdgeMetrics, EdgeIdx, RttTrend};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Cost function configuration with tunable weights
///
/// All weights should sum to approximately 1.0 for normalized costs.
/// Default values are balanced for general-purpose scheduling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostConfig {
    /// Weight for bandwidth term (0.0-1.0)
    pub bandwidth_weight: f32,
    /// Weight for RTT term (0.0-1.0)
    pub rtt_weight: f32,
    /// Weight for health term (0.0-1.0)
    pub health_weight: f32,
    /// Weight for load balancing term (0.0-1.0)
    pub load_weight: f32,
    /// Weight for path diversity term (0.0-1.0)
    ///
    /// When set > 0, paths using different network interfaces will be
    /// preferred to maximize aggregate throughput across multiple NICs.
    pub diversity_weight: f32,
    /// Weight for saturation penalty term (0.0-1.0)
    ///
    /// When set > 0, paths approaching their capacity (high saturation ratio)
    /// or showing signs of congestion (increasing RTT) will be penalized.
    /// Requires dynamic metrics to be provided via `compute_with_metrics`.
    pub saturation_weight: f32,
    /// Maximum acceptable RTT in microseconds for normalization
    pub max_acceptable_rtt_us: u32,
    /// Saturation threshold above which penalty is applied (0.0-1.0)
    ///
    /// When `throughput_bps / capacity_bps` exceeds this threshold,
    /// the saturation penalty increases exponentially. Default: 0.85
    pub saturation_threshold: f32,
}

impl Default for CostConfig {
    fn default() -> Self {
        Self {
            bandwidth_weight: 0.3,
            rtt_weight: 0.3,
            health_weight: 0.2,
            load_weight: 0.2,
            diversity_weight: 0.0,  // Disabled by default for backwards compat
            saturation_weight: 0.0, // Disabled by default for backwards compat
            max_acceptable_rtt_us: 100_000, // 100ms
            saturation_threshold: 0.85,
        }
    }
}

impl CostConfig {
    /// Create a new `CostConfig` with custom weights
    #[must_use]
    pub const fn new(
        bandwidth_weight: f32,
        rtt_weight: f32,
        health_weight: f32,
        load_weight: f32,
    ) -> Self {
        Self {
            bandwidth_weight,
            rtt_weight,
            health_weight,
            load_weight,
            diversity_weight: 0.0,
            saturation_weight: 0.0,
            max_acceptable_rtt_us: 100_000,
            saturation_threshold: 0.85,
        }
    }

    /// Create a config that prioritizes bandwidth
    #[must_use]
    pub const fn bandwidth_priority() -> Self {
        Self {
            bandwidth_weight: 0.6,
            rtt_weight: 0.2,
            health_weight: 0.1,
            load_weight: 0.1,
            diversity_weight: 0.0,
            saturation_weight: 0.0,
            max_acceptable_rtt_us: 100_000,
            saturation_threshold: 0.85,
        }
    }

    /// Create a config that prioritizes latency
    #[must_use]
    pub const fn latency_priority() -> Self {
        Self {
            bandwidth_weight: 0.1,
            rtt_weight: 0.6,
            health_weight: 0.2,
            load_weight: 0.1,
            diversity_weight: 0.0,
            saturation_weight: 0.0,
            max_acceptable_rtt_us: 100_000,
            saturation_threshold: 0.85,
        }
    }

    /// Create a config optimized for multi-path aggregation
    ///
    /// Prioritizes using diverse network paths to maximize aggregate throughput.
    /// Enables both diversity and saturation weights for adaptive load balancing.
    #[must_use]
    pub const fn multi_path() -> Self {
        Self {
            bandwidth_weight: 0.20,
            rtt_weight: 0.20,
            health_weight: 0.15,
            load_weight: 0.15,
            diversity_weight: 0.15,  // Path diversity for multi-NIC
            saturation_weight: 0.15, // Dynamic congestion avoidance
            max_acceptable_rtt_us: 100_000,
            saturation_threshold: 0.85,
        }
    }

    /// Create a config optimized for adaptive congestion control
    ///
    /// Heavily weights saturation metrics for aggressive load shifting
    /// away from congested paths.
    #[must_use]
    pub const fn congestion_aware() -> Self {
        Self {
            bandwidth_weight: 0.20,
            rtt_weight: 0.20,
            health_weight: 0.10,
            load_weight: 0.10,
            diversity_weight: 0.15,
            saturation_weight: 0.25, // High saturation weight
            max_acceptable_rtt_us: 100_000,
            saturation_threshold: 0.80, // More aggressive threshold
        }
    }

    /// Set maximum acceptable RTT
    #[must_use]
    pub const fn with_max_rtt(mut self, max_rtt_us: u32) -> Self {
        self.max_acceptable_rtt_us = max_rtt_us;
        self
    }

    /// Set diversity weight for multi-path scheduling
    #[must_use]
    pub const fn with_diversity_weight(mut self, weight: f32) -> Self {
        self.diversity_weight = weight.clamp(0.0, 1.0);
        self
    }

    /// Set saturation weight for congestion-aware scheduling
    #[must_use]
    pub const fn with_saturation_weight(mut self, weight: f32) -> Self {
        self.saturation_weight = weight.clamp(0.0, 1.0);
        self
    }

    /// Set saturation threshold for congestion detection
    #[must_use]
    pub const fn with_saturation_threshold(mut self, threshold: f32) -> Self {
        self.saturation_threshold = threshold.clamp(0.0, 1.0);
        self
    }
}

/// CPU-based cost matrix computation
///
/// Stores costs for all (chunk, edge) pairs in a flattened 2D array.
/// Layout: row-major [`chunk_0_edge_0`, `chunk_0_edge_1`, ..., `chunk_1_edge_0`, ...]
pub struct CpuCostMatrix {
    /// Flattened cost matrix [`num_chunks` * `num_edges`]
    costs: Vec<f32>,
    /// Valid mask: true if edge has replica of chunk
    valid_mask: Vec<bool>,
    /// Number of chunks
    num_chunks: usize,
    /// Number of edges
    num_edges: usize,
    /// Cost configuration
    config: CostConfig,
}

impl CpuCostMatrix {
    /// Create a new cost matrix
    ///
    /// # Arguments
    /// * `num_chunks` - Number of chunks to track
    /// * `num_edges` - Number of edges to track
    /// * `config` - Cost function configuration
    #[must_use]
    pub fn new(num_chunks: usize, num_edges: usize, config: CostConfig) -> Self {
        let size = num_chunks * num_edges;
        Self {
            costs: vec![f32::INFINITY; size],
            valid_mask: vec![false; size],
            num_chunks,
            num_edges,
            config,
        }
    }

    /// Compute costs for all (chunk, edge) pairs
    ///
    /// Uses state buffers to access chunk sizes, edge bandwidth, RTT, health,
    /// and replica locations. Computes weighted cost based on configuration.
    /// Uses Rayon for parallel computation across chunks.
    pub fn compute(&mut self, state: &CpuStateBuffers) {
        // Get actual counts from state
        let actual_chunks = state.chunk_count();
        let actual_edges = state.edge_count();

        // Reset costs in parallel
        self.costs.par_iter_mut().for_each(|c| *c = f32::INFINITY);
        self.valid_mask.par_iter_mut().for_each(|v| *v = false);

        // Capture config values for use in parallel closure
        let bandwidth_weight = self.config.bandwidth_weight;
        let rtt_weight = self.config.rtt_weight;
        let health_weight = self.config.health_weight;
        let load_weight = self.config.load_weight;
        let max_rtt_us = self.config.max_acceptable_rtt_us;
        let num_edges = self.num_edges;

        // Compute costs in parallel per chunk
        let results: Vec<Vec<(usize, f32)>> = (0..actual_chunks)
            .into_par_iter()
            .filter_map(|chunk_idx| {
                let chunk = state.get_chunk(chunk_idx as u32)?;
                let chunk_size = chunk.size;
                let replicas = state.get_replicas(chunk_idx as u32);

                let mut chunk_costs = Vec::new();

                for edge_idx in 0..actual_edges {
                    // Use slice::contains instead of HashSet (small replica sets, ~3 items)
                    if !replicas.contains(&EdgeIdx(edge_idx as u32)) {
                        continue;
                    }

                    let edge = match state.get_edge(EdgeIdx(edge_idx as u32)) {
                        Some(e) if e.can_accept_transfer() => e,
                        _ => continue,
                    };

                    // Compute individual cost components using static methods
                    let bandwidth_cost = Self::compute_bandwidth_cost_static(
                        chunk_size,
                        edge.available_bandwidth_bps,
                    );
                    let rtt_cost = Self::compute_rtt_cost_static(edge.rtt_us, max_rtt_us);
                    let health_cost = Self::compute_health_cost_static(edge.health_score_f32());
                    let load_cost =
                        Self::compute_load_cost_static(edge.active_transfers, edge.max_transfers);

                    // Weighted sum of all components
                    let total_cost = load_weight.mul_add(
                        load_cost,
                        health_weight.mul_add(
                            health_cost,
                            bandwidth_weight.mul_add(bandwidth_cost, rtt_weight * rtt_cost),
                        ),
                    );

                    let index = chunk_idx * num_edges + edge_idx;
                    chunk_costs.push((index, total_cost));
                }

                Some(chunk_costs)
            })
            .collect();

        // Apply results (single-threaded to avoid race conditions)
        for chunk_costs in results {
            for (index, cost) in chunk_costs {
                self.costs[index] = cost;
                self.valid_mask[index] = true;
            }
        }
    }

    /// Static bandwidth cost computation for use in parallel contexts
    #[inline]
    fn compute_bandwidth_cost_static(chunk_size: u32, bandwidth_bps: u64) -> f32 {
        if bandwidth_bps == 0 {
            return 1.0;
        }
        let bits = f64::from(chunk_size) * 8.0;
        let transfer_time_sec = bits / bandwidth_bps as f64;
        (transfer_time_sec / 10.0).min(1.0) as f32
    }

    /// Static RTT cost computation for use in parallel contexts
    #[inline]
    fn compute_rtt_cost_static(rtt_us: u32, max_rtt_us: u32) -> f32 {
        (rtt_us as f32 / max_rtt_us as f32).min(1.0)
    }

    /// Static health cost computation for use in parallel contexts
    #[inline]
    fn compute_health_cost_static(health_score: f32) -> f32 {
        1.0 - health_score.clamp(0.0, 1.0)
    }

    /// Static load cost computation for use in parallel contexts
    #[inline]
    fn compute_load_cost_static(active_transfers: u16, max_transfers: u16) -> f32 {
        if max_transfers == 0 {
            return 1.0;
        }
        f32::from(active_transfers) / f32::from(max_transfers)
    }

    /// Static saturation cost computation for use in parallel contexts
    ///
    /// Computes a penalty based on path saturation and RTT trend.
    /// - When `saturation_ratio` exceeds threshold, penalty increases exponentially
    /// - When RTT is increasing (congestion signal), adds additional penalty
    ///
    /// Returns value in range [0.0, 1.0]
    #[inline]
    fn compute_saturation_cost_static(
        metrics: Option<&DynamicEdgeMetrics>,
        saturation_threshold: f32,
    ) -> f32 {
        let Some(metrics) = metrics else {
            return 0.0; // No penalty if metrics not available
        };

        let mut penalty = 0.0;

        // Saturation ratio penalty (exponential above threshold)
        let saturation_ratio = metrics.throughput.saturation_ratio;
        if saturation_ratio > saturation_threshold {
            // Exponential penalty: (ratio - threshold) * scale factor
            // At 100% saturation with 0.85 threshold: (1.0 - 0.85) * 5.0 = 0.75
            let excess = saturation_ratio - saturation_threshold;
            let scale = 5.0; // Amplification factor
            penalty += (excess * scale).min(1.0);
        }

        // RTT trend penalty
        match metrics.rtt_trend {
            RttTrend::Increasing => {
                // Congestion signal - add penalty
                penalty += 0.3;
            }
            RttTrend::Decreasing => {
                // Path improving - small bonus (reduce penalty)
                penalty -= 0.1;
            }
            RttTrend::Stable => {
                // No change
            }
        }

        penalty.clamp(0.0, 1.0)
    }

    /// Compute costs with dynamic edge metrics for congestion-aware scheduling
    ///
    /// Similar to `compute`, but incorporates real-time throughput and RTT
    /// measurements to detect and avoid saturated paths.
    ///
    /// # Arguments
    /// * `state` - Static state buffers with chunk/edge information
    /// * `dynamic_metrics` - Map of edge index to dynamic metrics (throughput, RTT trend)
    pub fn compute_with_metrics(
        &mut self,
        state: &CpuStateBuffers,
        dynamic_metrics: &HashMap<EdgeIdx, DynamicEdgeMetrics>,
    ) {
        // Get actual counts from state
        let actual_chunks = state.chunk_count();
        let actual_edges = state.edge_count();

        // Reset costs in parallel
        self.costs.par_iter_mut().for_each(|c| *c = f32::INFINITY);
        self.valid_mask.par_iter_mut().for_each(|v| *v = false);

        // Capture config values for use in parallel closure
        let bandwidth_weight = self.config.bandwidth_weight;
        let rtt_weight = self.config.rtt_weight;
        let health_weight = self.config.health_weight;
        let load_weight = self.config.load_weight;
        let saturation_weight = self.config.saturation_weight;
        let saturation_threshold = self.config.saturation_threshold;
        let max_rtt_us = self.config.max_acceptable_rtt_us;
        let num_edges = self.num_edges;

        // Compute costs in parallel per chunk
        let results: Vec<Vec<(usize, f32)>> = (0..actual_chunks)
            .into_par_iter()
            .filter_map(|chunk_idx| {
                let chunk = state.get_chunk(chunk_idx as u32)?;
                let chunk_size = chunk.size;
                let replicas = state.get_replicas(chunk_idx as u32);

                let mut chunk_costs = Vec::new();

                for edge_idx in 0..actual_edges {
                    let edge_idx_typed = EdgeIdx(edge_idx as u32);

                    // Use slice::contains instead of HashSet (small replica sets, ~3 items)
                    if !replicas.contains(&edge_idx_typed) {
                        continue;
                    }

                    let edge = match state.get_edge(edge_idx_typed) {
                        Some(e) if e.can_accept_transfer() => e,
                        _ => continue,
                    };

                    // Compute individual cost components using static methods
                    let bandwidth_cost = Self::compute_bandwidth_cost_static(
                        chunk_size,
                        edge.available_bandwidth_bps,
                    );
                    let rtt_cost = Self::compute_rtt_cost_static(edge.rtt_us, max_rtt_us);
                    let health_cost = Self::compute_health_cost_static(edge.health_score_f32());
                    let load_cost =
                        Self::compute_load_cost_static(edge.active_transfers, edge.max_transfers);

                    // Compute saturation cost from dynamic metrics
                    let edge_metrics = dynamic_metrics.get(&edge_idx_typed);
                    let saturation_cost =
                        Self::compute_saturation_cost_static(edge_metrics, saturation_threshold);

                    // Weighted sum of all components
                    let total_cost = saturation_weight.mul_add(
                        saturation_cost,
                        load_weight.mul_add(
                            load_cost,
                            health_weight.mul_add(
                                health_cost,
                                bandwidth_weight.mul_add(bandwidth_cost, rtt_weight * rtt_cost),
                            ),
                        ),
                    );

                    let index = chunk_idx * num_edges + edge_idx;
                    chunk_costs.push((index, total_cost));
                }

                Some(chunk_costs)
            })
            .collect();

        // Apply results (single-threaded to avoid race conditions)
        for chunk_costs in results {
            for (index, cost) in chunk_costs {
                self.costs[index] = cost;
                self.valid_mask[index] = true;
            }
        }
    }

    /// Compute bandwidth cost component
    ///
    /// Returns normalized transfer time based on chunk size and bandwidth.
    /// Higher cost = slower transfer.
    fn compute_bandwidth_cost(&self, chunk_size: u32, bandwidth_bps: u64) -> f32 {
        if bandwidth_bps == 0 {
            return 1.0;
        }

        // Calculate transfer time in seconds
        let bits = f64::from(chunk_size) * 8.0;
        let transfer_time_sec = bits / bandwidth_bps as f64;

        // Normalize to 0-1 range (assume 10 seconds is max acceptable)

        (transfer_time_sec / 10.0).min(1.0) as f32
    }

    /// Compute RTT cost component
    ///
    /// Returns normalized RTT penalty. Higher RTT = higher cost.
    fn compute_rtt_cost(&self, rtt_us: u32) -> f32 {
        let rtt_ratio = rtt_us as f32 / self.config.max_acceptable_rtt_us as f32;
        rtt_ratio.min(1.0)
    }

    /// Compute health cost component
    ///
    /// Returns inverse of health score. Lower health = higher cost.
    fn compute_health_cost(&self, health_score: f32) -> f32 {
        1.0 - health_score.clamp(0.0, 1.0)
    }

    /// Compute load cost component
    ///
    /// Returns load ratio. More active transfers = higher cost.
    fn compute_load_cost(&self, active_transfers: u16, max_transfers: u16) -> f32 {
        if max_transfers == 0 {
            return 1.0;
        }
        f32::from(active_transfers) / f32::from(max_transfers)
    }

    /// Get cost for specific (chunk, edge) pair
    ///
    /// Returns None if the pair is invalid (edge doesn't have chunk replica).
    #[must_use]
    pub fn get_cost(&self, chunk_id: ChunkId, edge_idx: EdgeIdx) -> Option<f32> {
        let chunk_idx = chunk_id.0 as usize;
        let edge_idx = edge_idx.0 as usize;

        if chunk_idx >= self.num_chunks || edge_idx >= self.num_edges {
            return None;
        }

        let index = self.index(chunk_idx, edge_idx);
        if self.valid_mask[index] {
            Some(self.costs[index])
        } else {
            None
        }
    }

    /// Check if edge is valid source for chunk
    #[must_use]
    pub fn is_valid(&self, chunk_id: ChunkId, edge_idx: EdgeIdx) -> bool {
        let chunk_idx = chunk_id.0 as usize;
        let edge_idx = edge_idx.0 as usize;

        if chunk_idx >= self.num_chunks || edge_idx >= self.num_edges {
            return false;
        }

        let index = self.index(chunk_idx, edge_idx);
        self.valid_mask[index]
    }

    /// Get all valid edges for a chunk with their costs
    ///
    /// Returns edges sorted by cost (lowest first).
    #[must_use]
    pub fn get_valid_edges(&self, chunk_id: ChunkId) -> Vec<(EdgeIdx, f32)> {
        let chunk_idx = chunk_id.0 as usize;
        if chunk_idx >= self.num_chunks {
            return Vec::new();
        }

        // Pre-allocate with typical replication factor (3 replicas per chunk)
        let mut edges = Vec::with_capacity(self.num_edges.min(8));
        for edge_idx in 0..self.num_edges {
            let index = self.index(chunk_idx, edge_idx);
            if self.valid_mask[index] {
                edges.push((EdgeIdx(edge_idx as u32), self.costs[index]));
            }
        }

        // Sort by cost (ascending) - unstable sort is faster and order doesn't matter for equal costs
        edges.sort_unstable_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
        edges
    }

    /// Get matrix dimensions (`num_chunks`, `num_edges`)
    #[must_use]
    pub const fn dimensions(&self) -> (usize, usize) {
        (self.num_chunks, self.num_edges)
    }

    /// Resize the cost matrix
    ///
    /// Preserves existing costs where possible.
    pub fn resize(&mut self, num_chunks: usize, num_edges: usize) {
        let new_size = num_chunks * num_edges;
        self.costs.resize(new_size, f32::INFINITY);
        self.valid_mask.resize(new_size, false);
        self.num_chunks = num_chunks;
        self.num_edges = num_edges;
    }

    /// Get cost configuration
    #[must_use]
    pub const fn config(&self) -> &CostConfig {
        &self.config
    }

    /// Set cost for a specific (chunk, edge) pair
    ///
    /// Used by `ConstraintEvaluator` to apply multipliers after initial compute.
    /// Returns false if the pair is out of bounds or was invalid.
    pub fn set_cost(&mut self, chunk_idx: usize, edge_idx: usize, new_cost: f32) -> bool {
        if chunk_idx >= self.num_chunks || edge_idx >= self.num_edges {
            return false;
        }
        let index = self.index(chunk_idx, edge_idx);
        if !self.valid_mask[index] {
            return false;
        }
        self.costs[index] = new_cost;
        true
    }

    /// Mark a (chunk, edge) pair as invalid
    ///
    /// Used when constraints block an edge entirely.
    pub fn invalidate(&mut self, chunk_idx: usize, edge_idx: usize) -> bool {
        if chunk_idx >= self.num_chunks || edge_idx >= self.num_edges {
            return false;
        }
        let index = self.index(chunk_idx, edge_idx);
        self.valid_mask[index] = false;
        self.costs[index] = f32::INFINITY;
        true
    }

    /// Calculate flat index from 2D coordinates
    #[inline]
    const fn index(&self, chunk_idx: usize, edge_idx: usize) -> usize {
        chunk_idx * self.num_edges + edge_idx
    }
}

/// GPU-accelerated cost matrix (currently delegates to CPU)
///
/// Future implementation will use CUDA kernels for parallel computation.
pub struct CostMatrix {
    inner: CpuCostMatrix,
}

impl CostMatrix {
    /// Create a new GPU cost matrix
    #[must_use]
    pub fn new(num_chunks: usize, num_edges: usize, config: CostConfig) -> Self {
        Self {
            inner: CpuCostMatrix::new(num_chunks, num_edges, config),
        }
    }

    /// Compute costs (delegates to CPU)
    pub fn compute(&mut self, state: &CpuStateBuffers) {
        self.inner.compute(state);
    }

    /// Compute costs with dynamic metrics (delegates to CPU)
    ///
    /// Uses real-time throughput and RTT measurements for congestion-aware scheduling.
    pub fn compute_with_metrics(
        &mut self,
        state: &CpuStateBuffers,
        dynamic_metrics: &HashMap<EdgeIdx, DynamicEdgeMetrics>,
    ) {
        self.inner.compute_with_metrics(state, dynamic_metrics);
    }

    /// Get cost for specific pair
    #[must_use]
    pub fn get_cost(&self, chunk_id: ChunkId, edge_idx: EdgeIdx) -> Option<f32> {
        self.inner.get_cost(chunk_id, edge_idx)
    }

    /// Check if edge is valid source
    #[must_use]
    pub fn is_valid(&self, chunk_id: ChunkId, edge_idx: EdgeIdx) -> bool {
        self.inner.is_valid(chunk_id, edge_idx)
    }

    /// Get all valid edges for a chunk
    #[must_use]
    pub fn get_valid_edges(&self, chunk_id: ChunkId) -> Vec<(EdgeIdx, f32)> {
        self.inner.get_valid_edges(chunk_id)
    }

    /// Get dimensions
    #[must_use]
    pub const fn dimensions(&self) -> (usize, usize) {
        self.inner.dimensions()
    }

    /// Resize matrix
    pub fn resize(&mut self, num_chunks: usize, num_edges: usize) {
        self.inner.resize(num_chunks, num_edges);
    }

    /// Get configuration
    #[must_use]
    pub const fn config(&self) -> &CostConfig {
        self.inner.config()
    }

    /// Set cost for a specific (chunk, edge) pair
    pub fn set_cost(&mut self, chunk_idx: usize, edge_idx: usize, new_cost: f32) -> bool {
        self.inner.set_cost(chunk_idx, edge_idx, new_cost)
    }

    /// Mark a (chunk, edge) pair as invalid
    pub fn invalidate(&mut self, chunk_idx: usize, edge_idx: usize) -> bool {
        self.inner.invalidate(chunk_idx, edge_idx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ChunkState, EdgeStateGpu};

    fn make_test_state(num_chunks: usize, num_edges: usize) -> CpuStateBuffers {
        let mut state = CpuStateBuffers::new(num_chunks, num_edges);

        // Add chunks
        for i in 0..num_chunks {
            let mut hash = [0u8; 32];
            hash[0] = i as u8;
            let chunk = ChunkState::new(hash, 1024 * 1024, 128, 3);
            state.add_chunk(chunk).unwrap();
        }

        // Add edges
        for i in 0..num_edges {
            let edge = EdgeStateGpu::new(
                EdgeIdx(i as u32),
                1_000_000_000, // 1 Gbps
                10_000,        // 10ms RTT
                0.95,          // 95% health
                10,            // max 10 transfers
            );
            state.add_edge(i as u32, edge).unwrap();
        }

        state
    }

    #[test]
    fn test_cost_config_default() {
        let config = CostConfig::default();
        assert_eq!(config.bandwidth_weight, 0.3);
        assert_eq!(config.rtt_weight, 0.3);
        assert_eq!(config.health_weight, 0.2);
        assert_eq!(config.load_weight, 0.2);
        assert_eq!(config.max_acceptable_rtt_us, 100_000);
    }

    #[test]
    fn test_cost_config_new() {
        let config = CostConfig::new(0.4, 0.3, 0.2, 0.1);
        assert_eq!(config.bandwidth_weight, 0.4);
        assert_eq!(config.rtt_weight, 0.3);
        assert_eq!(config.health_weight, 0.2);
        assert_eq!(config.load_weight, 0.1);
    }

    #[test]
    fn test_cost_config_bandwidth_priority() {
        let config = CostConfig::bandwidth_priority();
        assert_eq!(config.bandwidth_weight, 0.6);
        assert!(config.bandwidth_weight > config.rtt_weight);
    }

    #[test]
    fn test_cost_config_latency_priority() {
        let config = CostConfig::latency_priority();
        assert_eq!(config.rtt_weight, 0.6);
        assert!(config.rtt_weight > config.bandwidth_weight);
    }

    #[test]
    fn test_cost_config_multi_path() {
        let config = CostConfig::multi_path();
        assert_eq!(config.diversity_weight, 0.15);
        assert_eq!(config.saturation_weight, 0.15);
        assert!(config.diversity_weight > 0.0);
        assert!(config.saturation_weight > 0.0);
        // Weights should still sum to approximately 1.0
        let sum = config.bandwidth_weight
            + config.rtt_weight
            + config.health_weight
            + config.load_weight
            + config.diversity_weight
            + config.saturation_weight;
        assert!((sum - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_cost_config_with_diversity_weight() {
        let config = CostConfig::default().with_diversity_weight(0.15);
        assert_eq!(config.diversity_weight, 0.15);

        // Test clamping
        let clamped = CostConfig::default().with_diversity_weight(1.5);
        assert_eq!(clamped.diversity_weight, 1.0);

        let clamped_neg = CostConfig::default().with_diversity_weight(-0.5);
        assert_eq!(clamped_neg.diversity_weight, 0.0);
    }

    #[test]
    fn test_cost_config_with_max_rtt() {
        let config = CostConfig::default().with_max_rtt(50_000);
        assert_eq!(config.max_acceptable_rtt_us, 50_000);
    }

    #[test]
    fn test_cpu_cost_matrix_creation() {
        let config = CostConfig::default();
        let matrix = CpuCostMatrix::new(100, 10, config);
        assert_eq!(matrix.dimensions(), (100, 10));
        assert_eq!(matrix.costs.len(), 1000);
        assert_eq!(matrix.valid_mask.len(), 1000);
    }

    #[test]
    fn test_cpu_cost_matrix_empty_state() {
        let config = CostConfig::default();
        let mut matrix = CpuCostMatrix::new(10, 5, config);
        let state = CpuStateBuffers::new(10, 5);

        matrix.compute(&state);

        // All should be invalid since no chunks/edges
        for chunk in 0..10 {
            for edge in 0..5 {
                assert!(!matrix.is_valid(ChunkId(chunk), EdgeIdx(edge as u32)));
            }
        }
    }

    #[test]
    fn test_cpu_cost_matrix_compute() {
        let config = CostConfig::default();
        let mut matrix = CpuCostMatrix::new(3, 2, config);
        let mut state = make_test_state(3, 2);

        // Add replicas: chunk 0 on edges 0,1; chunk 1 on edge 0
        state.add_replica(0, EdgeIdx(0));
        state.add_replica(0, EdgeIdx(1));
        state.add_replica(1, EdgeIdx(0));

        matrix.compute(&state);

        // Check valid pairs
        assert!(matrix.is_valid(ChunkId(0), EdgeIdx(0)));
        assert!(matrix.is_valid(ChunkId(0), EdgeIdx(1)));
        assert!(matrix.is_valid(ChunkId(1), EdgeIdx(0)));

        // Check invalid pairs
        assert!(!matrix.is_valid(ChunkId(1), EdgeIdx(1)));
        assert!(!matrix.is_valid(ChunkId(2), EdgeIdx(0)));
        assert!(!matrix.is_valid(ChunkId(2), EdgeIdx(1)));
    }

    #[test]
    fn test_cpu_cost_matrix_get_cost() {
        let config = CostConfig::default();
        let mut matrix = CpuCostMatrix::new(2, 2, config);
        let mut state = make_test_state(2, 2);

        state.add_replica(0, EdgeIdx(0));
        matrix.compute(&state);

        let cost = matrix.get_cost(ChunkId(0), EdgeIdx(0));
        assert!(cost.is_some());
        assert!(cost.unwrap() < f32::INFINITY);

        let invalid_cost = matrix.get_cost(ChunkId(0), EdgeIdx(1));
        assert!(invalid_cost.is_none());
    }

    #[test]
    fn test_cpu_cost_matrix_get_cost_out_of_bounds() {
        let config = CostConfig::default();
        let matrix = CpuCostMatrix::new(2, 2, config);

        assert!(matrix.get_cost(ChunkId(5), EdgeIdx(0)).is_none());
        assert!(matrix.get_cost(ChunkId(0), EdgeIdx(10)).is_none());
    }

    #[test]
    fn test_cpu_cost_matrix_get_valid_edges() {
        let config = CostConfig::default();
        let mut matrix = CpuCostMatrix::new(2, 3, config);
        let mut state = make_test_state(2, 3);

        state.add_replica(0, EdgeIdx(0));
        state.add_replica(0, EdgeIdx(1));
        state.add_replica(0, EdgeIdx(2));

        matrix.compute(&state);

        let edges = matrix.get_valid_edges(ChunkId(0));
        assert_eq!(edges.len(), 3);

        // Should be sorted by cost
        for i in 0..edges.len() - 1 {
            assert!(edges[i].1 <= edges[i + 1].1);
        }
    }

    #[test]
    fn test_cpu_cost_matrix_get_valid_edges_empty() {
        let config = CostConfig::default();
        let mut matrix = CpuCostMatrix::new(2, 2, config);
        let state = make_test_state(2, 2);

        matrix.compute(&state);

        let edges = matrix.get_valid_edges(ChunkId(0));
        assert_eq!(edges.len(), 0);
    }

    #[test]
    fn test_cpu_cost_matrix_resize() {
        let config = CostConfig::default();
        let mut matrix = CpuCostMatrix::new(2, 2, config);
        assert_eq!(matrix.dimensions(), (2, 2));

        matrix.resize(5, 3);
        assert_eq!(matrix.dimensions(), (5, 3));
        assert_eq!(matrix.costs.len(), 15);
        assert_eq!(matrix.valid_mask.len(), 15);
    }

    #[test]
    fn test_cpu_cost_matrix_config() {
        let config = CostConfig::bandwidth_priority();
        let matrix = CpuCostMatrix::new(2, 2, config.clone());
        assert_eq!(matrix.config().bandwidth_weight, 0.6);
    }

    #[test]
    fn test_bandwidth_cost_calculation() {
        let config = CostConfig::default();
        let matrix = CpuCostMatrix::new(1, 1, config);

        // Small chunk, high bandwidth = low cost
        let cost1 = matrix.compute_bandwidth_cost(1024, 1_000_000_000);
        assert!(cost1 < 0.1);

        // Large chunk, low bandwidth = higher cost
        let cost2 = matrix.compute_bandwidth_cost(10_000_000, 1_000_000);
        assert!(cost2 > cost1);

        // Zero bandwidth = max cost
        let cost3 = matrix.compute_bandwidth_cost(1024, 0);
        assert_eq!(cost3, 1.0);
    }

    #[test]
    fn test_rtt_cost_calculation() {
        let config = CostConfig::default();
        let matrix = CpuCostMatrix::new(1, 1, config);

        // Low RTT = low cost
        let cost1 = matrix.compute_rtt_cost(1_000); // 1ms
        assert!(cost1 < 0.1);

        // High RTT = high cost
        let cost2 = matrix.compute_rtt_cost(50_000); // 50ms
        assert!(cost2 > cost1);

        // Very high RTT = clamped to 1.0
        let cost3 = matrix.compute_rtt_cost(200_000); // 200ms
        assert_eq!(cost3, 1.0);
    }

    #[test]
    fn test_health_cost_calculation() {
        let config = CostConfig::default();
        let matrix = CpuCostMatrix::new(1, 1, config);

        // High health = low cost
        let cost1 = matrix.compute_health_cost(0.95);
        assert!((cost1 - 0.05).abs() < 0.01);

        // Low health = high cost
        let cost2 = matrix.compute_health_cost(0.2);
        assert!((cost2 - 0.8).abs() < 0.01);

        // Zero health = max cost
        let cost3 = matrix.compute_health_cost(0.0);
        assert_eq!(cost3, 1.0);
    }

    #[test]
    fn test_load_cost_calculation() {
        let config = CostConfig::default();
        let matrix = CpuCostMatrix::new(1, 1, config);

        // No load = zero cost
        let cost1 = matrix.compute_load_cost(0, 10);
        assert_eq!(cost1, 0.0);

        // Half load = 0.5 cost
        let cost2 = matrix.compute_load_cost(5, 10);
        assert_eq!(cost2, 0.5);

        // Full load = max cost
        let cost3 = matrix.compute_load_cost(10, 10);
        assert_eq!(cost3, 1.0);

        // Zero max = max cost
        let cost4 = matrix.compute_load_cost(5, 0);
        assert_eq!(cost4, 1.0);
    }

    #[test]
    fn test_cost_matrix_edge_offline() {
        let config = CostConfig::default();
        let mut matrix = CpuCostMatrix::new(1, 1, config);
        let mut state = CpuStateBuffers::new(1, 1);

        let chunk = ChunkState::new([0; 32], 1024, 128, 3);
        state.add_chunk(chunk).unwrap();

        let mut edge = EdgeStateGpu::new(EdgeIdx(0), 1_000_000_000, 10_000, 0.95, 10);
        edge.status = 0; // Offline
        state.add_edge(0, edge).unwrap();
        state.add_replica(0, EdgeIdx(0));

        matrix.compute(&state);

        // Should be invalid because edge is offline
        assert!(!matrix.is_valid(ChunkId(0), EdgeIdx(0)));
    }

    #[test]
    fn test_cost_matrix_edge_at_capacity() {
        let config = CostConfig::default();
        let mut matrix = CpuCostMatrix::new(1, 1, config);
        let mut state = CpuStateBuffers::new(1, 1);

        let chunk = ChunkState::new([0; 32], 1024, 128, 3);
        state.add_chunk(chunk).unwrap();

        let mut edge = EdgeStateGpu::new(EdgeIdx(0), 1_000_000_000, 10_000, 0.95, 5);
        edge.active_transfers = 5; // At capacity
        state.add_edge(0, edge).unwrap();
        state.add_replica(0, EdgeIdx(0));

        matrix.compute(&state);

        // Should be invalid because edge is at capacity
        assert!(!matrix.is_valid(ChunkId(0), EdgeIdx(0)));
    }

    #[test]
    fn test_cost_matrix_no_replica() {
        let config = CostConfig::default();
        let mut matrix = CpuCostMatrix::new(1, 1, config);
        let state = make_test_state(1, 1);

        // Don't add replica
        matrix.compute(&state);

        // Should be invalid because edge doesn't have replica
        assert!(!matrix.is_valid(ChunkId(0), EdgeIdx(0)));
    }

    #[test]
    fn test_gpu_cost_matrix_creation() {
        let config = CostConfig::default();
        let matrix = CostMatrix::new(10, 5, config);
        assert_eq!(matrix.dimensions(), (10, 5));
    }

    #[test]
    fn test_gpu_cost_matrix_compute() {
        let config = CostConfig::default();
        let mut matrix = CostMatrix::new(2, 2, config);
        let mut state = make_test_state(2, 2);

        state.add_replica(0, EdgeIdx(0));
        matrix.compute(&state);

        assert!(matrix.is_valid(ChunkId(0), EdgeIdx(0)));
        assert!(!matrix.is_valid(ChunkId(0), EdgeIdx(1)));
    }

    #[test]
    fn test_gpu_cost_matrix_get_cost() {
        let config = CostConfig::default();
        let mut matrix = CostMatrix::new(2, 2, config);
        let mut state = make_test_state(2, 2);

        state.add_replica(0, EdgeIdx(0));
        matrix.compute(&state);

        let cost = matrix.get_cost(ChunkId(0), EdgeIdx(0));
        assert!(cost.is_some());
    }

    #[test]
    fn test_gpu_cost_matrix_get_valid_edges() {
        let config = CostConfig::default();
        let mut matrix = CostMatrix::new(1, 3, config);
        let mut state = make_test_state(1, 3);

        state.add_replica(0, EdgeIdx(0));
        state.add_replica(0, EdgeIdx(1));

        matrix.compute(&state);

        let edges = matrix.get_valid_edges(ChunkId(0));
        assert_eq!(edges.len(), 2);
    }

    #[test]
    fn test_gpu_cost_matrix_resize() {
        let config = CostConfig::default();
        let mut matrix = CostMatrix::new(2, 2, config);
        matrix.resize(5, 3);
        assert_eq!(matrix.dimensions(), (5, 3));
    }

    #[test]
    fn test_gpu_cost_matrix_config() {
        let config = CostConfig::latency_priority();
        let matrix = CostMatrix::new(2, 2, config);
        assert_eq!(matrix.config().rtt_weight, 0.6);
    }

    #[test]
    fn test_set_cost() {
        let config = CostConfig::default();
        let mut matrix = CpuCostMatrix::new(2, 2, config);
        let mut state = make_test_state(2, 2);

        state.add_replica(0, EdgeIdx(0));
        matrix.compute(&state);

        // Get original cost
        let original = matrix.get_cost(ChunkId(0), EdgeIdx(0)).unwrap();

        // Set new cost
        assert!(matrix.set_cost(0, 0, 0.5));
        let new_cost = matrix.get_cost(ChunkId(0), EdgeIdx(0)).unwrap();
        assert!((new_cost - 0.5).abs() < 0.01);
        assert!(new_cost != original);
    }

    #[test]
    fn test_set_cost_invalid_pair() {
        let config = CostConfig::default();
        let mut matrix = CpuCostMatrix::new(2, 2, config);
        let state = make_test_state(2, 2);

        matrix.compute(&state);

        // No replica, so pair is invalid - set_cost should return false
        assert!(!matrix.set_cost(0, 0, 0.5));
    }

    #[test]
    fn test_set_cost_out_of_bounds() {
        let config = CostConfig::default();
        let mut matrix = CpuCostMatrix::new(2, 2, config);

        assert!(!matrix.set_cost(10, 0, 0.5));
        assert!(!matrix.set_cost(0, 10, 0.5));
    }

    #[test]
    fn test_invalidate() {
        let config = CostConfig::default();
        let mut matrix = CpuCostMatrix::new(2, 2, config);
        let mut state = make_test_state(2, 2);

        state.add_replica(0, EdgeIdx(0));
        matrix.compute(&state);

        // Initially valid
        assert!(matrix.is_valid(ChunkId(0), EdgeIdx(0)));

        // Invalidate
        assert!(matrix.invalidate(0, 0));

        // Now invalid
        assert!(!matrix.is_valid(ChunkId(0), EdgeIdx(0)));
        assert!(matrix.get_cost(ChunkId(0), EdgeIdx(0)).is_none());
    }

    #[test]
    fn test_invalidate_out_of_bounds() {
        let config = CostConfig::default();
        let mut matrix = CpuCostMatrix::new(2, 2, config);

        assert!(!matrix.invalidate(10, 0));
        assert!(!matrix.invalidate(0, 10));
    }

    #[test]
    fn test_gpu_matrix_set_cost() {
        let config = CostConfig::default();
        let mut matrix = CostMatrix::new(2, 2, config);
        let mut state = make_test_state(2, 2);

        state.add_replica(0, EdgeIdx(0));
        matrix.compute(&state);

        assert!(matrix.set_cost(0, 0, 0.75));
        let cost = matrix.get_cost(ChunkId(0), EdgeIdx(0)).unwrap();
        assert!((cost - 0.75).abs() < 0.01);
    }

    #[test]
    fn test_gpu_matrix_invalidate() {
        let config = CostConfig::default();
        let mut matrix = CostMatrix::new(2, 2, config);
        let mut state = make_test_state(2, 2);

        state.add_replica(0, EdgeIdx(0));
        matrix.compute(&state);

        assert!(matrix.is_valid(ChunkId(0), EdgeIdx(0)));
        assert!(matrix.invalidate(0, 0));
        assert!(!matrix.is_valid(ChunkId(0), EdgeIdx(0)));
    }

    // ============ Saturation / Dynamic Metrics Tests ============

    #[test]
    fn test_cost_config_saturation_weight() {
        let config = CostConfig::default();
        assert_eq!(config.saturation_weight, 0.0);
        assert_eq!(config.saturation_threshold, 0.85);

        let with_saturation = config.with_saturation_weight(0.25);
        assert_eq!(with_saturation.saturation_weight, 0.25);

        // Test clamping
        let clamped = CostConfig::default().with_saturation_weight(1.5);
        assert_eq!(clamped.saturation_weight, 1.0);
    }

    #[test]
    fn test_cost_config_saturation_threshold() {
        let config = CostConfig::default().with_saturation_threshold(0.75);
        assert_eq!(config.saturation_threshold, 0.75);

        // Test clamping
        let clamped = CostConfig::default().with_saturation_threshold(1.5);
        assert_eq!(clamped.saturation_threshold, 1.0);
    }

    #[test]
    fn test_cost_config_congestion_aware() {
        let config = CostConfig::congestion_aware();
        assert_eq!(config.saturation_weight, 0.25);
        assert_eq!(config.saturation_threshold, 0.80);
        // Weights should still sum to approximately 1.0
        let sum = config.bandwidth_weight
            + config.rtt_weight
            + config.health_weight
            + config.load_weight
            + config.diversity_weight
            + config.saturation_weight;
        assert!((sum - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_saturation_cost_no_metrics() {
        // No metrics = no penalty
        let cost = CpuCostMatrix::compute_saturation_cost_static(None, 0.85);
        assert_eq!(cost, 0.0);
    }

    #[test]
    fn test_saturation_cost_below_threshold() {
        use crate::PathThroughput;

        let metrics = DynamicEdgeMetrics::new(EdgeIdx(0), 1_000_000_000);
        // Default saturation_ratio is 0.0, well below threshold
        let cost = CpuCostMatrix::compute_saturation_cost_static(Some(&metrics), 0.85);
        assert_eq!(cost, 0.0);
    }

    #[test]
    fn test_saturation_cost_above_threshold() {
        use crate::PathThroughput;

        let mut metrics = DynamicEdgeMetrics::new(EdgeIdx(0), 1_000_000_000);
        // Set saturation above threshold (90%)
        metrics.throughput.saturation_ratio = 0.90;

        let cost = CpuCostMatrix::compute_saturation_cost_static(Some(&metrics), 0.85);
        // (0.90 - 0.85) * 5.0 = 0.25
        assert!((cost - 0.25).abs() < 0.01);
    }

    #[test]
    fn test_saturation_cost_fully_saturated() {
        let mut metrics = DynamicEdgeMetrics::new(EdgeIdx(0), 1_000_000_000);
        // Set saturation at 100%
        metrics.throughput.saturation_ratio = 1.0;

        let cost = CpuCostMatrix::compute_saturation_cost_static(Some(&metrics), 0.85);
        // (1.0 - 0.85) * 5.0 = 0.75
        assert!((cost - 0.75).abs() < 0.01);
    }

    #[test]
    fn test_saturation_cost_rtt_increasing() {
        let mut metrics = DynamicEdgeMetrics::new(EdgeIdx(0), 1_000_000_000);
        metrics.rtt_trend = RttTrend::Increasing;

        let cost = CpuCostMatrix::compute_saturation_cost_static(Some(&metrics), 0.85);
        // RTT increasing penalty: 0.3
        assert!((cost - 0.3).abs() < 0.01);
    }

    #[test]
    fn test_saturation_cost_rtt_decreasing() {
        let mut metrics = DynamicEdgeMetrics::new(EdgeIdx(0), 1_000_000_000);
        metrics.rtt_trend = RttTrend::Decreasing;

        let cost = CpuCostMatrix::compute_saturation_cost_static(Some(&metrics), 0.85);
        // RTT decreasing gives bonus (negative penalty clamped to 0)
        assert_eq!(cost, 0.0);
    }

    #[test]
    fn test_saturation_cost_combined_penalties() {
        let mut metrics = DynamicEdgeMetrics::new(EdgeIdx(0), 1_000_000_000);
        // High saturation + increasing RTT
        metrics.throughput.saturation_ratio = 0.95;
        metrics.rtt_trend = RttTrend::Increasing;

        let cost = CpuCostMatrix::compute_saturation_cost_static(Some(&metrics), 0.85);
        // (0.95 - 0.85) * 5.0 + 0.3 = 0.50 + 0.30 = 0.80
        assert!((cost - 0.80).abs() < 0.01);
    }

    #[test]
    fn test_saturation_cost_clamped_to_one() {
        let mut metrics = DynamicEdgeMetrics::new(EdgeIdx(0), 1_000_000_000);
        // Very high saturation would give > 1.0 but should be clamped
        metrics.throughput.saturation_ratio = 1.5; // artificially high
        metrics.rtt_trend = RttTrend::Increasing;

        let cost = CpuCostMatrix::compute_saturation_cost_static(Some(&metrics), 0.85);
        assert!(cost <= 1.0);
    }

    #[test]
    fn test_compute_with_metrics_no_metrics() {
        let config = CostConfig::multi_path(); // Has saturation_weight > 0
        let mut matrix = CpuCostMatrix::new(2, 2, config);
        let mut state = make_test_state(2, 2);

        state.add_replica(0, EdgeIdx(0));
        state.add_replica(0, EdgeIdx(1));

        // Empty metrics map
        let metrics: HashMap<EdgeIdx, DynamicEdgeMetrics> = HashMap::new();
        matrix.compute_with_metrics(&state, &metrics);

        // Should still compute valid costs
        assert!(matrix.is_valid(ChunkId(0), EdgeIdx(0)));
        assert!(matrix.is_valid(ChunkId(0), EdgeIdx(1)));
    }

    #[test]
    fn test_compute_with_metrics_saturated_edge() {
        let config = CostConfig::multi_path();
        let mut matrix = CpuCostMatrix::new(1, 2, config);
        let mut state = make_test_state(1, 2);

        state.add_replica(0, EdgeIdx(0));
        state.add_replica(0, EdgeIdx(1));

        // Edge 0 is saturated, Edge 1 is not
        let mut metrics = HashMap::new();
        let mut saturated = DynamicEdgeMetrics::new(EdgeIdx(0), 1_000_000_000);
        saturated.throughput.saturation_ratio = 0.95;
        saturated.rtt_trend = RttTrend::Increasing;
        metrics.insert(EdgeIdx(0), saturated);

        let healthy = DynamicEdgeMetrics::new(EdgeIdx(1), 1_000_000_000);
        metrics.insert(EdgeIdx(1), healthy);

        matrix.compute_with_metrics(&state, &metrics);

        let cost0 = matrix.get_cost(ChunkId(0), EdgeIdx(0)).unwrap();
        let cost1 = matrix.get_cost(ChunkId(0), EdgeIdx(1)).unwrap();

        // Saturated edge should have higher cost
        assert!(cost0 > cost1);
    }

    #[test]
    fn test_gpu_compute_with_metrics() {
        let config = CostConfig::multi_path();
        let mut matrix = CostMatrix::new(1, 2, config);
        let mut state = make_test_state(1, 2);

        state.add_replica(0, EdgeIdx(0));
        state.add_replica(0, EdgeIdx(1));

        let mut metrics = HashMap::new();
        let mut saturated = DynamicEdgeMetrics::new(EdgeIdx(0), 1_000_000_000);
        saturated.throughput.saturation_ratio = 0.95;
        metrics.insert(EdgeIdx(0), saturated);

        matrix.compute_with_metrics(&state, &metrics);

        assert!(matrix.is_valid(ChunkId(0), EdgeIdx(0)));
        assert!(matrix.is_valid(ChunkId(0), EdgeIdx(1)));
    }
}
