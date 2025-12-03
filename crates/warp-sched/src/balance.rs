//! Load balancing module for redistributing transfers from overloaded edges
//!
//! Prevents edge bottlenecks by analyzing load ratios and planning migrations
//! from overloaded edges to underloaded ones. Uses CPU implementation with
//! GPU wrapper that delegates to CPU for cudarc 0.18.1 compatibility.

use crate::{ChunkId, EdgeIdx, CpuStateBuffers};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Configuration for load balancing behavior
///
/// Controls thresholds and limits for rebalancing operations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LoadBalanceConfig {
    /// Load ratio above which an edge is considered overloaded (0.0-1.0)
    pub high_load_threshold: f32,
    /// Load ratio below which an edge can accept more transfers (0.0-1.0)
    pub low_load_threshold: f32,
    /// How often to run rebalancing in milliseconds
    pub rebalance_interval_ms: u64,
    /// Maximum number of migrations to perform per rebalance tick
    pub max_migrations_per_tick: usize,
}

impl Default for LoadBalanceConfig {
    fn default() -> Self {
        Self {
            high_load_threshold: 0.8,
            low_load_threshold: 0.3,
            rebalance_interval_ms: 1000,
            max_migrations_per_tick: 100,
        }
    }
}

impl LoadBalanceConfig {
    /// Create a new LoadBalanceConfig with custom values
    pub fn new(
        high_load_threshold: f32,
        low_load_threshold: f32,
        rebalance_interval_ms: u64,
        max_migrations_per_tick: usize,
    ) -> Self {
        Self {
            high_load_threshold: high_load_threshold.clamp(0.0, 1.0),
            low_load_threshold: low_load_threshold.clamp(0.0, 1.0),
            rebalance_interval_ms,
            max_migrations_per_tick,
        }
    }

    /// Validate configuration values
    pub fn validate(&self) -> Result<(), String> {
        if self.low_load_threshold >= self.high_load_threshold {
            return Err("low_load_threshold must be less than high_load_threshold".to_string());
        }
        if self.max_migrations_per_tick == 0 {
            return Err("max_migrations_per_tick must be greater than 0".to_string());
        }
        Ok(())
    }
}

/// A single rebalance operation to migrate a chunk
///
/// Represents moving one chunk from an overloaded edge to an underloaded one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RebalanceOp {
    /// Chunk to migrate
    pub chunk_id: ChunkId,
    /// Source edge (overloaded)
    pub from_edge: EdgeIdx,
    /// Destination edge (underloaded)
    pub to_edge: EdgeIdx,
    /// Expected improvement in load distribution (0.0-1.0)
    pub estimated_benefit: f32,
}

impl RebalanceOp {
    /// Create a new rebalance operation
    pub fn new(
        chunk_id: ChunkId,
        from_edge: EdgeIdx,
        to_edge: EdgeIdx,
        estimated_benefit: f32,
    ) -> Self {
        Self {
            chunk_id,
            from_edge,
            to_edge,
            estimated_benefit: estimated_benefit.max(0.0),
        }
    }
}

/// Collection of rebalance operations for a single planning cycle
///
/// Groups multiple operations together with generation tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebalancePlan {
    /// Vector of operations to perform
    pub operations: Vec<RebalanceOp>,
    /// Generation number for versioning
    pub generation: u64,
    /// Timestamp in milliseconds since epoch
    pub timestamp_ms: u64,
}

impl RebalancePlan {
    /// Create a new rebalance plan
    pub fn new(operations: Vec<RebalanceOp>, generation: u64) -> Self {
        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::ZERO)
            .as_millis() as u64;
        Self {
            operations,
            generation,
            timestamp_ms,
        }
    }

    /// Create an empty plan
    pub fn empty(generation: u64) -> Self {
        Self::new(Vec::new(), generation)
    }

    /// Get number of operations in the plan
    #[inline]
    pub fn len(&self) -> usize {
        self.operations.len()
    }

    /// Check if plan is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }

    /// Add an operation to the plan
    pub fn push(&mut self, operation: RebalanceOp) {
        self.operations.push(operation);
    }

    /// Sort operations by estimated benefit (highest first)
    pub fn sort_by_benefit(&mut self) {
        self.operations.sort_by(|a, b| {
            b.estimated_benefit.partial_cmp(&a.estimated_benefit).unwrap_or(std::cmp::Ordering::Equal)
        });
    }
}

/// Load metrics for a single edge
///
/// Contains calculated load information for balancing decisions.
#[derive(Debug, Clone, PartialEq)]
pub struct LoadMetrics {
    /// Edge index
    pub edge_idx: EdgeIdx,
    /// Load ratio: active_transfers / max_transfers (0.0-1.0)
    pub load_ratio: f32,
    /// Number of chunks waiting in queue
    pub queue_depth: u32,
    /// True if load_ratio > high_load_threshold
    pub is_overloaded: bool,
    /// True if load_ratio < low_load_threshold
    pub is_underloaded: bool,
}

impl LoadMetrics {
    /// Create new load metrics
    pub fn new(
        edge_idx: EdgeIdx,
        load_ratio: f32,
        queue_depth: u32,
        is_overloaded: bool,
        is_underloaded: bool,
    ) -> Self {
        Self {
            edge_idx,
            load_ratio,
            queue_depth,
            is_overloaded,
            is_underloaded,
        }
    }

    /// Check if edge is balanced (not over or under loaded)
    #[inline]
    pub fn is_balanced(&self) -> bool {
        !self.is_overloaded && !self.is_underloaded
    }
}

/// CPU implementation of load balancing
///
/// Analyzes edge load and creates rebalancing plans to redistribute transfers.
pub struct CpuLoadBalancer {
    config: LoadBalanceConfig,
    generation: u64,
}

impl CpuLoadBalancer {
    /// Create a new CPU load balancer
    pub fn new(config: LoadBalanceConfig) -> Self {
        Self {
            config,
            generation: 0,
        }
    }

    /// Get the current configuration
    pub fn config(&self) -> &LoadBalanceConfig {
        &self.config
    }

    /// Analyze load metrics for all edges
    ///
    /// Returns load metrics for each edge in the state.
    pub fn analyze(&self, state: &CpuStateBuffers) -> Vec<LoadMetrics> {
        let mut metrics = Vec::new();

        for i in 0..state.edge_count() {
            if let Some(edge) = state.get_edge(EdgeIdx(i as u32)) {
                let load_ratio = if edge.max_transfers > 0 {
                    edge.active_transfers as f32 / edge.max_transfers as f32
                } else {
                    0.0
                };

                let is_overloaded = load_ratio > self.config.high_load_threshold;
                let is_underloaded = load_ratio < self.config.low_load_threshold;

                metrics.push(LoadMetrics {
                    edge_idx: EdgeIdx(i as u32),
                    load_ratio,
                    queue_depth: 0, // Would track queue depth from state
                    is_overloaded,
                    is_underloaded,
                });
            }
        }

        metrics
    }

    /// Find all overloaded edges
    ///
    /// Returns edge indices where load_ratio > high_load_threshold.
    pub fn find_overloaded(&self, state: &CpuStateBuffers) -> Vec<EdgeIdx> {
        self.analyze(state)
            .into_iter()
            .filter(|m| m.is_overloaded)
            .map(|m| m.edge_idx)
            .collect()
    }

    /// Find all underloaded edges
    ///
    /// Returns edge indices where load_ratio < low_load_threshold.
    pub fn find_underloaded(&self, state: &CpuStateBuffers) -> Vec<EdgeIdx> {
        self.analyze(state)
            .into_iter()
            .filter(|m| m.is_underloaded)
            .map(|m| m.edge_idx)
            .collect()
    }

    /// Plan rebalance operations
    ///
    /// Creates a plan to migrate chunks from overloaded to underloaded edges.
    pub fn plan_rebalance(&mut self, state: &CpuStateBuffers) -> RebalancePlan {
        let overloaded = self.find_overloaded(state);
        let underloaded = self.find_underloaded(state);

        if overloaded.is_empty() || underloaded.is_empty() {
            self.generation += 1;
            return RebalancePlan::empty(self.generation);
        }

        let mut operations = Vec::new();
        let mut edge_loads: HashMap<EdgeIdx, f32> = HashMap::new();

        // Initialize edge load map
        for metrics in self.analyze(state) {
            edge_loads.insert(metrics.edge_idx, metrics.load_ratio);
        }

        // For each overloaded edge, find chunks to migrate
        for from_edge in overloaded {
            if operations.len() >= self.config.max_migrations_per_tick {
                break;
            }

            let from_load = edge_loads.get(&from_edge).copied().unwrap_or(0.0);

            // Find candidate chunks on this edge (simplified - would use replica map)
            for chunk_id in 0..state.chunk_count() {
                if operations.len() >= self.config.max_migrations_per_tick {
                    break;
                }

                // Find best underloaded edge for this chunk
                if let Some(to_edge) = underloaded.iter().min_by_key(|&&edge| {
                    let load = edge_loads.get(&edge).copied().unwrap_or(0.0);
                    (load * 1000.0) as u32
                }) {
                    let to_load = edge_loads.get(to_edge).copied().unwrap_or(0.0);

                    // Calculate estimated benefit
                    let load_diff = from_load - to_load;
                    let estimated_benefit = load_diff.max(0.0);

                    if estimated_benefit > 0.0 {
                        operations.push(RebalanceOp::new(
                            ChunkId(chunk_id as u64),
                            from_edge,
                            *to_edge,
                            estimated_benefit,
                        ));

                        // Update simulated loads
                        let transfer_weight = 1.0 / state.edge_count().max(1) as f32;
                        if let Some(load) = edge_loads.get_mut(&from_edge) {
                            *load -= transfer_weight;
                        }
                        if let Some(load) = edge_loads.get_mut(to_edge) {
                            *load += transfer_weight;
                        }
                    }
                }
            }
        }

        self.generation += 1;
        let mut plan = RebalancePlan::new(operations, self.generation);
        plan.sort_by_benefit();

        // Limit to max_migrations_per_tick
        if plan.operations.len() > self.config.max_migrations_per_tick {
            plan.operations.truncate(self.config.max_migrations_per_tick);
        }

        plan
    }
}

/// GPU-accelerated load balancer (delegates to CPU)
///
/// Provides the same API as CpuLoadBalancer but designed for future GPU
/// implementation using cudarc patterns.
pub struct LoadBalancer {
    inner: CpuLoadBalancer,
}

impl LoadBalancer {
    /// Create a new GPU load balancer (delegates to CPU)
    pub fn new(config: LoadBalanceConfig) -> Self {
        Self {
            inner: CpuLoadBalancer::new(config),
        }
    }

    /// Get the current configuration
    pub fn config(&self) -> &LoadBalanceConfig {
        self.inner.config()
    }

    /// Analyze load metrics (delegates to CPU)
    pub fn analyze(&self, state: &CpuStateBuffers) -> Vec<LoadMetrics> {
        self.inner.analyze(state)
    }

    /// Plan rebalance operations (delegates to CPU)
    pub fn plan_rebalance(&mut self, state: &CpuStateBuffers) -> RebalancePlan {
        self.inner.plan_rebalance(state)
    }

    /// Find overloaded edges (delegates to CPU)
    pub fn find_overloaded(&self, state: &CpuStateBuffers) -> Vec<EdgeIdx> {
        self.inner.find_overloaded(state)
    }

    /// Find underloaded edges (delegates to CPU)
    pub fn find_underloaded(&self, state: &CpuStateBuffers) -> Vec<EdgeIdx> {
        self.inner.find_underloaded(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ChunkState, EdgeStateGpu};

    fn make_chunk_state(id: u8) -> ChunkState {
        ChunkState::new([id; 32], 1024, 128, 3)
    }

    fn make_edge_state(idx: u32, active: u16, max: u16) -> EdgeStateGpu {
        let mut edge = EdgeStateGpu::new(EdgeIdx(idx), 1_000_000_000, 10_000, 0.95, max);
        edge.active_transfers = active;
        edge
    }

    #[test]
    fn test_config_default() {
        let config = LoadBalanceConfig::default();
        assert_eq!(config.high_load_threshold, 0.8);
        assert_eq!(config.low_load_threshold, 0.3);
        assert_eq!(config.rebalance_interval_ms, 1000);
        assert_eq!(config.max_migrations_per_tick, 100);
    }

    #[test]
    fn test_config_new() {
        let config = LoadBalanceConfig::new(0.9, 0.2, 2000, 50);
        assert_eq!(config.high_load_threshold, 0.9);
        assert_eq!(config.low_load_threshold, 0.2);
        assert_eq!(config.rebalance_interval_ms, 2000);
        assert_eq!(config.max_migrations_per_tick, 50);
    }

    #[test]
    fn test_config_clamping() {
        let config = LoadBalanceConfig::new(1.5, -0.5, 100, 10);
        assert_eq!(config.high_load_threshold, 1.0);
        assert_eq!(config.low_load_threshold, 0.0);
    }

    #[test]
    fn test_config_validate() {
        let config = LoadBalanceConfig::new(0.8, 0.3, 1000, 100);
        assert!(config.validate().is_ok());

        let invalid1 = LoadBalanceConfig::new(0.3, 0.8, 1000, 100);
        assert!(invalid1.validate().is_err());

        let invalid2 = LoadBalanceConfig::new(0.8, 0.3, 1000, 0);
        assert!(invalid2.validate().is_err());
    }

    #[test]
    fn test_config_serialization() {
        let config = LoadBalanceConfig::default();
        let serialized = rmp_serde::to_vec(&config).unwrap();
        let deserialized: LoadBalanceConfig = rmp_serde::from_slice(&serialized).unwrap();
        assert_eq!(config, deserialized);
    }

    #[test]
    fn test_rebalance_op_new() {
        let op = RebalanceOp::new(ChunkId(42), EdgeIdx(1), EdgeIdx(2), 0.5);
        assert_eq!(op.chunk_id.0, 42);
        assert_eq!(op.from_edge.0, 1);
        assert_eq!(op.to_edge.0, 2);
        assert_eq!(op.estimated_benefit, 0.5);
    }

    #[test]
    fn test_rebalance_op_negative_benefit() {
        let op = RebalanceOp::new(ChunkId(42), EdgeIdx(1), EdgeIdx(2), -0.5);
        assert_eq!(op.estimated_benefit, 0.0);
    }

    #[test]
    fn test_rebalance_op_serialization() {
        let op = RebalanceOp::new(ChunkId(42), EdgeIdx(1), EdgeIdx(2), 0.5);
        let serialized = rmp_serde::to_vec(&op).unwrap();
        let deserialized: RebalanceOp = rmp_serde::from_slice(&serialized).unwrap();
        assert_eq!(op, deserialized);
    }

    #[test]
    fn test_rebalance_plan_new() {
        let ops = vec![
            RebalanceOp::new(ChunkId(1), EdgeIdx(0), EdgeIdx(1), 0.3),
            RebalanceOp::new(ChunkId(2), EdgeIdx(0), EdgeIdx(1), 0.5),
        ];
        let plan = RebalancePlan::new(ops.clone(), 42);
        assert_eq!(plan.generation, 42);
        assert_eq!(plan.len(), 2);
        assert!(!plan.is_empty());
    }

    #[test]
    fn test_rebalance_plan_empty() {
        let plan = RebalancePlan::empty(10);
        assert_eq!(plan.generation, 10);
        assert_eq!(plan.len(), 0);
        assert!(plan.is_empty());
    }

    #[test]
    fn test_rebalance_plan_push() {
        let mut plan = RebalancePlan::empty(1);
        assert_eq!(plan.len(), 0);
        plan.push(RebalanceOp::new(ChunkId(1), EdgeIdx(0), EdgeIdx(1), 0.3));
        assert_eq!(plan.len(), 1);
    }

    #[test]
    fn test_rebalance_plan_sort_by_benefit() {
        let ops = vec![
            RebalanceOp::new(ChunkId(1), EdgeIdx(0), EdgeIdx(1), 0.3),
            RebalanceOp::new(ChunkId(2), EdgeIdx(0), EdgeIdx(1), 0.7),
            RebalanceOp::new(ChunkId(3), EdgeIdx(0), EdgeIdx(1), 0.5),
        ];
        let mut plan = RebalancePlan::new(ops, 1);
        plan.sort_by_benefit();
        assert_eq!(plan.operations[0].estimated_benefit, 0.7);
        assert_eq!(plan.operations[1].estimated_benefit, 0.5);
        assert_eq!(plan.operations[2].estimated_benefit, 0.3);
    }

    #[test]
    fn test_rebalance_plan_serialization() {
        let ops = vec![RebalanceOp::new(ChunkId(1), EdgeIdx(0), EdgeIdx(1), 0.3)];
        let plan = RebalancePlan::new(ops, 1);
        let serialized = rmp_serde::to_vec(&plan).unwrap();
        let deserialized: RebalancePlan = rmp_serde::from_slice(&serialized).unwrap();
        assert_eq!(plan.generation, deserialized.generation);
        assert_eq!(plan.operations.len(), deserialized.operations.len());
    }

    #[test]
    fn test_load_metrics_new() {
        let metrics = LoadMetrics::new(EdgeIdx(5), 0.6, 10, false, false);
        assert_eq!(metrics.edge_idx.0, 5);
        assert_eq!(metrics.load_ratio, 0.6);
        assert_eq!(metrics.queue_depth, 10);
        assert!(!metrics.is_overloaded);
        assert!(!metrics.is_underloaded);
    }

    #[test]
    fn test_load_metrics_is_balanced() {
        let balanced = LoadMetrics::new(EdgeIdx(0), 0.5, 0, false, false);
        assert!(balanced.is_balanced());

        let overloaded = LoadMetrics::new(EdgeIdx(0), 0.9, 0, true, false);
        assert!(!overloaded.is_balanced());

        let underloaded = LoadMetrics::new(EdgeIdx(0), 0.1, 0, false, true);
        assert!(!underloaded.is_balanced());
    }

    #[test]
    fn test_cpu_balancer_new() {
        let config = LoadBalanceConfig::default();
        let balancer = CpuLoadBalancer::new(config.clone());
        assert_eq!(balancer.config(), &config);
    }

    #[test]
    fn test_cpu_balancer_analyze_empty() {
        let config = LoadBalanceConfig::default();
        let balancer = CpuLoadBalancer::new(config);
        let state = CpuStateBuffers::new(100, 10);
        let metrics = balancer.analyze(&state);
        assert_eq!(metrics.len(), 0);
    }

    #[test]
    fn test_cpu_balancer_analyze() {
        let config = LoadBalanceConfig::default();
        let balancer = CpuLoadBalancer::new(config);
        let mut state = CpuStateBuffers::new(100, 10);

        // Add edges with different loads
        state.add_edge(0, make_edge_state(0, 9, 10)).unwrap(); // 90% - overloaded
        state.add_edge(1, make_edge_state(1, 2, 10)).unwrap(); // 20% - underloaded
        state.add_edge(2, make_edge_state(2, 5, 10)).unwrap(); // 50% - balanced

        let metrics = balancer.analyze(&state);
        assert_eq!(metrics.len(), 3);

        assert!((metrics[0].load_ratio - 0.9).abs() < 0.01);
        assert!(metrics[0].is_overloaded);
        assert!(!metrics[0].is_underloaded);

        assert!((metrics[1].load_ratio - 0.2).abs() < 0.01);
        assert!(!metrics[1].is_overloaded);
        assert!(metrics[1].is_underloaded);

        assert!((metrics[2].load_ratio - 0.5).abs() < 0.01);
        assert!(!metrics[2].is_overloaded);
        assert!(!metrics[2].is_underloaded);
    }

    #[test]
    fn test_cpu_balancer_find_overloaded() {
        let config = LoadBalanceConfig::default();
        let balancer = CpuLoadBalancer::new(config);
        let mut state = CpuStateBuffers::new(100, 10);

        state.add_edge(0, make_edge_state(0, 9, 10)).unwrap(); // 90% - overloaded
        state.add_edge(1, make_edge_state(1, 2, 10)).unwrap(); // 20%
        state.add_edge(2, make_edge_state(2, 8, 10)).unwrap(); // 80% - not quite overloaded

        let overloaded = balancer.find_overloaded(&state);
        assert_eq!(overloaded.len(), 1);
        assert_eq!(overloaded[0].0, 0);
    }

    #[test]
    fn test_cpu_balancer_find_underloaded() {
        let config = LoadBalanceConfig::default();
        let balancer = CpuLoadBalancer::new(config);
        let mut state = CpuStateBuffers::new(100, 10);

        state.add_edge(0, make_edge_state(0, 9, 10)).unwrap(); // 90%
        state.add_edge(1, make_edge_state(1, 2, 10)).unwrap(); // 20% - underloaded
        state.add_edge(2, make_edge_state(2, 1, 10)).unwrap(); // 10% - underloaded

        let underloaded = balancer.find_underloaded(&state);
        assert_eq!(underloaded.len(), 2);
    }

    #[test]
    fn test_cpu_balancer_plan_rebalance_no_imbalance() {
        let config = LoadBalanceConfig::default();
        let mut balancer = CpuLoadBalancer::new(config);
        let mut state = CpuStateBuffers::new(100, 10);

        // All edges balanced
        state.add_edge(0, make_edge_state(0, 5, 10)).unwrap();
        state.add_edge(1, make_edge_state(1, 5, 10)).unwrap();
        state.add_edge(2, make_edge_state(2, 5, 10)).unwrap();

        let plan = balancer.plan_rebalance(&state);
        assert!(plan.is_empty());
        assert_eq!(plan.generation, 1);
    }

    #[test]
    fn test_cpu_balancer_plan_rebalance_with_imbalance() {
        let config = LoadBalanceConfig::default();
        let mut balancer = CpuLoadBalancer::new(config);
        let mut state = CpuStateBuffers::new(100, 10);

        // Add edges with imbalance
        state.add_edge(0, make_edge_state(0, 9, 10)).unwrap(); // Overloaded
        state.add_edge(1, make_edge_state(1, 1, 10)).unwrap(); // Underloaded

        // Add some chunks
        state.add_chunk(make_chunk_state(1)).unwrap();
        state.add_chunk(make_chunk_state(2)).unwrap();

        let plan = balancer.plan_rebalance(&state);
        assert!(!plan.is_empty());
        assert_eq!(plan.generation, 1);
    }

    #[test]
    fn test_cpu_balancer_plan_rebalance_max_migrations() {
        let config = LoadBalanceConfig::new(0.8, 0.3, 1000, 5);
        let mut balancer = CpuLoadBalancer::new(config);
        let mut state = CpuStateBuffers::new(100, 10);

        state.add_edge(0, make_edge_state(0, 9, 10)).unwrap();
        state.add_edge(1, make_edge_state(1, 1, 10)).unwrap();

        // Add many chunks
        for i in 0..20 {
            state.add_chunk(make_chunk_state(i)).unwrap();
        }

        let plan = balancer.plan_rebalance(&state);
        assert!(plan.len() <= 5);
    }

    #[test]
    fn test_cpu_balancer_plan_rebalance_sorted() {
        let config = LoadBalanceConfig::default();
        let mut balancer = CpuLoadBalancer::new(config);
        let mut state = CpuStateBuffers::new(100, 10);

        state.add_edge(0, make_edge_state(0, 9, 10)).unwrap();
        state.add_edge(1, make_edge_state(1, 1, 10)).unwrap();

        for i in 0..5 {
            state.add_chunk(make_chunk_state(i)).unwrap();
        }

        let plan = balancer.plan_rebalance(&state);
        if plan.len() > 1 {
            for i in 0..plan.len() - 1 {
                assert!(plan.operations[i].estimated_benefit >= plan.operations[i + 1].estimated_benefit);
            }
        }
    }

    #[test]
    fn test_cpu_balancer_analyze_zero_max_transfers() {
        let config = LoadBalanceConfig::default();
        let balancer = CpuLoadBalancer::new(config);
        let mut state = CpuStateBuffers::new(100, 10);

        state.add_edge(0, make_edge_state(0, 0, 0)).unwrap();

        let metrics = balancer.analyze(&state);
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].load_ratio, 0.0);
    }

    #[test]
    fn test_cpu_balancer_generation_increment() {
        let config = LoadBalanceConfig::default();
        let mut balancer = CpuLoadBalancer::new(config);
        let mut state = CpuStateBuffers::new(100, 10);

        state.add_edge(0, make_edge_state(0, 5, 10)).unwrap();

        let plan1 = balancer.plan_rebalance(&state);
        assert_eq!(plan1.generation, 1);

        let plan2 = balancer.plan_rebalance(&state);
        assert_eq!(plan2.generation, 2);
    }

    #[test]
    fn test_gpu_balancer_new() {
        let config = LoadBalanceConfig::default();
        let balancer = LoadBalancer::new(config.clone());
        assert_eq!(balancer.config(), &config);
    }

    #[test]
    fn test_gpu_balancer_delegates_analyze() {
        let config = LoadBalanceConfig::default();
        let balancer = LoadBalancer::new(config);
        let mut state = CpuStateBuffers::new(100, 10);

        state.add_edge(0, make_edge_state(0, 9, 10)).unwrap();
        state.add_edge(1, make_edge_state(1, 2, 10)).unwrap();

        let metrics = balancer.analyze(&state);
        assert_eq!(metrics.len(), 2);
        assert!(metrics[0].is_overloaded);
        assert!(metrics[1].is_underloaded);
    }

    #[test]
    fn test_gpu_balancer_delegates_find_overloaded() {
        let config = LoadBalanceConfig::default();
        let balancer = LoadBalancer::new(config);
        let mut state = CpuStateBuffers::new(100, 10);

        state.add_edge(0, make_edge_state(0, 9, 10)).unwrap();

        let overloaded = balancer.find_overloaded(&state);
        assert_eq!(overloaded.len(), 1);
    }

    #[test]
    fn test_gpu_balancer_delegates_find_underloaded() {
        let config = LoadBalanceConfig::default();
        let balancer = LoadBalancer::new(config);
        let mut state = CpuStateBuffers::new(100, 10);

        state.add_edge(0, make_edge_state(0, 1, 10)).unwrap();

        let underloaded = balancer.find_underloaded(&state);
        assert_eq!(underloaded.len(), 1);
    }

    #[test]
    fn test_gpu_balancer_delegates_plan_rebalance() {
        let config = LoadBalanceConfig::default();
        let mut balancer = LoadBalancer::new(config);
        let mut state = CpuStateBuffers::new(100, 10);

        state.add_edge(0, make_edge_state(0, 9, 10)).unwrap();
        state.add_edge(1, make_edge_state(1, 1, 10)).unwrap();
        state.add_chunk(make_chunk_state(1)).unwrap();

        let plan = balancer.plan_rebalance(&state);
        assert!(!plan.is_empty());
    }

    #[test]
    fn test_load_metrics_extreme_values() {
        let metrics = LoadMetrics::new(EdgeIdx(0), 1.0, u32::MAX, true, false);
        assert_eq!(metrics.load_ratio, 1.0);
        assert_eq!(metrics.queue_depth, u32::MAX);
        assert!(metrics.is_overloaded);
        assert!(!metrics.is_underloaded);
    }

    #[test]
    fn test_rebalance_plan_timestamp() {
        let plan = RebalancePlan::empty(1);
        assert!(plan.timestamp_ms > 0);
    }

    #[test]
    fn test_multiple_edges_same_load() {
        let config = LoadBalanceConfig::default();
        let balancer = CpuLoadBalancer::new(config);
        let mut state = CpuStateBuffers::new(100, 10);

        state.add_edge(0, make_edge_state(0, 5, 10)).unwrap();
        state.add_edge(1, make_edge_state(1, 5, 10)).unwrap();
        state.add_edge(2, make_edge_state(2, 5, 10)).unwrap();

        let metrics = balancer.analyze(&state);
        assert_eq!(metrics.len(), 3);
        for m in metrics {
            assert_eq!(m.load_ratio, 0.5);
            assert!(m.is_balanced());
        }
    }
}
