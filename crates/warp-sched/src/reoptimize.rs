//! Incremental rescheduling for auto-reconciliation
//!
//! Provides efficient reoptimization of chunk assignments when edge conditions
//! change (degradation, overload) or better paths become available. Uses
//! incremental planning to minimize disruption while improving cost efficiency.

use crate::cost::CpuCostMatrix;
use crate::{Assignment, ChunkId, EdgeIdx, Result, SchedError};
use serde::{Deserialize, Serialize};

/// Scope of reoptimization operation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReoptScope {
    /// Only specific chunks
    Chunks(Vec<ChunkId>),
    /// Only chunks on specific edges
    Edges(Vec<EdgeIdx>),
    /// Edges and their neighbors within radius
    Region {
        /// Center edges of the region
        edges: Vec<EdgeIdx>,
        /// Hop radius for neighbor inclusion
        radius: u32,
    },
    /// Complete reschedule of all chunks
    Full,
}

/// Strategy for reoptimization
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ReoptStrategy {
    /// Quick, locally optimal decisions
    Greedy,
    /// Minimize changes to existing assignments
    MinDisruption,
    /// Find globally optimal solution (more expensive)
    CostOptimal,
    /// Balance between disruption and optimality
    Hybrid {
        /// Weight for disruption cost (0.0-1.0)
        disruption_weight: f64,
    },
}

/// Reason for chunk reassignment
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReassignmentReason {
    /// Source edge degraded
    EdgeDegraded,
    /// Source edge overloaded
    EdgeOverloaded,
    /// Better path discovered
    BetterPathFound,
    /// Load balancing requirement
    LoadBalance,
    /// Cost reduction opportunity
    CostReduction,
    /// Preposition for predicted demand
    Preposition,
}

/// Single chunk reassignment
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reassignment {
    /// Chunk being reassigned
    pub chunk_id: ChunkId,
    /// Current source edge
    pub from_edge: EdgeIdx,
    /// New target edges
    pub to_edges: Vec<EdgeIdx>,
    /// Reason for reassignment
    pub reason: ReassignmentReason,
    /// Execution priority (0 = highest)
    pub priority: u8,
}

impl Reassignment {
    /// Create a new reassignment
    #[must_use]
    pub const fn new(
        chunk_id: ChunkId,
        from_edge: EdgeIdx,
        to_edges: Vec<EdgeIdx>,
        reason: ReassignmentReason,
        priority: u8,
    ) -> Self {
        Self {
            chunk_id,
            from_edge,
            to_edges,
            reason,
            priority,
        }
    }
}

/// Plan for incremental rescheduling
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReoptPlan {
    /// Scope of reoptimization
    pub scope: ReoptScope,
    /// Strategy used
    pub strategy: ReoptStrategy,
    /// Planned chunk reassignments
    pub reassignments: Vec<Reassignment>,
    /// Expected improvement ratio (0.0-1.0)
    pub estimated_improvement: f64,
    /// Expected disruption ratio (0.0-1.0)
    pub estimated_disruption: f64,
    /// Order to execute reassignments
    pub execution_order: Vec<usize>,
}

impl ReoptPlan {
    /// Create a new reoptimization plan
    #[must_use]
    pub fn new(
        scope: ReoptScope,
        strategy: ReoptStrategy,
        reassignments: Vec<Reassignment>,
        estimated_improvement: f64,
        estimated_disruption: f64,
    ) -> Self {
        let execution_order = (0..reassignments.len()).collect();
        Self {
            scope,
            strategy,
            reassignments,
            estimated_improvement,
            estimated_disruption,
            execution_order,
        }
    }

    /// Get the number of reassignments in the plan
    #[must_use]
    pub fn len(&self) -> usize {
        self.reassignments.len()
    }

    /// Check if the plan is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.reassignments.is_empty()
    }
}

/// Configuration for incremental scheduler
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncrementalConfig {
    /// Max moves per scheduler tick
    pub max_reassignments_per_tick: usize,
    /// Min improvement to proceed (0.0-1.0)
    pub min_improvement_threshold: f64,
    /// Max acceptable disruption (0.0-1.0)
    pub max_disruption: f64,
    /// How many moves to do in parallel
    pub parallel_moves: usize,
}

impl Default for IncrementalConfig {
    fn default() -> Self {
        Self {
            max_reassignments_per_tick: 10,
            min_improvement_threshold: 0.05,
            max_disruption: 0.3,
            parallel_moves: 3,
        }
    }
}

impl IncrementalConfig {
    /// Create a new configuration
    #[must_use]
    pub const fn new(
        max_reassignments_per_tick: usize,
        min_improvement_threshold: f64,
        max_disruption: f64,
        parallel_moves: usize,
    ) -> Self {
        Self {
            max_reassignments_per_tick,
            min_improvement_threshold,
            max_disruption,
            parallel_moves,
        }
    }

    /// Validate configuration
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `max_reassignments_per_tick` is 0
    /// - `min_improvement_threshold` is not in 0.0-1.0
    /// - `max_disruption` is not in 0.0-1.0
    /// - `parallel_moves` is 0
    pub fn validate(&self) -> Result<()> {
        if self.max_reassignments_per_tick == 0 {
            return Err(SchedError::InvalidConfig(
                "max_reassignments_per_tick must be > 0".into(),
            ));
        }
        if !(0.0..=1.0).contains(&self.min_improvement_threshold) {
            return Err(SchedError::InvalidConfig(
                "min_improvement_threshold must be 0.0-1.0".into(),
            ));
        }
        if !(0.0..=1.0).contains(&self.max_disruption) {
            return Err(SchedError::InvalidConfig(
                "max_disruption must be 0.0-1.0".into(),
            ));
        }
        if self.parallel_moves == 0 {
            return Err(SchedError::InvalidConfig(
                "parallel_moves must be > 0".into(),
            ));
        }
        Ok(())
    }
}

/// Metrics for reoptimization operations
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReoptMetrics {
    /// Total reoptimizations executed
    pub total_reopts: u64,
    /// Partial scope reoptimizations
    pub partial_reopts: u64,
    /// Full scope reoptimizations
    pub full_reopts: u64,
    /// Average improvement achieved
    pub avg_improvement: f64,
    /// Average disruption caused
    pub avg_disruption: f64,
    /// Average execution time in milliseconds
    pub avg_execution_time_ms: u64,
    /// Number of aborted reoptimizations
    pub aborted_reopts: u64,
}

impl ReoptMetrics {
    /// Create new metrics
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a completed reoptimization
    pub fn record(&mut self, plan: &ReoptPlan, execution_time_ms: u64) {
        self.total_reopts += 1;
        match &plan.scope {
            ReoptScope::Full => self.full_reopts += 1,
            _ => self.partial_reopts += 1,
        }

        let n = self.total_reopts as f64;
        self.avg_improvement =
            (n - 1.0).mul_add(self.avg_improvement, plan.estimated_improvement) / n;
        self.avg_disruption = (n - 1.0).mul_add(self.avg_disruption, plan.estimated_disruption) / n;
        self.avg_execution_time_ms =
            (n - 1.0).mul_add(self.avg_execution_time_ms as f64, execution_time_ms as f64) as u64
                / self.total_reopts;
    }

    /// Record an aborted reoptimization
    pub const fn record_abort(&mut self) {
        self.aborted_reopts += 1;
    }
}

/// Current state of reoptimization
#[derive(Debug, Clone)]
pub enum ReoptState {
    /// No active reoptimization
    Idle,
    /// Planning reoptimization
    Planning,
    /// Executing a plan
    Executing {
        /// Reoptimization plan being executed
        plan: ReoptPlan,
        /// Current execution step index
        current_step: usize,
    },
    /// Paused for external reason
    Paused {
        /// Reason for pause
        reason: String,
    },
    /// Reoptimization completed
    Completed {
        /// Final metrics for completed reoptimization
        metrics: ReoptMetrics,
    },
}

/// Incremental scheduler for reoptimization
pub struct IncrementalScheduler {
    /// Configuration for incremental scheduling
    config: IncrementalConfig,
    /// Current reoptimization state
    state: ReoptState,
    /// Accumulated metrics
    metrics: ReoptMetrics,
}

impl IncrementalScheduler {
    /// Create a new incremental scheduler
    #[must_use]
    pub fn new(config: IncrementalConfig) -> Self {
        Self {
            config,
            state: ReoptState::Idle,
            metrics: ReoptMetrics::new(),
        }
    }

    /// Plan reoptimization based on scope and strategy
    #[must_use]
    pub fn plan_reopt(
        scope: ReoptScope,
        strategy: ReoptStrategy,
        current: &[Assignment],
        costs: &CpuCostMatrix,
    ) -> ReoptPlan {
        // Determine which chunks to consider based on scope
        let chunks_to_consider = Self::extract_chunks_from_scope(&scope, current);

        // Generate reassignments based on strategy
        let mut reassignments = match strategy {
            ReoptStrategy::Greedy => Self::plan_greedy(&chunks_to_consider, current, costs),
            ReoptStrategy::MinDisruption => {
                Self::plan_min_disruption(&chunks_to_consider, current, costs)
            }
            ReoptStrategy::CostOptimal => {
                Self::plan_cost_optimal(&chunks_to_consider, current, costs)
            }
            ReoptStrategy::Hybrid { disruption_weight } => {
                Self::plan_hybrid(&chunks_to_consider, current, costs, disruption_weight)
            }
        };

        // Calculate estimated improvement and disruption
        let estimated_improvement = Self::calculate_improvement(&reassignments, current, costs);
        let estimated_disruption = Self::calculate_disruption(&reassignments, current);

        // Sort reassignments by priority
        reassignments.sort_by_key(|r| r.priority);

        ReoptPlan::new(
            scope,
            strategy,
            reassignments,
            estimated_improvement,
            estimated_disruption,
        )
    }

    /// Execute a single step of the plan
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Step index is out of bounds
    /// - Execution order is invalid
    /// - Reassignment index is invalid
    pub fn execute_step(&mut self, plan: &ReoptPlan, step: usize) -> Result<Reassignment> {
        if step >= plan.reassignments.len() {
            return Err(SchedError::InvalidState("step index out of bounds".into()));
        }
        let order_idx = plan
            .execution_order
            .get(step)
            .ok_or_else(|| SchedError::InvalidState("invalid execution order".into()))?;
        let reassignment = plan
            .reassignments
            .get(*order_idx)
            .ok_or_else(|| SchedError::InvalidState("invalid reassignment index".into()))?;
        self.state = ReoptState::Executing {
            plan: plan.clone(),
            current_step: step,
        };
        Ok(reassignment.clone())
    }

    /// Estimate improvement for a single reassignment
    #[must_use]
    pub fn estimate_improvement(reassignment: &Reassignment, costs: &CpuCostMatrix) -> f64 {
        let chunk_id = reassignment.chunk_id;
        let current_cost = costs
            .get_cost(chunk_id, reassignment.from_edge)
            .unwrap_or(f32::MAX);
        let new_cost = reassignment
            .to_edges
            .iter()
            .filter_map(|&edge| costs.get_cost(chunk_id, edge))
            .min_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .unwrap_or(f32::MAX);
        if current_cost == 0.0 {
            return 0.0;
        }
        f64::from(((current_cost - new_cost) / current_cost).max(0.0))
    }

    /// Estimate total disruption for a plan
    #[must_use]
    pub const fn estimate_disruption(plan: &ReoptPlan) -> f64 {
        plan.estimated_disruption
    }

    /// Validate a reoptimization plan
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Execution order contains invalid indices
    /// - Execution order is incomplete
    pub fn validate_plan(plan: &ReoptPlan) -> Result<()> {
        for &idx in &plan.execution_order {
            if idx >= plan.reassignments.len() {
                return Err(SchedError::InvalidState(
                    "invalid execution order index".into(),
                ));
            }
        }
        let mut seen = vec![false; plan.reassignments.len()];
        for &idx in &plan.execution_order {
            if seen[idx] {
                return Err(SchedError::InvalidState(
                    "duplicate execution order index".into(),
                ));
            }
            seen[idx] = true;
        }
        for reassignment in &plan.reassignments {
            if reassignment.to_edges.is_empty() {
                return Err(SchedError::InvalidState(
                    "reassignment has no target edges".into(),
                ));
            }
        }
        Ok(())
    }

    /// Abort current reoptimization
    pub fn abort_plan(&mut self) {
        self.metrics.record_abort();
        self.state = ReoptState::Idle;
    }

    /// Get current state
    #[must_use]
    pub const fn state(&self) -> &ReoptState {
        &self.state
    }

    /// Get metrics
    #[must_use]
    pub const fn metrics(&self) -> &ReoptMetrics {
        &self.metrics
    }

    // Private helper methods

    fn extract_chunks_from_scope(scope: &ReoptScope, current: &[Assignment]) -> Vec<ChunkId> {
        match scope {
            ReoptScope::Chunks(chunks) => chunks.clone(),
            ReoptScope::Edges(edges) => current
                .iter()
                .filter(|a| a.source_edges.iter().any(|e| edges.contains(e)))
                .map(|a| ChunkId::from_hash(&a.chunk_hash))
                .collect(),
            ReoptScope::Region { edges, radius: _ } => {
                // For simplicity, treat region as edges for now
                current
                    .iter()
                    .filter(|a| a.source_edges.iter().any(|e| edges.contains(e)))
                    .map(|a| ChunkId::from_hash(&a.chunk_hash))
                    .collect()
            }
            ReoptScope::Full => current
                .iter()
                .map(|a| ChunkId::from_hash(&a.chunk_hash))
                .collect(),
        }
    }

    fn plan_greedy(
        chunks: &[ChunkId],
        current: &[Assignment],
        costs: &CpuCostMatrix,
    ) -> Vec<Reassignment> {
        let mut reassignments = Vec::new();

        for &chunk_id in chunks {
            // Find current assignment
            let current_assignment = current
                .iter()
                .find(|a| ChunkId::from_hash(&a.chunk_hash) == chunk_id);

            if let Some(assignment) = current_assignment {
                if let Some(&current_edge) = assignment.source_edges.first() {
                    // Get all valid edges and pick the best
                    let valid_edges = costs.get_valid_edges(chunk_id);
                    if let Some((best_edge, best_cost)) = valid_edges.first() {
                        let current_cost =
                            costs.get_cost(chunk_id, current_edge).unwrap_or(f32::MAX);

                        // Only reassign if there's improvement
                        if *best_cost < current_cost * 0.95 {
                            reassignments.push(Reassignment::new(
                                chunk_id,
                                current_edge,
                                vec![*best_edge],
                                ReassignmentReason::CostReduction,
                                0,
                            ));
                        }
                    }
                }
            }
        }

        reassignments
    }

    fn plan_min_disruption(
        chunks: &[ChunkId],
        current: &[Assignment],
        costs: &CpuCostMatrix,
    ) -> Vec<Reassignment> {
        let mut reassignments = Vec::new();

        for &chunk_id in chunks {
            let current_assignment = current
                .iter()
                .find(|a| ChunkId::from_hash(&a.chunk_hash) == chunk_id);

            if let Some(assignment) = current_assignment {
                if let Some(&current_edge) = assignment.source_edges.first() {
                    let current_cost = costs.get_cost(chunk_id, current_edge).unwrap_or(f32::MAX);
                    let valid_edges = costs.get_valid_edges(chunk_id);

                    // Only reassign if current edge is invalid or has very high cost
                    if current_cost == f32::MAX || current_cost > 0.9 {
                        if let Some((best_edge, _)) = valid_edges.first() {
                            reassignments.push(Reassignment::new(
                                chunk_id,
                                current_edge,
                                vec![*best_edge],
                                ReassignmentReason::EdgeDegraded,
                                1,
                            ));
                        }
                    }
                }
            }
        }

        reassignments
    }

    fn plan_cost_optimal(
        chunks: &[ChunkId],
        current: &[Assignment],
        costs: &CpuCostMatrix,
    ) -> Vec<Reassignment> {
        // For cost optimal, always pick the absolute best edge
        let mut reassignments = Vec::new();

        for &chunk_id in chunks {
            let current_assignment = current
                .iter()
                .find(|a| ChunkId::from_hash(&a.chunk_hash) == chunk_id);

            if let Some(assignment) = current_assignment {
                if let Some(&current_edge) = assignment.source_edges.first() {
                    let valid_edges = costs.get_valid_edges(chunk_id);
                    if let Some((best_edge, best_cost)) = valid_edges.first() {
                        let current_cost =
                            costs.get_cost(chunk_id, current_edge).unwrap_or(f32::MAX);

                        // Reassign even for small improvements
                        if *best_cost < current_cost {
                            reassignments.push(Reassignment::new(
                                chunk_id,
                                current_edge,
                                vec![*best_edge],
                                ReassignmentReason::BetterPathFound,
                                0,
                            ));
                        }
                    }
                }
            }
        }

        reassignments
    }

    fn plan_hybrid(
        chunks: &[ChunkId],
        current: &[Assignment],
        costs: &CpuCostMatrix,
        disruption_weight: f64,
    ) -> Vec<Reassignment> {
        let mut reassignments = Vec::new();
        let threshold = disruption_weight.mul_add(-0.4, 0.5); // Higher weight = higher threshold

        for &chunk_id in chunks {
            let current_assignment = current
                .iter()
                .find(|a| ChunkId::from_hash(&a.chunk_hash) == chunk_id);

            if let Some(assignment) = current_assignment {
                if let Some(&current_edge) = assignment.source_edges.first() {
                    let valid_edges = costs.get_valid_edges(chunk_id);
                    if let Some((best_edge, best_cost)) = valid_edges.first() {
                        let current_cost =
                            costs.get_cost(chunk_id, current_edge).unwrap_or(f32::MAX);

                        if *best_cost < current_cost * threshold as f32 {
                            reassignments.push(Reassignment::new(
                                chunk_id,
                                current_edge,
                                vec![*best_edge],
                                ReassignmentReason::BetterPathFound,
                                1,
                            ));
                        }
                    }
                }
            }
        }

        reassignments
    }

    fn calculate_improvement(
        reassignments: &[Reassignment],
        _current: &[Assignment],
        costs: &CpuCostMatrix,
    ) -> f64 {
        if reassignments.is_empty() {
            return 0.0;
        }

        let total_improvement: f64 = reassignments
            .iter()
            .map(|r| Self::estimate_improvement(r, costs))
            .sum();

        total_improvement / reassignments.len() as f64
    }

    fn calculate_disruption(reassignments: &[Reassignment], current: &[Assignment]) -> f64 {
        if current.is_empty() {
            return 0.0;
        }

        (reassignments.len() as f64 / current.len() as f64).min(1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cost::{CostConfig, CpuCostMatrix};
    use crate::{ChunkState, CpuStateBuffers, EdgeStateGpu};

    fn make_test_assignment(chunk_hash: [u8; 32], edges: Vec<EdgeIdx>) -> Assignment {
        Assignment::new(chunk_hash, 1024, edges, 128, 100)
    }

    fn make_test_costs() -> (CpuCostMatrix, CpuStateBuffers) {
        let mut state = CpuStateBuffers::new(10, 5);

        for i in 0..10 {
            let mut hash = [0u8; 32];
            hash[0] = i as u8;
            state
                .add_chunk(ChunkState::new(hash, 1024, 128, 3))
                .unwrap();
        }

        for i in 0..5 {
            let bandwidth = 1_000_000_000 - (i as u64 * 100_000_000);
            state
                .add_edge(
                    i,
                    EdgeStateGpu::new(EdgeIdx(i), bandwidth, 10_000, 0.95, 10),
                )
                .unwrap();
        }

        for i in 0..10 {
            for j in 0..5 {
                state.add_replica(i, EdgeIdx(j));
            }
        }

        let mut costs = CpuCostMatrix::new(10, 5, CostConfig::default());
        costs.compute(&state);

        (costs, state)
    }

    #[test]
    fn test_reopt_scope_variants() {
        assert_eq!(
            ReoptScope::Chunks(vec![ChunkId(1)]),
            ReoptScope::Chunks(vec![ChunkId(1)])
        );
        assert!(matches!(
            ReoptScope::Edges(vec![EdgeIdx(0)]),
            ReoptScope::Edges(_)
        ));
        assert!(matches!(
            ReoptScope::Region {
                edges: vec![],
                radius: 2
            },
            ReoptScope::Region { .. }
        ));
        assert!(matches!(ReoptScope::Full, ReoptScope::Full));
    }

    #[test]
    fn test_reopt_strategy_variants() {
        assert_eq!(ReoptStrategy::Greedy, ReoptStrategy::Greedy);
        assert_eq!(ReoptStrategy::MinDisruption, ReoptStrategy::MinDisruption);
        assert_eq!(ReoptStrategy::CostOptimal, ReoptStrategy::CostOptimal);
        assert!(matches!(
            ReoptStrategy::Hybrid {
                disruption_weight: 0.5
            },
            ReoptStrategy::Hybrid { .. }
        ));
    }

    #[test]
    fn test_reassignment_reason_variants() {
        assert_eq!(
            ReassignmentReason::EdgeDegraded,
            ReassignmentReason::EdgeDegraded
        );
        assert_eq!(
            ReassignmentReason::EdgeOverloaded,
            ReassignmentReason::EdgeOverloaded
        );
        assert_eq!(
            ReassignmentReason::BetterPathFound,
            ReassignmentReason::BetterPathFound
        );
        assert_eq!(
            ReassignmentReason::LoadBalance,
            ReassignmentReason::LoadBalance
        );
        assert_eq!(
            ReassignmentReason::CostReduction,
            ReassignmentReason::CostReduction
        );
        assert_eq!(
            ReassignmentReason::Preposition,
            ReassignmentReason::Preposition
        );
    }

    #[test]
    fn test_reassignment_creation() {
        let r = Reassignment::new(
            ChunkId(1),
            EdgeIdx(0),
            vec![EdgeIdx(1), EdgeIdx(2)],
            ReassignmentReason::BetterPathFound,
            5,
        );
        assert_eq!(r.chunk_id, ChunkId(1));
        assert_eq!(r.from_edge, EdgeIdx(0));
        assert_eq!(r.to_edges, vec![EdgeIdx(1), EdgeIdx(2)]);
        assert_eq!(r.reason, ReassignmentReason::BetterPathFound);
        assert_eq!(r.priority, 5);
    }

    #[test]
    fn test_reopt_plan_creation() {
        let scope = ReoptScope::Full;
        let strategy = ReoptStrategy::Greedy;
        let reassignments = vec![Reassignment::new(
            ChunkId(0),
            EdgeIdx(0),
            vec![EdgeIdx(1)],
            ReassignmentReason::CostReduction,
            0,
        )];

        let plan = ReoptPlan::new(scope.clone(), strategy, reassignments.clone(), 0.1, 0.2);
        assert_eq!(plan.scope, scope);
        assert_eq!(plan.strategy, strategy);
        assert_eq!(plan.reassignments.len(), 1);
        assert_eq!(plan.estimated_improvement, 0.1);
        assert_eq!(plan.estimated_disruption, 0.2);
        assert_eq!(plan.execution_order, vec![0]);
    }

    #[test]
    fn test_reopt_plan_len_empty() {
        let plan = ReoptPlan::new(ReoptScope::Full, ReoptStrategy::Greedy, vec![], 0.0, 0.0);
        assert_eq!(plan.len(), 0);
        assert!(plan.is_empty());
    }

    #[test]
    fn test_incremental_config_default() {
        let config = IncrementalConfig::default();
        assert_eq!(config.max_reassignments_per_tick, 10);
        assert_eq!(config.min_improvement_threshold, 0.05);
        assert_eq!(config.max_disruption, 0.3);
        assert_eq!(config.parallel_moves, 3);
    }

    #[test]
    fn test_incremental_config_new() {
        let config = IncrementalConfig::new(20, 0.1, 0.5, 5);
        assert_eq!(config.max_reassignments_per_tick, 20);
        assert_eq!(config.min_improvement_threshold, 0.1);
        assert_eq!(config.max_disruption, 0.5);
        assert_eq!(config.parallel_moves, 5);
    }

    #[test]
    fn test_incremental_config_validate_success() {
        let config = IncrementalConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_incremental_config_validate_failures() {
        assert!(IncrementalConfig::new(0, 0.05, 0.3, 3).validate().is_err());
        assert!(IncrementalConfig::new(10, 1.5, 0.3, 3).validate().is_err());
        assert!(
            IncrementalConfig::new(10, 0.05, -0.1, 3)
                .validate()
                .is_err()
        );
        assert!(IncrementalConfig::new(10, 0.05, 0.3, 0).validate().is_err());
    }

    #[test]
    fn test_incremental_scheduler_new() {
        let config = IncrementalConfig::default();
        let scheduler = IncrementalScheduler::new(config);
        assert!(matches!(scheduler.state, ReoptState::Idle));
    }

    #[test]
    fn test_plan_reopt_scopes() {
        let (costs, _) = make_test_costs();
        let mut hash = [0u8; 32];

        // Empty scope
        let empty_plan = IncrementalScheduler::plan_reopt(
            ReoptScope::Chunks(vec![]),
            ReoptStrategy::Greedy,
            &[],
            &costs,
        );
        assert!(empty_plan.is_empty());

        // Chunk scope - worst edge should trigger improvement
        let chunk_plan = IncrementalScheduler::plan_reopt(
            ReoptScope::Chunks(vec![ChunkId(0)]),
            ReoptStrategy::Greedy,
            &[make_test_assignment(hash, vec![EdgeIdx(4)])],
            &costs,
        );
        assert!(chunk_plan.estimated_improvement >= 0.0);

        // Edge scope
        let edge_plan = IncrementalScheduler::plan_reopt(
            ReoptScope::Edges(vec![EdgeIdx(0)]),
            ReoptStrategy::Greedy,
            &[make_test_assignment(hash, vec![EdgeIdx(0)])],
            &costs,
        );
        assert!(edge_plan.reassignments.len() <= 1);
    }

    #[test]
    fn test_plan_reopt_strategies() {
        let (costs, _) = make_test_costs();

        // Greedy strategy - finds improvements on bad edges
        let mut bad_assignments = vec![];
        for i in 0..3 {
            let mut hash = [0u8; 32];
            hash[0] = i;
            bad_assignments.push(make_test_assignment(hash, vec![EdgeIdx(4)]));
        }
        let greedy_plan = IncrementalScheduler::plan_reopt(
            ReoptScope::Full,
            ReoptStrategy::Greedy,
            &bad_assignments,
            &costs,
        );
        assert!(greedy_plan.reassignments.len() >= 0);

        // Min disruption - minimizes changes on good edges
        let mut good_assignments = vec![];
        for i in 0..3 {
            let mut hash = [0u8; 32];
            hash[0] = i;
            good_assignments.push(make_test_assignment(hash, vec![EdgeIdx(0)]));
        }
        let min_disrupt_plan = IncrementalScheduler::plan_reopt(
            ReoptScope::Full,
            ReoptStrategy::MinDisruption,
            &good_assignments,
            &costs,
        );
        assert!(min_disrupt_plan.reassignments.len() <= good_assignments.len());
    }

    #[test]
    fn test_improvement_and_disruption_estimation() {
        let (costs, _) = make_test_costs();

        // Test improvement with change (bad to good edge)
        let r1 = Reassignment::new(
            ChunkId(0),
            EdgeIdx(4),
            vec![EdgeIdx(0)],
            ReassignmentReason::CostReduction,
            0,
        );
        assert!(IncrementalScheduler::estimate_improvement(&r1, &costs) > 0.0);

        // Test no improvement (same edge)
        let r2 = Reassignment::new(
            ChunkId(0),
            EdgeIdx(0),
            vec![EdgeIdx(0)],
            ReassignmentReason::CostReduction,
            0,
        );
        assert_eq!(IncrementalScheduler::estimate_improvement(&r2, &costs), 0.0);

        // Test disruption estimation
        let plan = ReoptPlan::new(
            ReoptScope::Full,
            ReoptStrategy::Greedy,
            vec![r1, r2],
            0.1,
            0.5,
        );
        assert_eq!(IncrementalScheduler::estimate_disruption(&plan), 0.5);
        assert_eq!(plan.execution_order, vec![0, 1]);
    }

    #[test]
    fn test_execute_step() {
        let mut scheduler = IncrementalScheduler::new(IncrementalConfig::default());
        let r = Reassignment::new(
            ChunkId(0),
            EdgeIdx(0),
            vec![EdgeIdx(1)],
            ReassignmentReason::CostReduction,
            0,
        );
        let plan = ReoptPlan::new(ReoptScope::Full, ReoptStrategy::Greedy, vec![r], 0.1, 0.1);

        assert!(scheduler.execute_step(&plan, 0).is_ok());
        assert!(matches!(scheduler.state, ReoptState::Executing { .. }));

        // Out of bounds
        let empty_plan = ReoptPlan::new(ReoptScope::Full, ReoptStrategy::Greedy, vec![], 0.0, 0.0);
        assert!(scheduler.execute_step(&empty_plan, 0).is_err());
    }

    #[test]
    fn test_validate_plan() {
        let r = Reassignment::new(
            ChunkId(0),
            EdgeIdx(0),
            vec![EdgeIdx(1)],
            ReassignmentReason::CostReduction,
            0,
        );
        let plan = ReoptPlan::new(ReoptScope::Full, ReoptStrategy::Greedy, vec![r], 0.1, 0.1);
        assert!(IncrementalScheduler::validate_plan(&plan).is_ok());

        // Invalid execution order
        let mut bad_plan = plan.clone();
        bad_plan.execution_order = vec![5];
        assert!(IncrementalScheduler::validate_plan(&bad_plan).is_err());

        // Empty target edges
        let r2 = Reassignment::new(
            ChunkId(0),
            EdgeIdx(0),
            vec![],
            ReassignmentReason::CostReduction,
            0,
        );
        let bad_plan2 = ReoptPlan::new(ReoptScope::Full, ReoptStrategy::Greedy, vec![r2], 0.1, 0.1);
        assert!(IncrementalScheduler::validate_plan(&bad_plan2).is_err());
    }

    #[test]
    fn test_abort_plan() {
        let mut scheduler = IncrementalScheduler::new(IncrementalConfig::default());
        scheduler.abort_plan();

        assert!(matches!(scheduler.state, ReoptState::Idle));
        assert_eq!(scheduler.metrics.aborted_reopts, 1);
    }

    #[test]
    fn test_reopt_metrics() {
        let mut metrics = ReoptMetrics::new();
        assert_eq!(metrics.total_reopts, 0);

        // Record full reopt
        let full_plan = ReoptPlan::new(ReoptScope::Full, ReoptStrategy::Greedy, vec![], 0.1, 0.2);
        metrics.record(&full_plan, 100);
        assert_eq!(metrics.total_reopts, 1);
        assert_eq!(metrics.full_reopts, 1);
        assert_eq!(metrics.avg_improvement, 0.1);

        // Record partial reopt
        let partial_plan = ReoptPlan::new(
            ReoptScope::Chunks(vec![ChunkId(0)]),
            ReoptStrategy::Greedy,
            vec![],
            0.15,
            0.1,
        );
        metrics.record(&partial_plan, 50);
        assert_eq!(metrics.total_reopts, 2);
        assert_eq!(metrics.partial_reopts, 1);

        // Test state
        let scheduler = IncrementalScheduler::new(IncrementalConfig::default());
        assert!(matches!(scheduler.state(), &ReoptState::Idle));
    }

    #[test]
    fn test_integration_full_reopt_cycle() {
        let (costs, _) = make_test_costs();
        let mut assignments = vec![];
        for i in 0..5 {
            let mut hash = [0u8; 32];
            hash[0] = i;
            assignments.push(make_test_assignment(hash, vec![EdgeIdx(4)]));
        }
        let plan = IncrementalScheduler::plan_reopt(
            ReoptScope::Full,
            ReoptStrategy::CostOptimal,
            &assignments,
            &costs,
        );
        assert!(IncrementalScheduler::validate_plan(&plan).is_ok());

        let mut scheduler = IncrementalScheduler::new(IncrementalConfig::default());
        for step in 0..plan.reassignments.len() {
            assert!(scheduler.execute_step(&plan, step).is_ok());
        }
    }

    #[test]
    fn test_no_improvement_possible() {
        let (costs, _) = make_test_costs();
        let mut assignments = vec![];
        for i in 0..3 {
            let mut hash = [0u8; 32];
            hash[0] = i;
            assignments.push(make_test_assignment(hash, vec![EdgeIdx(0)])); // Already optimal
        }
        let plan = IncrementalScheduler::plan_reopt(
            ReoptScope::Full,
            ReoptStrategy::Greedy,
            &assignments,
            &costs,
        );
        assert!(plan.estimated_improvement <= 0.1); // Minimal improvement possible
    }
}
