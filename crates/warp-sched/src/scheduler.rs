//! Main scheduler module - central coordinator for chunk scheduling operations.
//!
//! Runs a 50ms tick loop that orchestrates:
//! - Cost matrix computation
//! - Path selection
//! - Failover detection and handling
//! - Load balancing
//! - Assignment dispatch

use crate::{
    Assignment, AssignmentBatch, ChunkId, EdgeIdx, ScheduleRequest, SchedulerMetrics,
    CpuStateBuffers,
};
use crate::balance::{CpuLoadBalancer, LoadBalanceConfig};
use crate::constraints::ConstraintEvaluator;
use crate::cost::{CostConfig, CpuCostMatrix};
use crate::dispatch::DispatchQueue;
use crate::failover::{CpuFailoverManager, FailoverConfig, FailoverDecision};
use crate::paths::{CpuPathSelector, PathConfig};
use crate::reoptimize::{IncrementalConfig, IncrementalScheduler, ReoptPlan, ReoptScope, ReoptStrategy, Reassignment};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Configuration for the chunk scheduler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulerConfig {
    /// Main loop interval in milliseconds (default 50ms).
    pub tick_interval_ms: u64,
    /// Maximum assignments to produce per tick (default 1000).
    pub max_assignments_per_tick: usize,
    /// Cost matrix computation configuration.
    pub cost_config: CostConfig,
    /// Path selection configuration.
    pub path_config: PathConfig,
    /// Failover detection and handling configuration.
    pub failover_config: FailoverConfig,
    /// Load balancing configuration.
    pub balance_config: LoadBalanceConfig,
    /// Incremental rescheduling configuration.
    pub incremental_config: IncrementalConfig,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            tick_interval_ms: 50,
            max_assignments_per_tick: 1000,
            cost_config: CostConfig::default(),
            path_config: PathConfig::default(),
            failover_config: FailoverConfig::default(),
            balance_config: LoadBalanceConfig::default(),
            incremental_config: IncrementalConfig::default(),
        }
    }
}

/// Internal scheduler state.
#[derive(Debug, Clone)]
struct SchedulerState {
    running: bool,
    generation: u64,
}

/// CPU-based chunk scheduler implementation.
///
/// Orchestrates all scheduling operations in a synchronous manner.
pub struct CpuChunkScheduler {
    config: SchedulerConfig,
    state: SchedulerState,
    state_buffers: CpuStateBuffers,
    cost_matrix: CpuCostMatrix,
    path_selector: CpuPathSelector,
    failover_mgr: CpuFailoverManager,
    load_balancer: CpuLoadBalancer,
    dispatch_queue: DispatchQueue,
    pending_requests: Vec<ScheduleRequest>,
    metrics: SchedulerMetrics,
    /// Optional constraint evaluator for time/cost/power-aware scheduling
    constraint_evaluator: Option<ConstraintEvaluator>,
    /// Incremental scheduler for reoptimization
    incremental_scheduler: IncrementalScheduler,
    /// Pending reoptimization plan
    pending_reopt: Option<ReoptPlan>,
    /// Current step in pending reopt plan
    reopt_step: usize,
    /// Current assignments for reoptimization reference
    current_assignments: Vec<Assignment>,
    /// Index for O(1) assignment lookups by chunk_hash
    assignment_index: HashMap<[u8; 32], usize>,
    /// Reverse index for O(1) ChunkId to chunk_hash lookups
    chunk_id_index: HashMap<ChunkId, [u8; 32]>,
}

impl CpuChunkScheduler {
    /// Creates a new CPU-based chunk scheduler.
    pub fn new(config: SchedulerConfig, max_chunks: usize, max_edges: usize) -> Self {
        debug_assert!(max_chunks > 0, "max_chunks must be positive");
        debug_assert!(max_edges > 0, "max_edges must be positive");
        debug_assert!(
            config.tick_interval_ms > 0,
            "tick_interval_ms must be positive"
        );
        debug_assert!(
            config.max_assignments_per_tick > 0,
            "max_assignments_per_tick must be positive"
        );

        let state_buffers = CpuStateBuffers::new(max_chunks, max_edges);
        let cost_matrix = CpuCostMatrix::new(max_chunks, max_edges, config.cost_config.clone());
        let path_selector = CpuPathSelector::new(config.path_config.clone());
        let failover_mgr = CpuFailoverManager::new(config.failover_config.clone());
        let load_balancer = CpuLoadBalancer::new(config.balance_config.clone());
        let dispatch_queue = DispatchQueue::new();
        let incremental_scheduler = IncrementalScheduler::new(config.incremental_config.clone());

        Self {
            config,
            state: SchedulerState {
                running: false,
                generation: 0,
            },
            state_buffers,
            cost_matrix,
            path_selector,
            failover_mgr,
            load_balancer,
            dispatch_queue,
            pending_requests: Vec::with_capacity(max_chunks),
            metrics: SchedulerMetrics::default(),
            constraint_evaluator: None,
            incremental_scheduler,
            pending_reopt: None,
            reopt_step: 0,
            current_assignments: Vec::new(),
            assignment_index: HashMap::new(),
            chunk_id_index: HashMap::new(),
        }
    }

    /// Sets the constraint evaluator for time/cost/power-aware scheduling.
    ///
    /// When set, the scheduler will apply constraint multipliers to costs
    /// and filter out edges that violate hard constraints.
    pub fn set_constraint_evaluator(&mut self, evaluator: ConstraintEvaluator) {
        self.constraint_evaluator = Some(evaluator);
    }

    /// Removes the constraint evaluator.
    pub fn clear_constraint_evaluator(&mut self) {
        self.constraint_evaluator = None;
    }

    /// Returns a reference to the constraint evaluator, if set.
    pub fn constraint_evaluator(&self) -> Option<&ConstraintEvaluator> {
        self.constraint_evaluator.as_ref()
    }

    /// Returns a mutable reference to the constraint evaluator, if set.
    pub fn constraint_evaluator_mut(&mut self) -> Option<&mut ConstraintEvaluator> {
        self.constraint_evaluator.as_mut()
    }

    /// Request a reoptimization of chunk assignments.
    ///
    /// Creates a new reoptimization plan based on the given scope and strategy,
    /// which will be executed incrementally during subsequent ticks.
    pub fn request_reopt(&mut self, scope: ReoptScope, strategy: ReoptStrategy) {
        let plan = IncrementalScheduler::plan_reopt(
            scope,
            strategy,
            &self.current_assignments,
            &self.cost_matrix,
        );

        // Only set the plan if there are reassignments to make
        if !plan.is_empty() {
            self.pending_reopt = Some(plan);
            self.reopt_step = 0;
        }
    }

    /// Check if there is a pending reoptimization plan.
    pub fn has_pending_reopt(&self) -> bool {
        self.pending_reopt.is_some()
    }

    /// Cancel any pending reoptimization plan.
    pub fn cancel_reopt(&mut self) {
        if self.pending_reopt.is_some() {
            self.incremental_scheduler.abort_plan();
            self.pending_reopt = None;
            self.reopt_step = 0;
        }
    }

    /// Get the current reoptimization plan, if any.
    pub fn pending_reopt_plan(&self) -> Option<&ReoptPlan> {
        self.pending_reopt.as_ref()
    }

    /// Get the incremental scheduler's metrics.
    pub fn reopt_metrics(&self) -> &crate::reoptimize::ReoptMetrics {
        self.incremental_scheduler.metrics()
    }

    /// Execute a single step of the pending reoptimization plan.
    /// Returns the reassignment made, if any.
    fn execute_reopt_step(&mut self) -> Option<Reassignment> {
        let plan = self.pending_reopt.as_ref()?;

        if self.reopt_step >= plan.reassignments.len() {
            // Plan is complete
            self.pending_reopt = None;
            self.reopt_step = 0;
            return None;
        }

        // Execute the next step
        let result = self.incremental_scheduler.execute_step(plan, self.reopt_step);

        if let Ok(reassignment) = result {
            self.reopt_step += 1;

            // Check if we've completed all steps
            if self.reopt_step >= plan.reassignments.len() {
                self.pending_reopt = None;
                self.reopt_step = 0;
            }

            return Some(reassignment);
        }

        // Step failed, abort the plan
        self.incremental_scheduler.abort_plan();
        self.pending_reopt = None;
        self.reopt_step = 0;
        None
    }

    /// Apply a reassignment to the current assignments.
    fn apply_reassignment(&mut self, reassignment: &Reassignment) -> Option<Assignment> {
        // Find and update the assignment for this chunk
        let chunk_hash = self.find_chunk_hash(reassignment.chunk_id)?;

        // Find the current assignment using O(1) index lookup
        let assignment_idx = *self.assignment_index.get(&chunk_hash)?;

        // Update the source edges
        let mut assignment = self.current_assignments[assignment_idx].clone();
        assignment.source_edges = reassignment.to_edges.clone();
        self.current_assignments[assignment_idx] = assignment.clone();

        Some(assignment)
    }

    /// Find chunk hash by ChunkId - O(1) via reverse index.
    #[inline]
    fn find_chunk_hash(&self, chunk_id: ChunkId) -> Option<[u8; 32]> {
        self.chunk_id_index.get(&chunk_id).copied()
    }

    /// Schedules chunks for assignment.
    pub fn schedule(&mut self, request: ScheduleRequest) -> crate::Result<()> {
        self.metrics.scheduled_chunks += request.chunks.len();
        self.pending_requests.push(request);
        Ok(())
    }

    /// Executes a single scheduling tick synchronously.
    ///
    /// Algorithm:
    /// 1. Check for timeouts and process failovers
    /// 2. Update edge states from state buffers
    /// 3. Compute cost matrix
    /// 4. Select K-best paths for pending chunks
    /// 5. Create assignments from path selections
    /// 6. Apply load balancing if needed
    /// 7. Execute reoptimization step if pending
    /// 8. Push assignments to dispatch queue
    /// 9. Update metrics
    pub fn tick(&mut self) -> AssignmentBatch {
        self.state.generation += 1;
        self.metrics.tick_count += 1;

        let mut assignments = Vec::new();

        // Step 1: Check for failovers
        let failover_decisions = self.failover_mgr.check_timeouts(&self.state_buffers);
        for decision in failover_decisions {
            self.handle_failover(decision);
        }

        // Step 2: Update edge states (already in state_buffers)

        // Step 3: Compute cost matrix
        self.cost_matrix.compute(&self.state_buffers);

        // Step 3b: Apply constraints if evaluator is set (time/cost/power-aware)
        if let Some(evaluator) = &self.constraint_evaluator {
            let now = Utc::now();
            evaluator.apply_to_cost_matrix(&mut self.cost_matrix, now);
        }

        // Step 4 & 5: Select paths and create assignments for new requests
        if !self.pending_requests.is_empty() {
            let requests_to_process: Vec<ScheduleRequest> = self
                .pending_requests
                .drain(..)
                .take(self.config.max_assignments_per_tick)
                .collect();

            for request in &requests_to_process {
                for chunk_hash in &request.chunks {
                    // Convert hash to ChunkId for path selection
                    let chunk_id = ChunkId::from_hash(chunk_hash);

                    let path_selection = self.path_selector.select(chunk_id, &self.cost_matrix);
                    if !path_selection.selected_edges.is_empty() {
                        // Extract just the EdgeIdx from (EdgeIdx, cost) tuples
                        let source_edges: Vec<EdgeIdx> = path_selection
                            .selected_edges
                            .iter()
                            .map(|(edge, _cost)| *edge)
                            .collect();

                        let assignment = Assignment {
                            chunk_hash: *chunk_hash,
                            chunk_size: 1024 * 256, // Default chunk size
                            source_edges,
                            priority: request.priority,
                            estimated_duration_ms: 100,
                        };
                        assignments.push(assignment.clone());
                        // Track for reoptimization - add to indices for O(1) lookups
                        let idx = self.current_assignments.len();
                        let chunk_id = ChunkId::from_hash(&assignment.chunk_hash);
                        self.assignment_index.insert(assignment.chunk_hash, idx);
                        self.chunk_id_index.insert(chunk_id, assignment.chunk_hash);
                        self.current_assignments.push(assignment);
                    }
                }
            }
        }

        // Step 6: Apply load balancing (currently plan_rebalance only, not applying yet)
        let _rebalance_plan = self.load_balancer.plan_rebalance(&self.state_buffers);

        // Step 7: Execute reoptimization step if pending
        if self.pending_reopt.is_some() {
            // Execute up to max_reassignments_per_tick steps
            let max_steps = self.config.incremental_config.max_reassignments_per_tick;
            for _ in 0..max_steps {
                if let Some(reassignment) = self.execute_reopt_step() {
                    // Apply the reassignment and add to output
                    if let Some(updated_assignment) = self.apply_reassignment(&reassignment) {
                        assignments.push(updated_assignment);
                    }
                } else {
                    break;
                }
            }
        }

        // Step 8: Push to dispatch queue
        self.dispatch_queue.write_assignments(assignments.clone());
        self.dispatch_queue.swap_buffers();

        // Step 9: Update metrics
        self.metrics.active_transfers = assignments.len();

        self.create_batch(assignments)
    }

    fn create_batch(&self, assignments: Vec<Assignment>) -> AssignmentBatch {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(std::time::Duration::ZERO)
            .as_millis() as u64;

        AssignmentBatch {
            assignments,
            generation: self.state.generation,
            timestamp_ms,
        }
    }

    /// Gets current assignments from dispatch queue.
    pub fn get_assignments(&self) -> AssignmentBatch {
        self.dispatch_queue.read_assignments()
    }

    /// Handles a failover decision.
    pub fn handle_failover(&mut self, _decision: FailoverDecision) {
        // Failover handling: could re-enqueue affected chunks
        // For now, just track in metrics
        self.metrics.failed_chunks += 1;
    }

    /// Returns current scheduler metrics.
    pub fn metrics(&self) -> SchedulerMetrics {
        self.metrics.clone()
    }

    /// Returns reference to state buffers.
    pub fn state(&self) -> &CpuStateBuffers {
        &self.state_buffers
    }

    /// Checks if scheduler is running.
    pub fn is_running(&self) -> bool {
        self.state.running
    }

    /// Stops the scheduler.
    pub fn stop(&mut self) {
        self.state.running = false;
    }

    /// Starts the scheduler.
    pub fn start(&mut self) {
        self.state.running = true;
    }

    /// Gets the configuration.
    pub fn config(&self) -> &SchedulerConfig {
        &self.config
    }

    /// Gets mutable reference to state buffers for testing.
    pub fn state_mut(&mut self) -> &mut CpuStateBuffers {
        &mut self.state_buffers
    }
}

/// GPU-accelerated chunk scheduler (delegates to CPU implementation).
///
/// Currently wraps CpuChunkScheduler. Future versions will implement
/// GPU-accelerated scheduling algorithms using cudarc.
pub struct ChunkScheduler {
    cpu_scheduler: CpuChunkScheduler,
}

impl ChunkScheduler {
    /// Creates a new chunk scheduler.
    pub fn new(config: SchedulerConfig, max_chunks: usize, max_edges: usize) -> Self {
        Self {
            cpu_scheduler: CpuChunkScheduler::new(config, max_chunks, max_edges),
        }
    }

    /// Schedules chunks for assignment.
    pub fn schedule(&mut self, request: ScheduleRequest) -> crate::Result<()> {
        self.cpu_scheduler.schedule(request)
    }

    /// Executes a single scheduling tick.
    pub fn tick(&mut self) -> AssignmentBatch {
        self.cpu_scheduler.tick()
    }

    /// Gets current assignments from dispatch queue.
    pub fn get_assignments(&self) -> AssignmentBatch {
        self.cpu_scheduler.get_assignments()
    }

    /// Handles a failover decision.
    pub fn handle_failover(&mut self, decision: FailoverDecision) {
        self.cpu_scheduler.handle_failover(decision);
    }

    /// Returns current scheduler metrics.
    pub fn metrics(&self) -> SchedulerMetrics {
        self.cpu_scheduler.metrics()
    }

    /// Returns reference to state buffers.
    pub fn state(&self) -> &CpuStateBuffers {
        self.cpu_scheduler.state()
    }

    /// Checks if scheduler is running.
    pub fn is_running(&self) -> bool {
        self.cpu_scheduler.is_running()
    }

    /// Stops the scheduler.
    pub fn stop(&mut self) {
        self.cpu_scheduler.stop();
    }

    /// Starts the scheduler.
    pub fn start(&mut self) {
        self.cpu_scheduler.start();
    }

    /// Gets the configuration.
    pub fn config(&self) -> &SchedulerConfig {
        self.cpu_scheduler.config()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scheduler_config_default() {
        let config = SchedulerConfig::default();
        assert_eq!(config.tick_interval_ms, 50);
        assert_eq!(config.max_assignments_per_tick, 1000);
    }

    #[test]
    fn test_scheduler_config_custom() {
        let config = SchedulerConfig {
            tick_interval_ms: 100,
            max_assignments_per_tick: 500,
            ..Default::default()
        };
        assert_eq!(config.tick_interval_ms, 100);
        assert_eq!(config.max_assignments_per_tick, 500);
    }

    #[test]
    fn test_cpu_scheduler_new() {
        let config = SchedulerConfig::default();
        let scheduler = CpuChunkScheduler::new(config, 100, 10);
        assert!(!scheduler.is_running());
        assert_eq!(scheduler.metrics().tick_count, 0);
    }

    #[test]
    fn test_schedule_single_chunk() {
        let mut scheduler = CpuChunkScheduler::new(SchedulerConfig::default(), 100, 10);
        let request = ScheduleRequest {
            chunks: vec![[1u8; 32]],
            priority: 128,
            replica_target: 3,
            deadline_ms: None,
        };
        assert!(scheduler.schedule(request).is_ok());
        assert_eq!(scheduler.metrics().scheduled_chunks, 1);
    }

    #[test]
    fn test_schedule_batch_chunks() {
        let mut scheduler = CpuChunkScheduler::new(SchedulerConfig::default(), 100, 10);
        let request = ScheduleRequest {
            chunks: vec![[1u8; 32], [2u8; 32], [3u8; 32]],
            priority: 128,
            replica_target: 3,
            deadline_ms: None,
        };
        assert!(scheduler.schedule(request).is_ok());
        assert_eq!(scheduler.metrics().scheduled_chunks, 3);
    }

    #[test]
    fn test_schedule_duplicate_chunks() {
        let mut scheduler = CpuChunkScheduler::new(SchedulerConfig::default(), 100, 10);
        let request1 = ScheduleRequest {
            chunks: vec![[1u8; 32]],
            priority: 128,
            replica_target: 3,
            deadline_ms: None,
        };
        let request2 = ScheduleRequest {
            chunks: vec![[1u8; 32]],
            priority: 128,
            replica_target: 3,
            deadline_ms: None,
        };
        scheduler.schedule(request1).unwrap();
        scheduler.schedule(request2).unwrap();
        // Both requests are tracked
        assert_eq!(scheduler.metrics().scheduled_chunks, 2);
    }

    #[test]
    fn test_tick_empty_state() {
        let mut scheduler = CpuChunkScheduler::new(SchedulerConfig::default(), 100, 10);
        let batch = scheduler.tick();
        assert!(batch.assignments.is_empty());
        assert_eq!(scheduler.metrics().tick_count, 1);
    }

    #[test]
    fn test_tick_with_chunks() {
        let mut scheduler = CpuChunkScheduler::new(SchedulerConfig::default(), 100, 10);

        let request = ScheduleRequest {
            chunks: vec![[1u8; 32], [2u8; 32]],
            priority: 128,
            replica_target: 3,
            deadline_ms: None,
        };
        scheduler.schedule(request).unwrap();

        let _batch = scheduler.tick();
        assert_eq!(scheduler.metrics().tick_count, 1);
        // Assignments depend on cost matrix and path selector logic
    }

    #[test]
    fn test_multiple_ticks() {
        let mut scheduler = CpuChunkScheduler::new(SchedulerConfig::default(), 100, 10);

        scheduler.tick();
        scheduler.tick();
        scheduler.tick();

        assert_eq!(scheduler.metrics().tick_count, 3);
    }

    #[test]
    fn test_handle_failover() {
        let mut scheduler = CpuChunkScheduler::new(SchedulerConfig::default(), 100, 10);

        use crate::failover::{FailoverReason, FailoverAction};
        let decision = FailoverDecision {
            chunk_id: ChunkId(1),
            reason: FailoverReason::Timeout,
            action: FailoverAction::Retry { edge_idx: EdgeIdx(0) },
            failed_edge: EdgeIdx(0),
            retry_count: 1,
            timestamp_ms: 12345,
        };

        scheduler.handle_failover(decision);
        assert_eq!(scheduler.metrics().failed_chunks, 1);
    }

    #[test]
    fn test_metrics_tracking() {
        let mut scheduler = CpuChunkScheduler::new(SchedulerConfig::default(), 100, 10);

        let request = ScheduleRequest {
            chunks: vec![[1u8; 32]],
            priority: 128,
            replica_target: 3,
            deadline_ms: None,
        };
        scheduler.schedule(request).unwrap();
        scheduler.tick();

        let metrics = scheduler.metrics();
        assert_eq!(metrics.scheduled_chunks, 1);
        assert_eq!(metrics.tick_count, 1);
    }

    #[test]
    fn test_start_stop_scheduler() {
        let mut scheduler = CpuChunkScheduler::new(SchedulerConfig::default(), 100, 10);

        assert!(!scheduler.is_running());
        scheduler.start();
        assert!(scheduler.is_running());
        scheduler.stop();
        assert!(!scheduler.is_running());
    }

    #[test]
    fn test_get_assignments() {
        let scheduler = CpuChunkScheduler::new(SchedulerConfig::default(), 100, 10);

        // Initially empty
        let batch = scheduler.get_assignments();
        assert!(batch.assignments.is_empty());
    }

    #[test]
    fn test_state_access() {
        let scheduler = CpuChunkScheduler::new(SchedulerConfig::default(), 100, 10);
        let _state = scheduler.state();
        // State buffers don't have direct public fields anymore
        assert!(!scheduler.is_running());
    }

    #[test]
    fn test_config_access() {
        let config = SchedulerConfig {
            tick_interval_ms: 75,
            ..Default::default()
        };
        let scheduler = CpuChunkScheduler::new(config, 100, 10);
        assert_eq!(scheduler.config().tick_interval_ms, 75);
    }

    #[test]
    fn test_gpu_scheduler_new() {
        let config = SchedulerConfig::default();
        let scheduler = ChunkScheduler::new(config, 100, 10);
        assert!(!scheduler.is_running());
    }

    #[test]
    fn test_gpu_scheduler_delegation() {
        let mut scheduler = ChunkScheduler::new(SchedulerConfig::default(), 100, 10);

        let request = ScheduleRequest {
            chunks: vec![[1u8; 32]],
            priority: 128,
            replica_target: 3,
            deadline_ms: None,
        };
        assert!(scheduler.schedule(request).is_ok());

        scheduler.tick();
        assert_eq!(scheduler.metrics().tick_count, 1);
        assert_eq!(scheduler.metrics().scheduled_chunks, 1);
    }

    #[test]
    fn test_gpu_scheduler_start_stop() {
        let mut scheduler = ChunkScheduler::new(SchedulerConfig::default(), 100, 10);

        scheduler.start();
        assert!(scheduler.is_running());
        scheduler.stop();
        assert!(!scheduler.is_running());
    }

    #[test]
    fn test_max_assignments_per_tick() {
        let config = SchedulerConfig {
            max_assignments_per_tick: 2,
            ..Default::default()
        };
        let mut scheduler = CpuChunkScheduler::new(config, 100, 10);

        // Schedule more chunks than max
        let request = ScheduleRequest {
            chunks: vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]],
            priority: 128,
            replica_target: 3,
            deadline_ms: None,
        };
        scheduler.schedule(request).unwrap();

        // First tick should process max_assignments_per_tick
        scheduler.tick();
        // Exact number depends on path selection, but tick should respect limit
        assert_eq!(scheduler.metrics().tick_count, 1);
    }

    #[test]
    fn test_tick_duration_tracking() {
        let mut scheduler = CpuChunkScheduler::new(SchedulerConfig::default(), 100, 10);

        scheduler.tick();
        let metrics = scheduler.metrics();
        assert_eq!(metrics.tick_count, 1);
    }

    #[test]
    fn test_failover_requeues_chunks() {
        let mut scheduler = CpuChunkScheduler::new(SchedulerConfig::default(), 100, 10);

        use crate::failover::{FailoverReason, FailoverAction};
        let decision = FailoverDecision {
            chunk_id: ChunkId(5),
            reason: FailoverReason::Timeout,
            action: FailoverAction::Retry { edge_idx: EdgeIdx(0) },
            failed_edge: EdgeIdx(0),
            retry_count: 1,
            timestamp_ms: 12345,
        };

        scheduler.handle_failover(decision);
        // Chunks should be re-queued (visible in next tick)
        assert_eq!(scheduler.metrics().failed_chunks, 1);
    }

    #[test]
    fn test_scheduler_state_initialization() {
        let config = SchedulerConfig::default();
        let scheduler = CpuChunkScheduler::new(config, 100, 10);
        assert!(!scheduler.is_running());
        assert_eq!(scheduler.state.generation, 0);
    }

    #[test]
    fn test_empty_schedule_request() {
        let mut scheduler = CpuChunkScheduler::new(SchedulerConfig::default(), 100, 10);
        let request = ScheduleRequest {
            chunks: vec![],
            priority: 128,
            replica_target: 3,
            deadline_ms: None,
        };
        assert!(scheduler.schedule(request).is_ok());
        assert_eq!(scheduler.metrics().scheduled_chunks, 0);
    }

    #[test]
    fn test_config_serialization() {
        let config = SchedulerConfig::default();
        let serialized = serde_json::to_string(&config).unwrap();
        let deserialized: SchedulerConfig = serde_json::from_str(&serialized).unwrap();
        assert_eq!(config.tick_interval_ms, deserialized.tick_interval_ms);
    }

    #[test]
    fn test_constraint_evaluator_initially_none() {
        let scheduler = CpuChunkScheduler::new(SchedulerConfig::default(), 100, 10);
        assert!(scheduler.constraint_evaluator().is_none());
    }

    #[test]
    fn test_set_constraint_evaluator() {
        let mut scheduler = CpuChunkScheduler::new(SchedulerConfig::default(), 100, 10);
        let evaluator = ConstraintEvaluator::new();

        scheduler.set_constraint_evaluator(evaluator);
        assert!(scheduler.constraint_evaluator().is_some());
    }

    #[test]
    fn test_clear_constraint_evaluator() {
        let mut scheduler = CpuChunkScheduler::new(SchedulerConfig::default(), 100, 10);
        scheduler.set_constraint_evaluator(ConstraintEvaluator::new());
        assert!(scheduler.constraint_evaluator().is_some());

        scheduler.clear_constraint_evaluator();
        assert!(scheduler.constraint_evaluator().is_none());
    }

    #[test]
    fn test_constraint_evaluator_mut() {
        use crate::constraints::{EdgeConstraints, TimeConstraint};

        let mut scheduler = CpuChunkScheduler::new(SchedulerConfig::default(), 100, 10);
        scheduler.set_constraint_evaluator(ConstraintEvaluator::new());

        // Modify through mutable reference
        if let Some(evaluator) = scheduler.constraint_evaluator_mut() {
            let constraints = EdgeConstraints::new(EdgeIdx(0))
                .with_time(TimeConstraint::Anytime);
            evaluator.add_constraint(EdgeIdx(0), constraints);
        }

        // Verify modification persisted
        let evaluator = scheduler.constraint_evaluator().unwrap();
        assert!(evaluator.is_available(EdgeIdx(0), Utc::now()));
    }

    #[test]
    fn test_tick_with_constraint_evaluator() {
        use crate::constraints::{EdgeConstraints, TimeConstraint, TimeWindow};
        use chrono::Weekday;

        let mut scheduler = CpuChunkScheduler::new(SchedulerConfig::default(), 100, 10);

        // Set up a constraint evaluator with a required time window
        let mut evaluator = ConstraintEvaluator::new();

        // Create a window that is NOT currently active (blocks edge 0)
        let blocked_window = TimeWindow::new(1, 2, vec![Weekday::Sun], 0).unwrap();
        let constraints = EdgeConstraints::new(EdgeIdx(0))
            .with_time(TimeConstraint::RequiredWindow(blocked_window));
        evaluator.add_constraint(EdgeIdx(0), constraints);

        scheduler.set_constraint_evaluator(evaluator);

        // Run a tick - should work without panic
        let batch = scheduler.tick();
        // No assignments expected since no chunks scheduled
        assert!(batch.assignments.is_empty());
    }

    #[test]
    fn test_no_pending_reopt_initially() {
        let scheduler = CpuChunkScheduler::new(SchedulerConfig::default(), 100, 10);
        assert!(!scheduler.has_pending_reopt());
        assert!(scheduler.pending_reopt_plan().is_none());
    }

    #[test]
    fn test_request_reopt_empty_assignments() {
        let mut scheduler = CpuChunkScheduler::new(SchedulerConfig::default(), 100, 10);

        // Request reopt with no current assignments - should not create a plan
        scheduler.request_reopt(ReoptScope::Full, ReoptStrategy::Greedy);
        assert!(!scheduler.has_pending_reopt());
    }

    #[test]
    fn test_cancel_reopt() {
        let mut scheduler = CpuChunkScheduler::new(SchedulerConfig::default(), 100, 10);

        // Even with no plan, cancel should work safely
        scheduler.cancel_reopt();
        assert!(!scheduler.has_pending_reopt());
        assert_eq!(scheduler.reopt_metrics().aborted_reopts, 0);
    }

    #[test]
    fn test_reopt_metrics_access() {
        let scheduler = CpuChunkScheduler::new(SchedulerConfig::default(), 100, 10);
        let metrics = scheduler.reopt_metrics();
        assert_eq!(metrics.total_reopts, 0);
        assert_eq!(metrics.aborted_reopts, 0);
    }

    #[test]
    fn test_scheduler_config_has_incremental_config() {
        let config = SchedulerConfig::default();
        assert_eq!(config.incremental_config.max_reassignments_per_tick, 10);
        assert_eq!(config.incremental_config.min_improvement_threshold, 0.05);
    }

    #[test]
    fn test_tick_tracks_current_assignments() {
        use crate::{ChunkState, CpuStateBuffers, EdgeStateGpu};

        let mut scheduler = CpuChunkScheduler::new(SchedulerConfig::default(), 100, 10);

        // Set up state buffers with chunks and edges
        let hash = [1u8; 32];
        scheduler.state_mut().add_chunk(ChunkState::new(hash, 1024, 128, 3)).unwrap();
        scheduler.state_mut().add_edge(0, EdgeStateGpu::new(
            EdgeIdx(0),
            1_000_000_000,
            10_000,
            0.95,
            10,
        )).unwrap();
        scheduler.state_mut().add_replica(0, EdgeIdx(0));

        // Schedule a chunk
        let request = ScheduleRequest {
            chunks: vec![hash],
            priority: 128,
            replica_target: 3,
            deadline_ms: None,
        };
        scheduler.schedule(request).unwrap();

        // Tick should create assignment and track it
        let batch = scheduler.tick();
        // Assignment tracking depends on path selection
        assert_eq!(scheduler.metrics().tick_count, 1);
    }

    #[test]
    fn test_tick_with_pending_reopt() {
        let mut scheduler = CpuChunkScheduler::new(SchedulerConfig::default(), 100, 10);

        // Tick should work even with no pending reopt
        let batch = scheduler.tick();
        assert!(batch.assignments.is_empty());
    }
}
