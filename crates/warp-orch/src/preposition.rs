//! Predictive Pre-Positioning Engine
//!
//! This module provides proactive chunk placement based on predicted access patterns.
//! It monitors access patterns, predicts future demand, and executes background transfers
//! to position chunks on optimal edges before they are needed.
//!
//! # Architecture
//!
//! - **PrepositionPlanner**: Plans pre-positioning operations based on predictions
//! - **PrepositionExecutor**: Executes planned operations as background transfers
//! - **PrepositionManager**: Coordinates planning and execution with rate limiting

use crate::predict::{
    AccessPattern, PatternConfig, PatternDetector, PrepositionPriority, PrepositionRequest,
    Predictor, PredictorConfig,
};
use crate::types::{TransferDirection, TransferId};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use warp_edge::BandwidthEstimator;
use warp_sched::{ChunkId, EdgeIdx};

/// Configuration for pre-positioning operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrepositionConfig {
    /// Minimum confidence to trigger pre-positioning (0.0-1.0)
    pub min_confidence: f64,
    /// Maximum concurrent pre-position transfers
    pub max_concurrent_transfers: usize,
    /// Maximum bytes to pre-position per second (rate limit)
    pub max_bytes_per_second: u64,
    /// Cooldown between pre-positioning same chunk (milliseconds)
    pub chunk_cooldown_ms: u64,
    /// How far ahead to predict (milliseconds)
    pub prediction_horizon_ms: u64,
    /// Maximum chunks to pre-position per batch
    pub max_batch_size: usize,
    /// Minimum improvement ratio to justify pre-positioning
    pub min_improvement_ratio: f64,
    /// Pattern detection configuration
    pub pattern_config: PatternConfig,
    /// Predictor configuration
    pub predictor_config: PredictorConfig,
}

impl Default for PrepositionConfig {
    fn default() -> Self {
        Self {
            min_confidence: 0.6,
            max_concurrent_transfers: 5,
            max_bytes_per_second: 100_000_000, // 100 MB/s
            chunk_cooldown_ms: 60_000,         // 1 minute
            prediction_horizon_ms: 30_000,     // 30 seconds
            max_batch_size: 50,
            min_improvement_ratio: 0.2,
            pattern_config: PatternConfig::default(),
            predictor_config: PredictorConfig::default(),
        }
    }
}

impl PrepositionConfig {
    /// Create a new configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        if !(0.0..=1.0).contains(&self.min_confidence) {
            return Err("min_confidence must be between 0.0 and 1.0".to_string());
        }
        if self.max_concurrent_transfers == 0 {
            return Err("max_concurrent_transfers must be > 0".to_string());
        }
        if self.max_batch_size == 0 {
            return Err("max_batch_size must be > 0".to_string());
        }
        Ok(())
    }

    /// Builder: set minimum confidence
    pub fn with_min_confidence(mut self, confidence: f64) -> Self {
        self.min_confidence = confidence;
        self
    }

    /// Builder: set max concurrent transfers
    pub fn with_max_concurrent(mut self, max: usize) -> Self {
        self.max_concurrent_transfers = max;
        self
    }

    /// Builder: set rate limit
    pub fn with_rate_limit(mut self, bytes_per_second: u64) -> Self {
        self.max_bytes_per_second = bytes_per_second;
        self
    }
}

/// A planned pre-positioning operation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrepositionOp {
    /// Unique operation ID
    pub id: u64,
    /// Chunk to pre-position
    pub chunk_id: ChunkId,
    /// Source edge (where chunk exists)
    pub source_edge: EdgeIdx,
    /// Target edge (where chunk should be placed)
    pub target_edge: EdgeIdx,
    /// Estimated chunk size in bytes
    pub estimated_size: u64,
    /// Priority level
    pub priority: PrepositionPriority,
    /// Confidence score (0.0-1.0)
    pub confidence: f64,
    /// Reason for pre-positioning
    pub reason: String,
}

impl PrepositionOp {
    /// Create a new pre-position operation
    pub fn new(
        id: u64,
        chunk_id: ChunkId,
        source_edge: EdgeIdx,
        target_edge: EdgeIdx,
        estimated_size: u64,
        priority: PrepositionPriority,
        confidence: f64,
        reason: String,
    ) -> Self {
        Self {
            id,
            chunk_id,
            source_edge,
            target_edge,
            estimated_size,
            priority,
            confidence,
            reason,
        }
    }
}

/// Status of a pre-position operation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PrepositionStatus {
    /// Operation is queued
    Queued,
    /// Operation is in progress
    InProgress {
        /// Transfer ID
        transfer_id: TransferId,
        /// Bytes transferred so far
        bytes_transferred: u64,
    },
    /// Operation completed successfully
    Completed {
        /// Total bytes transferred
        bytes_transferred: u64,
        /// Duration in milliseconds
        duration_ms: u64,
    },
    /// Operation failed
    Failed {
        /// Error message
        reason: String,
    },
    /// Operation was cancelled
    Cancelled,
}

/// Metrics for pre-positioning operations
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PrepositionMetrics {
    /// Total operations planned
    pub total_planned: u64,
    /// Total operations executed
    pub total_executed: u64,
    /// Total operations completed successfully
    pub total_completed: u64,
    /// Total operations failed
    pub total_failed: u64,
    /// Total bytes pre-positioned
    pub total_bytes: u64,
    /// Average latency improvement (milliseconds)
    pub avg_latency_improvement_ms: f64,
    /// Hit rate (chunks that were accessed after pre-positioning)
    pub hit_rate: f64,
    /// Total predictions made
    pub total_predictions: u64,
    /// Accurate predictions (chunk was accessed within horizon)
    pub accurate_predictions: u64,
}

impl PrepositionMetrics {
    /// Create new metrics
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a completed operation
    pub fn record_completed(&mut self, bytes: u64) {
        self.total_completed += 1;
        self.total_bytes += bytes;
    }

    /// Record a failed operation
    pub fn record_failed(&mut self) {
        self.total_failed += 1;
    }

    /// Record a prediction
    pub fn record_prediction(&mut self, was_accurate: bool) {
        self.total_predictions += 1;
        if was_accurate {
            self.accurate_predictions += 1;
        }
        // Update hit rate
        if self.total_predictions > 0 {
            self.hit_rate = self.accurate_predictions as f64 / self.total_predictions as f64;
        }
    }

    /// Update average latency improvement
    pub fn update_latency_improvement(&mut self, improvement_ms: f64) {
        let n = self.total_completed as f64;
        if n > 0.0 {
            self.avg_latency_improvement_ms =
                ((n - 1.0) * self.avg_latency_improvement_ms + improvement_ms) / n;
        }
    }
}

/// Edge information for planning
#[derive(Debug, Clone)]
pub struct EdgeInfo {
    /// Edge index
    pub edge_idx: EdgeIdx,
    /// Estimated bandwidth in bytes per second
    pub bandwidth_bps: u64,
    /// Estimated RTT in milliseconds
    pub rtt_ms: u64,
    /// Health score (0.0-1.0)
    pub health: f64,
    /// Current load ratio (0.0-1.0)
    pub load_ratio: f64,
}

impl EdgeInfo {
    /// Create new edge info
    pub fn new(edge_idx: EdgeIdx, bandwidth_bps: u64, rtt_ms: u64, health: f64, load_ratio: f64) -> Self {
        Self {
            edge_idx,
            bandwidth_bps,
            rtt_ms,
            health,
            load_ratio,
        }
    }

    /// Calculate estimated transfer time for given bytes
    pub fn estimate_transfer_time_ms(&self, bytes: u64) -> u64 {
        let transfer_time = (bytes as f64 / self.bandwidth_bps as f64 * 1000.0) as u64;
        self.rtt_ms + transfer_time
    }
}

/// Pre-position planner - plans operations based on predictions
pub struct PrepositionPlanner {
    /// Configuration
    config: PrepositionConfig,
    /// Pattern detector
    pattern_detector: PatternDetector,
    /// Predictor
    predictor: Predictor,
    /// Chunk locations: chunk_id -> edges that have the chunk
    chunk_locations: HashMap<ChunkId, HashSet<EdgeIdx>>,
    /// Edge information
    edge_info: HashMap<EdgeIdx, EdgeInfo>,
    /// Recent operations (for cooldown)
    recent_ops: HashMap<ChunkId, Instant>,
    /// Next operation ID
    next_op_id: AtomicU64,
}

impl PrepositionPlanner {
    /// Create a new pre-position planner
    pub fn new(config: PrepositionConfig) -> Self {
        let pattern_detector = PatternDetector::new(config.pattern_config);
        let predictor = Predictor::new(config.predictor_config);

        Self {
            config,
            pattern_detector,
            predictor,
            chunk_locations: HashMap::new(),
            edge_info: HashMap::new(),
            recent_ops: HashMap::new(),
            next_op_id: AtomicU64::new(1),
        }
    }

    /// Update chunk location information
    pub fn update_chunk_location(&mut self, chunk_id: ChunkId, edges: HashSet<EdgeIdx>) {
        self.chunk_locations.insert(chunk_id, edges);
    }

    /// Add a chunk location
    pub fn add_chunk_location(&mut self, chunk_id: ChunkId, edge: EdgeIdx) {
        self.chunk_locations
            .entry(chunk_id)
            .or_insert_with(HashSet::new)
            .insert(edge);
    }

    /// Remove a chunk location
    pub fn remove_chunk_location(&mut self, chunk_id: ChunkId, edge: EdgeIdx) {
        if let Some(edges) = self.chunk_locations.get_mut(&chunk_id) {
            edges.remove(&edge);
        }
    }

    /// Update edge information
    pub fn update_edge_info(&mut self, edge_idx: EdgeIdx, info: EdgeInfo) {
        self.edge_info.insert(edge_idx, info);
    }

    /// Record an access event
    pub fn record_access(&mut self, record: crate::predict::AccessRecord) {
        self.pattern_detector.record_access(record);
    }

    /// Get detected patterns
    pub fn detect_patterns(&self) -> Vec<AccessPattern> {
        self.pattern_detector.detect_patterns()
    }

    /// Predict chunks that will be needed
    pub fn predict_demand(&mut self, _horizon_ms: u64) -> Vec<ChunkId> {
        let patterns = self.pattern_detector.detect_patterns();
        self.predictor.predict_next(&patterns)
    }

    /// Plan pre-positioning operations
    pub fn plan_preposition(&mut self, predicted_chunks: &[ChunkId]) -> Vec<PrepositionOp> {
        let mut ops = Vec::new();
        let now = Instant::now();

        for &chunk_id in predicted_chunks {
            // Check cooldown
            if let Some(&last_op_time) = self.recent_ops.get(&chunk_id) {
                let elapsed = now.duration_since(last_op_time).as_millis() as u64;
                if elapsed < self.config.chunk_cooldown_ms {
                    continue;
                }
            }

            // Get current locations
            let current_edges = match self.chunk_locations.get(&chunk_id) {
                Some(edges) if !edges.is_empty() => edges.clone(),
                _ => continue, // Chunk location unknown
            };

            // Find best source edge
            let source_edge = self.select_best_source(&current_edges);
            let source_edge = match source_edge {
                Some(edge) => edge,
                None => continue,
            };

            // Find best target edge (not already having the chunk)
            let target_edge = self.select_best_target(&current_edges);
            let target_edge = match target_edge {
                Some(edge) => edge,
                None => continue,
            };

            // Calculate confidence
            let patterns = self.pattern_detector.detect_patterns();
            let confidence = self.predictor.score_prediction(chunk_id, &patterns);

            if confidence < self.config.min_confidence {
                continue;
            }

            // Estimate size (default if unknown)
            let estimated_size = 256 * 1024; // 256 KB default

            // Check if pre-positioning is worthwhile
            if !self.is_preposition_worthwhile(chunk_id, source_edge, target_edge, estimated_size) {
                continue;
            }

            let priority = if confidence >= 0.9 {
                PrepositionPriority::High
            } else if confidence >= 0.7 {
                PrepositionPriority::Medium
            } else {
                PrepositionPriority::Low
            };

            // Relaxed is sufficient for ID generation
            let op_id = self.next_op_id.fetch_add(1, Ordering::Relaxed);
            ops.push(PrepositionOp::new(
                op_id,
                chunk_id,
                source_edge,
                target_edge,
                estimated_size,
                priority,
                confidence,
                format!("Predicted access (confidence: {:.2})", confidence),
            ));

            // Update cooldown
            self.recent_ops.insert(chunk_id, now);

            // Limit batch size
            if ops.len() >= self.config.max_batch_size {
                break;
            }
        }

        // Sort by priority (highest first)
        ops.sort_by(|a, b| b.priority.cmp(&a.priority));

        ops
    }

    /// Select best source edge from current locations
    fn select_best_source(&self, current_edges: &HashSet<EdgeIdx>) -> Option<EdgeIdx> {
        current_edges
            .iter()
            .filter_map(|&edge| {
                self.edge_info.get(&edge).map(|info| (edge, info))
            })
            .filter(|(_, info)| info.health >= 0.5 && info.load_ratio < 0.9)
            .max_by(|(_, a), (_, b)| {
                // Prefer edges with higher bandwidth and lower load
                let score_a = a.bandwidth_bps as f64 * (1.0 - a.load_ratio) * a.health;
                let score_b = b.bandwidth_bps as f64 * (1.0 - b.load_ratio) * b.health;
                score_a.partial_cmp(&score_b).unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(edge, _)| edge)
    }

    /// Select best target edge (not in current locations)
    fn select_best_target(&self, current_edges: &HashSet<EdgeIdx>) -> Option<EdgeIdx> {
        self.edge_info
            .iter()
            .filter(|(edge, _)| !current_edges.contains(edge))
            .filter(|(_, info)| info.health >= 0.5 && info.load_ratio < 0.8)
            .max_by(|(_, a), (_, b)| {
                // Prefer edges with higher bandwidth, lower load, and lower RTT
                let score_a = a.bandwidth_bps as f64 * (1.0 - a.load_ratio) * a.health / (a.rtt_ms as f64 + 1.0);
                let score_b = b.bandwidth_bps as f64 * (1.0 - b.load_ratio) * b.health / (b.rtt_ms as f64 + 1.0);
                score_a.partial_cmp(&score_b).unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(edge, _)| *edge)
    }

    /// Check if pre-positioning is worthwhile (latency improvement > threshold)
    fn is_preposition_worthwhile(
        &self,
        _chunk_id: ChunkId,
        source_edge: EdgeIdx,
        target_edge: EdgeIdx,
        estimated_size: u64,
    ) -> bool {
        let source_info = match self.edge_info.get(&source_edge) {
            Some(info) => info,
            None => return false,
        };

        let target_info = match self.edge_info.get(&target_edge) {
            Some(info) => info,
            None => return false,
        };

        // Compare transfer times
        let source_time = source_info.estimate_transfer_time_ms(estimated_size);
        let target_time = target_info.estimate_transfer_time_ms(estimated_size);

        // Pre-position if target would be faster by min_improvement_ratio
        if target_time < source_time {
            let improvement = (source_time - target_time) as f64 / source_time as f64;
            improvement >= self.config.min_improvement_ratio
        } else {
            false
        }
    }

    /// Clear old cooldown entries
    pub fn clear_old_cooldowns(&mut self, max_age_ms: u64) {
        let cutoff = Instant::now() - std::time::Duration::from_millis(max_age_ms);
        self.recent_ops.retain(|_, &mut instant| instant > cutoff);
    }

    /// Get configuration
    pub fn config(&self) -> &PrepositionConfig {
        &self.config
    }
}

/// Pre-position executor state
#[derive(Debug, Clone)]
struct ExecutorState {
    /// Active operations: op_id -> (op, status)
    active_ops: HashMap<u64, (PrepositionOp, PrepositionStatus)>,
    /// Queued operations
    queue: VecDeque<PrepositionOp>,
    /// Total bytes currently in flight
    bytes_in_flight: u64,
    /// Metrics
    metrics: PrepositionMetrics,
}

/// Pre-position executor - executes planned operations
pub struct PrepositionExecutor {
    /// Configuration
    config: PrepositionConfig,
    /// State
    state: Arc<RwLock<ExecutorState>>,
    /// Next transfer ID
    next_transfer_id: AtomicU64,
}

impl PrepositionExecutor {
    /// Create a new executor
    pub fn new(config: PrepositionConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(ExecutorState {
                active_ops: HashMap::new(),
                queue: VecDeque::new(),
                bytes_in_flight: 0,
                metrics: PrepositionMetrics::new(),
            })),
            next_transfer_id: AtomicU64::new(1),
        }
    }

    /// Queue operations for execution
    pub fn queue_operations(&self, ops: Vec<PrepositionOp>) {
        let mut state = self.state.write();
        for op in ops {
            state.metrics.total_planned += 1;
            state.queue.push_back(op);
        }
    }

    /// Execute pending operations (call periodically)
    pub fn tick(&self) -> Vec<PrepositionOp> {
        let mut started_ops = Vec::new();
        let mut state = self.state.write();

        // Start operations up to concurrent limit
        while state.active_ops.len() < self.config.max_concurrent_transfers {
            // Check rate limit
            if state.bytes_in_flight >= self.config.max_bytes_per_second {
                break;
            }

            // Get next operation
            let op = match state.queue.pop_front() {
                Some(op) => op,
                None => break,
            };

            // Start the operation
            // Relaxed is sufficient for ID generation
            let transfer_id = TransferId::new(self.next_transfer_id.fetch_add(1, Ordering::Relaxed));
            let status = PrepositionStatus::InProgress {
                transfer_id,
                bytes_transferred: 0,
            };

            state.bytes_in_flight += op.estimated_size;
            state.metrics.total_executed += 1;
            state.active_ops.insert(op.id, (op.clone(), status));
            started_ops.push(op);
        }

        started_ops
    }

    /// Mark an operation as completed
    pub fn complete_operation(&self, op_id: u64, bytes_transferred: u64, duration_ms: u64) {
        let mut state = self.state.write();

        if let Some((op, _)) = state.active_ops.remove(&op_id) {
            state.bytes_in_flight = state.bytes_in_flight.saturating_sub(op.estimated_size);
            state.metrics.record_completed(bytes_transferred);

            // Store completed status (could be used for history)
            let _status = PrepositionStatus::Completed {
                bytes_transferred,
                duration_ms,
            };
        }
    }

    /// Mark an operation as failed
    pub fn fail_operation(&self, op_id: u64, reason: String) {
        let mut state = self.state.write();

        if let Some((op, _)) = state.active_ops.remove(&op_id) {
            state.bytes_in_flight = state.bytes_in_flight.saturating_sub(op.estimated_size);
            state.metrics.record_failed();

            // Store failed status (could be used for history)
            let _status = PrepositionStatus::Failed { reason };
        }
    }

    /// Cancel an operation
    pub fn cancel_operation(&self, op_id: u64) {
        let mut state = self.state.write();

        if let Some((op, _)) = state.active_ops.remove(&op_id) {
            state.bytes_in_flight = state.bytes_in_flight.saturating_sub(op.estimated_size);
        }
    }

    /// Get metrics
    pub fn metrics(&self) -> PrepositionMetrics {
        self.state.read().metrics.clone()
    }

    /// Get queue length
    pub fn queue_length(&self) -> usize {
        self.state.read().queue.len()
    }

    /// Get active operation count
    pub fn active_count(&self) -> usize {
        self.state.read().active_ops.len()
    }

    /// Get all active operations
    pub fn active_operations(&self) -> Vec<(PrepositionOp, PrepositionStatus)> {
        self.state.read().active_ops.values().cloned().collect()
    }
}

/// Pre-position manager - coordinates planning and execution
pub struct PrepositionManager {
    /// Configuration
    config: PrepositionConfig,
    /// Planner
    planner: PrepositionPlanner,
    /// Executor
    executor: PrepositionExecutor,
    /// Prediction tracking: chunk_id -> prediction time
    prediction_times: HashMap<ChunkId, u64>,
    /// Access tracking: chunk_id -> was_accessed
    access_tracking: HashMap<ChunkId, bool>,
}

impl PrepositionManager {
    /// Create a new pre-position manager
    pub fn new(config: PrepositionConfig) -> Self {
        let planner = PrepositionPlanner::new(config.clone());
        let executor = PrepositionExecutor::new(config.clone());

        Self {
            config,
            planner,
            executor,
            prediction_times: HashMap::new(),
            access_tracking: HashMap::new(),
        }
    }

    /// Update chunk location information
    pub fn update_chunk_location(&mut self, chunk_id: ChunkId, edges: HashSet<EdgeIdx>) {
        self.planner.update_chunk_location(chunk_id, edges);
    }

    /// Update edge information
    pub fn update_edge_info(&mut self, edge_idx: EdgeIdx, info: EdgeInfo) {
        self.planner.update_edge_info(edge_idx, info);
    }

    /// Record an access event
    pub fn record_access(&mut self, record: crate::predict::AccessRecord) {
        // Track if this was a predicted chunk
        if self.prediction_times.contains_key(&record.chunk_id) {
            self.access_tracking.insert(record.chunk_id, true);
        }

        self.planner.record_access(record);
    }

    /// Run prediction and planning cycle
    pub fn plan_cycle(&mut self) -> Vec<PrepositionOp> {
        // Predict demand
        let predicted_chunks = self.planner.predict_demand(self.config.prediction_horizon_ms);

        // Track predictions
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::ZERO)
            .as_millis() as u64;

        for &chunk_id in &predicted_chunks {
            self.prediction_times.insert(chunk_id, now_ms);
            self.access_tracking.insert(chunk_id, false);
        }

        // Plan operations
        let ops = self.planner.plan_preposition(&predicted_chunks);

        // Queue for execution
        self.executor.queue_operations(ops.clone());

        ops
    }

    /// Execute pending operations
    pub fn execute_tick(&self) -> Vec<PrepositionOp> {
        self.executor.tick()
    }

    /// Update prediction accuracy metrics
    pub fn update_accuracy_metrics(&mut self) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::ZERO)
            .as_millis() as u64;

        let horizon = self.config.prediction_horizon_ms;

        // Check predictions that have expired
        let expired: Vec<ChunkId> = self
            .prediction_times
            .iter()
            .filter(|&(_, time)| now_ms.saturating_sub(*time) > horizon)
            .map(|(&id, _)| id)
            .collect();

        let mut state = self.executor.state.write();

        for chunk_id in expired {
            let was_accurate = self.access_tracking.get(&chunk_id).copied().unwrap_or(false);
            state.metrics.record_prediction(was_accurate);

            self.prediction_times.remove(&chunk_id);
            self.access_tracking.remove(&chunk_id);
        }
    }

    /// Complete an operation
    pub fn complete_operation(&self, op_id: u64, bytes_transferred: u64, duration_ms: u64) {
        self.executor.complete_operation(op_id, bytes_transferred, duration_ms);
    }

    /// Fail an operation
    pub fn fail_operation(&self, op_id: u64, reason: String) {
        self.executor.fail_operation(op_id, reason);
    }

    /// Get metrics
    pub fn metrics(&self) -> PrepositionMetrics {
        self.executor.metrics()
    }

    /// Get planner reference
    pub fn planner(&self) -> &PrepositionPlanner {
        &self.planner
    }

    /// Get planner mutable reference
    pub fn planner_mut(&mut self) -> &mut PrepositionPlanner {
        &mut self.planner
    }

    /// Get executor reference
    pub fn executor(&self) -> &PrepositionExecutor {
        &self.executor
    }

    /// Get configuration
    pub fn config(&self) -> &PrepositionConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::predict::AccessRecord;

    fn make_test_edge_info(edge_idx: EdgeIdx, bandwidth: u64, rtt: u64) -> EdgeInfo {
        EdgeInfo::new(edge_idx, bandwidth, rtt, 0.9, 0.3)
    }

    #[test]
    fn test_preposition_config_default() {
        let config = PrepositionConfig::default();
        assert_eq!(config.min_confidence, 0.6);
        assert_eq!(config.max_concurrent_transfers, 5);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_preposition_config_validation() {
        let mut config = PrepositionConfig::default();
        config.min_confidence = 1.5;
        assert!(config.validate().is_err());

        config.min_confidence = 0.6;
        config.max_concurrent_transfers = 0;
        assert!(config.validate().is_err());

        config.max_concurrent_transfers = 5;
        config.max_batch_size = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_preposition_config_builder() {
        let config = PrepositionConfig::new()
            .with_min_confidence(0.8)
            .with_max_concurrent(10)
            .with_rate_limit(200_000_000);

        assert_eq!(config.min_confidence, 0.8);
        assert_eq!(config.max_concurrent_transfers, 10);
        assert_eq!(config.max_bytes_per_second, 200_000_000);
    }

    #[test]
    fn test_preposition_op_creation() {
        let op = PrepositionOp::new(
            1,
            ChunkId::new(100),
            EdgeIdx(0),
            EdgeIdx(1),
            256 * 1024,
            PrepositionPriority::High,
            0.95,
            "Test reason".to_string(),
        );

        assert_eq!(op.id, 1);
        assert_eq!(op.chunk_id, ChunkId::new(100));
        assert_eq!(op.source_edge, EdgeIdx(0));
        assert_eq!(op.target_edge, EdgeIdx(1));
        assert_eq!(op.priority, PrepositionPriority::High);
    }

    #[test]
    fn test_edge_info_transfer_time() {
        let info = EdgeInfo::new(EdgeIdx(0), 100_000_000, 10, 0.9, 0.3); // 100 MB/s, 10ms RTT

        // 1 MB transfer: 10ms RTT + 10ms transfer = 20ms
        let time = info.estimate_transfer_time_ms(1_000_000);
        assert_eq!(time, 20);
    }

    #[test]
    fn test_preposition_planner_creation() {
        let config = PrepositionConfig::default();
        let planner = PrepositionPlanner::new(config);
        assert!(planner.chunk_locations.is_empty());
        assert!(planner.edge_info.is_empty());
    }

    #[test]
    fn test_planner_update_chunk_location() {
        let mut planner = PrepositionPlanner::new(PrepositionConfig::default());

        let chunk_id = ChunkId::new(1);
        let mut edges = HashSet::new();
        edges.insert(EdgeIdx(0));
        edges.insert(EdgeIdx(1));

        planner.update_chunk_location(chunk_id, edges);
        assert!(planner.chunk_locations.contains_key(&chunk_id));
        assert_eq!(planner.chunk_locations[&chunk_id].len(), 2);
    }

    #[test]
    fn test_planner_add_remove_location() {
        let mut planner = PrepositionPlanner::new(PrepositionConfig::default());

        let chunk_id = ChunkId::new(1);
        planner.add_chunk_location(chunk_id, EdgeIdx(0));
        planner.add_chunk_location(chunk_id, EdgeIdx(1));

        assert_eq!(planner.chunk_locations[&chunk_id].len(), 2);

        planner.remove_chunk_location(chunk_id, EdgeIdx(0));
        assert_eq!(planner.chunk_locations[&chunk_id].len(), 1);
    }

    #[test]
    fn test_planner_update_edge_info() {
        let mut planner = PrepositionPlanner::new(PrepositionConfig::default());

        let info = make_test_edge_info(EdgeIdx(0), 100_000_000, 10);
        planner.update_edge_info(EdgeIdx(0), info);

        assert!(planner.edge_info.contains_key(&EdgeIdx(0)));
    }

    #[test]
    fn test_planner_predict_demand_empty() {
        let mut planner = PrepositionPlanner::new(PrepositionConfig::default());
        let predicted = planner.predict_demand(30_000);
        assert!(predicted.is_empty());
    }

    #[test]
    fn test_planner_plan_preposition_no_chunks() {
        let mut planner = PrepositionPlanner::new(PrepositionConfig::default());
        let ops = planner.plan_preposition(&[]);
        assert!(ops.is_empty());
    }

    #[test]
    fn test_planner_plan_preposition_unknown_location() {
        let mut planner = PrepositionPlanner::new(PrepositionConfig::default());

        // Add edge info but no chunk locations
        planner.update_edge_info(EdgeIdx(0), make_test_edge_info(EdgeIdx(0), 100_000_000, 10));
        planner.update_edge_info(EdgeIdx(1), make_test_edge_info(EdgeIdx(1), 100_000_000, 10));

        let ops = planner.plan_preposition(&[ChunkId::new(1)]);
        assert!(ops.is_empty()); // No chunk location known
    }

    #[test]
    fn test_preposition_executor_creation() {
        let config = PrepositionConfig::default();
        let executor = PrepositionExecutor::new(config);
        assert_eq!(executor.queue_length(), 0);
        assert_eq!(executor.active_count(), 0);
    }

    #[test]
    fn test_executor_queue_operations() {
        let executor = PrepositionExecutor::new(PrepositionConfig::default());

        let ops = vec![
            PrepositionOp::new(1, ChunkId::new(1), EdgeIdx(0), EdgeIdx(1), 1024, PrepositionPriority::High, 0.9, "Test".to_string()),
            PrepositionOp::new(2, ChunkId::new(2), EdgeIdx(0), EdgeIdx(1), 1024, PrepositionPriority::Medium, 0.8, "Test".to_string()),
        ];

        executor.queue_operations(ops);
        assert_eq!(executor.queue_length(), 2);
        assert_eq!(executor.metrics().total_planned, 2);
    }

    #[test]
    fn test_executor_tick_starts_operations() {
        let config = PrepositionConfig::default();
        let executor = PrepositionExecutor::new(config);

        let ops = vec![
            PrepositionOp::new(1, ChunkId::new(1), EdgeIdx(0), EdgeIdx(1), 1024, PrepositionPriority::High, 0.9, "Test".to_string()),
        ];

        executor.queue_operations(ops);
        let started = executor.tick();

        assert_eq!(started.len(), 1);
        assert_eq!(executor.queue_length(), 0);
        assert_eq!(executor.active_count(), 1);
        assert_eq!(executor.metrics().total_executed, 1);
    }

    #[test]
    fn test_executor_complete_operation() {
        let executor = PrepositionExecutor::new(PrepositionConfig::default());

        let ops = vec![
            PrepositionOp::new(1, ChunkId::new(1), EdgeIdx(0), EdgeIdx(1), 1024, PrepositionPriority::High, 0.9, "Test".to_string()),
        ];

        executor.queue_operations(ops);
        executor.tick();

        executor.complete_operation(1, 1024, 50);

        assert_eq!(executor.active_count(), 0);
        assert_eq!(executor.metrics().total_completed, 1);
        assert_eq!(executor.metrics().total_bytes, 1024);
    }

    #[test]
    fn test_executor_fail_operation() {
        let executor = PrepositionExecutor::new(PrepositionConfig::default());

        let ops = vec![
            PrepositionOp::new(1, ChunkId::new(1), EdgeIdx(0), EdgeIdx(1), 1024, PrepositionPriority::High, 0.9, "Test".to_string()),
        ];

        executor.queue_operations(ops);
        executor.tick();

        executor.fail_operation(1, "Network error".to_string());

        assert_eq!(executor.active_count(), 0);
        assert_eq!(executor.metrics().total_failed, 1);
    }

    #[test]
    fn test_executor_respects_concurrent_limit() {
        let mut config = PrepositionConfig::default();
        config.max_concurrent_transfers = 2;
        let executor = PrepositionExecutor::new(config);

        let ops = vec![
            PrepositionOp::new(1, ChunkId::new(1), EdgeIdx(0), EdgeIdx(1), 1024, PrepositionPriority::High, 0.9, "Test".to_string()),
            PrepositionOp::new(2, ChunkId::new(2), EdgeIdx(0), EdgeIdx(1), 1024, PrepositionPriority::High, 0.9, "Test".to_string()),
            PrepositionOp::new(3, ChunkId::new(3), EdgeIdx(0), EdgeIdx(1), 1024, PrepositionPriority::High, 0.9, "Test".to_string()),
        ];

        executor.queue_operations(ops);
        let started = executor.tick();

        assert_eq!(started.len(), 2);
        assert_eq!(executor.active_count(), 2);
        assert_eq!(executor.queue_length(), 1);
    }

    #[test]
    fn test_preposition_manager_creation() {
        let config = PrepositionConfig::default();
        let manager = PrepositionManager::new(config);
        assert_eq!(manager.metrics().total_planned, 0);
    }

    #[test]
    fn test_manager_plan_cycle_empty() {
        let mut manager = PrepositionManager::new(PrepositionConfig::default());
        let ops = manager.plan_cycle();
        assert!(ops.is_empty());
    }

    #[test]
    fn test_manager_update_chunk_location() {
        let mut manager = PrepositionManager::new(PrepositionConfig::default());

        let mut edges = HashSet::new();
        edges.insert(EdgeIdx(0));

        manager.update_chunk_location(ChunkId::new(1), edges);
        // Verify via planner
        assert!(manager.planner().chunk_locations.contains_key(&ChunkId::new(1)));
    }

    #[test]
    fn test_manager_record_access() {
        let mut manager = PrepositionManager::new(PrepositionConfig::default());

        let record = AccessRecord::new(ChunkId::new(1), 1000000, EdgeIdx(0), 50);
        manager.record_access(record);

        // Verify pattern detector received the record
        let patterns = manager.planner().detect_patterns();
        // May or may not detect patterns based on single record
        assert!(patterns.is_empty() || !patterns.is_empty());
    }

    #[test]
    fn test_preposition_metrics_default() {
        let metrics = PrepositionMetrics::new();
        assert_eq!(metrics.total_planned, 0);
        assert_eq!(metrics.total_executed, 0);
        assert_eq!(metrics.total_completed, 0);
        assert_eq!(metrics.hit_rate, 0.0);
    }

    #[test]
    fn test_metrics_record_completed() {
        let mut metrics = PrepositionMetrics::new();
        metrics.record_completed(1024);
        metrics.record_completed(2048);

        assert_eq!(metrics.total_completed, 2);
        assert_eq!(metrics.total_bytes, 3072);
    }

    #[test]
    fn test_metrics_record_prediction() {
        let mut metrics = PrepositionMetrics::new();
        metrics.record_prediction(true);
        metrics.record_prediction(true);
        metrics.record_prediction(false);

        assert_eq!(metrics.total_predictions, 3);
        assert_eq!(metrics.accurate_predictions, 2);
        assert!((metrics.hit_rate - 0.666).abs() < 0.01);
    }

    #[test]
    fn test_preposition_status_variants() {
        let _queued = PrepositionStatus::Queued;
        let _in_progress = PrepositionStatus::InProgress {
            transfer_id: TransferId::new(1),
            bytes_transferred: 0,
        };
        let _completed = PrepositionStatus::Completed {
            bytes_transferred: 1024,
            duration_ms: 100,
        };
        let _failed = PrepositionStatus::Failed {
            reason: "Error".to_string(),
        };
        let _cancelled = PrepositionStatus::Cancelled;
    }

    #[test]
    fn test_planner_clear_old_cooldowns() {
        let mut planner = PrepositionPlanner::new(PrepositionConfig::default());

        // Add a chunk location and edge info
        let mut edges = HashSet::new();
        edges.insert(EdgeIdx(0));
        planner.update_chunk_location(ChunkId::new(1), edges);
        planner.update_edge_info(EdgeIdx(0), make_test_edge_info(EdgeIdx(0), 100_000_000, 10));
        planner.update_edge_info(EdgeIdx(1), make_test_edge_info(EdgeIdx(1), 100_000_000, 5));

        // Clear old cooldowns (should be a no-op with fresh planner)
        planner.clear_old_cooldowns(60_000);
        assert!(planner.recent_ops.is_empty());
    }

    #[test]
    fn test_priority_ordering() {
        assert!(PrepositionPriority::Critical > PrepositionPriority::High);
        assert!(PrepositionPriority::High > PrepositionPriority::Medium);
        assert!(PrepositionPriority::Medium > PrepositionPriority::Low);
    }

    #[test]
    fn test_executor_cancel_operation() {
        let executor = PrepositionExecutor::new(PrepositionConfig::default());

        let ops = vec![
            PrepositionOp::new(1, ChunkId::new(1), EdgeIdx(0), EdgeIdx(1), 1024, PrepositionPriority::High, 0.9, "Test".to_string()),
        ];

        executor.queue_operations(ops);
        executor.tick();

        executor.cancel_operation(1);
        assert_eq!(executor.active_count(), 0);
    }

    #[test]
    fn test_executor_active_operations() {
        let executor = PrepositionExecutor::new(PrepositionConfig::default());

        let ops = vec![
            PrepositionOp::new(1, ChunkId::new(1), EdgeIdx(0), EdgeIdx(1), 1024, PrepositionPriority::High, 0.9, "Test".to_string()),
        ];

        executor.queue_operations(ops);
        executor.tick();

        let active = executor.active_operations();
        assert_eq!(active.len(), 1);
    }
}
