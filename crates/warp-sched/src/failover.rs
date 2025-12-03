//! Failover management for edge transfer failures.
//!
//! This module provides fast failure detection and recovery decisions with
//! a sub-50ms latency target. It tracks active transfers, detects timeouts,
//! and makes intelligent routing decisions based on edge health and retry limits.

use crate::cost::CostMatrix;
use crate::paths::PathSelector;
use crate::{ChunkId, CpuStateBuffers, EdgeIdx};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// Configuration for failover behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailoverConfig {
    /// Transfer timeout before triggering failover (milliseconds).
    pub timeout_ms: u64,
    /// Maximum number of retry attempts per transfer.
    pub max_retries: u8,
    /// Cooldown period before re-using a failed edge (milliseconds).
    pub cooldown_ms: u64,
    /// Minimum edge health threshold to consider for routing.
    pub health_threshold: f32,
}

impl Default for FailoverConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 30000,
            max_retries: 3,
            cooldown_ms: 60000,
            health_threshold: 0.3,
        }
    }
}

impl FailoverConfig {
    /// Creates a new configuration with custom values.
    pub fn new(timeout_ms: u64, max_retries: u8, cooldown_ms: u64, health_threshold: f32) -> Self {
        Self {
            timeout_ms,
            max_retries,
            cooldown_ms,
            health_threshold,
        }
    }

    /// Validates configuration parameters.
    pub fn validate(&self) -> Result<(), String> {
        if self.health_threshold < 0.0 || self.health_threshold > 1.0 {
            return Err("health_threshold must be between 0.0 and 1.0".to_string());
        }
        if self.timeout_ms == 0 {
            return Err("timeout_ms must be greater than 0".to_string());
        }
        Ok(())
    }
}

/// Reason for failover decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FailoverReason {
    /// Transfer exceeded timeout threshold.
    Timeout,
    /// Edge became offline/unavailable.
    EdgeOffline,
    /// Edge health dropped below threshold.
    EdgeUnhealthy,
    /// Transfer operation reported failure.
    TransferFailed,
    /// Maximum retry attempts exceeded.
    MaxRetriesExceeded,
}

/// Action to take for failover recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailoverAction {
    /// Retry the transfer on the same edge.
    Retry { edge_idx: EdgeIdx },
    /// Reroute transfer through different edges.
    Reroute { new_edges: Vec<EdgeIdx> },
    /// Abort the transfer due to unrecoverable failure.
    Abort { reason: String },
    /// Wait before retrying.
    Wait { duration_ms: u64 },
}

/// Complete failover decision with context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailoverDecision {
    /// Chunk being transferred.
    pub chunk_id: ChunkId,
    /// Reason for failover.
    pub reason: FailoverReason,
    /// Action to take.
    pub action: FailoverAction,
    /// Edge that failed.
    pub failed_edge: EdgeIdx,
    /// Number of retries so far.
    pub retry_count: u8,
    /// Timestamp when decision was made (milliseconds since epoch).
    pub timestamp_ms: u64,
}

impl FailoverDecision {
    /// Creates a new failover decision.
    pub fn new(
        chunk_id: ChunkId,
        reason: FailoverReason,
        action: FailoverAction,
        failed_edge: EdgeIdx,
        retry_count: u8,
    ) -> Self {
        Self {
            chunk_id,
            reason,
            action,
            failed_edge,
            retry_count,
            timestamp_ms: current_timestamp_ms(),
        }
    }
}

/// Tracks a transfer that may need failover.
#[derive(Debug, Clone)]
struct FailedTransfer {
    chunk_id: ChunkId,
    edge_idx: EdgeIdx,
    started_at: Instant,
    retry_count: u8,
}

/// Metrics about failover operations.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct FailoverMetrics {
    /// Total number of failover events.
    pub total_failovers: u64,
    /// Number of retry actions.
    pub retries: u64,
    /// Number of reroute actions.
    pub reroutes: u64,
    /// Number of abort actions.
    pub aborts: u64,
    /// Average recovery decision time in microseconds.
    pub avg_recovery_time_us: u64,
}

impl FailoverMetrics {
    /// Merges another metrics instance into this one.
    pub fn merge(&mut self, other: &FailoverMetrics) {
        self.total_failovers += other.total_failovers;
        self.retries += other.retries;
        self.reroutes += other.reroutes;
        self.aborts += other.aborts;
        // Weighted average for recovery time
        let total = self.total_failovers + other.total_failovers;
        if total > 0 {
            self.avg_recovery_time_us = (self.avg_recovery_time_us * self.total_failovers
                + other.avg_recovery_time_us * other.total_failovers)
                / total;
        }
    }
}

/// CPU-based failover manager implementation.
#[derive(Debug)]
pub struct CpuFailoverManager {
    config: FailoverConfig,
    active_transfers: HashMap<ChunkId, FailedTransfer>,
    failed_edges: HashMap<EdgeIdx, Instant>,
    metrics: FailoverMetrics,
    recovery_times: Vec<u64>,
}

impl CpuFailoverManager {
    /// Creates a new CPU failover manager.
    pub fn new(config: FailoverConfig) -> Self {
        Self {
            config,
            active_transfers: HashMap::new(),
            failed_edges: HashMap::new(),
            metrics: FailoverMetrics::default(),
            recovery_times: Vec::new(),
        }
    }

    /// Starts tracking a transfer for potential failover.
    pub fn track_transfer(&mut self, chunk_id: ChunkId, edge_idx: EdgeIdx) {
        self.active_transfers.insert(
            chunk_id,
            FailedTransfer {
                chunk_id,
                edge_idx,
                started_at: Instant::now(),
                retry_count: 0,
            },
        );
    }

    /// Reports a transfer failure and gets a recovery decision.
    pub fn report_failure(
        &mut self,
        chunk_id: ChunkId,
        edge_idx: EdgeIdx,
        _reason: FailoverReason,
    ) {
        // Mark edge as failed for cooldown tracking
        self.failed_edges.insert(edge_idx, Instant::now());

        // Update retry count if this chunk is being tracked
        if let Some(transfer) = self.active_transfers.get_mut(&chunk_id) {
            transfer.retry_count += 1;
        }
    }

    /// Checks for timed out transfers and returns failover decisions.
    pub fn check_timeouts(&mut self, _state: &CpuStateBuffers) -> Vec<FailoverDecision> {
        let timeout_duration = Duration::from_millis(self.config.timeout_ms);
        let now = Instant::now();
        let mut decisions = Vec::new();

        // Collect timed out transfers
        let timed_out: Vec<_> = self
            .active_transfers
            .iter()
            .filter(|(_, transfer)| now.duration_since(transfer.started_at) > timeout_duration)
            .map(|(chunk_id, transfer)| (*chunk_id, transfer.edge_idx, transfer.retry_count))
            .collect();

        // Create decisions for timed out transfers
        for (chunk_id, edge_idx, retry_count) in timed_out {
            let decision = FailoverDecision::new(
                chunk_id,
                FailoverReason::Timeout,
                FailoverAction::Abort {
                    reason: "Timeout exceeded".to_string(),
                },
                edge_idx,
                retry_count,
            );
            self.update_metrics(&decision);
            decisions.push(decision);
        }

        decisions
    }

    /// Makes a failover decision based on the failure context.
    pub fn decide(
        &self,
        chunk_id: ChunkId,
        edge_idx: EdgeIdx,
        reason: FailoverReason,
        state: &CpuStateBuffers,
        paths: &PathSelector,
        cost_matrix: &CostMatrix,
    ) -> FailoverDecision {
        let start = Instant::now();
        let retry_count = self
            .active_transfers
            .get(&chunk_id)
            .map(|t| t.retry_count)
            .unwrap_or(0);

        let action = self.decide_action(chunk_id, edge_idx, reason, retry_count, state, paths, cost_matrix);

        let decision = FailoverDecision::new(chunk_id, reason, action, edge_idx, retry_count);

        // Track recovery time for metrics
        let _recovery_time = start.elapsed().as_micros() as u64;
        // Note: In real usage, you'd update metrics through a mutable reference

        decision
    }

    /// Marks a transfer as complete and stops tracking it.
    pub fn complete_transfer(&mut self, chunk_id: ChunkId) {
        self.active_transfers.remove(&chunk_id);
    }

    /// Returns current failover metrics.
    pub fn metrics(&self) -> FailoverMetrics {
        self.metrics
    }

    /// Determines the appropriate failover action.
    fn decide_action(
        &self,
        chunk_id: ChunkId,
        edge_idx: EdgeIdx,
        reason: FailoverReason,
        retry_count: u8,
        state: &CpuStateBuffers,
        paths: &PathSelector,
        cost_matrix: &CostMatrix,
    ) -> FailoverAction {
        // Check if max retries exceeded
        if retry_count >= self.config.max_retries {
            return FailoverAction::Abort {
                reason: "Max retries exceeded".to_string(),
            };
        }

        // Check if edge is in cooldown
        let edge_in_cooldown = self.is_edge_in_cooldown(edge_idx);

        // For certain reasons, try to retry on same edge if healthy and not in cooldown
        match reason {
            FailoverReason::Timeout | FailoverReason::TransferFailed => {
                if !edge_in_cooldown && self.is_edge_healthy(edge_idx, state) {
                    return FailoverAction::Retry { edge_idx };
                }
            }
            _ => {}
        }

        // Try to find alternative route using PathSelector for optimal selection
        if let Some(alternative) = self.find_alternative_edges(chunk_id, edge_idx, state, paths, cost_matrix) {
            return FailoverAction::Reroute {
                new_edges: alternative,
            };
        }

        // No alternatives found
        FailoverAction::Abort {
            reason: format!("No viable alternative routes for {:?}", reason),
        }
    }

    /// Checks if an edge is currently in cooldown period.
    fn is_edge_in_cooldown(&self, edge_idx: EdgeIdx) -> bool {
        if let Some(failed_at) = self.failed_edges.get(&edge_idx) {
            let cooldown = Duration::from_millis(self.config.cooldown_ms);
            Instant::now().duration_since(*failed_at) < cooldown
        } else {
            false
        }
    }

    /// Checks if an edge is healthy enough to use.
    fn is_edge_healthy(&self, edge_idx: EdgeIdx, state: &CpuStateBuffers) -> bool {
        if let Some(edge) = state.get_edge(edge_idx) {
            edge.health_score_f32() >= self.config.health_threshold
        } else {
            false
        }
    }

    /// Finds alternative edges for rerouting using PathSelector for optimal selection.
    fn find_alternative_edges(
        &self,
        chunk_id: ChunkId,
        failed_edge: EdgeIdx,
        state: &CpuStateBuffers,
        paths: &PathSelector,
        cost_matrix: &CostMatrix,
    ) -> Option<Vec<EdgeIdx>> {
        // Use PathSelector to get optimal paths ranked by cost
        let selection = paths.select(chunk_id, cost_matrix);

        if !selection.has_paths() {
            return None;
        }

        // Filter out the failed edge and any edges in cooldown or unhealthy
        let alternative: Vec<EdgeIdx> = selection
            .selected_edges
            .iter()
            .map(|(edge_idx, _cost)| *edge_idx)
            .filter(|&edge_idx| {
                edge_idx != failed_edge
                    && self.is_edge_healthy(edge_idx, state)
                    && !self.is_edge_in_cooldown(edge_idx)
            })
            .collect();

        if alternative.is_empty() {
            None
        } else {
            Some(alternative)
        }
    }

    /// Updates metrics based on a decision.
    fn update_metrics(&mut self, decision: &FailoverDecision) {
        self.metrics.total_failovers += 1;

        match &decision.action {
            FailoverAction::Retry { .. } => self.metrics.retries += 1,
            FailoverAction::Reroute { .. } => self.metrics.reroutes += 1,
            FailoverAction::Abort { .. } => self.metrics.aborts += 1,
            FailoverAction::Wait { .. } => {}
        }

        // Update average recovery time
        if !self.recovery_times.is_empty() {
            let sum: u64 = self.recovery_times.iter().sum();
            self.metrics.avg_recovery_time_us = sum / self.recovery_times.len() as u64;
        }
    }

    /// Cleans up old cooldown entries.
    pub fn cleanup_cooldowns(&mut self) {
        let cooldown = Duration::from_millis(self.config.cooldown_ms);
        let now = Instant::now();

        self.failed_edges
            .retain(|_, failed_at| now.duration_since(*failed_at) < cooldown);
    }
}

/// GPU-accelerated failover manager (delegates to CPU implementation).
///
/// GPU acceleration is not beneficial for failover management as it involves
/// complex decision logic and small data sizes. This wrapper delegates all
/// operations to the CPU implementation.
#[derive(Debug)]
pub struct FailoverManager {
    cpu: CpuFailoverManager,
}

impl FailoverManager {
    /// Creates a new failover manager.
    pub fn new(config: FailoverConfig) -> Self {
        Self {
            cpu: CpuFailoverManager::new(config),
        }
    }

    /// Starts tracking a transfer for potential failover.
    pub fn track_transfer(&mut self, chunk_id: ChunkId, edge_idx: EdgeIdx) {
        self.cpu.track_transfer(chunk_id, edge_idx);
    }

    /// Reports a transfer failure.
    pub fn report_failure(
        &mut self,
        chunk_id: ChunkId,
        edge_idx: EdgeIdx,
        reason: FailoverReason,
    ) {
        self.cpu.report_failure(chunk_id, edge_idx, reason);
    }

    /// Checks for timed out transfers.
    pub fn check_timeouts(&mut self, state: &CpuStateBuffers) -> Vec<FailoverDecision> {
        self.cpu.check_timeouts(state)
    }

    /// Makes a failover decision.
    pub fn decide(
        &self,
        chunk_id: ChunkId,
        edge_idx: EdgeIdx,
        reason: FailoverReason,
        state: &CpuStateBuffers,
        paths: &PathSelector,
        cost_matrix: &CostMatrix,
    ) -> FailoverDecision {
        self.cpu.decide(chunk_id, edge_idx, reason, state, paths, cost_matrix)
    }

    /// Marks a transfer as complete.
    pub fn complete_transfer(&mut self, chunk_id: ChunkId) {
        self.cpu.complete_transfer(chunk_id);
    }

    /// Returns current metrics.
    pub fn metrics(&self) -> FailoverMetrics {
        self.cpu.metrics()
    }

    /// Cleans up old cooldown entries.
    pub fn cleanup_cooldowns(&mut self) {
        self.cpu.cleanup_cooldowns();
    }
}

/// Gets current timestamp in milliseconds since Unix epoch.
fn current_timestamp_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> FailoverConfig {
        FailoverConfig {
            timeout_ms: 1000,
            max_retries: 2,
            cooldown_ms: 5000,
            health_threshold: 0.5,
        }
    }

    fn create_test_state(num_edges: usize, num_chunks: usize) -> CpuStateBuffers {
        let mut state = CpuStateBuffers::new(num_chunks, num_edges);

        // Add edges with healthy state
        for i in 0..num_edges {
            let edge = crate::EdgeStateGpu::new(
                EdgeIdx::from(i as u32),
                100_000_000, // 100 Mbps
                10_000,      // 10ms RTT
                1.0,         // Full health
                10,          // Max 10 transfers
            );
            let _ = state.add_edge(i as u32, edge);
        }

        // Add chunks
        for i in 0..num_chunks {
            let chunk = crate::ChunkState::new(
                [i as u8; 32],
                1024 * 1024, // 1MB
                100,         // Medium priority
                3,           // 3 replicas
            );
            let _ = state.add_chunk(chunk);
        }

        state
    }

    fn create_test_path_selector() -> PathSelector {
        use crate::paths::PathConfig;
        let path_config = PathConfig {
            k: 3,
            max_cost: 1.0,
            diversity_weight: 0.1,
        };
        PathSelector::new(path_config)
    }

    fn create_test_cost_matrix(state: &mut CpuStateBuffers, num_chunks: usize, num_edges: usize) -> CostMatrix {
        use crate::cost::CostConfig;

        // Add replicas for all chunks to all edges so PathSelector can find them
        for chunk_idx in 0..num_chunks {
            for edge_idx in 0..num_edges {
                state.add_replica(chunk_idx as u32, EdgeIdx::from(edge_idx as u32));
            }
        }

        let mut matrix = CostMatrix::new(num_chunks, num_edges, CostConfig::default());
        matrix.compute(state);
        matrix
    }

    #[test]
    fn test_failover_config_default() {
        let config = FailoverConfig::default();
        assert_eq!(config.timeout_ms, 30000);
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.cooldown_ms, 60000);
        assert_eq!(config.health_threshold, 0.3);
    }

    #[test]
    fn test_failover_config_new() {
        let config = FailoverConfig::new(5000, 5, 10000, 0.8);
        assert_eq!(config.timeout_ms, 5000);
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.cooldown_ms, 10000);
        assert_eq!(config.health_threshold, 0.8);
    }

    #[test]
    fn test_failover_config_validation() {
        let valid_config = FailoverConfig::new(1000, 3, 5000, 0.5);
        assert!(valid_config.validate().is_ok());

        let invalid_config = FailoverConfig::new(1000, 3, 5000, 1.5);
        assert!(invalid_config.validate().is_err());

        let zero_timeout = FailoverConfig::new(0, 3, 5000, 0.5);
        assert!(zero_timeout.validate().is_err());
    }

    #[test]
    fn test_failover_reason_equality() {
        assert_eq!(FailoverReason::Timeout, FailoverReason::Timeout);
        assert_ne!(FailoverReason::Timeout, FailoverReason::EdgeOffline);
    }

    #[test]
    fn test_failover_actions() {
        // Test Retry
        let retry = FailoverAction::Retry { edge_idx: EdgeIdx::from(5u32) };
        assert!(matches!(retry, FailoverAction::Retry { .. }));

        // Test Reroute
        let reroute = FailoverAction::Reroute { new_edges: vec![EdgeIdx::from(1u32)] };
        assert!(matches!(reroute, FailoverAction::Reroute { .. }));

        // Test Abort
        let abort = FailoverAction::Abort { reason: "Test".to_string() };
        assert!(matches!(abort, FailoverAction::Abort { .. }));
    }

    #[test]
    fn test_failover_decision_creation() {
        let decision = FailoverDecision::new(
            ChunkId::from(10),
            FailoverReason::Timeout,
            FailoverAction::Retry { edge_idx: EdgeIdx::from(5u32) },
            EdgeIdx::from(5u32),
            1,
        );
        assert_eq!(decision.chunk_id, ChunkId::from(10));
        assert_eq!(decision.reason, FailoverReason::Timeout);
        assert_eq!(decision.failed_edge, EdgeIdx::from(5u32));
        assert_eq!(decision.retry_count, 1);
        assert!(decision.timestamp_ms > 0);
    }

    #[test]
    fn test_transfer_tracking() {
        let mut manager = CpuFailoverManager::new(create_test_config());

        // Track
        manager.track_transfer(ChunkId::from(5), EdgeIdx::from(10u32));
        assert!(manager.active_transfers.contains_key(&ChunkId::from(5)));

        // Report failure
        manager.report_failure(ChunkId::from(5), EdgeIdx::from(10u32), FailoverReason::TransferFailed);
        assert!(manager.failed_edges.contains_key(&EdgeIdx::from(10u32)));
        assert_eq!(manager.active_transfers.get(&ChunkId::from(5)).unwrap().retry_count, 1);

        // Complete
        manager.complete_transfer(ChunkId::from(5));
        assert!(!manager.active_transfers.contains_key(&ChunkId::from(5)));
    }

    #[test]
    fn test_check_timeouts() {
        // No timeout
        let mut mgr1 = CpuFailoverManager::new(create_test_config());
        let state = create_test_state(10, 10);
        mgr1.track_transfer(ChunkId::from(5), EdgeIdx::from(3u32));
        assert_eq!(mgr1.check_timeouts(&state).len(), 0);

        // With timeout
        let mut mgr2 = CpuFailoverManager::new(FailoverConfig { timeout_ms: 10, max_retries: 2,
            cooldown_ms: 5000, health_threshold: 0.5 });
        mgr2.track_transfer(ChunkId::from(5), EdgeIdx::from(3u32));
        std::thread::sleep(Duration::from_millis(20));
        let decisions = mgr2.check_timeouts(&state);
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].reason, FailoverReason::Timeout);
    }

    #[test]
    fn test_decide_retry_action() {
        let manager = CpuFailoverManager::new(create_test_config());
        let mut state = create_test_state(10, 10);
        let paths = create_test_path_selector();
        let cost_matrix = create_test_cost_matrix(&mut state, 10, 10);

        let decision = manager.decide(
            ChunkId::from(5),
            EdgeIdx::from(3u32),
            FailoverReason::TransferFailed,
            &state,
            &paths,
            &cost_matrix,
        );

        assert_eq!(decision.chunk_id, ChunkId::from(5));
        assert_eq!(decision.failed_edge, EdgeIdx::from(3u32));
        match decision.action {
            FailoverAction::Retry { edge_idx } => assert_eq!(edge_idx, EdgeIdx::from(3u32)),
            _ => panic!("Expected retry action"),
        }
    }

    #[test]
    fn test_decide_reroute_action() {
        let mut manager = CpuFailoverManager::new(create_test_config());
        let mut state = create_test_state(10, 10);
        let paths = create_test_path_selector();
        let cost_matrix = create_test_cost_matrix(&mut state, 10, 10);

        // Mark edge as failed to trigger reroute
        manager.failed_edges.insert(EdgeIdx::from(3u32), Instant::now());

        let decision = manager.decide(
            ChunkId::from(5),
            EdgeIdx::from(3u32),
            FailoverReason::EdgeOffline,
            &state,
            &paths,
            &cost_matrix,
        );

        assert_eq!(decision.chunk_id, ChunkId::from(5));
        match decision.action {
            FailoverAction::Reroute { new_edges } => assert!(!new_edges.is_empty()),
            _ => panic!("Expected reroute action"),
        }
    }

    #[test]
    fn test_decide_abort_max_retries() {
        let mut manager = CpuFailoverManager::new(create_test_config());
        let mut state = create_test_state(10, 10);
        let paths = create_test_path_selector();
        let cost_matrix = create_test_cost_matrix(&mut state, 10, 10);

        // Track transfer with max retries
        manager.track_transfer(ChunkId::from(5), EdgeIdx::from(3u32));
        if let Some(transfer) = manager.active_transfers.get_mut(&ChunkId::from(5)) {
            transfer.retry_count = 2; // At max retries
        }

        let decision = manager.decide(
            ChunkId::from(5),
            EdgeIdx::from(3u32),
            FailoverReason::TransferFailed,
            &state,
            &paths,
            &cost_matrix,
        );

        match decision.action {
            FailoverAction::Abort { reason } => assert!(reason.contains("Max retries")),
            _ => panic!("Expected abort action"),
        }
    }

    #[test]
    fn test_edge_health_and_cooldown() {
        let mut manager = CpuFailoverManager::new(create_test_config());
        let mut state = create_test_state(10, 10);

        // Health check
        assert!(manager.is_edge_healthy(EdgeIdx::from(3u32), &state));
        let unhealthy = crate::EdgeStateGpu::new(EdgeIdx::from(3u32), 100_000_000, 10_000, 0.2, 10);
        let _ = state.update_edge(EdgeIdx::from(3u32), unhealthy);
        assert!(!manager.is_edge_healthy(EdgeIdx::from(3u32), &state));

        // Cooldown check
        assert!(!manager.is_edge_in_cooldown(EdgeIdx::from(3u32)));
        manager.failed_edges.insert(EdgeIdx::from(3u32), Instant::now());
        assert!(manager.is_edge_in_cooldown(EdgeIdx::from(3u32)));
    }

    #[test]
    fn test_failover_metrics_default() {
        let metrics = FailoverMetrics::default();
        assert_eq!(metrics.total_failovers, 0);
        assert_eq!(metrics.retries, 0);
        assert_eq!(metrics.reroutes, 0);
        assert_eq!(metrics.aborts, 0);
        assert_eq!(metrics.avg_recovery_time_us, 0);
    }

    #[test]
    fn test_failover_metrics_merge() {
        let mut m1 = FailoverMetrics {
            total_failovers: 10,
            retries: 5,
            reroutes: 3,
            aborts: 2,
            avg_recovery_time_us: 100,
        };

        let m2 = FailoverMetrics {
            total_failovers: 5,
            retries: 2,
            reroutes: 2,
            aborts: 1,
            avg_recovery_time_us: 200,
        };

        m1.merge(&m2);
        assert_eq!(m1.total_failovers, 15);
        assert_eq!(m1.retries, 7);
        assert_eq!(m1.reroutes, 5);
        assert_eq!(m1.aborts, 3);
    }

    #[test]
    fn test_cleanup_cooldowns() {
        let mut manager = CpuFailoverManager::new(FailoverConfig {
            timeout_ms: 1000,
            max_retries: 2,
            cooldown_ms: 50, // Short cooldown for testing
            health_threshold: 0.5,
        });

        // Add some failed edges
        manager.failed_edges.insert(EdgeIdx::from(1u32), Instant::now());
        manager.failed_edges.insert(EdgeIdx::from(2u32), Instant::now());

        assert_eq!(manager.failed_edges.len(), 2);

        // Wait for cooldown to expire
        std::thread::sleep(Duration::from_millis(60));
        manager.cleanup_cooldowns();

        // All should be cleaned up
        assert_eq!(manager.failed_edges.len(), 0);
    }

    #[test]
    fn test_multiple_concurrent_failures() {
        let mut manager = CpuFailoverManager::new(create_test_config());
        let _state = create_test_state(10, 10);

        // Track multiple transfers
        manager.track_transfer(ChunkId::from(1), EdgeIdx::from(2u32));
        manager.track_transfer(ChunkId::from(2), EdgeIdx::from(3u32));
        manager.track_transfer(ChunkId::from(3), EdgeIdx::from(4u32));

        // Report failures
        manager.report_failure(ChunkId::from(1), EdgeIdx::from(2u32), FailoverReason::TransferFailed);
        manager.report_failure(ChunkId::from(2), EdgeIdx::from(3u32), FailoverReason::EdgeOffline);
        manager.report_failure(ChunkId::from(3), EdgeIdx::from(4u32), FailoverReason::EdgeUnhealthy);

        assert_eq!(manager.failed_edges.len(), 3);
        assert_eq!(manager.active_transfers.len(), 3);
    }

    #[test]
    fn test_gpu_wrapper_delegation() {
        let mut manager = FailoverManager::new(create_test_config());
        let mut state = create_test_state(10, 10);
        let paths = create_test_path_selector();
        let cost_matrix = create_test_cost_matrix(&mut state, 10, 10);

        // Test track/complete/report/decide/metrics all delegate to CPU
        manager.track_transfer(ChunkId::from(5), EdgeIdx::from(10u32));
        assert!(manager.cpu.active_transfers.contains_key(&ChunkId::from(5)));

        manager.report_failure(ChunkId::from(5), EdgeIdx::from(10u32), FailoverReason::TransferFailed);
        assert!(manager.cpu.failed_edges.contains_key(&EdgeIdx::from(10u32)));

        let decision = manager.decide(ChunkId::from(5), EdgeIdx::from(3u32),
            FailoverReason::TransferFailed, &state, &paths, &cost_matrix);
        assert_eq!(decision.chunk_id, ChunkId::from(5));

        manager.complete_transfer(ChunkId::from(5));
        assert!(!manager.cpu.active_transfers.contains_key(&ChunkId::from(5)));

        assert_eq!(manager.metrics().total_failovers, 0);
    }

    #[test]
    fn test_serialization() {
        // Test all serializable types
        let config = create_test_config();
        assert!(serde_json::to_string(&config).is_ok());

        let reason = FailoverReason::Timeout;
        let action = FailoverAction::Retry { edge_idx: EdgeIdx::from(5u32) };
        let decision = FailoverDecision::new(ChunkId::from(10), reason, action.clone(),
            EdgeIdx::from(5u32), 1);
        let metrics = FailoverMetrics { total_failovers: 100, retries: 50, reroutes: 30,
            aborts: 20, avg_recovery_time_us: 1000 };

        // All types should serialize/deserialize correctly
        assert_eq!(reason, serde_json::from_str(&serde_json::to_string(&reason).unwrap()).unwrap());
        assert_eq!(action, serde_json::from_str(&serde_json::to_string(&action).unwrap()).unwrap());
        assert_eq!(decision, serde_json::from_str(&serde_json::to_string(&decision).unwrap()).unwrap());
        let decoded_metrics: FailoverMetrics = serde_json::from_str(
            &serde_json::to_string(&metrics).unwrap()).unwrap();
        assert_eq!(metrics.total_failovers, decoded_metrics.total_failovers);
    }

    #[test]
    fn test_find_alternative_edges() {
        use crate::cost::CostConfig;

        // Test no healthy edges
        let manager = CpuFailoverManager::new(create_test_config());
        let mut state = create_test_state(5, 10);
        let paths = create_test_path_selector();

        // Add replicas before computing costs
        for chunk_idx in 0..10 {
            for edge_idx in 0..5 {
                state.add_replica(chunk_idx as u32, EdgeIdx::from(edge_idx as u32));
            }
        }

        let mut cost_matrix = CostMatrix::new(10, 5, CostConfig::default());
        cost_matrix.compute(&state);

        // Mark all edges as unhealthy
        for i in 0..state.edge_count() {
            let unhealthy = crate::EdgeStateGpu::new(EdgeIdx::from(i as u32), 100_000_000, 10_000, 0.1, 10);
            let _ = state.update_edge(EdgeIdx::from(i as u32), unhealthy);
        }
        assert!(manager.find_alternative_edges(ChunkId::from(5), EdgeIdx::from(3u32), &state, &paths, &cost_matrix).is_none());

        // Test all in cooldown
        let mut manager2 = CpuFailoverManager::new(create_test_config());
        let mut state2 = create_test_state(5, 10);

        // Add replicas before computing costs
        for chunk_idx in 0..10 {
            for edge_idx in 0..5 {
                state2.add_replica(chunk_idx as u32, EdgeIdx::from(edge_idx as u32));
            }
        }

        let mut cost_matrix2 = CostMatrix::new(10, 5, CostConfig::default());
        cost_matrix2.compute(&state2);

        for i in 0..state2.edge_count() {
            manager2.failed_edges.insert(EdgeIdx::from(i as u32), Instant::now());
        }
        assert!(manager2.find_alternative_edges(ChunkId::from(5), EdgeIdx::from(3u32), &state2, &paths, &cost_matrix2).is_none());
    }

    #[test]
    fn test_performance_decision_latency() {
        let manager = CpuFailoverManager::new(create_test_config());
        let mut state = create_test_state(100, 100);
        let paths = create_test_path_selector();
        let cost_matrix = create_test_cost_matrix(&mut state, 100, 100);

        let start = Instant::now();
        for i in 0..100 {
            let _ = manager.decide(
                ChunkId::from(i % 100),
                EdgeIdx::from((i % 10) as u32),
                FailoverReason::TransferFailed,
                &state,
                &paths,
                &cost_matrix,
            );
        }
        let elapsed = start.elapsed();

        // Should average well under 50ms per decision
        let avg_latency = elapsed.as_micros() / 100;
        assert!(avg_latency < 50000, "Average latency: {} us", avg_latency);
    }
}
