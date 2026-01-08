//! Health scoring for edge selection
//!
//! Multi-dimensional health tracking for edge nodes combining success rates,
//! uptime metrics, and response times.
//!
//! # Scoring: `overall = w1*success + w2*uptime + w3*response`

use crate::types::EdgeId;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};

/// Configurable weights for health score components (should sum to 1.0)
#[derive(Debug, Clone)]
pub struct HealthWeights {
    /// Weight for success rate component (default: 0.4)
    pub success_rate: f64,
    /// Weight for uptime component (default: 0.3)
    pub uptime: f64,
    /// Weight for response time component (default: 0.3)
    pub response_time: f64,
}

impl HealthWeights {
    /// Creates new health weights with specified values
    #[must_use]
    pub const fn new(success_rate: f64, uptime: f64, response_time: f64) -> Self {
        Self {
            success_rate,
            uptime,
            response_time,
        }
    }
}

impl Default for HealthWeights {
    fn default() -> Self {
        Self {
            success_rate: 0.4,
            uptime: 0.3,
            response_time: 0.3,
        }
    }
}

/// Individual health score components with raw statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthComponents {
    /// Success rate: completed / total (0.0-1.0)
    pub success_rate: f64,
    /// Uptime ratio: online checks / total checks (0.0-1.0)
    pub uptime: f64,
    /// Normalized response time score (0.0-1.0, higher is better)
    pub response_time: f64,

    /// Total number of requests
    pub total_requests: u64,
    /// Number of successful requests
    pub successful_requests: u64,
    /// Number of failed requests
    pub failed_requests: u64,

    /// Total uptime checks performed
    pub uptime_checks: u64,
    /// Number of checks where edge was online
    pub online_checks: u64,

    /// Average response time in milliseconds
    pub avg_response_ms: f64,
    /// Minimum response time in milliseconds
    pub min_response_ms: f64,
    /// Maximum response time in milliseconds
    pub max_response_ms: f64,
}

impl HealthComponents {
    /// Creates new health components with zero values
    #[must_use]
    pub const fn new() -> Self {
        Self {
            success_rate: 0.0,
            uptime: 0.0,
            response_time: 0.0,
            total_requests: 0,
            successful_requests: 0,
            failed_requests: 0,
            uptime_checks: 0,
            online_checks: 0,
            avg_response_ms: 0.0,
            min_response_ms: 0.0,
            max_response_ms: 0.0,
        }
    }

    /// Records a successful request with response time
    fn record_success(&mut self, response_time: Duration) {
        let response_ms = response_time.as_secs_f64() * 1000.0;

        self.total_requests += 1;
        self.successful_requests += 1;

        // Update response time statistics
        if self.total_requests == 1 {
            self.avg_response_ms = response_ms;
            self.min_response_ms = response_ms;
            self.max_response_ms = response_ms;
        } else {
            // Incremental average calculation
            let prev_total = (self.total_requests - 1) as f64;
            self.avg_response_ms =
                self.avg_response_ms.mul_add(prev_total, response_ms) / self.total_requests as f64;
            self.min_response_ms = self.min_response_ms.min(response_ms);
            self.max_response_ms = self.max_response_ms.max(response_ms);
        }

        self.recalculate_scores();
    }

    /// Records a failed request
    fn record_failure(&mut self) {
        self.total_requests += 1;
        self.failed_requests += 1;
        self.recalculate_scores();
    }

    /// Records an uptime check
    fn record_uptime_check(&mut self, is_online: bool) {
        self.uptime_checks += 1;
        if is_online {
            self.online_checks += 1;
        }
        self.recalculate_scores();
    }

    /// Recalculates normalized scores from raw statistics
    fn recalculate_scores(&mut self) {
        // Success rate
        if self.total_requests > 0 {
            self.success_rate = self.successful_requests as f64 / self.total_requests as f64;
        } else {
            self.success_rate = 0.0;
        }

        // Uptime
        if self.uptime_checks > 0 {
            self.uptime = self.online_checks as f64 / self.uptime_checks as f64;
        } else {
            self.uptime = 0.0;
        }

        // Response time score (normalized: 1.0 is best, 0.0 is worst)
        // Score decreases as response time increases, with 5000ms being the threshold
        // Only calculate if we have successful requests with response times
        if self.successful_requests > 0 {
            const MAX_RESPONSE_MS: f64 = 5000.0;
            let normalized = (self.avg_response_ms / MAX_RESPONSE_MS).min(1.0);
            self.response_time = 1.0 - normalized;
        } else {
            self.response_time = 0.0;
        }
    }
}

impl Default for HealthComponents {
    fn default() -> Self {
        Self::new()
    }
}

/// Complete health score with component breakdown
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthScore {
    /// Overall composite health score (0.0-1.0, higher is better)
    pub overall: f64,
    /// Individual component scores
    pub components: HealthComponents,
    /// Timestamp when score was last updated
    pub last_updated: SystemTime,
}

impl HealthScore {
    /// Creates a new health score from components
    fn new(components: HealthComponents, weights: &HealthWeights) -> Self {
        let overall = Self::calculate(&components, weights);
        Self {
            overall,
            components,
            last_updated: SystemTime::now(),
        }
    }

    /// Calculates the composite health score from components and weights
    #[must_use]
    pub fn calculate(components: &HealthComponents, weights: &HealthWeights) -> f64 {
        weights.response_time.mul_add(
            components.response_time,
            weights
                .success_rate
                .mul_add(components.success_rate, weights.uptime * components.uptime),
        )
    }

    /// Checks if the edge is considered healthy based on a threshold
    #[must_use]
    pub fn is_healthy(&self, threshold: f64) -> bool {
        self.overall >= threshold
    }
}

/// Multi-dimensional health tracker for edge nodes (thread-safe via `DashMap`)
pub struct HealthScorer {
    scores: DashMap<EdgeId, HealthComponents>,
    weights: HealthWeights,
}

impl HealthScorer {
    /// Creates a new health scorer with default weights
    #[must_use]
    pub fn new() -> Self {
        Self {
            scores: DashMap::new(),
            weights: HealthWeights::default(),
        }
    }

    /// Creates a new health scorer with custom weights
    #[must_use]
    pub fn with_weights(weights: HealthWeights) -> Self {
        Self {
            scores: DashMap::new(),
            weights,
        }
    }

    /// Records a successful request with response time
    pub fn record_success(&self, edge: &EdgeId, response_time: Duration) {
        self.scores
            .entry(*edge)
            .or_default()
            .record_success(response_time);
    }

    /// Records a failed request
    pub fn record_failure(&self, edge: &EdgeId) {
        self.scores.entry(*edge).or_default().record_failure();
    }

    /// Records an uptime check
    pub fn record_uptime_check(&self, edge: &EdgeId, is_online: bool) {
        self.scores
            .entry(*edge)
            .or_default()
            .record_uptime_check(is_online);
    }

    /// Gets the complete health score for an edge
    #[must_use]
    pub fn get_score(&self, edge: &EdgeId) -> Option<HealthScore> {
        self.scores
            .get(edge)
            .map(|entry| HealthScore::new(entry.value().clone(), &self.weights))
    }

    /// Gets only the overall health score for an edge
    #[must_use]
    pub fn get_overall(&self, edge: &EdgeId) -> Option<f64> {
        self.scores
            .get(edge)
            .map(|entry| HealthScore::calculate(entry.value(), &self.weights))
    }

    /// Ranks a set of edges by their health scores (best first)
    #[must_use]
    pub fn rank_edges(&self, edges: &[EdgeId]) -> Vec<(EdgeId, f64)> {
        let mut ranked: Vec<(EdgeId, f64)> = edges
            .iter()
            .filter_map(|edge| self.get_overall(edge).map(|score| (*edge, score)))
            .collect();

        // Sort by score descending (highest score first)
        ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        ranked
    }

    /// Gets the N healthiest edges from a set
    #[must_use]
    pub fn get_healthiest(&self, edges: &[EdgeId], count: usize) -> Vec<EdgeId> {
        self.rank_edges(edges)
            .into_iter()
            .take(count)
            .map(|(edge, _score)| edge)
            .collect()
    }

    /// Filters edges that meet a minimum health threshold
    #[must_use]
    pub fn filter_healthy(&self, edges: &[EdgeId], threshold: f64) -> Vec<EdgeId> {
        edges
            .iter()
            .filter(|edge| {
                self.get_overall(edge)
                    .is_some_and(|score| score >= threshold)
            })
            .copied()
            .collect()
    }

    /// Removes an edge from tracking
    pub fn remove(&self, edge: &EdgeId) {
        self.scores.remove(edge);
    }

    /// Resets health statistics for an edge
    pub fn reset(&self, edge: &EdgeId) {
        self.scores.insert(*edge, HealthComponents::new());
    }
}

impl Default for HealthScorer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_edge(byte: u8) -> EdgeId {
        EdgeId::new([byte; 32])
    }

    #[test]
    fn test_health_weights() {
        let weights = HealthWeights::default();
        assert_eq!(weights.success_rate, 0.4);
        assert_eq!(weights.uptime, 0.3);
        assert_eq!(weights.response_time, 0.3);

        let custom = HealthWeights::new(0.5, 0.3, 0.2);
        assert_eq!(custom.success_rate, 0.5);
        assert_eq!(custom.uptime, 0.3);
        assert_eq!(custom.response_time, 0.2);
    }

    #[test]
    fn test_health_components_new() {
        let components = HealthComponents::new();
        assert_eq!(components.total_requests, 0);
        assert_eq!(components.successful_requests, 0);
        assert_eq!(components.failed_requests, 0);
        assert_eq!(components.uptime_checks, 0);
        assert_eq!(components.online_checks, 0);
        assert_eq!(components.success_rate, 0.0);
        assert_eq!(components.uptime, 0.0);
        assert_eq!(components.response_time, 0.0);
        assert_eq!(components.avg_response_ms, 0.0);
    }

    #[test]
    fn test_health_scorer_creation() {
        let scorer = HealthScorer::new();
        let edge = create_test_edge(1);
        assert!(scorer.get_score(&edge).is_none());

        let weights = HealthWeights::new(0.5, 0.3, 0.2);
        let scorer = HealthScorer::with_weights(weights);
        scorer.record_success(&edge, Duration::from_millis(100));
        scorer.record_uptime_check(&edge, true);
        assert!(scorer.get_overall(&edge).unwrap() > 0.0);
    }

    #[test]
    fn test_record_success() {
        let scorer = HealthScorer::new();
        let edge = create_test_edge(1);

        scorer.record_success(&edge, Duration::from_millis(100));

        let score = scorer.get_score(&edge).unwrap();
        assert_eq!(score.components.total_requests, 1);
        assert_eq!(score.components.successful_requests, 1);
        assert_eq!(score.components.failed_requests, 0);
        assert_eq!(score.components.success_rate, 1.0);
        assert!((score.components.avg_response_ms - 100.0).abs() < 0.01);
    }

    #[test]
    fn test_record_multiple_successes() {
        let scorer = HealthScorer::new();
        let edge = create_test_edge(1);

        scorer.record_success(&edge, Duration::from_millis(100));
        scorer.record_success(&edge, Duration::from_millis(200));
        scorer.record_success(&edge, Duration::from_millis(300));

        let score = scorer.get_score(&edge).unwrap();
        assert_eq!(score.components.total_requests, 3);
        assert_eq!(score.components.successful_requests, 3);
        assert_eq!(score.components.success_rate, 1.0);
        assert!((score.components.avg_response_ms - 200.0).abs() < 0.01);
        assert!((score.components.min_response_ms - 100.0).abs() < 0.01);
        assert!((score.components.max_response_ms - 300.0).abs() < 0.01);
    }

    #[test]
    fn test_record_mixed_success_failure() {
        let scorer = HealthScorer::new();
        let edge = create_test_edge(1);

        scorer.record_failure(&edge);
        let score = scorer.get_score(&edge).unwrap();
        assert_eq!(score.components.total_requests, 1);
        assert_eq!(score.components.successful_requests, 0);
        assert_eq!(score.components.failed_requests, 1);
        assert_eq!(score.components.success_rate, 0.0);

        scorer.record_success(&edge, Duration::from_millis(100));
        scorer.record_success(&edge, Duration::from_millis(200));
        scorer.record_success(&edge, Duration::from_millis(150));

        let score = scorer.get_score(&edge).unwrap();
        assert_eq!(score.components.total_requests, 4);
        assert_eq!(score.components.successful_requests, 3);
        assert_eq!(score.components.failed_requests, 1);
        assert_eq!(score.components.success_rate, 0.75);
    }

    #[test]
    fn test_record_uptime_check() {
        let scorer = HealthScorer::new();
        let edge = create_test_edge(1);

        scorer.record_uptime_check(&edge, true);
        scorer.record_uptime_check(&edge, true);
        scorer.record_uptime_check(&edge, false);

        let score = scorer.get_score(&edge).unwrap();
        assert_eq!(score.components.uptime_checks, 3);
        assert_eq!(score.components.online_checks, 2);
        assert!((score.components.uptime - 0.666667).abs() < 0.01);
    }

    #[test]
    fn test_response_time_normalization() {
        let scorer = HealthScorer::new();

        let edge1 = create_test_edge(1);
        scorer.record_success(&edge1, Duration::from_millis(100));
        assert!(scorer.get_score(&edge1).unwrap().components.response_time > 0.95);

        let edge2 = create_test_edge(2);
        scorer.record_success(&edge2, Duration::from_millis(5000));
        assert!(scorer.get_score(&edge2).unwrap().components.response_time < 0.05);

        let edge3 = create_test_edge(3);
        scorer.record_success(&edge3, Duration::from_millis(2500));
        assert!((scorer.get_score(&edge3).unwrap().components.response_time - 0.5).abs() < 0.01);

        let edge4 = create_test_edge(4);
        scorer.record_success(&edge4, Duration::from_millis(10000));
        assert_eq!(
            scorer.get_score(&edge4).unwrap().components.response_time,
            0.0
        );
    }

    #[test]
    fn test_calculate_overall_and_health_check() {
        let mut components = HealthComponents::new();
        components.success_rate = 0.8;
        components.uptime = 0.9;
        components.response_time = 0.7;

        let weights = HealthWeights::default();
        let overall = HealthScore::calculate(&components, &weights);
        assert!((overall - 0.8).abs() < 0.01);

        let health_score = HealthScore {
            overall,
            components: components.clone(),
            last_updated: SystemTime::now(),
        };
        assert!(health_score.is_healthy(0.5));
        assert!(health_score.is_healthy(0.7));
        assert!(!health_score.is_healthy(0.9));
    }

    #[test]
    fn test_rank_and_get_healthiest() {
        let scorer = HealthScorer::new();
        let edge1 = create_test_edge(1);
        let edge2 = create_test_edge(2);
        let edge3 = create_test_edge(3);

        scorer.record_success(&edge1, Duration::from_millis(100));
        scorer.record_success(&edge1, Duration::from_millis(100));
        scorer.record_uptime_check(&edge1, true);

        scorer.record_success(&edge2, Duration::from_millis(500));
        scorer.record_failure(&edge2);
        scorer.record_uptime_check(&edge2, true);

        scorer.record_success(&edge3, Duration::from_millis(3000));
        scorer.record_uptime_check(&edge3, false);

        let edges = vec![edge1, edge2, edge3];
        let ranked = scorer.rank_edges(&edges);
        assert_eq!(ranked.len(), 3);
        assert_eq!(ranked[0].0, edge1);
        assert_eq!(ranked[2].0, edge3);
        assert!(ranked[0].1 >= ranked[1].1);
        assert!(ranked[1].1 >= ranked[2].1);

        let healthiest = scorer.get_healthiest(&edges, 2);
        assert_eq!(healthiest.len(), 2);
        assert_eq!(healthiest[0], edge1);
        assert_eq!(healthiest[1], edge2);
    }

    #[test]
    fn test_filter_healthy() {
        let scorer = HealthScorer::new();
        let edge1 = create_test_edge(1);
        let edge2 = create_test_edge(2);
        let edge3 = create_test_edge(3);

        scorer.record_success(&edge1, Duration::from_millis(100));
        scorer.record_uptime_check(&edge1, true);
        scorer.record_failure(&edge2);
        scorer.record_failure(&edge2);
        scorer.record_uptime_check(&edge2, false);
        scorer.record_success(&edge3, Duration::from_millis(500));
        scorer.record_failure(&edge3);

        let edges = vec![edge1, edge2, edge3];
        let healthy = scorer.filter_healthy(&edges, 0.3);
        assert!(healthy.len() >= 1);
        assert!(healthy.contains(&edge1));
        assert!(!healthy.contains(&edge2));
    }

    #[test]
    fn test_remove_and_reset_edge() {
        let scorer = HealthScorer::new();
        let edge1 = create_test_edge(1);
        let edge2 = create_test_edge(2);

        scorer.record_success(&edge1, Duration::from_millis(100));
        assert!(scorer.get_score(&edge1).is_some());
        scorer.remove(&edge1);
        assert!(scorer.get_score(&edge1).is_none());

        scorer.record_success(&edge2, Duration::from_millis(100));
        scorer.record_failure(&edge2);
        scorer.record_uptime_check(&edge2, true);
        assert_eq!(
            scorer.get_score(&edge2).unwrap().components.total_requests,
            2
        );
        scorer.reset(&edge2);
        let score = scorer.get_score(&edge2).unwrap();
        assert_eq!(score.components.total_requests, 0);
        assert_eq!(score.components.uptime_checks, 0);
    }

    #[test]
    fn test_edge_cases() {
        let scorer = HealthScorer::new();
        let edge1 = create_test_edge(1);
        assert!(scorer.get_score(&edge1).is_none());
        assert!(scorer.get_overall(&edge1).is_none());

        let edge2 = create_test_edge(2);
        scorer.record_failure(&edge2);
        scorer.record_failure(&edge2);
        scorer.record_failure(&edge2);
        let score = scorer.get_score(&edge2).unwrap();
        assert_eq!(score.components.success_rate, 0.0);
        assert_eq!(score.overall, 0.0);
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let scorer = Arc::new(HealthScorer::new());
        let edge = create_test_edge(1);
        let mut handles = vec![];

        for _ in 0..10 {
            let scorer_clone = Arc::clone(&scorer);
            let handle = thread::spawn(move || {
                for i in 0..10 {
                    scorer_clone.record_success(&edge, Duration::from_millis(100 + i));
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let score = scorer.get_score(&edge).unwrap();
        assert_eq!(score.components.total_requests, 100);
        assert_eq!(score.components.successful_requests, 100);
        assert_eq!(score.components.success_rate, 1.0);
    }

    #[test]
    fn test_defaults() {
        let components = HealthComponents::default();
        assert_eq!(components.total_requests, 0);
        assert_eq!(components.success_rate, 0.0);

        let scorer = HealthScorer::default();
        let edge = create_test_edge(1);
        assert!(scorer.get_score(&edge).is_none());

        scorer.record_success(&edge, Duration::from_millis(100));
        scorer.record_uptime_check(&edge, true);
        let overall = scorer.get_overall(&edge).unwrap();
        assert!(overall > 0.0 && overall <= 1.0);
    }

    #[test]
    fn test_empty_operations() {
        let scorer = HealthScorer::new();
        let edge1 = create_test_edge(1);
        let edge2 = create_test_edge(2);

        let edges = vec![edge1, edge2];
        assert_eq!(scorer.rank_edges(&edges).len(), 0);
        assert_eq!(scorer.filter_healthy(&edges, 0.5).len(), 0);
    }

    #[test]
    fn test_custom_weights_calculation() {
        let weights = HealthWeights::new(0.6, 0.2, 0.2);
        let scorer = HealthScorer::with_weights(weights);
        let edge = create_test_edge(1);

        scorer.record_success(&edge, Duration::from_millis(100));
        scorer.record_uptime_check(&edge, true);

        let score = scorer.get_score(&edge).unwrap();
        let expected = 0.6 * score.components.success_rate
            + 0.2 * score.components.uptime
            + 0.2 * score.components.response_time;
        assert!((score.overall - expected).abs() < 0.01);
    }

    #[test]
    fn test_serialization() {
        let mut components = HealthComponents::new();
        components.total_requests = 10;
        components.successful_requests = 8;
        components.success_rate = 0.8;

        let json = serde_json::to_string(&components).unwrap();
        let deserialized: HealthComponents = serde_json::from_str(&json).unwrap();
        assert_eq!(components.total_requests, deserialized.total_requests);
        assert_eq!(
            components.successful_requests,
            deserialized.successful_requests
        );

        let msgpack = rmp_serde::to_vec(&components).unwrap();
        let deserialized: HealthComponents = rmp_serde::from_slice(&msgpack).unwrap();
        assert_eq!(components.total_requests, deserialized.total_requests);
    }
}
