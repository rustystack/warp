//! Saturation Detection for Multi-Path Load Shifting
//!
//! This module provides detection of saturated network paths and automatic
//! load shifting away from congested paths. It works in conjunction with
//! `DynamicEdgeMetrics` to provide adaptive congestion control.
//!
//! # Key Concepts
//!
//! - **Saturation Ratio**: `throughput_bps / capacity_bps` - how full is the path
//! - **RTT Trend**: Increasing RTT indicates congestion building up
//! - **Load Shifting**: Moving traffic away from saturated paths to healthier ones
//!
//! # Usage
//!
//! ```ignore
//! use warp_sched::{SaturationDetector, DynamicEdgeMetrics, EdgeIdx};
//!
//! let detector = SaturationDetector::default();
//! let metrics = DynamicEdgeMetrics::new(EdgeIdx(0), 10_000_000_000);
//!
//! if detector.is_saturated(&metrics) {
//!     // Shift load away from this edge
//! }
//!
//! let penalty = detector.saturation_penalty(&metrics);
//! // Use penalty in cost function
//! ```

use crate::{DynamicEdgeMetrics, EdgeIdx, RttTrend};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Configuration and state for saturation detection
///
/// Provides methods to detect saturated paths and compute penalties
/// for use in the cost function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaturationDetector {
    /// Threshold above which path is considered saturated (0.0-1.0)
    ///
    /// When `throughput_bps / capacity_bps` exceeds this threshold,
    /// the path is considered saturated and penalized. Default: 0.85
    pub saturation_threshold: f32,

    /// RTT increase threshold for congestion detection (0.0-1.0)
    ///
    /// When recent RTT is this much higher than baseline, it's a congestion
    /// signal. Default: 0.20 (20% increase triggers penalty)
    pub rtt_increase_threshold: f32,

    /// Minimum RTT samples before making decisions
    ///
    /// Avoids false positives from noisy measurements. Default: 5
    pub min_samples: usize,

    /// Penalty multiplier for saturation ratio excess
    ///
    /// When `saturation_ratio` exceeds threshold, penalty is:
    /// `(ratio - threshold) * saturation_penalty_scale`
    /// Default: 5.0
    pub saturation_penalty_scale: f32,

    /// Fixed penalty for increasing RTT
    ///
    /// Applied when RTT trend is Increasing. Default: 0.3
    pub rtt_increasing_penalty: f32,

    /// Bonus for decreasing RTT (negative penalty)
    ///
    /// Applied when RTT trend is Decreasing. Default: 0.1
    pub rtt_decreasing_bonus: f32,
}

impl Default for SaturationDetector {
    fn default() -> Self {
        Self {
            saturation_threshold: 0.85,
            rtt_increase_threshold: 0.20,
            min_samples: 5,
            saturation_penalty_scale: 5.0,
            rtt_increasing_penalty: 0.3,
            rtt_decreasing_bonus: 0.1,
        }
    }
}

impl SaturationDetector {
    /// Create a new `SaturationDetector` with custom threshold
    #[must_use]
    pub fn with_threshold(saturation_threshold: f32) -> Self {
        Self {
            saturation_threshold: saturation_threshold.clamp(0.0, 1.0),
            ..Default::default()
        }
    }

    /// Create a detector optimized for aggressive congestion avoidance
    ///
    /// Lower thresholds mean earlier detection and more aggressive shifting.
    #[must_use]
    pub const fn aggressive() -> Self {
        Self {
            saturation_threshold: 0.75,
            rtt_increase_threshold: 0.15,
            min_samples: 3,
            saturation_penalty_scale: 8.0,
            rtt_increasing_penalty: 0.4,
            rtt_decreasing_bonus: 0.15,
        }
    }

    /// Create a detector optimized for conservative congestion avoidance
    ///
    /// Higher thresholds mean more tolerance for saturation before shifting.
    #[must_use]
    pub const fn conservative() -> Self {
        Self {
            saturation_threshold: 0.90,
            rtt_increase_threshold: 0.30,
            min_samples: 10,
            saturation_penalty_scale: 3.0,
            rtt_increasing_penalty: 0.2,
            rtt_decreasing_bonus: 0.05,
        }
    }

    /// Check if an edge is saturated based on its metrics
    ///
    /// Returns true if:
    /// - Saturation ratio exceeds threshold, OR
    /// - RTT trend is Increasing (congestion signal)
    #[must_use]
    pub fn is_saturated(&self, metrics: &DynamicEdgeMetrics) -> bool {
        // Check saturation ratio
        if metrics.throughput.saturation_ratio > self.saturation_threshold {
            return true;
        }

        // Check RTT trend (only if we have enough samples)
        if metrics.rtt_samples.len() >= self.min_samples
            && metrics.rtt_trend == RttTrend::Increasing
        {
            return true;
        }

        false
    }

    /// Calculate saturation penalty for cost function (0.0 - 1.0)
    ///
    /// The penalty is computed from:
    /// 1. Saturation ratio excess (exponential above threshold)
    /// 2. RTT trend (Increasing adds penalty, Decreasing subtracts)
    ///
    /// Returns a value in [0.0, 1.0] suitable for weighting in cost function.
    #[must_use]
    pub fn saturation_penalty(&self, metrics: &DynamicEdgeMetrics) -> f32 {
        let mut penalty = 0.0;

        // Saturation ratio penalty
        let saturation_ratio = metrics.throughput.saturation_ratio;
        if saturation_ratio > self.saturation_threshold {
            let excess = saturation_ratio - self.saturation_threshold;
            penalty += (excess * self.saturation_penalty_scale).min(1.0);
        }

        // RTT trend penalty (only if we have enough samples)
        if metrics.rtt_samples.len() >= self.min_samples {
            match metrics.rtt_trend {
                RttTrend::Increasing => {
                    penalty += self.rtt_increasing_penalty;
                }
                RttTrend::Decreasing => {
                    penalty -= self.rtt_decreasing_bonus;
                }
                RttTrend::Stable => {}
            }
        }

        penalty.clamp(0.0, 1.0)
    }

    /// Get all saturated edges from a metrics map
    ///
    /// Returns a list of edge indices that are currently saturated.
    #[must_use]
    pub fn saturated_edges(&self, metrics: &HashMap<EdgeIdx, DynamicEdgeMetrics>) -> Vec<EdgeIdx> {
        metrics
            .iter()
            .filter(|(_, m)| self.is_saturated(m))
            .map(|(idx, _)| *idx)
            .collect()
    }

    /// Get saturation penalties for all edges
    ///
    /// Returns a map of edge index to penalty value.
    #[must_use]
    pub fn all_penalties(
        &self,
        metrics: &HashMap<EdgeIdx, DynamicEdgeMetrics>,
    ) -> HashMap<EdgeIdx, f32> {
        metrics
            .iter()
            .map(|(idx, m)| (*idx, self.saturation_penalty(m)))
            .collect()
    }

    /// Compute saturation level for a single edge (0.0 - 1.0)
    ///
    /// This is a simpler metric than penalty - just the saturation ratio
    /// relative to threshold.
    #[must_use]
    pub fn saturation_level(&self, metrics: &DynamicEdgeMetrics) -> f32 {
        let ratio = metrics.throughput.saturation_ratio;
        if ratio <= 0.0 {
            0.0
        } else if ratio >= 1.0 {
            1.0
        } else {
            ratio
        }
    }

    /// Check if an edge is approaching saturation (early warning)
    ///
    /// Returns true if saturation ratio is within 10% of threshold.
    #[must_use]
    pub fn is_near_saturation(&self, metrics: &DynamicEdgeMetrics) -> bool {
        let warning_threshold = self.saturation_threshold * 0.9;
        metrics.throughput.saturation_ratio >= warning_threshold
    }

    /// Get the headroom remaining before saturation (0.0 - 1.0)
    ///
    /// Returns how much capacity is left before hitting the threshold.
    /// 1.0 means fully available, 0.0 means at threshold.
    #[must_use]
    pub fn headroom(&self, metrics: &DynamicEdgeMetrics) -> f32 {
        let ratio = metrics.throughput.saturation_ratio;
        let headroom = (self.saturation_threshold - ratio) / self.saturation_threshold;
        headroom.clamp(0.0, 1.0)
    }

    /// Builder method: set saturation threshold
    #[must_use]
    pub const fn with_saturation_threshold(mut self, threshold: f32) -> Self {
        self.saturation_threshold = threshold.clamp(0.0, 1.0);
        self
    }

    /// Builder method: set RTT increase threshold
    #[must_use]
    pub const fn with_rtt_threshold(mut self, threshold: f32) -> Self {
        self.rtt_increase_threshold = threshold.clamp(0.0, 1.0);
        self
    }

    /// Builder method: set minimum samples
    #[must_use]
    pub fn with_min_samples(mut self, samples: usize) -> Self {
        self.min_samples = samples.max(1);
        self
    }

    /// Builder method: set penalty scale
    #[must_use]
    pub const fn with_penalty_scale(mut self, scale: f32) -> Self {
        self.saturation_penalty_scale = scale.max(0.0);
        self
    }
}

/// Summary of saturation state across all edges
#[derive(Debug, Clone, Default)]
pub struct SaturationSummary {
    /// Total number of edges
    pub total_edges: usize,
    /// Number of saturated edges
    pub saturated_count: usize,
    /// Number of edges near saturation (early warning)
    pub near_saturation_count: usize,
    /// Average saturation level across all edges
    pub avg_saturation: f32,
    /// Maximum saturation level
    pub max_saturation: f32,
    /// Edge with highest saturation
    pub most_saturated: Option<EdgeIdx>,
}

impl SaturationSummary {
    /// Compute summary from edge metrics
    #[must_use]
    pub fn from_metrics(
        detector: &SaturationDetector,
        metrics: &HashMap<EdgeIdx, DynamicEdgeMetrics>,
    ) -> Self {
        if metrics.is_empty() {
            return Self::default();
        }

        let total_edges = metrics.len();
        let mut saturated_count = 0;
        let mut near_saturation_count = 0;
        let mut total_saturation = 0.0;
        let mut max_saturation = 0.0_f32;
        let mut most_saturated = None;

        for (idx, m) in metrics {
            let level = detector.saturation_level(m);
            total_saturation += level;

            if detector.is_saturated(m) {
                saturated_count += 1;
            }
            if detector.is_near_saturation(m) {
                near_saturation_count += 1;
            }
            if level > max_saturation {
                max_saturation = level;
                most_saturated = Some(*idx);
            }
        }

        Self {
            total_edges,
            saturated_count,
            near_saturation_count,
            avg_saturation: total_saturation / total_edges as f32,
            max_saturation,
            most_saturated,
        }
    }

    /// Check if any edges are saturated
    #[must_use]
    pub const fn has_saturation(&self) -> bool {
        self.saturated_count > 0
    }

    /// Get saturation ratio (fraction of edges saturated)
    #[must_use]
    pub fn saturation_ratio(&self) -> f32 {
        if self.total_edges == 0 {
            0.0
        } else {
            self.saturated_count as f32 / self.total_edges as f32
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PathThroughput;

    fn make_metrics(
        edge_idx: u32,
        saturation_ratio: f32,
        rtt_trend: RttTrend,
    ) -> DynamicEdgeMetrics {
        let mut metrics = DynamicEdgeMetrics::new(EdgeIdx(edge_idx), 1_000_000_000);
        metrics.throughput.saturation_ratio = saturation_ratio;
        metrics.rtt_trend = rtt_trend;
        // Add enough samples to pass min_samples check
        metrics.rtt_samples = vec![1000; 10];
        metrics
    }

    #[test]
    fn test_default_detector() {
        let detector = SaturationDetector::default();
        assert_eq!(detector.saturation_threshold, 0.85);
        assert_eq!(detector.rtt_increase_threshold, 0.20);
        assert_eq!(detector.min_samples, 5);
    }

    #[test]
    fn test_aggressive_detector() {
        let detector = SaturationDetector::aggressive();
        assert!(detector.saturation_threshold < 0.85);
        assert!(detector.saturation_penalty_scale > 5.0);
    }

    #[test]
    fn test_conservative_detector() {
        let detector = SaturationDetector::conservative();
        assert!(detector.saturation_threshold > 0.85);
        assert!(detector.saturation_penalty_scale < 5.0);
    }

    #[test]
    fn test_is_saturated_by_ratio() {
        let detector = SaturationDetector::default();

        // Below threshold
        let healthy = make_metrics(0, 0.5, RttTrend::Stable);
        assert!(!detector.is_saturated(&healthy));

        // Above threshold
        let saturated = make_metrics(0, 0.90, RttTrend::Stable);
        assert!(detector.is_saturated(&saturated));
    }

    #[test]
    fn test_is_saturated_by_rtt() {
        let detector = SaturationDetector::default();

        // Below threshold but RTT increasing
        let congested = make_metrics(0, 0.5, RttTrend::Increasing);
        assert!(detector.is_saturated(&congested));
    }

    #[test]
    fn test_saturation_penalty_below_threshold() {
        let detector = SaturationDetector::default();
        let metrics = make_metrics(0, 0.5, RttTrend::Stable);

        let penalty = detector.saturation_penalty(&metrics);
        assert_eq!(penalty, 0.0);
    }

    #[test]
    fn test_saturation_penalty_above_threshold() {
        let detector = SaturationDetector::default();
        let metrics = make_metrics(0, 0.90, RttTrend::Stable);

        let penalty = detector.saturation_penalty(&metrics);
        // (0.90 - 0.85) * 5.0 = 0.25
        assert!((penalty - 0.25).abs() < 0.01);
    }

    #[test]
    fn test_saturation_penalty_rtt_increasing() {
        let detector = SaturationDetector::default();
        let metrics = make_metrics(0, 0.5, RttTrend::Increasing);

        let penalty = detector.saturation_penalty(&metrics);
        assert!((penalty - 0.3).abs() < 0.01);
    }

    #[test]
    fn test_saturation_penalty_rtt_decreasing() {
        let detector = SaturationDetector::default();
        let metrics = make_metrics(0, 0.5, RttTrend::Decreasing);

        let penalty = detector.saturation_penalty(&metrics);
        assert_eq!(penalty, 0.0); // Clamped to 0
    }

    #[test]
    fn test_saturation_penalty_combined() {
        let detector = SaturationDetector::default();
        let metrics = make_metrics(0, 0.95, RttTrend::Increasing);

        let penalty = detector.saturation_penalty(&metrics);
        // (0.95 - 0.85) * 5.0 + 0.3 = 0.50 + 0.30 = 0.80
        assert!((penalty - 0.80).abs() < 0.01);
    }

    #[test]
    fn test_saturated_edges() {
        let detector = SaturationDetector::default();
        let mut metrics = HashMap::new();

        metrics.insert(EdgeIdx(0), make_metrics(0, 0.5, RttTrend::Stable));
        metrics.insert(EdgeIdx(1), make_metrics(1, 0.90, RttTrend::Stable));
        metrics.insert(EdgeIdx(2), make_metrics(2, 0.6, RttTrend::Increasing));

        let saturated = detector.saturated_edges(&metrics);
        assert_eq!(saturated.len(), 2);
        assert!(saturated.contains(&EdgeIdx(1)));
        assert!(saturated.contains(&EdgeIdx(2)));
    }

    #[test]
    fn test_is_near_saturation() {
        let detector = SaturationDetector::default();

        // Warning threshold is 0.85 * 0.9 = 0.765
        let near = make_metrics(0, 0.80, RttTrend::Stable);
        assert!(detector.is_near_saturation(&near));

        let not_near = make_metrics(0, 0.5, RttTrend::Stable);
        assert!(!detector.is_near_saturation(&not_near));
    }

    #[test]
    fn test_headroom() {
        let detector = SaturationDetector::default();

        // At 0% saturation: full headroom
        let empty = make_metrics(0, 0.0, RttTrend::Stable);
        assert!((detector.headroom(&empty) - 1.0).abs() < 0.01);

        // At 85% saturation: zero headroom
        let at_threshold = make_metrics(0, 0.85, RttTrend::Stable);
        assert!((detector.headroom(&at_threshold) - 0.0).abs() < 0.01);

        // At 50% saturation: ~41% headroom (0.35/0.85)
        let half = make_metrics(0, 0.50, RttTrend::Stable);
        let expected = (0.85 - 0.50) / 0.85;
        assert!((detector.headroom(&half) - expected).abs() < 0.01);
    }

    #[test]
    fn test_saturation_summary() {
        let detector = SaturationDetector::default();
        let mut metrics = HashMap::new();

        metrics.insert(EdgeIdx(0), make_metrics(0, 0.5, RttTrend::Stable));
        metrics.insert(EdgeIdx(1), make_metrics(1, 0.90, RttTrend::Stable));
        metrics.insert(EdgeIdx(2), make_metrics(2, 0.80, RttTrend::Stable));

        let summary = SaturationSummary::from_metrics(&detector, &metrics);

        assert_eq!(summary.total_edges, 3);
        assert_eq!(summary.saturated_count, 1); // Only edge 1 is above 0.85
        assert_eq!(summary.near_saturation_count, 2); // Edges 1 and 2 are >= 0.765
        assert!((summary.max_saturation - 0.90).abs() < 0.01);
        assert_eq!(summary.most_saturated, Some(EdgeIdx(1)));
    }

    #[test]
    fn test_summary_empty_metrics() {
        let detector = SaturationDetector::default();
        let metrics = HashMap::new();

        let summary = SaturationSummary::from_metrics(&detector, &metrics);
        assert_eq!(summary.total_edges, 0);
        assert!(!summary.has_saturation());
    }

    #[test]
    fn test_builder_methods() {
        let detector = SaturationDetector::default()
            .with_saturation_threshold(0.75)
            .with_rtt_threshold(0.15)
            .with_min_samples(3)
            .with_penalty_scale(10.0);

        assert_eq!(detector.saturation_threshold, 0.75);
        assert_eq!(detector.rtt_increase_threshold, 0.15);
        assert_eq!(detector.min_samples, 3);
        assert_eq!(detector.saturation_penalty_scale, 10.0);
    }

    #[test]
    fn test_min_samples_requirement() {
        let detector = SaturationDetector::default();

        // Too few samples - RTT trend should be ignored
        let mut metrics = DynamicEdgeMetrics::new(EdgeIdx(0), 1_000_000_000);
        metrics.rtt_trend = RttTrend::Increasing;
        metrics.rtt_samples = vec![1000; 2]; // Only 2 samples, need 5

        // Should not be considered saturated (RTT ignored, ratio is 0)
        assert!(!detector.is_saturated(&metrics));

        // Penalty should not include RTT component
        let penalty = detector.saturation_penalty(&metrics);
        assert_eq!(penalty, 0.0);
    }
}
