//! Dynamic Backpressure Propagation for Scheduler
//!
//! This module prevents the scheduler from overwhelming slow consumers by
//! dynamically adjusting the rate of new assignments based on queue depth.
//!
//! # Key Concepts
//!
//! - **Queue Depth**: Bytes waiting to be processed at each edge
//! - **High/Low Water Marks**: Thresholds for throttling decisions
//! - **Throttle Ratio**: Scaling factor for assignment rate (0.0 = paused, 1.0 = full speed)
//!
//! # Usage
//!
//! ```ignore
//! use warp_sched::{BackpressureState, BackpressureConfig};
//!
//! let config = BackpressureConfig::default();
//! let mut state = BackpressureState::new(config);
//!
//! // Update with current queue depth
//! state.update_queue_depth(50_000_000); // 50MB in queue
//!
//! // Get adjusted assignment limit
//! let base_limit = 100;
//! let adjusted = state.adjusted_max_assignments(base_limit);
//! ```

use crate::EdgeIdx;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Configuration for backpressure behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackpressureConfig {
    /// High water mark - start throttling above this queue depth (bytes)
    ///
    /// When queue depth exceeds this, throttle ratio starts decreasing.
    /// Default: 100MB
    pub high_water_mark: u64,

    /// Low water mark - resume full speed below this queue depth (bytes)
    ///
    /// When queue depth falls below this, throttle ratio returns to 1.0.
    /// Default: 50MB
    pub low_water_mark: u64,

    /// Minimum throttle ratio (never go below this)
    ///
    /// Prevents complete starvation. Default: 0.1 (10% minimum)
    pub min_throttle_ratio: f32,

    /// Per-edge high water mark (bytes)
    ///
    /// Individual edges can be throttled independently.
    /// Default: 20MB
    pub per_edge_high_water: u64,

    /// Per-edge low water mark (bytes)
    ///
    /// Default: 10MB
    pub per_edge_low_water: u64,

    /// Smoothing factor for throttle ratio changes (0.0 - 1.0)
    ///
    /// Higher values = faster response to queue changes.
    /// Default: 0.3
    pub smoothing_factor: f32,
}

impl Default for BackpressureConfig {
    fn default() -> Self {
        Self {
            high_water_mark: 100 * 1024 * 1024, // 100MB
            low_water_mark: 50 * 1024 * 1024,   // 50MB
            min_throttle_ratio: 0.1,
            per_edge_high_water: 20 * 1024 * 1024, // 20MB
            per_edge_low_water: 10 * 1024 * 1024,  // 10MB
            smoothing_factor: 0.3,
        }
    }
}

impl BackpressureConfig {
    /// Create a more aggressive backpressure config
    ///
    /// Lower thresholds, faster response to congestion.
    #[must_use]
    pub const fn aggressive() -> Self {
        Self {
            high_water_mark: 50 * 1024 * 1024,
            low_water_mark: 20 * 1024 * 1024,
            min_throttle_ratio: 0.05,
            per_edge_high_water: 10 * 1024 * 1024,
            per_edge_low_water: 5 * 1024 * 1024,
            smoothing_factor: 0.5,
        }
    }

    /// Create a more lenient backpressure config
    ///
    /// Higher thresholds, more tolerance for queue buildup.
    #[must_use]
    pub const fn lenient() -> Self {
        Self {
            high_water_mark: 200 * 1024 * 1024,
            low_water_mark: 100 * 1024 * 1024,
            min_throttle_ratio: 0.2,
            per_edge_high_water: 50 * 1024 * 1024,
            per_edge_low_water: 25 * 1024 * 1024,
            smoothing_factor: 0.2,
        }
    }

    /// Builder: set water marks
    #[must_use]
    pub const fn with_water_marks(mut self, low: u64, high: u64) -> Self {
        self.low_water_mark = low;
        self.high_water_mark = high;
        self
    }

    /// Builder: set minimum throttle ratio
    #[must_use]
    pub const fn with_min_throttle(mut self, min: f32) -> Self {
        self.min_throttle_ratio = min.clamp(0.0, 1.0);
        self
    }
}

/// Current backpressure state for the scheduler
#[derive(Debug, Clone)]
pub struct BackpressureState {
    /// Configuration
    config: BackpressureConfig,

    /// Global queue depth (bytes waiting across all edges)
    queue_depth_bytes: u64,

    /// Per-edge queue depth
    edge_queue_depth: HashMap<EdgeIdx, u64>,

    /// Current throttle ratio (0.0 = paused, 1.0 = full speed)
    throttle_ratio: f32,

    /// Edges currently experiencing backpressure
    pressured_edges: HashSet<EdgeIdx>,

    /// Last update timestamp (for rate limiting updates)
    last_update_ms: u64,
}

impl BackpressureState {
    /// Create a new backpressure state
    #[must_use]
    pub fn new(config: BackpressureConfig) -> Self {
        Self {
            config,
            queue_depth_bytes: 0,
            edge_queue_depth: HashMap::new(),
            throttle_ratio: 1.0,
            pressured_edges: HashSet::new(),
            last_update_ms: 0,
        }
    }

    /// Update global queue depth and recalculate throttle ratio
    pub fn update_queue_depth(&mut self, queue_depth_bytes: u64) {
        self.queue_depth_bytes = queue_depth_bytes;
        self.recalculate_throttle();
    }

    /// Update queue depth for a specific edge
    pub fn update_edge_queue_depth(&mut self, edge_idx: EdgeIdx, depth_bytes: u64) {
        self.edge_queue_depth.insert(edge_idx, depth_bytes);

        // Check if edge is pressured
        if depth_bytes > self.config.per_edge_high_water {
            self.pressured_edges.insert(edge_idx);
        } else if depth_bytes < self.config.per_edge_low_water {
            self.pressured_edges.remove(&edge_idx);
        }

        // Recalculate global queue depth
        self.queue_depth_bytes = self.edge_queue_depth.values().sum();
        self.recalculate_throttle();
    }

    /// Increment queue depth for an edge (when assigning work)
    pub fn add_pending(&mut self, edge_idx: EdgeIdx, bytes: u64) {
        let current = self.edge_queue_depth.entry(edge_idx).or_insert(0);
        *current = current.saturating_add(bytes);
        self.queue_depth_bytes = self.queue_depth_bytes.saturating_add(bytes);

        // Check pressure threshold
        if *current > self.config.per_edge_high_water {
            self.pressured_edges.insert(edge_idx);
        }

        self.recalculate_throttle();
    }

    /// Decrement queue depth for an edge (when work completes)
    pub fn complete_pending(&mut self, edge_idx: EdgeIdx, bytes: u64) {
        if let Some(current) = self.edge_queue_depth.get_mut(&edge_idx) {
            *current = current.saturating_sub(bytes);
            self.queue_depth_bytes = self.queue_depth_bytes.saturating_sub(bytes);

            // Check if pressure relieved
            if *current < self.config.per_edge_low_water {
                self.pressured_edges.remove(&edge_idx);
            }
        }

        self.recalculate_throttle();
    }

    /// Recalculate throttle ratio based on current queue depth
    fn recalculate_throttle(&mut self) {
        let target_ratio = if self.queue_depth_bytes > self.config.high_water_mark {
            // Exponential backoff as we exceed high water
            let excess = self.queue_depth_bytes - self.config.high_water_mark;
            let ratio = 1.0 - (excess as f32 / self.config.high_water_mark as f32);
            ratio.clamp(self.config.min_throttle_ratio, 1.0)
        } else if self.queue_depth_bytes < self.config.low_water_mark {
            1.0 // Full speed
        } else {
            // Linear interpolation between low and high
            let range = self.config.high_water_mark - self.config.low_water_mark;
            let position = self.queue_depth_bytes - self.config.low_water_mark;
            let reduction = position as f32 / range as f32 * 0.5; // 50-100%
            (1.0 - reduction).clamp(self.config.min_throttle_ratio, 1.0)
        };

        // Apply smoothing
        self.throttle_ratio = self
            .config
            .smoothing_factor
            .mul_add(target_ratio - self.throttle_ratio, self.throttle_ratio);
    }

    /// Get adjusted max assignments for current tick
    #[must_use]
    pub fn adjusted_max_assignments(&self, base_max: usize) -> usize {
        let adjusted = (base_max as f32 * self.throttle_ratio) as usize;
        adjusted.max(1) // Always allow at least 1
    }

    /// Check if an edge should be avoided due to backpressure
    #[must_use]
    pub fn is_edge_pressured(&self, edge_idx: EdgeIdx) -> bool {
        self.pressured_edges.contains(&edge_idx)
    }

    /// Get current throttle ratio
    #[must_use]
    pub const fn throttle_ratio(&self) -> f32 {
        self.throttle_ratio
    }

    /// Get current queue depth
    #[must_use]
    pub const fn queue_depth(&self) -> u64 {
        self.queue_depth_bytes
    }

    /// Get queue depth for a specific edge
    #[must_use]
    pub fn edge_queue_depth(&self, edge_idx: EdgeIdx) -> u64 {
        self.edge_queue_depth.get(&edge_idx).copied().unwrap_or(0)
    }

    /// Get all pressured edges
    #[must_use]
    pub const fn pressured_edges(&self) -> &HashSet<EdgeIdx> {
        &self.pressured_edges
    }

    /// Get number of pressured edges
    #[must_use]
    pub fn pressured_edge_count(&self) -> usize {
        self.pressured_edges.len()
    }

    /// Check if system is under global backpressure
    #[must_use]
    pub fn is_under_pressure(&self) -> bool {
        self.throttle_ratio < 1.0
    }

    /// Get configuration
    #[must_use]
    pub const fn config(&self) -> &BackpressureConfig {
        &self.config
    }

    /// Reset all state
    pub fn reset(&mut self) {
        self.queue_depth_bytes = 0;
        self.edge_queue_depth.clear();
        self.throttle_ratio = 1.0;
        self.pressured_edges.clear();
    }
}

/// Summary of backpressure state for metrics/monitoring
#[derive(Debug, Clone, Default)]
pub struct BackpressureSummary {
    /// Global queue depth in bytes
    pub queue_depth_bytes: u64,
    /// Current throttle ratio
    pub throttle_ratio: f32,
    /// Number of pressured edges
    pub pressured_edge_count: usize,
    /// High water mark from config
    pub high_water_mark: u64,
    /// Low water mark from config
    pub low_water_mark: u64,
    /// Percentage of high water mark used
    pub usage_percent: f32,
}

impl BackpressureSummary {
    /// Create summary from state
    #[must_use]
    pub fn from_state(state: &BackpressureState) -> Self {
        let usage_percent = if state.config.high_water_mark > 0 {
            (state.queue_depth_bytes as f32 / state.config.high_water_mark as f32) * 100.0
        } else {
            0.0
        };

        Self {
            queue_depth_bytes: state.queue_depth_bytes,
            throttle_ratio: state.throttle_ratio,
            pressured_edge_count: state.pressured_edges.len(),
            high_water_mark: state.config.high_water_mark,
            low_water_mark: state.config.low_water_mark,
            usage_percent,
        }
    }

    /// Check if summary indicates pressure
    #[must_use]
    pub fn is_under_pressure(&self) -> bool {
        self.throttle_ratio < 1.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = BackpressureConfig::default();
        assert_eq!(config.high_water_mark, 100 * 1024 * 1024);
        assert_eq!(config.low_water_mark, 50 * 1024 * 1024);
        assert_eq!(config.min_throttle_ratio, 0.1);
    }

    #[test]
    fn test_aggressive_config() {
        let config = BackpressureConfig::aggressive();
        assert!(config.high_water_mark < BackpressureConfig::default().high_water_mark);
        assert!(config.smoothing_factor > BackpressureConfig::default().smoothing_factor);
    }

    #[test]
    fn test_lenient_config() {
        let config = BackpressureConfig::lenient();
        assert!(config.high_water_mark > BackpressureConfig::default().high_water_mark);
    }

    #[test]
    fn test_initial_state() {
        let state = BackpressureState::new(BackpressureConfig::default());
        assert_eq!(state.throttle_ratio(), 1.0);
        assert_eq!(state.queue_depth(), 0);
        assert!(!state.is_under_pressure());
    }

    #[test]
    fn test_below_low_water() {
        let config = BackpressureConfig::default();
        let mut state = BackpressureState::new(config.clone());

        state.update_queue_depth(config.low_water_mark / 2);
        assert_eq!(state.throttle_ratio(), 1.0);
        assert!(!state.is_under_pressure());
    }

    #[test]
    fn test_between_water_marks() {
        let config = BackpressureConfig::default();
        let mut state = BackpressureState::new(config.clone());

        // Set to midpoint between low and high
        let midpoint = (config.low_water_mark + config.high_water_mark) / 2;
        state.update_queue_depth(midpoint);

        // Should be throttled but not at minimum
        assert!(state.throttle_ratio() < 1.0);
        assert!(state.throttle_ratio() > config.min_throttle_ratio);
        assert!(state.is_under_pressure());
    }

    #[test]
    fn test_above_high_water() {
        let mut config = BackpressureConfig::default();
        config.smoothing_factor = 1.0; // Disable smoothing for this test
        let mut state = BackpressureState::new(config.clone());

        // Set well above high water
        state.update_queue_depth(config.high_water_mark * 2);

        // Should be heavily throttled (without smoothing)
        assert!(state.throttle_ratio() < 0.5);
        assert!(state.throttle_ratio() >= config.min_throttle_ratio);
        assert!(state.is_under_pressure());
    }

    #[test]
    fn test_never_below_min_throttle() {
        let config = BackpressureConfig::default();
        let mut state = BackpressureState::new(config.clone());

        // Set extremely high
        state.update_queue_depth(config.high_water_mark * 100);

        assert!(state.throttle_ratio() >= config.min_throttle_ratio);
    }

    #[test]
    fn test_adjusted_max_assignments() {
        let config = BackpressureConfig::default();
        let mut state = BackpressureState::new(config.clone());

        // Full speed
        assert_eq!(state.adjusted_max_assignments(100), 100);

        // Under pressure
        state.update_queue_depth(config.high_water_mark * 2);
        let adjusted = state.adjusted_max_assignments(100);
        assert!(adjusted < 100);
        assert!(adjusted >= 1); // Always at least 1
    }

    #[test]
    fn test_edge_pressure() {
        let config = BackpressureConfig::default();
        let mut state = BackpressureState::new(config.clone());

        let edge = EdgeIdx(1);

        // Initially not pressured
        assert!(!state.is_edge_pressured(edge));

        // Add enough to trigger pressure
        state.update_edge_queue_depth(edge, config.per_edge_high_water + 1);
        assert!(state.is_edge_pressured(edge));

        // Relieve pressure
        state.update_edge_queue_depth(edge, config.per_edge_low_water - 1);
        assert!(!state.is_edge_pressured(edge));
    }

    #[test]
    fn test_add_complete_pending() {
        let config = BackpressureConfig::default();
        let mut state = BackpressureState::new(config);

        let edge = EdgeIdx(1);

        state.add_pending(edge, 1000);
        assert_eq!(state.queue_depth(), 1000);
        assert_eq!(state.edge_queue_depth(edge), 1000);

        state.add_pending(edge, 500);
        assert_eq!(state.queue_depth(), 1500);

        state.complete_pending(edge, 700);
        assert_eq!(state.queue_depth(), 800);
        assert_eq!(state.edge_queue_depth(edge), 800);
    }

    #[test]
    fn test_reset() {
        let config = BackpressureConfig::default();
        let mut state = BackpressureState::new(config.clone());

        state.update_queue_depth(config.high_water_mark * 2);
        state.update_edge_queue_depth(EdgeIdx(1), config.per_edge_high_water * 2);

        assert!(state.is_under_pressure());
        assert!(state.pressured_edge_count() > 0);

        state.reset();

        assert!(!state.is_under_pressure());
        assert_eq!(state.queue_depth(), 0);
        assert_eq!(state.pressured_edge_count(), 0);
        assert_eq!(state.throttle_ratio(), 1.0);
    }

    #[test]
    fn test_summary() {
        let config = BackpressureConfig::default();
        let mut state = BackpressureState::new(config.clone());

        state.update_queue_depth(config.high_water_mark / 2); // 50%

        let summary = BackpressureSummary::from_state(&state);
        assert_eq!(summary.queue_depth_bytes, config.high_water_mark / 2);
        assert!((summary.usage_percent - 50.0).abs() < 1.0);
    }

    #[test]
    fn test_smoothing() {
        let mut config = BackpressureConfig::default();
        config.smoothing_factor = 1.0; // No smoothing
        let high_water = config.high_water_mark;

        let mut state = BackpressureState::new(config.clone());

        // Jump to high pressure
        state.update_queue_depth(high_water * 2);
        let ratio_fast = state.throttle_ratio();

        // Now with smoothing
        config.smoothing_factor = 0.1; // Strong smoothing
        let mut state_slow = BackpressureState::new(config);
        state_slow.update_queue_depth(high_water * 2);
        let ratio_slow = state_slow.throttle_ratio();

        // Slow should be closer to 1.0 (starting point)
        assert!(ratio_slow > ratio_fast);
    }
}
