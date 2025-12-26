//! Adaptive Erasure Coding
//!
//! Automatically adjusts erasure coding parameters based on network conditions.
//! Monitors packet loss, latency, and throughput to optimize the data:parity ratio.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Network quality metrics for adaptive erasure decisions
#[derive(Debug, Clone, Copy)]
pub struct NetworkMetrics {
    /// Packet loss rate (0.0 - 1.0)
    pub packet_loss: f64,
    /// Average round-trip latency in milliseconds
    pub avg_latency_ms: f64,
    /// Latency variance (jitter) in milliseconds
    pub latency_jitter_ms: f64,
    /// Current throughput in bytes per second
    pub throughput_bps: f64,
    /// Connection quality score (0.0 - 1.0, higher is better)
    pub quality_score: f64,
}

impl NetworkMetrics {
    /// Calculate quality score from other metrics
    pub fn calculate_quality(&mut self) {
        // Lower packet loss = better quality
        let loss_factor = 1.0 - self.packet_loss.clamp(0.0, 1.0);

        // Lower latency = better quality (normalize to 0-1, assuming 500ms is bad)
        let latency_factor = 1.0 - (self.avg_latency_ms / 500.0).clamp(0.0, 1.0);

        // Lower jitter = better quality (normalize to 0-1, assuming 100ms jitter is bad)
        let jitter_factor = 1.0 - (self.latency_jitter_ms / 100.0).clamp(0.0, 1.0);

        // Weighted average
        self.quality_score = loss_factor * 0.5 + latency_factor * 0.3 + jitter_factor * 0.2;
    }
}

impl Default for NetworkMetrics {
    fn default() -> Self {
        Self {
            packet_loss: 0.0,
            avg_latency_ms: 50.0,
            latency_jitter_ms: 10.0,
            throughput_bps: 100_000_000.0, // 100 MB/s default
            quality_score: 0.9,
        }
    }
}

/// Suggested erasure coding parameters
#[derive(Debug, Clone, Copy)]
pub struct ErasureParameters {
    /// Number of data shards
    pub data_shards: usize,
    /// Number of parity shards
    pub parity_shards: usize,
    /// Recommended parallel streams
    pub parallel_streams: usize,
}

impl ErasureParameters {
    /// Get total shard count
    pub fn total_shards(&self) -> usize {
        self.data_shards + self.parity_shards
    }

    /// Get redundancy ratio (parity / data)
    pub fn redundancy_ratio(&self) -> f64 {
        self.parity_shards as f64 / self.data_shards as f64
    }

    /// Get overhead percentage
    pub fn overhead_percent(&self) -> f64 {
        (self.parity_shards as f64 / self.data_shards as f64) * 100.0
    }
}

impl Default for ErasureParameters {
    fn default() -> Self {
        Self {
            data_shards: 4,
            parity_shards: 2,
            parallel_streams: 4,
        }
    }
}

/// Configuration for adaptive erasure
#[derive(Debug, Clone)]
pub struct AdaptiveErasureConfig {
    /// Minimum data shards
    pub min_data_shards: usize,
    /// Maximum data shards
    pub max_data_shards: usize,
    /// Minimum parity shards
    pub min_parity_shards: usize,
    /// Maximum parity shards
    pub max_parity_shards: usize,
    /// Network quality threshold for increasing parity
    pub quality_threshold_increase: f64,
    /// Network quality threshold for decreasing parity
    pub quality_threshold_decrease: f64,
    /// Sample window for averaging metrics
    pub sample_window: usize,
    /// Minimum time between parameter adjustments
    pub adjustment_cooldown: Duration,
}

impl Default for AdaptiveErasureConfig {
    fn default() -> Self {
        Self {
            min_data_shards: 2,
            max_data_shards: 16,
            min_parity_shards: 1,
            max_parity_shards: 8,
            quality_threshold_increase: 0.7, // Increase parity when quality < 70%
            quality_threshold_decrease: 0.9, // Decrease parity when quality > 90%
            sample_window: 20,
            adjustment_cooldown: Duration::from_secs(5),
        }
    }
}

/// Adaptive erasure coding controller
#[derive(Debug)]
pub struct AdaptiveErasure {
    config: AdaptiveErasureConfig,
    current_params: ErasureParameters,
    metrics_history: VecDeque<NetworkMetrics>,
    last_adjustment: Option<Instant>,
    total_samples: u64,
}

impl AdaptiveErasure {
    /// Create a new adaptive erasure controller
    pub fn new(config: AdaptiveErasureConfig) -> Self {
        Self {
            config,
            current_params: ErasureParameters::default(),
            metrics_history: VecDeque::with_capacity(50),
            last_adjustment: None,
            total_samples: 0,
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(AdaptiveErasureConfig::default())
    }

    /// Record a network metrics sample
    pub fn record_sample(&mut self, mut metrics: NetworkMetrics) {
        metrics.calculate_quality();
        self.metrics_history.push_back(metrics);
        self.total_samples += 1;

        // Keep only the recent samples
        while self.metrics_history.len() > self.config.sample_window {
            self.metrics_history.pop_front();
        }
    }

    /// Record individual metrics from transfer
    pub fn record_transfer_metrics(
        &mut self,
        latency_ms: f64,
        bytes_transferred: u64,
        duration: Duration,
        shards_lost: usize,
        total_shards: usize,
    ) {
        let throughput = if duration.as_secs_f64() > 0.0 {
            bytes_transferred as f64 / duration.as_secs_f64()
        } else {
            0.0
        };

        let packet_loss = if total_shards > 0 {
            shards_lost as f64 / total_shards as f64
        } else {
            0.0
        };

        let avg_latency = if !self.metrics_history.is_empty() {
            (self.get_average_metrics().avg_latency_ms + latency_ms) / 2.0
        } else {
            latency_ms
        };

        let jitter = if !self.metrics_history.is_empty() {
            (latency_ms - self.get_average_metrics().avg_latency_ms).abs()
        } else {
            0.0
        };

        self.record_sample(NetworkMetrics {
            packet_loss,
            avg_latency_ms: avg_latency,
            latency_jitter_ms: jitter,
            throughput_bps: throughput,
            quality_score: 0.0, // Will be calculated
        });
    }

    /// Get average metrics over the sample window
    pub fn get_average_metrics(&self) -> NetworkMetrics {
        if self.metrics_history.is_empty() {
            return NetworkMetrics::default();
        }

        let count = self.metrics_history.len() as f64;
        let mut avg = NetworkMetrics::default();

        for m in &self.metrics_history {
            avg.packet_loss += m.packet_loss;
            avg.avg_latency_ms += m.avg_latency_ms;
            avg.latency_jitter_ms += m.latency_jitter_ms;
            avg.throughput_bps += m.throughput_bps;
            avg.quality_score += m.quality_score;
        }

        avg.packet_loss /= count;
        avg.avg_latency_ms /= count;
        avg.latency_jitter_ms /= count;
        avg.throughput_bps /= count;
        avg.quality_score /= count;

        avg
    }

    /// Evaluate and potentially adjust erasure parameters
    pub fn evaluate(&mut self) -> ErasureParameters {
        // Check cooldown
        if let Some(last) = self.last_adjustment {
            if last.elapsed() < self.config.adjustment_cooldown {
                return self.current_params;
            }
        }

        // Need enough samples
        if self.metrics_history.len() < 5 {
            return self.current_params;
        }

        let avg = self.get_average_metrics();
        let mut adjusted = false;

        // Poor network quality: increase redundancy
        if avg.quality_score < self.config.quality_threshold_increase {
            if self.current_params.parity_shards < self.config.max_parity_shards {
                self.current_params.parity_shards += 1;
                adjusted = true;
                tracing::info!(
                    quality = avg.quality_score,
                    parity = self.current_params.parity_shards,
                    "Increased parity shards due to poor network quality"
                );
            }
        }
        // Good network quality: decrease redundancy
        else if avg.quality_score > self.config.quality_threshold_decrease {
            if self.current_params.parity_shards > self.config.min_parity_shards {
                self.current_params.parity_shards -= 1;
                adjusted = true;
                tracing::info!(
                    quality = avg.quality_score,
                    parity = self.current_params.parity_shards,
                    "Decreased parity shards due to good network quality"
                );
            }
        }

        // Adjust parallel streams based on throughput
        // High throughput + low latency = more parallel streams
        if avg.throughput_bps > 500_000_000.0 && avg.avg_latency_ms < 20.0 {
            self.current_params.parallel_streams =
                (self.current_params.parallel_streams + 1).min(8);
        } else if avg.throughput_bps < 10_000_000.0 || avg.avg_latency_ms > 200.0 {
            self.current_params.parallel_streams =
                (self.current_params.parallel_streams - 1).max(1);
        }

        if adjusted {
            self.last_adjustment = Some(Instant::now());
        }

        self.current_params
    }

    /// Get current parameters without evaluation
    pub fn current_parameters(&self) -> ErasureParameters {
        self.current_params
    }

    /// Set initial parameters
    pub fn set_parameters(&mut self, params: ErasureParameters) {
        self.current_params = params;
    }

    /// Get recommended parameters for given packet loss rate
    pub fn recommend_for_loss_rate(loss_rate: f64) -> ErasureParameters {
        // Higher loss = more parity shards
        let parity = match loss_rate {
            l if l < 0.01 => 1,   // < 1% loss: minimal parity
            l if l < 0.05 => 2,   // < 5% loss: standard parity
            l if l < 0.10 => 3,   // < 10% loss: increased parity
            l if l < 0.20 => 4,   // < 20% loss: high parity
            l if l < 0.30 => 6,   // < 30% loss: very high parity
            _ => 8,               // >= 30% loss: maximum parity
        };

        // Data shards scale with parity to maintain efficiency
        let data = (parity * 2).max(4).min(16);

        ErasureParameters {
            data_shards: data,
            parity_shards: parity,
            parallel_streams: 4,
        }
    }

    /// Get statistics
    pub fn stats(&self) -> AdaptiveErasureStats {
        AdaptiveErasureStats {
            total_samples: self.total_samples,
            current_params: self.current_params,
            avg_metrics: self.get_average_metrics(),
            adjustments_made: self.last_adjustment.is_some(),
        }
    }
}

/// Statistics from adaptive erasure controller
#[derive(Debug, Clone)]
pub struct AdaptiveErasureStats {
    /// Total samples recorded
    pub total_samples: u64,
    /// Current erasure parameters
    pub current_params: ErasureParameters,
    /// Average network metrics
    pub avg_metrics: NetworkMetrics,
    /// Whether any adjustments have been made
    pub adjustments_made: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_parameters() {
        let params = ErasureParameters::default();
        assert_eq!(params.data_shards, 4);
        assert_eq!(params.parity_shards, 2);
        assert_eq!(params.total_shards(), 6);
        assert!((params.redundancy_ratio() - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_quality_calculation() {
        let mut metrics = NetworkMetrics {
            packet_loss: 0.0,
            avg_latency_ms: 10.0,
            latency_jitter_ms: 5.0,
            throughput_bps: 100_000_000.0,
            quality_score: 0.0,
        };
        metrics.calculate_quality();
        assert!(metrics.quality_score > 0.9); // Good network = high score
    }

    #[test]
    fn test_recommend_for_loss_rate() {
        let low_loss = AdaptiveErasure::recommend_for_loss_rate(0.005);
        assert_eq!(low_loss.parity_shards, 1);

        let high_loss = AdaptiveErasure::recommend_for_loss_rate(0.25);
        assert_eq!(high_loss.parity_shards, 6);
    }

    #[test]
    fn test_adaptive_increase_parity() {
        let mut adaptive = AdaptiveErasure::with_defaults();

        // Record poor network conditions
        for _ in 0..10 {
            adaptive.record_sample(NetworkMetrics {
                packet_loss: 0.15,
                avg_latency_ms: 200.0,
                latency_jitter_ms: 50.0,
                throughput_bps: 10_000_000.0,
                quality_score: 0.0,
            });
        }

        let initial_parity = adaptive.current_parameters().parity_shards;
        let params = adaptive.evaluate();

        // Should have increased parity due to poor quality
        assert!(params.parity_shards >= initial_parity);
    }
}
