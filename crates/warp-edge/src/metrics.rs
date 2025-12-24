//! Network performance metrics for bandwidth and RTT estimation
//!
//! This module provides:
//! - BandwidthEstimator: EMA-based bandwidth tracking per edge
//! - RttEstimator: RFC 6298 style RTT estimation with SRTT/RTTVAR
//! - Thread-safe concurrent access via DashMap

use crate::types::EdgeId;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};

/// Bandwidth metrics for a single edge
///
/// Tracks upload/download bandwidth using exponential moving average (EMA).
/// All bandwidth values are in bytes per second.
///
/// Field ordering optimized for cache efficiency:
/// - HOT fields (bandwidth values, sample_count) are first
/// - COLD fields (peaks, timestamp) are last with SystemTime at the end (16 bytes)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthMetrics {
    // === HOT: Read on every bandwidth estimate ===
    /// Upload bandwidth in bytes/sec (EMA)
    pub upload_bps: f64,
    /// Download bandwidth in bytes/sec (EMA)
    pub download_bps: f64,
    /// Number of samples recorded
    pub sample_count: u64,

    // === COLD: Statistics and timestamps ===
    /// Peak upload bandwidth observed
    pub peak_upload: f64,
    /// Peak download bandwidth observed
    pub peak_download: f64,
    /// Last time metrics were updated (16 bytes - placed last)
    pub last_updated: SystemTime,
}

/// Bandwidth estimator with EMA smoothing
///
/// Uses exponential moving average to estimate upload/download bandwidth
/// per edge. Thread-safe via DashMap. Formula: `new_ema = alpha * sample + (1-alpha) * old_ema`
pub struct BandwidthEstimator {
    metrics: DashMap<EdgeId, BandwidthMetrics>,
    alpha: f64,
}

impl BandwidthEstimator {
    /// Creates a new bandwidth estimator with custom alpha (0.0 to 1.0)
    pub fn new(alpha: f64) -> Self {
        BandwidthEstimator {
            metrics: DashMap::new(),
            alpha: alpha.clamp(0.0, 1.0),
        }
    }

    /// Creates a new bandwidth estimator with default alpha (0.2)
    pub fn with_default_alpha() -> Self {
        Self::new(0.2)
    }

    /// Records an upload measurement for an edge
    pub fn record_upload(&self, edge: EdgeId, bytes: u64, duration: Duration) {
        let duration_secs = duration.as_secs_f64();
        if duration_secs <= 0.0 {
            return;
        }

        let sample_bps = bytes as f64 / duration_secs;
        // Cache timestamp before lock to avoid syscall inside critical section
        let now = SystemTime::now();

        self.metrics
            .entry(edge)
            .and_modify(|m| {
                m.upload_bps = self.alpha * sample_bps + (1.0 - self.alpha) * m.upload_bps;
                m.peak_upload = m.peak_upload.max(sample_bps);
                m.sample_count = m.sample_count.saturating_add(1);
                m.last_updated = now;
            })
            .or_insert_with(|| BandwidthMetrics {
                // HOT
                upload_bps: sample_bps,
                download_bps: 0.0,
                sample_count: 1,
                // COLD
                peak_upload: sample_bps,
                peak_download: 0.0,
                last_updated: now,
            });
    }

    /// Records a download measurement for an edge
    pub fn record_download(&self, edge: EdgeId, bytes: u64, duration: Duration) {
        let duration_secs = duration.as_secs_f64();
        if duration_secs <= 0.0 {
            return;
        }

        let sample_bps = bytes as f64 / duration_secs;
        // Cache timestamp before lock to avoid syscall inside critical section
        let now = SystemTime::now();

        self.metrics
            .entry(edge)
            .and_modify(|m| {
                m.download_bps = self.alpha * sample_bps + (1.0 - self.alpha) * m.download_bps;
                m.peak_download = m.peak_download.max(sample_bps);
                m.sample_count = m.sample_count.saturating_add(1);
                m.last_updated = now;
            })
            .or_insert_with(|| BandwidthMetrics {
                // HOT
                upload_bps: 0.0,
                download_bps: sample_bps,
                sample_count: 1,
                // COLD
                peak_upload: 0.0,
                peak_download: sample_bps,
                last_updated: now,
            });
    }

    /// Retrieves bandwidth metrics for an edge
    pub fn get(&self, edge: &EdgeId) -> Option<BandwidthMetrics> {
        self.metrics.get(edge).map(|m| m.clone())
    }

    /// Estimates upload time for a given number of bytes. Returns None if no metrics available.
    pub fn estimate_upload_time(&self, edge: &EdgeId, bytes: u64) -> Option<Duration> {
        let metrics = self.metrics.get(edge)?;
        if metrics.upload_bps <= 0.0 {
            return None;
        }
        let secs = bytes as f64 / metrics.upload_bps;
        Some(Duration::from_secs_f64(secs))
    }

    /// Estimates download time for a given number of bytes. Returns None if no metrics available.
    pub fn estimate_download_time(&self, edge: &EdgeId, bytes: u64) -> Option<Duration> {
        let metrics = self.metrics.get(edge)?;
        if metrics.download_bps <= 0.0 {
            return None;
        }
        let secs = bytes as f64 / metrics.download_bps;
        Some(Duration::from_secs_f64(secs))
    }

    /// Removes an edge from tracking
    pub fn remove(&self, edge: &EdgeId) {
        self.metrics.remove(edge);
    }
}

/// RTT metrics for a single edge using RFC 6298 TCP-style estimation
///
/// Field ordering optimized for cache efficiency:
/// - HOT fields (SRTT, RTTVAR, sample_count) are first - used in RFC 6298 calculations
/// - WARM fields (RTO - derived value) are next
/// - COLD fields (min/max, timestamp) are last with SystemTime at the end (16 bytes)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RttMetrics {
    // === HOT: Used in RFC 6298 calculations ===
    /// Smoothed RTT in microseconds
    pub srtt_us: u64,
    /// RTT variance in microseconds
    pub rttvar_us: u64,
    /// Number of RTT samples
    pub sample_count: u64,

    // === WARM: Derived timeout value ===
    /// Recommended timeout (RTO)
    pub rto: Duration,

    // === COLD: Statistics and timestamps ===
    /// Minimum RTT observed (microseconds)
    pub min_rtt_us: u64,
    /// Maximum RTT observed (microseconds)
    pub max_rtt_us: u64,
    /// Last update timestamp (16 bytes - placed last)
    pub last_updated: SystemTime,
}

/// RTT estimator using RFC 6298 algorithm (alpha=1/8, beta=1/4, RTO=SRTT+4*RTTVAR)
pub struct RttEstimator {
    metrics: DashMap<EdgeId, RttMetrics>,
}

impl RttEstimator {
    const ALPHA: f64 = 0.125; // 1/8
    const BETA: f64 = 0.25; // 1/4

    /// Creates a new RTT estimator
    pub fn new() -> Self {
        RttEstimator {
            metrics: DashMap::new(),
        }
    }

    /// Records an RTT sample and updates SRTT, RTTVAR, and RTO per RFC 6298
    pub fn record_rtt(&self, edge: EdgeId, rtt: Duration) {
        let rtt_us = rtt.as_micros() as u64;

        self.metrics
            .entry(edge)
            .and_modify(|m| {
                // RFC 6298: subsequent samples
                let rtt_diff = (m.srtt_us as i64 - rtt_us as i64).abs() as u64;
                m.rttvar_us =
                    ((1.0 - Self::BETA) * m.rttvar_us as f64 + Self::BETA * rtt_diff as f64)
                        as u64;
                m.srtt_us =
                    ((1.0 - Self::ALPHA) * m.srtt_us as f64 + Self::ALPHA * rtt_us as f64) as u64;

                let rto_us = m.srtt_us + 4 * m.rttvar_us;
                m.rto = Duration::from_micros(rto_us);

                m.min_rtt_us = m.min_rtt_us.min(rtt_us);
                m.max_rtt_us = m.max_rtt_us.max(rtt_us);
                m.sample_count = m.sample_count.saturating_add(1);
                m.last_updated = SystemTime::now();
            })
            .or_insert_with(|| {
                // RFC 6298: first sample
                let rttvar_us = rtt_us / 2;
                let rto_us = rtt_us + 4 * rttvar_us;
                RttMetrics {
                    // HOT
                    srtt_us: rtt_us,
                    rttvar_us,
                    sample_count: 1,
                    // WARM
                    rto: Duration::from_micros(rto_us),
                    // COLD
                    min_rtt_us: rtt_us,
                    max_rtt_us: rtt_us,
                    last_updated: SystemTime::now(),
                }
            });
    }

    /// Retrieves RTT metrics for an edge
    pub fn get(&self, edge: &EdgeId) -> Option<RttMetrics> {
        self.metrics.get(edge).map(|m| m.clone())
    }

    /// Gets the recommended timeout (RTO) for an edge
    pub fn get_timeout(&self, edge: &EdgeId) -> Option<Duration> {
        self.metrics.get(edge).map(|m| m.rto)
    }

    /// Gets the smoothed RTT (SRTT) for an edge
    pub fn get_srtt(&self, edge: &EdgeId) -> Option<Duration> {
        self.metrics
            .get(edge)
            .map(|m| Duration::from_micros(m.srtt_us))
    }

    /// Removes an edge from tracking
    pub fn remove(&self, edge: &EdgeId) {
        self.metrics.remove(edge);
    }
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_edge(id: u8) -> EdgeId {
        EdgeId::new([id; 32])
    }

    // BandwidthEstimator Tests

    #[test]
    fn test_bandwidth_estimator_new_custom_alpha() {
        let estimator = BandwidthEstimator::new(0.3);
        assert_eq!(estimator.alpha, 0.3);
    }

    #[test]
    fn test_bandwidth_estimator_new_alpha_clamping() {
        let estimator1 = BandwidthEstimator::new(-0.5);
        assert_eq!(estimator1.alpha, 0.0);

        let estimator2 = BandwidthEstimator::new(1.5);
        assert_eq!(estimator2.alpha, 1.0);
    }

    #[test]
    fn test_bandwidth_estimator_default_alpha() {
        let estimator = BandwidthEstimator::with_default_alpha();
        assert_eq!(estimator.alpha, 0.2);
    }

    #[test]
    fn test_bandwidth_record_upload_first_sample() {
        let estimator = BandwidthEstimator::with_default_alpha();
        let edge = test_edge(1);

        // 1MB in 1 second = 1MB/s
        estimator.record_upload(edge, 1_000_000, Duration::from_secs(1));

        let metrics = estimator.get(&edge).unwrap();
        assert_eq!(metrics.upload_bps, 1_000_000.0);
        assert_eq!(metrics.download_bps, 0.0);
        assert_eq!(metrics.sample_count, 1);
        assert_eq!(metrics.peak_upload, 1_000_000.0);
    }

    #[test]
    fn test_bandwidth_record_download_first_sample() {
        let estimator = BandwidthEstimator::with_default_alpha();
        let edge = test_edge(1);

        // 5MB in 1 second = 5MB/s
        estimator.record_download(edge, 5_000_000, Duration::from_secs(1));

        let metrics = estimator.get(&edge).unwrap();
        assert_eq!(metrics.upload_bps, 0.0);
        assert_eq!(metrics.download_bps, 5_000_000.0);
        assert_eq!(metrics.sample_count, 1);
        assert_eq!(metrics.peak_download, 5_000_000.0);
    }

    #[test]
    fn test_bandwidth_ema_convergence() {
        let estimator = BandwidthEstimator::new(0.2); // alpha = 0.2
        let edge = test_edge(1);

        // First sample: 1MB/s
        estimator.record_upload(edge, 1_000_000, Duration::from_secs(1));
        let m1 = estimator.get(&edge).unwrap();
        assert_eq!(m1.upload_bps, 1_000_000.0);

        // Second sample: 2MB/s
        // EMA = 0.2 * 2_000_000 + 0.8 * 1_000_000 = 1_200_000
        estimator.record_upload(edge, 2_000_000, Duration::from_secs(1));
        let m2 = estimator.get(&edge).unwrap();
        assert_eq!(m2.upload_bps, 1_200_000.0);

        // Third sample: 2MB/s
        // EMA = 0.2 * 2_000_000 + 0.8 * 1_200_000 = 1_360_000
        estimator.record_upload(edge, 2_000_000, Duration::from_secs(1));
        let m3 = estimator.get(&edge).unwrap();
        assert_eq!(m3.upload_bps, 1_360_000.0);

        assert_eq!(m3.sample_count, 3);
    }

    #[test]
    fn test_bandwidth_peak_tracking() {
        let estimator = BandwidthEstimator::with_default_alpha();
        let edge = test_edge(1);

        estimator.record_upload(edge, 1_000_000, Duration::from_secs(1));
        estimator.record_upload(edge, 3_000_000, Duration::from_secs(1));
        estimator.record_upload(edge, 2_000_000, Duration::from_secs(1));

        let metrics = estimator.get(&edge).unwrap();
        assert_eq!(metrics.peak_upload, 3_000_000.0);

        estimator.record_download(edge, 4_000_000, Duration::from_secs(1));
        estimator.record_download(edge, 6_000_000, Duration::from_secs(1));
        estimator.record_download(edge, 5_000_000, Duration::from_secs(1));

        let metrics = estimator.get(&edge).unwrap();
        assert_eq!(metrics.peak_download, 6_000_000.0);
    }

    #[test]
    fn test_bandwidth_zero_duration_ignored() {
        let estimator = BandwidthEstimator::with_default_alpha();
        let edge = test_edge(1);

        estimator.record_upload(edge, 1_000_000, Duration::from_secs(0));
        assert!(estimator.get(&edge).is_none());

        estimator.record_download(edge, 1_000_000, Duration::from_secs(0));
        assert!(estimator.get(&edge).is_none());
    }

    #[test]
    fn test_bandwidth_estimate_upload_time() {
        let estimator = BandwidthEstimator::with_default_alpha();
        let edge = test_edge(1);

        // 1MB/s bandwidth
        estimator.record_upload(edge, 1_000_000, Duration::from_secs(1));

        // 2MB should take 2 seconds
        let time = estimator.estimate_upload_time(&edge, 2_000_000).unwrap();
        assert_eq!(time, Duration::from_secs(2));
    }

    #[test]
    fn test_bandwidth_estimate_download_time() {
        let estimator = BandwidthEstimator::with_default_alpha();
        let edge = test_edge(1);

        // 5MB/s bandwidth
        estimator.record_download(edge, 5_000_000, Duration::from_secs(1));

        // 10MB should take 2 seconds
        let time = estimator.estimate_download_time(&edge, 10_000_000).unwrap();
        assert_eq!(time, Duration::from_secs(2));
    }

    #[test]
    fn test_bandwidth_estimate_time_no_metrics() {
        let estimator = BandwidthEstimator::with_default_alpha();
        let edge = test_edge(1);

        assert!(estimator.estimate_upload_time(&edge, 1_000_000).is_none());
        assert!(estimator
            .estimate_download_time(&edge, 1_000_000)
            .is_none());
    }

    #[test]
    fn test_bandwidth_remove_edge() {
        let estimator = BandwidthEstimator::with_default_alpha();
        let edge = test_edge(1);

        estimator.record_upload(edge, 1_000_000, Duration::from_secs(1));
        assert!(estimator.get(&edge).is_some());

        estimator.remove(&edge);
        assert!(estimator.get(&edge).is_none());
    }

    #[test]
    fn test_bandwidth_multiple_edges() {
        let estimator = BandwidthEstimator::with_default_alpha();
        let edge1 = test_edge(1);
        let edge2 = test_edge(2);

        estimator.record_upload(edge1, 1_000_000, Duration::from_secs(1));
        estimator.record_upload(edge2, 2_000_000, Duration::from_secs(1));

        let m1 = estimator.get(&edge1).unwrap();
        let m2 = estimator.get(&edge2).unwrap();

        assert_eq!(m1.upload_bps, 1_000_000.0);
        assert_eq!(m2.upload_bps, 2_000_000.0);
    }

    #[test]
    fn test_bandwidth_mixed_upload_download() {
        let estimator = BandwidthEstimator::with_default_alpha();
        let edge = test_edge(1);

        estimator.record_upload(edge, 1_000_000, Duration::from_secs(1));
        assert_eq!(estimator.get(&edge).unwrap().sample_count, 1);

        estimator.record_download(edge, 5_000_000, Duration::from_secs(1));

        let metrics = estimator.get(&edge).unwrap();
        assert_eq!(metrics.upload_bps, 1_000_000.0);
        // download_bps = 0.2 * 5_000_000 + 0.8 * 0 = 1_000_000
        assert_eq!(metrics.download_bps, 1_000_000.0);
        assert_eq!(metrics.sample_count, 2);
    }

    #[test]
    fn test_bandwidth_sample_count_saturation() {
        let estimator = BandwidthEstimator::with_default_alpha();
        let edge = test_edge(1);

        // Record many samples
        for _ in 0..1000 {
            estimator.record_upload(edge, 1_000_000, Duration::from_secs(1));
        }

        let metrics = estimator.get(&edge).unwrap();
        assert_eq!(metrics.sample_count, 1000);
    }

    // RttEstimator Tests

    #[test]
    fn test_rtt_estimator_new() {
        let estimator = RttEstimator::new();
        assert!(estimator.metrics.is_empty());
    }

    #[test]
    fn test_rtt_estimator_default() {
        let estimator = RttEstimator::default();
        assert!(estimator.metrics.is_empty());
    }

    #[test]
    fn test_rtt_record_first_sample() {
        let estimator = RttEstimator::new();
        let edge = test_edge(1);

        estimator.record_rtt(edge, Duration::from_millis(100));

        let metrics = estimator.get(&edge).unwrap();
        assert_eq!(metrics.srtt_us, 100_000);
        assert_eq!(metrics.rttvar_us, 50_000); // RTT/2 for first sample
        assert_eq!(metrics.min_rtt_us, 100_000);
        assert_eq!(metrics.max_rtt_us, 100_000);
        assert_eq!(metrics.sample_count, 1);

        // RTO = SRTT + 4 * RTTVAR = 100_000 + 4 * 50_000 = 300_000 us
        assert_eq!(metrics.rto, Duration::from_micros(300_000));
    }

    #[test]
    fn test_rtt_record_multiple_samples() {
        let estimator = RttEstimator::new();
        let edge = test_edge(1);

        // First sample: 100ms
        estimator.record_rtt(edge, Duration::from_millis(100));

        // Second sample: 120ms
        estimator.record_rtt(edge, Duration::from_millis(120));

        let metrics = estimator.get(&edge).unwrap();

        // RTTVAR = (1-0.25) * 50_000 + 0.25 * |100_000 - 120_000|
        //        = 0.75 * 50_000 + 0.25 * 20_000
        //        = 37_500 + 5_000 = 42_500
        assert_eq!(metrics.rttvar_us, 42_500);

        // SRTT = (1-0.125) * 100_000 + 0.125 * 120_000
        //      = 0.875 * 100_000 + 0.125 * 120_000
        //      = 87_500 + 15_000 = 102_500
        assert_eq!(metrics.srtt_us, 102_500);

        // RTO = 102_500 + 4 * 42_500 = 272_500
        assert_eq!(metrics.rto, Duration::from_micros(272_500));
        assert_eq!(metrics.sample_count, 2);
    }

    #[test]
    fn test_rtt_min_max_tracking() {
        let estimator = RttEstimator::new();
        let edge = test_edge(1);

        estimator.record_rtt(edge, Duration::from_millis(100));
        estimator.record_rtt(edge, Duration::from_millis(150));
        estimator.record_rtt(edge, Duration::from_millis(80));

        let metrics = estimator.get(&edge).unwrap();
        assert_eq!(metrics.min_rtt_us, 80_000);
        assert_eq!(metrics.max_rtt_us, 150_000);
    }

    #[test]
    fn test_rtt_small_values() {
        let estimator = RttEstimator::new();
        let edge = test_edge(1);

        // Very small RTT: 1ms
        estimator.record_rtt(edge, Duration::from_millis(1));

        let metrics = estimator.get(&edge).unwrap();
        // RTO = 1000 + 4 * 500 = 3000 microseconds = 3ms
        assert_eq!(metrics.rto, Duration::from_micros(3000));
        assert_eq!(metrics.srtt_us, 1000);
    }

    #[test]
    fn test_rtt_convergence() {
        let estimator = RttEstimator::new();
        let edge = test_edge(1);

        // Record stable RTT samples
        for _ in 0..10 {
            estimator.record_rtt(edge, Duration::from_millis(50));
        }

        let metrics = estimator.get(&edge).unwrap();
        // SRTT should converge to 50ms
        assert!((metrics.srtt_us as f64 - 50_000.0).abs() < 1000.0);
        // RTTVAR should converge to near zero
        assert!(metrics.rttvar_us < 10_000);
        assert_eq!(metrics.sample_count, 10);
    }

    #[test]
    fn test_rtt_get_timeout() {
        let estimator = RttEstimator::new();
        let edge = test_edge(1);

        estimator.record_rtt(edge, Duration::from_millis(100));

        let timeout = estimator.get_timeout(&edge).unwrap();
        assert_eq!(timeout, Duration::from_micros(300_000));
    }

    #[test]
    fn test_rtt_get_srtt() {
        let estimator = RttEstimator::new();
        let edge = test_edge(1);

        estimator.record_rtt(edge, Duration::from_millis(100));

        let srtt = estimator.get_srtt(&edge).unwrap();
        assert_eq!(srtt, Duration::from_micros(100_000));
    }

    #[test]
    fn test_rtt_get_none_for_unknown_edge() {
        let estimator = RttEstimator::new();
        let edge = test_edge(1);

        assert!(estimator.get(&edge).is_none());
        assert!(estimator.get_timeout(&edge).is_none());
        assert!(estimator.get_srtt(&edge).is_none());
    }

    #[test]
    fn test_rtt_remove_edge() {
        let estimator = RttEstimator::new();
        let edge = test_edge(1);

        estimator.record_rtt(edge, Duration::from_millis(100));
        assert!(estimator.get(&edge).is_some());

        estimator.remove(&edge);
        assert!(estimator.get(&edge).is_none());
    }

    #[test]
    fn test_rtt_multiple_edges() {
        let estimator = RttEstimator::new();
        let edge1 = test_edge(1);
        let edge2 = test_edge(2);

        estimator.record_rtt(edge1, Duration::from_millis(50));
        estimator.record_rtt(edge2, Duration::from_millis(100));

        let m1 = estimator.get(&edge1).unwrap();
        let m2 = estimator.get(&edge2).unwrap();

        assert_eq!(m1.srtt_us, 50_000);
        assert_eq!(m2.srtt_us, 100_000);
    }

    #[test]
    fn test_rtt_variance_calculation() {
        let estimator = RttEstimator::new();
        let edge = test_edge(1);

        // First sample: 100ms
        estimator.record_rtt(edge, Duration::from_millis(100));
        let m1 = estimator.get(&edge).unwrap();
        assert_eq!(m1.rttvar_us, 50_000);

        // Second sample: same 100ms
        estimator.record_rtt(edge, Duration::from_millis(100));
        let m2 = estimator.get(&edge).unwrap();
        // RTTVAR = 0.75 * 50_000 + 0.25 * |100_000 - 100_000|
        //        = 0.75 * 50_000 + 0.25 * 0 = 37_500
        assert_eq!(m2.rttvar_us, 37_500);
    }

    // Concurrent Access Tests

    #[test]
    fn test_bandwidth_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let estimator = Arc::new(BandwidthEstimator::with_default_alpha());
        let mut handles = vec![];

        for i in 0..10 {
            let est = estimator.clone();
            let handle = thread::spawn(move || {
                let edge = test_edge(i);
                est.record_upload(edge, 1_000_000, Duration::from_secs(1));
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // All edges should have metrics
        for i in 0..10 {
            let edge = test_edge(i);
            assert!(estimator.get(&edge).is_some());
        }
    }

    #[test]
    fn test_rtt_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let estimator = Arc::new(RttEstimator::new());
        let mut handles = vec![];

        for i in 0..10 {
            let est = estimator.clone();
            let handle = thread::spawn(move || {
                let edge = test_edge(i);
                est.record_rtt(edge, Duration::from_millis(50));
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // All edges should have metrics
        for i in 0..10 {
            let edge = test_edge(i);
            assert!(estimator.get(&edge).is_some());
        }
    }

    // Serialization Tests

    #[test]
    fn test_bandwidth_metrics_serialize() {
        let metrics = BandwidthMetrics {
            // HOT
            upload_bps: 1_000_000.0,
            download_bps: 5_000_000.0,
            sample_count: 10,
            // COLD
            peak_upload: 1_500_000.0,
            peak_download: 6_000_000.0,
            last_updated: SystemTime::now(),
        };

        let json = serde_json::to_string(&metrics).unwrap();
        let deserialized: BandwidthMetrics = serde_json::from_str(&json).unwrap();

        assert_eq!(metrics.upload_bps, deserialized.upload_bps);
        assert_eq!(metrics.download_bps, deserialized.download_bps);
        assert_eq!(metrics.sample_count, deserialized.sample_count);
    }

    #[test]
    fn test_rtt_metrics_serialize() {
        let metrics = RttMetrics {
            // HOT
            srtt_us: 50_000,
            rttvar_us: 10_000,
            sample_count: 5,
            // WARM
            rto: Duration::from_millis(90),
            // COLD
            min_rtt_us: 40_000,
            max_rtt_us: 60_000,
            last_updated: SystemTime::now(),
        };

        let json = serde_json::to_string(&metrics).unwrap();
        let deserialized: RttMetrics = serde_json::from_str(&json).unwrap();

        assert_eq!(metrics.srtt_us, deserialized.srtt_us);
        assert_eq!(metrics.rttvar_us, deserialized.rttvar_us);
        assert_eq!(metrics.sample_count, deserialized.sample_count);
    }
}
