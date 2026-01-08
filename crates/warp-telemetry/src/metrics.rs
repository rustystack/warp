//! Performance metrics collection and export
//!
//! This module provides a comprehensive metrics system for collecting and exporting
//! performance data. It supports four metric types:
//!
//! - **Counter**: Monotonically increasing values (e.g., request counts)
//! - **Gauge**: Point-in-time values that can go up or down (e.g., memory usage)
//! - **Histogram**: Distribution of values across configurable buckets
//! - **Timer**: Specialized histogram for measuring durations
//!
//! # Example
//!
//! ```
//! use warp_telemetry::metrics::MetricRegistry;
//!
//! let registry = MetricRegistry::new();
//!
//! // Create and use a counter
//! let requests = registry.counter("http_requests_total", "Total HTTP requests");
//! requests.inc();
//!
//! // Create and use a gauge
//! let connections = registry.gauge("active_connections", "Current active connections");
//! connections.set(42.0);
//!
//! // Export to Prometheus format
//! let output = registry.export_prometheus();
//! ```

use chrono::Utc;
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Default latency buckets for timing histograms (in milliseconds).
///
/// These buckets cover a range from 1ms to 5000ms (5 seconds), suitable for
/// typical API latency measurements.
pub const LATENCY_BUCKETS: &[f64] = &[
    1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0,
];

/// Default size buckets for data size histograms (in bytes).
///
/// These buckets cover a range from 1KB to 1GB, suitable for measuring
/// request/response sizes or file sizes.
pub const SIZE_BUCKETS: &[f64] = &[
    1024.0,          // 1 KB
    10_240.0,        // 10 KB
    102_400.0,       // 100 KB
    1_048_576.0,     // 1 MB
    10_485_760.0,    // 10 MB
    104_857_600.0,   // 100 MB
    1_073_741_824.0, // 1 GB
];

/// The type of metric being collected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MetricType {
    /// A monotonically increasing counter (e.g., total requests).
    Counter,
    /// A point-in-time value that can increase or decrease (e.g., memory usage).
    Gauge,
    /// A distribution of values across buckets (e.g., request sizes).
    Histogram,
    /// A histogram specialized for timing measurements (e.g., latencies).
    Timer,
}

/// The value of a metric at a point in time.
///
/// Only one of `counter`, `gauge`, or `histogram` will be set, depending
/// on the metric type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricValue {
    /// Counter value (present for Counter metrics).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub counter: Option<u64>,
    /// Gauge value (present for Gauge metrics).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gauge: Option<f64>,
    /// Histogram data (present for Histogram and Timer metrics).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub histogram: Option<HistogramData>,
    /// Timestamp when this value was recorded (milliseconds since epoch).
    pub timestamp_ms: u64,
}

/// Statistical data from a histogram metric.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistogramData {
    /// Total number of observations recorded.
    pub count: u64,
    /// Sum of all observed values.
    pub sum: f64,
    /// Arithmetic mean of observed values.
    pub mean: f64,
    /// Bucket boundaries and cumulative counts as (`upper_bound`, count) pairs.
    pub buckets: Vec<(f64, u64)>,
}

/// A monotonically increasing counter metric.
///
/// Counters are useful for tracking events that only increase, such as
/// total requests, errors, or bytes transferred. They are thread-safe
/// and can be cloned to share the same underlying value.
///
/// # Example
///
/// ```
/// use warp_telemetry::metrics::Counter;
///
/// let counter = Counter::new("requests_total", "Total requests processed");
/// counter.inc();
/// counter.inc_by(5);
/// assert_eq!(counter.get(), 6);
/// ```
#[derive(Debug)]
pub struct Counter {
    name: String,
    description: String,
    value: Arc<AtomicU64>,
}

impl Counter {
    /// Creates a new counter with the given name and description.
    #[must_use]
    pub fn new(name: &str, description: &str) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            value: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Increments the counter by 1.
    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    /// Increments the counter by the specified amount.
    pub fn inc_by(&self, n: u64) {
        self.value.fetch_add(n, Ordering::Relaxed);
    }

    /// Returns the current counter value.
    #[must_use]
    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }

    /// Resets the counter to zero.
    pub fn reset(&self) {
        self.value.store(0, Ordering::Relaxed);
    }

    /// Returns the metric name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the metric description.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }
}

impl Clone for Counter {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            description: self.description.clone(),
            value: Arc::clone(&self.value),
        }
    }
}

/// A gauge metric that can increase or decrease.
///
/// Gauges represent a single numerical value that can go up or down,
/// such as current memory usage, active connections, or queue depth.
/// They are thread-safe and can be cloned to share the same underlying value.
///
/// # Example
///
/// ```
/// use warp_telemetry::metrics::Gauge;
///
/// let gauge = Gauge::new("memory_bytes", "Current memory usage in bytes");
/// gauge.set(1024.0);
/// gauge.inc_by(256.0);
/// gauge.dec_by(128.0);
/// assert_eq!(gauge.get(), 1152.0);
/// ```
#[derive(Debug)]
pub struct Gauge {
    name: String,
    description: String,
    value: Arc<RwLock<f64>>,
}

impl Gauge {
    /// Creates a new gauge with the given name and description.
    #[must_use]
    pub fn new(name: &str, description: &str) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            value: Arc::new(RwLock::new(0.0)),
        }
    }

    /// Sets the gauge to the specified value.
    pub fn set(&self, value: f64) {
        *self.value.write() = value;
    }

    /// Increments the gauge by 1.
    pub fn inc(&self) {
        *self.value.write() += 1.0;
    }

    /// Decrements the gauge by 1.
    pub fn dec(&self) {
        *self.value.write() -= 1.0;
    }

    /// Increments the gauge by the specified amount.
    pub fn inc_by(&self, n: f64) {
        *self.value.write() += n;
    }

    /// Decrements the gauge by the specified amount.
    pub fn dec_by(&self, n: f64) {
        *self.value.write() -= n;
    }

    /// Returns the current gauge value.
    #[must_use]
    pub fn get(&self) -> f64 {
        *self.value.read()
    }

    /// Returns the metric name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the metric description.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }
}

impl Clone for Gauge {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            description: self.description.clone(),
            value: Arc::clone(&self.value),
        }
    }
}

/// A histogram metric for tracking distributions of values.
///
/// Histograms track the distribution of observed values across configurable
/// buckets, along with sum, count, and percentile calculations. Useful for
/// measuring things like request sizes, response latencies, or batch sizes.
///
/// # Example
///
/// ```
/// use warp_telemetry::metrics::Histogram;
///
/// let hist = Histogram::new("request_size", "Request size in bytes", vec![100.0, 1000.0, 10000.0]);
/// hist.observe(50.0);
/// hist.observe(500.0);
/// hist.observe(5000.0);
/// assert_eq!(hist.count(), 3);
/// ```
#[derive(Debug)]
pub struct Histogram {
    name: String,
    description: String,
    inner: Arc<RwLock<HistogramInner>>,
}

/// Internal histogram state.
#[derive(Debug)]
struct HistogramInner {
    /// Sorted bucket upper bounds.
    buckets: Vec<f64>,
    /// Cumulative counts for each bucket.
    bucket_counts: Vec<AtomicU64>,
    /// All observed samples (for percentile calculation).
    samples: Vec<f64>,
    /// Sum of all observed values.
    sum: f64,
    /// Total observation count.
    count: u64,
}

impl Histogram {
    /// Creates a new histogram with the given name, description, and bucket boundaries.
    ///
    /// Buckets will be sorted automatically. Each bucket represents an upper bound,
    /// and values are counted in all buckets they fall into (cumulative).
    #[must_use]
    pub fn new(name: &str, description: &str, buckets: Vec<f64>) -> Self {
        let mut sorted_buckets = buckets;
        sorted_buckets.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let bucket_counts: Vec<AtomicU64> =
            sorted_buckets.iter().map(|_| AtomicU64::new(0)).collect();
        Self {
            name: name.to_string(),
            description: description.to_string(),
            inner: Arc::new(RwLock::new(HistogramInner {
                buckets: sorted_buckets,
                bucket_counts,
                samples: Vec::new(),
                sum: 0.0,
                count: 0,
            })),
        }
    }

    /// Records an observation in the histogram.
    pub fn observe(&self, value: f64) {
        let mut inner = self.inner.write();
        inner.samples.push(value);
        inner.sum += value;
        inner.count += 1;
        for (i, &bucket) in inner.buckets.iter().enumerate() {
            if value <= bucket {
                inner.bucket_counts[i].fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Returns the total number of observations.
    #[must_use]
    pub fn count(&self) -> u64 {
        self.inner.read().count
    }

    /// Returns the sum of all observed values.
    #[must_use]
    pub fn sum(&self) -> f64 {
        self.inner.read().sum
    }

    /// Returns the arithmetic mean of observed values.
    #[must_use]
    pub fn mean(&self) -> f64 {
        let inner = self.inner.read();
        if inner.count == 0 {
            0.0
        } else {
            #[allow(clippy::cast_precision_loss)]
            let count_f64 = inner.count as f64;
            inner.sum / count_f64
        }
    }

    /// Calculates the specified percentile (0-100) from observed values.
    ///
    /// Returns 0.0 if no observations have been recorded.
    #[must_use]
    pub fn percentile(&self, p: f64) -> f64 {
        // Filter out NaN values before sorting to prevent unpredictable ordering
        let mut sorted: Vec<f64> = {
            let inner = self.inner.read();
            if inner.samples.is_empty() {
                return 0.0;
            }
            inner
                .samples
                .iter()
                .copied()
                .filter(|x| !x.is_nan())
                .collect()
        }; // inner is dropped here

        if sorted.is_empty() {
            return 0.0;
        }

        // Use total_cmp for deterministic ordering (handles infinities correctly)
        sorted.sort_by(f64::total_cmp);

        #[allow(clippy::cast_precision_loss)]
        let len_f64 = (sorted.len() - 1) as f64;
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let index = (p / 100.0 * len_f64).round() as usize;
        sorted[index.min(sorted.len() - 1)]
    }

    /// Returns bucket boundaries and their cumulative counts.
    #[must_use]
    pub fn buckets(&self) -> Vec<(f64, u64)> {
        let inner = self.inner.read();
        inner
            .buckets
            .iter()
            .enumerate()
            .map(|(i, &bucket)| (bucket, inner.bucket_counts[i].load(Ordering::Relaxed)))
            .collect()
    }

    /// Returns the metric name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the metric description.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }
}

impl Clone for Histogram {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            description: self.description.clone(),
            inner: Arc::clone(&self.inner),
        }
    }
}

/// A timer metric for measuring durations.
///
/// Timer wraps a histogram with predefined latency buckets, providing
/// convenient methods for measuring operation durations. Supports both
/// manual recording and RAII-style timing with guards.
///
/// # Example
///
/// ```
/// use warp_telemetry::metrics::Timer;
/// use std::time::Duration;
///
/// let timer = Timer::new("request_duration", "Request processing time");
///
/// // Manual recording
/// timer.record(Duration::from_millis(50));
///
/// // RAII-style timing
/// {
///     let _guard = timer.start();
///     // ... do work ...
/// } // Duration recorded automatically when guard drops
/// ```
#[derive(Debug)]
pub struct Timer {
    histogram: Histogram,
}

impl Timer {
    /// Creates a new timer with the given name and description.
    ///
    /// Uses [`LATENCY_BUCKETS`] as the default bucket configuration.
    #[must_use]
    pub fn new(name: &str, description: &str) -> Self {
        Self {
            histogram: Histogram::new(name, description, LATENCY_BUCKETS.to_vec()),
        }
    }

    /// Starts timing and returns a guard that records duration when dropped.
    #[must_use]
    pub fn start(&self) -> TimerGuard {
        TimerGuard {
            histogram: self.histogram.clone(),
            start: Instant::now(),
            stopped: false,
        }
    }

    /// Records a duration directly.
    pub fn record(&self, duration: Duration) {
        self.histogram.observe(duration.as_secs_f64() * 1000.0);
    }

    /// Records a duration in milliseconds.
    pub fn observe_ms(&self, ms: u64) {
        #[allow(clippy::cast_precision_loss)]
        let ms_f64 = ms as f64;
        self.histogram.observe(ms_f64);
    }

    /// Returns the metric name.
    #[must_use]
    pub fn name(&self) -> &str {
        self.histogram.name()
    }

    /// Returns the metric description.
    #[must_use]
    pub fn description(&self) -> &str {
        self.histogram.description()
    }

    /// Returns the underlying histogram for advanced access.
    #[must_use]
    pub const fn histogram(&self) -> &Histogram {
        &self.histogram
    }
}

impl Clone for Timer {
    fn clone(&self) -> Self {
        Self {
            histogram: self.histogram.clone(),
        }
    }
}

/// A guard that records timing when dropped.
///
/// Created by [`Timer::start()`]. The duration from creation to drop is
/// automatically recorded in the timer's histogram.
pub struct TimerGuard {
    histogram: Histogram,
    start: Instant,
    stopped: bool,
}

impl TimerGuard {
    /// Stops the timer and returns the elapsed duration.
    ///
    /// Calling this method records the duration immediately and prevents
    /// the Drop implementation from recording again.
    #[must_use]
    pub fn stop(mut self) -> Duration {
        self.stopped = true;
        let duration = self.start.elapsed();
        self.histogram.observe(duration.as_secs_f64() * 1000.0);
        duration
    }
}

impl Drop for TimerGuard {
    fn drop(&mut self) {
        if !self.stopped {
            let duration = self.start.elapsed();
            self.histogram.observe(duration.as_secs_f64() * 1000.0);
        }
    }
}

/// A collection of key-value labels for metric dimensions.
///
/// Labels allow metrics to be tagged with additional context, such as
/// HTTP method, status code, or service name. Supports builder-style
/// construction.
///
/// # Example
///
/// ```
/// use warp_telemetry::metrics::Labels;
///
/// let labels = Labels::new()
///     .add("method", "GET")
///     .add("status", "200");
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Labels {
    labels: HashMap<String, String>,
}

impl Labels {
    /// Creates an empty label set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            labels: HashMap::new(),
        }
    }

    /// Adds a label and returns self for chaining.
    #[must_use]
    pub fn add(mut self, key: &str, value: &str) -> Self {
        self.labels.insert(key.to_string(), value.to_string());
        self
    }

    /// Returns the labels as a `HashMap` reference.
    #[must_use]
    pub const fn as_map(&self) -> &HashMap<String, String> {
        &self.labels
    }
}

impl std::fmt::Display for Labels {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut pairs: Vec<_> = self.labels.iter().collect();
        pairs.sort_by_key(|(k, _)| *k);
        let formatted: Vec<String> = pairs.iter().map(|(k, v)| format!("{k}={v}")).collect();
        write!(f, "{}", formatted.join(","))
    }
}

/// A point-in-time snapshot of a metric's state.
///
/// Used for exporting metric data to monitoring systems.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricSnapshot {
    /// The metric name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// The type of metric.
    pub metric_type: MetricType,
    /// The current metric value.
    pub value: MetricValue,
    /// Associated labels/dimensions.
    pub labels: HashMap<String, String>,
    /// Timestamp when snapshot was taken (milliseconds since epoch).
    pub timestamp_ms: u64,
}

/// A registry for managing and exporting metrics.
///
/// The registry provides a central location for creating and accessing
/// metrics, ensuring that metrics with the same name share the same
/// underlying storage. Supports export to Prometheus and JSON formats.
///
/// # Example
///
/// ```
/// use warp_telemetry::metrics::MetricRegistry;
///
/// let registry = MetricRegistry::new();
/// let counter = registry.counter("requests", "Total requests");
/// counter.inc();
///
/// // Export to Prometheus format
/// let prometheus_output = registry.export_prometheus();
///
/// // Export to JSON
/// let json_output = registry.export_json();
/// ```
#[derive(Debug)]
pub struct MetricRegistry {
    metrics: DashMap<String, MetricEntry>,
}

/// Internal storage for different metric types.
#[derive(Debug)]
enum MetricEntry {
    /// A counter metric entry.
    Counter(Counter),
    /// A gauge metric entry.
    Gauge(Gauge),
    /// A histogram metric entry.
    Histogram(Histogram),
    /// A timer metric entry.
    Timer(Timer),
}

impl MetricRegistry {
    /// Creates a new empty metric registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            metrics: DashMap::new(),
        }
    }

    /// Returns the global singleton metric registry.
    ///
    /// This is useful for application-wide metrics that need to be
    /// accessible from multiple modules.
    pub fn global() -> &'static Self {
        static INSTANCE: std::sync::OnceLock<MetricRegistry> = std::sync::OnceLock::new();
        INSTANCE.get_or_init(Self::new)
    }

    /// Gets or creates a counter metric.
    ///
    /// If a metric with the same name already exists, returns the existing
    /// counter.
    ///
    /// # Panics
    ///
    /// Panics if a metric with the same name but different type exists.
    #[must_use]
    pub fn counter(&self, name: &str, description: &str) -> Counter {
        let entry = self
            .metrics
            .entry(name.to_string())
            .or_insert_with(|| MetricEntry::Counter(Counter::new(name, description)));
        match entry.value() {
            MetricEntry::Counter(c) => c.clone(),
            _ => panic!("Metric {name} already exists with different type"),
        }
    }

    /// Gets or creates a gauge metric.
    ///
    /// If a metric with the same name already exists, returns the existing
    /// gauge.
    ///
    /// # Panics
    ///
    /// Panics if a metric with the same name but different type exists.
    #[must_use]
    pub fn gauge(&self, name: &str, description: &str) -> Gauge {
        let entry = self
            .metrics
            .entry(name.to_string())
            .or_insert_with(|| MetricEntry::Gauge(Gauge::new(name, description)));
        match entry.value() {
            MetricEntry::Gauge(g) => g.clone(),
            _ => panic!("Metric {name} already exists with different type"),
        }
    }

    /// Gets or creates a histogram metric.
    ///
    /// If a metric with the same name already exists, returns the existing
    /// histogram.
    ///
    /// # Panics
    ///
    /// Panics if a metric with the same name but different type exists.
    #[must_use]
    pub fn histogram(&self, name: &str, description: &str, buckets: Vec<f64>) -> Histogram {
        let entry = self
            .metrics
            .entry(name.to_string())
            .or_insert_with(|| MetricEntry::Histogram(Histogram::new(name, description, buckets)));
        match entry.value() {
            MetricEntry::Histogram(h) => h.clone(),
            _ => panic!("Metric {name} already exists with different type"),
        }
    }

    /// Gets or creates a timer metric.
    ///
    /// If a metric with the same name already exists, returns the existing
    /// timer.
    ///
    /// # Panics
    ///
    /// Panics if a metric with the same name but different type exists.
    #[must_use]
    pub fn timer(&self, name: &str, description: &str) -> Timer {
        let entry = self
            .metrics
            .entry(name.to_string())
            .or_insert_with(|| MetricEntry::Timer(Timer::new(name, description)));
        match entry.value() {
            MetricEntry::Timer(t) => t.clone(),
            _ => panic!("Metric {name} already exists with different type"),
        }
    }

    /// Returns snapshots of all registered metrics.
    #[must_use]
    pub fn get_all_metrics(&self) -> Vec<MetricSnapshot> {
        #[allow(clippy::cast_sign_loss)]
        let timestamp_ms = Utc::now().timestamp_millis() as u64;
        let mut snapshots = Vec::new();
        for entry in &self.metrics {
            let snapshot = match entry.value() {
                MetricEntry::Counter(c) => MetricSnapshot {
                    name: c.name().to_string(),
                    description: c.description().to_string(),
                    metric_type: MetricType::Counter,
                    value: MetricValue {
                        counter: Some(c.get()),
                        gauge: None,
                        histogram: None,
                        timestamp_ms,
                    },
                    labels: HashMap::new(),
                    timestamp_ms,
                },
                MetricEntry::Gauge(g) => MetricSnapshot {
                    name: g.name().to_string(),
                    description: g.description().to_string(),
                    metric_type: MetricType::Gauge,
                    value: MetricValue {
                        counter: None,
                        gauge: Some(g.get()),
                        histogram: None,
                        timestamp_ms,
                    },
                    labels: HashMap::new(),
                    timestamp_ms,
                },
                MetricEntry::Histogram(h) => MetricSnapshot {
                    name: h.name().to_string(),
                    description: h.description().to_string(),
                    metric_type: MetricType::Histogram,
                    value: MetricValue {
                        counter: None,
                        gauge: None,
                        histogram: Some(HistogramData {
                            count: h.count(),
                            sum: h.sum(),
                            mean: h.mean(),
                            buckets: h.buckets(),
                        }),
                        timestamp_ms,
                    },
                    labels: HashMap::new(),
                    timestamp_ms,
                },
                MetricEntry::Timer(t) => {
                    let h = t.histogram();
                    MetricSnapshot {
                        name: h.name().to_string(),
                        description: h.description().to_string(),
                        metric_type: MetricType::Timer,
                        value: MetricValue {
                            counter: None,
                            gauge: None,
                            histogram: Some(HistogramData {
                                count: h.count(),
                                sum: h.sum(),
                                mean: h.mean(),
                                buckets: h.buckets(),
                            }),
                            timestamp_ms,
                        },
                        labels: HashMap::new(),
                        timestamp_ms,
                    }
                }
            };
            snapshots.push(snapshot);
        }
        snapshots
    }

    /// Exports all metrics in Prometheus text format.
    ///
    /// The output follows the Prometheus exposition format and can be
    /// scraped by Prometheus or compatible monitoring systems.
    #[must_use]
    pub fn export_prometheus(&self) -> String {
        use std::fmt::Write;
        let mut output = String::new();
        for entry in &self.metrics {
            match entry.value() {
                MetricEntry::Counter(c) => {
                    let _ = writeln!(output, "# HELP {} {}", c.name(), c.description());
                    let _ = writeln!(output, "# TYPE {} counter", c.name());
                    let _ = writeln!(output, "{} {}", c.name(), c.get());
                }
                MetricEntry::Gauge(g) => {
                    let _ = writeln!(output, "# HELP {} {}", g.name(), g.description());
                    let _ = writeln!(output, "# TYPE {} gauge", g.name());
                    let _ = writeln!(output, "{} {}", g.name(), g.get());
                }
                MetricEntry::Histogram(h) => {
                    let _ = writeln!(output, "# HELP {} {}", h.name(), h.description());
                    let _ = writeln!(output, "# TYPE {} histogram", h.name());
                    for (bucket, count) in h.buckets() {
                        let _ =
                            writeln!(output, "{}_bucket{{le=\"{}\"}} {}", h.name(), bucket, count);
                    }
                    let _ = writeln!(output, "{}_bucket{{le=\"+Inf\"}} {}", h.name(), h.count());
                    let _ = writeln!(output, "{}_sum {}", h.name(), h.sum());
                    let _ = writeln!(output, "{}_count {}", h.name(), h.count());
                }
                MetricEntry::Timer(t) => {
                    let h = t.histogram();
                    let _ = writeln!(output, "# HELP {} {}", h.name(), h.description());
                    let _ = writeln!(output, "# TYPE {} histogram", h.name());
                    for (bucket, count) in h.buckets() {
                        let _ =
                            writeln!(output, "{}_bucket{{le=\"{}\"}} {}", h.name(), bucket, count);
                    }
                    let _ = writeln!(output, "{}_bucket{{le=\"+Inf\"}} {}", h.name(), h.count());
                    let _ = writeln!(output, "{}_sum {}", h.name(), h.sum());
                    let _ = writeln!(output, "{}_count {}", h.name(), h.count());
                }
            }
            output.push('\n');
        }
        output
    }

    /// Exports all metrics as a JSON array of snapshots.
    ///
    /// Returns pretty-printed JSON suitable for APIs or debugging.
    #[must_use]
    pub fn export_json(&self) -> String {
        let snapshots = self.get_all_metrics();
        serde_json::to_string_pretty(&snapshots).unwrap_or_default()
    }
}

impl Default for MetricRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration as StdDuration;

    #[test]
    fn test_metric_type_variants() {
        assert_eq!(MetricType::Counter, MetricType::Counter);
        assert_ne!(MetricType::Counter, MetricType::Gauge);
    }

    #[test]
    fn test_counter_creation() {
        let counter = Counter::new("test_counter", "Test counter description");
        assert_eq!(counter.name(), "test_counter");
        assert_eq!(counter.description(), "Test counter description");
        assert_eq!(counter.get(), 0);
    }

    #[test]
    fn test_counter_increment() {
        let counter = Counter::new("test", "desc");
        counter.inc();
        assert_eq!(counter.get(), 1);
        counter.inc();
        assert_eq!(counter.get(), 2);
    }

    #[test]
    fn test_counter_increment_by() {
        let counter = Counter::new("test", "desc");
        counter.inc_by(5);
        assert_eq!(counter.get(), 5);
        counter.inc_by(10);
        assert_eq!(counter.get(), 15);
    }

    #[test]
    fn test_counter_reset() {
        let counter = Counter::new("test", "desc");
        counter.inc_by(100);
        assert_eq!(counter.get(), 100);
        counter.reset();
        assert_eq!(counter.get(), 0);
    }

    #[test]
    fn test_counter_thread_safety() {
        let counter = Counter::new("test", "desc");
        let c1 = counter.clone();
        let c2 = counter.clone();
        let h1 = thread::spawn(move || {
            for _ in 0..1000 {
                c1.inc();
            }
        });
        let h2 = thread::spawn(move || {
            for _ in 0..1000 {
                c2.inc();
            }
        });
        h1.join().unwrap();
        h2.join().unwrap();
        assert_eq!(counter.get(), 2000);
    }

    #[test]
    fn test_gauge_creation() {
        let gauge = Gauge::new("test_gauge", "Test gauge description");
        assert_eq!(gauge.name(), "test_gauge");
        assert_eq!(gauge.description(), "Test gauge description");
        assert_eq!(gauge.get(), 0.0);
    }

    #[test]
    fn test_gauge_set() {
        let gauge = Gauge::new("test", "desc");
        gauge.set(42.5);
        assert_eq!(gauge.get(), 42.5);
    }

    #[test]
    fn test_gauge_inc_dec() {
        let gauge = Gauge::new("test", "desc");
        gauge.inc();
        assert_eq!(gauge.get(), 1.0);
        gauge.dec();
        assert_eq!(gauge.get(), 0.0);
    }

    #[test]
    fn test_gauge_inc_by_dec_by() {
        let gauge = Gauge::new("test", "desc");
        gauge.inc_by(5.5);
        assert_eq!(gauge.get(), 5.5);
        gauge.dec_by(2.5);
        assert_eq!(gauge.get(), 3.0);
    }

    #[test]
    fn test_gauge_negative_values() {
        let gauge = Gauge::new("test", "desc");
        gauge.set(-10.0);
        assert_eq!(gauge.get(), -10.0);
    }

    #[test]
    fn test_histogram_creation() {
        let buckets = vec![1.0, 5.0, 10.0];
        let hist = Histogram::new("test_hist", "Test histogram", buckets);
        assert_eq!(hist.name(), "test_hist");
        assert_eq!(hist.count(), 0);
    }

    #[test]
    fn test_histogram_observe() {
        let buckets = vec![10.0, 20.0, 30.0];
        let hist = Histogram::new("test", "desc", buckets);
        hist.observe(5.0);
        assert_eq!(hist.count(), 1);
        hist.observe(15.0);
        assert_eq!(hist.count(), 2);
    }

    #[test]
    fn test_histogram_count_and_sum() {
        let buckets = vec![10.0, 20.0, 30.0];
        let hist = Histogram::new("test", "desc", buckets);
        hist.observe(5.0);
        hist.observe(15.0);
        hist.observe(25.0);
        assert_eq!(hist.count(), 3);
        assert_eq!(hist.sum(), 45.0);
    }

    #[test]
    fn test_histogram_mean() {
        let buckets = vec![10.0, 20.0, 30.0];
        let hist = Histogram::new("test", "desc", buckets);
        assert_eq!(hist.mean(), 0.0);
        hist.observe(10.0);
        hist.observe(20.0);
        hist.observe(30.0);
        assert_eq!(hist.mean(), 20.0);
    }

    #[test]
    fn test_histogram_percentile_p50() {
        let buckets = vec![100.0];
        let hist = Histogram::new("test", "desc", buckets);
        for i in 1..=100 {
            hist.observe(i as f64);
        }
        let p50 = hist.percentile(50.0);
        assert!((p50 - 50.0).abs() < 2.0);
    }

    #[test]
    fn test_histogram_percentile_p90() {
        let buckets = vec![100.0];
        let hist = Histogram::new("test", "desc", buckets);
        for i in 1..=100 {
            hist.observe(i as f64);
        }
        let p90 = hist.percentile(90.0);
        assert!((p90 - 90.0).abs() < 2.0);
    }

    #[test]
    fn test_histogram_percentile_p99() {
        let buckets = vec![100.0];
        let hist = Histogram::new("test", "desc", buckets);
        for i in 1..=100 {
            hist.observe(i as f64);
        }
        let p99 = hist.percentile(99.0);
        assert!((p99 - 99.0).abs() < 2.0);
    }

    #[test]
    fn test_histogram_bucket_counts() {
        let buckets = vec![10.0, 20.0, 30.0];
        let hist = Histogram::new("test", "desc", buckets);
        hist.observe(5.0);
        hist.observe(15.0);
        hist.observe(25.0);
        hist.observe(35.0);
        let bucket_counts = hist.buckets();
        assert_eq!(bucket_counts.len(), 3);
        assert_eq!(bucket_counts[0], (10.0, 1));
        assert_eq!(bucket_counts[1], (20.0, 2));
        assert_eq!(bucket_counts[2], (30.0, 3));
    }

    #[test]
    fn test_timer_creation() {
        let timer = Timer::new("test_timer", "Test timer");
        assert_eq!(timer.name(), "test_timer");
    }

    #[test]
    fn test_timer_start_stop() {
        let timer = Timer::new("test", "desc");
        let guard = timer.start();
        thread::sleep(StdDuration::from_millis(10));
        let duration = guard.stop();
        assert!(duration.as_millis() >= 10);
        assert_eq!(timer.histogram().count(), 1);
    }

    #[test]
    fn test_timer_guard_auto_record() {
        let timer = Timer::new("test", "desc");
        {
            let _guard = timer.start();
            thread::sleep(StdDuration::from_millis(10));
        }
        assert_eq!(timer.histogram().count(), 1);
    }

    #[test]
    fn test_timer_record_duration() {
        let timer = Timer::new("test", "desc");
        timer.record(StdDuration::from_millis(100));
        assert_eq!(timer.histogram().count(), 1);
        let mean = timer.histogram().mean();
        assert!((mean - 100.0).abs() < 1.0);
    }

    #[test]
    fn test_timer_observe_ms() {
        let timer = Timer::new("test", "desc");
        timer.observe_ms(250);
        assert_eq!(timer.histogram().count(), 1);
        assert_eq!(timer.histogram().mean(), 250.0);
    }

    #[test]
    fn test_labels_creation() {
        let labels = Labels::new();
        assert!(labels.as_map().is_empty());
    }

    #[test]
    fn test_labels_add() {
        let labels = Labels::new().add("key1", "value1").add("key2", "value2");
        assert_eq!(labels.as_map().len(), 2);
        assert_eq!(labels.as_map().get("key1"), Some(&"value1".to_string()));
    }

    #[test]
    fn test_labels_formatting() {
        let labels = Labels::new().add("method", "GET").add("status", "200");
        let formatted = labels.to_string();
        assert!(formatted.contains("method=GET"));
        assert!(formatted.contains("status=200"));
    }

    #[test]
    fn test_metric_registry_creation() {
        let registry = MetricRegistry::new();
        assert_eq!(registry.get_all_metrics().len(), 0);
    }

    #[test]
    fn test_metric_registry_counter() {
        let registry = MetricRegistry::new();
        let counter = registry.counter("test_counter", "desc");
        counter.inc();
        let counter2 = registry.counter("test_counter", "desc");
        assert_eq!(counter2.get(), 1);
    }

    #[test]
    fn test_metric_registry_gauge() {
        let registry = MetricRegistry::new();
        let gauge = registry.gauge("test_gauge", "desc");
        gauge.set(42.0);
        let gauge2 = registry.gauge("test_gauge", "desc");
        assert_eq!(gauge2.get(), 42.0);
    }

    #[test]
    fn test_metric_registry_histogram() {
        let registry = MetricRegistry::new();
        let hist = registry.histogram("test_hist", "desc", vec![10.0, 20.0]);
        hist.observe(15.0);
        let hist2 = registry.histogram("test_hist", "desc", vec![10.0, 20.0]);
        assert_eq!(hist2.count(), 1);
    }

    #[test]
    fn test_metric_registry_timer() {
        let registry = MetricRegistry::new();
        let timer = registry.timer("test_timer", "desc");
        timer.observe_ms(100);
        let timer2 = registry.timer("test_timer", "desc");
        assert_eq!(timer2.histogram().count(), 1);
    }

    #[test]
    fn test_metric_registry_get_all_metrics() {
        let registry = MetricRegistry::new();
        let counter = registry.counter("counter1", "desc");
        counter.inc_by(5);
        let gauge = registry.gauge("gauge1", "desc");
        gauge.set(42.0);
        let snapshots = registry.get_all_metrics();
        assert_eq!(snapshots.len(), 2);
    }

    #[test]
    fn test_prometheus_export_counter() {
        let registry = MetricRegistry::new();
        let counter = registry.counter("http_requests_total", "Total HTTP requests");
        counter.inc_by(100);
        let output = registry.export_prometheus();
        assert!(output.contains("# HELP http_requests_total Total HTTP requests"));
        assert!(output.contains("# TYPE http_requests_total counter"));
        assert!(output.contains("http_requests_total 100"));
    }

    #[test]
    fn test_prometheus_export_gauge() {
        let registry = MetricRegistry::new();
        let gauge = registry.gauge("memory_usage", "Memory usage in bytes");
        gauge.set(1024.0);
        let output = registry.export_prometheus();
        assert!(output.contains("# HELP memory_usage Memory usage in bytes"));
        assert!(output.contains("# TYPE memory_usage gauge"));
        assert!(output.contains("memory_usage 1024"));
    }

    #[test]
    fn test_prometheus_export_histogram() {
        let registry = MetricRegistry::new();
        let hist = registry.histogram(
            "request_duration",
            "Request duration",
            vec![10.0, 50.0, 100.0],
        );
        hist.observe(25.0);
        hist.observe(75.0);
        let output = registry.export_prometheus();
        assert!(output.contains("# HELP request_duration Request duration"));
        assert!(output.contains("# TYPE request_duration histogram"));
        // Check for bucket with le=10 (formatting may vary)
        assert!(output.contains("request_duration_bucket{le=\"10"));
        assert!(output.contains("request_duration_count 2"));
    }

    #[test]
    fn test_json_export() {
        let registry = MetricRegistry::new();
        let counter = registry.counter("test_counter", "desc");
        counter.inc_by(10);
        let json = registry.export_json();
        assert!(json.contains("test_counter"));
        // JSON pretty print adds spaces, check for the value presence
        assert!(json.contains("\"counter\"") && json.contains("10"));
    }

    #[test]
    fn test_metric_snapshot_creation() {
        let snapshot = MetricSnapshot {
            name: "test".to_string(),
            description: "desc".to_string(),
            metric_type: MetricType::Counter,
            value: MetricValue {
                counter: Some(42),
                gauge: None,
                histogram: None,
                timestamp_ms: 1000,
            },
            labels: HashMap::new(),
            timestamp_ms: 1000,
        };
        assert_eq!(snapshot.name, "test");
        assert_eq!(snapshot.value.counter, Some(42));
    }

    #[test]
    fn test_default_latency_buckets() {
        assert_eq!(LATENCY_BUCKETS.len(), 11);
        assert_eq!(LATENCY_BUCKETS[0], 1.0);
        assert_eq!(LATENCY_BUCKETS[10], 5000.0);
    }

    #[test]
    fn test_default_size_buckets() {
        assert_eq!(SIZE_BUCKETS.len(), 7);
        assert_eq!(SIZE_BUCKETS[0], 1024.0);
        assert_eq!(SIZE_BUCKETS[6], 1073741824.0);
    }

    #[test]
    #[should_panic(expected = "already exists with different type")]
    fn test_metric_registry_type_conflict() {
        let registry = MetricRegistry::new();
        let _counter = registry.counter("test", "desc");
        let _gauge = registry.gauge("test", "desc");
    }

    #[test]
    fn test_histogram_empty_percentile() {
        let hist = Histogram::new("test", "desc", vec![10.0]);
        assert_eq!(hist.percentile(50.0), 0.0);
    }

    #[test]
    fn test_gauge_thread_safety() {
        let gauge = Gauge::new("test", "desc");
        let g1 = gauge.clone();
        let g2 = gauge.clone();
        let h1 = thread::spawn(move || {
            for _ in 0..100 {
                g1.inc();
            }
        });
        let h2 = thread::spawn(move || {
            for _ in 0..100 {
                g2.inc();
            }
        });
        h1.join().unwrap();
        h2.join().unwrap();
        assert_eq!(gauge.get(), 200.0);
    }

    #[test]
    fn test_histogram_sorted_buckets() {
        let buckets = vec![100.0, 10.0, 50.0];
        let hist = Histogram::new("test", "desc", buckets);
        hist.observe(25.0);
        let bucket_counts = hist.buckets();
        assert!(bucket_counts[0].0 < bucket_counts[1].0);
        assert!(bucket_counts[1].0 < bucket_counts[2].0);
    }

    #[test]
    fn test_counter_clone() {
        let counter = Counter::new("test", "desc");
        counter.inc_by(5);
        let cloned = counter.clone();
        assert_eq!(cloned.get(), 5);
        cloned.inc();
        assert_eq!(counter.get(), 6);
    }

    #[test]
    fn test_metric_value_timestamp() {
        let value = MetricValue {
            counter: Some(100),
            gauge: None,
            histogram: None,
            timestamp_ms: 12345,
        };
        assert_eq!(value.timestamp_ms, 12345);
    }

    #[test]
    fn test_global_registry() {
        let registry1 = MetricRegistry::global();
        let counter = registry1.counter("global_test", "desc");
        counter.inc();
        let registry2 = MetricRegistry::global();
        let counter2 = registry2.counter("global_test", "desc");
        assert_eq!(counter2.get(), 1);
    }

    #[test]
    fn test_histogram_percentile_edge_cases() {
        let hist = Histogram::new("test", "desc", vec![100.0]);
        hist.observe(50.0);
        assert_eq!(hist.percentile(0.0), 50.0);
        assert_eq!(hist.percentile(100.0), 50.0);
    }

    #[test]
    fn test_labels_empty_formatting() {
        let labels = Labels::new();
        assert_eq!(labels.to_string(), "");
    }
}
