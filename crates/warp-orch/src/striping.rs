//! Single-Stream Bandwidth Aggregation via Sub-Chunk Striping
//!
//! This module enables a single large transfer to exceed single-NIC throughput
//! by striping data across multiple network paths.
//!
//! # Architecture
//!
//! ```text
//! 1GB Read Request
//!        ↓
//! ┌──────────────────────┐
//! │   Stripe Splitter    │  Split into 512KB stripes
//! └──────────────────────┘
//!        ↓
//! ┌───────┬───────┬───────┬───────┐
//! │Stripe0│Stripe1│Stripe2│Stripe3│ ...
//! │Path A │Path B │Path A │Path B │  Round-robin or weighted
//! └───────┴───────┴───────┴───────┘
//!        ↓
//! ┌──────────────────────┐
//! │  Reassembly Buffer   │  Reorder by stripe index
//! └──────────────────────┘
//!        ↓
//!     Sequential Output
//! ```
//!
//! # Key Features
//!
//! - **Sub-chunk striping**: Split large transfers into smaller stripes
//! - **Multi-path distribution**: Send stripes over different network paths
//! - **Out-of-order reassembly**: Handle stripes arriving out of order
//! - **Head-of-line blocking mitigation**: Timeout and re-request stalled stripes

use bytes::Bytes;
use portal_net::types::PathId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Unique identifier for a striped transfer
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TransferId(pub u64);

impl TransferId {
    /// Generate a new unique transfer ID
    ///
    /// Uses a combination of timestamp and counter to ensure uniqueness
    /// even when generated in rapid succession.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::{SystemTime, UNIX_EPOCH};

        static COUNTER: AtomicU64 = AtomicU64::new(0);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        // Combine timestamp with counter to ensure uniqueness
        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        Self(timestamp.wrapping_add(counter))
    }
}

impl Default for TransferId {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration for sub-chunk striping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripingConfig {
    /// Minimum transfer size to enable striping (bytes)
    ///
    /// Transfers smaller than this use single-path.
    /// Default: 10MB
    pub min_size_for_striping: u64,

    /// Size of each stripe in bytes
    ///
    /// Smaller stripes = better load balancing but more overhead.
    /// Default: 512KB
    pub stripe_size: usize,

    /// Maximum stripes in flight per transfer
    ///
    /// Limits memory usage and prevents overwhelming slow paths.
    /// Default: 16
    pub max_stripes_in_flight: usize,

    /// Stripe timeout in milliseconds
    ///
    /// If a stripe doesn't complete within this time, re-request it.
    /// Default: 5000ms
    pub stripe_timeout_ms: u64,

    /// Enable redundant stripe requests for critical data
    ///
    /// Request each stripe from 2 paths simultaneously.
    /// Default: false
    pub enable_redundant_requests: bool,
}

impl Default for StripingConfig {
    fn default() -> Self {
        Self {
            min_size_for_striping: 10 * 1024 * 1024, // 10MB
            stripe_size: 512 * 1024,                 // 512KB
            max_stripes_in_flight: 16,
            stripe_timeout_ms: 5000,
            enable_redundant_requests: false,
        }
    }
}

impl StripingConfig {
    /// Create a config optimized for high throughput
    ///
    /// Larger stripes, more in-flight, for maximizing bandwidth.
    #[must_use]
    pub fn high_throughput() -> Self {
        Self {
            min_size_for_striping: 5 * 1024 * 1024,
            stripe_size: 1024 * 1024, // 1MB
            max_stripes_in_flight: 32,
            stripe_timeout_ms: 10000,
            enable_redundant_requests: false,
        }
    }

    /// Create a config optimized for low latency
    ///
    /// Smaller stripes for faster first-byte delivery.
    #[must_use]
    pub fn low_latency() -> Self {
        Self {
            min_size_for_striping: 1 * 1024 * 1024,
            stripe_size: 128 * 1024, // 128KB
            max_stripes_in_flight: 8,
            stripe_timeout_ms: 2000,
            enable_redundant_requests: false,
        }
    }

    /// Create a config with redundant requests for reliability
    #[must_use]
    pub fn reliable() -> Self {
        Self {
            enable_redundant_requests: true,
            ..Default::default()
        }
    }

    /// Check if a transfer should use striping
    #[must_use]
    pub const fn should_stripe(&self, transfer_size: u64) -> bool {
        transfer_size >= self.min_size_for_striping
    }

    /// Calculate number of stripes for a transfer
    #[must_use]
    #[allow(clippy::cast_lossless, clippy::cast_possible_truncation)]
    pub fn stripe_count(&self, transfer_size: u64) -> u32 {
        let count = (transfer_size + self.stripe_size as u64 - 1) / self.stripe_size as u64;
        count as u32
    }
}

/// Status of a single stripe
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StripeStatus {
    /// Stripe not yet requested
    Pending,
    /// Stripe request sent, waiting for data
    InFlight,
    /// Stripe data received
    Received,
    /// Stripe request timed out
    TimedOut,
    /// Stripe failed (after retries)
    Failed,
}

/// A single stripe of a larger transfer
#[derive(Debug, Clone)]
pub struct Stripe {
    /// Parent transfer ID
    pub transfer_id: TransferId,
    /// Stripe index within the transfer (0-based)
    pub stripe_index: u32,
    /// Byte offset in the original data
    pub offset: u64,
    /// Length of this stripe in bytes
    pub length: usize,
    /// Path ID this stripe was/will be sent on
    pub path_id: PathId,
    /// Stripe data (None if not yet received)
    pub data: Option<Bytes>,
    /// Current status
    pub status: StripeStatus,
    /// Timestamp when request was sent (ms)
    pub sent_at_ms: Option<u64>,
    /// Number of retry attempts
    pub retry_count: u8,
}

impl Stripe {
    /// Create a new pending stripe
    #[must_use]
    pub const fn new(
        transfer_id: TransferId,
        stripe_index: u32,
        offset: u64,
        length: usize,
        path_id: PathId,
    ) -> Self {
        Self {
            transfer_id,
            stripe_index,
            offset,
            length,
            path_id,
            data: None,
            status: StripeStatus::Pending,
            sent_at_ms: None,
            retry_count: 0,
        }
    }

    /// Check if stripe has timed out
    #[must_use]
    pub fn is_timed_out(&self, current_time_ms: u64, timeout_ms: u64) -> bool {
        if let Some(sent_at) = self.sent_at_ms {
            self.status == StripeStatus::InFlight && current_time_ms > sent_at + timeout_ms
        } else {
            false
        }
    }
}

/// Manages stripe distribution and reassembly for a single transfer
#[derive(Debug)]
pub struct StripedTransfer {
    /// Unique transfer identifier
    pub transfer_id: TransferId,
    /// Total size of the transfer in bytes
    pub total_size: u64,
    /// Size of each stripe
    pub stripe_size: usize,
    /// Total number of stripes
    pub total_stripes: u32,
    /// Stripes received, keyed by index
    pub received: HashMap<u32, Bytes>,
    /// Next stripe index to dispatch
    pub next_dispatch: u32,
    /// Next stripe index expected for sequential output
    pub next_output: u32,
    /// Paths to stripe across (round-robin)
    pub paths: Vec<PathId>,
    /// In-flight stripe tracking
    pub in_flight: HashMap<u32, Stripe>,
    /// Configuration
    config: StripingConfig,
    /// Start time for metrics
    start_time_ms: u64,
}

impl StripedTransfer {
    /// Create a new striped transfer
    pub fn new(total_size: u64, paths: Vec<PathId>, config: StripingConfig) -> Self {
        let stripe_size = config.stripe_size;
        let total_stripes = config.stripe_count(total_size);

        Self {
            transfer_id: TransferId::new(),
            total_size,
            stripe_size,
            total_stripes,
            received: HashMap::with_capacity(total_stripes as usize),
            next_dispatch: 0,
            next_output: 0,
            paths,
            in_flight: HashMap::new(),
            config,
            start_time_ms: current_time_ms(),
        }
    }

    /// Get next stripe to dispatch and which path to use
    ///
    /// Returns (stripe_index, path_id, offset, length) or None if all dispatched.
    pub fn next_stripe(&mut self) -> Option<(u32, PathId, u64, usize)> {
        if self.next_dispatch >= self.total_stripes {
            return None;
        }

        // Check if we have too many in-flight
        if self.in_flight.len() >= self.config.max_stripes_in_flight {
            return None;
        }

        let stripe_idx = self.next_dispatch;
        let path_idx = (stripe_idx as usize) % self.paths.len();
        let path_id = self.paths[path_idx];

        let offset = stripe_idx as u64 * self.stripe_size as u64;
        let remaining = self.total_size.saturating_sub(offset);
        let length = (remaining as usize).min(self.stripe_size);

        // Create stripe tracking entry
        let stripe = Stripe::new(self.transfer_id, stripe_idx, offset, length, path_id);
        self.in_flight.insert(stripe_idx, stripe);

        self.next_dispatch += 1;

        Some((stripe_idx, path_id, offset, length))
    }

    /// Mark a stripe as sent (in-flight)
    pub fn mark_sent(&mut self, stripe_idx: u32) {
        if let Some(stripe) = self.in_flight.get_mut(&stripe_idx) {
            stripe.status = StripeStatus::InFlight;
            stripe.sent_at_ms = Some(current_time_ms());
        }
    }

    /// Record received stripe, return sequential data if available
    ///
    /// Returns a vector of contiguous stripes that can be output.
    pub fn receive_stripe(&mut self, index: u32, data: Bytes) -> Option<Vec<Bytes>> {
        // Remove from in-flight
        self.in_flight.remove(&index);

        // Store in received buffer
        self.received.insert(index, data);

        // Try to output sequential stripes
        let mut output = Vec::new();
        while let Some(data) = self.received.remove(&self.next_output) {
            output.push(data);
            self.next_output += 1;
        }

        if output.is_empty() {
            None
        } else {
            Some(output)
        }
    }

    /// Check for timed-out stripes and return them for retry
    pub fn check_timeouts(&mut self) -> Vec<u32> {
        let current = current_time_ms();
        let timeout = self.config.stripe_timeout_ms;

        let timed_out: Vec<u32> = self
            .in_flight
            .iter()
            .filter(|(_, stripe)| stripe.is_timed_out(current, timeout))
            .map(|(&idx, _)| idx)
            .collect();

        for &idx in &timed_out {
            if let Some(stripe) = self.in_flight.get_mut(&idx) {
                stripe.status = StripeStatus::TimedOut;
                stripe.retry_count += 1;
            }
        }

        timed_out
    }

    /// Retry a timed-out stripe on a different path
    pub fn retry_stripe(&mut self, stripe_idx: u32) -> Option<(PathId, u64, usize)> {
        let stripe = self.in_flight.get_mut(&stripe_idx)?;

        if stripe.retry_count > 3 {
            stripe.status = StripeStatus::Failed;
            return None;
        }

        // Pick a different path
        let current_path_idx = self.paths.iter().position(|&p| p == stripe.path_id)?;
        let new_path_idx = (current_path_idx + 1) % self.paths.len();
        let new_path = self.paths[new_path_idx];

        stripe.path_id = new_path;
        stripe.status = StripeStatus::Pending;
        stripe.sent_at_ms = None;

        Some((new_path, stripe.offset, stripe.length))
    }

    /// Check if transfer is complete
    pub fn is_complete(&self) -> bool {
        self.next_output >= self.total_stripes
    }

    /// Get progress as percentage
    pub fn progress(&self) -> f32 {
        if self.total_stripes == 0 {
            100.0
        } else {
            (self.next_output as f32 / self.total_stripes as f32) * 100.0
        }
    }

    /// Get number of stripes in flight
    pub fn in_flight_count(&self) -> usize {
        self.in_flight.len()
    }

    /// Get number of stripes received (possibly out of order)
    pub fn received_count(&self) -> usize {
        self.received.len() + self.next_output as usize
    }

    /// Get elapsed time in milliseconds
    pub fn elapsed_ms(&self) -> u64 {
        current_time_ms().saturating_sub(self.start_time_ms)
    }

    /// Get current throughput estimate (bytes/second)
    pub fn throughput_bps(&self) -> u64 {
        let elapsed_sec = self.elapsed_ms() as f64 / 1000.0;
        if elapsed_sec < 0.001 {
            return 0;
        }
        let bytes_transferred = self.next_output as u64 * self.stripe_size as u64;
        (bytes_transferred as f64 / elapsed_sec) as u64
    }
}

/// Summary of a striped transfer for monitoring
#[derive(Debug, Clone, Default)]
pub struct StripedTransferMetrics {
    /// Transfer ID
    pub transfer_id: TransferId,
    /// Total size in bytes
    pub total_size: u64,
    /// Total stripes
    pub total_stripes: u32,
    /// Stripes completed (output)
    pub completed_stripes: u32,
    /// Stripes in flight
    pub in_flight_stripes: usize,
    /// Stripes waiting for output (received but not yet sequential)
    pub buffered_stripes: usize,
    /// Progress percentage
    pub progress_percent: f32,
    /// Elapsed time in milliseconds
    pub elapsed_ms: u64,
    /// Current throughput estimate
    pub throughput_bps: u64,
    /// Number of paths in use
    pub path_count: usize,
}

impl StripedTransferMetrics {
    /// Create metrics from a striped transfer
    pub fn from_transfer(transfer: &StripedTransfer) -> Self {
        Self {
            transfer_id: transfer.transfer_id,
            total_size: transfer.total_size,
            total_stripes: transfer.total_stripes,
            completed_stripes: transfer.next_output,
            in_flight_stripes: transfer.in_flight.len(),
            buffered_stripes: transfer.received.len(),
            progress_percent: transfer.progress(),
            elapsed_ms: transfer.elapsed_ms(),
            throughput_bps: transfer.throughput_bps(),
            path_count: transfer.paths.len(),
        }
    }
}

/// Helper to get current time in milliseconds
fn current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_striping_config_default() {
        let config = StripingConfig::default();
        assert_eq!(config.min_size_for_striping, 10 * 1024 * 1024);
        assert_eq!(config.stripe_size, 512 * 1024);
        assert_eq!(config.max_stripes_in_flight, 16);
    }

    #[test]
    fn test_should_stripe() {
        let config = StripingConfig::default();

        assert!(!config.should_stripe(1024)); // 1KB - too small
        assert!(!config.should_stripe(5 * 1024 * 1024)); // 5MB - still too small
        assert!(config.should_stripe(10 * 1024 * 1024)); // 10MB - exactly threshold
        assert!(config.should_stripe(100 * 1024 * 1024)); // 100MB - should stripe
    }

    #[test]
    fn test_stripe_count() {
        let config = StripingConfig::default();

        // Exactly one stripe
        assert_eq!(config.stripe_count(512 * 1024), 1);

        // Two stripes
        assert_eq!(config.stripe_count(512 * 1024 + 1), 2);

        // 10MB = 20 stripes (at 512KB each)
        assert_eq!(config.stripe_count(10 * 1024 * 1024), 20);
    }

    #[test]
    fn test_transfer_id() {
        let id1 = TransferId::new();
        let id2 = TransferId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_striped_transfer_creation() {
        let config = StripingConfig::default();
        let paths = vec![PathId(1), PathId(2)];
        let transfer = StripedTransfer::new(10 * 1024 * 1024, paths.clone(), config);

        assert_eq!(transfer.total_stripes, 20);
        assert_eq!(transfer.paths.len(), 2);
        assert_eq!(transfer.next_dispatch, 0);
        assert_eq!(transfer.next_output, 0);
        assert!(!transfer.is_complete());
    }

    #[test]
    fn test_next_stripe_round_robin() {
        let config = StripingConfig::default();
        let paths = vec![PathId(1), PathId(2)];
        let mut transfer = StripedTransfer::new(2 * 1024 * 1024, paths, config);

        // First stripe goes to path 0
        let (idx0, path0, _, _) = transfer.next_stripe().unwrap();
        assert_eq!(idx0, 0);
        assert_eq!(path0, PathId(1));

        // Second stripe goes to path 1
        let (idx1, path1, _, _) = transfer.next_stripe().unwrap();
        assert_eq!(idx1, 1);
        assert_eq!(path1, PathId(2));

        // Third stripe wraps back to path 0
        let (idx2, path2, _, _) = transfer.next_stripe().unwrap();
        assert_eq!(idx2, 2);
        assert_eq!(path2, PathId(1));
    }

    #[test]
    fn test_receive_stripe_in_order() {
        let config = StripingConfig::default();
        let paths = vec![PathId(1)];
        let mut transfer = StripedTransfer::new(1024 * 1024, paths, config);

        // Get first stripe
        let _ = transfer.next_stripe();
        transfer.mark_sent(0);

        // Receive in order
        let data = Bytes::from(vec![1u8; 512 * 1024]);
        let output = transfer.receive_stripe(0, data);

        assert!(output.is_some());
        assert_eq!(output.unwrap().len(), 1);
        assert_eq!(transfer.next_output, 1);
    }

    #[test]
    fn test_receive_stripe_out_of_order() {
        let mut config = StripingConfig::default();
        config.max_stripes_in_flight = 100; // Allow many in-flight
        let paths = vec![PathId(1)];
        let mut transfer = StripedTransfer::new(3 * 512 * 1024, paths, config);

        // Dispatch all three stripes
        transfer.next_stripe();
        transfer.next_stripe();
        transfer.next_stripe();

        // Receive stripe 2 first (out of order)
        let data2 = Bytes::from(vec![2u8; 512 * 1024]);
        let output = transfer.receive_stripe(2, data2);
        assert!(output.is_none()); // Can't output yet

        // Receive stripe 0
        let data0 = Bytes::from(vec![0u8; 512 * 1024]);
        let output = transfer.receive_stripe(0, data0);
        assert!(output.is_some());
        assert_eq!(output.unwrap().len(), 1); // Only stripe 0

        // Receive stripe 1 - should unlock stripe 2 as well
        let data1 = Bytes::from(vec![1u8; 512 * 1024]);
        let output = transfer.receive_stripe(1, data1);
        assert!(output.is_some());
        assert_eq!(output.unwrap().len(), 2); // Both stripe 1 and 2
    }

    #[test]
    fn test_max_stripes_in_flight() {
        let mut config = StripingConfig::default();
        config.max_stripes_in_flight = 2;
        let paths = vec![PathId(1)];
        let mut transfer = StripedTransfer::new(10 * 1024 * 1024, paths, config);

        // Should get first two stripes
        assert!(transfer.next_stripe().is_some());
        assert!(transfer.next_stripe().is_some());

        // Third should be blocked
        assert!(transfer.next_stripe().is_none());

        // Complete one stripe
        let data = Bytes::from(vec![0u8; 512 * 1024]);
        transfer.receive_stripe(0, data);

        // Now we can get another
        assert!(transfer.next_stripe().is_some());
    }

    #[test]
    fn test_progress() {
        let config = StripingConfig::default();
        let paths = vec![PathId(1)];
        let mut transfer = StripedTransfer::new(4 * 512 * 1024, paths, config);

        assert_eq!(transfer.progress(), 0.0);

        // Complete 2 of 4 stripes
        for i in 0..2 {
            transfer.next_stripe();
            let data = Bytes::from(vec![i as u8; 512 * 1024]);
            transfer.receive_stripe(i, data);
        }

        assert_eq!(transfer.progress(), 50.0);
    }

    #[test]
    fn test_metrics() {
        let config = StripingConfig::default();
        let paths = vec![PathId(1), PathId(2)];
        let transfer = StripedTransfer::new(10 * 1024 * 1024, paths, config);

        let metrics = StripedTransferMetrics::from_transfer(&transfer);
        assert_eq!(metrics.total_size, 10 * 1024 * 1024);
        assert_eq!(metrics.total_stripes, 20);
        assert_eq!(metrics.path_count, 2);
        assert_eq!(metrics.progress_percent, 0.0);
    }

    #[test]
    fn test_stripe_timeout() {
        let stripe = Stripe::new(TransferId(1), 0, 0, 512 * 1024, PathId(1));

        // Not sent yet - not timed out
        assert!(!stripe.is_timed_out(1000, 5000));

        // Create in-flight stripe
        let mut stripe = stripe;
        stripe.status = StripeStatus::InFlight;
        stripe.sent_at_ms = Some(1000);

        // Not timed out yet
        assert!(!stripe.is_timed_out(5000, 5000));

        // Now timed out
        assert!(stripe.is_timed_out(7000, 5000));
    }
}
