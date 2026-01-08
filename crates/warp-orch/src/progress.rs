//! Real-time transfer progress tracking and ETA calculation
//!
//! This module provides progress monitoring for distributed transfers with:
//! - Real-time progress updates via tokio broadcast channels
//! - EMA-based speed estimation for accurate ETAs
//! - Support for multiple concurrent subscribers
//! - Thread-safe tracking of multiple transfers

use crate::types::{TransferId, TransferStatus};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::broadcast;

/// Progress update event broadcast to all subscribers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressUpdate {
    /// Unique identifier for the transfer
    pub transfer_id: TransferId,
    /// Elapsed time since transfer started in milliseconds
    pub timestamp_ms: u64,
    /// Number of chunks successfully completed
    pub chunks_completed: usize,
    /// Total number of chunks in the transfer
    pub total_chunks: usize,
    /// Total bytes transferred so far
    pub bytes_transferred: u64,
    /// Total bytes to be transferred
    pub total_bytes: u64,
    /// Current transfer speed in bytes per second
    pub current_speed_bps: u64,
    /// Estimated time to completion in milliseconds
    pub eta_ms: Option<u64>,
}

/// Exponential moving average based speed estimator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpeedEstimator {
    alpha: f64,
    current_speed_bps: f64,
    #[serde(skip)]
    last_update: Option<Instant>,
}

impl SpeedEstimator {
    /// Create new speed estimator with EMA smoothing factor
    ///
    /// # Arguments
    /// * `alpha` - EMA smoothing factor (0.0-1.0), default 0.3
    ///   Higher alpha = more weight to recent samples
    #[must_use]
    pub fn new(alpha: f64) -> Self {
        Self {
            alpha: alpha.clamp(0.0, 1.0),
            current_speed_bps: 0.0,
            last_update: None,
        }
    }

    /// Record a new data transfer observation
    ///
    /// # Arguments
    /// * `bytes` - Number of bytes transferred
    /// * `duration_ms` - Time taken for transfer in milliseconds
    #[allow(clippy::cast_precision_loss)]
    pub fn record(&mut self, bytes: u64, duration_ms: u64) {
        if duration_ms == 0 {
            return;
        }

        let speed_bps = (bytes as f64 * 1000.0) / duration_ms as f64;

        if self.current_speed_bps == 0.0 {
            self.current_speed_bps = speed_bps;
        } else {
            self.current_speed_bps =
                self.alpha * speed_bps + (1.0 - self.alpha) * self.current_speed_bps;
        }

        self.last_update = Some(Instant::now());
    }

    /// Get current estimated speed in bytes per second
    #[must_use]
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub fn current_speed_bps(&self) -> u64 {
        self.current_speed_bps as u64
    }

    /// Estimate time remaining in milliseconds for remaining bytes
    ///
    /// Returns `None` if no speed data available or speed is zero
    #[must_use]
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    pub fn estimate_eta(&self, remaining_bytes: u64) -> Option<u64> {
        if self.current_speed_bps <= 0.0 || remaining_bytes == 0 {
            return None;
        }

        let eta_seconds = remaining_bytes as f64 / self.current_speed_bps;
        Some((eta_seconds * 1000.0) as u64)
    }
}

impl Default for SpeedEstimator {
    fn default() -> Self {
        Self::new(0.3)
    }
}

/// Progress state for a single transfer
#[derive(Debug, Clone)]
pub struct TransferProgress {
    /// Unique identifier for this transfer
    pub transfer_id: TransferId,
    /// Current status of the transfer
    pub status: TransferStatus,
    /// Total number of chunks in the transfer
    pub total_chunks: usize,
    /// Number of chunks successfully completed
    pub completed_chunks: usize,
    /// Number of chunks that failed
    pub failed_chunks: usize,
    /// Total bytes to be transferred
    pub total_bytes: u64,
    /// Total bytes transferred so far
    pub transferred_bytes: u64,
    /// Time when the transfer started
    pub started_at: Option<Instant>,
    /// Speed estimator for ETA calculations
    pub speed_estimator: SpeedEstimator,
}

impl TransferProgress {
    /// Create new transfer progress tracker
    #[must_use]
    pub fn new(transfer_id: TransferId, total_chunks: usize, total_bytes: u64) -> Self {
        Self {
            transfer_id,
            status: TransferStatus::Pending,
            total_chunks,
            completed_chunks: 0,
            failed_chunks: 0,
            total_bytes,
            transferred_bytes: 0,
            started_at: None,
            speed_estimator: SpeedEstimator::default(),
        }
    }

    /// Get progress ratio from 0.0 to 1.0
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn progress_ratio(&self) -> f64 {
        if self.total_bytes == 0 {
            return 0.0;
        }
        (self.transferred_bytes as f64 / self.total_bytes as f64).min(1.0)
    }

    /// Get elapsed time since transfer started in milliseconds
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn elapsed_ms(&self) -> u64 {
        match self.started_at {
            Some(start) => start.elapsed().as_millis() as u64,
            None => 0,
        }
    }

    /// Get estimated time remaining in milliseconds
    #[must_use]
    pub fn eta_ms(&self) -> Option<u64> {
        let remaining = self.total_bytes.saturating_sub(self.transferred_bytes);
        self.speed_estimator.estimate_eta(remaining)
    }

    /// Check if transfer is complete
    #[must_use]
    pub fn is_complete(&self) -> bool {
        matches!(
            self.status,
            TransferStatus::Completed | TransferStatus::Failed { .. } | TransferStatus::Cancelled
        )
    }
}

/// Central progress tracking manager with subscription support
#[derive(Clone)]
pub struct ProgressTracker {
    transfers: Arc<RwLock<HashMap<TransferId, TransferProgress>>>,
    update_tx: broadcast::Sender<ProgressUpdate>,
}

impl ProgressTracker {
    /// Create new progress tracker with default channel capacity
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(1024)
    }

    /// Create new progress tracker with specific channel capacity
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self {
            transfers: Arc::new(RwLock::new(HashMap::new())),
            update_tx: tx,
        }
    }

    /// Register a new transfer for tracking
    pub fn register(&self, transfer_id: TransferId, total_chunks: usize, total_bytes: u64) {
        let mut transfers = self.transfers.write();
        transfers.insert(
            transfer_id,
            TransferProgress::new(transfer_id, total_chunks, total_bytes),
        );
    }

    /// Mark transfer as started
    pub fn start(&self, transfer_id: TransferId) {
        let mut transfers = self.transfers.write();
        if let Some(progress) = transfers.get_mut(&transfer_id) {
            progress.status = TransferStatus::Active;
            progress.started_at = Some(Instant::now());
            drop(transfers);
            self.broadcast_update(transfer_id);
        }
    }

    /// Record completion of a chunk
    pub fn record_chunk_complete(&self, transfer_id: TransferId, chunk_bytes: u64) {
        let mut transfers = self.transfers.write();
        if let Some(progress) = transfers.get_mut(&transfer_id) {
            progress.completed_chunks += 1;
            progress.transferred_bytes += chunk_bytes;

            if let Some(started) = progress.started_at {
                let duration_ms = started.elapsed().as_millis() as u64;
                if duration_ms > 0 {
                    progress.speed_estimator.record(chunk_bytes, duration_ms);
                }
            }

            drop(transfers);
            self.broadcast_update(transfer_id);
        }
    }

    /// Record chunk failure
    pub fn record_chunk_failed(&self, transfer_id: TransferId) {
        let mut transfers = self.transfers.write();
        if let Some(progress) = transfers.get_mut(&transfer_id) {
            progress.failed_chunks += 1;
            drop(transfers);
            self.broadcast_update(transfer_id);
        }
    }

    /// Record bytes transferred with timing for speed estimation
    pub fn record_bytes(&self, transfer_id: TransferId, bytes: u64, duration_ms: u64) {
        let mut transfers = self.transfers.write();
        if let Some(progress) = transfers.get_mut(&transfer_id) {
            progress.transferred_bytes += bytes;
            progress.speed_estimator.record(bytes, duration_ms);
            drop(transfers);
            self.broadcast_update(transfer_id);
        }
    }

    /// Mark transfer as completed successfully
    pub fn complete(&self, transfer_id: TransferId) {
        let mut transfers = self.transfers.write();
        if let Some(progress) = transfers.get_mut(&transfer_id) {
            progress.status = TransferStatus::Completed;
            progress.transferred_bytes = progress.total_bytes;
            drop(transfers);
            self.broadcast_update(transfer_id);
        }
    }

    /// Mark transfer as failed
    pub fn fail(&self, transfer_id: TransferId, reason: String) {
        let mut transfers = self.transfers.write();
        if let Some(progress) = transfers.get_mut(&transfer_id) {
            progress.status = TransferStatus::Failed { reason };
            drop(transfers);
            self.broadcast_update(transfer_id);
        }
    }

    /// Cancel transfer
    pub fn cancel(&self, transfer_id: TransferId) {
        let mut transfers = self.transfers.write();
        if let Some(progress) = transfers.get_mut(&transfer_id) {
            progress.status = TransferStatus::Cancelled;
            drop(transfers);
            self.broadcast_update(transfer_id);
        }
    }

    /// Get current progress for a transfer
    pub fn get_progress(&self, transfer_id: TransferId) -> Option<TransferProgress> {
        let transfers = self.transfers.read();
        transfers.get(&transfer_id).cloned()
    }

    /// Subscribe to progress updates
    pub fn subscribe(&self) -> broadcast::Receiver<ProgressUpdate> {
        self.update_tx.subscribe()
    }

    /// Get all transfer progress states
    pub fn all_progress(&self) -> Vec<TransferProgress> {
        let transfers = self.transfers.read();
        transfers.values().cloned().collect()
    }

    /// Broadcast progress update to all subscribers
    fn broadcast_update(&self, transfer_id: TransferId) {
        let transfers = self.transfers.read();
        if let Some(progress) = transfers.get(&transfer_id) {
            let update = ProgressUpdate {
                transfer_id,
                timestamp_ms: progress.elapsed_ms(),
                chunks_completed: progress.completed_chunks,
                total_chunks: progress.total_chunks,
                bytes_transferred: progress.transferred_bytes,
                total_bytes: progress.total_bytes,
                current_speed_bps: progress.speed_estimator.current_speed_bps(),
                eta_ms: progress.eta_ms(),
            };
            let _ = self.update_tx.send(update);
        }
    }
}

impl Default for ProgressTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_speed_estimator_new() {
        let estimator = SpeedEstimator::new(0.5);
        assert_eq!(estimator.current_speed_bps(), 0);
    }

    #[test]
    fn test_speed_estimator_default() {
        let estimator = SpeedEstimator::default();
        assert_eq!(estimator.current_speed_bps(), 0);
    }

    #[test]
    fn test_speed_estimator_single_record() {
        let mut estimator = SpeedEstimator::new(0.3);
        estimator.record(1000, 100); // 10KB/s
        assert_eq!(estimator.current_speed_bps(), 10000);
    }

    #[test]
    fn test_speed_estimator_ema_calculation() {
        let mut estimator = SpeedEstimator::new(0.3);
        estimator.record(1000, 100); // 10KB/s
        assert_eq!(estimator.current_speed_bps(), 10000);

        estimator.record(2000, 100); // 20KB/s
        // EMA: 0.3 * 20000 + 0.7 * 10000 = 13000
        assert_eq!(estimator.current_speed_bps(), 13000);
    }

    #[test]
    fn test_speed_estimator_zero_duration() {
        let mut estimator = SpeedEstimator::new(0.3);
        estimator.record(1000, 0);
        assert_eq!(estimator.current_speed_bps(), 0);
    }

    #[test]
    fn test_speed_estimator_eta_estimation() {
        let mut estimator = SpeedEstimator::new(0.3);
        estimator.record(1000, 100); // 10KB/s = 10000 B/s

        let eta = estimator.estimate_eta(10000);
        assert_eq!(eta, Some(1000)); // 10000 bytes / 10000 B/s = 1 second = 1000ms
    }

    #[test]
    fn test_speed_estimator_eta_no_speed() {
        let estimator = SpeedEstimator::new(0.3);
        assert_eq!(estimator.estimate_eta(10000), None);
    }

    #[test]
    fn test_speed_estimator_eta_zero_remaining() {
        let mut estimator = SpeedEstimator::new(0.3);
        estimator.record(1000, 100);
        assert_eq!(estimator.estimate_eta(0), None);
    }

    #[test]
    fn test_transfer_progress_new() {
        let id = TransferId(1);
        let progress = TransferProgress::new(id, 10, 1000);

        assert_eq!(progress.transfer_id, id);
        assert_eq!(progress.status, TransferStatus::Pending);
        assert_eq!(progress.total_chunks, 10);
        assert_eq!(progress.completed_chunks, 0);
        assert_eq!(progress.total_bytes, 1000);
        assert_eq!(progress.transferred_bytes, 0);
        assert!(progress.started_at.is_none());
    }

    #[test]
    fn test_transfer_progress_ratio_zero_bytes() {
        let progress = TransferProgress::new(TransferId(1), 10, 0);
        assert_eq!(progress.progress_ratio(), 0.0);
    }

    #[test]
    fn test_transfer_progress_ratio_partial() {
        let mut progress = TransferProgress::new(TransferId(1), 10, 1000);
        progress.transferred_bytes = 250;
        assert_eq!(progress.progress_ratio(), 0.25);
    }

    #[test]
    fn test_transfer_progress_ratio_complete() {
        let mut progress = TransferProgress::new(TransferId(1), 10, 1000);
        progress.transferred_bytes = 1000;
        assert_eq!(progress.progress_ratio(), 1.0);
    }

    #[test]
    fn test_transfer_progress_ratio_overflow() {
        let mut progress = TransferProgress::new(TransferId(1), 10, 1000);
        progress.transferred_bytes = 1500;
        assert_eq!(progress.progress_ratio(), 1.0);
    }

    #[test]
    fn test_transfer_progress_elapsed_not_started() {
        let progress = TransferProgress::new(TransferId(1), 10, 1000);
        assert_eq!(progress.elapsed_ms(), 0);
    }

    #[test]
    fn test_transfer_progress_is_complete() {
        let mut progress = TransferProgress::new(TransferId(1), 10, 1000);
        assert!(!progress.is_complete());

        progress.status = TransferStatus::Active;
        assert!(!progress.is_complete());

        progress.status = TransferStatus::Completed;
        assert!(progress.is_complete());

        progress.status = TransferStatus::Failed {
            reason: "test".to_string(),
        };
        assert!(progress.is_complete());

        progress.status = TransferStatus::Cancelled;
        assert!(progress.is_complete());
    }

    #[test]
    fn test_progress_tracker_new() {
        let tracker = ProgressTracker::new();
        assert!(tracker.all_progress().is_empty());
    }

    #[test]
    fn test_progress_tracker_register() {
        let tracker = ProgressTracker::new();
        let id = TransferId(1);

        tracker.register(id, 10, 1000);

        let progress = tracker.get_progress(id).unwrap();
        assert_eq!(progress.transfer_id, id);
        assert_eq!(progress.total_chunks, 10);
        assert_eq!(progress.total_bytes, 1000);
        assert_eq!(progress.status, TransferStatus::Pending);
    }

    #[test]
    fn test_progress_tracker_start() {
        let tracker = ProgressTracker::new();
        let id = TransferId(1);

        tracker.register(id, 10, 1000);
        tracker.start(id);

        let progress = tracker.get_progress(id).unwrap();
        assert_eq!(progress.status, TransferStatus::Active);
        assert!(progress.started_at.is_some());
    }

    #[test]
    fn test_progress_tracker_record_chunk_complete() {
        let tracker = ProgressTracker::new();
        let id = TransferId(1);

        tracker.register(id, 10, 1000);
        tracker.start(id);
        tracker.record_chunk_complete(id, 100);

        let progress = tracker.get_progress(id).unwrap();
        assert_eq!(progress.completed_chunks, 1);
        assert_eq!(progress.transferred_bytes, 100);
    }

    #[test]
    fn test_progress_tracker_record_chunk_failed() {
        let tracker = ProgressTracker::new();
        let id = TransferId(1);

        tracker.register(id, 10, 1000);
        tracker.record_chunk_failed(id);

        let progress = tracker.get_progress(id).unwrap();
        assert_eq!(progress.failed_chunks, 1);
    }

    #[test]
    fn test_progress_tracker_record_bytes() {
        let tracker = ProgressTracker::new();
        let id = TransferId(1);

        tracker.register(id, 10, 1000);
        tracker.record_bytes(id, 500, 100);

        let progress = tracker.get_progress(id).unwrap();
        assert_eq!(progress.transferred_bytes, 500);
        assert!(progress.speed_estimator.current_speed_bps() > 0);
    }

    #[test]
    fn test_progress_tracker_complete() {
        let tracker = ProgressTracker::new();
        let id = TransferId(1);

        tracker.register(id, 10, 1000);
        tracker.complete(id);

        let progress = tracker.get_progress(id).unwrap();
        assert_eq!(progress.status, TransferStatus::Completed);
        assert_eq!(progress.transferred_bytes, 1000);
    }

    #[test]
    fn test_progress_tracker_fail() {
        let tracker = ProgressTracker::new();
        let id = TransferId(1);

        tracker.register(id, 10, 1000);
        tracker.fail(id, "test error".to_string());

        let progress = tracker.get_progress(id).unwrap();
        assert!(matches!(progress.status, TransferStatus::Failed { .. }));
    }

    #[test]
    fn test_progress_tracker_cancel() {
        let tracker = ProgressTracker::new();
        let id = TransferId(1);

        tracker.register(id, 10, 1000);
        tracker.cancel(id);

        let progress = tracker.get_progress(id).unwrap();
        assert_eq!(progress.status, TransferStatus::Cancelled);
    }

    #[test]
    fn test_progress_tracker_get_nonexistent() {
        let tracker = ProgressTracker::new();
        assert!(tracker.get_progress(TransferId(999)).is_none());
    }

    #[test]
    fn test_progress_tracker_all_progress() {
        let tracker = ProgressTracker::new();

        tracker.register(TransferId(1), 10, 1000);
        tracker.register(TransferId(2), 20, 2000);
        tracker.register(TransferId(3), 30, 3000);

        let all = tracker.all_progress();
        assert_eq!(all.len(), 3);
    }

    #[tokio::test]
    async fn test_progress_tracker_subscribe() {
        let tracker = ProgressTracker::new();
        let mut rx = tracker.subscribe();

        let id = TransferId(1);
        tracker.register(id, 10, 1000);
        tracker.start(id);

        let update = rx.recv().await.unwrap();
        assert_eq!(update.transfer_id, id);
        assert_eq!(update.total_chunks, 10);
        assert_eq!(update.total_bytes, 1000);
    }

    #[tokio::test]
    async fn test_progress_tracker_multiple_subscribers() {
        let tracker = ProgressTracker::new();
        let mut rx1 = tracker.subscribe();
        let mut rx2 = tracker.subscribe();

        let id = TransferId(1);
        tracker.register(id, 10, 1000);
        tracker.start(id);

        let update1 = rx1.recv().await.unwrap();
        let update2 = rx2.recv().await.unwrap();

        assert_eq!(update1.transfer_id, update2.transfer_id);
        assert_eq!(update1.timestamp_ms, update2.timestamp_ms);
    }

    #[tokio::test]
    async fn test_progress_update_on_chunk_complete() {
        let tracker = ProgressTracker::new();
        let mut rx = tracker.subscribe();

        let id = TransferId(1);
        tracker.register(id, 10, 1000);
        tracker.start(id);
        let _ = rx.recv().await; // Consume start update

        tracker.record_chunk_complete(id, 100);

        let update = rx.recv().await.unwrap();
        assert_eq!(update.chunks_completed, 1);
        assert_eq!(update.bytes_transferred, 100);
    }

    #[tokio::test]
    async fn test_progress_update_on_complete() {
        let tracker = ProgressTracker::new();
        let mut rx = tracker.subscribe();

        let id = TransferId(1);
        tracker.register(id, 10, 1000);
        tracker.start(id);
        let _ = rx.recv().await; // Consume start update

        tracker.complete(id);

        let update = rx.recv().await.unwrap();
        assert_eq!(update.bytes_transferred, 1000);
    }

    #[test]
    fn test_speed_estimator_alpha_clamping() {
        let estimator1 = SpeedEstimator::new(-0.5);
        assert_eq!(estimator1.alpha, 0.0);

        let estimator2 = SpeedEstimator::new(1.5);
        assert_eq!(estimator2.alpha, 1.0);
    }

    #[test]
    fn test_multiple_transfers_tracking() {
        let tracker = ProgressTracker::new();

        let id1 = TransferId(1);
        let id2 = TransferId(2);

        tracker.register(id1, 10, 1000);
        tracker.register(id2, 20, 2000);

        tracker.start(id1);
        tracker.start(id2);

        tracker.record_chunk_complete(id1, 100);
        tracker.record_chunk_complete(id2, 200);

        let progress1 = tracker.get_progress(id1).unwrap();
        let progress2 = tracker.get_progress(id2).unwrap();

        assert_eq!(progress1.completed_chunks, 1);
        assert_eq!(progress1.transferred_bytes, 100);

        assert_eq!(progress2.completed_chunks, 1);
        assert_eq!(progress2.transferred_bytes, 200);
    }

    #[test]
    fn test_progress_after_completion() {
        let tracker = ProgressTracker::new();
        let id = TransferId(1);

        tracker.register(id, 10, 1000);
        tracker.start(id);
        tracker.complete(id);

        // Recording after completion should not change status
        tracker.record_chunk_complete(id, 100);

        let progress = tracker.get_progress(id).unwrap();
        assert_eq!(progress.status, TransferStatus::Completed);
    }

    #[test]
    fn test_speed_calculation_accuracy() {
        let mut estimator = SpeedEstimator::new(0.3);

        // Record 1KB in 100ms = 10KB/s
        estimator.record(1000, 100);
        assert_eq!(estimator.current_speed_bps(), 10000);

        // Record 2KB in 100ms = 20KB/s
        estimator.record(2000, 100);
        assert_eq!(estimator.current_speed_bps(), 13000);

        // Record 3KB in 100ms = 30KB/s
        estimator.record(3000, 100);
        // EMA: 0.3 * 30000 + 0.7 * 13000 = 18100
        assert_eq!(estimator.current_speed_bps(), 18100);
    }

    #[test]
    fn test_eta_accuracy_with_varying_speeds() {
        let mut estimator = SpeedEstimator::new(0.3);

        estimator.record(1000, 100); // 10KB/s
        let eta1 = estimator.estimate_eta(20000).unwrap();
        assert_eq!(eta1, 2000); // 2 seconds

        estimator.record(2000, 100); // 20KB/s, EMA = 13KB/s
        let eta2 = estimator.estimate_eta(20000).unwrap();
        assert!(eta2 < eta1); // Should be faster
    }

    #[test]
    fn test_transfer_status_equality() {
        assert_eq!(TransferStatus::Pending, TransferStatus::Pending);
        assert_ne!(TransferStatus::Pending, TransferStatus::Active);
    }

    #[tokio::test]
    async fn test_late_subscriber() {
        let tracker = ProgressTracker::new();
        let id = TransferId(1);

        tracker.register(id, 10, 1000);
        tracker.start(id);
        tracker.record_chunk_complete(id, 100);

        // Subscribe after some updates
        let mut rx = tracker.subscribe();

        tracker.record_chunk_complete(id, 100);

        let update = rx.recv().await.unwrap();
        assert_eq!(update.chunks_completed, 2);
        assert_eq!(update.bytes_transferred, 200);
    }

    #[test]
    fn test_concurrent_chunk_completions() {
        let tracker = ProgressTracker::new();
        let id = TransferId(1);

        tracker.register(id, 100, 10000);
        tracker.start(id);

        for _ in 0..50 {
            tracker.record_chunk_complete(id, 100);
        }

        let progress = tracker.get_progress(id).unwrap();
        assert_eq!(progress.completed_chunks, 50);
        assert_eq!(progress.transferred_bytes, 5000);
    }

    #[test]
    fn test_chunk_failures_tracking() {
        let tracker = ProgressTracker::new();
        let id = TransferId(1);

        tracker.register(id, 10, 1000);

        tracker.record_chunk_complete(id, 100);
        tracker.record_chunk_failed(id);
        tracker.record_chunk_complete(id, 100);
        tracker.record_chunk_failed(id);

        let progress = tracker.get_progress(id).unwrap();
        assert_eq!(progress.completed_chunks, 2);
        assert_eq!(progress.failed_chunks, 2);
    }
}
