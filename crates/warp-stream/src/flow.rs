//! Flow control and backpressure handling
//!
//! This module provides mechanisms for controlling data flow through the
//! pipeline and handling backpressure when downstream stages are slower
//! than upstream stages.
//!
//! # Backpressure Strategy
//!
//! The pipeline uses a bounded queue between stages. When a queue reaches
//! capacity, the upstream stage blocks until space is available. This
//! prevents memory exhaustion while maintaining throughput.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Semaphore};
use tracing::trace;

use crate::{Result, SharedStats, StreamError};

/// Flow control state shared between pipeline stages
#[derive(Debug)]
pub struct FlowControl {
    /// Maximum items allowed in flight
    max_in_flight: usize,
    /// Current items in flight
    in_flight: AtomicUsize,
    /// Semaphore for limiting concurrency
    semaphore: Arc<Semaphore>,
    /// Whether flow control is paused
    paused: AtomicBool,
    /// Statistics handle
    stats: Option<SharedStats>,
}

impl FlowControl {
    /// Create new flow control with given capacity
    pub fn new(max_in_flight: usize) -> Self {
        Self {
            max_in_flight,
            in_flight: AtomicUsize::new(0),
            semaphore: Arc::new(Semaphore::new(max_in_flight)),
            paused: AtomicBool::new(false),
            stats: None,
        }
    }

    /// Create flow control with statistics tracking
    pub fn with_stats(max_in_flight: usize, stats: SharedStats) -> Self {
        Self {
            max_in_flight,
            in_flight: AtomicUsize::new(0),
            semaphore: Arc::new(Semaphore::new(max_in_flight)),
            paused: AtomicBool::new(false),
            stats: Some(stats),
        }
    }

    /// Acquire a permit to send an item
    ///
    /// Blocks if at capacity. Returns error if cancelled.
    pub async fn acquire(&self) -> Result<FlowPermit> {
        if self.paused.load(Ordering::Relaxed) {
            return Err(StreamError::Cancelled);
        }

        let permit = self.semaphore.clone().acquire_owned().await
            .map_err(|_| StreamError::Cancelled)?;

        let count = self.in_flight.fetch_add(1, Ordering::Relaxed) + 1;
        trace!("Flow control acquired permit, in_flight: {}", count);

        Ok(FlowPermit {
            _permit: permit,
            in_flight: &self.in_flight,
        })
    }

    /// Try to acquire a permit without blocking
    pub fn try_acquire(&self) -> Option<FlowPermit> {
        if self.paused.load(Ordering::Relaxed) {
            return None;
        }

        match self.semaphore.clone().try_acquire_owned() {
            Ok(permit) => {
                let count = self.in_flight.fetch_add(1, Ordering::Relaxed) + 1;
                trace!("Flow control try_acquire succeeded, in_flight: {}", count);
                Some(FlowPermit {
                    _permit: permit,
                    in_flight: &self.in_flight,
                })
            }
            Err(_) => {
                if let Some(ref stats) = self.stats {
                    stats.record_backpressure();
                }
                None
            }
        }
    }

    /// Get current items in flight
    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Relaxed)
    }

    /// Check if at capacity (would block on acquire)
    pub fn at_capacity(&self) -> bool {
        self.in_flight() >= self.max_in_flight
    }

    /// Get available capacity
    pub fn available(&self) -> usize {
        self.max_in_flight.saturating_sub(self.in_flight())
    }

    /// Pause flow control (blocks all acquire calls)
    pub fn pause(&self) {
        self.paused.store(true, Ordering::Relaxed);
    }

    /// Resume flow control
    pub fn resume(&self) {
        self.paused.store(false, Ordering::Relaxed);
    }

    /// Check if paused
    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Relaxed)
    }
}

/// RAII permit for flow control
///
/// Automatically releases permit when dropped.
pub struct FlowPermit {
    _permit: tokio::sync::OwnedSemaphorePermit,
    in_flight: *const AtomicUsize,
}

// Safety: FlowPermit is Send because we only decrement the counter on drop
unsafe impl Send for FlowPermit {}

impl Drop for FlowPermit {
    fn drop(&mut self) {
        // Safety: in_flight pointer is valid for lifetime of FlowControl
        unsafe {
            let count = (*self.in_flight).fetch_sub(1, Ordering::Relaxed) - 1;
            trace!("Flow control released permit, in_flight: {}", count);
        }
    }
}

/// Backpressure controller for managing stage-to-stage flow
#[derive(Debug)]
pub struct BackpressureController<T> {
    /// Sender end of the channel
    sender: mpsc::Sender<T>,
    /// Flow control
    flow: Arc<FlowControl>,
    /// Statistics handle (reserved for future backpressure event tracking)
    #[allow(dead_code)]
    stats: Option<SharedStats>,
}

impl<T: Send> BackpressureController<T> {
    /// Create a new backpressure-controlled channel
    pub fn new(capacity: usize) -> (Self, BackpressureReceiver<T>) {
        let (sender, receiver) = mpsc::channel(capacity);
        let flow = Arc::new(FlowControl::new(capacity));

        let controller = Self {
            sender,
            flow: Arc::clone(&flow),
            stats: None,
        };

        let receiver = BackpressureReceiver {
            receiver,
            flow,
        };

        (controller, receiver)
    }

    /// Create with statistics tracking
    pub fn with_stats(capacity: usize, stats: SharedStats) -> (Self, BackpressureReceiver<T>) {
        let (sender, receiver) = mpsc::channel(capacity);
        let flow = Arc::new(FlowControl::with_stats(capacity, Arc::clone(&stats)));

        let controller = Self {
            sender,
            flow: Arc::clone(&flow),
            stats: Some(stats),
        };

        let receiver = BackpressureReceiver {
            receiver,
            flow,
        };

        (controller, receiver)
    }

    /// Send an item, blocking if at capacity
    pub async fn send(&self, item: T) -> Result<()> {
        let _permit = self.flow.acquire().await?;

        self.sender.send(item).await
            .map_err(|_| StreamError::ChannelClosed("backpressure channel"))
    }

    /// Try to send without blocking
    pub fn try_send(&self, item: T) -> std::result::Result<(), T> {
        if self.flow.try_acquire().is_none() {
            return Err(item);
        }

        match self.sender.try_send(item) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(item)) => Err(item),
            Err(mpsc::error::TrySendError::Closed(item)) => Err(item),
        }
    }

    /// Send with timeout
    pub async fn send_timeout(&self, item: T, timeout: Duration) -> Result<()> {
        match tokio::time::timeout(timeout, self.send(item)).await {
            Ok(result) => result,
            Err(_) => Err(StreamError::Timeout {
                stage: "backpressure_send",
                elapsed_ms: timeout.as_millis() as u64,
                limit_ms: timeout.as_millis() as u64,
            }),
        }
    }

    /// Check if at capacity
    pub fn at_capacity(&self) -> bool {
        self.flow.at_capacity()
    }

    /// Get current queue depth
    pub fn queue_depth(&self) -> usize {
        self.flow.in_flight()
    }

    /// Pause sending (blocks all sends)
    pub fn pause(&self) {
        self.flow.pause();
    }

    /// Resume sending
    pub fn resume(&self) {
        self.flow.resume();
    }
}

/// Receiver end of a backpressure-controlled channel
#[derive(Debug)]
pub struct BackpressureReceiver<T> {
    receiver: mpsc::Receiver<T>,
    #[allow(dead_code)]
    flow: Arc<FlowControl>,
}

impl<T> BackpressureReceiver<T> {
    /// Receive an item
    pub async fn recv(&mut self) -> Option<T> {
        self.receiver.recv().await
    }

    /// Try to receive without blocking
    pub fn try_recv(&mut self) -> Option<T> {
        self.receiver.try_recv().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_flow_control_acquire_release() {
        let flow = FlowControl::new(2);

        assert_eq!(flow.in_flight(), 0);
        assert_eq!(flow.available(), 2);

        let permit1 = flow.acquire().await.unwrap();
        assert_eq!(flow.in_flight(), 1);

        let permit2 = flow.acquire().await.unwrap();
        assert_eq!(flow.in_flight(), 2);
        assert!(flow.at_capacity());

        drop(permit1);
        assert_eq!(flow.in_flight(), 1);

        drop(permit2);
        assert_eq!(flow.in_flight(), 0);
    }

    #[tokio::test]
    async fn test_flow_control_try_acquire() {
        let flow = FlowControl::new(1);

        let permit1 = flow.try_acquire();
        assert!(permit1.is_some());

        let permit2 = flow.try_acquire();
        assert!(permit2.is_none());

        drop(permit1);

        let permit3 = flow.try_acquire();
        assert!(permit3.is_some());
    }

    #[tokio::test]
    async fn test_flow_control_pause_resume() {
        let flow = FlowControl::new(2);

        flow.pause();
        assert!(flow.is_paused());

        let result = flow.acquire().await;
        assert!(result.is_err());

        flow.resume();
        assert!(!flow.is_paused());

        let permit = flow.acquire().await;
        assert!(permit.is_ok());
    }

    #[tokio::test]
    async fn test_backpressure_channel_send_recv() {
        let (sender, mut receiver) = BackpressureController::new(2);

        sender.send(1u32).await.unwrap();
        sender.send(2u32).await.unwrap();

        assert_eq!(receiver.recv().await, Some(1));
        assert_eq!(receiver.recv().await, Some(2));
    }

    #[tokio::test]
    async fn test_backpressure_channel_try_send() {
        let (sender, _receiver) = BackpressureController::<u32>::new(1);

        assert!(sender.try_send(1).is_ok());
        assert!(sender.try_send(2).is_err());
    }

    #[tokio::test]
    async fn test_backpressure_channel_capacity() {
        // Flow control limits concurrent sends, not queue depth
        // After send completes, the permit is released
        let (sender, _receiver) = BackpressureController::<u32>::new(2);

        assert!(!sender.at_capacity());
        assert_eq!(sender.queue_depth(), 0);

        // Send completes and releases permit
        sender.send(1).await.unwrap();
        sender.send(2).await.unwrap();

        // After sends complete, queue_depth returns to 0
        // because permits are released
        assert_eq!(sender.queue_depth(), 0);
        assert!(!sender.at_capacity());
    }

    #[tokio::test]
    async fn test_backpressure_with_stats() {
        let stats = Arc::new(crate::PipelineStats::new());
        let (sender, _receiver) = BackpressureController::<u32>::with_stats(1, Arc::clone(&stats));

        sender.send(1).await.unwrap();

        // Try to send when at capacity - should record backpressure
        assert!(sender.try_send(2).is_err());
    }

    #[tokio::test]
    async fn test_send_timeout() {
        let (sender, _receiver) = BackpressureController::<u32>::new(1);

        sender.send(1).await.unwrap();

        // Should timeout since at capacity
        let result = sender.send_timeout(2, Duration::from_millis(10)).await;
        assert!(matches!(result, Err(StreamError::Timeout { .. })));
    }

    #[tokio::test]
    async fn test_flow_control_with_stats() {
        let stats = Arc::new(crate::PipelineStats::new());
        let flow = FlowControl::with_stats(2, Arc::clone(&stats));

        // Acquire permit
        let permit = flow.acquire().await.unwrap();
        assert_eq!(flow.in_flight(), 1);

        // Drop permit
        drop(permit);
        assert_eq!(flow.in_flight(), 0);
    }

    #[tokio::test]
    async fn test_flow_control_max_in_flight() {
        let flow = FlowControl::new(3);

        assert_eq!(flow.in_flight(), 0);

        let _p1 = flow.acquire().await.unwrap();
        let _p2 = flow.acquire().await.unwrap();
        let _p3 = flow.acquire().await.unwrap();

        assert_eq!(flow.in_flight(), 3);

        // Should not be able to acquire more
        assert!(flow.try_acquire().is_none());
    }

    #[tokio::test]
    async fn test_flow_control_concurrent_acquire() {
        let flow = Arc::new(FlowControl::new(2));

        let flow1 = Arc::clone(&flow);
        let flow2 = Arc::clone(&flow);

        let h1 = tokio::spawn(async move {
            let _p = flow1.acquire().await.unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
        });

        let h2 = tokio::spawn(async move {
            let _p = flow2.acquire().await.unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
        });

        h1.await.unwrap();
        h2.await.unwrap();

        assert_eq!(flow.in_flight(), 0);
    }

    #[tokio::test]
    async fn test_backpressure_receiver_close() {
        let (sender, receiver) = BackpressureController::<u32>::new(2);

        sender.send(1).await.unwrap();

        // Close receiver
        drop(receiver);

        // Sender should still work (won't fail)
        // Channel is internally managed, so this tests the drop behavior
    }

    #[tokio::test]
    async fn test_flow_control_default_state() {
        let flow = FlowControl::new(10);

        assert_eq!(flow.in_flight(), 0);
        assert!(!flow.is_paused());
    }

    #[tokio::test]
    async fn test_flow_control_debug() {
        let flow = FlowControl::new(5);

        // Test that FlowControl can be debugged
        let debug_str = format!("{:?}", flow);
        assert!(debug_str.contains("FlowControl"));
    }

    #[tokio::test]
    async fn test_backpressure_sequential_sends() {
        let (sender, mut receiver) = BackpressureController::<u32>::new(10);

        // Send multiple values sequentially
        for i in 0..5 {
            sender.send(i).await.unwrap();
        }

        // Receive all values
        let mut received = vec![];
        while let Ok(v) = tokio::time::timeout(
            Duration::from_millis(10),
            receiver.recv()
        ).await {
            if let Some(v) = v {
                received.push(v);
            } else {
                break;
            }
        }

        assert_eq!(received.len(), 5);
    }
}
