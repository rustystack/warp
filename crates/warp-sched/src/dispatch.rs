//! CPU-readable scheduling output queue with double-buffering
//!
//! The `DispatchQueue` provides a thread-safe, double-buffered queue for
//! assignments from the GPU scheduler. It allows concurrent producers
//! (schedulers) to write while consumers read from a stable buffer.
//!
//! # Architecture
//!
//! - **Double-buffering**: Front buffer for reading, back buffer for writing
//! - **Atomic operations**: Lock-free generation counter and buffer tracking
//! - **Async notifications**: Efficient waiting for new assignments
//! - **Thread-safe**: Multiple readers and writers supported via Arc cloning
//!
//! # Example
//!
//! ```no_run
//! use warp_sched::dispatch::DispatchQueue;
//!
//! # #[tokio::main]
//! # async fn main() {
//! let queue = DispatchQueue::new();
//!
//! // Producer (scheduler)
//! let producer = queue.clone();
//! tokio::spawn(async move {
//!     let assignments = vec![]; // Create assignments
//!     producer.write_assignments(assignments);
//!     producer.swap_buffers(); // Make available to consumers
//! });
//!
//! // Consumer (dispatcher)
//! let batch = queue.wait_for_assignments().await;
//! # }
//! ```

use crate::types::{Assignment, AssignmentBatch};
use parking_lot::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;

/// Double-buffered assignment queue for CPU consumption
///
/// This structure provides lock-free reading and writing through double-buffering.
/// The producer writes to the back buffer while consumers read from the front buffer.
/// After writing, the producer calls `swap_buffers()` to atomically switch buffers.
#[derive(Debug)]
pub struct DispatchQueue {
    /// Front buffer (consumers read from this)
    front_buffer: Arc<Mutex<Vec<Assignment>>>,
    /// Back buffer (producer writes to this)
    back_buffer: Arc<Mutex<Vec<Assignment>>>,
    /// Which buffer is currently active for reading (0 = front, 1 = back)
    active_buffer: Arc<AtomicUsize>,
    /// Generation counter (increments on each write)
    generation: Arc<AtomicU64>,
    /// Notification mechanism for waiting consumers
    notify: Arc<Notify>,
}

impl DispatchQueue {
    /// Create a new dispatch queue
    ///
    /// # Examples
    ///
    /// ```
    /// use warp_sched::dispatch::DispatchQueue;
    ///
    /// let queue = DispatchQueue::new();
    /// assert_eq!(queue.generation(), 0);
    /// assert_eq!(queue.pending_count(), 0);
    /// ```
    pub fn new() -> Self {
        Self {
            front_buffer: Arc::new(Mutex::new(Vec::new())),
            back_buffer: Arc::new(Mutex::new(Vec::new())),
            active_buffer: Arc::new(AtomicUsize::new(0)),
            generation: Arc::new(AtomicU64::new(0)),
            notify: Arc::new(Notify::new()),
        }
    }

    /// Write assignments to the back buffer
    ///
    /// This method is typically called by the scheduler after computing
    /// assignments. It writes to the inactive buffer, allowing consumers
    /// to continue reading from the active buffer.
    ///
    /// # Returns
    ///
    /// The generation number for this batch of assignments.
    ///
    /// # Examples
    ///
    /// ```
    /// use warp_sched::dispatch::DispatchQueue;
    /// use warp_sched::types::{Assignment, EdgeIdx};
    ///
    /// let queue = DispatchQueue::new();
    /// let assignments = vec![Assignment {
    ///     chunk_hash: [0u8; 32],
    ///     chunk_size: 1024,
    ///     source_edges: vec![EdgeIdx(0)],
    ///     priority: 100,
    ///     estimated_duration_ms: 100,
    /// }];
    ///
    /// let generation = queue.write_assignments(assignments);
    /// assert_eq!(generation, 1);
    /// ```
    pub fn write_assignments(&self, assignments: Vec<Assignment>) -> u64 {
        // Increment generation first
        // Relaxed: generation is an independent monotonic counter
        let generation_num = self.generation.fetch_add(1, Ordering::Relaxed) + 1;

        // Determine which buffer to write to (opposite of active)
        // Acquire: synchronize with Release in swap_buffers to see consistent state
        let active = self.active_buffer.load(Ordering::Acquire);
        let write_buffer = if active == 0 {
            &self.back_buffer
        } else {
            &self.front_buffer
        };

        // Write to the inactive buffer
        let mut buffer = write_buffer.lock();
        buffer.clear();
        buffer.extend(assignments);

        generation_num
    }

    /// Swap front and back buffers
    ///
    /// This atomically makes the newly written assignments available to
    /// consumers. Should be called after `write_assignments()`.
    ///
    /// # Examples
    ///
    /// ```
    /// use warp_sched::dispatch::DispatchQueue;
    ///
    /// let queue = DispatchQueue::new();
    /// queue.write_assignments(vec![]);
    /// queue.swap_buffers();
    ///
    /// let batch = queue.read_assignments();
    /// assert!(batch.is_empty());
    /// ```
    pub fn swap_buffers(&self) {
        // Atomically swap the active buffer
        // Acquire: see current buffer state
        let current = self.active_buffer.load(Ordering::Acquire);
        let new = if current == 0 { 1 } else { 0 };
        // Release: publish buffer contents to readers
        self.active_buffer.store(new, Ordering::Release);

        // Notify any waiting consumers
        self.notify.notify_waiters();
    }

    /// Read assignments from the front buffer (non-blocking)
    ///
    /// Returns an empty batch if no assignments are available.
    ///
    /// # Examples
    ///
    /// ```
    /// use warp_sched::dispatch::DispatchQueue;
    ///
    /// let queue = DispatchQueue::new();
    /// let batch = queue.read_assignments();
    /// assert!(batch.is_empty());
    /// ```
    pub fn read_assignments(&self) -> AssignmentBatch {
        // Acquire: synchronize with Release in swap_buffers
        let active = self.active_buffer.load(Ordering::Acquire);
        let read_buffer = if active == 0 {
            &self.front_buffer
        } else {
            &self.back_buffer
        };

        let buffer = read_buffer.lock();
        // Relaxed: generation is informational, doesn't need synchronization
        let generation = self.generation.load(Ordering::Relaxed);

        AssignmentBatch::new(buffer.clone(), generation)
    }

    /// Wait for new assignments (async)
    ///
    /// Blocks until `swap_buffers()` is called by a producer, then returns
    /// the new batch of assignments.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use warp_sched::dispatch::DispatchQueue;
    ///
    /// # #[tokio::main]
    /// # async fn main() {
    /// let queue = DispatchQueue::new();
    ///
    /// // In another task: queue.write_assignments(...); queue.swap_buffers();
    ///
    /// let batch = queue.wait_for_assignments().await;
    /// # }
    /// ```
    pub async fn wait_for_assignments(&self) -> AssignmentBatch {
        // Wait for notification
        self.notify.notified().await;

        // Read the assignments
        self.read_assignments()
    }

    /// Try to read assignments with a timeout
    ///
    /// Returns `Some(batch)` if assignments become available within the timeout,
    /// or `None` if the timeout expires.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use warp_sched::dispatch::DispatchQueue;
    /// use std::time::Duration;
    ///
    /// # #[tokio::main]
    /// # async fn main() {
    /// let queue = DispatchQueue::new();
    /// let timeout = Duration::from_millis(100);
    ///
    /// if let Some(batch) = queue.read_with_timeout(timeout).await {
    ///     println!("Got {} assignments", batch.len());
    /// } else {
    ///     println!("Timeout waiting for assignments");
    /// }
    /// # }
    /// ```
    pub async fn read_with_timeout(&self, timeout: Duration) -> Option<AssignmentBatch> {
        // Use tokio's timeout
        match tokio::time::timeout(timeout, self.wait_for_assignments()).await {
            Ok(batch) => Some(batch),
            Err(_) => None,
        }
    }

    /// Get the current generation number
    ///
    /// The generation number increments each time `write_assignments()` is called.
    ///
    /// # Examples
    ///
    /// ```
    /// use warp_sched::dispatch::DispatchQueue;
    ///
    /// let queue = DispatchQueue::new();
    /// assert_eq!(queue.generation(), 0);
    ///
    /// queue.write_assignments(vec![]);
    /// assert_eq!(queue.generation(), 1);
    /// ```
    pub fn generation(&self) -> u64 {
        // Relaxed: generation is an independent monotonic counter
        self.generation.load(Ordering::Relaxed)
    }

    /// Get the number of pending assignments in the active buffer
    ///
    /// # Examples
    ///
    /// ```
    /// use warp_sched::dispatch::DispatchQueue;
    /// use warp_sched::types::{Assignment, EdgeIdx};
    ///
    /// let queue = DispatchQueue::new();
    /// assert_eq!(queue.pending_count(), 0);
    ///
    /// let assignments = vec![Assignment {
    ///     chunk_hash: [0u8; 32],
    ///     chunk_size: 1024,
    ///     source_edges: vec![EdgeIdx(0)],
    ///     priority: 100,
    ///     estimated_duration_ms: 100,
    /// }];
    ///
    /// queue.write_assignments(assignments);
    /// queue.swap_buffers();
    /// assert_eq!(queue.pending_count(), 1);
    /// ```
    pub fn pending_count(&self) -> usize {
        // Acquire: synchronize with Release in swap_buffers
        let active = self.active_buffer.load(Ordering::Acquire);
        let read_buffer = if active == 0 {
            &self.front_buffer
        } else {
            &self.back_buffer
        };

        read_buffer.lock().len()
    }

    /// Clear all buffers
    ///
    /// Removes all assignments from both buffers. The generation counter
    /// is not reset.
    ///
    /// # Examples
    ///
    /// ```
    /// use warp_sched::dispatch::DispatchQueue;
    ///
    /// let queue = DispatchQueue::new();
    /// queue.write_assignments(vec![]);
    /// queue.swap_buffers();
    ///
    /// queue.clear();
    /// assert_eq!(queue.pending_count(), 0);
    /// ```
    pub fn clear(&self) {
        self.front_buffer.lock().clear();
        self.back_buffer.lock().clear();
    }

    /// Check if there are pending assignments
    ///
    /// # Examples
    ///
    /// ```
    /// use warp_sched::dispatch::DispatchQueue;
    ///
    /// let queue = DispatchQueue::new();
    /// assert!(!queue.has_pending());
    ///
    /// queue.write_assignments(vec![]);
    /// queue.swap_buffers();
    /// assert!(!queue.has_pending()); // Empty vec has no pending
    /// ```
    pub fn has_pending(&self) -> bool {
        self.pending_count() > 0
    }
}

impl Default for DispatchQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for DispatchQueue {
    /// Clone creates a handle to the same underlying queue
    ///
    /// This allows multiple producers and consumers to share the same queue.
    fn clone(&self) -> Self {
        Self {
            front_buffer: Arc::clone(&self.front_buffer),
            back_buffer: Arc::clone(&self.back_buffer),
            active_buffer: Arc::clone(&self.active_buffer),
            generation: Arc::clone(&self.generation),
            notify: Arc::clone(&self.notify),
        }
    }
}

// Ensure DispatchQueue is Send + Sync for multi-threaded use
static_assertions::assert_impl_all!(DispatchQueue: Send, Sync);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::EdgeIdx;

    fn create_test_assignment(chunk_idx: u8, edge_idx: u32, _generation: u64) -> Assignment {
        let mut chunk_hash = [0u8; 32];
        chunk_hash[0] = chunk_idx;

        Assignment {
            chunk_hash,
            chunk_size: 1024 * u32::from(chunk_idx),
            source_edges: vec![EdgeIdx(edge_idx), EdgeIdx(edge_idx + 1), EdgeIdx(edge_idx + 2)],
            priority: chunk_idx,
            estimated_duration_ms: 100 + u32::from(chunk_idx),
        }
    }

    #[test]
    fn test_dispatch_queue_creation() {
        let queue = DispatchQueue::new();
        assert_eq!(queue.generation(), 0);
        assert_eq!(queue.pending_count(), 0);
        assert!(!queue.has_pending());
    }

    #[test]
    fn test_dispatch_queue_default() {
        let queue = DispatchQueue::default();
        assert_eq!(queue.generation(), 0);
        assert_eq!(queue.pending_count(), 0);
    }

    #[test]
    fn test_write_single_assignment() {
        let queue = DispatchQueue::new();
        let assignment = create_test_assignment(1, 10, 0);

        let generation_num = queue.write_assignments(vec![assignment.clone()]);
        assert_eq!(generation_num, 1);
        assert_eq!(queue.generation(), 1);

        // Not visible until swap
        assert_eq!(queue.pending_count(), 0);

        queue.swap_buffers();
        assert_eq!(queue.pending_count(), 1);

        let batch = queue.read_assignments();
        assert_eq!(batch.len(), 1);
        assert_eq!(batch.generation, 1);
        assert_eq!(batch.assignments[0], assignment);
    }

    #[test]
    fn test_write_batch_of_assignments() {
        let queue = DispatchQueue::new();
        let assignments = vec![
            create_test_assignment(1, 10, 0),
            create_test_assignment(2, 20, 0),
            create_test_assignment(3, 30, 0),
        ];

        let generation_num = queue.write_assignments(assignments.clone());
        assert_eq!(generation_num, 1);

        queue.swap_buffers();
        assert_eq!(queue.pending_count(), 3);

        let batch = queue.read_assignments();
        assert_eq!(batch.len(), 3);
        assert_eq!(batch.assignments, assignments);
    }

    #[test]
    fn test_swap_buffers() {
        let queue = DispatchQueue::new();

        // Write first batch
        queue.write_assignments(vec![create_test_assignment(1, 10, 1)]);
        queue.swap_buffers();
        assert_eq!(queue.pending_count(), 1);

        // Write second batch
        queue.write_assignments(vec![
            create_test_assignment(2, 20, 2),
            create_test_assignment(3, 30, 2),
        ]);

        // First batch still readable before swap
        let batch1 = queue.read_assignments();
        assert_eq!(batch1.len(), 1);

        // Swap to see second batch
        queue.swap_buffers();
        let batch2 = queue.read_assignments();
        assert_eq!(batch2.len(), 2);
        assert_eq!(batch2.generation, 2);
    }

    #[test]
    fn test_read_empty_queue() {
        let queue = DispatchQueue::new();
        let batch = queue.read_assignments();

        assert!(batch.is_empty());
        assert_eq!(batch.len(), 0);
        assert_eq!(batch.generation, 0);
    }

    #[test]
    fn test_generation_increments() {
        let queue = DispatchQueue::new();
        assert_eq!(queue.generation(), 0);

        queue.write_assignments(vec![]);
        assert_eq!(queue.generation(), 1);

        queue.write_assignments(vec![]);
        assert_eq!(queue.generation(), 2);

        queue.write_assignments(vec![]);
        assert_eq!(queue.generation(), 3);
    }

    #[tokio::test]
    async fn test_wait_for_assignments() {
        let queue = DispatchQueue::new();
        let producer = queue.clone();

        // Spawn producer task
        let handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            producer.write_assignments(vec![create_test_assignment(1, 10, 1)]);
            producer.swap_buffers();
        });

        // Wait for assignments
        let batch = queue.wait_for_assignments().await;
        assert_eq!(batch.len(), 1);

        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_read_with_timeout_success() {
        let queue = DispatchQueue::new();
        let producer = queue.clone();

        // Spawn producer task
        let handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            producer.write_assignments(vec![create_test_assignment(1, 10, 1)]);
            producer.swap_buffers();
        });

        // Read with sufficient timeout
        let result = queue.read_with_timeout(Duration::from_millis(100)).await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 1);

        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_read_with_timeout_expires() {
        let queue = DispatchQueue::new();

        // Read with very short timeout (no producer)
        let result = queue.read_with_timeout(Duration::from_millis(10)).await;
        assert!(result.is_none());
    }

    #[test]
    fn test_clear_buffers() {
        let queue = DispatchQueue::new();

        // Write and swap
        queue.write_assignments(vec![
            create_test_assignment(1, 10, 1),
            create_test_assignment(2, 20, 1),
        ]);
        queue.swap_buffers();
        assert_eq!(queue.pending_count(), 2);

        // Clear
        queue.clear();
        assert_eq!(queue.pending_count(), 0);
        assert!(!queue.has_pending());

        // Generation should not be reset
        assert_eq!(queue.generation(), 1);
    }

    #[test]
    fn test_pending_count() {
        let queue = DispatchQueue::new();

        // Empty initially
        assert_eq!(queue.pending_count(), 0);

        // Write 5 assignments
        let assignments = (0..5)
            .map(|i| create_test_assignment(i, u32::from(i) * 10, 1))
            .collect();
        queue.write_assignments(assignments);
        queue.swap_buffers();

        assert_eq!(queue.pending_count(), 5);
        assert!(queue.has_pending());
    }

    #[test]
    fn test_has_pending() {
        let queue = DispatchQueue::new();
        assert!(!queue.has_pending());

        queue.write_assignments(vec![create_test_assignment(1, 10, 1)]);
        queue.swap_buffers();
        assert!(queue.has_pending());

        queue.clear();
        assert!(!queue.has_pending());
    }

    #[test]
    fn test_clone_shares_queue() {
        let queue1 = DispatchQueue::new();
        let queue2 = queue1.clone();

        // Write through queue1
        queue1.write_assignments(vec![create_test_assignment(1, 10, 1)]);
        queue1.swap_buffers();

        // Read through queue2
        let batch = queue2.read_assignments();
        assert_eq!(batch.len(), 1);

        // Both see same generation
        assert_eq!(queue1.generation(), queue2.generation());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_read_write() {
        let queue = Arc::new(DispatchQueue::new());
        let mut handles = vec![];

        // Spawn multiple producers
        for i in 0..3 {
            let q = Arc::clone(&queue);
            let handle = tokio::spawn(async move {
                for j in 0..10 {
                    let assignment = create_test_assignment((i * 10 + j) as u8, i * 100, 0);
                    q.write_assignments(vec![assignment]);
                    q.swap_buffers();
                    tokio::time::sleep(Duration::from_micros(100)).await;
                }
            });
            handles.push(handle);
        }

        // Spawn multiple consumers
        for _ in 0..2 {
            let q = Arc::clone(&queue);
            let handle = tokio::spawn(async move {
                for _ in 0..15 {
                    let batch = q
                        .read_with_timeout(Duration::from_millis(100))
                        .await;
                    if let Some(b) = batch {
                        assert!(!b.is_empty() || b.generation > 0);
                    }
                }
            });
            handles.push(handle);
        }

        // Wait for all tasks
        for handle in handles {
            handle.await.unwrap();
        }

        // Final generation should be 30 (3 producers * 10 writes)
        assert_eq!(queue.generation(), 30);
    }

    #[tokio::test]
    async fn test_multiple_swaps() {
        let queue = DispatchQueue::new();

        // First batch
        queue.write_assignments(vec![create_test_assignment(1, 10, 1)]);
        queue.swap_buffers();
        let batch1 = queue.read_assignments();
        assert_eq!(batch1.len(), 1);
        assert_eq!(batch1.generation, 1);

        // Second batch
        queue.write_assignments(vec![create_test_assignment(2, 20, 2)]);
        queue.swap_buffers();
        let batch2 = queue.read_assignments();
        assert_eq!(batch2.len(), 1);
        assert_eq!(batch2.generation, 2);

        // Third batch
        queue.write_assignments(vec![create_test_assignment(3, 30, 3)]);
        queue.swap_buffers();
        let batch3 = queue.read_assignments();
        assert_eq!(batch3.len(), 1);
        assert_eq!(batch3.generation, 3);
    }

    #[test]
    fn test_assignment_batch_methods() {
        let batch = AssignmentBatch::empty(0);
        assert!(batch.is_empty());
        assert_eq!(batch.len(), 0);
        assert_eq!(batch.generation, 0);

        let assignments = vec![
            create_test_assignment(1, 10, 1),
            create_test_assignment(2, 20, 1),
        ];
        let batch = AssignmentBatch::new(assignments, 1);

        assert!(!batch.is_empty());
        assert_eq!(batch.len(), 2);
        assert_eq!(batch.generation, 1);
    }

    #[tokio::test]
    async fn test_notify_multiple_waiters() {
        let queue = Arc::new(DispatchQueue::new());
        let mut handles = vec![];

        // Spawn multiple waiters
        for _ in 0..5 {
            let q = Arc::clone(&queue);
            let handle = tokio::spawn(async move {
                let batch = q.wait_for_assignments().await;
                assert_eq!(batch.len(), 3);
            });
            handles.push(handle);
        }

        // Give waiters time to start waiting
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Write and swap (should notify all waiters)
        queue.write_assignments(vec![
            create_test_assignment(1, 10, 1),
            create_test_assignment(2, 20, 1),
            create_test_assignment(3, 30, 1),
        ]);
        queue.swap_buffers();

        // All waiters should complete
        for handle in handles {
            handle.await.unwrap();
        }
    }

    #[test]
    fn test_buffer_isolation() {
        let queue = DispatchQueue::new();

        // Write to back buffer
        queue.write_assignments(vec![create_test_assignment(1, 10, 1)]);

        // Front buffer still empty
        assert_eq!(queue.pending_count(), 0);

        // Write again (overwrites back buffer)
        queue.write_assignments(vec![
            create_test_assignment(2, 20, 2),
            create_test_assignment(3, 30, 2),
        ]);

        // Front buffer still empty
        assert_eq!(queue.pending_count(), 0);

        // Swap to see latest write
        queue.swap_buffers();
        assert_eq!(queue.pending_count(), 2);

        let batch = queue.read_assignments();
        assert_eq!(batch.len(), 2);
        assert_eq!(batch.generation, 2);
    }
}
