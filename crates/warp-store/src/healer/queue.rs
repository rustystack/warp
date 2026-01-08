//! Repair job queue with priority ordering

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::time::Instant;

use dashmap::DashSet;
use parking_lot::Mutex;

use crate::replication::ShardKey;

/// Priority level for repair jobs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum RepairPriority {
    /// Critical - data at risk of permanent loss
    Critical = 0,
    /// High - multiple shards degraded
    High = 1,
    /// Normal - single shard issue
    #[default]
    Normal = 2,
    /// Low - proactive/predictive repair
    Low = 3,
}

impl RepairPriority {
    /// Get numeric priority (lower = more urgent)
    pub fn value(&self) -> u8 {
        *self as u8
    }
}

/// A repair job in the queue
#[derive(Debug, Clone)]
pub struct RepairJob {
    /// Unique job ID
    pub id: u64,

    /// The shard to repair
    pub shard_key: ShardKey,

    /// Priority level
    pub priority: RepairPriority,

    /// When the job was created
    pub created_at: Instant,

    /// Number of retry attempts
    pub retry_count: u32,

    /// Maximum retries before giving up
    pub max_retries: u32,
}

impl RepairJob {
    /// Create a new repair job
    pub fn new(shard_key: ShardKey, priority: RepairPriority) -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);

        Self {
            id: NEXT_ID.fetch_add(1, AtomicOrdering::SeqCst),
            shard_key,
            priority,
            created_at: Instant::now(),
            retry_count: 0,
            max_retries: 3,
        }
    }

    /// Check if job can be retried
    pub fn can_retry(&self) -> bool {
        debug_assert!(
            self.max_retries > 0,
            "max_retries should be positive, got {}",
            self.max_retries
        );
        self.retry_count < self.max_retries
    }

    /// Increment retry count
    pub fn increment_retry(&mut self) {
        self.retry_count += 1;
    }

    /// Get age of the job
    pub fn age(&self) -> std::time::Duration {
        self.created_at.elapsed()
    }
}

// Implement ordering for BinaryHeap (max-heap, so we invert priority)
impl PartialEq for RepairJob {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for RepairJob {}

impl PartialOrd for RepairJob {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RepairJob {
    fn cmp(&self, other: &Self) -> Ordering {
        // Lower priority value = higher urgency = should come first
        // BinaryHeap is max-heap, so we reverse the comparison
        match other.priority.value().cmp(&self.priority.value()) {
            Ordering::Equal => {
                // Same priority: older jobs first (FIFO within priority)
                other.created_at.cmp(&self.created_at)
            }
            ord => ord,
        }
    }
}

/// Thread-safe priority queue for repair jobs
pub struct RepairQueue {
    /// The priority queue
    heap: Mutex<BinaryHeap<RepairJob>>,

    /// Set of shard keys currently in queue (for deduplication)
    in_queue: DashSet<ShardKey>,

    /// Total jobs ever enqueued
    total_enqueued: AtomicU64,

    /// Total jobs completed
    total_completed: AtomicU64,

    /// Total jobs failed
    total_failed: AtomicU64,
}

impl RepairQueue {
    /// Create a new repair queue
    pub fn new() -> Self {
        Self {
            heap: Mutex::new(BinaryHeap::new()),
            in_queue: DashSet::new(),
            total_enqueued: AtomicU64::new(0),
            total_completed: AtomicU64::new(0),
            total_failed: AtomicU64::new(0),
        }
    }

    /// Push a job onto the queue
    pub fn push(&self, job: RepairJob) {
        let key = job.shard_key.clone();

        // Deduplicate
        if self.in_queue.insert(key.clone()) {
            self.heap.lock().push(job);
            self.total_enqueued.fetch_add(1, AtomicOrdering::Relaxed);
        }
    }

    /// Pop the highest priority job
    pub fn pop(&self) -> Option<RepairJob> {
        let job = self.heap.lock().pop()?;
        self.in_queue.remove(&job.shard_key);
        Some(job)
    }

    /// Peek at the highest priority job without removing
    pub fn peek(&self) -> Option<RepairJob> {
        self.heap.lock().peek().cloned()
    }

    /// Check if a shard key is in the queue
    pub fn contains(&self, key: &ShardKey) -> bool {
        self.in_queue.contains(key)
    }

    /// Get current queue length
    pub fn len(&self) -> usize {
        self.heap.lock().len()
    }

    /// Check if queue is empty
    pub fn is_empty(&self) -> bool {
        self.heap.lock().is_empty()
    }

    /// Clear the queue
    pub fn clear(&self) {
        self.heap.lock().clear();
        self.in_queue.clear();
    }

    /// Re-queue a failed job with incremented retry count
    pub fn requeue(&self, mut job: RepairJob) {
        job.increment_retry();
        if job.can_retry() {
            // Demote priority on retry
            job.priority = match job.priority {
                RepairPriority::Critical => RepairPriority::High,
                RepairPriority::High => RepairPriority::Normal,
                _ => RepairPriority::Low,
            };
            self.push(job);
        } else {
            self.total_failed.fetch_add(1, AtomicOrdering::Relaxed);
        }
    }

    /// Mark a job as completed
    pub fn mark_completed(&self) {
        self.total_completed.fetch_add(1, AtomicOrdering::Relaxed);
    }

    /// Get queue statistics
    pub fn stats(&self) -> QueueStats {
        QueueStats {
            current_size: self.len(),
            total_enqueued: self.total_enqueued.load(AtomicOrdering::Relaxed),
            total_completed: self.total_completed.load(AtomicOrdering::Relaxed),
            total_failed: self.total_failed.load(AtomicOrdering::Relaxed),
        }
    }
}

impl Default for RepairQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Queue statistics
#[derive(Debug, Clone, Default)]
pub struct QueueStats {
    /// Current number of jobs in queue
    pub current_size: usize,
    /// Total jobs ever enqueued
    pub total_enqueued: u64,
    /// Total jobs completed successfully
    pub total_completed: u64,
    /// Total jobs that failed permanently
    pub total_failed: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priority_ordering() {
        let queue = RepairQueue::new();

        // Add jobs with different priorities
        queue.push(RepairJob::new(
            ShardKey::new("bucket", "key1", 0),
            RepairPriority::Low,
        ));
        queue.push(RepairJob::new(
            ShardKey::new("bucket", "key2", 0),
            RepairPriority::Critical,
        ));
        queue.push(RepairJob::new(
            ShardKey::new("bucket", "key3", 0),
            RepairPriority::Normal,
        ));

        // Should pop in priority order
        assert_eq!(queue.pop().unwrap().shard_key.key, "key2"); // Critical
        assert_eq!(queue.pop().unwrap().shard_key.key, "key3"); // Normal
        assert_eq!(queue.pop().unwrap().shard_key.key, "key1"); // Low
    }

    #[test]
    fn test_deduplication() {
        let queue = RepairQueue::new();

        let key = ShardKey::new("bucket", "key", 0);
        queue.push(RepairJob::new(key.clone(), RepairPriority::Normal));
        queue.push(RepairJob::new(key.clone(), RepairPriority::Critical)); // Duplicate

        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn test_retry() {
        let queue = RepairQueue::new();

        let mut job = RepairJob::new(ShardKey::new("bucket", "key", 0), RepairPriority::Critical);

        assert!(job.can_retry());
        job.increment_retry();
        job.increment_retry();
        job.increment_retry();
        assert!(!job.can_retry());
    }
}
