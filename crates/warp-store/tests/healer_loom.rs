//! Loom-based concurrency tests for the Healer repair queue
//!
//! These tests use loom to exhaustively check all possible interleavings
//! of concurrent operations on the repair queue.

use loom::sync::atomic::{AtomicU64, Ordering};
use loom::sync::Arc;
use loom::thread;
use std::collections::VecDeque;

/// Simplified ShardKey for loom testing (loom doesn't support all std types)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ShardKey {
    key: String,
    shard: u32,
}

impl ShardKey {
    fn new(key: &str, shard: u32) -> Self {
        Self {
            key: key.to_string(),
            shard,
        }
    }
}

/// Simplified repair priority for testing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RepairPriority {
    Critical,
    High,
    Normal,
    Low,
}

/// Simplified repair job for loom testing
#[derive(Debug, Clone)]
struct RepairJob {
    id: u64,
    shard_key: ShardKey,
    priority: RepairPriority,
}

impl RepairJob {
    fn new(id: u64, shard_key: ShardKey, priority: RepairPriority) -> Self {
        Self {
            id,
            shard_key,
            priority,
        }
    }
}

/// Simplified repair queue using loom primitives
struct LoomRepairQueue {
    queue: loom::sync::Mutex<VecDeque<RepairJob>>,
    total_enqueued: AtomicU64,
    total_dequeued: AtomicU64,
}

impl LoomRepairQueue {
    fn new() -> Self {
        Self {
            queue: loom::sync::Mutex::new(VecDeque::new()),
            total_enqueued: AtomicU64::new(0),
            total_dequeued: AtomicU64::new(0),
        }
    }

    fn push(&self, job: RepairJob) {
        let mut queue = self.queue.lock().unwrap();
        queue.push_back(job);
        self.total_enqueued.fetch_add(1, Ordering::SeqCst);
    }

    fn pop(&self) -> Option<RepairJob> {
        let mut queue = self.queue.lock().unwrap();
        let job = queue.pop_front();
        if job.is_some() {
            self.total_dequeued.fetch_add(1, Ordering::SeqCst);
        }
        job
    }

    fn len(&self) -> usize {
        self.queue.lock().unwrap().len()
    }

    fn total_enqueued(&self) -> u64 {
        self.total_enqueued.load(Ordering::SeqCst)
    }

    fn total_dequeued(&self) -> u64 {
        self.total_dequeued.load(Ordering::SeqCst)
    }
}

#[test]
fn test_concurrent_enqueue() {
    loom::model(|| {
        let queue = Arc::new(LoomRepairQueue::new());

        let q1 = queue.clone();
        let t1 = thread::spawn(move || {
            q1.push(RepairJob::new(
                1,
                ShardKey::new("key1", 0),
                RepairPriority::Critical,
            ));
        });

        let q2 = queue.clone();
        let t2 = thread::spawn(move || {
            q2.push(RepairJob::new(
                2,
                ShardKey::new("key2", 0),
                RepairPriority::High,
            ));
        });

        t1.join().unwrap();
        t2.join().unwrap();

        // Both jobs should be enqueued
        assert_eq!(queue.len(), 2);
        assert_eq!(queue.total_enqueued(), 2);
    });
}

#[test]
fn test_concurrent_dequeue() {
    loom::model(|| {
        let queue = Arc::new(LoomRepairQueue::new());

        // Pre-populate queue
        queue.push(RepairJob::new(
            1,
            ShardKey::new("key1", 0),
            RepairPriority::Normal,
        ));
        queue.push(RepairJob::new(
            2,
            ShardKey::new("key2", 0),
            RepairPriority::Normal,
        ));

        let q1 = queue.clone();
        let t1 = thread::spawn(move || q1.pop());

        let q2 = queue.clone();
        let t2 = thread::spawn(move || q2.pop());

        let result1 = t1.join().unwrap();
        let result2 = t2.join().unwrap();

        // Both threads should get a job (no double-dequeue)
        assert!(result1.is_some());
        assert!(result2.is_some());
        assert!(queue.pop().is_none());
        assert_eq!(queue.total_dequeued(), 2);
    });
}

#[test]
fn test_concurrent_enqueue_dequeue() {
    loom::model(|| {
        let queue = Arc::new(LoomRepairQueue::new());

        // Start with one job
        queue.push(RepairJob::new(
            1,
            ShardKey::new("key1", 0),
            RepairPriority::Critical,
        ));

        let q1 = queue.clone();
        let t1 = thread::spawn(move || {
            q1.push(RepairJob::new(
                2,
                ShardKey::new("key2", 0),
                RepairPriority::High,
            ));
        });

        let q2 = queue.clone();
        let t2 = thread::spawn(move || q2.pop());

        t1.join().unwrap();
        let popped = t2.join().unwrap();

        // One job was popped
        assert!(popped.is_some());

        // Should have either 1 or 2 jobs enqueued total depending on ordering
        // Enqueue count should be 2 (initial + t1)
        // Dequeue count should be 1
        assert_eq!(queue.total_enqueued(), 2);
        assert_eq!(queue.total_dequeued(), 1);
    });
}

#[test]
fn test_stats_consistency() {
    loom::model(|| {
        let queue = Arc::new(LoomRepairQueue::new());

        let q1 = queue.clone();
        let t1 = thread::spawn(move || {
            q1.push(RepairJob::new(
                1,
                ShardKey::new("key1", 0),
                RepairPriority::Normal,
            ));
            q1.push(RepairJob::new(
                2,
                ShardKey::new("key2", 0),
                RepairPriority::Normal,
            ));
        });

        let q2 = queue.clone();
        let t2 = thread::spawn(move || {
            let _ = q2.pop();
        });

        t1.join().unwrap();
        t2.join().unwrap();

        // Stats should be consistent
        let enqueued = queue.total_enqueued();
        let dequeued = queue.total_dequeued();
        let len = queue.len();

        // len + dequeued should equal enqueued
        assert_eq!(len + dequeued as usize, enqueued as usize);
    });
}

/// Test that counter updates are atomic
#[test]
fn test_atomic_counter_increment() {
    loom::model(|| {
        let counter = Arc::new(AtomicU64::new(0));

        let c1 = counter.clone();
        let t1 = thread::spawn(move || {
            c1.fetch_add(1, Ordering::SeqCst);
        });

        let c2 = counter.clone();
        let t2 = thread::spawn(move || {
            c2.fetch_add(1, Ordering::SeqCst);
        });

        t1.join().unwrap();
        t2.join().unwrap();

        assert_eq!(counter.load(Ordering::SeqCst), 2);
    });
}
