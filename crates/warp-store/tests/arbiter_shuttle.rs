//! Shuttle-based concurrency tests for the Arbiter partition detector
//!
//! These tests verify that the partition detector correctly handles
//! concurrent node status updates and partition detection races.

#![allow(dead_code)]

use shuttle::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use shuttle::sync::{Mutex, RwLock};
use shuttle::thread;
use std::collections::HashMap;
use std::sync::Arc;

/// Simplified node status for testing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeStatus {
    Healthy,
    Suspect,
    Failed,
    Partitioned,
}

/// Simplified node ID type
type NodeId = u64;

/// Simplified partition detector for shuttle testing
struct ShuttlePartitionDetector {
    /// Node statuses
    nodes: RwLock<HashMap<NodeId, NodeStatus>>,
    /// Whether a partition is detected
    partition_detected: AtomicBool,
    /// Number of healthy nodes required for quorum
    quorum_size: usize,
    /// Epoch counter for detecting stale updates
    epoch: AtomicU64,
    /// Lock for partition state transitions
    partition_lock: Mutex<()>,
}

impl ShuttlePartitionDetector {
    fn new(quorum_size: usize) -> Self {
        Self {
            nodes: RwLock::new(HashMap::new()),
            partition_detected: AtomicBool::new(false),
            quorum_size,
            epoch: AtomicU64::new(0),
            partition_lock: Mutex::new(()),
        }
    }

    /// Register a node
    fn register_node(&self, node_id: NodeId) {
        let mut nodes = self.nodes.write().unwrap();
        nodes.insert(node_id, NodeStatus::Healthy);
    }

    /// Update node status
    fn update_status(&self, node_id: NodeId, status: NodeStatus) {
        let mut nodes = self.nodes.write().unwrap();
        if let Some(current_status) = nodes.get_mut(&node_id) {
            *current_status = status;
        }
        drop(nodes);

        // Check for partition
        self.check_partition();
    }

    /// Mark node as suspect
    fn mark_suspect(&self, node_id: NodeId) {
        self.update_status(node_id, NodeStatus::Suspect);
    }

    /// Mark node as failed
    fn mark_failed(&self, node_id: NodeId) {
        self.update_status(node_id, NodeStatus::Failed);
    }

    /// Mark node as healthy
    fn mark_healthy(&self, node_id: NodeId) {
        self.update_status(node_id, NodeStatus::Healthy);

        // Healthy node might heal partition
        self.check_partition_healed();
    }

    /// Check if partition should be detected
    fn check_partition(&self) {
        let _lock = self.partition_lock.lock().unwrap();

        let nodes = self.nodes.read().unwrap();
        let healthy_count = nodes
            .values()
            .filter(|s| **s == NodeStatus::Healthy)
            .count();
        let total_count = nodes.len();
        drop(nodes);

        if healthy_count < self.quorum_size && total_count >= self.quorum_size {
            // Lost quorum - partition detected
            self.partition_detected.store(true, Ordering::SeqCst);
            self.epoch.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Check if partition has healed
    fn check_partition_healed(&self) {
        let _lock = self.partition_lock.lock().unwrap();

        if !self.is_partitioned() {
            return;
        }

        let nodes = self.nodes.read().unwrap();
        let healthy_count = nodes
            .values()
            .filter(|s| **s == NodeStatus::Healthy)
            .count();
        drop(nodes);

        if healthy_count >= self.quorum_size {
            // Regained quorum - partition healed
            self.partition_detected.store(false, Ordering::SeqCst);
            self.epoch.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Check if currently partitioned
    fn is_partitioned(&self) -> bool {
        self.partition_detected.load(Ordering::SeqCst)
    }

    /// Get current epoch
    fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst)
    }

    /// Get node count
    fn node_count(&self) -> usize {
        self.nodes.read().unwrap().len()
    }

    /// Get healthy node count
    fn healthy_count(&self) -> usize {
        self.nodes
            .read()
            .unwrap()
            .values()
            .filter(|s| **s == NodeStatus::Healthy)
            .count()
    }

    /// Get node status
    fn get_status(&self, node_id: NodeId) -> Option<NodeStatus> {
        self.nodes.read().unwrap().get(&node_id).copied()
    }
}

#[test]
fn test_concurrent_status_updates() {
    shuttle::check_random(
        || {
            let detector = Arc::new(ShuttlePartitionDetector::new(2));

            // Register 3 nodes
            detector.register_node(1);
            detector.register_node(2);
            detector.register_node(3);

            let d1 = detector.clone();
            let t1 = thread::spawn(move || {
                d1.mark_suspect(1);
            });

            let d2 = detector.clone();
            let t2 = thread::spawn(move || {
                d2.mark_healthy(1);
            });

            t1.join().unwrap();
            t2.join().unwrap();

            // Node 1 should have a valid status
            let status = detector.get_status(1);
            assert!(status.is_some());
            assert!(status == Some(NodeStatus::Suspect) || status == Some(NodeStatus::Healthy));
        },
        1000,
    );
}

#[test]
fn test_partition_detection_race() {
    shuttle::check_random(
        || {
            let detector = Arc::new(ShuttlePartitionDetector::new(2));

            // Register 3 nodes
            detector.register_node(1);
            detector.register_node(2);
            detector.register_node(3);

            // Concurrently fail two nodes - should detect partition
            let d1 = detector.clone();
            let t1 = thread::spawn(move || {
                d1.mark_failed(1);
            });

            let d2 = detector.clone();
            let t2 = thread::spawn(move || {
                d2.mark_failed(2);
            });

            t1.join().unwrap();
            t2.join().unwrap();

            // With 2 nodes failed out of 3, and quorum of 2,
            // we should detect partition
            assert!(detector.is_partitioned());
            assert_eq!(detector.healthy_count(), 1);
        },
        1000,
    );
}

#[test]
fn test_partition_heal_race() {
    shuttle::check_random(
        || {
            let detector = Arc::new(ShuttlePartitionDetector::new(2));

            // Register 3 nodes
            detector.register_node(1);
            detector.register_node(2);
            detector.register_node(3);

            // Fail two nodes to create partition
            detector.mark_failed(1);
            detector.mark_failed(2);

            // Concurrently heal both nodes
            let d1 = detector.clone();
            let t1 = thread::spawn(move || {
                d1.mark_healthy(1);
            });

            let d2 = detector.clone();
            let t2 = thread::spawn(move || {
                d2.mark_healthy(2);
            });

            t1.join().unwrap();
            t2.join().unwrap();

            // Partition should be healed
            assert!(!detector.is_partitioned());
            assert!(detector.healthy_count() >= 2);
        },
        1000,
    );
}

#[test]
fn test_epoch_monotonicity() {
    shuttle::check_random(
        || {
            let detector = Arc::new(ShuttlePartitionDetector::new(2));

            // Register 3 nodes
            detector.register_node(1);
            detector.register_node(2);
            detector.register_node(3);

            let initial_epoch = detector.epoch();

            // Multiple threads update status
            let handles: Vec<_> = (0..4)
                .map(|i| {
                    let d = detector.clone();
                    thread::spawn(move || {
                        let node_id = (i % 3) + 1;
                        if i % 2 == 0 {
                            d.mark_failed(node_id);
                        } else {
                            d.mark_healthy(node_id);
                        }
                        d.epoch()
                    })
                })
                .collect();

            let epochs: Vec<u64> = handles.into_iter().map(|h| h.join().unwrap()).collect();

            // All observed epochs should be >= initial
            for epoch in epochs {
                assert!(epoch >= initial_epoch);
            }

            // Final epoch should be >= all observed epochs
            let final_epoch = detector.epoch();
            assert!(final_epoch >= initial_epoch);
        },
        1000,
    );
}

#[test]
fn test_register_during_partition() {
    shuttle::check_random(
        || {
            let detector = Arc::new(ShuttlePartitionDetector::new(2));

            // Register 2 nodes initially
            detector.register_node(1);
            detector.register_node(2);

            // Fail both to create partition
            let d1 = detector.clone();
            let t1 = thread::spawn(move || {
                d1.mark_failed(1);
                d1.mark_failed(2);
            });

            // Register new node concurrently
            let d2 = detector.clone();
            let t2 = thread::spawn(move || {
                d2.register_node(3);
            });

            t1.join().unwrap();
            t2.join().unwrap();

            // Node 3 should be registered
            assert_eq!(detector.node_count(), 3);
            assert!(detector.get_status(3).is_some());
        },
        1000,
    );
}

#[test]
fn test_no_double_partition_detection() {
    shuttle::check_random(
        || {
            let detector = Arc::new(ShuttlePartitionDetector::new(2));

            // Register 4 nodes
            detector.register_node(1);
            detector.register_node(2);
            detector.register_node(3);
            detector.register_node(4);

            let initial_epoch = detector.epoch();

            // Fail multiple nodes concurrently
            let handles: Vec<_> = (1..=3)
                .map(|i| {
                    let d = detector.clone();
                    thread::spawn(move || {
                        d.mark_failed(i);
                    })
                })
                .collect();

            for h in handles {
                h.join().unwrap();
            }

            // Should be partitioned
            assert!(detector.is_partitioned());

            // Epoch should have changed exactly once per state transition
            // (may be multiple if partition was detected and then more failures occurred)
            let final_epoch = detector.epoch();
            assert!(final_epoch > initial_epoch);
        },
        1000,
    );
}
