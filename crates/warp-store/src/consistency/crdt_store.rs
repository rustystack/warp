//! CRDT-based Eventually Consistent Store
//!
//! Provides conflict-free replication for multi-site active-active deployments.
//! Uses CRDTs (Conflict-free Replicated Data Types) to enable concurrent writes
//! across multiple sites without coordination.
//!
//! # Consistency Models
//!
//! - **Strong (Raft)**: Linearizable, single-leader - use for metadata
//! - **Eventual (CRDT)**: Conflict-free merge - use for data, counters, sets
//!
//! # Supported CRDT Types
//!
//! - `LWWRegister<T>`: Last-Write-Wins register for single values
//! - `ORSet<T>`: Observed-Remove Set for collections
//! - `GCounter`: Grow-only counter
//! - `PNCounter`: Positive-Negative counter (supports decrement)
//! - `HLC`: Hybrid Logical Clock for distributed ordering

#![cfg(feature = "crdt")]

use std::collections::HashMap;
use std::sync::Arc;

use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, trace, warn};

use warp_crdt::{CrdtMerge, GCounter, HLC, LWWRegister, MergeStats, NodeId, ORSet, PNCounter};

use crate::ObjectKey;
use crate::error::{Error, Result};

/// CRDT-based store for eventually consistent data
///
/// This store complements the Raft-based store by providing conflict-free
/// replication for data that can tolerate eventual consistency.
pub struct CrdtStore {
    /// This node's ID
    node_id: NodeId,
    /// Hybrid Logical Clock for this node
    clock: RwLock<HLC>,
    /// LWW registers for object data references
    registers: DashMap<String, LWWRegister<ObjectDataRef>>,
    /// OR-Sets for tags/collections
    sets: DashMap<String, ORSet<String>>,
    /// G-Counters for metrics
    g_counters: DashMap<String, GCounter>,
    /// PN-Counters for bidirectional counters
    pn_counters: DashMap<String, PNCounter>,
    /// Pending merges from remote nodes
    pending_merges: RwLock<Vec<CrdtDelta>>,
    /// Statistics
    stats: CrdtStoreStats,
}

/// Reference to object data stored elsewhere
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectDataRef {
    /// Object key
    pub key: String,
    /// Content hash (for deduplication)
    pub content_hash: [u8; 32],
    /// Size in bytes
    pub size: u64,
    /// Storage locations (node IDs)
    pub locations: Vec<NodeId>,
    /// Custom metadata
    pub metadata: HashMap<String, String>,
}

impl Default for ObjectDataRef {
    fn default() -> Self {
        Self {
            key: String::new(),
            content_hash: [0; 32],
            size: 0,
            locations: Vec::new(),
            metadata: HashMap::new(),
        }
    }
}

/// Delta containing CRDT updates to sync
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CrdtDelta {
    /// LWW Register update
    Register {
        key: String,
        value: ObjectDataRef,
        timestamp: HLC,
    },
    /// ORSet add operation
    SetAdd {
        key: String,
        element: String,
        dot: (NodeId, u64),
    },
    /// ORSet remove operation
    SetRemove { key: String, element: String },
    /// GCounter increment
    GCounterIncrement {
        key: String,
        node_id: NodeId,
        value: u64,
    },
    /// PNCounter update
    PNCounterUpdate {
        key: String,
        node_id: NodeId,
        positive: u64,
        negative: u64,
    },
    /// Full state for initial sync
    FullState {
        registers: Vec<(String, ObjectDataRef, HLC)>,
        sets: Vec<(String, Vec<(String, (NodeId, u64))>)>,
        g_counters: Vec<(String, Vec<(NodeId, u64)>)>,
        pn_counters: Vec<(String, Vec<(NodeId, u64)>, Vec<(NodeId, u64)>)>,
    },
}

/// Statistics for the CRDT store
#[derive(Debug, Default)]
pub struct CrdtStoreStats {
    /// Total merges performed
    pub merges: std::sync::atomic::AtomicU64,
    /// Total conflicts resolved
    pub conflicts_resolved: std::sync::atomic::AtomicU64,
    /// Total register operations
    pub register_ops: std::sync::atomic::AtomicU64,
    /// Total set operations
    pub set_ops: std::sync::atomic::AtomicU64,
    /// Total counter operations
    pub counter_ops: std::sync::atomic::AtomicU64,
}

impl CrdtStore {
    /// Create a new CRDT store for the given node
    pub fn new(node_id: NodeId) -> Self {
        info!(node_id, "Creating CRDT store");
        Self {
            node_id,
            clock: RwLock::new(HLC::new(node_id)),
            registers: DashMap::new(),
            sets: DashMap::new(),
            g_counters: DashMap::new(),
            pn_counters: DashMap::new(),
            pending_merges: RwLock::new(Vec::new()),
            stats: CrdtStoreStats::default(),
        }
    }

    /// Get this node's ID
    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Get the current clock value
    pub fn current_time(&self) -> HLC {
        self.clock.read().clone()
    }

    // =========================================================================
    // LWW Register Operations
    // =========================================================================

    /// Put an object reference (LWW semantics)
    pub fn put(&self, key: &ObjectKey, data_ref: ObjectDataRef) -> HLC {
        let key_str = key.to_string();
        let mut clock = self.clock.write();
        let timestamp = clock.tick();

        self.registers
            .entry(key_str.clone())
            .and_modify(|reg| {
                reg.set(data_ref.clone(), &mut *clock);
            })
            .or_insert_with(|| LWWRegister::from_parts(data_ref.clone(), timestamp));

        self.stats
            .register_ops
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        debug!(key = %key, "Put object reference");
        timestamp
    }

    /// Get an object reference
    pub fn get(&self, key: &ObjectKey) -> Option<ObjectDataRef> {
        let key_str = key.to_string();
        self.registers.get(&key_str).map(|reg| reg.get().clone())
    }

    /// Delete an object reference (tombstone with empty ref)
    pub fn delete(&self, key: &ObjectKey) -> HLC {
        self.put(key, ObjectDataRef::default())
    }

    /// Check if object exists and is not a tombstone
    pub fn exists(&self, key: &ObjectKey) -> bool {
        self.get(key).map(|r| !r.key.is_empty()).unwrap_or(false)
    }

    // =========================================================================
    // ORSet Operations (for tags, collections)
    // =========================================================================

    /// Add an element to a set
    pub fn set_add(&self, set_key: &str, element: String) {
        self.sets
            .entry(set_key.to_string())
            .and_modify(|set| {
                set.add(element.clone());
            })
            .or_insert_with(|| {
                let mut set = ORSet::new(self.node_id);
                set.add(element);
                set
            });

        self.stats
            .set_ops
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        trace!(set_key, "Added element to set");
    }

    /// Remove an element from a set
    pub fn set_remove(&self, set_key: &str, element: &str) {
        if let Some(mut set) = self.sets.get_mut(set_key) {
            set.remove(element);
            self.stats
                .set_ops
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            trace!(set_key, "Removed element from set");
        }
    }

    /// Check if set contains element
    pub fn set_contains(&self, set_key: &str, element: &str) -> bool {
        self.sets
            .get(set_key)
            .map(|set| set.contains(element))
            .unwrap_or(false)
    }

    /// Get all elements in a set
    pub fn set_elements(&self, set_key: &str) -> Vec<String> {
        self.sets
            .get(set_key)
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Get set cardinality
    pub fn set_size(&self, set_key: &str) -> usize {
        self.sets.get(set_key).map(|set| set.len()).unwrap_or(0)
    }

    // =========================================================================
    // Counter Operations
    // =========================================================================

    /// Increment a grow-only counter
    pub fn g_counter_increment(&self, key: &str) {
        self.g_counter_increment_by(key, 1);
    }

    /// Increment a grow-only counter by amount
    pub fn g_counter_increment_by(&self, key: &str, amount: u64) {
        self.g_counters
            .entry(key.to_string())
            .and_modify(|counter| {
                counter.increment_by(amount);
            })
            .or_insert_with(|| {
                let mut counter = GCounter::new(self.node_id);
                counter.increment_by(amount);
                counter
            });

        self.stats
            .counter_ops
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        trace!(key, amount, "Incremented g-counter");
    }

    /// Get g-counter value
    pub fn g_counter_value(&self, key: &str) -> u64 {
        match self.g_counters.get(key) {
            Some(counter) => GCounter::value(&counter),
            None => 0,
        }
    }

    /// Increment a PN-counter (positive)
    pub fn pn_counter_increment(&self, key: &str) {
        self.pn_counters
            .entry(key.to_string())
            .and_modify(|counter| {
                counter.increment();
            })
            .or_insert_with(|| {
                let mut counter = PNCounter::new(self.node_id);
                counter.increment();
                counter
            });

        self.stats
            .counter_ops
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Decrement a PN-counter (negative)
    pub fn pn_counter_decrement(&self, key: &str) {
        self.pn_counters
            .entry(key.to_string())
            .and_modify(|counter| {
                counter.decrement();
            })
            .or_insert_with(|| {
                let mut counter = PNCounter::new(self.node_id);
                counter.decrement();
                counter
            });

        self.stats
            .counter_ops
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Get PN-counter value (may be negative)
    pub fn pn_counter_value(&self, key: &str) -> i64 {
        match self.pn_counters.get(key) {
            Some(counter) => PNCounter::value(&counter),
            None => 0,
        }
    }

    // =========================================================================
    // Replication / Merge Operations
    // =========================================================================

    /// Apply a delta from a remote node
    pub fn apply_delta(&self, delta: CrdtDelta) -> MergeStats {
        let mut stats = MergeStats::default();

        match delta {
            CrdtDelta::Register {
                key,
                value,
                timestamp,
            } => {
                let mut clock = self.clock.write();
                clock.receive(&timestamp);

                self.registers
                    .entry(key.clone())
                    .and_modify(|reg| {
                        if reg.set_with_timestamp(value.clone(), timestamp) {
                            stats.elements_updated = 1;
                            stats.conflicts_resolved = 1;
                        }
                    })
                    .or_insert_with(|| {
                        stats.elements_added = 1;
                        LWWRegister::from_parts(value, timestamp)
                    });
            }

            CrdtDelta::SetAdd {
                key,
                element,
                dot: _,
            } => {
                self.sets
                    .entry(key.clone())
                    .and_modify(|set| {
                        if !set.contains(&element) {
                            set.add(element.clone());
                            stats.elements_added = 1;
                        }
                    })
                    .or_insert_with(|| {
                        let mut set = ORSet::new(self.node_id);
                        set.add(element);
                        stats.elements_added = 1;
                        set
                    });
            }

            CrdtDelta::SetRemove { key, element } => {
                if let Some(mut set) = self.sets.get_mut(&key) {
                    if set.contains(&element) {
                        set.remove(&element);
                        stats.elements_removed = 1;
                    }
                }
            }

            CrdtDelta::GCounterIncrement {
                key,
                node_id,
                value,
            } => {
                self.g_counters
                    .entry(key.clone())
                    .and_modify(|counter| {
                        // Merge remote state
                        let mut remote = GCounter::new(node_id);
                        remote.increment_by(value);
                        counter.merge(&remote);
                        stats.elements_updated = 1;
                    })
                    .or_insert_with(|| {
                        let mut counter = GCounter::new(node_id);
                        counter.increment_by(value);
                        stats.elements_added = 1;
                        counter
                    });
            }

            CrdtDelta::PNCounterUpdate {
                key,
                node_id,
                positive,
                negative,
            } => {
                self.pn_counters
                    .entry(key.clone())
                    .and_modify(|counter| {
                        let mut remote = PNCounter::new(node_id);
                        remote.increment_by(positive);
                        remote.decrement_by(negative);
                        counter.merge(&remote);
                        stats.elements_updated = 1;
                    })
                    .or_insert_with(|| {
                        let mut counter = PNCounter::new(node_id);
                        counter.increment_by(positive);
                        counter.decrement_by(negative);
                        stats.elements_added = 1;
                        counter
                    });
            }

            CrdtDelta::FullState {
                registers,
                sets,
                g_counters,
                pn_counters,
            } => {
                // Apply full state (for initial sync)
                for (key, value, timestamp) in registers {
                    let delta = CrdtDelta::Register {
                        key,
                        value,
                        timestamp,
                    };
                    let s = self.apply_delta(delta);
                    stats.elements_added += s.elements_added;
                    stats.elements_updated += s.elements_updated;
                    stats.conflicts_resolved += s.conflicts_resolved;
                }

                for (key, elements) in sets {
                    for (element, dot) in elements {
                        let delta = CrdtDelta::SetAdd {
                            key: key.clone(),
                            element,
                            dot,
                        };
                        let s = self.apply_delta(delta);
                        stats.elements_added += s.elements_added;
                    }
                }

                for (key, counts) in g_counters {
                    for (node_id, value) in counts {
                        let delta = CrdtDelta::GCounterIncrement {
                            key: key.clone(),
                            node_id,
                            value,
                        };
                        let s = self.apply_delta(delta);
                        stats.elements_added += s.elements_added;
                        stats.elements_updated += s.elements_updated;
                    }
                }

                for (key, positive_counts, negative_counts) in pn_counters {
                    for (node_id, positive) in positive_counts {
                        let negative = negative_counts
                            .iter()
                            .find(|(n, _)| *n == node_id)
                            .map(|(_, v)| *v)
                            .unwrap_or(0);
                        let delta = CrdtDelta::PNCounterUpdate {
                            key: key.clone(),
                            node_id,
                            positive,
                            negative,
                        };
                        let s = self.apply_delta(delta);
                        stats.elements_added += s.elements_added;
                        stats.elements_updated += s.elements_updated;
                    }
                }
            }
        }

        self.stats
            .merges
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.stats.conflicts_resolved.fetch_add(
            stats.conflicts_resolved as u64,
            std::sync::atomic::Ordering::Relaxed,
        );

        stats
    }

    /// Generate delta for sync
    pub fn generate_delta(&self, since: Option<HLC>) -> CrdtDelta {
        // For now, return full state
        // A more sophisticated implementation would track deltas since a given timestamp
        let registers: Vec<_> = self
            .registers
            .iter()
            .map(|entry| {
                let reg = entry.value();
                (entry.key().clone(), reg.get().clone(), *reg.timestamp())
            })
            .collect();

        let sets: Vec<_> = self
            .sets
            .iter()
            .map(|entry| {
                let elements: Vec<_> = entry
                    .value()
                    .iter()
                    .map(|e| (e.clone(), (self.node_id, 0))) // Simplified dot
                    .collect();
                (entry.key().clone(), elements)
            })
            .collect();

        let g_counters: Vec<_> = self
            .g_counters
            .iter()
            .map(|entry| {
                let counts = vec![(entry.value().node_id(), entry.value().local_value())];
                (entry.key().clone(), counts)
            })
            .collect();

        let pn_counters: Vec<_> = self
            .pn_counters
            .iter()
            .map(|entry| {
                let counter = entry.value();
                let positive = vec![(counter.node_id(), counter.total_increments())];
                let negative = vec![(counter.node_id(), counter.total_decrements())];
                (entry.key().clone(), positive, negative)
            })
            .collect();

        CrdtDelta::FullState {
            registers,
            sets,
            g_counters,
            pn_counters,
        }
    }

    /// Get statistics
    pub fn stats(&self) -> CrdtStoreStatsSnapshot {
        CrdtStoreStatsSnapshot {
            merges: self.stats.merges.load(std::sync::atomic::Ordering::Relaxed),
            conflicts_resolved: self
                .stats
                .conflicts_resolved
                .load(std::sync::atomic::Ordering::Relaxed),
            register_ops: self
                .stats
                .register_ops
                .load(std::sync::atomic::Ordering::Relaxed),
            set_ops: self
                .stats
                .set_ops
                .load(std::sync::atomic::Ordering::Relaxed),
            counter_ops: self
                .stats
                .counter_ops
                .load(std::sync::atomic::Ordering::Relaxed),
            registers_count: self.registers.len(),
            sets_count: self.sets.len(),
            g_counters_count: self.g_counters.len(),
            pn_counters_count: self.pn_counters.len(),
        }
    }
}

/// Snapshot of CRDT store statistics
#[derive(Debug, Clone)]
pub struct CrdtStoreStatsSnapshot {
    /// Total merges performed
    pub merges: u64,
    /// Total conflicts resolved
    pub conflicts_resolved: u64,
    /// Total register operations
    pub register_ops: u64,
    /// Total set operations
    pub set_ops: u64,
    /// Total counter operations
    pub counter_ops: u64,
    /// Number of registers
    pub registers_count: usize,
    /// Number of sets
    pub sets_count: usize,
    /// Number of g-counters
    pub g_counters_count: usize,
    /// Number of pn-counters
    pub pn_counters_count: usize,
}

/// Builder for configuring CRDT replication
pub struct CrdtReplicationConfig {
    /// Sync interval in milliseconds
    pub sync_interval_ms: u64,
    /// Maximum batch size for deltas
    pub max_batch_size: usize,
    /// Enable anti-entropy protocol
    pub enable_anti_entropy: bool,
    /// Peer nodes to sync with
    pub peers: Vec<(NodeId, String)>,
}

impl Default for CrdtReplicationConfig {
    fn default() -> Self {
        Self {
            sync_interval_ms: 1000,
            max_batch_size: 1000,
            enable_anti_entropy: true,
            peers: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crdt_store_creation() {
        let store = CrdtStore::new(1);
        assert_eq!(store.node_id(), 1);
    }

    #[test]
    fn test_lww_register_operations() {
        let store = CrdtStore::new(1);
        let key = ObjectKey::new("bucket", "test-object").unwrap();

        let data_ref = ObjectDataRef {
            key: "bucket/test-object".to_string(),
            content_hash: [0; 32],
            size: 1024,
            locations: vec![1],
            metadata: HashMap::new(),
        };

        store.put(&key, data_ref.clone());
        assert!(store.exists(&key));

        let retrieved = store.get(&key).unwrap();
        assert_eq!(retrieved.size, 1024);

        store.delete(&key);
        assert!(!store.exists(&key));
    }

    #[test]
    fn test_orset_operations() {
        let store = CrdtStore::new(1);

        store.set_add("tags", "important".to_string());
        store.set_add("tags", "archived".to_string());

        assert!(store.set_contains("tags", "important"));
        assert!(store.set_contains("tags", "archived"));
        assert!(!store.set_contains("tags", "deleted"));
        assert_eq!(store.set_size("tags"), 2);

        store.set_remove("tags", "archived");
        assert!(!store.set_contains("tags", "archived"));
        assert_eq!(store.set_size("tags"), 1);
    }

    #[test]
    fn test_g_counter_operations() {
        let store = CrdtStore::new(1);

        store.g_counter_increment("requests");
        store.g_counter_increment("requests");
        store.g_counter_increment_by("requests", 5);

        assert_eq!(store.g_counter_value("requests"), 7);
    }

    #[test]
    fn test_pn_counter_operations() {
        let store = CrdtStore::new(1);

        store.pn_counter_increment("balance");
        store.pn_counter_increment("balance");
        store.pn_counter_decrement("balance");

        assert_eq!(store.pn_counter_value("balance"), 1);

        // Test negative
        store.pn_counter_decrement("balance");
        store.pn_counter_decrement("balance");
        assert_eq!(store.pn_counter_value("balance"), -1);
    }

    #[test]
    fn test_delta_application() {
        let store1 = CrdtStore::new(1);
        let store2 = CrdtStore::new(2);

        // Store 1 writes
        let key = ObjectKey::new("bucket", "shared").unwrap();
        let data_ref = ObjectDataRef {
            key: "bucket/shared".to_string(),
            content_hash: [1; 32],
            size: 2048,
            locations: vec![1],
            metadata: HashMap::new(),
        };
        let timestamp = store1.put(&key, data_ref);

        // Generate delta and apply to store 2
        let delta = CrdtDelta::Register {
            key: key.to_string(),
            value: ObjectDataRef {
                key: "bucket/shared".to_string(),
                content_hash: [1; 32],
                size: 2048,
                locations: vec![1],
                metadata: HashMap::new(),
            },
            timestamp,
        };

        let stats = store2.apply_delta(delta);
        assert_eq!(stats.elements_added, 1);

        // Verify store 2 has the data
        let retrieved = store2.get(&key).unwrap();
        assert_eq!(retrieved.size, 2048);
    }

    #[test]
    fn test_concurrent_writes_merge() {
        let store1 = CrdtStore::new(1);
        let store2 = CrdtStore::new(2);

        let key = ObjectKey::new("bucket", "conflict").unwrap();

        // Both stores write concurrently
        let data_ref1 = ObjectDataRef {
            key: "bucket/conflict".to_string(),
            content_hash: [1; 32],
            size: 100,
            locations: vec![1],
            metadata: HashMap::new(),
        };
        let ts1 = store1.put(&key, data_ref1);

        std::thread::sleep(std::time::Duration::from_millis(2));

        let data_ref2 = ObjectDataRef {
            key: "bucket/conflict".to_string(),
            content_hash: [2; 32],
            size: 200,
            locations: vec![2],
            metadata: HashMap::new(),
        };
        let ts2 = store2.put(&key, data_ref2.clone());

        // Apply store2's delta to store1 (store2 wins due to later timestamp)
        let delta = CrdtDelta::Register {
            key: key.to_string(),
            value: data_ref2,
            timestamp: ts2,
        };
        store1.apply_delta(delta);

        // Both should converge to store2's value
        assert_eq!(store1.get(&key).unwrap().size, 200);
        assert_eq!(store2.get(&key).unwrap().size, 200);
    }

    #[test]
    fn test_generate_delta() {
        let store = CrdtStore::new(1);

        // Add some data
        let key = ObjectKey::new("bucket", "test").unwrap();
        store.put(
            &key,
            ObjectDataRef {
                key: "bucket/test".to_string(),
                content_hash: [0; 32],
                size: 100,
                locations: vec![1],
                metadata: HashMap::new(),
            },
        );

        store.set_add("tags", "test".to_string());
        store.g_counter_increment("count");

        // Generate delta
        let delta = store.generate_delta(None);

        match delta {
            CrdtDelta::FullState {
                registers,
                sets,
                g_counters,
                ..
            } => {
                assert_eq!(registers.len(), 1);
                assert_eq!(sets.len(), 1);
                assert_eq!(g_counters.len(), 1);
            }
            _ => panic!("Expected FullState delta"),
        }
    }

    #[test]
    fn test_stats() {
        let store = CrdtStore::new(1);

        let key = ObjectKey::new("bucket", "test").unwrap();
        store.put(&key, ObjectDataRef::default());
        store.set_add("tags", "test".to_string());
        store.g_counter_increment("count");

        let stats = store.stats();
        assert_eq!(stats.register_ops, 1);
        assert_eq!(stats.set_ops, 1);
        assert_eq!(stats.counter_ops, 1);
        assert_eq!(stats.registers_count, 1);
        assert_eq!(stats.sets_count, 1);
        assert_eq!(stats.g_counters_count, 1);
    }
}
