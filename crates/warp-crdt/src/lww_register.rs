//! Last-Write-Wins Register (LWW-Register)
//!
//! A register that resolves concurrent writes using timestamps.
//! The write with the highest timestamp wins.
//!
//! # Use Cases
//!
//! - Configuration values
//! - User profiles
//! - Object metadata
//! - Any single-value state that can be overwritten

use crate::{CrdtMerge, HLC, MergeStats, NodeId};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

/// Last-Write-Wins Register
///
/// Stores a single value with a timestamp. When merged, the value
/// with the higher timestamp wins.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LWWRegister<T> {
    /// The current value
    value: T,
    /// Timestamp of when the value was set
    timestamp: HLC,
}

impl<T: Clone> LWWRegister<T> {
    /// Create a new register with the given value
    pub fn new(value: T, clock: &mut HLC) -> Self {
        Self {
            value,
            timestamp: clock.tick(),
        }
    }

    /// Create a register from raw components (for testing/deserialization)
    pub fn from_parts(value: T, timestamp: HLC) -> Self {
        Self { value, timestamp }
    }

    /// Get the current value
    pub fn get(&self) -> &T {
        &self.value
    }

    /// Get the current value mutably
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.value
    }

    /// Get the timestamp of the current value
    pub fn timestamp(&self) -> &HLC {
        &self.timestamp
    }

    /// Set a new value
    pub fn set(&mut self, value: T, clock: &mut HLC) {
        self.value = value;
        self.timestamp = clock.tick();
    }

    /// Set a new value with an explicit timestamp
    ///
    /// This is useful when applying operations from other nodes.
    /// Only updates if the new timestamp is greater.
    pub fn set_with_timestamp(&mut self, value: T, timestamp: HLC) -> bool {
        if timestamp > self.timestamp {
            self.value = value;
            self.timestamp = timestamp;
            true
        } else {
            false
        }
    }

    /// Merge with another register
    ///
    /// The value with the higher timestamp wins.
    pub fn merge(&mut self, other: &Self, clock: &mut HLC) {
        clock.receive(&other.timestamp);

        if other.timestamp > self.timestamp {
            self.value = other.value.clone();
            self.timestamp = other.timestamp;
        }
    }

    /// Check if this register would be overwritten by a merge with other
    pub fn would_be_overwritten(&self, other: &Self) -> bool {
        other.timestamp > self.timestamp
    }

    /// Get the node ID that last wrote this register
    pub fn last_writer(&self) -> NodeId {
        self.timestamp.node_id
    }
}

impl<T: Clone + Default> Default for LWWRegister<T> {
    fn default() -> Self {
        let mut clock = HLC::new(0);
        Self::new(T::default(), &mut clock)
    }
}

impl<T: Clone + PartialEq> PartialEq for LWWRegister<T> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value && self.timestamp == other.timestamp
    }
}

impl<T: Clone + Eq> Eq for LWWRegister<T> {}

impl<T: Clone> CrdtMerge for LWWRegister<T> {
    fn merge_from(&mut self, other: &Self) -> MergeStats {
        let changed = other.timestamp > self.timestamp;

        if changed {
            self.value = other.value.clone();
            self.timestamp = other.timestamp;
        }

        MergeStats {
            elements_added: if changed { 1 } else { 0 },
            elements_removed: 0,
            elements_updated: 0,
            conflicts_resolved: if changed { 1 } else { 0 },
        }
    }
}

/// A multi-value register that keeps all concurrent values
///
/// Unlike LWW-Register, this doesn't lose concurrent writes.
/// Useful when you need to see all values and resolve conflicts manually.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MVRegister<T> {
    /// Values with their timestamps
    values: Vec<(T, HLC)>,
}

impl<T: Clone + PartialEq> MVRegister<T> {
    /// Create an empty multi-value register
    pub fn new() -> Self {
        Self { values: Vec::new() }
    }

    /// Set a new value
    pub fn set(&mut self, value: T, clock: &mut HLC) {
        let timestamp = clock.tick();

        // Remove values that are dominated by this new timestamp
        self.values.retain(|(_, ts)| ts >= &timestamp);

        // Add the new value
        self.values.push((value, timestamp));
    }

    /// Get all current values
    pub fn get_all(&self) -> Vec<&T> {
        self.values.iter().map(|(v, _)| v).collect()
    }

    /// Get the single value if there's exactly one, or None if concurrent
    pub fn get(&self) -> Option<&T> {
        if self.values.len() == 1 {
            Some(&self.values[0].0)
        } else {
            None
        }
    }

    /// Check if there are concurrent values
    pub fn is_conflicted(&self) -> bool {
        self.values.len() > 1
    }

    /// Merge with another register
    pub fn merge(&mut self, other: &Self, clock: &mut HLC) {
        for (_, ts) in &other.values {
            clock.receive(ts);
        }

        // Combine all values
        for (value, timestamp) in &other.values {
            let dominated = self
                .values
                .iter()
                .any(|(_, ts)| ts > timestamp && ts.node_id != timestamp.node_id);

            if !dominated && !self.values.iter().any(|(_, ts)| ts == timestamp) {
                self.values.push((value.clone(), *timestamp));
            }
        }

        // Remove dominated values
        let values = std::mem::take(&mut self.values);
        for (v, ts) in values {
            let dominated = self
                .values
                .iter()
                .any(|(_, other_ts)| other_ts > &ts && other_ts.node_id != ts.node_id);
            if !dominated {
                self.values.push((v, ts));
            }
        }
    }

    /// Resolve conflicts by keeping only the value with highest timestamp
    pub fn resolve_lww(&mut self) -> Option<&T> {
        if self.values.is_empty() {
            return None;
        }

        self.values.sort_by(|(_, a), (_, b)| b.cmp(a));
        self.values.truncate(1);
        Some(&self.values[0].0)
    }
}

impl<T: Clone + PartialEq> Default for MVRegister<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lww_creation() {
        let mut clock = HLC::new(1);
        let reg = LWWRegister::new("hello".to_string(), &mut clock);
        assert_eq!(reg.get(), "hello");
    }

    #[test]
    fn test_lww_set() {
        let mut clock = HLC::new(1);
        let mut reg = LWWRegister::new("initial".to_string(), &mut clock);

        reg.set("updated".to_string(), &mut clock);
        assert_eq!(reg.get(), "updated");
    }

    #[test]
    fn test_lww_merge_newer_wins() {
        let mut clock_a = HLC::new(1);
        let mut clock_b = HLC::new(2);

        let mut reg_a = LWWRegister::new("value_a".to_string(), &mut clock_a);

        // Give B a later timestamp
        std::thread::sleep(std::time::Duration::from_millis(1));
        let reg_b = LWWRegister::new("value_b".to_string(), &mut clock_b);

        reg_a.merge(&reg_b, &mut clock_a);
        assert_eq!(reg_a.get(), "value_b");
    }

    #[test]
    fn test_lww_merge_older_loses() {
        let mut clock_a = HLC::new(1);
        let mut clock_b = HLC::new(2);

        // B is created first with earlier timestamp
        let reg_b = LWWRegister::new("value_b".to_string(), &mut clock_b);

        // A is created later with later timestamp
        std::thread::sleep(std::time::Duration::from_millis(2));
        let mut reg_a = LWWRegister::new("value_a".to_string(), &mut clock_a);

        // A's timestamp should be later, so A's value should win
        reg_a.merge(&reg_b, &mut clock_a);
        assert_eq!(reg_a.get(), "value_a");
    }

    #[test]
    fn test_lww_convergence() {
        let mut clock_a = HLC::new(1);
        let mut clock_b = HLC::new(2);

        let mut reg_a = LWWRegister::new("a".to_string(), &mut clock_a);
        std::thread::sleep(std::time::Duration::from_millis(1));
        let mut reg_b = LWWRegister::new("b".to_string(), &mut clock_b);

        // Both merge with each other
        let reg_a_clone = reg_a.clone();
        let reg_b_clone = reg_b.clone();

        reg_a.merge(&reg_b_clone, &mut clock_a);
        reg_b.merge(&reg_a_clone, &mut clock_b);

        // Should converge to same value
        assert_eq!(reg_a.get(), reg_b.get());
    }

    #[test]
    fn test_lww_set_with_timestamp() {
        let mut clock = HLC::new(1);
        let mut reg = LWWRegister::new("initial".to_string(), &mut clock);

        let old_ts = HLC::from_parts(0, 0, 2);
        let new_ts = HLC::from_parts(u64::MAX, 0, 2);

        // Old timestamp shouldn't update
        assert!(!reg.set_with_timestamp("old".to_string(), old_ts));
        assert_eq!(reg.get(), "initial");

        // New timestamp should update
        assert!(reg.set_with_timestamp("new".to_string(), new_ts));
        assert_eq!(reg.get(), "new");
    }

    #[test]
    fn test_lww_last_writer() {
        let mut clock = HLC::new(42);
        let reg = LWWRegister::new("value".to_string(), &mut clock);
        assert_eq!(reg.last_writer(), 42);
    }

    #[test]
    fn test_lww_crdt_merge_trait() {
        let mut clock_a = HLC::new(1);
        let mut clock_b = HLC::new(2);

        let mut reg_a = LWWRegister::new(10, &mut clock_a);
        std::thread::sleep(std::time::Duration::from_millis(1));
        let reg_b = LWWRegister::new(20, &mut clock_b);

        let stats = reg_a.merge_from(&reg_b);
        assert_eq!(stats.elements_added, 1);
        assert_eq!(*reg_a.get(), 20);
    }

    #[test]
    fn test_mv_register_basic() {
        let mut clock = HLC::new(1);
        let mut reg: MVRegister<String> = MVRegister::new();

        reg.set("value".to_string(), &mut clock);
        assert_eq!(reg.get(), Some(&"value".to_string()));
        assert!(!reg.is_conflicted());
    }

    #[test]
    fn test_mv_register_conflict() {
        let mut clock_a = HLC::new(1);
        let mut clock_b = HLC::new(2);

        let mut reg_a: MVRegister<String> = MVRegister::new();
        let mut reg_b: MVRegister<String> = MVRegister::new();

        // Concurrent writes
        reg_a.set("a".to_string(), &mut clock_a);
        reg_b.set("b".to_string(), &mut clock_b);

        // Merge
        reg_a.merge(&reg_b, &mut clock_a);

        // Should have both values (conflict)
        assert!(reg_a.is_conflicted());
        let values = reg_a.get_all();
        assert!(values.contains(&&"a".to_string()));
        assert!(values.contains(&&"b".to_string()));
    }

    #[test]
    fn test_mv_register_resolve() {
        let mut clock_a = HLC::new(1);
        let mut clock_b = HLC::new(2);

        let mut reg_a: MVRegister<String> = MVRegister::new();
        let mut reg_b: MVRegister<String> = MVRegister::new();

        reg_a.set("a".to_string(), &mut clock_a);
        std::thread::sleep(std::time::Duration::from_millis(1));
        reg_b.set("b".to_string(), &mut clock_b);

        reg_a.merge(&reg_b, &mut clock_a);

        // Resolve using LWW
        let winner = reg_a.resolve_lww();
        assert!(winner.is_some());
        assert!(!reg_a.is_conflicted());
    }

    #[test]
    fn test_serialization() {
        let mut clock = HLC::new(1);
        let reg = LWWRegister::new("test".to_string(), &mut clock);

        let json = serde_json::to_string(&reg).unwrap();
        let deserialized: LWWRegister<String> = serde_json::from_str(&json).unwrap();

        assert_eq!(reg.get(), deserialized.get());
    }
}
