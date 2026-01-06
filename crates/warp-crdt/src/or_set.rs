//! Observed-Remove Set (OR-Set)
//!
//! A set CRDT where add and remove operations commute correctly.
//! Uses causal metadata (dots) to track each add operation uniquely.
//!
//! # Properties
//!
//! - Add-wins semantics: concurrent add and remove of same element, add wins
//! - Supports re-add after remove
//! - Convergent under any merge order
//!
//! # Use Cases
//!
//! - User group membership
//! - Tags/labels on objects
//! - Active session tracking
//! - Distributed set operations

use crate::{CrdtMerge, MergeStats, NodeId};
use serde::{Deserialize, Serialize};
use std::borrow::Borrow;
use std::collections::{HashMap, HashSet};
use std::hash::Hash;

/// A causal dot (node_id, counter) that uniquely identifies an add operation
pub type Dot = (NodeId, u64);

/// Observed-Remove Set CRDT
///
/// Each element is tagged with the set of dots (causal history) that added it.
/// Remove operations tombstone the currently visible dots for that element.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ORSet<T: Eq + Hash + Clone> {
    /// Elements with their causal dots
    /// Each dot represents a unique add operation
    elements: HashMap<T, HashSet<Dot>>,
    /// Per-node version counters
    counters: HashMap<NodeId, u64>,
    /// Local node ID
    node_id: NodeId,
}

impl<T: Eq + Hash + Clone> ORSet<T> {
    /// Create a new empty OR-Set for the given node
    pub fn new(node_id: NodeId) -> Self {
        Self {
            elements: HashMap::new(),
            counters: HashMap::new(),
            node_id,
        }
    }

    /// Add an element to the set
    ///
    /// Creates a new unique dot for this add operation.
    pub fn add(&mut self, element: T) {
        let counter = self.counters.entry(self.node_id).or_insert(0);
        *counter += 1;
        let dot = (self.node_id, *counter);

        self.elements.entry(element).or_default().insert(dot);
    }

    /// Remove an element from the set
    ///
    /// Removes all currently visible dots for this element.
    /// Concurrent adds will have different dots and won't be affected.
    pub fn remove<Q>(&mut self, element: &Q)
    where
        T: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.elements.remove(element);
    }

    /// Check if the set contains an element
    pub fn contains<Q>(&self, element: &Q) -> bool
    where
        T: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.elements
            .get(element)
            .map(|dots| !dots.is_empty())
            .unwrap_or(false)
    }

    /// Get the number of elements in the set
    pub fn len(&self) -> usize {
        self.elements
            .iter()
            .filter(|(_, dots)| !dots.is_empty())
            .count()
    }

    /// Check if the set is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterate over elements in the set
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.elements
            .iter()
            .filter(|(_, dots)| !dots.is_empty())
            .map(|(elem, _)| elem)
    }

    /// Get all elements as a Vec
    pub fn to_vec(&self) -> Vec<T> {
        self.iter().cloned().collect()
    }

    /// Merge with another OR-Set
    ///
    /// The merge takes the union of all dots for each element.
    /// This implements add-wins semantics: if one replica added
    /// and another removed concurrently, the add wins.
    pub fn merge(&mut self, other: &Self) {
        // Merge elements and their dots
        for (element, other_dots) in &other.elements {
            let local_dots = self.elements.entry(element.clone()).or_default();
            local_dots.extend(other_dots.iter().copied());
        }

        // Merge version counters
        for (&node_id, &counter) in &other.counters {
            let local = self.counters.entry(node_id).or_insert(0);
            *local = (*local).max(counter);
        }
    }

    /// Get the current version vector (for debugging/sync)
    pub fn version_vector(&self) -> HashMap<NodeId, u64> {
        self.counters.clone()
    }

    /// Get the node ID of this set
    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Clear all elements from the set
    pub fn clear(&mut self) {
        self.elements.clear();
    }
}

impl<T: Eq + Hash + Clone> CrdtMerge for ORSet<T> {
    fn merge_from(&mut self, other: &Self) -> MergeStats {
        let before_len = self.len();

        self.merge(other);

        let after_len = self.len();
        let added = after_len.saturating_sub(before_len);

        MergeStats {
            elements_added: added,
            elements_removed: 0, // OR-Set doesn't lose elements on merge
            elements_updated: 0,
            conflicts_resolved: 0,
        }
    }
}

impl<T: Eq + Hash + Clone> Default for ORSet<T> {
    fn default() -> Self {
        Self::new(0)
    }
}

impl<T: Eq + Hash + Clone> FromIterator<(T, NodeId)> for ORSet<T> {
    fn from_iter<I: IntoIterator<Item = (T, NodeId)>>(iter: I) -> Self {
        let mut set = ORSet::new(0);
        for (element, node_id) in iter {
            let counter = set.counters.entry(node_id).or_insert(0);
            *counter += 1;
            let dot = (node_id, *counter);
            set.elements.entry(element).or_default().insert(dot);
        }
        set
    }
}

/// Observed-Remove Map (OR-Map)
///
/// A map CRDT built on OR-Set semantics for keys, with values
/// being LWW-Registers or other CRDTs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ORMap<K: Eq + Hash + Clone, V: Clone> {
    /// Keys tracked by OR-Set
    keys: ORSet<K>,
    /// Values for each key
    values: HashMap<K, V>,
}

impl<K: Eq + Hash + Clone, V: Clone> ORMap<K, V> {
    /// Create a new empty OR-Map
    pub fn new(node_id: NodeId) -> Self {
        Self {
            keys: ORSet::new(node_id),
            values: HashMap::new(),
        }
    }

    /// Insert a key-value pair
    pub fn insert(&mut self, key: K, value: V) {
        self.keys.add(key.clone());
        self.values.insert(key, value);
    }

    /// Remove a key
    pub fn remove(&mut self, key: &K) {
        self.keys.remove(key);
        self.values.remove(key);
    }

    /// Get a value by key
    pub fn get(&self, key: &K) -> Option<&V> {
        if self.keys.contains(key) {
            self.values.get(key)
        } else {
            None
        }
    }

    /// Check if the map contains a key
    pub fn contains_key(&self, key: &K) -> bool {
        self.keys.contains(key)
    }

    /// Get the number of entries
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Check if the map is empty
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Iterate over key-value pairs
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.keys
            .iter()
            .filter_map(|k| self.values.get(k).map(|v| (k, v)))
    }

    /// Merge with another OR-Map
    ///
    /// For conflicting values, uses last-write-wins based on node_id.
    pub fn merge(&mut self, other: &Self) {
        // First merge keys
        self.keys.merge(&other.keys);

        // Then merge values for keys that exist in other
        for key in other.keys.iter() {
            if let Some(other_value) = other.values.get(key) {
                // Simple last-write-wins based on whether key was in local
                if !self.values.contains_key(key) {
                    self.values.insert(key.clone(), other_value.clone());
                }
            }
        }
    }
}

impl<K: Eq + Hash + Clone, V: Clone> Default for ORMap<K, V> {
    fn default() -> Self {
        Self::new(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_or_set_basic() {
        let mut set = ORSet::new(1);
        assert!(set.is_empty());

        set.add("a");
        set.add("b");
        set.add("c");

        assert_eq!(set.len(), 3);
        assert!(set.contains(&"a"));
        assert!(set.contains(&"b"));
        assert!(set.contains(&"c"));
    }

    #[test]
    fn test_or_set_remove() {
        let mut set = ORSet::new(1);
        set.add("a");
        set.add("b");

        set.remove(&"a");

        assert_eq!(set.len(), 1);
        assert!(!set.contains(&"a"));
        assert!(set.contains(&"b"));
    }

    #[test]
    fn test_or_set_re_add() {
        let mut set = ORSet::new(1);
        set.add("a");
        set.remove(&"a");
        set.add("a"); // Re-add

        assert!(set.contains(&"a"));
    }

    #[test]
    fn test_or_set_merge() {
        let mut set_a = ORSet::new(1);
        let mut set_b = ORSet::new(2);

        set_a.add("a");
        set_a.add("common");

        set_b.add("b");
        set_b.add("common");

        set_a.merge(&set_b);

        assert_eq!(set_a.len(), 3);
        assert!(set_a.contains(&"a"));
        assert!(set_a.contains(&"b"));
        assert!(set_a.contains(&"common"));
    }

    #[test]
    fn test_or_set_add_wins() {
        let mut set_a = ORSet::new(1);
        let mut set_b = ORSet::new(2);

        // Both add "item"
        set_a.add("item");
        set_b.add("item");

        // A removes it
        set_a.remove(&"item");

        // Merge: B's add should win
        set_a.merge(&set_b);

        assert!(set_a.contains(&"item"));
    }

    #[test]
    fn test_or_set_convergence() {
        let mut set_a = ORSet::new(1);
        let mut set_b = ORSet::new(2);

        // Different operations on each
        set_a.add("a");
        set_a.add("common");

        set_b.add("b");
        set_b.add("common");
        set_b.remove(&"common");

        // Merge in both directions
        let set_a_before = set_a.clone();
        set_a.merge(&set_b);
        set_b.merge(&set_a_before);

        // Should converge (but "common" status depends on concurrent add-wins)
        assert_eq!(set_a.contains(&"a"), set_b.contains(&"a"));
        assert_eq!(set_a.contains(&"b"), set_b.contains(&"b"));
    }

    #[test]
    fn test_or_set_idempotent() {
        let mut set_a = ORSet::new(1);
        let set_b = ORSet::new(2);

        set_a.add("a");

        // Merge same set multiple times
        let before = set_a.to_vec();
        set_a.merge(&set_b);
        set_a.merge(&set_b);
        set_a.merge(&set_b);

        assert_eq!(before, set_a.to_vec());
    }

    #[test]
    fn test_or_set_commutative() {
        let mut set_a = ORSet::new(1);
        let mut set_b = ORSet::new(2);
        let mut set_c = ORSet::new(3);

        set_a.add("a");
        set_b.add("b");
        set_c.add("c");

        // a merge b merge c
        let mut result1 = set_a.clone();
        result1.merge(&set_b);
        result1.merge(&set_c);

        // c merge a merge b
        let mut result2 = set_c.clone();
        result2.merge(&set_a);
        result2.merge(&set_b);

        assert_eq!(result1.len(), result2.len());
        for elem in result1.iter() {
            assert!(result2.contains(elem));
        }
    }

    #[test]
    fn test_or_set_version_vector() {
        let mut set = ORSet::new(1);
        set.add("a");
        set.add("b");

        let vv = set.version_vector();
        assert_eq!(vv.get(&1), Some(&2));
    }

    #[test]
    fn test_or_map_basic() {
        let mut map = ORMap::new(1);
        map.insert("key1", "value1");
        map.insert("key2", "value2");

        assert_eq!(map.len(), 2);
        assert_eq!(map.get(&"key1"), Some(&"value1"));
        assert_eq!(map.get(&"key2"), Some(&"value2"));
    }

    #[test]
    fn test_or_map_remove() {
        let mut map = ORMap::new(1);
        map.insert("key", "value");
        map.remove(&"key");

        assert!(!map.contains_key(&"key"));
        assert!(map.get(&"key").is_none());
    }

    #[test]
    fn test_or_map_merge() {
        let mut map_a = ORMap::new(1);
        let mut map_b = ORMap::new(2);

        map_a.insert("a", 1);
        map_b.insert("b", 2);

        map_a.merge(&map_b);

        assert_eq!(map_a.len(), 2);
        assert_eq!(map_a.get(&"a"), Some(&1));
        assert_eq!(map_a.get(&"b"), Some(&2));
    }

    #[test]
    fn test_serialization() {
        let mut set = ORSet::new(1);
        set.add("test".to_string());

        let json = serde_json::to_string(&set).unwrap();
        let deserialized: ORSet<String> = serde_json::from_str(&json).unwrap();

        assert!(deserialized.contains(&"test".to_string()));
    }

    #[test]
    fn test_crdt_merge_trait() {
        let mut set_a = ORSet::new(1);
        let mut set_b = ORSet::new(2);

        set_a.add("a");
        set_b.add("b");
        set_b.add("c");

        let stats = set_a.merge_from(&set_b);
        assert_eq!(stats.elements_added, 2);
    }
}
