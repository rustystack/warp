//! SLAI-driven placement engine

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use super::predictor::{PredictionResult, WorkloadPredictor, WorkloadType};
use super::tracker::{AccessOp, AccessPattern, AccessStats, AccessTracker};

/// Placement hint for the storage layer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlacementHint {
    /// Suggested node/location
    pub preferred_nodes: Vec<String>,
    /// GPU affinity (if applicable)
    pub gpu_affinity: Option<u32>,
    /// Replication factor suggestion
    pub replication_factor: Option<u8>,
    /// Cache priority (0-100)
    pub cache_priority: u8,
    /// Prefetch suggestion
    pub should_prefetch: bool,
    /// Prefetch objects
    pub prefetch_objects: Vec<String>,
    /// Reason for hint
    pub reason: String,
}

impl Default for PlacementHint {
    fn default() -> Self {
        Self {
            preferred_nodes: Vec::new(),
            gpu_affinity: None,
            replication_factor: None,
            cache_priority: 50,
            should_prefetch: false,
            prefetch_objects: Vec::new(),
            reason: String::new(),
        }
    }
}

/// Placement decision from the engine
#[derive(Debug, Clone)]
pub struct PlacementDecision {
    /// Object key
    pub key: String,
    /// Placement hint
    pub hint: PlacementHint,
    /// Workload type
    pub workload_type: WorkloadType,
    /// Access pattern
    pub access_pattern: AccessPattern,
    /// Confidence in decision (0.0-1.0)
    pub confidence: f64,
    /// Decision timestamp
    pub timestamp: Instant,
}

/// Node information for placement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    /// Node ID
    pub node_id: String,
    /// Location/rack
    pub location: String,
    /// Available storage (bytes)
    pub available_storage: u64,
    /// GPU available
    pub has_gpu: bool,
    /// GPU memory available (bytes)
    pub gpu_memory: u64,
    /// Network bandwidth (bytes/sec)
    pub bandwidth: u64,
    /// Current load (0.0-1.0)
    pub load: f64,
}

/// Placement engine statistics
#[derive(Debug, Clone, Default)]
pub struct EngineStats {
    /// Total placement decisions
    pub decisions: u64,
    /// Prefetch suggestions made
    pub prefetches_suggested: u64,
    /// GPU affinity suggestions
    pub gpu_affinities: u64,
    /// Average confidence
    pub avg_confidence: f64,
}

/// SLAI-driven placement engine
pub struct PlacementEngine {
    /// Workload predictor
    predictor: Arc<WorkloadPredictor>,
    /// Access tracker
    tracker: Arc<AccessTracker>,
    /// Known nodes
    nodes: DashMap<String, NodeInfo>,
    /// GPU node mapping (gpu_id -> node_id)
    gpu_nodes: DashMap<u32, String>,
    /// Object to node mapping (for locality)
    object_locations: DashMap<String, Vec<String>>,
    /// Statistics
    stats: RwLock<EngineStats>,
    /// Cache priority weights by workload
    cache_weights: HashMap<WorkloadType, u8>,
}

impl PlacementEngine {
    /// Create a new placement engine
    pub fn new() -> Self {
        let mut cache_weights = HashMap::new();
        cache_weights.insert(WorkloadType::Training, 80);
        cache_weights.insert(WorkloadType::Inference, 90);
        cache_weights.insert(WorkloadType::Checkpointing, 60);
        cache_weights.insert(WorkloadType::Preprocessing, 40);
        cache_weights.insert(WorkloadType::Evaluation, 70);
        cache_weights.insert(WorkloadType::Augmentation, 30);
        cache_weights.insert(WorkloadType::Unknown, 50);

        Self {
            predictor: Arc::new(WorkloadPredictor::new()),
            tracker: Arc::new(AccessTracker::new()),
            nodes: DashMap::new(),
            gpu_nodes: DashMap::new(),
            object_locations: DashMap::new(),
            stats: RwLock::new(EngineStats::default()),
            cache_weights,
        }
    }

    /// Create with custom predictor and tracker
    pub fn with_components(predictor: Arc<WorkloadPredictor>, tracker: Arc<AccessTracker>) -> Self {
        let mut engine = Self::new();
        engine.predictor = predictor;
        engine.tracker = tracker;
        engine
    }

    /// Register a storage node
    pub fn register_node(&self, info: NodeInfo) {
        if info.has_gpu {
            // Track GPU nodes
            self.gpu_nodes.insert(0, info.node_id.clone()); // Simplified: one GPU per node
        }
        self.nodes.insert(info.node_id.clone(), info);
    }

    /// Unregister a node
    pub fn unregister_node(&self, node_id: &str) {
        self.nodes.remove(node_id);
        self.gpu_nodes.retain(|_, v| v != node_id);
    }

    /// Record an access for learning
    pub fn record_access(
        &self,
        session_id: &str,
        key: &str,
        op: AccessOp,
        size: Option<u64>,
        latency_us: Option<u64>,
    ) {
        // Record in predictor for workload detection
        self.predictor.record_access(session_id, key);

        // Record in tracker for pattern analysis
        self.tracker.record(key, op, size, latency_us);
    }

    /// Get placement decision for an object
    pub fn get_placement(&self, session_id: &str, key: &str) -> PlacementDecision {
        let mut stats = self.stats.write();
        stats.decisions += 1;
        drop(stats);

        // Get prediction from workload predictor
        let prediction = self.predictor.predict(session_id);

        // Get access pattern from tracker
        let access_pattern = self.tracker.detect_pattern(key);

        // Build placement hint
        let mut hint = PlacementHint::default();

        // Set cache priority based on workload
        hint.cache_priority = *self
            .cache_weights
            .get(&prediction.workload_type)
            .unwrap_or(&50);

        // Set prefetch suggestions
        if !prediction.predicted_objects.is_empty() {
            hint.should_prefetch = true;
            hint.prefetch_objects = prediction.predicted_objects.clone();
            self.stats.write().prefetches_suggested += 1;
        }

        // Set preferred nodes based on workload
        hint.preferred_nodes = self.get_preferred_nodes(&prediction, &access_pattern);

        // Set GPU affinity for training/inference workloads
        if matches!(
            prediction.workload_type,
            WorkloadType::Training | WorkloadType::Inference
        ) {
            if let Some(gpu_node) = self.find_best_gpu_node() {
                hint.gpu_affinity = Some(0); // Simplified
                hint.preferred_nodes.insert(0, gpu_node);
                self.stats.write().gpu_affinities += 1;
            }
        }

        // Set replication factor based on access pattern
        hint.replication_factor = match access_pattern {
            AccessPattern::WriteOnceReadMany => Some(3), // High replication for frequently read
            AccessPattern::WriteHeavy => Some(1),        // Low replication for write-heavy
            AccessPattern::Repeated => Some(2),          // Medium for repeated reads
            _ => None,
        };

        // Build reason string
        hint.reason = format!(
            "workload={:?}, pattern={:?}, prefetch={}",
            prediction.workload_type,
            access_pattern,
            hint.prefetch_objects.len()
        );

        // Update average confidence
        {
            let mut stats = self.stats.write();
            let total = stats.avg_confidence * (stats.decisions - 1) as f64 + prediction.confidence;
            stats.avg_confidence = total / stats.decisions as f64;
        }

        PlacementDecision {
            key: key.to_string(),
            hint,
            workload_type: prediction.workload_type,
            access_pattern,
            confidence: prediction.confidence,
            timestamp: Instant::now(),
        }
    }

    /// Get preferred nodes for a workload
    fn get_preferred_nodes(
        &self,
        prediction: &PredictionResult,
        access_pattern: &AccessPattern,
    ) -> Vec<String> {
        let mut nodes: Vec<_> = self.nodes.iter().collect();

        // Sort nodes by suitability
        nodes.sort_by(|a, b| {
            let score_a = self.node_score(a.value(), prediction, access_pattern);
            let score_b = self.node_score(b.value(), prediction, access_pattern);
            score_b
                .partial_cmp(&score_a)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        nodes.into_iter().take(3).map(|n| n.key().clone()).collect()
    }

    /// Score a node for placement
    fn node_score(
        &self,
        node: &NodeInfo,
        prediction: &PredictionResult,
        _access_pattern: &AccessPattern,
    ) -> f64 {
        let mut score = 0.0;

        // Prefer nodes with more available storage
        score += (node.available_storage as f64 / 1_000_000_000_000.0) * 20.0; // TB

        // Prefer nodes with lower load
        score += (1.0 - node.load) * 30.0;

        // Prefer nodes with GPU for training/inference
        if matches!(
            prediction.workload_type,
            WorkloadType::Training | WorkloadType::Inference
        ) && node.has_gpu
        {
            score += 40.0;
        }

        // Prefer higher bandwidth
        score += (node.bandwidth as f64 / 10_000_000_000.0) * 10.0; // 10 Gbps reference

        score
    }

    /// Find the best GPU node
    fn find_best_gpu_node(&self) -> Option<String> {
        self.nodes
            .iter()
            .filter(|n| n.value().has_gpu)
            .min_by(|a, b| {
                a.value()
                    .load
                    .partial_cmp(&b.value().load)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|n| n.key().clone())
    }

    /// Get prefetch suggestions for upcoming accesses
    pub fn get_prefetch_suggestions(&self, session_id: &str, limit: usize) -> Vec<String> {
        let prediction = self.predictor.predict(session_id);
        prediction
            .predicted_objects
            .into_iter()
            .take(limit)
            .collect()
    }

    /// Pre-stage data to a node
    pub fn suggest_prestage(&self, session_id: &str, target_node: &str) -> Vec<String> {
        let prediction = self.predictor.predict(session_id);

        // Suggest objects to pre-stage based on prediction
        prediction
            .predicted_objects
            .into_iter()
            .filter(|obj| {
                // Don't suggest if already on target node
                self.object_locations
                    .get(obj)
                    .map(|locs| !locs.contains(&target_node.to_string()))
                    .unwrap_or(true)
            })
            .collect()
    }

    /// Update object location (for tracking locality)
    pub fn update_location(&self, key: &str, node_id: &str) {
        self.object_locations
            .entry(key.to_string())
            .and_modify(|nodes| {
                if !nodes.contains(&node_id.to_string()) {
                    nodes.push(node_id.to_string());
                }
            })
            .or_insert_with(|| vec![node_id.to_string()]);
    }

    /// Remove object location
    pub fn remove_location(&self, key: &str, node_id: &str) {
        if let Some(mut nodes) = self.object_locations.get_mut(key) {
            nodes.retain(|n| n != node_id);
        }
    }

    /// Get current access statistics
    pub fn get_access_stats(&self) -> AccessStats {
        self.tracker.get_stats()
    }

    /// Get engine statistics
    pub fn get_stats(&self) -> EngineStats {
        self.stats.read().clone()
    }

    /// Get predictor reference
    pub fn predictor(&self) -> &Arc<WorkloadPredictor> {
        &self.predictor
    }

    /// Get tracker reference
    pub fn tracker(&self) -> &Arc<AccessTracker> {
        &self.tracker
    }
}

impl Default for PlacementEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_placement_engine_creation() {
        let engine = PlacementEngine::new();
        let stats = engine.get_stats();
        assert_eq!(stats.decisions, 0);
    }

    #[test]
    fn test_register_node() {
        let engine = PlacementEngine::new();

        let node = NodeInfo {
            node_id: "node1".to_string(),
            location: "rack1".to_string(),
            available_storage: 1_000_000_000_000, // 1 TB
            has_gpu: true,
            gpu_memory: 16_000_000_000, // 16 GB
            bandwidth: 10_000_000_000,  // 10 Gbps
            load: 0.3,
        };

        engine.register_node(node);
        assert!(engine.nodes.contains_key("node1"));
    }

    #[test]
    fn test_placement_decision() {
        let engine = PlacementEngine::new();

        // Register some nodes
        engine.register_node(NodeInfo {
            node_id: "gpu_node".to_string(),
            location: "rack1".to_string(),
            available_storage: 1_000_000_000_000,
            has_gpu: true,
            gpu_memory: 16_000_000_000,
            bandwidth: 10_000_000_000,
            load: 0.2,
        });

        engine.register_node(NodeInfo {
            node_id: "storage_node".to_string(),
            location: "rack2".to_string(),
            available_storage: 10_000_000_000_000,
            has_gpu: false,
            gpu_memory: 0,
            bandwidth: 25_000_000_000,
            load: 0.5,
        });

        // Record some training-like accesses
        engine.record_access("session1", "batch_0.bin", AccessOp::Read, Some(1024), None);
        engine.record_access("session1", "batch_1.bin", AccessOp::Read, Some(1024), None);
        engine.record_access("session1", "batch_2.bin", AccessOp::Read, Some(1024), None);

        // Get placement decision
        let decision = engine.get_placement("session1", "batch_3.bin");

        assert_eq!(decision.workload_type, WorkloadType::Training);
        assert!(!decision.hint.preferred_nodes.is_empty());
    }

    #[test]
    fn test_prefetch_suggestions() {
        let engine = PlacementEngine::new();

        // Simulate a sequence of accesses
        for i in 0..5 {
            engine.record_access(
                "session1",
                &format!("batch_{}.bin", i),
                AccessOp::Read,
                None,
                None,
            );
        }

        let _suggestions = engine.get_prefetch_suggestions("session1", 3);
        // May be empty depending on pattern - just verify the call doesn't panic
    }

    #[test]
    fn test_object_location_tracking() {
        let engine = PlacementEngine::new();

        engine.update_location("file1.bin", "node1");
        engine.update_location("file1.bin", "node2");

        let locations = engine.object_locations.get("file1.bin").unwrap();
        assert_eq!(locations.len(), 2);

        engine.remove_location("file1.bin", "node1");
        let locations = engine.object_locations.get("file1.bin").unwrap();
        assert_eq!(locations.len(), 1);
    }
}
