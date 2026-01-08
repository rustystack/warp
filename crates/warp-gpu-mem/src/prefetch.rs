//! ML-aware tensor prefetcher

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::RwLock;

use crate::config::PrefetchStrategy;
use crate::tensor::{TensorHandle, TensorId};

/// Prefetch hint - suggestion for what to prefetch
#[derive(Debug, Clone)]
pub struct PrefetchHint {
    /// Tensor ID to prefetch
    pub tensor_id: TensorId,
    /// Priority (higher = more urgent)
    pub priority: u32,
    /// Expected access time
    pub expected_access: Option<Instant>,
    /// Layer index (for training awareness)
    pub layer_index: Option<usize>,
}

/// Access pattern type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessPattern {
    /// Sequential access (e.g., forward pass)
    Sequential,
    /// Reverse sequential (e.g., backward pass)
    ReverseSequential,
    /// Random access
    Random,
    /// Strided access
    Strided {
        /// Access stride in elements
        stride: usize,
    },
    /// Unknown pattern
    Unknown,
}

/// Training phase
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrainingPhase {
    /// Forward pass
    Forward,
    /// Backward pass
    Backward,
    /// Optimizer step
    OptimizerStep,
    /// Validation
    Validation,
    /// Unknown
    Unknown,
}

/// Access record for pattern detection
#[derive(Debug, Clone)]
struct AccessRecord {
    tensor_id: TensorId,
    timestamp: Instant,
    layer_index: Option<usize>,
}

/// Prefetcher statistics
#[derive(Debug, Clone, Default)]
pub struct PrefetchStats {
    /// Prefetch requests issued
    pub prefetch_requests: u64,
    /// Successful prefetches (tensor was used)
    pub successful_prefetches: u64,
    /// Wasted prefetches (tensor was not used)
    pub wasted_prefetches: u64,
    /// Prefetch hits (tensor was ready when needed)
    pub prefetch_hits: u64,
    /// Pattern changes detected
    pub pattern_changes: u64,
}

impl PrefetchStats {
    /// Get prefetch efficiency
    pub fn efficiency(&self) -> f64 {
        if self.prefetch_requests == 0 {
            0.0
        } else {
            self.successful_prefetches as f64 / self.prefetch_requests as f64
        }
    }
}

/// ML-aware prefetcher
pub struct Prefetcher {
    /// Prefetch strategy
    strategy: PrefetchStrategy,
    /// Lookahead count
    lookahead: usize,
    /// Access history
    access_history: RwLock<VecDeque<AccessRecord>>,
    /// Detected pattern
    current_pattern: RwLock<AccessPattern>,
    /// Current training phase
    training_phase: RwLock<TrainingPhase>,
    /// Layer access order (for training awareness)
    layer_order: RwLock<Vec<usize>>,
    /// Pending prefetch requests
    pending_prefetches: DashMap<TensorId, Instant>,
    /// Statistics
    stats: RwLock<PrefetchStats>,
    /// Maximum history size
    max_history: usize,
}

impl Prefetcher {
    /// Create a new prefetcher
    pub fn new(strategy: PrefetchStrategy, lookahead: usize) -> Self {
        Self {
            strategy,
            lookahead,
            access_history: RwLock::new(VecDeque::with_capacity(1000)),
            current_pattern: RwLock::new(AccessPattern::Unknown),
            training_phase: RwLock::new(TrainingPhase::Unknown),
            layer_order: RwLock::new(Vec::new()),
            pending_prefetches: DashMap::new(),
            stats: RwLock::new(PrefetchStats::default()),
            max_history: 1000,
        }
    }

    /// Record a tensor access
    pub fn record_access(&self, tensor: &TensorHandle) {
        let record = AccessRecord {
            tensor_id: tensor.id(),
            timestamp: Instant::now(),
            layer_index: tensor.meta.layer_index,
        };

        let mut history = self.access_history.write();
        history.push_back(record);
        if history.len() > self.max_history {
            history.pop_front();
        }

        // Check if this was a pending prefetch
        if self.pending_prefetches.remove(&tensor.id()).is_some() {
            self.stats.write().successful_prefetches += 1;
        }

        // Update detected pattern
        drop(history);
        self.detect_pattern();
    }

    /// Detect access pattern from history
    fn detect_pattern(&self) {
        let history = self.access_history.read();
        if history.len() < 10 {
            return;
        }

        // Get recent layer indices
        let recent_layers: Vec<Option<usize>> = history
            .iter()
            .rev()
            .take(20)
            .map(|r| r.layer_index)
            .collect();

        // Check for sequential pattern
        let sequential_layers: Vec<usize> = recent_layers.iter().filter_map(|l| *l).collect();

        if sequential_layers.len() >= 5 {
            let is_ascending = sequential_layers.windows(2).all(|w| w[0] <= w[1]);
            let is_descending = sequential_layers.windows(2).all(|w| w[0] >= w[1]);

            let mut pattern = self.current_pattern.write();
            let mut phase = self.training_phase.write();

            // Note: history is iterated in reverse, so ascending in reversed history
            // means descending in original access order (backward pass)
            if is_descending {
                // Descending in reversed history = ascending original access = forward pass
                *pattern = AccessPattern::Sequential;
                *phase = TrainingPhase::Forward;
            } else if is_ascending {
                // Ascending in reversed history = descending original access = backward pass
                *pattern = AccessPattern::ReverseSequential;
                *phase = TrainingPhase::Backward;
            }
        }
    }

    /// Get prefetch hints based on current state
    pub fn get_hints(&self, current_tensor: &TensorHandle) -> Vec<PrefetchHint> {
        match self.strategy {
            PrefetchStrategy::None => Vec::new(),
            PrefetchStrategy::Sequential => self.sequential_hints(current_tensor),
            PrefetchStrategy::TrainingAware => self.training_aware_hints(current_tensor),
            PrefetchStrategy::ModelDriven => self.model_driven_hints(current_tensor),
        }
    }

    /// Generate sequential prefetch hints
    fn sequential_hints(&self, current_tensor: &TensorHandle) -> Vec<PrefetchHint> {
        let history = self.access_history.read();
        let pattern = *self.current_pattern.read();

        // Get recent unique tensors in order
        let mut recent: Vec<TensorId> = Vec::new();
        for record in history.iter().rev() {
            if !recent.contains(&record.tensor_id) {
                recent.push(record.tensor_id);
            }
            if recent.len() >= 10 {
                break;
            }
        }

        // Find current position and predict next tensors
        if let Some(pos) = recent.iter().position(|&id| id == current_tensor.id()) {
            let start = if matches!(pattern, AccessPattern::ReverseSequential) {
                pos.saturating_add(1)
            } else {
                pos.saturating_sub(self.lookahead)
            };

            recent
                .iter()
                .skip(start)
                .take(self.lookahead)
                .enumerate()
                .map(|(i, &tensor_id)| PrefetchHint {
                    tensor_id,
                    priority: (self.lookahead - i) as u32,
                    expected_access: Some(
                        Instant::now() + Duration::from_millis(10 * (i as u64 + 1)),
                    ),
                    layer_index: None,
                })
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Generate training-aware prefetch hints
    fn training_aware_hints(&self, current_tensor: &TensorHandle) -> Vec<PrefetchHint> {
        let phase = *self.training_phase.read();
        let layer_order = self.layer_order.read();

        let current_layer = current_tensor.meta.layer_index;

        if current_layer.is_none() || layer_order.is_empty() {
            return self.sequential_hints(current_tensor);
        }

        let current_layer = current_layer.unwrap();
        let mut hints = Vec::new();

        match phase {
            TrainingPhase::Forward => {
                // Prefetch next layers
                for (_i, &layer) in layer_order.iter().enumerate() {
                    if layer > current_layer && hints.len() < self.lookahead {
                        hints.push(PrefetchHint {
                            tensor_id: TensorId::from_raw(layer as u64), // Placeholder
                            priority: (self.lookahead - hints.len()) as u32,
                            expected_access: None,
                            layer_index: Some(layer),
                        });
                    }
                }
            }
            TrainingPhase::Backward => {
                // Prefetch previous layers (in reverse)
                for &layer in layer_order.iter().rev() {
                    if layer < current_layer && hints.len() < self.lookahead {
                        hints.push(PrefetchHint {
                            tensor_id: TensorId::from_raw(layer as u64),
                            priority: (self.lookahead - hints.len()) as u32,
                            expected_access: None,
                            layer_index: Some(layer),
                        });
                    }
                }
            }
            _ => {
                return self.sequential_hints(current_tensor);
            }
        }

        hints
    }

    /// Generate model-driven hints (would integrate with SLAI)
    fn model_driven_hints(&self, current_tensor: &TensorHandle) -> Vec<PrefetchHint> {
        // Placeholder - would integrate with SLAI predictions
        self.training_aware_hints(current_tensor)
    }

    /// Register a prefetch request
    pub fn register_prefetch(&self, tensor_id: TensorId) {
        self.pending_prefetches.insert(tensor_id, Instant::now());
        self.stats.write().prefetch_requests += 1;
    }

    /// Set the layer order (from model structure)
    pub fn set_layer_order(&self, layers: Vec<usize>) {
        *self.layer_order.write() = layers;
    }

    /// Set training phase explicitly
    pub fn set_training_phase(&self, phase: TrainingPhase) {
        *self.training_phase.write() = phase;
    }

    /// Get current detected pattern
    pub fn current_pattern(&self) -> AccessPattern {
        *self.current_pattern.read()
    }

    /// Get current training phase
    pub fn current_phase(&self) -> TrainingPhase {
        *self.training_phase.read()
    }

    /// Get statistics
    pub fn stats(&self) -> PrefetchStats {
        self.stats.read().clone()
    }

    /// Clean up old pending prefetches
    pub fn cleanup_stale_prefetches(&self, timeout: Duration) {
        let now = Instant::now();
        let stale: Vec<TensorId> = self
            .pending_prefetches
            .iter()
            .filter(|entry| now.duration_since(*entry.value()) > timeout)
            .map(|entry| *entry.key())
            .collect();

        for tensor_id in stale {
            self.pending_prefetches.remove(&tensor_id);
            self.stats.write().wasted_prefetches += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tensor::{TensorDtype, TensorMeta};

    fn create_test_handle(layer: usize) -> TensorHandle {
        let meta = TensorMeta::new(vec![1024], TensorDtype::Float32).with_layer(layer);
        TensorHandle::new(meta)
    }

    #[test]
    fn test_prefetcher_creation() {
        let prefetcher = Prefetcher::new(PrefetchStrategy::TrainingAware, 3);
        assert_eq!(prefetcher.current_pattern(), AccessPattern::Unknown);
        assert_eq!(prefetcher.current_phase(), TrainingPhase::Unknown);
    }

    #[test]
    fn test_record_access() {
        let prefetcher = Prefetcher::new(PrefetchStrategy::Sequential, 3);

        for layer in 0..10 {
            let handle = create_test_handle(layer);
            prefetcher.record_access(&handle);
        }

        // Pattern should be detected as sequential
        assert_eq!(prefetcher.current_pattern(), AccessPattern::Sequential);
    }

    #[test]
    fn test_reverse_pattern_detection() {
        let prefetcher = Prefetcher::new(PrefetchStrategy::Sequential, 3);

        // Simulate backward pass (descending layers)
        for layer in (0..10).rev() {
            let handle = create_test_handle(layer);
            prefetcher.record_access(&handle);
        }

        assert_eq!(
            prefetcher.current_pattern(),
            AccessPattern::ReverseSequential
        );
        assert_eq!(prefetcher.current_phase(), TrainingPhase::Backward);
    }

    #[test]
    fn test_prefetch_stats() {
        let prefetcher = Prefetcher::new(PrefetchStrategy::Sequential, 3);

        prefetcher.register_prefetch(TensorId::generate());
        prefetcher.register_prefetch(TensorId::generate());

        let stats = prefetcher.stats();
        assert_eq!(stats.prefetch_requests, 2);
    }

    #[test]
    fn test_layer_order() {
        let prefetcher = Prefetcher::new(PrefetchStrategy::TrainingAware, 3);
        prefetcher.set_layer_order(vec![0, 1, 2, 3, 4]);
        prefetcher.set_training_phase(TrainingPhase::Forward);

        let handle = create_test_handle(2);
        let hints = prefetcher.get_hints(&handle);

        // Should suggest layers after current
        assert!(!hints.is_empty());
    }
}
