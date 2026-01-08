//! Tensor cache with GPU-optimized eviction

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::RwLock;

use crate::tensor::{TensorHandle, TensorId};

/// Cache configuration
pub use crate::config::CacheConfig;

/// Eviction policy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EvictionPolicy {
    /// Least Recently Used
    Lru,
    /// Least Frequently Used
    Lfu,
    /// Size-weighted LRU (prefer evicting larger tensors)
    #[default]
    SizeWeightedLru,
    /// Gradient-aware (prefer evicting activations)
    GradientAware,
}

/// Cache entry
struct CacheEntry {
    /// Tensor handle
    handle: Arc<TensorHandle>,
    /// Last access time
    last_access: Instant,
    /// Access count
    access_count: u64,
    /// Eviction score (higher = more likely to evict)
    eviction_score: f64,
}

/// Cache statistics
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    /// Cache hits
    pub hits: u64,
    /// Cache misses
    pub misses: u64,
    /// Evictions
    pub evictions: u64,
    /// Total entries
    pub entries: usize,
    /// Total cached bytes
    pub cached_bytes: u64,
}

impl CacheStats {
    /// Get hit ratio
    pub fn hit_ratio(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }
}

/// Tensor cache
pub struct TensorCache {
    /// Configuration
    config: CacheConfig,
    /// Eviction policy
    eviction_policy: EvictionPolicy,
    /// Cached tensors
    entries: DashMap<TensorId, CacheEntry>,
    /// Total cached bytes
    cached_bytes: AtomicU64,
    /// Statistics
    stats: RwLock<CacheStats>,
    /// Tensors marked for prefetch (should not be evicted)
    prefetch_protected: DashMap<TensorId, Instant>,
}

impl TensorCache {
    /// Create a new tensor cache
    pub fn new(config: CacheConfig) -> Self {
        Self {
            config,
            eviction_policy: EvictionPolicy::default(),
            entries: DashMap::new(),
            cached_bytes: AtomicU64::new(0),
            stats: RwLock::new(CacheStats::default()),
            prefetch_protected: DashMap::new(),
        }
    }

    /// Set eviction policy
    pub fn with_eviction_policy(mut self, policy: EvictionPolicy) -> Self {
        self.eviction_policy = policy;
        self
    }

    /// Get a tensor from cache
    pub fn get(&self, tensor_id: TensorId) -> Option<Arc<TensorHandle>> {
        if let Some(mut entry) = self.entries.get_mut(&tensor_id) {
            entry.last_access = Instant::now();
            entry.access_count += 1;
            self.stats.write().hits += 1;
            Some(entry.handle.clone())
        } else {
            self.stats.write().misses += 1;
            None
        }
    }

    /// Insert a tensor into cache
    pub fn insert(&self, handle: Arc<TensorHandle>) {
        let tensor_id = handle.id();
        let size = handle.size_bytes();

        let entry = CacheEntry {
            handle,
            last_access: Instant::now(),
            access_count: 1,
            eviction_score: 0.0,
        };

        self.entries.insert(tensor_id, entry);
        self.cached_bytes.fetch_add(size, Ordering::Relaxed);

        let mut stats = self.stats.write();
        stats.entries = self.entries.len();
        stats.cached_bytes = self.cached_bytes.load(Ordering::Relaxed);
    }

    /// Remove a tensor from cache
    pub fn remove(&self, tensor_id: TensorId) -> Option<Arc<TensorHandle>> {
        if let Some((_, entry)) = self.entries.remove(&tensor_id) {
            let size = entry.handle.size_bytes();
            self.cached_bytes.fetch_sub(size, Ordering::Relaxed);

            let mut stats = self.stats.write();
            stats.entries = self.entries.len();
            stats.cached_bytes = self.cached_bytes.load(Ordering::Relaxed);

            Some(entry.handle)
        } else {
            None
        }
    }

    /// Protect a tensor from eviction (for prefetch)
    pub fn protect_for_prefetch(&self, tensor_id: TensorId, duration: Duration) {
        let expiry = Instant::now() + duration;
        self.prefetch_protected.insert(tensor_id, expiry);
    }

    /// Check if tensor is protected
    fn is_protected(&self, tensor_id: TensorId) -> bool {
        if let Some(expiry) = self.prefetch_protected.get(&tensor_id) {
            if Instant::now() < *expiry {
                return true;
            }
            // Expired, remove protection
            self.prefetch_protected.remove(&tensor_id);
        }
        false
    }

    /// Select tensors for eviction to free at least `bytes_needed`
    pub fn select_for_eviction(&self, bytes_needed: u64) -> Vec<TensorId> {
        // Clean up expired protections
        self.prefetch_protected
            .retain(|_, expiry| Instant::now() < *expiry);

        // Calculate eviction scores
        let mut candidates: Vec<(TensorId, f64, u64)> = self
            .entries
            .iter()
            .filter(|entry| {
                let handle = &entry.value().handle;
                !handle.is_pinned() && !self.is_protected(*entry.key())
            })
            .map(|entry| {
                let tensor_id = *entry.key();
                let cache_entry = entry.value();
                let score = self.calculate_eviction_score(cache_entry);
                let size = cache_entry.handle.size_bytes();
                (tensor_id, score, size)
            })
            .collect();

        // Sort by eviction score (higher score = evict first)
        candidates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        // Select enough tensors to free required bytes
        let mut selected = Vec::new();
        let mut freed = 0u64;

        for (tensor_id, _, size) in candidates {
            if freed >= bytes_needed {
                break;
            }
            selected.push(tensor_id);
            freed += size;
        }

        selected
    }

    /// Calculate eviction score for a tensor
    fn calculate_eviction_score(&self, entry: &CacheEntry) -> f64 {
        let age = entry.last_access.elapsed().as_secs_f64();
        let size = entry.handle.size_bytes() as f64;
        let access_freq = entry.access_count as f64;

        match self.eviction_policy {
            EvictionPolicy::Lru => age,
            EvictionPolicy::Lfu => 1.0 / (access_freq + 1.0),
            EvictionPolicy::SizeWeightedLru => {
                // Prefer evicting larger, older tensors
                age * size.log2().max(1.0)
            }
            EvictionPolicy::GradientAware => {
                let handle = &entry.handle;
                let base_score = age * size.log2().max(1.0);

                // Prefer keeping gradients and parameters
                if handle.meta.is_gradient {
                    base_score * 0.5 // Less likely to evict gradients
                } else if handle.meta.is_parameter {
                    base_score * 0.3 // Even less likely to evict parameters
                } else {
                    base_score // Activations are fair game
                }
            }
        }
    }

    /// Record eviction
    pub fn record_eviction(&self, count: usize) {
        self.stats.write().evictions += count as u64;
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        self.stats.read().clone()
    }

    /// Get cached bytes
    pub fn cached_bytes(&self) -> u64 {
        self.cached_bytes.load(Ordering::Relaxed)
    }

    /// Get entry count
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear the cache
    pub fn clear(&self) {
        self.entries.clear();
        self.cached_bytes.store(0, Ordering::Relaxed);
        self.prefetch_protected.clear();

        let mut stats = self.stats.write();
        stats.entries = 0;
        stats.cached_bytes = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tensor::TensorDtype;

    fn create_test_handle(size: usize) -> Arc<TensorHandle> {
        let meta = TensorMeta::new(vec![size], TensorDtype::Float32);
        Arc::new(TensorHandle::new(meta))
    }

    #[test]
    fn test_cache_insert_get() {
        let cache = TensorCache::new(CacheConfig::default());
        let handle = create_test_handle(1024);
        let tensor_id = handle.id();

        cache.insert(handle.clone());
        assert_eq!(cache.len(), 1);

        let retrieved = cache.get(tensor_id);
        assert!(retrieved.is_some());
    }

    #[test]
    fn test_cache_remove() {
        let cache = TensorCache::new(CacheConfig::default());
        let handle = create_test_handle(1024);
        let tensor_id = handle.id();

        cache.insert(handle.clone());
        let removed = cache.remove(tensor_id);
        assert!(removed.is_some());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_cache_stats() {
        let cache = TensorCache::new(CacheConfig::default());
        let handle = create_test_handle(1024);
        let tensor_id = handle.id();

        // Miss
        cache.get(TensorId::generate());

        // Insert and hit
        cache.insert(handle.clone());
        cache.get(tensor_id);

        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hit_ratio(), 0.5);
    }

    #[test]
    fn test_eviction_selection() {
        let cache = TensorCache::new(CacheConfig::default());

        // Insert multiple tensors
        for _ in 0..5 {
            let handle = create_test_handle(1000);
            cache.insert(handle);
        }

        // Select for eviction
        let to_evict = cache.select_for_eviction(3000);
        assert!(!to_evict.is_empty());
    }

    #[test]
    fn test_prefetch_protection() {
        let cache = TensorCache::new(CacheConfig::default());
        let handle = create_test_handle(1000);
        let tensor_id = handle.id();

        cache.insert(handle.clone());
        cache.protect_for_prefetch(tensor_id, Duration::from_secs(60));

        // Should not be selected for eviction
        let to_evict = cache.select_for_eviction(1000);
        assert!(!to_evict.contains(&tensor_id));
    }
}
