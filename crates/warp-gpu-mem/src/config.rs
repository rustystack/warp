//! Configuration for GPU memory extension

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// GPU memory pool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuMemConfig {
    /// Maximum GPU memory to use (bytes)
    pub max_gpu_memory: u64,

    /// Reserved GPU memory for computation (bytes)
    pub reserved_memory: u64,

    /// Spill threshold (0.0-1.0, trigger spill when usage exceeds this)
    pub spill_threshold: f64,

    /// Page-in threshold (0.0-1.0, allow page-in when below this)
    pub page_in_threshold: f64,

    /// Spill policy
    pub spill_policy: SpillPolicy,

    /// Prefetch strategy
    pub prefetch_strategy: PrefetchStrategy,

    /// Maximum concurrent spill operations
    pub max_concurrent_spills: usize,

    /// Maximum concurrent page-in operations
    pub max_concurrent_page_ins: usize,

    /// Tensor alignment (bytes, typically 256 for GPU)
    pub alignment: usize,

    /// Cache configuration
    pub cache: CacheConfig,

    /// Prefetch lookahead (number of iterations)
    pub prefetch_lookahead: usize,

    /// Spill chunk size (bytes)
    pub spill_chunk_size: usize,
}

impl Default for GpuMemConfig {
    fn default() -> Self {
        Self {
            max_gpu_memory: 8 * 1024 * 1024 * 1024, // 8 GB
            reserved_memory: 512 * 1024 * 1024,     // 512 MB
            spill_threshold: 0.85,
            page_in_threshold: 0.70,
            spill_policy: SpillPolicy::LruWithPrefetch,
            prefetch_strategy: PrefetchStrategy::TrainingAware,
            max_concurrent_spills: 4,
            max_concurrent_page_ins: 4,
            alignment: 256,
            cache: CacheConfig::default(),
            prefetch_lookahead: 2,
            spill_chunk_size: 64 * 1024 * 1024, // 64 MB chunks
        }
    }
}

/// Spill policy - determines which tensors to evict
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SpillPolicy {
    /// Least Recently Used
    Lru,

    /// LRU with prefetch awareness (don't evict soon-to-be-used tensors)
    #[default]
    LruWithPrefetch,

    /// Size-aware (prefer evicting larger tensors)
    SizeAware,

    /// Gradient-aware (prefer evicting activations over gradients)
    GradientAware,

    /// Cost-based (consider recomputation vs reload cost)
    CostBased,
}

/// Prefetch strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PrefetchStrategy {
    /// No prefetching
    None,

    /// Sequential prefetch (based on access order)
    Sequential,

    /// Training-aware (understands forward/backward pass patterns)
    #[default]
    TrainingAware,

    /// ML-model driven (uses SLAI predictions)
    ModelDriven,
}

/// Cache configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Maximum entries in tensor metadata cache
    pub max_entries: usize,

    /// TTL for cached entries
    pub ttl: Duration,

    /// Enable async writeback
    pub async_writeback: bool,

    /// Writeback delay
    pub writeback_delay: Duration,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 10000,
            ttl: Duration::from_secs(3600),
            async_writeback: true,
            writeback_delay: Duration::from_millis(100),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = GpuMemConfig::default();
        assert_eq!(config.max_gpu_memory, 8 * 1024 * 1024 * 1024);
        assert_eq!(config.spill_policy, SpillPolicy::LruWithPrefetch);
        assert_eq!(config.prefetch_strategy, PrefetchStrategy::TrainingAware);
    }

    #[test]
    fn test_spill_threshold() {
        let config = GpuMemConfig::default();
        assert!(config.spill_threshold > config.page_in_threshold);
    }
}
