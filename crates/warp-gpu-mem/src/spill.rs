//! Spill manager - handles tensor spilling to storage

use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;
use parking_lot::RwLock;
use tokio::sync::Semaphore;

use crate::config::{GpuMemConfig, SpillPolicy};
use crate::error::{GpuMemError, GpuMemResult};
use crate::tensor::{TensorHandle, TensorId};

/// Spilled tensor record
#[derive(Debug, Clone)]
pub struct SpilledTensor {
    /// Tensor ID
    pub tensor_id: TensorId,
    /// Storage key
    pub storage_key: String,
    /// Size in bytes
    pub size_bytes: u64,
    /// Time spilled
    pub spilled_at: std::time::SystemTime,
    /// Chunk keys (for large tensors)
    pub chunk_keys: Vec<String>,
}

/// Spill statistics
#[derive(Debug, Clone, Default)]
pub struct SpillStats {
    /// Total spills
    pub spills: u64,
    /// Total bytes spilled
    pub bytes_spilled: u64,
    /// Total restores
    pub restores: u64,
    /// Total bytes restored
    pub bytes_restored: u64,
    /// Active spilled tensors
    pub active_spilled: usize,
    /// Average spill latency (microseconds)
    pub avg_spill_latency_us: u64,
    /// Average restore latency (microseconds)
    pub avg_restore_latency_us: u64,
}

/// Spill manager
pub struct SpillManager {
    /// Configuration
    config: GpuMemConfig,
    /// Spill policy
    policy: SpillPolicy,
    /// Spilled tensor records
    spilled: DashMap<TensorId, SpilledTensor>,
    /// Bucket for spilled tensors
    bucket: String,
    /// Spill semaphore
    spill_semaphore: Semaphore,
    /// Restore semaphore
    restore_semaphore: Semaphore,
    /// Statistics
    stats: RwLock<SpillStats>,
    /// Spill counter (for unique keys)
    spill_counter: AtomicU64,
}

impl SpillManager {
    /// Create a new spill manager
    pub fn new(config: GpuMemConfig, bucket: impl Into<String>) -> Self {
        let spill_semaphore = Semaphore::new(config.max_concurrent_spills);
        let restore_semaphore = Semaphore::new(config.max_concurrent_page_ins);

        Self {
            policy: config.spill_policy,
            config,
            spilled: DashMap::new(),
            bucket: bucket.into(),
            spill_semaphore,
            restore_semaphore,
            stats: RwLock::new(SpillStats::default()),
            spill_counter: AtomicU64::new(0),
        }
    }

    /// Generate storage key for a tensor
    pub fn generate_storage_key(&self, tensor: &TensorHandle) -> String {
        let counter = self.spill_counter.fetch_add(1, Ordering::SeqCst);
        format!("__gpu_spill__/{}/{:016x}", tensor.id(), counter)
    }

    /// Generate chunk keys for large tensor
    pub fn generate_chunk_keys(&self, tensor: &TensorHandle, num_chunks: usize) -> Vec<String> {
        let base_key = self.generate_storage_key(tensor);
        (0..num_chunks)
            .map(|i| format!("{}/chunk_{:04}", base_key, i))
            .collect()
    }

    /// Get number of chunks needed for tensor
    pub fn num_chunks(&self, tensor: &TensorHandle) -> usize {
        let size = tensor.size_bytes() as usize;
        let chunk_size = self.config.spill_chunk_size;
        size.div_ceil(chunk_size)
    }

    /// Record a spill
    pub fn record_spill(
        &self,
        tensor: &TensorHandle,
        storage_key: String,
        chunk_keys: Vec<String>,
        latency_us: u64,
    ) {
        let record = SpilledTensor {
            tensor_id: tensor.id(),
            storage_key,
            size_bytes: tensor.size_bytes(),
            spilled_at: std::time::SystemTime::now(),
            chunk_keys,
        };

        self.spilled.insert(tensor.id(), record);

        let mut stats = self.stats.write();
        stats.spills += 1;
        stats.bytes_spilled += tensor.size_bytes();
        stats.active_spilled = self.spilled.len();

        // Update running average
        if stats.spills > 0 {
            let total = stats.avg_spill_latency_us * (stats.spills - 1) + latency_us;
            stats.avg_spill_latency_us = total / stats.spills;
        }
    }

    /// Record a restore
    pub fn record_restore(&self, tensor_id: TensorId, latency_us: u64) {
        if let Some((_, record)) = self.spilled.remove(&tensor_id) {
            let mut stats = self.stats.write();
            stats.restores += 1;
            stats.bytes_restored += record.size_bytes;
            stats.active_spilled = self.spilled.len();

            // Update running average
            if stats.restores > 0 {
                let total = stats.avg_restore_latency_us * (stats.restores - 1) + latency_us;
                stats.avg_restore_latency_us = total / stats.restores;
            }
        }
    }

    /// Get spilled tensor info
    pub fn get_spilled(&self, tensor_id: TensorId) -> Option<SpilledTensor> {
        self.spilled.get(&tensor_id).map(|r| r.clone())
    }

    /// Check if tensor is spilled
    pub fn is_spilled(&self, tensor_id: TensorId) -> bool {
        self.spilled.contains_key(&tensor_id)
    }

    /// Get storage key for spilled tensor
    pub fn get_storage_key(&self, tensor_id: TensorId) -> Option<String> {
        self.spilled.get(&tensor_id).map(|r| r.storage_key.clone())
    }

    /// Get all chunk keys for spilled tensor
    pub fn get_chunk_keys(&self, tensor_id: TensorId) -> Option<Vec<String>> {
        self.spilled.get(&tensor_id).map(|r| r.chunk_keys.clone())
    }

    /// Remove spilled record (after restore or delete)
    pub fn remove(&self, tensor_id: TensorId) {
        self.spilled.remove(&tensor_id);
        self.stats.write().active_spilled = self.spilled.len();
    }

    /// Get bucket name
    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    /// Acquire spill permit
    pub async fn acquire_spill_permit(&self) -> GpuMemResult<tokio::sync::SemaphorePermit<'_>> {
        self.spill_semaphore
            .acquire()
            .await
            .map_err(|_| GpuMemError::SpillFailed("semaphore closed".to_string()))
    }

    /// Acquire restore permit
    pub async fn acquire_restore_permit(&self) -> GpuMemResult<tokio::sync::SemaphorePermit<'_>> {
        self.restore_semaphore
            .acquire()
            .await
            .map_err(|_| GpuMemError::PageInFailed("semaphore closed".to_string()))
    }

    /// Get statistics
    pub fn stats(&self) -> SpillStats {
        self.stats.read().clone()
    }

    /// List all spilled tensors
    pub fn list_spilled(&self) -> Vec<SpilledTensor> {
        self.spilled.iter().map(|r| r.clone()).collect()
    }

    /// Get total spilled bytes
    pub fn total_spilled_bytes(&self) -> u64 {
        self.spilled.iter().map(|r| r.size_bytes).sum()
    }

    /// Get spill policy
    pub fn policy(&self) -> SpillPolicy {
        self.policy
    }

    /// Calculate spill priority for a tensor (higher = spill first)
    pub fn calculate_priority(&self, tensor: &TensorHandle, time_since_access_ms: u64) -> f64 {
        let size = tensor.size_bytes() as f64;
        let age = time_since_access_ms as f64;
        let access_count = tensor.access_count() as f64;

        match self.policy {
            SpillPolicy::Lru => age,
            SpillPolicy::LruWithPrefetch => {
                // LRU but reduce priority for frequently accessed tensors
                age / (access_count.log2().max(1.0) + 1.0)
            }
            SpillPolicy::SizeAware => {
                // Prefer spilling larger tensors
                age * size.sqrt()
            }
            SpillPolicy::GradientAware => {
                let base = age * size.sqrt();
                // Reduce priority for gradients and parameters
                if tensor.meta.is_gradient {
                    base * 0.5
                } else if tensor.meta.is_parameter {
                    base * 0.3
                } else {
                    base
                }
            }
            SpillPolicy::CostBased => {
                // Consider recomputation vs reload cost
                // Larger tensors are cheaper to reload than recompute
                let reload_cost = size / (100.0 * 1024.0 * 1024.0); // Normalized by 100MB
                let recompute_cost = if tensor.meta.is_parameter {
                    f64::MAX // Never recompute parameters
                } else {
                    tensor.meta.numel() as f64 * 0.001 // Rough FLOP estimate
                };

                if reload_cost < recompute_cost {
                    age * size.sqrt() // Prefer spilling if cheap to reload
                } else {
                    age * 0.1 // Less likely to spill if expensive to reload
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tensor::{TensorDtype, TensorMeta};

    fn create_test_handle() -> TensorHandle {
        let meta = TensorMeta::new(vec![1024, 1024], TensorDtype::Float32);
        TensorHandle::new(meta)
    }

    #[test]
    fn test_spill_manager_creation() {
        let config = GpuMemConfig::default();
        let mgr = SpillManager::new(config, "test-bucket");

        assert_eq!(mgr.bucket(), "test-bucket");
        assert_eq!(mgr.total_spilled_bytes(), 0);
    }

    #[test]
    fn test_generate_storage_key() {
        let config = GpuMemConfig::default();
        let mgr = SpillManager::new(config, "test-bucket");

        let handle = create_test_handle();
        let key1 = mgr.generate_storage_key(&handle);
        let key2 = mgr.generate_storage_key(&handle);

        // Keys should be unique
        assert_ne!(key1, key2);
        assert!(key1.contains("__gpu_spill__"));
    }

    #[test]
    fn test_num_chunks() {
        let mut config = GpuMemConfig::default();
        config.spill_chunk_size = 1024 * 1024; // 1MB chunks
        let mgr = SpillManager::new(config, "test-bucket");

        let handle = create_test_handle(); // 1024*1024*4 = 4MB
        let chunks = mgr.num_chunks(&handle);

        assert_eq!(chunks, 4);
    }

    #[test]
    fn test_record_spill() {
        let config = GpuMemConfig::default();
        let mgr = SpillManager::new(config, "test-bucket");

        let handle = create_test_handle();
        let key = mgr.generate_storage_key(&handle);
        let chunks = vec![];

        mgr.record_spill(&handle, key.clone(), chunks, 1000);

        assert!(mgr.is_spilled(handle.id()));
        assert_eq!(mgr.get_storage_key(handle.id()), Some(key));

        let stats = mgr.stats();
        assert_eq!(stats.spills, 1);
        assert_eq!(stats.bytes_spilled, handle.size_bytes());
    }

    #[test]
    fn test_record_restore() {
        let config = GpuMemConfig::default();
        let mgr = SpillManager::new(config, "test-bucket");

        let handle = create_test_handle();
        let key = mgr.generate_storage_key(&handle);

        mgr.record_spill(&handle, key, vec![], 1000);
        mgr.record_restore(handle.id(), 500);

        assert!(!mgr.is_spilled(handle.id()));

        let stats = mgr.stats();
        assert_eq!(stats.restores, 1);
    }

    #[test]
    fn test_spill_priority() {
        let config = GpuMemConfig::default();
        let mgr = SpillManager::new(config, "test-bucket");

        let handle = create_test_handle();
        let priority = mgr.calculate_priority(&handle, 1000);

        assert!(priority > 0.0);
    }
}
