//! Model checkpointing with incremental saves

use std::collections::HashMap;
use std::time::SystemTime;

use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::config::TensorConfig;
use crate::error::{TensorError, TensorResult};
use crate::shard::ShardedTensorMeta;
use crate::tensor::{LazyTensor, TensorData, TensorMeta};

/// Checkpoint metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointMeta {
    /// Checkpoint name
    pub name: String,
    /// Version number
    pub version: u64,
    /// Parent checkpoint (for incremental)
    pub parent: Option<String>,
    /// Creation time
    pub created_at: SystemTime,
    /// Tensor names in this checkpoint
    pub tensor_names: Vec<String>,
    /// Tensor metadata
    pub tensors: HashMap<String, TensorMeta>,
    /// Sharded tensor metadata (for large tensors)
    pub sharded_tensors: HashMap<String, ShardedTensorMeta>,
    /// Custom metadata
    pub metadata: HashMap<String, String>,
    /// Total size in bytes
    pub total_size: u64,
}

impl CheckpointMeta {
    /// Create a new checkpoint metadata
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: 1,
            parent: None,
            created_at: SystemTime::now(),
            tensor_names: Vec::new(),
            tensors: HashMap::new(),
            sharded_tensors: HashMap::new(),
            metadata: HashMap::new(),
            total_size: 0,
        }
    }

    /// Set parent checkpoint
    #[must_use]
    pub fn with_parent(mut self, parent: impl Into<String>) -> Self {
        self.parent = Some(parent.into());
        self
    }

    /// Add custom metadata
    #[must_use]
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// A checkpoint containing model tensors
#[derive(Debug)]
pub struct Checkpoint {
    /// Checkpoint metadata
    pub meta: CheckpointMeta,
    /// Tensors (owned data)
    tensors: HashMap<String, TensorData>,
    /// Lazy tensors (metadata only)
    lazy_tensors: HashMap<String, LazyTensor>,
}

impl Checkpoint {
    /// Create a new checkpoint
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            meta: CheckpointMeta::new(name),
            tensors: HashMap::new(),
            lazy_tensors: HashMap::new(),
        }
    }

    /// Create from metadata (for lazy loading)
    #[must_use]
    pub fn from_meta(meta: CheckpointMeta) -> Self {
        let lazy_tensors: HashMap<String, LazyTensor> = meta
            .tensors
            .iter()
            .map(|(name, tensor_meta)| (name.clone(), LazyTensor::new(tensor_meta.clone())))
            .collect();

        Self {
            meta,
            tensors: HashMap::new(),
            lazy_tensors,
        }
    }

    /// Create a builder
    pub fn builder(name: impl Into<String>) -> CheckpointBuilder {
        CheckpointBuilder::new(name)
    }

    /// Add a tensor
    pub fn add_tensor(&mut self, tensor: TensorData) {
        let name = tensor.meta.name.clone();
        self.meta.tensor_names.push(name.clone());
        self.meta.tensors.insert(name.clone(), tensor.meta.clone());
        self.meta.total_size += tensor.size_bytes();
        self.tensors.insert(name, tensor);
    }

    /// Get a tensor by name
    #[must_use]
    pub fn get_tensor(&self, name: &str) -> Option<&TensorData> {
        self.tensors.get(name)
    }

    /// Get tensor metadata by name
    #[must_use]
    pub fn get_tensor_meta(&self, name: &str) -> Option<&TensorMeta> {
        self.meta.tensors.get(name)
    }

    /// Check if tensor is loaded
    #[must_use]
    pub fn is_tensor_loaded(&self, name: &str) -> bool {
        self.tensors.contains_key(name)
    }

    /// Get list of tensor names
    #[must_use]
    pub fn tensor_names(&self) -> &[String] {
        &self.meta.tensor_names
    }

    /// Get number of tensors
    #[must_use]
    pub fn tensor_count(&self) -> usize {
        self.meta.tensor_names.len()
    }

    /// Get total size
    #[must_use]
    pub fn total_size(&self) -> u64 {
        self.meta.total_size
    }

    /// Iterate over loaded tensors
    pub fn iter_tensors(&self) -> impl Iterator<Item = (&String, &TensorData)> {
        self.tensors.iter()
    }

    /// Get all loaded tensors
    #[must_use]
    pub fn tensors(&self) -> &HashMap<String, TensorData> {
        &self.tensors
    }
}

/// Builder for creating checkpoints
pub struct CheckpointBuilder {
    name: String,
    parent: Option<String>,
    tensors: Vec<TensorData>,
    metadata: HashMap<String, String>,
}

impl CheckpointBuilder {
    /// Create a new builder
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            parent: None,
            tensors: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Set parent checkpoint (for incremental)
    #[must_use]
    pub fn parent(mut self, parent: impl Into<String>) -> Self {
        self.parent = Some(parent.into());
        self
    }

    /// Add a tensor
    #[must_use]
    pub fn add_tensor(mut self, tensor: TensorData) -> Self {
        self.tensors.push(tensor);
        self
    }

    /// Add f32 tensor from data
    #[must_use]
    pub fn add_f32(mut self, name: impl Into<String>, shape: Vec<usize>, data: &[f32]) -> Self {
        self.tensors.push(TensorData::from_f32(name, shape, data));
        self
    }

    /// Add f64 tensor from data
    #[must_use]
    pub fn add_f64(mut self, name: impl Into<String>, shape: Vec<usize>, data: &[f64]) -> Self {
        self.tensors.push(TensorData::from_f64(name, shape, data));
        self
    }

    /// Add metadata
    #[must_use]
    pub fn metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Build the checkpoint
    #[must_use]
    pub fn build(self) -> Checkpoint {
        let mut checkpoint = Checkpoint::new(self.name);
        checkpoint.meta.parent = self.parent;
        checkpoint.meta.metadata = self.metadata;

        for tensor in self.tensors {
            checkpoint.add_tensor(tensor);
        }

        checkpoint
    }
}

/// Checkpoint manager for tracking and managing checkpoints
pub struct CheckpointManager {
    /// Configuration
    config: TensorConfig,
    /// Active checkpoints
    checkpoints: DashMap<String, CheckpointMeta>,
    /// Checkpoint history (version tracking)
    history: RwLock<Vec<String>>,
}

impl CheckpointManager {
    /// Create a new checkpoint manager
    #[must_use]
    pub fn new(config: TensorConfig) -> Self {
        Self {
            config,
            checkpoints: DashMap::new(),
            history: RwLock::new(Vec::new()),
        }
    }

    /// Register a checkpoint
    pub fn register(&self, meta: CheckpointMeta) {
        let name = meta.name.clone();
        self.checkpoints.insert(name.clone(), meta);
        self.history.write().push(name);
    }

    /// Get checkpoint metadata
    pub fn get_meta(&self, name: &str) -> Option<CheckpointMeta> {
        self.checkpoints.get(name).map(|c| c.clone())
    }

    /// Check if checkpoint exists
    pub fn exists(&self, name: &str) -> bool {
        self.checkpoints.contains_key(name)
    }

    /// List all checkpoints
    pub fn list(&self) -> Vec<String> {
        self.checkpoints.iter().map(|c| c.key().clone()).collect()
    }

    /// Get checkpoint count
    pub fn count(&self) -> usize {
        self.checkpoints.len()
    }

    /// Get history (ordered list of checkpoints)
    pub fn history(&self) -> Vec<String> {
        self.history.read().clone()
    }

    /// Remove a checkpoint
    pub fn remove(&self, name: &str) -> Option<CheckpointMeta> {
        self.checkpoints.remove(name).map(|(_, v)| v)
    }

    /// Find changes between two checkpoints
    ///
    /// # Errors
    ///
    /// Returns an error if either checkpoint does not exist.
    pub fn diff(&self, from: &str, to: &str) -> TensorResult<CheckpointDiff> {
        let from_meta = self
            .get_meta(from)
            .ok_or_else(|| TensorError::CheckpointNotFound(from.to_string()))?;
        let to_meta = self
            .get_meta(to)
            .ok_or_else(|| TensorError::CheckpointNotFound(to.to_string()))?;

        let mut added = Vec::new();
        let mut removed = Vec::new();
        let mut modified = Vec::new();

        // Find added and modified
        for name in &to_meta.tensor_names {
            if let Some(from_tensor) = from_meta.tensors.get(name) {
                let to_tensor = &to_meta.tensors[name];
                if from_tensor.checksum != to_tensor.checksum {
                    modified.push(name.clone());
                }
            } else {
                added.push(name.clone());
            }
        }

        // Find removed
        for name in &from_meta.tensor_names {
            if !to_meta.tensors.contains_key(name) {
                removed.push(name.clone());
            }
        }

        Ok(CheckpointDiff {
            from: from.to_string(),
            to: to.to_string(),
            added,
            removed,
            modified,
        })
    }
}

/// Difference between two checkpoints
#[derive(Debug, Clone)]
pub struct CheckpointDiff {
    /// Source checkpoint
    pub from: String,
    /// Target checkpoint
    pub to: String,
    /// Added tensors
    pub added: Vec<String>,
    /// Removed tensors
    pub removed: Vec<String>,
    /// Modified tensors
    pub modified: Vec<String>,
}

impl CheckpointDiff {
    /// Check if checkpoints are identical
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.modified.is_empty()
    }

    /// Get total number of changes
    #[must_use]
    pub fn change_count(&self) -> usize {
        self.added.len() + self.removed.len() + self.modified.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checkpoint_builder() {
        let checkpoint = Checkpoint::builder("test_v1")
            .add_f32("weight", vec![2, 3], &[1.0, 2.0, 3.0, 4.0, 5.0, 6.0])
            .add_f32("bias", vec![3], &[0.1, 0.2, 0.3])
            .metadata("epoch", "10")
            .metadata("loss", "0.05")
            .build();

        assert_eq!(checkpoint.meta.name, "test_v1");
        assert_eq!(checkpoint.tensor_count(), 2);
        assert!(checkpoint.meta.metadata.contains_key("epoch"));
    }

    #[test]
    fn test_checkpoint_get_tensor() {
        let checkpoint = Checkpoint::builder("test")
            .add_f32("layer1", vec![4], &[1.0, 2.0, 3.0, 4.0])
            .build();

        let tensor = checkpoint.get_tensor("layer1").unwrap();
        assert_eq!(tensor.name(), "layer1");
        assert_eq!(tensor.as_f32().unwrap(), vec![1.0, 2.0, 3.0, 4.0]);

        assert!(checkpoint.get_tensor("nonexistent").is_none());
    }

    #[test]
    fn test_checkpoint_manager() {
        let config = TensorConfig::default();
        let manager = CheckpointManager::new(config);

        let meta1 = CheckpointMeta::new("v1");
        let meta2 = CheckpointMeta::new("v2").with_parent("v1");

        manager.register(meta1);
        manager.register(meta2);

        assert!(manager.exists("v1"));
        assert!(manager.exists("v2"));
        assert!(!manager.exists("v3"));

        assert_eq!(manager.count(), 2);
        assert_eq!(manager.history(), vec!["v1", "v2"]);
    }

    #[test]
    fn test_checkpoint_from_meta() {
        let mut meta = CheckpointMeta::new("loaded");
        let tensor_meta =
            TensorMeta::new("weight", vec![10, 20], crate::tensor::TensorDtype::Float32);
        meta.tensor_names.push("weight".to_string());
        meta.tensors.insert("weight".to_string(), tensor_meta);

        let checkpoint = Checkpoint::from_meta(meta);

        assert_eq!(checkpoint.tensor_count(), 1);
        assert!(!checkpoint.is_tensor_loaded("weight"));
        assert!(checkpoint.get_tensor_meta("weight").is_some());
    }
}
