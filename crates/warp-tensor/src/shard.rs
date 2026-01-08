//! Tensor sharding for large tensors

use std::collections::HashMap;

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::{TensorError, TensorResult};
use crate::tensor::{TensorData, TensorMeta};

/// Sharding strategy for large tensors
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ShardStrategy {
    /// Shard by row (first dimension)
    Row,
    /// Shard by column (last dimension)
    Column,
    /// Shard by fixed byte size
    #[default]
    FixedSize,
    /// No sharding
    None,
}

/// A single shard of a tensor
#[derive(Debug, Clone)]
pub struct TensorShard {
    /// Parent tensor name
    pub tensor_name: String,
    /// Shard index
    pub shard_index: u32,
    /// Total shards
    pub total_shards: u32,
    /// Byte offset in original tensor
    pub byte_offset: u64,
    /// Size in bytes
    pub size_bytes: u64,
    /// Data
    pub data: Bytes,
    /// Checksum
    pub checksum: String,
}

impl TensorShard {
    /// Create a new shard
    pub fn new(
        tensor_name: impl Into<String>,
        shard_index: u32,
        total_shards: u32,
        byte_offset: u64,
        data: Bytes,
    ) -> Self {
        let checksum = blake3::hash(&data).to_hex().to_string();
        Self {
            tensor_name: tensor_name.into(),
            shard_index,
            total_shards,
            byte_offset,
            size_bytes: data.len() as u64,
            data,
            checksum,
        }
    }

    /// Get storage key for this shard
    pub fn storage_key(&self) -> String {
        format!(
            "{}/shard_{:04}_{:04}",
            self.tensor_name, self.shard_index, self.total_shards
        )
    }
}

/// Metadata for a sharded tensor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardedTensorMeta {
    /// Original tensor metadata
    pub meta: TensorMeta,
    /// Sharding strategy
    pub strategy: ShardStrategy,
    /// Shard size (bytes)
    pub shard_size: u64,
    /// Number of shards
    pub num_shards: u32,
    /// Shard keys
    pub shard_keys: Vec<String>,
    /// Shard checksums
    pub shard_checksums: Vec<String>,
}

/// A sharded tensor
#[derive(Debug)]
pub struct ShardedTensor {
    /// Metadata
    pub meta: ShardedTensorMeta,
    /// Shards (may be partially loaded)
    shards: HashMap<u32, TensorShard>,
}

impl ShardedTensor {
    /// Create a new sharded tensor from metadata
    #[must_use]
    pub fn from_meta(meta: ShardedTensorMeta) -> Self {
        Self {
            meta,
            shards: HashMap::new(),
        }
    }

    /// Add a loaded shard
    pub fn add_shard(&mut self, shard: TensorShard) {
        self.shards.insert(shard.shard_index, shard);
    }

    /// Check if all shards are loaded
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.shards.len() == self.meta.num_shards as usize
    }

    /// Get number of loaded shards
    #[must_use]
    pub fn loaded_shards(&self) -> usize {
        self.shards.len()
    }

    /// Reassemble the tensor data
    ///
    /// # Errors
    ///
    /// Returns an error if not all shards are loaded.
    pub fn reassemble(&self) -> TensorResult<TensorData> {
        if !self.is_complete() {
            return Err(TensorError::ShardNotFound {
                tensor_name: self.meta.meta.name.clone(),
                shard_id: self.missing_shards().first().copied().unwrap_or(0),
            });
        }

        // Collect shards in order
        let mut ordered: Vec<&TensorShard> = self.shards.values().collect();
        ordered.sort_by_key(|s| s.shard_index);

        // Concatenate data
        let total_size: usize = ordered.iter().map(|s| s.data.len()).sum();
        let mut data = Vec::with_capacity(total_size);

        for shard in ordered {
            data.extend_from_slice(&shard.data);
        }

        Ok(TensorData::new(self.meta.meta.clone(), Bytes::from(data)))
    }

    /// Get list of missing shard indices
    #[must_use]
    pub fn missing_shards(&self) -> Vec<u32> {
        (0..self.meta.num_shards)
            .filter(|i| !self.shards.contains_key(i))
            .collect()
    }
}

/// Shard a tensor into fixed-size pieces
///
/// # Errors
///
/// Returns an error if the number of shards exceeds the maximum allowed.
pub fn shard_tensor(
    tensor: &TensorData,
    shard_size: u64,
    max_shards: u32,
) -> TensorResult<Vec<TensorShard>> {
    let total_size = tensor.data.len() as u64;

    if total_size <= shard_size {
        // No sharding needed
        return Ok(vec![TensorShard::new(
            tensor.name(),
            0,
            1,
            0,
            tensor.data.clone(),
        )]);
    }

    #[allow(clippy::cast_possible_truncation)]
    let num_shards = total_size.div_ceil(shard_size) as u32;

    if num_shards > max_shards {
        return Err(TensorError::TooManyShards {
            count: num_shards,
            max: max_shards,
        });
    }

    #[allow(clippy::cast_possible_truncation)]
    let mut shards = Vec::with_capacity(num_shards as usize);
    let mut offset = 0u64;

    for i in 0..num_shards {
        #[allow(clippy::cast_possible_truncation)]
        let chunk_size = std::cmp::min(shard_size, total_size - offset) as usize;
        #[allow(clippy::cast_possible_truncation)]
        let start = offset as usize;
        let end = start + chunk_size;

        let data = Bytes::copy_from_slice(&tensor.data[start..end]);
        shards.push(TensorShard::new(tensor.name(), i, num_shards, offset, data));

        offset += chunk_size as u64;
    }

    Ok(shards)
}

/// Create sharded tensor metadata
pub fn create_sharded_meta(
    tensor: &TensorData,
    strategy: ShardStrategy,
    shard_size: u64,
    shards: &[TensorShard],
) -> ShardedTensorMeta {
    #[allow(clippy::cast_possible_truncation)]
    let num_shards = shards.len() as u32;

    ShardedTensorMeta {
        meta: tensor.meta.clone(),
        strategy,
        shard_size,
        num_shards,
        shard_keys: shards.iter().map(TensorShard::storage_key).collect(),
        shard_checksums: shards.iter().map(|s| s.checksum.clone()).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shard_small_tensor() {
        let data: Vec<f32> = vec![1.0, 2.0, 3.0, 4.0];
        let tensor = TensorData::from_f32("small", vec![4], &data);

        // Shard size larger than tensor - should produce 1 shard
        let shards = shard_tensor(&tensor, 1024, 100).unwrap();
        assert_eq!(shards.len(), 1);
        assert_eq!(shards[0].shard_index, 0);
        assert_eq!(shards[0].total_shards, 1);
    }

    #[test]
    fn test_shard_large_tensor() {
        let data: Vec<f32> = vec![0.0; 1000];
        let tensor = TensorData::from_f32("large", vec![1000], &data);

        // 4000 bytes total, 1024 byte shards = 4 shards
        let shards = shard_tensor(&tensor, 1024, 100).unwrap();
        assert_eq!(shards.len(), 4);

        for (i, shard) in shards.iter().enumerate() {
            assert_eq!(shard.shard_index, i as u32);
            assert_eq!(shard.total_shards, 4);
        }
    }

    #[test]
    fn test_too_many_shards() {
        let data: Vec<f32> = vec![0.0; 10000];
        let tensor = TensorData::from_f32("huge", vec![10000], &data);

        // Very small shard size with low limit
        let result = shard_tensor(&tensor, 100, 10);
        assert!(matches!(result, Err(TensorError::TooManyShards { .. })));
    }

    #[test]
    fn test_reassemble_shards() {
        let data: Vec<f32> = (0..1000).map(|i| i as f32).collect();
        let tensor = TensorData::from_f32("test", vec![1000], &data);

        // Shard the tensor
        let shards = shard_tensor(&tensor, 1024, 100).unwrap();
        let sharded_meta = create_sharded_meta(&tensor, ShardStrategy::FixedSize, 1024, &shards);

        // Create sharded tensor and add shards
        let mut sharded = ShardedTensor::from_meta(sharded_meta);
        assert!(!sharded.is_complete());

        for shard in shards {
            sharded.add_shard(shard);
        }
        assert!(sharded.is_complete());

        // Reassemble
        let reassembled = sharded.reassemble().unwrap();
        let recovered = reassembled.as_f32().unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn test_shard_storage_key() {
        let shard = TensorShard::new("model.layer1.weight", 5, 10, 0, Bytes::new());
        assert_eq!(shard.storage_key(), "model.layer1.weight/shard_0005_0010");
    }
}
