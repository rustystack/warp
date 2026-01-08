//! Tensor types and metadata

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use serde::{Deserialize, Serialize};

/// Unique tensor identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TensorId(u64);

impl TensorId {
    /// Generate a new unique tensor ID
    pub fn generate() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        Self(COUNTER.fetch_add(1, Ordering::Relaxed))
    }

    /// Create from raw value
    #[must_use]
    pub fn from_raw(id: u64) -> Self {
        Self(id)
    }

    /// Get the raw value
    #[must_use]
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for TensorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tensor_{:016x}", self.0)
    }
}

/// Tensor data type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TensorDtype {
    /// 32-bit floating point
    Float32,
    /// 64-bit floating point
    Float64,
    /// 16-bit floating point (IEEE)
    Float16,
    /// Brain floating point (bfloat16)
    BFloat16,
    /// 32-bit signed integer
    Int32,
    /// 64-bit signed integer
    Int64,
    /// 16-bit signed integer
    Int16,
    /// 8-bit signed integer
    Int8,
    /// 8-bit unsigned integer
    UInt8,
    /// Boolean
    Bool,
    /// 8-bit float (E4M3)
    Float8E4M3,
    /// 8-bit float (E5M2)
    Float8E5M2,
}

impl TensorDtype {
    /// Get the size of one element in bytes
    #[must_use]
    pub fn element_size(&self) -> usize {
        match self {
            Self::Float32 | Self::Int32 => 4,
            Self::Float64 | Self::Int64 => 8,
            Self::Float16 | Self::BFloat16 | Self::Int16 => 2,
            Self::Int8 | Self::UInt8 | Self::Bool | Self::Float8E4M3 | Self::Float8E5M2 => 1,
        }
    }

    /// Get the name of the dtype
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Float32 => "float32",
            Self::Float64 => "float64",
            Self::Float16 => "float16",
            Self::BFloat16 => "bfloat16",
            Self::Int32 => "int32",
            Self::Int64 => "int64",
            Self::Int16 => "int16",
            Self::Int8 => "int8",
            Self::UInt8 => "uint8",
            Self::Bool => "bool",
            Self::Float8E4M3 => "float8_e4m3",
            Self::Float8E5M2 => "float8_e5m2",
        }
    }
}

impl std::str::FromStr for TensorDtype {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "float32" | "f32" => Ok(Self::Float32),
            "float64" | "f64" => Ok(Self::Float64),
            "float16" | "f16" => Ok(Self::Float16),
            "bfloat16" | "bf16" => Ok(Self::BFloat16),
            "int32" | "i32" => Ok(Self::Int32),
            "int64" | "i64" => Ok(Self::Int64),
            "int16" | "i16" => Ok(Self::Int16),
            "int8" | "i8" => Ok(Self::Int8),
            "uint8" | "u8" => Ok(Self::UInt8),
            "bool" => Ok(Self::Bool),
            "float8_e4m3" | "f8_e4m3" => Ok(Self::Float8E4M3),
            "float8_e5m2" | "f8_e5m2" => Ok(Self::Float8E5M2),
            _ => Err(format!("Unknown tensor dtype: {s}")),
        }
    }
}

/// Memory layout
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum TensorLayout {
    /// Row-major (C-style) layout
    #[default]
    RowMajor,
    /// Column-major (Fortran-style) layout
    ColumnMajor,
}

/// Tensor metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TensorMeta {
    /// Unique identifier
    pub id: TensorId,
    /// Tensor name
    pub name: String,
    /// Shape
    pub shape: Vec<usize>,
    /// Data type
    pub dtype: TensorDtype,
    /// Memory layout
    pub layout: TensorLayout,
    /// Size in bytes
    pub size_bytes: u64,
    /// Number of elements
    pub numel: u64,
    /// Checksum of data
    pub checksum: Option<String>,
    /// Compression algorithm used
    pub compression: Option<String>,
    /// Original size before compression
    pub original_size: Option<u64>,
    /// Whether tensor is sharded
    pub is_sharded: bool,
    /// Number of shards (if sharded)
    pub num_shards: Option<u32>,
    /// Storage location (object keys)
    pub storage_keys: Vec<String>,
    /// Custom metadata
    pub custom: HashMap<String, String>,
    /// Creation time
    pub created_at: SystemTime,
}

impl TensorMeta {
    /// Create new tensor metadata
    pub fn new(name: impl Into<String>, shape: Vec<usize>, dtype: TensorDtype) -> Self {
        let numel: u64 = shape.iter().product::<usize>() as u64;
        let size_bytes = numel * dtype.element_size() as u64;

        Self {
            id: TensorId::generate(),
            name: name.into(),
            shape,
            dtype,
            layout: TensorLayout::default(),
            size_bytes,
            numel,
            checksum: None,
            compression: None,
            original_size: None,
            is_sharded: false,
            num_shards: None,
            storage_keys: Vec::new(),
            custom: HashMap::new(),
            created_at: SystemTime::now(),
        }
    }

    /// Set layout
    #[must_use]
    pub fn with_layout(mut self, layout: TensorLayout) -> Self {
        self.layout = layout;
        self
    }

    /// Set checksum
    pub fn with_checksum(mut self, checksum: impl Into<String>) -> Self {
        self.checksum = Some(checksum.into());
        self
    }

    /// Add custom metadata
    pub fn with_custom(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.custom.insert(key.into(), value.into());
        self
    }
}

/// Tensor data container
#[derive(Debug, Clone)]
pub struct TensorData {
    /// Tensor metadata
    pub meta: TensorMeta,
    /// Raw data bytes
    pub data: Bytes,
}

impl TensorData {
    /// Create new tensor data
    pub fn new(meta: TensorMeta, data: Bytes) -> Self {
        Self { meta, data }
    }

    /// Create tensor from f32 slice
    pub fn from_f32(name: impl Into<String>, shape: Vec<usize>, data: &[f32]) -> Self {
        let meta = TensorMeta::new(name, shape, TensorDtype::Float32);
        let bytes: Vec<u8> = data.iter().flat_map(|f| f.to_le_bytes()).collect();
        Self::new(meta, Bytes::from(bytes))
    }

    /// Create tensor from f64 slice
    pub fn from_f64(name: impl Into<String>, shape: Vec<usize>, data: &[f64]) -> Self {
        let meta = TensorMeta::new(name, shape, TensorDtype::Float64);
        let bytes: Vec<u8> = data.iter().flat_map(|f| f.to_le_bytes()).collect();
        Self::new(meta, Bytes::from(bytes))
    }

    /// Create tensor from i32 slice
    pub fn from_i32(name: impl Into<String>, shape: Vec<usize>, data: &[i32]) -> Self {
        let meta = TensorMeta::new(name, shape, TensorDtype::Int32);
        let bytes: Vec<u8> = data.iter().flat_map(|i| i.to_le_bytes()).collect();
        Self::new(meta, Bytes::from(bytes))
    }

    /// Get data as f32 slice
    pub fn as_f32(&self) -> Option<Vec<f32>> {
        if self.meta.dtype != TensorDtype::Float32 {
            return None;
        }
        Some(
            self.data
                .chunks_exact(4)
                .map(|chunk| {
                    let arr: [u8; 4] = chunk.try_into().unwrap();
                    f32::from_le_bytes(arr)
                })
                .collect(),
        )
    }

    /// Get data as f64 slice
    pub fn as_f64(&self) -> Option<Vec<f64>> {
        if self.meta.dtype != TensorDtype::Float64 {
            return None;
        }
        Some(
            self.data
                .chunks_exact(8)
                .map(|chunk| {
                    let arr: [u8; 8] = chunk.try_into().unwrap();
                    f64::from_le_bytes(arr)
                })
                .collect(),
        )
    }

    /// Get name
    pub fn name(&self) -> &str {
        &self.meta.name
    }

    /// Get shape
    pub fn shape(&self) -> &[usize] {
        &self.meta.shape
    }

    /// Get dtype
    pub fn dtype(&self) -> TensorDtype {
        self.meta.dtype
    }

    /// Get size in bytes
    pub fn size_bytes(&self) -> u64 {
        self.meta.size_bytes
    }
}

/// Reference to a lazily-loaded tensor
#[derive(Debug, Clone)]
pub struct LazyTensor {
    /// Tensor metadata
    pub meta: TensorMeta,
    /// Whether data has been loaded
    pub loaded: bool,
    /// Last access time
    pub last_access: Option<Instant>,
}

impl LazyTensor {
    /// Create new lazy tensor reference
    #[must_use]
    pub fn new(meta: TensorMeta) -> Self {
        Self {
            meta,
            loaded: false,
            last_access: None,
        }
    }

    /// Mark as loaded
    pub fn mark_loaded(&mut self) {
        self.loaded = true;
        self.last_access = Some(Instant::now());
    }

    /// Get time since last access
    #[must_use]
    pub fn time_since_access(&self) -> Option<Duration> {
        self.last_access.map(|t| t.elapsed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tensor_id_uniqueness() {
        let id1 = TensorId::generate();
        let id2 = TensorId::generate();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_tensor_dtype_size() {
        assert_eq!(TensorDtype::Float32.element_size(), 4);
        assert_eq!(TensorDtype::Float64.element_size(), 8);
        assert_eq!(TensorDtype::Float16.element_size(), 2);
        assert_eq!(TensorDtype::BFloat16.element_size(), 2);
        assert_eq!(TensorDtype::Int8.element_size(), 1);
    }

    #[test]
    fn test_tensor_dtype_from_str() {
        assert_eq!(TensorDtype::from_str("float32"), Some(TensorDtype::Float32));
        assert_eq!(TensorDtype::from_str("f32"), Some(TensorDtype::Float32));
        assert_eq!(TensorDtype::from_str("bf16"), Some(TensorDtype::BFloat16));
        assert_eq!(TensorDtype::from_str("unknown"), None);
    }

    #[test]
    fn test_tensor_meta() {
        let meta = TensorMeta::new("weight", vec![1024, 512], TensorDtype::Float32);
        assert_eq!(meta.name, "weight");
        assert_eq!(meta.shape, vec![1024, 512]);
        assert_eq!(meta.numel, 1024 * 512);
        assert_eq!(meta.size_bytes, 1024 * 512 * 4);
    }

    #[test]
    fn test_tensor_data_f32() {
        let data: Vec<f32> = vec![1.0, 2.0, 3.0, 4.0];
        let tensor = TensorData::from_f32("test", vec![2, 2], &data);

        assert_eq!(tensor.name(), "test");
        assert_eq!(tensor.shape(), &[2, 2]);
        assert_eq!(tensor.dtype(), TensorDtype::Float32);

        let recovered = tensor.as_f32().unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn test_lazy_tensor() {
        let meta = TensorMeta::new("lazy", vec![100], TensorDtype::Float32);
        let mut lazy = LazyTensor::new(meta);

        assert!(!lazy.loaded);
        assert!(lazy.last_access.is_none());

        lazy.mark_loaded();
        assert!(lazy.loaded);
        assert!(lazy.last_access.is_some());
    }
}
