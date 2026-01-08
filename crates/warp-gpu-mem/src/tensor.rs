//! Tensor handle and metadata

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

/// Unique tensor identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TensorId(u64);

impl TensorId {
    /// Generate a new unique tensor ID
    pub fn generate() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Self(COUNTER.fetch_add(1, Ordering::SeqCst))
    }

    /// Create from raw value
    pub fn from_raw(val: u64) -> Self {
        Self(val)
    }

    /// Get raw value
    pub fn raw(&self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for TensorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tensor-{:016x}", self.0)
    }
}

/// Tensor data type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum TensorDtype {
    /// 32-bit float
    #[default]
    Float32,
    /// 64-bit float
    Float64,
    /// 16-bit float (half precision)
    Float16,
    /// Brain float 16
    BFloat16,
    /// 32-bit integer
    Int32,
    /// 64-bit integer
    Int64,
    /// 8-bit integer
    Int8,
    /// 8-bit unsigned integer
    UInt8,
    /// Boolean
    Bool,
}

impl TensorDtype {
    /// Get size in bytes
    pub fn size_bytes(&self) -> usize {
        match self {
            TensorDtype::Float32 | TensorDtype::Int32 => 4,
            TensorDtype::Float64 | TensorDtype::Int64 => 8,
            TensorDtype::Float16 | TensorDtype::BFloat16 => 2,
            TensorDtype::Int8 | TensorDtype::UInt8 | TensorDtype::Bool => 1,
        }
    }

    /// Get name
    pub fn name(&self) -> &'static str {
        match self {
            TensorDtype::Float32 => "float32",
            TensorDtype::Float64 => "float64",
            TensorDtype::Float16 => "float16",
            TensorDtype::BFloat16 => "bfloat16",
            TensorDtype::Int32 => "int32",
            TensorDtype::Int64 => "int64",
            TensorDtype::Int8 => "int8",
            TensorDtype::UInt8 => "uint8",
            TensorDtype::Bool => "bool",
        }
    }
}

/// Tensor memory layout
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum TensorLayout {
    /// Row-major (C-style)
    #[default]
    RowMajor,
    /// Column-major (Fortran-style)
    ColumnMajor,
}

/// Tensor location
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TensorLocation {
    /// Tensor is in GPU memory
    Gpu,
    /// Tensor is spilled to storage
    Storage,
    /// Tensor is being transferred
    Transferring,
}

/// Tensor metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TensorMeta {
    /// Tensor ID
    pub id: TensorId,

    /// Name (optional, for debugging)
    pub name: Option<String>,

    /// Shape
    pub shape: Vec<usize>,

    /// Data type
    pub dtype: TensorDtype,

    /// Memory layout
    pub layout: TensorLayout,

    /// Size in bytes
    pub size_bytes: u64,

    /// Storage key (when spilled)
    pub storage_key: Option<String>,

    /// Is gradient tensor
    pub is_gradient: bool,

    /// Is parameter (weight) tensor
    pub is_parameter: bool,

    /// Layer index (for training awareness)
    pub layer_index: Option<usize>,

    /// Creation time
    pub created_at: std::time::SystemTime,
}

impl TensorMeta {
    /// Create new tensor metadata
    pub fn new(shape: Vec<usize>, dtype: TensorDtype) -> Self {
        let numel: usize = shape.iter().product();
        let size_bytes = (numel * dtype.size_bytes()) as u64;

        Self {
            id: TensorId::generate(),
            name: None,
            shape,
            dtype,
            layout: TensorLayout::default(),
            size_bytes,
            storage_key: None,
            is_gradient: false,
            is_parameter: false,
            layer_index: None,
            created_at: std::time::SystemTime::now(),
        }
    }

    /// Set name
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Mark as gradient
    pub fn as_gradient(mut self) -> Self {
        self.is_gradient = true;
        self
    }

    /// Mark as parameter
    pub fn as_parameter(mut self) -> Self {
        self.is_parameter = true;
        self
    }

    /// Set layer index
    pub fn with_layer(mut self, index: usize) -> Self {
        self.layer_index = Some(index);
        self
    }

    /// Get number of elements
    pub fn numel(&self) -> usize {
        self.shape.iter().product()
    }

    /// Get number of dimensions
    pub fn ndim(&self) -> usize {
        self.shape.len()
    }
}

/// Handle to a tensor in the GPU memory pool
pub struct TensorHandle {
    /// Tensor metadata
    pub meta: TensorMeta,
    /// Current location
    location: RwLock<TensorLocation>,
    /// Last access time
    last_access: RwLock<Instant>,
    /// Access count
    access_count: AtomicU64,
    /// Is pinned (cannot be spilled)
    pinned: RwLock<bool>,
}

impl TensorHandle {
    /// Create a new tensor handle
    pub fn new(meta: TensorMeta) -> Self {
        Self {
            meta,
            location: RwLock::new(TensorLocation::Gpu),
            last_access: RwLock::new(Instant::now()),
            access_count: AtomicU64::new(0),
            pinned: RwLock::new(false),
        }
    }

    /// Get tensor ID
    pub fn id(&self) -> TensorId {
        self.meta.id
    }

    /// Get tensor size in bytes
    pub fn size_bytes(&self) -> u64 {
        self.meta.size_bytes
    }

    /// Get current location
    pub fn location(&self) -> TensorLocation {
        *self.location.read()
    }

    /// Set location
    pub fn set_location(&self, loc: TensorLocation) {
        *self.location.write() = loc;
    }

    /// Record an access
    pub fn record_access(&self) {
        *self.last_access.write() = Instant::now();
        self.access_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Get time since last access
    pub fn time_since_access(&self) -> Duration {
        self.last_access.read().elapsed()
    }

    /// Get access count
    pub fn access_count(&self) -> u64 {
        self.access_count.load(Ordering::Relaxed)
    }

    /// Check if tensor is in GPU memory
    pub fn is_resident(&self) -> bool {
        matches!(*self.location.read(), TensorLocation::Gpu)
    }

    /// Check if tensor is spilled
    pub fn is_spilled(&self) -> bool {
        matches!(*self.location.read(), TensorLocation::Storage)
    }

    /// Pin tensor (prevent spilling)
    pub fn pin(&self) {
        *self.pinned.write() = true;
    }

    /// Unpin tensor
    pub fn unpin(&self) {
        *self.pinned.write() = false;
    }

    /// Check if pinned
    pub fn is_pinned(&self) -> bool {
        *self.pinned.read()
    }
}

impl std::fmt::Debug for TensorHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TensorHandle")
            .field("id", &self.meta.id)
            .field("shape", &self.meta.shape)
            .field("dtype", &self.meta.dtype)
            .field("location", &self.location())
            .field("size_bytes", &self.meta.size_bytes)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tensor_id_uniqueness() {
        let ids: Vec<TensorId> = (0..100).map(|_| TensorId::generate()).collect();
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(ids.len(), unique.len());
    }

    #[test]
    fn test_tensor_dtype_size() {
        assert_eq!(TensorDtype::Float32.size_bytes(), 4);
        assert_eq!(TensorDtype::Float64.size_bytes(), 8);
        assert_eq!(TensorDtype::Float16.size_bytes(), 2);
        assert_eq!(TensorDtype::Int8.size_bytes(), 1);
    }

    #[test]
    fn test_tensor_meta() {
        let meta = TensorMeta::new(vec![32, 64, 128], TensorDtype::Float32)
            .with_name("layer1.weight")
            .as_parameter()
            .with_layer(0);

        assert_eq!(meta.numel(), 32 * 64 * 128);
        assert_eq!(meta.size_bytes, (32 * 64 * 128 * 4) as u64);
        assert!(meta.is_parameter);
        assert_eq!(meta.layer_index, Some(0));
    }

    #[test]
    fn test_tensor_handle() {
        let meta = TensorMeta::new(vec![1024, 1024], TensorDtype::Float32);
        let handle = TensorHandle::new(meta);

        assert!(handle.is_resident());
        assert!(!handle.is_spilled());
        assert!(!handle.is_pinned());

        handle.pin();
        assert!(handle.is_pinned());

        handle.record_access();
        assert_eq!(handle.access_count(), 1);
    }
}
