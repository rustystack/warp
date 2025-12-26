//! GPU Backend Abstraction
//!
//! This module provides a common interface for GPU backends (CUDA, Metal).
//! Each backend implements the `GpuBackend` trait to provide:
//! - Device context management
//! - Memory allocation and transfer
//! - Kernel compilation and execution
//!
//! # Feature Flags
//!
//! - `cuda`: Enable CUDA backend for NVIDIA GPUs
//! - `metal`: Enable Metal backend for Apple GPUs (macOS/iOS)
//!
//! # Example
//!
//! ```ignore
//! use warp_gpu::backend::{GpuBackend, create_default_backend};
//!
//! let backend = create_default_backend()?;
//! println!("Using GPU: {}", backend.device_name());
//! ```

use crate::Result;

/// Kernel source code for different backends
#[derive(Debug, Clone)]
pub struct KernelSource {
    /// CUDA C source code
    pub cuda: Option<&'static str>,
    /// Metal Shading Language source code
    pub metal: Option<&'static str>,
}

impl KernelSource {
    /// Create kernel source with CUDA code only
    pub const fn cuda_only(cuda: &'static str) -> Self {
        Self {
            cuda: Some(cuda),
            metal: None,
        }
    }

    /// Create kernel source with Metal code only
    pub const fn metal_only(metal: &'static str) -> Self {
        Self {
            cuda: None,
            metal: Some(metal),
        }
    }

    /// Create kernel source with both CUDA and Metal code
    pub const fn both(cuda: &'static str, metal: &'static str) -> Self {
        Self {
            cuda: Some(cuda),
            metal: Some(metal),
        }
    }
}

/// Device capabilities returned by backends
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    /// Device name (e.g., "NVIDIA RTX 4090", "Apple M3 Max")
    pub name: String,
    /// Backend type
    pub backend: BackendType,
    /// Compute capability or GPU family
    pub compute_capability: (u32, u32),
    /// Total device memory in bytes
    pub total_memory: usize,
    /// Maximum threads per threadgroup/block
    pub max_threads_per_group: u32,
    /// Number of compute units (SMs for CUDA, compute units for Metal)
    pub compute_units: u32,
    /// Estimated total cores
    pub estimated_cores: u32,
}

/// Backend type identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendType {
    /// NVIDIA CUDA backend
    Cuda,
    /// Apple Metal backend
    Metal,
    /// CPU fallback (no GPU)
    Cpu,
}

impl std::fmt::Display for BackendType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendType::Cuda => write!(f, "CUDA"),
            BackendType::Metal => write!(f, "Metal"),
            BackendType::Cpu => write!(f, "CPU"),
        }
    }
}

/// GPU buffer handle (opaque, backend-specific)
pub trait GpuBuffer: Send + Sync {
    /// Get buffer size in bytes
    fn size(&self) -> usize;
}

/// Compiled kernel module handle (opaque, backend-specific)
pub trait GpuModule: Send + Sync {}

/// Kernel function handle (opaque, backend-specific)
pub trait GpuFunction: Send + Sync {}

/// Abstract GPU backend trait
///
/// This trait provides a unified interface for GPU operations across different
/// backends (CUDA, Metal). Implementations handle backend-specific details.
pub trait GpuBackend: Send + Sync {
    /// Buffer type for this backend
    type Buffer: GpuBuffer;
    /// Module type for this backend
    type Module: GpuModule;
    /// Function type for this backend
    type Function: GpuFunction;

    // =========================================================================
    // Device Information
    // =========================================================================

    /// Get device name
    fn device_name(&self) -> &str;

    /// Get backend type
    fn backend_type(&self) -> BackendType;

    /// Get detailed device information
    fn device_info(&self) -> &DeviceInfo;

    /// Get total device memory in bytes
    fn total_memory(&self) -> usize;

    /// Get free device memory in bytes
    fn free_memory(&self) -> Result<usize>;

    /// Check if device has sufficient memory
    fn has_sufficient_memory(&self, required_bytes: usize) -> bool {
        match self.free_memory() {
            Ok(free) => free >= required_bytes,
            Err(_) => false,
        }
    }

    // =========================================================================
    // Memory Operations
    // =========================================================================

    /// Allocate device memory
    ///
    /// # Arguments
    /// * `bytes` - Number of bytes to allocate
    ///
    /// # Returns
    /// Opaque buffer handle
    fn allocate(&self, bytes: usize) -> Result<Self::Buffer>;

    /// Copy data from host to device
    ///
    /// # Arguments
    /// * `data` - Host data to copy
    ///
    /// # Returns
    /// Device buffer containing the data
    fn copy_to_device(&self, data: &[u8]) -> Result<Self::Buffer>;

    /// Copy data from device to host
    ///
    /// # Arguments
    /// * `buffer` - Device buffer to copy from
    ///
    /// # Returns
    /// Vector containing the data
    fn copy_to_host(&self, buffer: &Self::Buffer) -> Result<Vec<u8>>;

    // =========================================================================
    // Kernel Operations
    // =========================================================================

    /// Compile kernel source code
    ///
    /// # Arguments
    /// * `source` - Kernel source code for the appropriate backend
    ///
    /// # Returns
    /// Compiled module handle
    fn compile(&self, source: &KernelSource) -> Result<Self::Module>;

    /// Get a function from a compiled module
    ///
    /// # Arguments
    /// * `module` - Compiled module
    /// * `name` - Function name
    ///
    /// # Returns
    /// Function handle for launching
    fn get_function(&self, module: &Self::Module, name: &str) -> Result<Self::Function>;

    // =========================================================================
    // Synchronization
    // =========================================================================

    /// Synchronize device (wait for all operations to complete)
    fn synchronize(&self) -> Result<()>;
}

/// Minimum size for GPU acceleration (below this, CPU is faster)
pub const DEFAULT_GPU_THRESHOLD: usize = 64 * 1024; // 64KB

/// Check if GPU should be used based on data size
pub fn should_use_gpu(data_size: usize, threshold: usize) -> bool {
    data_size >= threshold
}

// =============================================================================
// Backend Factory Functions
// =============================================================================

/// Create the default GPU backend for the current platform
///
/// Priority order:
/// 1. CUDA (if available and `cuda` feature enabled)
/// 2. Metal (if available and `metal` feature enabled on macOS)
/// 3. Returns error if no GPU available
#[cfg(feature = "cuda")]
pub fn create_default_backend() -> Result<impl GpuBackend> {
    use crate::backends::cuda::CudaBackend;
    CudaBackend::new(0)
}

#[cfg(all(feature = "metal", not(feature = "cuda")))]
pub fn create_default_backend() -> Result<impl GpuBackend> {
    use crate::backends::metal::MetalBackend;
    MetalBackend::new()
}

#[cfg(not(any(feature = "cuda", feature = "metal")))]
pub fn create_default_backend() -> Result<()> {
    Err(crate::Error::InvalidOperation(
        "No GPU backend available. Enable 'cuda' or 'metal' feature.".into()
    ))
}

/// Check if any GPU backend is available
pub fn is_gpu_available() -> bool {
    #[cfg(feature = "cuda")]
    {
        if crate::backends::cuda::CudaBackend::is_available() {
            return true;
        }
    }

    #[cfg(feature = "metal")]
    {
        if crate::backends::metal::MetalBackend::is_available() {
            return true;
        }
    }

    false
}

/// Get list of available backends
pub fn available_backends() -> Vec<BackendType> {
    let mut backends = Vec::new();

    #[cfg(feature = "cuda")]
    {
        if crate::backends::cuda::CudaBackend::is_available() {
            backends.push(BackendType::Cuda);
        }
    }

    #[cfg(feature = "metal")]
    {
        if crate::backends::metal::MetalBackend::is_available() {
            backends.push(BackendType::Metal);
        }
    }

    backends
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kernel_source_creation() {
        let cuda_only = KernelSource::cuda_only("__global__ void test() {}");
        assert!(cuda_only.cuda.is_some());
        assert!(cuda_only.metal.is_none());

        let metal_only = KernelSource::metal_only("kernel void test() {}");
        assert!(metal_only.cuda.is_none());
        assert!(metal_only.metal.is_some());

        let both = KernelSource::both(
            "__global__ void test() {}",
            "kernel void test() {}"
        );
        assert!(both.cuda.is_some());
        assert!(both.metal.is_some());
    }

    #[test]
    fn test_backend_type_display() {
        assert_eq!(format!("{}", BackendType::Cuda), "CUDA");
        assert_eq!(format!("{}", BackendType::Metal), "Metal");
        assert_eq!(format!("{}", BackendType::Cpu), "CPU");
    }

    #[test]
    fn test_should_use_gpu() {
        assert!(!should_use_gpu(1024, DEFAULT_GPU_THRESHOLD));
        assert!(!should_use_gpu(32 * 1024, DEFAULT_GPU_THRESHOLD));
        assert!(should_use_gpu(64 * 1024, DEFAULT_GPU_THRESHOLD));
        assert!(should_use_gpu(1024 * 1024, DEFAULT_GPU_THRESHOLD));
    }

    #[test]
    fn test_device_info_debug() {
        let info = DeviceInfo {
            name: "Test GPU".to_string(),
            backend: BackendType::Cuda,
            compute_capability: (8, 9),
            total_memory: 24 * 1024 * 1024 * 1024,
            max_threads_per_group: 1024,
            compute_units: 128,
            estimated_cores: 16384,
        };

        let debug_str = format!("{:?}", info);
        assert!(debug_str.contains("Test GPU"));
        assert!(debug_str.contains("Cuda"));
    }
}
