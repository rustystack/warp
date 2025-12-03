//! GPU context management for CUDA operations
//!
//! This module provides the core GPU context abstraction that manages
//! CUDA device initialization, capability queries, and resource management.

use crate::{Error, Result};
use cudarc::driver::{
    result as cuda_result,
    sys::CUdevice_attribute,
    CudaContext, CudaFunction, CudaModule, CudaSlice, CudaStream,
    DeviceRepr, LaunchConfig, ValidAsZeroBits,
};
use std::sync::Arc;
use tracing::{debug, info};

/// GPU device capabilities
#[derive(Debug, Clone, Copy)]
pub struct DeviceCapabilities {
    /// Compute capability (major, minor)
    pub compute_capability: (i32, i32),
    /// Total global memory in bytes
    pub total_memory: usize,
    /// Maximum threads per block
    pub max_threads_per_block: i32,
    /// Maximum block dimensions (x, y, z)
    pub max_block_dims: (i32, i32, i32),
    /// Maximum grid dimensions (x, y, z)
    pub max_grid_dims: (i32, i32, i32),
    /// Warp size
    pub warp_size: i32,
    /// Number of multiprocessors
    pub multiprocessor_count: i32,
}

impl DeviceCapabilities {
    /// Check if device supports required compute capability
    pub fn supports_compute(&self, major: i32, minor: i32) -> bool {
        self.compute_capability.0 > major
            || (self.compute_capability.0 == major && self.compute_capability.1 >= minor)
    }

    /// Get total number of CUDA cores (estimated)
    pub fn estimated_cuda_cores(&self) -> i32 {
        // Cores per SM varies by architecture
        let cores_per_sm = match self.compute_capability.0 {
            3 => 192, // Kepler
            5 => 128, // Maxwell
            6 => {
                // Pascal
                match self.compute_capability.1 {
                    0 => 64,
                    1 => 128,
                    _ => 128,
                }
            }
            7 => 64,  // Volta/Turing
            8 => 64,  // Ampere
            9 => 128, // Hopper
            _ => 64,  // Conservative default
        };
        self.multiprocessor_count * cores_per_sm
    }
}

/// GPU context for managing CUDA device and resources
///
/// This context encapsulates a CUDA context and provides methods for:
/// - Device capability queries
/// - Memory information
/// - Synchronization
/// - Resource management
///
/// The context is stored in an Arc for safe sharing across threads.
/// Memory operations use the default stream.
#[derive(Clone)]
pub struct GpuContext {
    ctx: Arc<CudaContext>,
    stream: Arc<CudaStream>,
    capabilities: DeviceCapabilities,
    device_id: usize,
}

impl GpuContext {
    /// Create a new GPU context using the default device (device 0)
    ///
    /// # Errors
    /// Returns an error if:
    /// - No CUDA-capable device is available
    /// - Device initialization fails
    /// - Capability query fails
    pub fn new() -> Result<Self> {
        Self::with_device(0)
    }

    /// Create a new GPU context using a specific device ID
    ///
    /// # Arguments
    /// * `device_id` - The CUDA device ordinal (0-based)
    ///
    /// # Errors
    /// Returns an error if the specified device doesn't exist or initialization fails
    pub fn with_device(device_id: usize) -> Result<Self> {
        debug!("Initializing CUDA device {}", device_id);

        let ctx = CudaContext::new(device_id)
            .map_err(|e| Error::device_init(device_id, e))?;

        let name = ctx.name()
            .map_err(|e| Error::DeviceQuery(format!("Failed to get device name: {:?}", e)))?;

        info!("CUDA device {} initialized: {}", device_id, name);

        // Get default stream for memory operations
        let stream = ctx.default_stream();

        // Query device capabilities
        let capabilities = Self::query_capabilities(device_id)?;

        debug!("Device capabilities: {:?}", capabilities);

        Ok(Self {
            ctx,
            stream,
            capabilities,
            device_id,
        })
    }

    /// Query device capabilities via CUDA API
    fn query_capabilities(device_id: usize) -> Result<DeviceCapabilities> {
        // Get the CUdevice handle for attribute queries
        let dev = cuda_result::device::get(device_id as i32)
            .map_err(|e| Error::DeviceQuery(format!("Failed to get device {}: {:?}", device_id, e)))?;

        // Helper to query a device attribute
        let get_attr = |attr: CUdevice_attribute| -> Result<i32> {
            unsafe {
                cuda_result::device::get_attribute(dev, attr)
                    .map_err(|e| Error::DeviceQuery(format!("Failed to get attribute {:?}: {:?}", attr, e)))
            }
        };

        // Query total memory
        let total_memory = unsafe {
            cuda_result::device::total_mem(dev)
                .map_err(|e| Error::DeviceQuery(format!("Failed to get total memory: {:?}", e)))?
        };

        // Query compute capability
        let compute_major = get_attr(CUdevice_attribute::CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR)?;
        let compute_minor = get_attr(CUdevice_attribute::CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR)?;

        // Query thread/block limits
        let max_threads_per_block = get_attr(CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAX_THREADS_PER_BLOCK)?;
        let max_block_dim_x = get_attr(CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAX_BLOCK_DIM_X)?;
        let max_block_dim_y = get_attr(CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAX_BLOCK_DIM_Y)?;
        let max_block_dim_z = get_attr(CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAX_BLOCK_DIM_Z)?;

        // Query grid limits
        let max_grid_dim_x = get_attr(CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAX_GRID_DIM_X)?;
        let max_grid_dim_y = get_attr(CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAX_GRID_DIM_Y)?;
        let max_grid_dim_z = get_attr(CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAX_GRID_DIM_Z)?;

        // Query other properties
        let warp_size = get_attr(CUdevice_attribute::CU_DEVICE_ATTRIBUTE_WARP_SIZE)?;
        let multiprocessor_count = get_attr(CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT)?;

        Ok(DeviceCapabilities {
            compute_capability: (compute_major, compute_minor),
            total_memory,
            max_threads_per_block,
            max_block_dims: (max_block_dim_x, max_block_dim_y, max_block_dim_z),
            max_grid_dims: (max_grid_dim_x, max_grid_dim_y, max_grid_dim_z),
            warp_size,
            multiprocessor_count,
        })
    }

    /// Get the underlying CUDA context
    #[inline]
    pub fn context(&self) -> &Arc<CudaContext> {
        &self.ctx
    }

    /// Get the default CUDA stream
    #[inline]
    pub fn stream(&self) -> &Arc<CudaStream> {
        &self.stream
    }

    /// Get the underlying CUDA context (alias for backwards compatibility)
    #[inline]
    #[deprecated(note = "Use context() instead")]
    pub fn device(&self) -> &Arc<CudaContext> {
        &self.ctx
    }

    /// Get device ID
    #[inline]
    pub fn device_id(&self) -> usize {
        self.device_id
    }

    /// Get device capabilities
    #[inline]
    pub fn capabilities(&self) -> &DeviceCapabilities {
        &self.capabilities
    }

    /// Get the device name
    pub fn device_name(&self) -> Result<String> {
        self.ctx
            .name()
            .map_err(|e| Error::DeviceQuery(format!("Failed to get device name: {:?}", e)))
    }

    /// Get total global memory in bytes
    #[inline]
    pub fn total_memory(&self) -> usize {
        self.capabilities.total_memory
    }

    /// Get free memory in bytes
    ///
    /// This queries the current free memory on the device using cuMemGetInfo.
    pub fn free_memory(&self) -> Result<usize> {
        // Query via cuMemGetInfo - returns (free, total)
        let (free, _total) = cuda_result::mem_get_info()
            .map_err(|e| Error::DeviceQuery(format!("Failed to get memory info: {:?}", e)))?;
        Ok(free)
    }

    /// Synchronize the context (wait for all operations to complete)
    pub fn synchronize(&self) -> Result<()> {
        self.ctx.synchronize()?;
        Ok(())
    }

    /// Check if GPU has sufficient memory for an operation
    ///
    /// # Arguments
    /// * `required_bytes` - The number of bytes required
    pub fn has_sufficient_memory(&self, required_bytes: usize) -> bool {
        match self.free_memory() {
            Ok(free) => free >= required_bytes,
            Err(_) => false,
        }
    }

    /// Allocate device memory
    ///
    /// # Arguments
    /// * `len` - Number of elements
    ///
    /// # Returns
    /// A new CudaSlice containing zeros
    pub fn allocate<T: DeviceRepr + ValidAsZeroBits>(&self, len: usize) -> Result<CudaSlice<T>> {
        let size = len * std::mem::size_of::<T>();
        let free = self.free_memory()?;
        if size > free {
            return Err(Error::out_of_memory(size, free));
        }

        Ok(self.stream.alloc_zeros::<T>(len)?)
    }

    /// Copy data from host to device
    pub fn host_to_device<T: DeviceRepr>(&self, data: &[T]) -> Result<CudaSlice<T>> {
        Ok(self.stream.clone_htod(data)?)
    }

    /// Copy data from device to host
    pub fn device_to_host<T: DeviceRepr + Clone + Default>(&self, src: &CudaSlice<T>) -> Result<Vec<T>> {
        Ok(self.stream.clone_dtoh(src)?)
    }

    /// Create a new CUDA stream
    pub fn new_stream(&self) -> Result<Arc<CudaStream>> {
        Ok(self.ctx.new_stream()?)
    }

    /// Compile CUDA source code to PTX and load as a module
    ///
    /// # Arguments
    /// * `cuda_source` - CUDA C/C++ source code
    ///
    /// # Returns
    /// Arc-wrapped CudaModule containing the compiled kernels
    ///
    /// # Errors
    /// Returns error if compilation or loading fails
    pub fn compile_and_load(&self, cuda_source: &str) -> Result<Arc<CudaModule>> {
        debug!("Compiling CUDA source ({} bytes)", cuda_source.len());

        // Compile CUDA source to PTX using nvrtc
        let ptx = cudarc::nvrtc::compile_ptx(cuda_source)
            .map_err(|e| Error::CudaOperation(format!("PTX compilation failed: {:?}", e)))?;

        debug!("PTX compilation successful, loading module");

        // Load the PTX module
        let module = self.ctx.load_module(ptx)
            .map_err(|e| Error::CudaOperation(format!("Module load failed: {:?}", e)))?;

        Ok(module)
    }

    /// Load a pre-compiled PTX module
    ///
    /// # Arguments
    /// * `ptx` - Pre-compiled PTX code
    ///
    /// # Returns
    /// Arc-wrapped CudaModule
    pub fn load_ptx(&self, ptx: cudarc::nvrtc::Ptx) -> Result<Arc<CudaModule>> {
        let module = self.ctx.load_module(ptx)
            .map_err(|e| Error::CudaOperation(format!("Module load failed: {:?}", e)))?;
        Ok(module)
    }

    /// Get a kernel function from a loaded module
    ///
    /// # Arguments
    /// * `module` - Arc-wrapped CudaModule
    /// * `name` - Kernel function name
    ///
    /// # Returns
    /// CudaFunction handle for kernel launching
    pub fn get_function(&self, module: &Arc<CudaModule>, name: &str) -> Result<CudaFunction> {
        module.load_function(name)
            .map_err(|e| Error::CudaOperation(format!("Function '{}' not found: {:?}", name, e)))
    }

    /// Get the default launch configuration for a given number of elements
    ///
    /// # Arguments
    /// * `num_elements` - Number of elements to process
    ///
    /// # Returns
    /// LaunchConfig with appropriate grid and block dimensions
    pub fn launch_config_for_elements(&self, num_elements: u32) -> LaunchConfig {
        LaunchConfig::for_num_elems(num_elements)
    }

    /// Create a custom launch configuration
    ///
    /// # Arguments
    /// * `grid` - Grid dimensions (blocks_x, blocks_y, blocks_z)
    /// * `block` - Block dimensions (threads_x, threads_y, threads_z)
    /// * `shared_mem` - Shared memory per block in bytes
    pub fn launch_config(
        &self,
        grid: (u32, u32, u32),
        block: (u32, u32, u32),
        shared_mem: u32,
    ) -> LaunchConfig {
        LaunchConfig {
            grid_dim: grid,
            block_dim: block,
            shared_mem_bytes: shared_mem,
        }
    }
}

impl std::fmt::Debug for GpuContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GpuContext")
            .field("device_id", &self.device_id)
            .field("device_name", &self.device_name().ok())
            .field("capabilities", &self.capabilities)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_capabilities() {
        let caps = DeviceCapabilities {
            compute_capability: (7, 5),
            total_memory: 8 * 1024 * 1024 * 1024,
            max_threads_per_block: 1024,
            max_block_dims: (1024, 1024, 64),
            max_grid_dims: (2147483647, 65535, 65535),
            warp_size: 32,
            multiprocessor_count: 80,
        };

        assert!(caps.supports_compute(7, 0));
        assert!(caps.supports_compute(7, 5));
        assert!(!caps.supports_compute(8, 0));

        let cores = caps.estimated_cuda_cores();
        assert_eq!(cores, 80 * 64); // Volta: 64 cores/SM
    }

    #[test]
    fn test_gpu_context_creation() {
        match GpuContext::new() {
            Ok(ctx) => {
                println!("GPU context created successfully");
                println!("Device ID: {}", ctx.device_id());
                println!("Device: {:?}", ctx.device_name());
                println!("Total memory: {} bytes", ctx.total_memory());
                println!("Capabilities: {:?}", ctx.capabilities());

                assert_eq!(ctx.device_id(), 0);
                assert!(ctx.total_memory() > 0);
            }
            Err(e) => {
                println!("No GPU available (expected in CI): {}", e);
            }
        }
    }

    #[test]
    fn test_memory_query() {
        if let Ok(ctx) = GpuContext::new() {
            let total = ctx.total_memory();
            let free = ctx.free_memory().unwrap();

            println!("Total: {}, Free: {}", total, free);
            assert!(free <= total);
            assert!(free > 0);
        }
    }

    #[test]
    fn test_synchronize() {
        if let Ok(ctx) = GpuContext::new() {
            assert!(ctx.synchronize().is_ok());
        }
    }

    #[test]
    fn test_sufficient_memory() {
        if let Ok(ctx) = GpuContext::new() {
            assert!(ctx.has_sufficient_memory(1024)); // 1KB should always be available
            assert!(!ctx.has_sufficient_memory(usize::MAX)); // Should never have this much
        }
    }
}
