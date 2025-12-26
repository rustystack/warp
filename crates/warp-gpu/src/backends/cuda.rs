//! CUDA Backend Implementation
//!
//! This module provides the CUDA backend using cudarc 0.18.2.
//! It implements the `GpuBackend` trait for NVIDIA GPUs.

use crate::backend::{BackendType, DeviceInfo, GpuBackend, GpuBuffer, GpuFunction, GpuModule, KernelSource};
use crate::{Error, Result};
use cudarc::driver::{
    result as cuda_result,
    sys::CUdevice_attribute,
    CudaContext, CudaFunction as CudarcFunction, CudaModule as CudarcModule,
    CudaSlice, CudaStream,
};
use cudarc::nvrtc::compile_ptx;
use std::sync::Arc;
use tracing::{debug, info};

/// CUDA buffer wrapper
pub struct CudaBuffer {
    /// Raw CUDA slice
    slice: CudaSlice<u8>,
    /// Buffer size in bytes
    size: usize,
}

impl GpuBuffer for CudaBuffer {
    fn size(&self) -> usize {
        self.size
    }
}

impl CudaBuffer {
    /// Get the underlying CUDA slice
    pub fn as_slice(&self) -> &CudaSlice<u8> {
        &self.slice
    }

    /// Get the underlying CUDA slice mutably
    pub fn as_slice_mut(&mut self) -> &mut CudaSlice<u8> {
        &mut self.slice
    }
}

/// CUDA module wrapper
pub struct CudaModule {
    module: Arc<CudarcModule>,
}

impl GpuModule for CudaModule {}

impl CudaModule {
    /// Get the underlying cudarc module
    pub fn inner(&self) -> &Arc<CudarcModule> {
        &self.module
    }
}

/// CUDA function wrapper
pub struct CudaFunction {
    func: CudarcFunction,
}

impl GpuFunction for CudaFunction {}

impl CudaFunction {
    /// Get the underlying cudarc function
    pub fn inner(&self) -> &CudarcFunction {
        &self.func
    }
}

/// CUDA Backend implementation
///
/// Provides GPU acceleration using NVIDIA CUDA via cudarc 0.18.2.
pub struct CudaBackend {
    ctx: Arc<CudaContext>,
    stream: Arc<CudaStream>,
    device_info: DeviceInfo,
    device_id: usize,
}

impl CudaBackend {
    /// Create a new CUDA backend using the specified device
    ///
    /// # Arguments
    /// * `device_id` - CUDA device ordinal (0-based)
    pub fn new(device_id: usize) -> Result<Self> {
        debug!("Initializing CUDA backend for device {}", device_id);

        let ctx = CudaContext::new(device_id)
            .map_err(|e| Error::device_init(device_id, e))?;

        let name = ctx.name()
            .map_err(|e| Error::DeviceQuery(format!("Failed to get device name: {:?}", e)))?;

        info!("CUDA device {} initialized: {}", device_id, name);

        let stream = ctx.default_stream();
        let device_info = Self::query_device_info(device_id, &name)?;

        debug!("CUDA backend ready: {:?}", device_info);

        Ok(Self {
            ctx,
            stream,
            device_info,
            device_id,
        })
    }

    /// Check if CUDA is available on this system
    pub fn is_available() -> bool {
        CudaContext::new(0).is_ok()
    }

    /// Get the number of available CUDA devices
    pub fn device_count() -> Result<usize> {
        let count = cuda_result::device::get_count()
            .map_err(|e| Error::DeviceQuery(format!("Failed to get device count: {:?}", e)))?;
        Ok(count as usize)
    }

    /// Query device information
    fn query_device_info(device_id: usize, name: &str) -> Result<DeviceInfo> {
        let dev = cuda_result::device::get(device_id as i32)
            .map_err(|e| Error::DeviceQuery(format!("Failed to get device {}: {:?}", device_id, e)))?;

        let get_attr = |attr: CUdevice_attribute| -> Result<i32> {
            unsafe {
                cuda_result::device::get_attribute(dev, attr)
                    .map_err(|e| Error::DeviceQuery(format!("Failed to get attribute {:?}: {:?}", attr, e)))
            }
        };

        let total_memory = unsafe {
            cuda_result::device::total_mem(dev)
                .map_err(|e| Error::DeviceQuery(format!("Failed to get total memory: {:?}", e)))?
        };

        let compute_major = get_attr(CUdevice_attribute::CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR)?;
        let compute_minor = get_attr(CUdevice_attribute::CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR)?;
        let max_threads = get_attr(CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAX_THREADS_PER_BLOCK)?;
        let sm_count = get_attr(CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT)?;

        // Estimate CUDA cores based on architecture
        let cores_per_sm = match compute_major {
            3 => 192,  // Kepler
            5 => 128,  // Maxwell
            6 => if compute_minor == 0 { 64 } else { 128 }, // Pascal
            7 => 64,   // Volta/Turing
            8 => 64,   // Ampere
            9 => 128,  // Hopper/Ada
            _ => 64,   // Conservative default
        };

        Ok(DeviceInfo {
            name: name.to_string(),
            backend: BackendType::Cuda,
            compute_capability: (compute_major as u32, compute_minor as u32),
            total_memory,
            max_threads_per_group: max_threads as u32,
            compute_units: sm_count as u32,
            estimated_cores: (sm_count * cores_per_sm) as u32,
        })
    }

    /// Get the underlying CUDA context
    pub fn context(&self) -> &Arc<CudaContext> {
        &self.ctx
    }

    /// Get the default CUDA stream
    pub fn stream(&self) -> &Arc<CudaStream> {
        &self.stream
    }

    /// Get device ID
    pub fn device_id(&self) -> usize {
        self.device_id
    }
}

impl GpuBackend for CudaBackend {
    type Buffer = CudaBuffer;
    type Module = CudaModule;
    type Function = CudaFunction;

    fn device_name(&self) -> &str {
        &self.device_info.name
    }

    fn backend_type(&self) -> BackendType {
        BackendType::Cuda
    }

    fn device_info(&self) -> &DeviceInfo {
        &self.device_info
    }

    fn total_memory(&self) -> usize {
        self.device_info.total_memory
    }

    fn free_memory(&self) -> Result<usize> {
        let (free, _total) = cuda_result::mem_get_info()
            .map_err(|e| Error::DeviceQuery(format!("Failed to get memory info: {:?}", e)))?;
        Ok(free)
    }

    fn allocate(&self, bytes: usize) -> Result<Self::Buffer> {
        let free = self.free_memory()?;
        if bytes > free {
            return Err(Error::out_of_memory(bytes, free));
        }

        let slice = self.stream.alloc_zeros::<u8>(bytes)?;
        Ok(CudaBuffer { slice, size: bytes })
    }

    fn copy_to_device(&self, data: &[u8]) -> Result<Self::Buffer> {
        let slice = self.stream.clone_htod(data)?;
        Ok(CudaBuffer { slice, size: data.len() })
    }

    fn copy_to_host(&self, buffer: &Self::Buffer) -> Result<Vec<u8>> {
        let data = self.stream.clone_dtoh(&buffer.slice)?;
        Ok(data)
    }

    fn compile(&self, source: &KernelSource) -> Result<Self::Module> {
        let cuda_source = source.cuda.ok_or_else(|| {
            Error::InvalidOperation("No CUDA source provided for CUDA backend".into())
        })?;

        debug!("Compiling CUDA kernel ({} bytes)", cuda_source.len());

        let ptx = compile_ptx(cuda_source)
            .map_err(|e| Error::CudaOperation(format!("PTX compilation failed: {:?}", e)))?;

        let module = self.ctx.load_module(ptx)
            .map_err(|e| Error::CudaOperation(format!("Module load failed: {:?}", e)))?;

        Ok(CudaModule { module })
    }

    fn get_function(&self, module: &Self::Module, name: &str) -> Result<Self::Function> {
        let func = module.module.load_function(name)
            .map_err(|e| Error::CudaOperation(format!("Function '{}' not found: {:?}", name, e)))?;

        Ok(CudaFunction { func })
    }

    fn synchronize(&self) -> Result<()> {
        self.ctx.synchronize()?;
        Ok(())
    }
}

impl std::fmt::Debug for CudaBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CudaBackend")
            .field("device_id", &self.device_id)
            .field("device_info", &self.device_info)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cuda_availability() {
        let available = CudaBackend::is_available();
        println!("CUDA available: {}", available);
    }

    #[test]
    fn test_cuda_backend_creation() {
        if !CudaBackend::is_available() {
            println!("Skipping test - no CUDA device available");
            return;
        }

        let backend = CudaBackend::new(0).expect("Failed to create CUDA backend");
        println!("Device: {}", backend.device_name());
        println!("Backend: {}", backend.backend_type());
        println!("Memory: {} bytes", backend.total_memory());

        let info = backend.device_info();
        println!("Compute capability: {}.{}", info.compute_capability.0, info.compute_capability.1);
        println!("Compute units: {}", info.compute_units);
        println!("Estimated cores: {}", info.estimated_cores);
    }

    #[test]
    fn test_cuda_memory_operations() {
        if !CudaBackend::is_available() {
            println!("Skipping test - no CUDA device available");
            return;
        }

        let backend = CudaBackend::new(0).expect("Failed to create CUDA backend");

        // Test allocation
        let buffer = backend.allocate(1024).expect("Failed to allocate");
        assert_eq!(buffer.size(), 1024);

        // Test copy to device and back
        let data = vec![0x42u8; 1024];
        let device_buffer = backend.copy_to_device(&data).expect("Failed to copy to device");
        let host_data = backend.copy_to_host(&device_buffer).expect("Failed to copy to host");
        assert_eq!(host_data, data);
    }

    #[test]
    fn test_cuda_kernel_compilation() {
        if !CudaBackend::is_available() {
            println!("Skipping test - no CUDA device available");
            return;
        }

        let backend = CudaBackend::new(0).expect("Failed to create CUDA backend");

        let source = KernelSource::cuda_only(r#"
            extern "C" __global__ void test_kernel(float* data, int n) {
                int idx = blockIdx.x * blockDim.x + threadIdx.x;
                if (idx < n) {
                    data[idx] *= 2.0f;
                }
            }
        "#);

        let module = backend.compile(&source).expect("Failed to compile kernel");
        let _func = backend.get_function(&module, "test_kernel").expect("Failed to get function");
    }
}
