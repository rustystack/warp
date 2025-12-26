//! Metal Backend Implementation
//!
//! This module provides the Metal backend using objc2-metal 0.3.2.
//! It implements the `GpuBackend` trait for Apple GPUs (macOS/iOS).
//!
//! Note: This uses the objc2 ecosystem which is the modern replacement
//! for the deprecated gfx-rs/metal-rs crate.

use crate::backend::{BackendType, DeviceInfo, GpuBackend, GpuBuffer, GpuFunction, GpuModule, KernelSource};
use crate::{Error, Result};
use objc2::rc::Retained;
use objc2::runtime::ProtocolObject;
use objc2_foundation::NSString;
use objc2_metal::{
    MTLBuffer, MTLCommandBuffer, MTLCommandQueue, MTLComputePipelineState, MTLDevice,
    MTLFunction, MTLLibrary, MTLResourceOptions,
};
use std::ptr::NonNull;
use tracing::{debug, info};

// Link to CoreGraphics for MTLCreateSystemDefaultDevice
#[link(name = "CoreGraphics", kind = "framework")]
unsafe extern "C" {}

/// Metal buffer wrapper
///
/// Note: Metal buffers are not Send/Sync, so this wrapper provides
/// the necessary unsafe impls for use in the GpuBackend trait.
pub struct MetalBuffer {
    buffer: Retained<ProtocolObject<dyn MTLBuffer>>,
    size: usize,
}

// SAFETY: Metal buffers can be safely shared across threads when properly synchronized
// The MetalBackend handles synchronization via command queue barriers
unsafe impl Send for MetalBuffer {}
unsafe impl Sync for MetalBuffer {}

impl GpuBuffer for MetalBuffer {
    fn size(&self) -> usize {
        self.size
    }
}

impl MetalBuffer {
    /// Get the underlying Metal buffer
    pub fn inner(&self) -> &Retained<ProtocolObject<dyn MTLBuffer>> {
        &self.buffer
    }

    /// Get a raw pointer to the buffer contents
    pub fn contents(&self) -> NonNull<std::ffi::c_void> {
        self.buffer.contents()
    }
}

/// Metal library (compiled shaders) wrapper
pub struct MetalModule {
    library: Retained<ProtocolObject<dyn MTLLibrary>>,
}

// SAFETY: Metal libraries are immutable and can be shared across threads
unsafe impl Send for MetalModule {}
unsafe impl Sync for MetalModule {}

impl GpuModule for MetalModule {}

impl MetalModule {
    /// Get the underlying Metal library
    pub fn inner(&self) -> &Retained<ProtocolObject<dyn MTLLibrary>> {
        &self.library
    }
}

/// Metal compute pipeline wrapper
pub struct MetalFunction {
    pipeline: Retained<ProtocolObject<dyn MTLComputePipelineState>>,
    #[allow(dead_code)]
    function: Retained<ProtocolObject<dyn MTLFunction>>,
}

// SAFETY: Compute pipeline states are immutable and can be shared across threads
unsafe impl Send for MetalFunction {}
unsafe impl Sync for MetalFunction {}

impl GpuFunction for MetalFunction {}

impl MetalFunction {
    /// Get the compute pipeline state
    pub fn pipeline(&self) -> &Retained<ProtocolObject<dyn MTLComputePipelineState>> {
        &self.pipeline
    }
}

/// Metal Backend implementation
///
/// Provides GPU acceleration using Apple Metal via objc2-metal 0.3.2.
pub struct MetalBackend {
    device: Retained<ProtocolObject<dyn MTLDevice>>,
    command_queue: Retained<ProtocolObject<dyn MTLCommandQueue>>,
    device_info: DeviceInfo,
}

// SAFETY: MetalBackend manages synchronization through command queue barriers
// All operations that modify GPU state are synchronized before returning
unsafe impl Send for MetalBackend {}
unsafe impl Sync for MetalBackend {}

impl MetalBackend {
    /// Create a new Metal backend using the system default device
    pub fn new() -> Result<Self> {
        debug!("Initializing Metal backend");

        let device = objc2_metal::MTLCreateSystemDefaultDevice()
            .ok_or_else(|| Error::DeviceInit {
                device_id: 0,
                message: "No Metal-capable device found".into(),
            })?;

        let name = device.name().to_string();
        info!("Metal device initialized: {}", name);

        let command_queue = device.newCommandQueue()
            .ok_or_else(|| Error::DeviceInit {
                device_id: 0,
                message: "Failed to create command queue".into(),
            })?;

        let device_info = Self::query_device_info(&device, &name);

        debug!("Metal backend ready: {:?}", device_info);

        Ok(Self {
            device,
            command_queue,
            device_info,
        })
    }

    /// Check if Metal is available on this system
    pub fn is_available() -> bool {
        objc2_metal::MTLCreateSystemDefaultDevice().is_some()
    }

    /// Query device information
    fn query_device_info(device: &Retained<ProtocolObject<dyn MTLDevice>>, name: &str) -> DeviceInfo {
        // Get GPU family for compute capability equivalent
        let (family_major, family_minor) = Self::get_gpu_family(device);

        // Get recommended working set size as total memory estimate
        // On Apple Silicon, this represents unified memory available to GPU
        let total_memory = device.recommendedMaxWorkingSetSize() as usize;

        // Get max threads per threadgroup
        let size = device.maxThreadsPerThreadgroup();
        let max_threads = size.width as u32;

        // Estimate compute units based on device name
        let compute_units = Self::estimate_compute_units(name);

        // Estimate cores (Apple doesn't expose this directly)
        let estimated_cores = compute_units * 128; // Rough estimate for Apple GPUs

        DeviceInfo {
            name: name.to_string(),
            backend: BackendType::Metal,
            compute_capability: (family_major, family_minor),
            total_memory,
            max_threads_per_group: max_threads,
            compute_units,
            estimated_cores,
        }
    }

    /// Get GPU family version (similar to CUDA compute capability)
    fn get_gpu_family(device: &Retained<ProtocolObject<dyn MTLDevice>>) -> (u32, u32) {
        // Check for Apple GPU families (Apple Silicon)
        // Apple9 = M3 family
        if device.supportsFamily(objc2_metal::MTLGPUFamily::Apple9) {
            return (9, 0);
        }
        // Apple8 = M2 family
        if device.supportsFamily(objc2_metal::MTLGPUFamily::Apple8) {
            return (8, 0);
        }
        // Apple7 = M1 family
        if device.supportsFamily(objc2_metal::MTLGPUFamily::Apple7) {
            return (7, 0);
        }
        // Apple6 = A14
        if device.supportsFamily(objc2_metal::MTLGPUFamily::Apple6) {
            return (6, 0);
        }
        // Apple5 = A12
        if device.supportsFamily(objc2_metal::MTLGPUFamily::Apple5) {
            return (5, 0);
        }

        // Default for older devices
        (4, 0)
    }

    /// Estimate compute units based on device name
    fn estimate_compute_units(name: &str) -> u32 {
        let name_lower = name.to_lowercase();

        // M4 family (newest)
        if name_lower.contains("m4") {
            if name_lower.contains("ultra") { return 80; }
            if name_lower.contains("max") { return 40; }
            if name_lower.contains("pro") { return 20; }
            return 10;
        }

        // M3 family
        if name_lower.contains("m3") {
            if name_lower.contains("ultra") { return 80; }
            if name_lower.contains("max") { return 40; }
            if name_lower.contains("pro") { return 18; }
            return 10;
        }

        // M2 family
        if name_lower.contains("m2") {
            if name_lower.contains("ultra") { return 76; }
            if name_lower.contains("max") { return 38; }
            if name_lower.contains("pro") { return 19; }
            return 10;
        }

        // M1 family
        if name_lower.contains("m1") {
            if name_lower.contains("ultra") { return 64; }
            if name_lower.contains("max") { return 32; }
            if name_lower.contains("pro") { return 16; }
            return 8;
        }

        // Default
        8
    }

    /// Get the underlying Metal device
    pub fn device(&self) -> &Retained<ProtocolObject<dyn MTLDevice>> {
        &self.device
    }

    /// Get the command queue
    pub fn command_queue(&self) -> &Retained<ProtocolObject<dyn MTLCommandQueue>> {
        &self.command_queue
    }
}

impl GpuBackend for MetalBackend {
    type Buffer = MetalBuffer;
    type Module = MetalModule;
    type Function = MetalFunction;

    fn device_name(&self) -> &str {
        &self.device_info.name
    }

    fn backend_type(&self) -> BackendType {
        BackendType::Metal
    }

    fn device_info(&self) -> &DeviceInfo {
        &self.device_info
    }

    fn total_memory(&self) -> usize {
        self.device_info.total_memory
    }

    fn free_memory(&self) -> Result<usize> {
        // Metal doesn't provide a direct free memory API
        // Return current working set size as an approximation
        let current = self.device.currentAllocatedSize() as usize;
        let max = self.device_info.total_memory;
        Ok(max.saturating_sub(current))
    }

    fn allocate(&self, bytes: usize) -> Result<Self::Buffer> {
        let buffer = self.device.newBufferWithLength_options(
            bytes,
            MTLResourceOptions::StorageModeShared,
        ).ok_or_else(|| Error::OutOfMemory {
            size: bytes,
            available: 0,
        })?;

        Ok(MetalBuffer { buffer, size: bytes })
    }

    fn copy_to_device(&self, data: &[u8]) -> Result<Self::Buffer> {
        // SAFETY: data.as_ptr() is valid for the slice's lifetime
        let ptr = NonNull::new(data.as_ptr() as *mut std::ffi::c_void)
            .ok_or_else(|| Error::InvalidOperation("Null pointer in source data".into()))?;

        // SAFETY: ptr is valid and points to data.len() bytes of readable memory
        let buffer = unsafe {
            self.device.newBufferWithBytes_length_options(
                ptr,
                data.len(),
                MTLResourceOptions::StorageModeShared,
            )
        }.ok_or_else(|| Error::OutOfMemory {
            size: data.len(),
            available: 0,
        })?;

        Ok(MetalBuffer { buffer, size: data.len() })
    }

    fn copy_to_host(&self, buffer: &Self::Buffer) -> Result<Vec<u8>> {
        // NonNull is guaranteed to be non-null, so no null check needed
        let ptr = buffer.buffer.contents();

        // SAFETY: ptr is valid and buffer.size was set during allocation
        let slice = unsafe {
            std::slice::from_raw_parts(ptr.as_ptr().cast::<u8>(), buffer.size)
        };

        Ok(slice.to_vec())
    }

    fn compile(&self, source: &KernelSource) -> Result<Self::Module> {
        let metal_source = source.metal.ok_or_else(|| {
            Error::InvalidOperation("No Metal source provided for Metal backend".into())
        })?;

        debug!("Compiling Metal shader ({} bytes)", metal_source.len());

        let source_str = NSString::from_str(metal_source);

        let library = self.device.newLibraryWithSource_options_error(&source_str, None)
            .map_err(|e| {
                Error::ShaderCompilation(format!("Metal shader compilation failed: {:?}", e))
            })?;

        Ok(MetalModule { library })
    }

    fn get_function(&self, module: &Self::Module, name: &str) -> Result<Self::Function> {
        let name_str = NSString::from_str(name);

        let function = module.library.newFunctionWithName(&name_str)
            .ok_or_else(|| {
                Error::InvalidOperation(format!("Function '{}' not found in Metal library", name))
            })?;

        let pipeline = self.device.newComputePipelineStateWithFunction_error(&function)
            .map_err(|e| {
                Error::MetalOperation(format!("Failed to create compute pipeline: {:?}", e))
            })?;

        Ok(MetalFunction { pipeline, function })
    }

    fn synchronize(&self) -> Result<()> {
        // Create a command buffer and wait for completion
        if let Some(cmd_buffer) = self.command_queue.commandBuffer() {
            cmd_buffer.commit();
            cmd_buffer.waitUntilCompleted();
        }
        Ok(())
    }
}

impl std::fmt::Debug for MetalBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetalBackend")
            .field("device_info", &self.device_info)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metal_availability() {
        let available = MetalBackend::is_available();
        println!("Metal available: {}", available);
    }

    #[test]
    fn test_metal_backend_creation() {
        if !MetalBackend::is_available() {
            println!("Skipping test - no Metal device available");
            return;
        }

        let backend = MetalBackend::new().expect("Failed to create Metal backend");
        println!("Device: {}", backend.device_name());
        println!("Backend: {}", backend.backend_type());
        println!("Memory: {} bytes", backend.total_memory());

        let info = backend.device_info();
        println!("GPU Family: {}.{}", info.compute_capability.0, info.compute_capability.1);
        println!("Compute units: {}", info.compute_units);
        println!("Estimated cores: {}", info.estimated_cores);
    }

    #[test]
    fn test_metal_memory_operations() {
        if !MetalBackend::is_available() {
            println!("Skipping test - no Metal device available");
            return;
        }

        let backend = MetalBackend::new().expect("Failed to create Metal backend");

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
    fn test_metal_shader_compilation() {
        if !MetalBackend::is_available() {
            println!("Skipping test - no Metal device available");
            return;
        }

        let backend = MetalBackend::new().expect("Failed to create Metal backend");

        let source = KernelSource::metal_only(r#"
            #include <metal_stdlib>
            using namespace metal;

            kernel void test_kernel(
                device float* data [[buffer(0)]],
                uint idx [[thread_position_in_grid]]
            ) {
                data[idx] *= 2.0f;
            }
        "#);

        let module = backend.compile(&source).expect("Failed to compile shader");
        let _func = backend.get_function(&module, "test_kernel").expect("Failed to get function");
    }
}
