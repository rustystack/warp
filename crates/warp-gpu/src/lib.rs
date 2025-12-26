//! GPU acceleration primitives for warp
//!
//! This crate provides foundational GPU primitives for accelerated operations:
//! - **Multi-backend support**: CUDA (NVIDIA) and Metal (Apple Silicon)
//! - Device context management and capability queries
//! - Pinned memory pool for zero-copy DMA transfers
//! - Traits for GPU-accelerated hashing, encryption, and compression
//! - Buffer abstractions with lifetime safety
//! - CPU fallback support for portability
//!
//! # Backends
//!
//! - **CUDA**: NVIDIA GPUs via cudarc 0.18.2 (`cuda` feature)
//! - **Metal**: Apple GPUs via objc2-metal 0.3.2 (`metal` feature)
//!
//! # Architecture
//!
//! The design follows these principles:
//! 1. **Zero-copy transfers**: Pinned memory eliminates staging buffers
//! 2. **Memory reuse**: Pooled buffers minimize allocation overhead
//! 3. **Type safety**: Rust ownership prevents use-after-free
//! 4. **CPU fallback**: Traits enable graceful degradation
//! 5. **Backend abstraction**: Common interface for CUDA and Metal
//!
//! # Example (Metal)
//!
//! ```no_run
//! # #[cfg(feature = "metal")]
//! # fn main() -> warp_gpu::Result<()> {
//! use warp_gpu::{GpuBackend, MetalBackend};
//!
//! // Create Metal backend
//! let backend = MetalBackend::new()?;
//! println!("Device: {}", backend.device_name());
//! println!("Memory: {} bytes", backend.total_memory());
//!
//! // Copy data to GPU
//! let data = vec![42u8; 1024];
//! let device_buffer = backend.copy_to_device(&data)?;
//!
//! // Copy back to host
//! let host_data = backend.copy_to_host(&device_buffer)?;
//! assert_eq!(host_data, data);
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "metal"))]
//! # fn main() {}
//! ```
//!
//! # Example (CUDA)
//!
//! ```ignore
//! use warp_gpu::{GpuContext, PinnedMemoryPool};
//!
//! let ctx = GpuContext::new()?;
//! let pool = PinnedMemoryPool::with_defaults(ctx.context().clone());
//!
//! // Acquire pinned buffer for zero-copy transfer
//! let mut buffer = pool.acquire(1024 * 1024)?; // 1MB
//! let data = vec![42u8; 1024 * 1024];
//! buffer.copy_from_slice(&data)?;
//!
//! // Transfer to GPU
//! let device_data = ctx.host_to_device(buffer.as_slice())?;
//!
//! // Return buffer to pool
//! pool.release(buffer);
//! ```

pub mod error;
pub mod backend;
pub mod backends;

#[cfg(feature = "cuda")]
pub mod context;
#[cfg(feature = "cuda")]
pub mod memory;
#[cfg(feature = "cuda")]
pub mod buffer;
pub mod traits;
#[cfg(feature = "cuda")]
pub mod blake3;
#[cfg(feature = "metal")]
pub mod blake3_metal;
#[cfg(feature = "cuda")]
pub mod chacha20;
#[cfg(feature = "metal")]
pub mod chacha20_metal;
#[cfg(feature = "cuda")]
pub mod stream;
#[cfg(feature = "cuda")]
pub mod pooled;

pub use error::{Error, Result};
pub use backend::{BackendType, DeviceInfo, GpuBackend, KernelSource};

#[cfg(feature = "cuda")]
pub use context::{GpuContext, DeviceCapabilities};
#[cfg(feature = "cuda")]
pub use memory::{PinnedBuffer, PinnedMemoryPool, PoolConfig, PoolStatistics};
#[cfg(feature = "cuda")]
pub use buffer::{GpuBuffer, HostBuffer};
pub use traits::{GpuOp, GpuHasher, GpuCipher, GpuCompressor};
#[cfg(feature = "cuda")]
pub use blake3::{Blake3Hasher, Blake3Batch};
#[cfg(feature = "metal")]
pub use blake3_metal::BLAKE3_METAL_KERNEL;
#[cfg(feature = "cuda")]
pub use chacha20::{ChaCha20Poly1305, EncryptionBatch};
#[cfg(feature = "metal")]
pub use chacha20_metal::CHACHA20_METAL_KERNEL;
#[cfg(feature = "cuda")]
pub use stream::{StreamConfig, StreamManager, StreamGuard, PipelineExecutor};
#[cfg(feature = "cuda")]
pub use pooled::{PooledHasher, PooledCipher, create_shared_pool};

// Re-export backend implementations
#[cfg(feature = "cuda")]
pub use backends::cuda::CudaBackend;
#[cfg(feature = "metal")]
pub use backends::metal::MetalBackend;

// Re-export cudarc types for kernel operations (CUDA only)
#[cfg(feature = "cuda")]
pub use cudarc::driver::{CudaFunction, CudaModule, CudaSlice, LaunchConfig};
#[cfg(feature = "cuda")]
pub use cudarc::nvrtc::Ptx;
