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

#![allow(clippy::expect_fun_call)]
#![allow(clippy::field_reassign_with_default)]

pub mod backend;
pub mod backends;
pub mod error;

#[cfg(feature = "cuda")]
pub mod blake3;
#[cfg(feature = "metal")]
pub mod blake3_metal;
#[cfg(feature = "cuda")]
pub mod buffer;
#[cfg(feature = "cuda")]
pub mod chacha20;
#[cfg(feature = "metal")]
pub mod chacha20_metal;
#[cfg(feature = "cuda")]
pub mod context;
#[cfg(feature = "cuda")]
pub mod memory;
#[cfg(feature = "cuda")]
pub mod pooled;
#[cfg(feature = "cuda")]
pub mod stream;
pub mod traits;

pub use backend::{BackendType, DeviceInfo, GpuBackend, KernelSource};
pub use error::{Error, Result};

#[cfg(feature = "cuda")]
pub use blake3::{Blake3Batch, Blake3Hasher};
#[cfg(feature = "metal")]
pub use blake3_metal::{BLAKE3_METAL_KERNEL, MetalBlake3Hasher};
#[cfg(feature = "cuda")]
pub use buffer::{GpuBuffer, HostBuffer};
#[cfg(feature = "cuda")]
pub use chacha20::{ChaCha20Poly1305, EncryptionBatch};
#[cfg(feature = "metal")]
pub use chacha20_metal::{CHACHA20_METAL_KERNEL, MetalChaCha20Cipher};
#[cfg(feature = "cuda")]
pub use context::{DeviceCapabilities, GpuContext};
#[cfg(feature = "cuda")]
pub use memory::{PinnedBuffer, PinnedMemoryPool, PoolConfig, PoolStatistics};
#[cfg(feature = "cuda")]
pub use pooled::{PooledCipher, PooledHasher, create_shared_pool};
#[cfg(feature = "cuda")]
pub use stream::{PipelineExecutor, StreamConfig, StreamGuard, StreamManager};
pub use traits::{GpuCipher, GpuCompressor, GpuHasher, GpuOp};

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
