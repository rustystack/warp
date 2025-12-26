//! GPU Backend Implementations
//!
//! This module contains the implementations of the `GpuBackend` trait for
//! different GPU platforms:
//!
//! - `cuda`: NVIDIA CUDA backend (requires `cuda` feature)
//! - `metal`: Apple Metal backend (requires `metal` feature, macOS only)
//!
//! Each backend provides the same interface but uses platform-specific APIs.

#[cfg(feature = "cuda")]
pub mod cuda;

#[cfg(feature = "metal")]
pub mod metal;

// Re-export backends based on feature flags
#[cfg(feature = "cuda")]
pub use cuda::CudaBackend;

#[cfg(feature = "metal")]
pub use metal::MetalBackend;
