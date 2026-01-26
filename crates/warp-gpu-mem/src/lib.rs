//! # warp-gpu-mem: GPU Memory Extension for WARP Storage
//!
//! This crate enables treating WARP storage as extended GPU memory, allowing
//! training of models larger than available GPU VRAM through automatic tensor
//! paging and intelligent prefetching.
//!
//! ## Features
//!
//! - **GPU Pager**: Handles page faults when tensors exceed GPU memory
//! - **ML-Aware Prefetcher**: Predicts tensor access patterns from training loops
//! - **Tensor Cache**: LRU cache for hot tensors with GPU-optimized eviction
//! - **Spill Manager**: Efficiently spills GPU tensors to WARP storage
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                      GPU Memory                              │
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
//! │  │ Hot Tensors │  │ Active Grad │  │ Computation Buffer  │ │
//! │  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘ │
//! └─────────┼────────────────┼───────────────────┼─────────────┘
//!           │                │                    │
//!           ▼                ▼                    ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    warp-gpu-mem                              │
//! │  ┌───────────┐  ┌────────────┐  ┌────────────┐  ┌────────┐ │
//! │  │ GPU Pager │  │ Prefetcher │  │ TensorCache│  │ Spiller│ │
//! │  └─────┬─────┘  └─────┬──────┘  └─────┬──────┘  └────┬───┘ │
//! └────────┼──────────────┼───────────────┼──────────────┼─────┘
//!          │              │               │              │
//!          ▼              ▼               ▼              ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                      warp-store                              │
//! │              (SSD/NVMe/Network Storage)                      │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Example
//!
//! ```rust,ignore
//! use warp_gpu_mem::{GpuMemoryPool, TensorHandle, SpillPolicy};
//!
//! // Create a GPU memory pool with 8GB limit, backed by WARP storage
//! let pool = GpuMemoryPool::new(store, 8 * 1024 * 1024 * 1024)
//!     .with_spill_policy(SpillPolicy::LruWithPrefetch)
//!     .build()
//!     .await?;
//!
//! // Allocate a large tensor (may spill to storage if needed)
//! let weights = pool.allocate_tensor::<f32>(&[1024, 1024, 1024]).await?;
//!
//! // Access tensor data (automatically pages in if spilled)
//! let data = weights.read().await?;
//! ```

#![warn(missing_docs)]
#![allow(dead_code)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::unused_enumerate_index)]
#![allow(clippy::field_reassign_with_default)]

pub mod cache;
pub mod config;
pub mod error;
pub mod pager;
pub mod pool;
pub mod prefetch;
pub mod spill;
pub mod tensor;

pub use cache::{CacheConfig, CacheStats, EvictionPolicy, TensorCache};
pub use config::{GpuMemConfig, PrefetchStrategy, SpillPolicy};
pub use error::{GpuMemError, GpuMemResult};
pub use pager::{GpuPager, PageFault, PageState};
pub use pool::{GpuMemoryPool, PoolStats};
pub use prefetch::{AccessPattern, PrefetchHint, Prefetcher};
pub use spill::{SpillManager, SpillStats, SpilledTensor};
pub use tensor::{TensorHandle, TensorId, TensorLayout, TensorMeta};
