//! NVMe-oF Initiator Backend
//!
//! This module provides an NVMe-oF storage backend that connects to remote
//! NVMe-oF targets and uses them as object storage.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                     NvmeOfBackend                            │
//! ├──────────────────────────────────────────────────────────────┤
//! │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
//! │  │ NvmeOfClient │  │ObjectMapper  │  │MetadataStore │       │
//! │  │ (connections)│  │(LBA mapping) │  │(object→block)│       │
//! │  └──────┬───────┘  └──────────────┘  └──────────────┘       │
//! │         │                                                    │
//! │  ┌──────▼───────────────────────────────────────────────────┤
//! │  │               Connection Pool                             │
//! │  │  ┌────────┐  ┌────────┐  ┌────────┐  ...                 │
//! │  │  │Target 1│  │Target 2│  │Target 3│                      │
//! │  │  └────────┘  └────────┘  └────────┘                      │
//! │  └──────────────────────────────────────────────────────────┤
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```rust,no_run
//! use warp_store::backend::nvmeof::{NvmeOfBackend, NvmeOfBackendConfig, NvmeOfTargetConfig};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = NvmeOfBackendConfig {
//!     targets: vec![
//!         NvmeOfTargetConfig {
//!             nqn: "nqn.2024-01.io.warp:storage".into(),
//!             addresses: vec!["192.168.1.100:4420".parse()?],
//!             ..Default::default()
//!         },
//!     ],
//!     ..Default::default()
//! };
//!
//! let backend = NvmeOfBackend::new(config).await?;
//! // Use backend with warp-store
//! # Ok(())
//! # }
//! ```

mod backend;
mod client;
mod config;
mod error;
mod mapper;
mod metadata;
mod pool;
mod transport;

pub use backend::NvmeOfBackend;
pub use client::NvmeOfClient;
pub use config::{
    AllocationStrategy, MetadataBackendConfig, NvmeOfBackendConfig, NvmeOfTargetConfig,
    TransportPreference,
};
pub use error::{NvmeOfBackendError, NvmeOfBackendResult};
pub use mapper::{ObjectBlockMapper, ObjectExtent, ObjectLocation};
pub use metadata::MetadataStore;
pub use pool::{NvmeOfConnectionPool, PoolStats};
