#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::collapsible_if)]
#![allow(dead_code)]
#![allow(unused_imports)]

//! NBD Block Device Gateway for WARP Storage
//!
//! This crate provides a Network Block Device (NBD) server that exposes
//! WARP storage as virtual block devices.
//!
//! # Features
//!
//! - NBD protocol support for Linux clients
//! - Thin provisioning with allocate-on-write
//! - Extent-based block-to-object mapping
//! - Copy-on-write (COW) snapshots
//! - TRIM/discard support
//! - NVMe over Fabrics (NVMe-oF) target support
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────┐     ┌─────────────┐
//! │ NBD Client  │     │ NVMe Client │
//! │ (nbd-client)│     │ (nvme-cli)  │
//! └──────┬──────┘     └──────┬──────┘
//!        │ NBD Protocol       │ NVMe-oF
//! ┌──────▼──────┐     ┌──────▼──────┐
//! │  NbdServer  │     │NvmeOfTarget │
//! │  - Extent   │     │ - Subsystem │
//! │  - ThinPool │     │ - Namespace │
//! │  - Snapshot │     │ - Transport │
//! └──────┬──────┘     └──────┬──────┘
//!        │                   │
//!        └─────────┬─────────┘
//!                  │
//!           ┌──────▼──────┐
//!           │  warp-store │
//!           └─────────────┘
//! ```

#![warn(missing_docs)]

pub mod config;
pub mod error;
pub mod extent;
pub mod nbd;
pub mod nvmeof;
#[cfg(feature = "nbd-server")]
pub mod server;
pub mod snapshot;
pub mod thin;
pub mod volume;

pub use config::{BlockConfig, ThinPoolConfig, ThinVolumeConfig};
pub use error::{BlockError, BlockResult};
pub use extent::{BlockExtent, ExtentFlags, ExtentMap};
#[cfg(feature = "nbd-server")]
pub use server::NbdServer;
pub use snapshot::BlockSnapshot;
pub use thin::{ThinPool, ThinVolume};
pub use volume::{Volume, VolumeId, VolumeState};

// NVMe-oF re-exports (always available for types, feature-gated for runtime)
pub use nvmeof::{
    DISCOVERY_NQN, NvmeOfConfig, NvmeOfError, NvmeOfResult, SubsystemConfig, WARP_NQN_PREFIX,
    generate_nqn, validate_nqn,
};

#[cfg(feature = "nvmeof")]
pub use nvmeof::{
    AsyncVolume, DiscoveryService, NvmeOfConnection, NvmeOfNamespace, NvmeOfSubsystem, NvmeOfTarget,
};
