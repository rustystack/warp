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
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────┐
//! │ NBD Client  │
//! │ (nbd-client)│
//! └──────┬──────┘
//!        │ NBD Protocol
//! ┌──────▼──────┐
//! │  NbdServer  │
//! │  - Extent   │
//! │  - ThinPool │
//! │  - Snapshot │
//! └──────┬──────┘
//!        │
//! ┌──────▼──────┐
//! │  warp-store │
//! └─────────────┘
//! ```

#![warn(missing_docs)]

pub mod config;
pub mod error;
pub mod extent;
pub mod nbd;
pub mod server;
pub mod snapshot;
pub mod thin;
pub mod volume;

pub use config::{BlockConfig, ThinPoolConfig, ThinVolumeConfig};
pub use error::{BlockError, BlockResult};
pub use extent::{BlockExtent, ExtentFlags, ExtentMap};
pub use server::NbdServer;
pub use snapshot::BlockSnapshot;
pub use thin::{ThinPool, ThinVolume};
pub use volume::{Volume, VolumeId, VolumeState};
