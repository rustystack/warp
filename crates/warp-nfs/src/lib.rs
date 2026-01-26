//! NFSv4.1 Gateway for WARP Storage
//!
//! This crate provides an NFSv4.1 server that exposes WARP storage as an NFS share.
//!
//! # Features
//!
//! - NFSv4.1 protocol support with session semantics
//! - Parallel NFS (pNFS) for distributed data access
//! - Client delegations for aggressive caching
//! - Byte-range locking
//! - POSIX ACL support
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────┐
//! │ NFS Client  │
//! └──────┬──────┘
//!        │ NFSv4.1/pNFS
//! ┌──────▼──────┐
//! │  NfsServer  │
//! │   - RPC     │
//! │   - Session │
//! │   - State   │
//! └──────┬──────┘
//!        │
//! ┌──────▼──────┐
//! │  warp-store │
//! └─────────────┘
//! ```

#![warn(missing_docs)]
#![allow(dead_code)]

pub mod config;
pub mod error;
pub mod export;
pub mod nfs4;
pub mod pnfs;
pub mod rpc;
pub mod server;

pub use config::{NfsConfig, NfsExport, SecurityFlavor, SquashMode};
pub use error::{NfsError, NfsResult};
pub use server::NfsServer;
