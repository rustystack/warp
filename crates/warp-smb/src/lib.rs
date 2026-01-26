//! SMB3 Gateway for WARP Storage
//!
//! This crate provides an SMB3 server that exposes WARP storage as Windows file shares.
//!
//! # Features
//!
//! - SMB3 protocol support (SMB3_0_2, SMB3_1_1)
//! - Opportunistic locks (oplocks) and leases
//! - Distributed File System (DFS) namespace support
//! - POSIX ↔ Windows ACL translation
//! - Change notifications
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────┐
//! │ SMB Client  │
//! └──────┬──────┘
//!        │ SMB3
//! ┌──────▼──────┐
//! │  SmbServer  │
//! │   - Dialect │
//! │   - Session │
//! │   - Oplocks │
//! └──────┬──────┘
//!        │
//! ┌──────▼──────┐
//! │  warp-store │
//! └─────────────┘
//! ```

#![warn(missing_docs)]

pub mod config;
pub mod dfs;
pub mod error;
pub mod handler;
pub mod oplocks;
pub mod protocol;
pub mod security;
pub mod server;
pub mod share;

pub use config::{SmbConfig, SmbDialect};
pub use error::{SmbError, SmbResult};
pub use server::SmbServer;
pub use share::SmbShare;
