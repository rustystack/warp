//! Common abstractions for WARP protocol gateways
//!
//! This crate provides shared functionality for NFS, SMB, and Block device gateways:
//! - Lock management (byte-range and whole-file locks)
//! - Session management (client session tracking)
//! - ACL translation (POSIX ↔ Windows)
//! - Filehandle generation (stable, opaque handles)
//! - Delegation/oplock abstraction
//! - Lease management

#![warn(missing_docs)]

pub mod acl;
pub mod delegation;
pub mod error;
pub mod filehandle;
pub mod lease;
pub mod lock;
pub mod session;

pub use acl::{AclEntry, AclTranslator, AccessType, AclPermissions, PrincipalId, UnifiedAcl};
pub use delegation::{Delegation, DelegationManager, DelegationType, DelegationState};
pub use error::{GatewayError, GatewayResult};
pub use filehandle::{FileHandle, FileHandleVersion};
pub use lease::{Lease, LeaseManager, LeaseState};
pub use lock::{
    ByteRangeLock, InMemoryLockManager, LockError, LockManager, LockMode, LockToken,
};
pub use session::{ClientId, ClientSession, SessionConfig, SessionId, SessionManager};
