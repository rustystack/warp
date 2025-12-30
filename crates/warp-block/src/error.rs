//! Block device error types
//!
//! Error types for the NBD block device gateway.

use std::io;

use thiserror::Error;

/// Block device result type
pub type BlockResult<T> = Result<T, BlockError>;

/// Block device error types
#[derive(Debug, Error)]
pub enum BlockError {
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Protocol error
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Volume not found
    #[error("Volume not found: {0}")]
    VolumeNotFound(String),

    /// Pool not found
    #[error("Pool not found: {0}")]
    PoolNotFound(String),

    /// Snapshot not found
    #[error("Snapshot not found: {0}")]
    SnapshotNotFound(String),

    /// Out of space
    #[error("Out of space: pool has no free chunks")]
    OutOfSpace,

    /// Invalid offset
    #[error("Invalid offset: {offset} (volume size: {size})")]
    InvalidOffset { offset: u64, size: u64 },

    /// Invalid length
    #[error("Invalid length: {length}")]
    InvalidLength { length: u32 },

    /// Read-only volume
    #[error("Volume is read-only")]
    ReadOnly,

    /// Volume busy
    #[error("Volume is busy (has {clients} connected clients)")]
    VolumeBusy { clients: usize },

    /// Snapshot has children
    #[error("Snapshot has children (cannot delete)")]
    SnapshotHasChildren,

    /// Invalid volume state
    #[error("Invalid volume state: expected {expected}, found {found}")]
    InvalidState { expected: String, found: String },

    /// Store error
    #[error("Store error: {0}")]
    Store(String),

    /// Unsupported feature
    #[error("Unsupported feature: {0}")]
    Unsupported(String),
}

impl BlockError {
    /// Convert to NBD error code
    pub fn to_nbd_error(&self) -> NbdError {
        match self {
            BlockError::Io(e) => match e.kind() {
                io::ErrorKind::NotFound => NbdError::NoSuchDevice,
                io::ErrorKind::PermissionDenied => NbdError::Perm,
                io::ErrorKind::OutOfMemory => NbdError::NoMem,
                io::ErrorKind::InvalidInput => NbdError::Inval,
                _ => NbdError::Io,
            },
            BlockError::VolumeNotFound(_) => NbdError::NoSuchDevice,
            BlockError::OutOfSpace => NbdError::NoSpc,
            BlockError::InvalidOffset { .. } => NbdError::Inval,
            BlockError::InvalidLength { .. } => NbdError::Inval,
            BlockError::ReadOnly => NbdError::Rofs,
            BlockError::Unsupported(_) => NbdError::NotSup,
            _ => NbdError::Io,
        }
    }
}

/// NBD error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NbdError {
    /// Success
    Ok = 0,
    /// Permission denied
    Perm = 1,
    /// I/O error
    Io = 5,
    /// Out of memory
    NoMem = 12,
    /// Invalid argument
    Inval = 22,
    /// No space left on device
    NoSpc = 28,
    /// Function not implemented
    NotSup = 95,
    /// Device not found
    NoSuchDevice = 19,
    /// Read-only filesystem
    Rofs = 30,
    /// Shutdown in progress
    Shutdown = 108,
}

impl NbdError {
    /// Get the error code
    pub fn code(&self) -> u32 {
        *self as u32
    }

    /// Check if this is a success
    pub fn is_ok(&self) -> bool {
        matches!(self, NbdError::Ok)
    }

    /// Create from errno
    pub fn from_errno(errno: i32) -> Self {
        match errno {
            0 => Self::Ok,
            1 => Self::Perm,
            5 => Self::Io,
            12 => Self::NoMem,
            22 => Self::Inval,
            28 => Self::NoSpc,
            95 => Self::NotSup,
            19 => Self::NoSuchDevice,
            30 => Self::Rofs,
            108 => Self::Shutdown,
            _ => Self::Io,
        }
    }
}

impl std::fmt::Display for NbdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NbdError::Ok => write!(f, "Success"),
            NbdError::Perm => write!(f, "Permission denied"),
            NbdError::Io => write!(f, "I/O error"),
            NbdError::NoMem => write!(f, "Out of memory"),
            NbdError::Inval => write!(f, "Invalid argument"),
            NbdError::NoSpc => write!(f, "No space left"),
            NbdError::NotSup => write!(f, "Not supported"),
            NbdError::NoSuchDevice => write!(f, "No such device"),
            NbdError::Rofs => write!(f, "Read-only"),
            NbdError::Shutdown => write!(f, "Shutdown"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nbd_error_codes() {
        assert_eq!(NbdError::Ok.code(), 0);
        assert_eq!(NbdError::Perm.code(), 1);
        assert_eq!(NbdError::Io.code(), 5);
        assert!(NbdError::Ok.is_ok());
        assert!(!NbdError::Io.is_ok());
    }

    #[test]
    fn test_block_error_to_nbd() {
        let err = BlockError::OutOfSpace;
        assert_eq!(err.to_nbd_error(), NbdError::NoSpc);

        let err = BlockError::ReadOnly;
        assert_eq!(err.to_nbd_error(), NbdError::Rofs);
    }
}
