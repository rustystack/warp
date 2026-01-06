//! NVMe-oF Backend Error Types

use std::io;
use thiserror::Error;

/// Result type for NVMe-oF backend operations
pub type NvmeOfBackendResult<T> = Result<T, NvmeOfBackendError>;

/// NVMe-oF backend error types
#[derive(Debug, Error)]
pub enum NvmeOfBackendError {
    /// I/O error
    #[error("I/O error: {0}")]
    Io(String),

    /// Raw I/O error (for From impl)
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),

    /// Connection error
    #[error("Connection error: {0}")]
    Connection(String),

    /// Protocol error
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Target not found
    #[error("Target not found: {0}")]
    TargetNotFound(String),

    /// Namespace not found
    #[error("Namespace not found: {0}")]
    NamespaceNotFound(u32),

    /// Object not found
    #[error("Object not found: {0}")]
    ObjectNotFound(String),

    /// Bucket not found
    #[error("Bucket not found: {0}")]
    BucketNotFound(String),

    /// Allocation failed
    #[error("Allocation failed: {0}")]
    AllocationFailed(String),

    /// Metadata error
    #[error("Metadata error: {0}")]
    Metadata(String),

    /// Pool exhausted
    #[error("Connection pool exhausted")]
    PoolExhausted,

    /// Timeout
    #[error("Operation timed out: {0}")]
    Timeout(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Not supported
    #[error("Not supported: {0}")]
    NotSupported(String),
}

impl From<NvmeOfBackendError> for crate::Error {
    fn from(e: NvmeOfBackendError) -> Self {
        crate::Error::Backend(e.to_string())
    }
}
