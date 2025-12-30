//! Error types for gateway operations

use thiserror::Error;

/// Gateway error types
#[derive(Debug, Error)]
pub enum GatewayError {
    /// Lock acquisition failed
    #[error("lock conflict: {0}")]
    LockConflict(String),

    /// Lock not found
    #[error("lock not found: {0}")]
    LockNotFound(String),

    /// Lock deadlock detected
    #[error("deadlock detected")]
    Deadlock,

    /// Session not found
    #[error("session not found: {0}")]
    SessionNotFound(String),

    /// Session expired
    #[error("session expired: {0}")]
    SessionExpired(String),

    /// Invalid filehandle
    #[error("invalid filehandle: {0}")]
    InvalidHandle(String),

    /// Stale filehandle (generation mismatch)
    #[error("stale filehandle: expected generation {expected}, got {actual}")]
    StaleHandle {
        /// Expected generation
        expected: u64,
        /// Actual generation
        actual: u64,
    },

    /// Delegation conflict
    #[error("delegation conflict: {0}")]
    DelegationConflict(String),

    /// Delegation recall failed
    #[error("delegation recall failed: {0}")]
    RecallFailed(String),

    /// Lease expired
    #[error("lease expired: {0}")]
    LeaseExpired(String),

    /// ACL translation error
    #[error("ACL translation error: {0}")]
    AclError(String),

    /// Permission denied
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// I/O error from underlying storage
    #[error("storage error: {0}")]
    StorageError(String),

    /// Internal error
    #[error("internal error: {0}")]
    Internal(String),
}

/// Result type for gateway operations
pub type GatewayResult<T> = Result<T, GatewayError>;
