//! Error types for warp-store

use thiserror::Error;

/// Result type for warp-store operations
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur in warp-store
#[derive(Error, Debug)]
pub enum Error {
    /// Bucket already exists
    #[error("bucket already exists: {0}")]
    BucketAlreadyExists(String),

    /// Bucket not found
    #[error("bucket not found: {0}")]
    BucketNotFound(String),

    /// Bucket is not empty
    #[error("bucket is not empty: {0}")]
    BucketNotEmpty(String),

    /// Object not found
    #[error("object not found: {bucket}/{key}")]
    ObjectNotFound {
        /// Bucket name
        bucket: String,
        /// Object key
        key: String,
    },

    /// Object too large
    #[error("object too large: {size} bytes exceeds maximum of {max} bytes")]
    ObjectTooLarge {
        /// Actual size
        size: u64,
        /// Maximum allowed size
        max: u64,
    },

    /// Invalid key format
    #[error("invalid key: {0}")]
    InvalidKey(String),

    /// Invalid bucket name
    #[error("invalid bucket name: {0}")]
    InvalidBucketName(String),

    /// Token expired
    #[error("ephemeral token expired")]
    TokenExpired,

    /// Token signature invalid
    #[error("invalid token signature")]
    InvalidSignature,

    /// Token scope mismatch
    #[error("token scope does not match requested resource")]
    ScopeMismatch,

    /// IP not allowed
    #[error("IP address {0} not allowed by token restrictions")]
    IpNotAllowed(std::net::IpAddr),

    /// Rate limit exceeded
    #[error("rate limit exceeded")]
    RateLimitExceeded,

    /// Permission denied
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// Version not found
    #[error("version not found: {0}")]
    VersionNotFound(String),

    /// Field not found in parcode object
    #[error("field not found: {0}")]
    FieldNotFound(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Backend error
    #[error("backend error: {0}")]
    Backend(String),

    /// Token encoding error
    #[error("token encoding error: {0}")]
    TokenEncoding(String),

    /// Raft consensus error
    #[error("raft error: {0}")]
    Raft(String),

    /// Domain not found
    #[error("domain not found: {0}")]
    DomainNotFound(u64),

    /// Domain already exists
    #[error("domain already exists: {0}")]
    DomainAlreadyExists(u64),

    /// Node not found in domain
    #[error("node not found: {0}")]
    NodeNotFound(u64),

    /// Insufficient replicas for write quorum
    #[error("insufficient replicas: have {available} but need {required}")]
    InsufficientReplicas {
        /// Available replicas
        available: usize,
        /// Required replicas
        required: usize,
    },

    /// Replication error
    #[error("replication error: {0}")]
    Replication(String),

    /// WireGuard tunnel error
    #[error("wireguard error: {0}")]
    WireGuard(String),

    /// Shard not found
    #[error("shard not found: {bucket}/{key} shard {shard_index}")]
    ShardNotFound {
        /// Bucket name
        bucket: String,
        /// Object key
        key: String,
        /// Shard index
        shard_index: u16,
    },

    /// Erasure coding error
    #[error("erasure coding error: {0}")]
    ErasureCoding(String),

    /// Object is locked (WORM/Object Lock)
    #[error("object is locked: {0}")]
    ObjectLocked(String),

    /// Invalid argument
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
}

impl From<rmp_serde::encode::Error> for Error {
    fn from(e: rmp_serde::encode::Error) -> Self {
        Error::Serialization(e.to_string())
    }
}

impl From<rmp_serde::decode::Error> for Error {
    fn from(e: rmp_serde::decode::Error) -> Self {
        Error::Serialization(e.to_string())
    }
}

impl From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Self {
        Error::TokenEncoding(e.to_string())
    }
}
