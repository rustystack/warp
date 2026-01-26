//! Portal Core - Zero-knowledge encryption and portal lifecycle management
//!
//! This crate provides the core functionality for Portal distributed storage:
//! - Key hierarchy with BIP-39 recovery phrases
//! - Convergent encryption for content-addressed storage
//! - Portal lifecycle management (create, activate, expire)
//! - Access control (owner, grant, link-based)
//!
//! # Architecture
//!
//! Portal uses a zero-knowledge model where:
//! - The Hub never sees plaintext content
//! - Content is encrypted with convergent encryption (same content = same ciphertext)
//! - Keys are derived from a BIP-39 recovery phrase
//! - Portals have configurable lifecycle policies

#![warn(missing_docs)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::redundant_clone)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::doc_markdown)]

pub mod access;
pub mod encryption;
pub mod keys;
pub mod portal;

// Re-exports for convenience
pub use access::{AccessConditions, AccessControlList, AccessGrant, AccessLevel, Accessor};
pub use encryption::{ConvergentEncryptor, EncryptedChunk, ManifestEncryptor};
pub use keys::{
    AuthenticationKey, DeviceKey, KeyHierarchy, MasterEncryptionKey, MasterSeed, MasterSigningKey,
    RecoveryPhrase,
};
pub use portal::{Portal, PortalBuilder, PortalStats};

use uuid::Uuid;

/// Unique portal identifier
pub type PortalId = Uuid;

/// Content ID (BLAKE3 hash of plaintext)
pub type ContentId = warp_hash::Hash;

/// Portal core error types
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Key derivation error
    #[error("Key derivation error: {0}")]
    KeyDerivation(String),

    /// Invalid recovery phrase
    #[error("Invalid recovery phrase: {0}")]
    InvalidRecoveryPhrase(String),

    /// Encryption error
    #[error("Encryption error: {0}")]
    Encryption(#[from] warp_crypto::Error),

    /// Invalid portal state transition
    #[error("Invalid state transition: {from:?} -> {to:?}")]
    InvalidStateTransition {
        /// Current state
        from: PortalState,
        /// Attempted target state
        to: PortalState,
    },

    /// Access denied
    #[error("Access denied")]
    AccessDenied,

    /// Portal not found
    #[error("Portal not found: {0}")]
    PortalNotFound(PortalId),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Invalid content ID
    #[error("Invalid content ID")]
    InvalidContentId,

    /// Policy evaluation error
    #[error("Policy evaluation error: {0}")]
    PolicyEvaluation(String),

    /// Invalid key length
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength {
        /// Expected length
        expected: usize,
        /// Actual length
        actual: usize,
    },
}

/// Result type for portal-core operations
pub type Result<T> = std::result::Result<T, Error>;

/// Portal lifecycle states
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Default,
)]
pub enum PortalState {
    /// Created but not yet active
    #[default]
    Created,
    /// Currently active and accepting access
    Active,
    /// Temporarily paused (e.g., outside scheduled hours)
    Paused,
    /// Expired, no longer accepting new access
    Expired,
    /// Archived, data retained but no access
    Archived,
}

impl std::fmt::Display for PortalState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Created => write!(f, "Created"),
            Self::Active => write!(f, "Active"),
            Self::Paused => write!(f, "Paused"),
            Self::Expired => write!(f, "Expired"),
            Self::Archived => write!(f, "Archived"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_portal_state_default() {
        assert_eq!(PortalState::default(), PortalState::Created);
    }

    #[test]
    fn test_portal_state_display() {
        assert_eq!(PortalState::Created.to_string(), "Created");
        assert_eq!(PortalState::Active.to_string(), "Active");
        assert_eq!(PortalState::Paused.to_string(), "Paused");
        assert_eq!(PortalState::Expired.to_string(), "Expired");
        assert_eq!(PortalState::Archived.to_string(), "Archived");
    }

    #[test]
    fn test_error_display() {
        let err = Error::KeyDerivation("test error".into());
        assert!(err.to_string().contains("Key derivation error"));

        let err = Error::InvalidStateTransition {
            from: PortalState::Created,
            to: PortalState::Expired,
        };
        assert!(err.to_string().contains("Invalid state transition"));
    }
}
