//! Error types for OPRF operations

use thiserror::Error;

/// Result type for OPRF operations
pub type Result<T> = std::result::Result<T, OprfError>;

/// Errors that can occur during OPRF operations
#[derive(Debug, Error)]
pub enum OprfError {
    /// Invalid cipher suite or configuration
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    /// Invalid input data
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// Blinding operation failed
    #[error("blinding failed: {0}")]
    BlindingFailed(String),

    /// Evaluation operation failed
    #[error("evaluation failed: {0}")]
    EvaluationFailed(String),

    /// Finalization operation failed
    #[error("finalization failed: {0}")]
    FinalizationFailed(String),

    /// VOPRF proof verification failed
    #[error("proof verification failed: {0}")]
    ProofVerificationFailed(String),

    /// Invalid blinded element
    #[error("invalid blinded element")]
    InvalidBlindedElement,

    /// Invalid evaluation response
    #[error("invalid evaluation response")]
    InvalidEvaluation,

    /// Server key not found
    #[error("server key not found: {0}")]
    KeyNotFound(String),

    /// Key has been rotated
    #[error("key rotated: expected {expected}, got {actual}")]
    KeyRotated {
        expected: String,
        actual: String,
    },

    /// Serialization error
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Deserialization error
    #[error("deserialization error: {0}")]
    Deserialization(String),

    /// OPAQUE-specific errors
    #[cfg(feature = "opaque")]
    #[error("OPAQUE error: {0}")]
    Opaque(String),

    /// Registration error
    #[error("registration failed: {0}")]
    RegistrationFailed(String),

    /// Login error
    #[error("login failed: {0}")]
    LoginFailed(String),

    /// User not found
    #[error("user not found: {0}")]
    UserNotFound(String),

    /// Invalid password
    #[error("invalid credentials")]
    InvalidCredentials,

    /// Internal error
    #[error("internal error: {0}")]
    Internal(String),
}

impl From<std::io::Error> for OprfError {
    fn from(err: std::io::Error) -> Self {
        OprfError::Internal(err.to_string())
    }
}
