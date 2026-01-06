//! KMS error types

use thiserror::Error;

/// KMS error type
#[derive(Error, Debug)]
pub enum KmsError {
    /// Key not found
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    /// Key is pending deletion
    #[error("Key is pending deletion: {0}")]
    KeyPendingDeletion(String),

    /// Key is disabled
    #[error("Key is disabled: {0}")]
    KeyDisabled(String),

    /// Invalid key state for operation
    #[error("Invalid key state for operation: {0}")]
    InvalidKeyState(String),

    /// Invalid ciphertext
    #[error("Invalid ciphertext: {0}")]
    InvalidCiphertext(String),

    /// Decryption failed
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    /// Encryption failed
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Key generation failed
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    /// Invalid key ID
    #[error("Invalid key ID: {0}")]
    InvalidKeyId(String),

    /// Key alias already exists
    #[error("Key alias already exists: {0}")]
    AliasAlreadyExists(String),

    /// Key version not found
    #[error("Key version not found: {0}")]
    KeyVersionNotFound(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    /// AWS KMS error
    #[cfg(feature = "aws")]
    #[error("AWS KMS error: {0}")]
    AwsKmsError(String),

    /// Internal error
    #[error("Internal KMS error: {0}")]
    InternalError(String),

    /// Operation not supported
    #[error("Operation not supported: {0}")]
    NotSupported(String),
}

/// Result type for KMS operations
pub type KmsResult<T> = Result<T, KmsError>;
