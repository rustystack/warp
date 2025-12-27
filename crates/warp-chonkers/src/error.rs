//! Error types for the Chonkers algorithm

use thiserror::Error;

/// Result type for Chonkers operations
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during Chonkers operations
#[derive(Error, Debug)]
pub enum Error {
    /// Invalid configuration
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    /// Layer processing failed
    #[error("layer {layer} processing failed: {message}")]
    LayerError {
        /// Layer index that failed
        layer: usize,
        /// Error message
        message: String,
    },

    /// Chunk size constraint violation
    #[error("chunk size {size} violates bounds [{min}, {max}]")]
    ChunkSizeViolation {
        /// Actual chunk size
        size: usize,
        /// Minimum allowed size
        min: usize,
        /// Maximum allowed size
        max: usize,
    },

    /// Internal algorithm error
    #[error("internal error: {0}")]
    Internal(String),
}
