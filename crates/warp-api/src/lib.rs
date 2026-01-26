#![allow(dead_code)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::useless_vec)]

//! REST API with OpenAPI documentation for Warp
//!
//! This crate provides:
//! - REST API endpoints using Axum
//! - OpenAPI 3.0 specification with utoipa
//! - Swagger UI integration
//! - Transfer management API
//! - Health and metrics endpoints
//! - Edge node information

pub mod routes;
pub mod server;
pub mod types;

pub use routes::*;
pub use server::*;
pub use types::*;

use thiserror::Error;

/// API error types
#[derive(Debug, Error)]
pub enum ApiError {
    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Server error
    #[error("Server error: {0}")]
    Server(String),

    /// Bind error
    #[error("Failed to bind to {address}: {source}")]
    Bind {
        /// Address that failed to bind
        address: String,
        /// Source error
        source: std::io::Error,
    },

    /// Shutdown error
    #[error("Shutdown error: {0}")]
    Shutdown(String),

    /// Transfer not found
    #[error("Transfer not found: {0}")]
    TransferNotFound(uuid::Uuid),

    /// Invalid request
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type for API operations
pub type Result<T> = std::result::Result<T, ApiError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = ApiError::Config("test config error".to_string());
        assert_eq!(err.to_string(), "Configuration error: test config error");
    }

    #[test]
    fn test_error_bind() {
        let io_err = std::io::Error::new(std::io::ErrorKind::AddrInUse, "address in use");
        let err = ApiError::Bind {
            address: "127.0.0.1:3000".to_string(),
            source: io_err,
        };
        assert!(err.to_string().contains("Failed to bind to 127.0.0.1:3000"));
    }

    #[test]
    fn test_error_transfer_not_found() {
        let id = uuid::Uuid::new_v4();
        let err = ApiError::TransferNotFound(id);
        assert!(err.to_string().contains("Transfer not found"));
        assert!(err.to_string().contains(&id.to_string()));
    }

    #[test]
    fn test_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
        let err: ApiError = io_err.into();
        assert!(matches!(err, ApiError::Io(_)));
    }

    #[test]
    fn test_error_from_serde() {
        let json_err = serde_json::from_str::<serde_json::Value>("{invalid}").unwrap_err();
        let err: ApiError = json_err.into();
        assert!(matches!(err, ApiError::Serialization(_)));
    }
}
