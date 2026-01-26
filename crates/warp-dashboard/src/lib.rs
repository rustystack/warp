#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::double_ended_iterator_last)]
#![allow(clippy::unnecessary_cast)]

//! Web Monitoring Dashboard for Warp Transfers
//!
//! This crate provides:
//! - Real-time transfer visualization
//! - Edge network monitoring
//! - Performance metrics display
//! - Live updates via Server-Sent Events
//! - RESTful API for state queries
//! - IPC integration with Horizon dashboard

pub mod handlers;
pub mod ipc;
pub mod server;
pub mod templates;
pub mod types;

pub use handlers::*;
pub use ipc::IpcHandler;
pub use server::*;
pub use templates::*;
pub use types::*;

use thiserror::Error;

/// Dashboard error types
#[derive(Debug, Error)]
pub enum DashboardError {
    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Template rendering error
    #[error("Template rendering error: {0}")]
    Template(String),

    /// HTTP server error
    #[error("HTTP server error: {0}")]
    Server(String),

    /// State management error
    #[error("State management error: {0}")]
    State(String),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Result type for dashboard operations
pub type Result<T> = std::result::Result<T, DashboardError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = DashboardError::Config("test error".to_string());
        assert_eq!(err.to_string(), "Configuration error: test error");
    }

    #[test]
    fn test_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err = DashboardError::from(io_err);
        assert!(matches!(err, DashboardError::Io(_)));
    }

    #[test]
    fn test_error_from_json() {
        let json_err = serde_json::from_str::<i32>("invalid").unwrap_err();
        let err = DashboardError::from(json_err);
        assert!(matches!(err, DashboardError::Json(_)));
    }
}
