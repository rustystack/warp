#![allow(clippy::unreadable_literal)]
#![allow(clippy::redundant_clone)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::used_underscore_binding)]
#![allow(clippy::float_cmp)]
#![allow(clippy::cast_lossless)]

//! Telemetry, Logging, and Metrics for Portal Distributed Storage
//!
//! This crate provides:
//! - Structured logging with tracing
//! - Performance metrics collection
//! - Distributed tracing support
//! - Health monitoring

pub mod logging;
pub mod metrics;

pub use logging::*;
pub use metrics::*;

use thiserror::Error;

/// Telemetry error types
#[derive(Debug, Error)]
pub enum TelemetryError {
    /// Initialization error
    #[error("Initialization error: {0}")]
    Init(String),

    /// Logging error
    #[error("Logging error: {0}")]
    Logging(String),

    /// Metrics error
    #[error("Metrics error: {0}")]
    Metrics(String),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type for telemetry operations
pub type Result<T> = std::result::Result<T, TelemetryError>;
