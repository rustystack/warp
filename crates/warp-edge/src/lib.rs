#![allow(clippy::similar_names)]
#![allow(clippy::significant_drop_tightening)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::branches_sharing_code)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::format_collect)]
#![allow(clippy::float_cmp)]
#![allow(clippy::default_trait_access)]
#![allow(clippy::redundant_clone)]
#![allow(clippy::len_zero)]
#![allow(clippy::suboptimal_flops)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::clone_on_copy)]
#![allow(clippy::uninlined_format_args)]
#![allow(unused_must_use)]

//! Edge Intelligence for Portal Distributed Storage
//!
//! This crate provides edge discovery, health tracking, and intelligent
//! peer selection for the distributed storage network:
//!
//! - Edge registration and state tracking
//! - Chunk availability mapping (chunk → edges, edge → chunks)
//! - Bandwidth and RTT estimation
//! - Health scoring for edge selection
//! - Resource constraint tracking

pub mod availability;
pub mod constraints;
pub mod health;
pub mod metrics;
pub mod registry;
pub mod types;

pub use availability::{ChunkAvailabilityMap, ChunkLocation};
pub use constraints::{BatteryConstraints, ConstraintTracker, ResourceConstraints, TimeWindow};
pub use health::{HealthComponents, HealthScore, HealthScorer, HealthWeights};
pub use metrics::{BandwidthEstimator, BandwidthMetrics, RttEstimator, RttMetrics};
pub use registry::{EdgeRegistry, EdgeSnapshot};
pub use types::{EdgeCapabilities, EdgeId, EdgeInfo, EdgeState, EdgeStatus, EdgeType};

use thiserror::Error;

/// Edge intelligence errors
#[derive(Debug, Error)]
pub enum EdgeError {
    /// Edge not found in registry
    #[error("edge not found: {0}")]
    EdgeNotFound(String),

    /// Chunk not found in availability map
    #[error("chunk not found: {0}")]
    ChunkNotFound(String),

    /// Invalid health score value
    #[error("invalid health score: {0} (must be 0.0-1.0)")]
    InvalidHealthScore(f64),

    /// Metrics calculation overflow
    #[error("metrics overflow: {0}")]
    MetricsOverflow(String),

    /// Constraint violation
    #[error("constraint violation: {0}")]
    ConstraintViolation(String),

    /// Invalid virtual IP
    #[error("invalid virtual IP: {0}")]
    InvalidVirtualIp(String),

    /// Serialization error
    #[error("serialization error: {0}")]
    Serialization(String),
}

/// Result type for warp-edge operations
pub type Result<T> = std::result::Result<T, EdgeError>;
