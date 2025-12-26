//! Transfer Orchestration for Portal Distributed Storage
//!
//! This crate provides multi-source swarm downloads and distributed uploads,
//! coordinating transfers across multiple edges with connection pooling,
//! progress tracking, and automatic failure recovery.
//!
//! # Key Components
//!
//! - **Connection Pool**: Manages QUIC connections to edges
//! - **Progress Tracker**: Real-time transfer progress and ETA
//! - **Swarm Download**: BitTorrent-style parallel chunk fetching
//! - **Distributed Upload**: Parallel push to multiple edges
//! - **Orchestrator**: High-level transfer coordination
//! - **Reconcile**: Drift detection and reoptimization triggers
//! - **Predict**: Predictive pre-positioning and access patterns
//! - **Preposition**: Predictive pre-positioning execution

pub mod adaptive_erasure;
pub mod types;
pub mod pool;
pub mod progress;
pub mod download;
pub mod upload;
pub mod orchestrator;
pub mod reconcile;
pub mod predict;
pub mod triggers;
pub mod preposition;

pub use types::{
    TransferId, TransferState, TransferStatus, TransferDirection,
    TransferRequest, TransferResult, ChunkTransfer, EdgeTransfer,
};
pub use pool::{ConnectionPool, PoolConfig, PooledConnection};
pub use progress::{ProgressTracker, TransferProgress, ProgressUpdate};
pub use download::{SwarmDownloader, DownloadConfig, DownloadSession};
pub use upload::{ActiveChunkUpload, DistributedUploader, UploadConfig, UploadSession};
pub use orchestrator::{Orchestrator, OrchestratorConfig};
pub use reconcile::{
    DriftConfig, DriftDetector, DriftMetrics, ReoptConfig, ReoptDecision,
    ReoptEvaluator, ReoptTrigger,
};
pub use predict::{
    AccessAnalytics, AccessPattern, AccessRecord, PatternConfig, PatternDetector,
    PrepositionPriority, PrepositionRequest, Predictor, PredictorConfig,
};
pub use triggers::{TriggerConfig, TriggerGenerator};
pub use preposition::{
    PrepositionConfig, PrepositionOp, PrepositionStatus, PrepositionMetrics,
    EdgeInfo, PrepositionPlanner, PrepositionExecutor, PrepositionManager,
};
pub use adaptive_erasure::{
    AdaptiveErasure, AdaptiveErasureConfig, AdaptiveErasureStats,
    ErasureParameters, NetworkMetrics,
};

use thiserror::Error;

/// Orchestration error types
#[derive(Debug, Error)]
pub enum OrchError {
    /// Scheduler error
    #[error("Scheduler error: {0}")]
    Scheduler(#[from] warp_sched::SchedError),

    /// Edge error
    #[error("Edge error: {0}")]
    Edge(#[from] warp_edge::EdgeError),

    /// Network error
    #[error("Network error: {0}")]
    Network(String),

    /// Connection pool error
    #[error("Pool error: {0}")]
    Pool(String),

    /// Transfer failed
    #[error("Transfer failed: {0}")]
    TransferFailed(String),

    /// Transfer cancelled
    #[error("Transfer cancelled")]
    Cancelled,

    /// Timeout
    #[error("Timeout: {0}")]
    Timeout(String),

    /// No sources available
    #[error("No sources available for chunk")]
    NoSources,

    /// Invalid state
    #[error("Invalid state: {0}")]
    InvalidState(String),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type for warp-orch operations
pub type Result<T> = std::result::Result<T, OrchError>;
