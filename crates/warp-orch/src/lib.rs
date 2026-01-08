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
pub mod download;
pub mod orchestrator;
pub mod pool;
pub mod predict;
pub mod preposition;
pub mod progress;
pub mod reconcile;
pub mod striping;
pub mod triggers;
pub mod types;
pub mod upload;

pub use adaptive_erasure::{
    AdaptiveErasure, AdaptiveErasureConfig, AdaptiveErasureStats, ErasureParameters, NetworkMetrics,
};
pub use download::{DownloadConfig, DownloadSession, SwarmDownloader};
pub use orchestrator::{Orchestrator, OrchestratorConfig};
pub use pool::{ConnectionPool, PoolConfig, PooledConnection};
pub use predict::{
    AccessAnalytics, AccessPattern, AccessRecord, PatternConfig, PatternDetector, Predictor,
    PredictorConfig, PrepositionPriority, PrepositionRequest,
};
pub use preposition::{
    EdgeInfo, PrepositionConfig, PrepositionExecutor, PrepositionManager, PrepositionMetrics,
    PrepositionOp, PrepositionPlanner, PrepositionStatus,
};
pub use progress::{ProgressTracker, ProgressUpdate, TransferProgress};
pub use reconcile::{
    DriftConfig, DriftDetector, DriftMetrics, ReoptConfig, ReoptDecision, ReoptEvaluator,
    ReoptTrigger,
};
pub use striping::{Stripe, StripeStatus, StripedTransfer, StripedTransferMetrics, StripingConfig};
pub use triggers::{TriggerConfig, TriggerGenerator};
pub use types::{
    ChunkTransfer, EdgeTransfer, TransferDirection, TransferId, TransferRequest, TransferResult,
    TransferState, TransferStatus,
};
pub use upload::{ActiveChunkUpload, DistributedUploader, UploadConfig, UploadSession};

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
