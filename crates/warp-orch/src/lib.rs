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

#![allow(clippy::unreadable_literal)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::unused_async)]
#![allow(clippy::manual_midpoint)]
#![allow(clippy::manual_clamp)]
#![allow(clippy::unnecessary_map_or)]
#![allow(clippy::single_match_else)]
#![allow(clippy::unused_enumerate_index)]
#![allow(clippy::redundant_closure)]
#![allow(clippy::explicit_iter_loop)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::significant_drop_tightening)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::redundant_clone)]
#![allow(clippy::suboptimal_flops)]
#![allow(clippy::float_cmp)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::if_not_else)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::useless_let_if_seq)]
#![allow(clippy::significant_drop_in_scrutinee)]
#![allow(clippy::missing_fields_in_debug)]
#![allow(clippy::unwrap_or_default)]
#![allow(clippy::used_underscore_binding)]
#![allow(clippy::map_unwrap_or)]
#![allow(clippy::needless_continue)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::option_map_unit_fn)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::derive_partial_eq_without_eq)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::unchecked_time_subtraction)]
#![allow(clippy::no_effect_underscore_binding)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::identity_op)]
#![allow(clippy::manual_div_ceil)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::len_zero)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::option_as_ref_deref)]
#![allow(clippy::needless_pass_by_ref_mut)]
#![allow(clippy::clone_on_copy)]
#![allow(clippy::unnecessary_get_then_check)]
#![allow(clippy::useless_vec)]
#![allow(unused_variables)]
#![allow(dead_code)]

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
