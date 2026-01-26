//! warp-core: Transfer orchestration and session management
//!
//! This crate coordinates all aspects of a warp transfer:
//! - Payload analysis and strategy selection
//! - Session management and state tracking
//! - Chunk scheduling and prioritization
//! - Progress reporting and metrics

#![warn(missing_docs)]
// Allow pedantic clippy lints for this crate
#![allow(clippy::collapsible_if)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::missing_errors_doc)]
#![allow(unused_mut)]
#![allow(unused_variables)]
#![allow(clippy::identity_op)]
#![allow(clippy::unnecessary_mut_passed)]

pub mod analyzer;
#[cfg(feature = "hpc-channels")]
pub mod channels;
pub mod engine;
pub mod pipeline;
pub mod scheduler;
pub mod session;

pub use analyzer::{CompressionHint, PayloadAnalysis, analyze_payload};
pub use engine::{
    ProgressCallback, TransferConfig, TransferEngine, TransferProgress, VerificationMode,
};
// Re-export ErasureConfig for convenience
#[cfg(feature = "hpc-channels")]
pub use channels::{
    DownloadStartEvent, SharedStorageChannelBridge, StorageChannelBridge, TransferProgressEvent,
    TransferStatus, TransferStatusEvent, UploadStartEvent, shared_channel_bridge,
};
pub use pipeline::TransferPipeline;
pub use scheduler::ChunkScheduler;
pub use session::{ErasureState, Session, SessionState};
pub use warp_ec::ErasureConfig;

/// Core error types
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Format error
    #[error("Format error: {0}")]
    Format(#[from] warp_format::Error),

    /// Network error
    #[error("Network error: {0}")]
    Network(#[from] warp_net::Error),

    /// I/O utilities error
    #[error("I/O utilities error: {0}")]
    WarpIo(#[from] warp_io::Error),

    /// Session error
    #[error("Session error: {0}")]
    Session(String),

    /// Transfer cancelled
    #[error("Transfer cancelled")]
    Cancelled,
}

/// Result type for warp-core operations
pub type Result<T> = std::result::Result<T, Error>;
