//! warp-core: Transfer orchestration and session management
//!
//! This crate coordinates all aspects of a warp transfer:
//! - Payload analysis and strategy selection
//! - Session management and state tracking
//! - Chunk scheduling and prioritization
//! - Progress reporting and metrics

#![warn(missing_docs)]

pub mod analyzer;
#[cfg(feature = "hpc-channels")]
pub mod channels;
pub mod engine;
pub mod pipeline;
pub mod scheduler;
pub mod session;

pub use analyzer::{analyze_payload, CompressionHint, PayloadAnalysis};
pub use engine::{ProgressCallback, TransferConfig, TransferEngine, TransferProgress, VerificationMode};
// Re-export ErasureConfig for convenience
pub use warp_ec::ErasureConfig;
pub use pipeline::TransferPipeline;
pub use scheduler::ChunkScheduler;
pub use session::{Session, SessionState};
#[cfg(feature = "hpc-channels")]
pub use channels::{
    StorageChannelBridge, SharedStorageChannelBridge,
    UploadStartEvent, DownloadStartEvent, TransferProgressEvent,
    TransferStatusEvent, TransferStatus, shared_channel_bridge,
};

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
