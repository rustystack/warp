//! warp-format: Native .warp file format
//!
//! Binary format optimized for:
//! - O(1) file lookup via memory-mapped B-tree index
//! - Streaming creation and extraction
//! - Incremental Merkle verification
//! - Chunk-level deduplication

#![warn(missing_docs)]
#![allow(clippy::manual_range_contains)]
#![allow(clippy::collapsible_if)]

pub mod file_table;
pub mod header;
pub mod index;
pub mod merkle;
pub mod reader;
pub mod writer;

pub use header::{Compression, Encryption, Header, MAGIC, VERSION};
pub use merkle::{MerkleProof, MerkleTree, SparseMerkleTree};
pub use reader::WarpReader;
pub use writer::{WarpWriter, WarpWriterConfig};

// Re-export encryption key for convenience
pub use warp_crypto::encrypt::Key as EncryptionKey;

/// Format error types
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid magic bytes
    #[error("Invalid magic bytes")]
    InvalidMagic,

    /// Unsupported version
    #[error("Unsupported version: {0}")]
    UnsupportedVersion(u32),

    /// Corrupted data
    #[error("Corrupted data: {0}")]
    Corrupted(String),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Compression error
    #[error("Compression error: {0}")]
    Compression(#[from] warp_compress::Error),

    /// Warp I/O error
    #[error("Warp I/O error: {0}")]
    WarpIo(#[from] warp_io::Error),

    /// Cryptographic error
    #[error("Crypto error: {0}")]
    Crypto(#[from] warp_crypto::Error),
}

/// Result type for format operations
pub type Result<T> = std::result::Result<T, Error>;
