//! Neural compression error types

use std::path::PathBuf;

/// Neural compression error types
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Model loading failed
    #[error("Model loading failed: {0}")]
    ModelLoad(String),

    /// Model not found at path
    #[error("Model not found: {path}")]
    ModelNotFound {
        /// Path where model was expected
        path: PathBuf,
    },

    /// ONNX Runtime error
    #[error("ONNX Runtime error: {0}")]
    OnnxRuntime(String),

    /// Invalid input shape for neural network
    #[error("Invalid input shape: expected {expected:?}, got {actual:?}")]
    InvalidShape {
        /// Expected shape
        expected: Vec<usize>,
        /// Actual shape
        actual: Vec<usize>,
    },

    /// Input size too small for neural compression
    #[error("Input too small: {size} bytes (minimum: {minimum})")]
    InputTooSmall {
        /// Actual input size
        size: usize,
        /// Minimum required size
        minimum: usize,
    },

    /// Unsupported data type for neural compression
    #[error("Unsupported data type for neural compression: {0}")]
    UnsupportedDataType(String),

    /// Quality constraint violated
    #[error("Quality constraint violated: target PSNR {target} dB, actual {actual} dB")]
    QualityViolation {
        /// Target PSNR
        target: f32,
        /// Actual PSNR achieved
        actual: f32,
    },

    /// Wavelet transform error
    #[error("Wavelet transform error: {0}")]
    WaveletTransform(String),

    /// Entropy coding error
    #[error("Entropy coding error: {0}")]
    EntropyCoding(String),

    /// GPU acceleration unavailable
    #[error("GPU acceleration unavailable: {0}")]
    GpuUnavailable(String),

    /// Compression error from warp-compress
    #[error("Compression error: {0}")]
    Compression(#[from] warp_compress::Error),

    /// Invalid header format
    #[error("Invalid header: {0}")]
    InvalidHeader(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type for neural compression operations
pub type Result<T> = std::result::Result<T, Error>;
