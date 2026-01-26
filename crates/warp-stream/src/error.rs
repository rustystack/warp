//! Error types for streaming pipeline operations

use std::fmt;

/// Errors that can occur during streaming operations
#[derive(Debug)]
pub enum StreamError {
    /// Pipeline stage timeout exceeded
    Timeout {
        /// The pipeline stage that timed out
        stage: &'static str,
        /// Time elapsed in milliseconds
        elapsed_ms: u64,
        /// Configured timeout limit in milliseconds
        limit_ms: u64,
    },

    /// Backpressure limit exceeded
    BackpressureExceeded {
        /// Current queue size
        queue_size: usize,
        /// Maximum allowed queue size
        max_size: usize,
    },

    /// Channel closed unexpectedly
    ChannelClosed(&'static str),

    /// GPU operation failed
    GpuError(warp_gpu::Error),

    /// Crypto operation failed
    CryptoError(String),

    /// I/O operation failed
    IoError(std::io::Error),

    /// Invalid configuration
    InvalidConfig(String),

    /// Pipeline not initialized
    NotInitialized,

    /// Pipeline already running
    AlreadyRunning,

    /// Operation cancelled
    Cancelled,

    /// Buffer overflow (data exceeds buffer capacity)
    BufferOverflow,
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout {
                stage,
                elapsed_ms,
                limit_ms,
            } => {
                write!(
                    f,
                    "Pipeline stage '{}' timed out: {}ms > {}ms limit",
                    stage, elapsed_ms, limit_ms
                )
            }
            Self::BackpressureExceeded {
                queue_size,
                max_size,
            } => {
                write!(
                    f,
                    "Backpressure exceeded: queue {} > max {}",
                    queue_size, max_size
                )
            }
            Self::ChannelClosed(name) => {
                write!(f, "Channel '{}' closed unexpectedly", name)
            }
            Self::GpuError(e) => write!(f, "GPU error: {}", e),
            Self::CryptoError(msg) => write!(f, "Crypto error: {}", msg),
            Self::IoError(e) => write!(f, "I/O error: {}", e),
            Self::InvalidConfig(msg) => write!(f, "Invalid configuration: {}", msg),
            Self::NotInitialized => write!(f, "Pipeline not initialized"),
            Self::AlreadyRunning => write!(f, "Pipeline already running"),
            Self::Cancelled => write!(f, "Operation cancelled"),
            Self::BufferOverflow => write!(f, "Buffer overflow: data exceeds buffer capacity"),
        }
    }
}

impl std::error::Error for StreamError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::GpuError(e) => Some(e),
            Self::IoError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<warp_gpu::Error> for StreamError {
    fn from(err: warp_gpu::Error) -> Self {
        Self::GpuError(err)
    }
}

impl From<std::io::Error> for StreamError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err)
    }
}

/// Result type for streaming operations
pub type Result<T> = std::result::Result<T, StreamError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timeout_error_display() {
        let err = StreamError::Timeout {
            stage: "encrypt",
            elapsed_ms: 10,
            limit_ms: 5,
        };
        assert!(err.to_string().contains("encrypt"));
        assert!(err.to_string().contains("10ms"));
    }

    #[test]
    fn test_backpressure_error_display() {
        let err = StreamError::BackpressureExceeded {
            queue_size: 100,
            max_size: 50,
        };
        assert!(err.to_string().contains("100"));
        assert!(err.to_string().contains("50"));
    }

    #[test]
    fn test_channel_closed_display() {
        let err = StreamError::ChannelClosed("input");
        assert!(err.to_string().contains("input"));
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let stream_err: StreamError = io_err.into();
        assert!(matches!(stream_err, StreamError::IoError(_)));
    }
}
