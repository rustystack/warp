//! Error types for GPU operations

/// Result type for GPU operations
pub type Result<T> = std::result::Result<T, Error>;

/// GPU operation errors
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// CUDA device initialization failed
    #[error("Failed to initialize CUDA device {device_id}: {message}")]
    DeviceInit {
        /// Device ordinal
        device_id: usize,
        /// Error message
        message: String,
    },

    /// CUDA operation failed
    #[error("CUDA operation failed: {0}")]
    CudaOperation(String),

    /// Memory allocation failed
    #[error("GPU memory allocation failed: {size} bytes requested, {available} bytes available")]
    OutOfMemory {
        /// Requested size
        size: usize,
        /// Available memory
        available: usize,
    },

    /// Invalid buffer size
    #[error("Invalid buffer size: requested {requested}, maximum {maximum}")]
    InvalidBufferSize {
        /// Requested size
        requested: usize,
        /// Maximum allowed
        maximum: usize,
    },

    /// Memory pool exhausted
    #[error("Pinned memory pool exhausted: {allocated}/{capacity} bytes allocated")]
    PoolExhausted {
        /// Currently allocated
        allocated: usize,
        /// Pool capacity
        capacity: usize,
    },

    /// Buffer alignment error
    #[error("Buffer alignment error: address {address:#x} not aligned to {alignment} bytes")]
    Alignment {
        /// Buffer address
        address: usize,
        /// Required alignment
        alignment: usize,
    },

    /// Device query failed
    #[error("Failed to query device property: {0}")]
    DeviceQuery(String),

    /// Stream operation failed
    #[error("Stream operation failed: {0}")]
    Stream(String),

    /// Invalid operation
    #[error("Invalid operation: {0}")]
    InvalidOperation(String),

    /// Cryptographic operation failed
    #[error("Cryptographic error: {0}")]
    Crypto(String),

    /// Hashing operation failed
    #[error("Hashing error: {0}")]
    Hashing(String),

    /// Invalid parameter
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    /// Synchronization error
    #[error("Synchronization error: {0}")]
    Synchronization(String),
}

impl Error {
    /// Create a device initialization error
    #[inline]
    pub fn device_init(device_id: usize, err: cudarc::driver::DriverError) -> Self {
        // DriverError doesn't implement Display in cudarc 0.18, use Debug format
        Self::DeviceInit { device_id, message: format!("{:?}", err) }
    }

    /// Create an out-of-memory error
    #[inline]
    pub fn out_of_memory(size: usize, available: usize) -> Self {
        Self::OutOfMemory { size, available }
    }

    /// Create a pool exhausted error
    #[inline]
    pub fn pool_exhausted(allocated: usize, capacity: usize) -> Self {
        Self::PoolExhausted { allocated, capacity }
    }

    /// Create an alignment error
    #[inline]
    pub fn alignment(address: usize, alignment: usize) -> Self {
        Self::Alignment { address, alignment }
    }

    /// Check if error is recoverable
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::OutOfMemory { .. } | Self::PoolExhausted { .. }
        )
    }
}

/// Convert cudarc DriverError to our Error type
/// DriverError in cudarc 0.18 doesn't implement Display, so we use Debug format
impl From<cudarc::driver::DriverError> for Error {
    fn from(err: cudarc::driver::DriverError) -> Self {
        Error::CudaOperation(format!("{:?}", err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = Error::out_of_memory(1024 * 1024, 512 * 1024);
        assert!(err.to_string().contains("1048576"));
        assert!(err.to_string().contains("524288"));
    }

    #[test]
    fn test_error_recoverable() {
        assert!(Error::out_of_memory(100, 50).is_recoverable());
        assert!(Error::pool_exhausted(100, 100).is_recoverable());
        assert!(!Error::InvalidOperation("test".into()).is_recoverable());
    }

    #[test]
    fn test_pool_exhausted_error() {
        let err = Error::pool_exhausted(1024, 2048);
        assert!(err.to_string().contains("1024/2048"));
    }

    #[test]
    fn test_device_init_error_display() {
        let err = Error::DeviceInit {
            device_id: 99,
            message: "Device not found".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("99"));
        assert!(msg.contains("Device not found"));
    }

    #[test]
    fn test_cuda_operation_error() {
        let err = Error::CudaOperation("kernel launch failed".into());
        assert!(err.to_string().contains("kernel launch failed"));
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_invalid_buffer_size_error() {
        let err = Error::InvalidBufferSize {
            requested: 1024 * 1024 * 1024,
            maximum: 512 * 1024 * 1024,
        };
        let msg = err.to_string();
        assert!(msg.contains("1073741824"));
        assert!(msg.contains("536870912"));
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_alignment_error() {
        let err = Error::alignment(0x1001, 16);
        let msg = err.to_string();
        assert!(msg.contains("0x1001"));
        assert!(msg.contains("16"));
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_device_query_error() {
        let err = Error::DeviceQuery("Failed to get compute capability".into());
        assert!(err.to_string().contains("compute capability"));
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_stream_error() {
        let err = Error::Stream("Stream synchronization failed".into());
        assert!(err.to_string().contains("synchronization"));
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_invalid_operation_error() {
        let err = Error::InvalidOperation("Cannot hash empty data".into());
        assert!(err.to_string().contains("empty data"));
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_crypto_error() {
        let err = Error::Crypto("Invalid key length".into());
        assert!(err.to_string().contains("Invalid key length"));
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_hashing_error() {
        let err = Error::Hashing("Buffer too small".into());
        assert!(err.to_string().contains("Buffer too small"));
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_invalid_parameter_error() {
        let err = Error::InvalidParameter("Chunk size must be positive".into());
        assert!(err.to_string().contains("Chunk size"));
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_synchronization_error() {
        let err = Error::Synchronization("Deadlock detected".into());
        assert!(err.to_string().contains("Deadlock"));
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_error_debug_format() {
        let err = Error::out_of_memory(100, 50);
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("OutOfMemory"));
    }

    #[test]
    fn test_all_error_variants_are_non_empty() {
        let errors: Vec<Error> = vec![
            Error::DeviceInit { device_id: 0, message: "test".into() },
            Error::CudaOperation("test".into()),
            Error::out_of_memory(1, 0),
            Error::InvalidBufferSize { requested: 1, maximum: 0 },
            Error::pool_exhausted(1, 1),
            Error::alignment(1, 1),
            Error::DeviceQuery("test".into()),
            Error::Stream("test".into()),
            Error::InvalidOperation("test".into()),
            Error::Crypto("test".into()),
            Error::Hashing("test".into()),
            Error::InvalidParameter("test".into()),
            Error::Synchronization("test".into()),
        ];

        for err in errors {
            let msg = err.to_string();
            assert!(!msg.is_empty(), "Error message should not be empty: {:?}", err);
        }
    }
}
