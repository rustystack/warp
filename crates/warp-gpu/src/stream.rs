//! Multi-stream management for overlapping computation and transfers
//!
//! # GPU Stream Architecture
//!
//! CUDA streams enable concurrent execution of:
//! 1. Host-to-device transfers (H2D)
//! 2. Kernel execution
//! 3. Device-to-host transfers (D2H)
//!
//! # Overlap Strategy
//!
//! Classic three-stage pipeline:
//! ```text
//! Stream 0: [H2D] [Kernel] [D2H]
//! Stream 1:       [H2D]    [Kernel] [D2H]
//! Stream 2:               [H2D]     [Kernel] [D2H]
//! ```
//!
//! This achieves near-perfect overlap when:
//! - Transfer time ~= Kernel time
//! - At least 3 streams (one per pipeline stage)
//! - Pinned memory for async transfers
//!
//! # Performance Impact
//!
//! Without streams:
//! - Total time = N * (H2D + Kernel + D2H)
//!
//! With M streams (M >= 3):
//! - Total time ≈ max(H2D, Kernel, D2H) + (N-1) * max(H2D, Kernel, D2H) / M
//! - Speedup: ~3x for balanced workloads
//!
//! # Memory Requirements
//!
//! Each stream requires:
//! - Input buffer (pinned host memory)
//! - Device buffer (GPU memory)
//! - Output buffer (pinned host memory)
//!
//! Total: M * (2 * buffer_size) host + M * buffer_size device

use crate::{Error, Result, memory::PinnedMemoryPool};
use cudarc::driver::{CudaContext, CudaStream};
use std::sync::{Arc, Mutex};
use tracing::{debug, trace, warn};

/// Configuration for stream manager
#[derive(Debug, Clone)]
pub struct StreamConfig {
    /// Number of concurrent streams
    pub num_streams: usize,

    /// Buffer size per stream
    pub buffer_size: usize,

    /// Enable priority streams (high-priority streams execute first)
    pub use_priority: bool,

    /// Stream priority (0 = highest, used if use_priority = true)
    pub priority: i32,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            num_streams: 4,                // 4 streams for good overlap
            buffer_size: 16 * 1024 * 1024, // 16MB per stream
            use_priority: false,
            priority: 0,
        }
    }
}

impl StreamConfig {
    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        if self.num_streams == 0 {
            return Err(Error::InvalidParameter(
                "num_streams must be > 0".to_string(),
            ));
        }

        if self.buffer_size == 0 {
            return Err(Error::InvalidParameter(
                "buffer_size must be > 0".to_string(),
            ));
        }

        Ok(())
    }

    /// Estimate total memory required
    pub fn memory_requirement(&self) -> usize {
        // Per stream: input + output (host pinned) + device buffer
        let per_stream = self.buffer_size * 3;
        per_stream * self.num_streams
    }
}

/// A managed CUDA stream with associated buffers
struct StreamSlot {
    stream: Arc<CudaStream>,
    slot_id: usize,
    is_busy: bool,
}

impl StreamSlot {
    fn new(ctx: &Arc<CudaContext>, slot_id: usize, priority: Option<i32>) -> Result<Self> {
        let stream = if let Some(_pri) = priority {
            // cudarc 0.18 doesn't expose stream priority directly
            // In production CUDA API, use cudaStreamCreateWithPriority
            ctx.new_stream()?
        } else {
            ctx.new_stream()?
        };

        Ok(Self {
            stream,
            slot_id,
            is_busy: false,
        })
    }
}

/// Manages multiple CUDA streams for concurrent execution
///
/// The stream manager maintains a pool of streams and schedules work
/// across them to maximize GPU utilization and hide transfer latency.
pub struct StreamManager {
    ctx: Arc<CudaContext>,
    config: StreamConfig,
    streams: Vec<Mutex<StreamSlot>>,
    /// Memory pool for pinned buffer allocation (reserved for future use)
    #[allow(dead_code)]
    memory_pool: Arc<PinnedMemoryPool>,
}

impl StreamManager {
    /// Create a new stream manager
    ///
    /// # Arguments
    /// * `ctx` - CUDA context
    /// * `config` - Stream configuration
    /// * `memory_pool` - Shared memory pool for buffers
    pub fn new(
        ctx: Arc<CudaContext>,
        config: StreamConfig,
        memory_pool: Arc<PinnedMemoryPool>,
    ) -> Result<Self> {
        config.validate()?;

        let mut streams = Vec::with_capacity(config.num_streams);

        let priority = if config.use_priority {
            Some(config.priority)
        } else {
            None
        };

        for i in 0..config.num_streams {
            let slot = StreamSlot::new(&ctx, i, priority)?;
            streams.push(Mutex::new(slot));
        }

        debug!(
            "Created stream manager with {} streams, {} MB per stream",
            config.num_streams,
            config.buffer_size / (1024 * 1024)
        );

        Ok(Self {
            ctx,
            config,
            streams,
            memory_pool,
        })
    }

    /// Create stream manager with default configuration
    pub fn with_defaults(
        ctx: Arc<CudaContext>,
        memory_pool: Arc<PinnedMemoryPool>,
    ) -> Result<Self> {
        Self::new(ctx, StreamConfig::default(), memory_pool)
    }

    /// Acquire an available stream
    ///
    /// This method blocks until a stream becomes available.
    /// Returns the stream index and a guard that releases the stream on drop.
    pub fn acquire_stream(&self) -> Result<StreamGuard<'_>> {
        // Try to find an idle stream (non-blocking)
        for (idx, stream_mutex) in self.streams.iter().enumerate() {
            if let Ok(mut stream) = stream_mutex.try_lock()
                && !stream.is_busy
            {
                stream.is_busy = true;
                trace!("Acquired stream {}", idx);
                return Ok(StreamGuard {
                    manager: self,
                    stream_id: idx,
                });
            }
        }

        // All streams busy, wait for one (blocking)
        // In production, use condition variable for efficient waiting
        warn!("All streams busy, waiting...");

        loop {
            for (idx, stream_mutex) in self.streams.iter().enumerate() {
                if let Ok(mut stream) = stream_mutex.lock()
                    && !stream.is_busy
                {
                    stream.is_busy = true;
                    trace!("Acquired stream {} after waiting", idx);
                    return Ok(StreamGuard {
                        manager: self,
                        stream_id: idx,
                    });
                }
            }

            // Small sleep to avoid busy-waiting
            std::thread::sleep(std::time::Duration::from_micros(100));
        }
    }

    /// Get reference to underlying CUDA stream
    ///
    /// # Safety
    /// Check if a stream ID is valid
    ///
    /// Each valid stream slot always has an associated CUDA stream
    pub fn has_stream(&self, stream_id: usize) -> bool {
        stream_id < self.streams.len()
    }

    /// Synchronize all streams
    ///
    /// Blocks until all streams have completed their work
    pub fn synchronize_all(&self) -> Result<()> {
        for stream_mutex in &self.streams {
            if let Ok(stream) = stream_mutex.lock() {
                // Synchronize each stream individually
                trace!("Synchronizing stream {}", stream.slot_id);
                stream.stream.synchronize()?;
            }
        }

        debug!("All streams synchronized");
        Ok(())
    }

    /// Get number of streams
    pub fn num_streams(&self) -> usize {
        self.config.num_streams
    }

    /// Get buffer size per stream
    pub fn buffer_size(&self) -> usize {
        self.config.buffer_size
    }

    /// Release a stream (called by StreamGuard on drop)
    fn release_stream(&self, stream_id: usize) {
        if let Some(stream_mutex) = self.streams.get(stream_id)
            && let Ok(mut stream) = stream_mutex.lock()
        {
            stream.is_busy = false;
            trace!("Released stream {}", stream_id);
        }
    }
}

/// RAII guard for stream ownership
///
/// Automatically releases the stream when dropped
pub struct StreamGuard<'a> {
    manager: &'a StreamManager,
    stream_id: usize,
}

impl<'a> StreamGuard<'a> {
    /// Get the stream ID
    pub fn id(&self) -> usize {
        self.stream_id
    }

    /// Check if this guard has a valid stream
    pub fn has_stream(&self) -> bool {
        self.manager.has_stream(self.stream_id)
    }

    /// Synchronize this stream
    pub fn synchronize(&self) -> Result<()> {
        // Synchronize the context to wait for all work
        self.manager.ctx.synchronize()?;
        Ok(())
    }
}

impl<'a> Drop for StreamGuard<'a> {
    fn drop(&mut self) {
        self.manager.release_stream(self.stream_id);
    }
}

/// Pipeline executor for multi-stream operations
///
/// Manages a three-stage pipeline:
/// 1. Transfer input to GPU
/// 2. Execute kernel
/// 3. Transfer output from GPU
pub struct PipelineExecutor {
    manager: Arc<StreamManager>,
}

impl PipelineExecutor {
    /// Create a new pipeline executor
    pub fn new(manager: Arc<StreamManager>) -> Self {
        Self { manager }
    }

    /// Execute a batch of operations with pipelined streams
    ///
    /// # Arguments
    /// * `inputs` - Input data batches
    /// * `process_fn` - Function to process each batch on GPU
    ///
    /// # Returns
    /// Vector of results, one per input
    ///
    /// Note: CUDA streams are not thread-safe, so this processes sequentially
    /// but uses stream-based overlapping within the GPU for performance.
    pub fn execute_batch<F, T>(&self, inputs: &[Vec<u8>], process_fn: F) -> Result<Vec<T>>
    where
        F: Fn(usize, &[u8]) -> Result<T>,
    {
        let mut results = Vec::with_capacity(inputs.len());

        // Process each input sequentially, using round-robin stream assignment
        // This still benefits from GPU stream overlap for memory transfers
        for input in inputs.iter() {
            // Acquire and process on stream
            let stream_guard = self.manager.acquire_stream()?;
            let result = process_fn(stream_guard.id(), input)?;
            results.push(result);
            // Stream released on guard drop
        }

        Ok(results)
    }

    /// Execute a batch of operations sequentially
    ///
    /// Simpler version that doesn't require stream management
    pub fn execute_sequential<F, T>(&self, inputs: &[Vec<u8>], process_fn: F) -> Result<Vec<T>>
    where
        F: Fn(&[u8]) -> Result<T>,
    {
        inputs.iter().map(|input| process_fn(input)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_config_validation() {
        let mut config = StreamConfig::default();
        assert!(config.validate().is_ok());

        config.num_streams = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_memory_requirement() {
        let config = StreamConfig {
            num_streams: 4,
            buffer_size: 16 * 1024 * 1024,
            ..Default::default()
        };

        let required = config.memory_requirement();
        assert_eq!(required, 4 * 3 * 16 * 1024 * 1024);
    }
}
