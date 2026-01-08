//! Core data structures for GPU chunk scheduling
//!
//! All types are designed for GPU compatibility with C representation and
//! proper alignment. Critical state structures (`ChunkState`, `EdgeStateGpu`)
//! are aligned to 64 bytes for optimal GPU memory access patterns.

use serde::{Deserialize, Serialize};

/// Compact chunk identifier for GPU efficiency
///
/// Uses a single u64 to uniquely identify chunks. Can be derived from
/// the first 8 bytes of the BLAKE3 hash for fast lookups.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChunkId(pub u64);

impl ChunkId {
    /// Create a `ChunkId` from a u64
    #[inline]
    #[must_use]
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Get the inner u64 value
    #[inline]
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Create a `ChunkId` from the first 8 bytes of a hash
    #[must_use]
    pub fn from_hash(hash: &[u8; 32]) -> Self {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&hash[..8]);
        Self(u64::from_le_bytes(bytes))
    }
}

impl From<u64> for ChunkId {
    fn from(id: u64) -> Self {
        Self(id)
    }
}

impl From<ChunkId> for u64 {
    fn from(id: ChunkId) -> Self {
        id.0
    }
}

/// Compact edge index for GPU efficiency
///
/// Uses a u32 to index into edge arrays. Supports up to 4 billion edges,
/// which is far beyond practical distributed storage network sizes.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EdgeIdx(pub u32);

impl EdgeIdx {
    /// Create an `EdgeIdx` from a u32
    #[inline]
    #[must_use]
    pub const fn new(idx: u32) -> Self {
        Self(idx)
    }

    /// Get the inner u32 value
    #[inline]
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl From<u32> for EdgeIdx {
    fn from(idx: u32) -> Self {
        Self(idx)
    }
}

impl From<EdgeIdx> for u32 {
    fn from(idx: EdgeIdx) -> Self {
        idx.0
    }
}

impl From<usize> for EdgeIdx {
    fn from(idx: usize) -> Self {
        Self(idx as u32)
    }
}

/// Transfer status enum
///
/// Represents the current state of a chunk transfer. Repr(u8) for GPU compatibility.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ChunkStatus {
    /// Chunk is idle, not scheduled
    #[default]
    Idle = 0,
    /// Chunk is scheduled but transfer hasn't started
    Scheduled = 1,
    /// Chunk is actively transferring
    InTransfer = 2,
    /// Chunk transfer failed
    Failed = 3,
    /// Chunk transfer completed
    Completed = 4,
}

impl ChunkStatus {
    /// Convert from u8 value
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Idle),
            1 => Some(Self::Scheduled),
            2 => Some(Self::InTransfer),
            3 => Some(Self::Failed),
            4 => Some(Self::Completed),
            _ => None,
        }
    }

    /// Check if status represents an active transfer
    #[inline]
    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Scheduled | Self::InTransfer)
    }

    /// Check if status represents a terminal state
    #[inline]
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Failed | Self::Completed)
    }
}

/// GPU-compatible chunk state (64 bytes aligned)
///
/// Contains all necessary state for GPU scheduling decisions.
/// Layout is carefully designed for coalesced memory access.
#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct ChunkState {
    /// BLAKE3 hash of chunk content
    pub hash: [u8; 32],
    /// Chunk size in bytes
    pub size: u32,
    /// Priority (0-255, higher is more urgent)
    pub priority: u8,
    /// Desired number of replicas
    pub replica_target: u8,
    /// Current number of replicas
    pub replica_count: u8,
    /// Transfer status
    pub status: ChunkStatus,
    /// Last update timestamp (epoch millis mod 2^32)
    pub last_update_ms: u32,
    /// Padding to 64 bytes
    pub _padding: [u8; 20],
}

impl ChunkState {
    /// Create a new `ChunkState`
    #[must_use]
    pub const fn new(hash: [u8; 32], size: u32, priority: u8, replica_target: u8) -> Self {
        Self {
            hash,
            size,
            priority,
            replica_target,
            replica_count: 0,
            status: ChunkStatus::Idle,
            last_update_ms: 0,
            _padding: [0; 20],
        }
    }

    /// Update the timestamp to current time
    pub fn update_timestamp(&mut self) {
        self.last_update_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::ZERO)
            .as_millis() as u32;
    }

    /// Check if chunk needs more replicas
    #[inline]
    #[must_use]
    pub const fn needs_replication(&self) -> bool {
        self.replica_count < self.replica_target
    }
}

impl std::fmt::Debug for ChunkState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChunkState")
            .field("hash", &format!("{:x?}", &self.hash[..8]))
            .field("size", &self.size)
            .field("priority", &self.priority)
            .field("replica_target", &self.replica_target)
            .field("replica_count", &self.replica_count)
            .field("status", &self.status)
            .field("last_update_ms", &self.last_update_ms)
            .finish()
    }
}

/// GPU-compatible edge state (64 bytes aligned)
///
/// Contains edge network characteristics for scheduling decisions.
/// Layout: `edge_idx(4)` + pad(4) + bandwidth(8) + rtt(4) + health(2) +
///         active(2) + max(2) + status(1) + pad(37) = 64 bytes
#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct EdgeStateGpu {
    /// Edge index
    pub edge_idx: EdgeIdx,
    /// Padding for u64 alignment (4 bytes)
    pub _pad1: u32,
    /// Available bandwidth in bits per second
    pub available_bandwidth_bps: u64,
    /// Round-trip time in microseconds
    pub rtt_us: u32,
    /// Health score (0-65535 scaled from 0.0-1.0)
    pub health_score: u16,
    /// Number of active transfers
    pub active_transfers: u16,
    /// Maximum concurrent transfers
    pub max_transfers: u16,
    /// Edge status as u8
    pub status: u8,
    /// Padding to 64 bytes (37 bytes)
    pub _padding: [u8; 37],
}

impl EdgeStateGpu {
    /// Create a new `EdgeStateGpu`
    #[must_use]
    pub fn new(
        edge_idx: EdgeIdx,
        available_bandwidth_bps: u64,
        rtt_us: u32,
        health_score: f32,
        max_transfers: u16,
    ) -> Self {
        let health_score_u16 = (health_score.clamp(0.0, 1.0) * 65535.0) as u16;
        Self {
            edge_idx,
            _pad1: 0,
            available_bandwidth_bps,
            rtt_us,
            health_score: health_score_u16,
            active_transfers: 0,
            max_transfers,
            status: 1, // Active by default
            _padding: [0; 37],
        }
    }

    /// Get health score as f32 (0.0-1.0)
    #[inline]
    #[must_use]
    pub fn health_score_f32(&self) -> f32 {
        f32::from(self.health_score) / 65535.0
    }

    /// Check if edge can accept more transfers
    #[inline]
    #[must_use]
    pub const fn can_accept_transfer(&self) -> bool {
        self.active_transfers < self.max_transfers && self.status == 1
    }

    /// Get estimated transfer time for given bytes
    #[must_use]
    pub fn estimate_transfer_time_ms(&self, bytes: u32) -> u32 {
        if self.available_bandwidth_bps == 0 {
            return u32::MAX;
        }
        let bits = u64::from(bytes) * 8;
        let transfer_ms = (bits * 1000) / self.available_bandwidth_bps;
        let rtt_ms = self.rtt_us / 1000;
        (transfer_ms as u32 + rtt_ms).max(1)
    }
}

impl std::fmt::Debug for EdgeStateGpu {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EdgeStateGpu")
            .field("edge_idx", &self.edge_idx)
            .field("available_bandwidth_bps", &self.available_bandwidth_bps)
            .field("rtt_us", &self.rtt_us)
            .field("health_score", &self.health_score_f32())
            .field("active_transfers", &self.active_transfers)
            .field("max_transfers", &self.max_transfers)
            .field("status", &self.status)
            .finish()
    }
}

/// Scheduling assignment result
///
/// Represents the decision to transfer a chunk via specific edges.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assignment {
    /// BLAKE3 hash of the chunk
    pub chunk_hash: [u8; 32],
    /// Size of the chunk in bytes
    pub chunk_size: u32,
    /// K-best source edges for this transfer
    pub source_edges: Vec<EdgeIdx>,
    /// Priority level (0-255)
    pub priority: u8,
    /// Estimated duration in milliseconds
    pub estimated_duration_ms: u32,
}

impl Assignment {
    /// Create a new Assignment
    #[must_use]
    pub const fn new(
        chunk_hash: [u8; 32],
        chunk_size: u32,
        source_edges: Vec<EdgeIdx>,
        priority: u8,
        estimated_duration_ms: u32,
    ) -> Self {
        Self {
            chunk_hash,
            chunk_size,
            source_edges,
            priority,
            estimated_duration_ms,
        }
    }

    /// Get the number of source edges
    #[inline]
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.source_edges.len()
    }

    /// Check if assignment has any source edges
    #[inline]
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.source_edges.is_empty()
    }
}

/// Batch of assignments
///
/// Groups multiple assignments together for efficient processing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssignmentBatch {
    /// Vector of assignments
    pub assignments: Vec<Assignment>,
    /// Generation number for versioning
    pub generation: u64,
    /// Timestamp in milliseconds since epoch
    pub timestamp_ms: u64,
}

impl AssignmentBatch {
    /// Create a new `AssignmentBatch`
    #[must_use]
    pub fn new(assignments: Vec<Assignment>, generation: u64) -> Self {
        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::ZERO)
            .as_millis() as u64;
        Self {
            assignments,
            generation,
            timestamp_ms,
        }
    }

    /// Create an empty batch
    #[must_use]
    pub fn empty(generation: u64) -> Self {
        Self::new(Vec::new(), generation)
    }

    /// Get the number of assignments in the batch
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.assignments.len()
    }

    /// Check if the batch is empty
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.assignments.is_empty()
    }

    /// Add an assignment to the batch
    pub fn push(&mut self, assignment: Assignment) {
        self.assignments.push(assignment);
    }

    /// Get total estimated duration for all assignments
    #[must_use]
    pub fn total_estimated_duration_ms(&self) -> u64 {
        self.assignments
            .iter()
            .map(|a| u64::from(a.estimated_duration_ms))
            .sum()
    }
}

impl Default for AssignmentBatch {
    fn default() -> Self {
        Self::empty(0)
    }
}

/// Request to schedule chunks
///
/// Contains the chunks to schedule and their requirements.
#[derive(Debug, Clone)]
pub struct ScheduleRequest {
    /// Chunk hashes to schedule
    pub chunks: Vec<[u8; 32]>,
    /// Priority level (0-255, higher is more urgent)
    pub priority: u8,
    /// Target number of replicas
    pub replica_target: u8,
    /// Optional deadline in milliseconds since epoch
    pub deadline_ms: Option<u64>,
}

impl ScheduleRequest {
    /// Create a new `ScheduleRequest`
    #[must_use]
    pub const fn new(chunks: Vec<[u8; 32]>, priority: u8, replica_target: u8) -> Self {
        Self {
            chunks,
            priority,
            replica_target,
            deadline_ms: None,
        }
    }

    /// Create a `ScheduleRequest` with a deadline
    #[must_use]
    pub const fn with_deadline(
        chunks: Vec<[u8; 32]>,
        priority: u8,
        replica_target: u8,
        deadline_ms: u64,
    ) -> Self {
        Self {
            chunks,
            priority,
            replica_target,
            deadline_ms: Some(deadline_ms),
        }
    }

    /// Get the number of chunks in the request
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.chunks.len()
    }

    /// Check if the request is empty
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    /// Check if the deadline has passed
    #[must_use]
    pub fn is_past_deadline(&self) -> bool {
        if let Some(deadline) = self.deadline_ms {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or(std::time::Duration::ZERO)
                .as_millis() as u64;
            now > deadline
        } else {
            false
        }
    }

    /// Get time remaining until deadline in milliseconds
    #[must_use]
    pub fn time_remaining_ms(&self) -> Option<u64> {
        self.deadline_ms.map(|deadline| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or(std::time::Duration::ZERO)
                .as_millis() as u64;
            deadline.saturating_sub(now)
        })
    }
}

/// Performance metrics
///
/// Tracks scheduler performance for monitoring and optimization.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SchedulerMetrics {
    /// Total number of chunks being tracked
    pub total_chunks: usize,
    /// Number of scheduled chunks
    pub scheduled_chunks: usize,
    /// Number of active transfers
    pub active_transfers: usize,
    /// Number of failed chunks
    pub failed_chunks: usize,
    /// Average scheduling time in microseconds
    pub avg_schedule_time_us: u64,
    /// Average failover time in microseconds
    pub avg_failover_time_us: u64,
    /// Total number of scheduling ticks
    pub tick_count: u64,
}

impl SchedulerMetrics {
    /// Create new metrics with all fields set to zero
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset all metrics to zero
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Get the completion rate (0.0-1.0)
    #[must_use]
    pub fn completion_rate(&self) -> f64 {
        if self.total_chunks == 0 {
            return 0.0;
        }
        let completed = self
            .total_chunks
            .saturating_sub(self.scheduled_chunks + self.active_transfers + self.failed_chunks);
        completed as f64 / self.total_chunks as f64
    }

    /// Get the failure rate (0.0-1.0)
    #[must_use]
    pub fn failure_rate(&self) -> f64 {
        if self.total_chunks == 0 {
            return 0.0;
        }
        self.failed_chunks as f64 / self.total_chunks as f64
    }

    /// Check if metrics indicate healthy operation
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.failure_rate() < 0.1 && self.avg_failover_time_us < 50_000
    }
}

// ============================================================================
// Dynamic Throughput Measurement Types (Phase 7)
// ============================================================================

/// RTT trend detection for congestion signaling
///
/// Tracks whether round-trip time is stable, increasing (congestion), or decreasing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum RttTrend {
    /// RTT variance < 10% - stable network conditions
    #[default]
    Stable,
    /// RTT growing - potential congestion signal
    Increasing,
    /// RTT improving - congestion clearing
    Decreasing,
}

impl RttTrend {
    /// Calculate trend from RTT samples
    ///
    /// Compares recent samples against older samples to detect trend.
    /// Returns Stable if insufficient samples or variance is low.
    #[must_use]
    pub fn from_samples(samples: &[u32], threshold: f32) -> Self {
        if samples.len() < 4 {
            return Self::Stable;
        }

        let mid = samples.len() / 2;
        let (older, recent) = samples.split_at(mid);

        let older_avg = older.iter().map(|&x| f64::from(x)).sum::<f64>() / older.len() as f64;
        let recent_avg = recent.iter().map(|&x| f64::from(x)).sum::<f64>() / recent.len() as f64;

        if older_avg == 0.0 {
            return Self::Stable;
        }

        let change_ratio = (recent_avg - older_avg) / older_avg;

        if change_ratio > f64::from(threshold) {
            Self::Increasing
        } else if change_ratio < -f64::from(threshold) {
            Self::Decreasing
        } else {
            Self::Stable
        }
    }
}

/// Per-path throughput metrics with sliding window measurement
///
/// Tracks actual throughput vs nominal capacity to detect saturation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathThroughput {
    /// Bytes transferred in current measurement window
    pub bytes_in_window: u64,
    /// Window start timestamp (milliseconds since epoch)
    pub window_start_ms: u64,
    /// Calculated throughput (bytes per second)
    pub throughput_bps: u64,
    /// Nominal/configured capacity (bytes per second)
    pub capacity_bps: u64,
    /// Saturation ratio (throughput / capacity), 0.0 to 1.0+
    pub saturation_ratio: f32,
}

impl PathThroughput {
    /// Create new throughput tracker with given capacity
    #[must_use]
    pub fn new(capacity_bps: u64) -> Self {
        Self {
            bytes_in_window: 0,
            window_start_ms: current_time_ms(),
            throughput_bps: 0,
            capacity_bps,
            saturation_ratio: 0.0,
        }
    }

    /// Record bytes transferred
    pub const fn record_bytes(&mut self, bytes: u64) {
        self.bytes_in_window += bytes;
    }

    /// Update throughput calculation if window has elapsed
    ///
    /// Returns true if window was reset (throughput recalculated)
    pub fn maybe_update(&mut self, window_ms: u64) -> bool {
        let now = current_time_ms();
        let elapsed = now.saturating_sub(self.window_start_ms);

        if elapsed >= window_ms {
            // Calculate throughput: bytes/second
            if elapsed > 0 {
                self.throughput_bps = (self.bytes_in_window * 1000) / elapsed;
            }

            // Calculate saturation ratio
            if self.capacity_bps > 0 {
                self.saturation_ratio = self.throughput_bps as f32 / self.capacity_bps as f32;
            }

            // Reset window
            self.bytes_in_window = 0;
            self.window_start_ms = now;
            true
        } else {
            false
        }
    }

    /// Check if path is saturated (above threshold)
    #[must_use]
    pub fn is_saturated(&self, threshold: f32) -> bool {
        self.saturation_ratio > threshold
    }
}

impl Default for PathThroughput {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Enhanced edge metrics for dynamic adaptation
///
/// Combines throughput measurement, RTT tracking, and queue depth
/// for intelligent load shifting decisions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicEdgeMetrics {
    /// Edge index this metrics belongs to
    pub edge_idx: EdgeIdx,
    /// Current throughput metrics
    pub throughput: PathThroughput,
    /// Rolling buffer of RTT samples (microseconds)
    pub rtt_samples: Vec<u32>,
    /// Maximum RTT samples to keep
    pub max_rtt_samples: usize,
    /// Detected RTT trend
    pub rtt_trend: RttTrend,
    /// RTT change threshold for trend detection (e.g., 0.20 = 20%)
    pub rtt_threshold: f32,
    /// Bytes currently queued for this edge
    pub queue_depth_bytes: u64,
    /// Last update timestamp
    pub last_updated_ms: u64,
}

impl DynamicEdgeMetrics {
    /// Create new metrics for an edge
    #[must_use]
    pub fn new(edge_idx: EdgeIdx, capacity_bps: u64) -> Self {
        Self {
            edge_idx,
            throughput: PathThroughput::new(capacity_bps),
            rtt_samples: Vec::with_capacity(10),
            max_rtt_samples: 10,
            rtt_trend: RttTrend::Stable,
            rtt_threshold: 0.20, // 20% change threshold
            queue_depth_bytes: 0,
            last_updated_ms: current_time_ms(),
        }
    }

    /// Record a new RTT sample and update trend
    pub fn record_rtt(&mut self, rtt_us: u32) {
        // Add sample, maintaining max size
        if self.rtt_samples.len() >= self.max_rtt_samples {
            self.rtt_samples.remove(0);
        }
        self.rtt_samples.push(rtt_us);

        // Update trend
        self.rtt_trend = RttTrend::from_samples(&self.rtt_samples, self.rtt_threshold);
        self.last_updated_ms = current_time_ms();
    }

    /// Record bytes transferred and update throughput
    pub fn record_transfer(&mut self, bytes: u64, window_ms: u64) {
        self.throughput.record_bytes(bytes);
        self.throughput.maybe_update(window_ms);
        self.last_updated_ms = current_time_ms();
    }

    /// Update queue depth
    pub fn update_queue_depth(&mut self, bytes: u64) {
        self.queue_depth_bytes = bytes;
        self.last_updated_ms = current_time_ms();
    }

    /// Get current average RTT in microseconds
    #[must_use]
    pub fn avg_rtt_us(&self) -> u32 {
        if self.rtt_samples.is_empty() {
            return 0;
        }
        let sum: u64 = self.rtt_samples.iter().map(|&x| u64::from(x)).sum();
        (sum / self.rtt_samples.len() as u64) as u32
    }

    /// Check if edge shows signs of congestion
    #[must_use]
    pub fn is_congested(&self, saturation_threshold: f32) -> bool {
        self.throughput.is_saturated(saturation_threshold) || self.rtt_trend == RttTrend::Increasing
    }
}

/// Helper function to get current time in milliseconds
fn current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(std::time::Duration::ZERO)
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_id() {
        let id = ChunkId::new(42);
        assert_eq!(id.get(), 42);
        let id: ChunkId = 123u64.into();
        assert_eq!(id.0, 123);
        let value: u64 = id.into();
        assert_eq!(value, 123);
        let mut hash = [0u8; 32];
        hash[..8].copy_from_slice(&[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]);
        let id = ChunkId::from_hash(&hash);
        assert_eq!(
            id.get(),
            u64::from_le_bytes([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0])
        );
    }

    #[test]
    fn test_edge_idx() {
        let idx = EdgeIdx::new(100);
        assert_eq!(idx.get(), 100);
        let idx: EdgeIdx = 256u32.into();
        assert_eq!(idx.0, 256);
        let value: u32 = idx.into();
        assert_eq!(value, 256);
        let idx: EdgeIdx = 1000usize.into();
        assert_eq!(idx.get(), 1000);
    }

    #[test]
    fn test_chunk_status() {
        assert_eq!(ChunkStatus::Idle as u8, 0);
        assert_eq!(ChunkStatus::Scheduled as u8, 1);
        assert_eq!(ChunkStatus::InTransfer as u8, 2);
        assert_eq!(ChunkStatus::Failed as u8, 3);
        assert_eq!(ChunkStatus::Completed as u8, 4);
        assert_eq!(ChunkStatus::from_u8(0), Some(ChunkStatus::Idle));
        assert_eq!(ChunkStatus::from_u8(1), Some(ChunkStatus::Scheduled));
        assert_eq!(ChunkStatus::from_u8(2), Some(ChunkStatus::InTransfer));
        assert_eq!(ChunkStatus::from_u8(3), Some(ChunkStatus::Failed));
        assert_eq!(ChunkStatus::from_u8(4), Some(ChunkStatus::Completed));
        assert_eq!(ChunkStatus::from_u8(5), None);
        assert!(!ChunkStatus::Idle.is_active());
        assert!(ChunkStatus::Scheduled.is_active());
        assert!(ChunkStatus::InTransfer.is_active());
        assert!(!ChunkStatus::Failed.is_active());
        assert!(!ChunkStatus::Completed.is_active());
        assert!(!ChunkStatus::Idle.is_terminal());
        assert!(!ChunkStatus::Scheduled.is_terminal());
        assert!(!ChunkStatus::InTransfer.is_terminal());
        assert!(ChunkStatus::Failed.is_terminal());
        assert!(ChunkStatus::Completed.is_terminal());
    }

    #[test]
    fn test_chunk_state_size() {
        assert_eq!(std::mem::size_of::<ChunkState>(), 64);
        assert_eq!(std::mem::align_of::<ChunkState>(), 64);
    }

    #[test]
    fn test_chunk_state_new() {
        let hash = [1u8; 32];
        let state = ChunkState::new(hash, 1024, 128, 3);
        assert_eq!(state.hash, hash);
        assert_eq!(state.size, 1024);
        assert_eq!(state.priority, 128);
        assert_eq!(state.replica_target, 3);
        assert_eq!(state.replica_count, 0);
        assert_eq!(state.status, ChunkStatus::Idle);
    }

    #[test]
    fn test_chunk_state_needs_replication() {
        let mut state = ChunkState::new([0; 32], 1024, 128, 3);
        assert!(state.needs_replication());
        state.replica_count = 3;
        assert!(!state.needs_replication());
        state.replica_count = 4;
        assert!(!state.needs_replication());
    }

    #[test]
    fn test_edge_state_gpu_size() {
        assert_eq!(std::mem::size_of::<EdgeStateGpu>(), 64);
        assert_eq!(std::mem::align_of::<EdgeStateGpu>(), 64);
    }

    #[test]
    fn test_edge_state_gpu_new() {
        let edge = EdgeStateGpu::new(EdgeIdx::new(5), 1_000_000_000, 5000, 0.95, 10);
        assert_eq!(edge.edge_idx.get(), 5);
        assert_eq!(edge.available_bandwidth_bps, 1_000_000_000);
        assert_eq!(edge.rtt_us, 5000);
        assert_eq!(edge.active_transfers, 0);
        assert_eq!(edge.max_transfers, 10);
        assert_eq!(edge.status, 1);

        // Check health score conversion
        let health = edge.health_score_f32();
        assert!((health - 0.95).abs() < 0.01);
    }

    #[test]
    fn test_edge_state_gpu_can_accept_transfer() {
        let mut edge = EdgeStateGpu::new(EdgeIdx::new(0), 1_000_000_000, 5000, 0.95, 10);
        assert!(edge.can_accept_transfer());

        edge.active_transfers = 10;
        assert!(!edge.can_accept_transfer());

        edge.active_transfers = 5;
        edge.status = 0;
        assert!(!edge.can_accept_transfer());
    }

    #[test]
    fn test_edge_state_gpu_estimate_transfer_time() {
        let edge = EdgeStateGpu::new(EdgeIdx::new(0), 1_000_000_000, 1000, 1.0, 10);
        // 1MB at 1Gbps = 8ms + 1ms RTT = 9ms
        let time = edge.estimate_transfer_time_ms(1024 * 1024);
        assert!(time >= 8 && time <= 10);
    }

    #[test]
    fn test_assignment_new() {
        let hash = [2u8; 32];
        let edges = vec![EdgeIdx::new(0), EdgeIdx::new(1), EdgeIdx::new(2)];
        let assignment = Assignment::new(hash, 2048, edges.clone(), 200, 100);

        assert_eq!(assignment.chunk_hash, hash);
        assert_eq!(assignment.chunk_size, 2048);
        assert_eq!(assignment.source_edges, edges);
        assert_eq!(assignment.priority, 200);
        assert_eq!(assignment.estimated_duration_ms, 100);
    }

    #[test]
    fn test_assignment_validation() {
        let assignment = Assignment::new(
            [0; 32],
            1024,
            vec![EdgeIdx::new(0), EdgeIdx::new(1)],
            100,
            50,
        );
        assert_eq!(assignment.edge_count(), 2);
        assert!(assignment.is_valid());
        let invalid = Assignment::new([0; 32], 1024, vec![], 100, 50);
        assert!(!invalid.is_valid());
    }

    #[test]
    fn test_assignment_serialization() {
        let assignment = Assignment::new(
            [3u8; 32],
            4096,
            vec![EdgeIdx::new(0), EdgeIdx::new(1)],
            150,
            75,
        );

        let serialized = rmp_serde::to_vec(&assignment).unwrap();
        let deserialized: Assignment = rmp_serde::from_slice(&serialized).unwrap();

        assert_eq!(deserialized.chunk_hash, assignment.chunk_hash);
        assert_eq!(deserialized.chunk_size, assignment.chunk_size);
        assert_eq!(deserialized.source_edges, assignment.source_edges);
    }

    #[test]
    fn test_assignment_batch() {
        let assignments = vec![
            Assignment::new([0; 32], 1024, vec![EdgeIdx::new(0)], 100, 50),
            Assignment::new([1; 32], 2048, vec![EdgeIdx::new(1)], 150, 75),
        ];
        let batch = AssignmentBatch::new(assignments.clone(), 42);
        assert_eq!(batch.generation, 42);
        assert_eq!(batch.len(), 2);
        assert!(!batch.is_empty());
        let empty_batch = AssignmentBatch::empty(10);
        assert_eq!(empty_batch.generation, 10);
        assert!(empty_batch.is_empty());
        assert_eq!(empty_batch.len(), 0);
        let mut batch = AssignmentBatch::empty(1);
        assert_eq!(batch.len(), 0);
        batch.push(Assignment::new(
            [0; 32],
            1024,
            vec![EdgeIdx::new(0)],
            100,
            50,
        ));
        assert_eq!(batch.len(), 1);
    }

    #[test]
    fn test_assignment_batch_total_duration() {
        let mut batch = AssignmentBatch::empty(1);
        batch.push(Assignment::new(
            [0; 32],
            1024,
            vec![EdgeIdx::new(0)],
            100,
            50,
        ));
        batch.push(Assignment::new(
            [1; 32],
            2048,
            vec![EdgeIdx::new(1)],
            150,
            75,
        ));
        batch.push(Assignment::new(
            [2; 32],
            4096,
            vec![EdgeIdx::new(2)],
            200,
            100,
        ));

        assert_eq!(batch.total_estimated_duration_ms(), 225);
    }

    #[test]
    fn test_schedule_request_basic() {
        let chunks = vec![[0u8; 32], [1u8; 32]];
        let request = ScheduleRequest::new(chunks.clone(), 150, 3);
        assert_eq!(request.chunks, chunks);
        assert_eq!(request.priority, 150);
        assert_eq!(request.replica_target, 3);
        assert!(request.deadline_ms.is_none());
        let deadline = 1000000;
        let request = ScheduleRequest::with_deadline(vec![[0u8; 32]], 200, 5, deadline);
        assert_eq!(request.deadline_ms, Some(deadline));
        let request = ScheduleRequest::new(vec![[0; 32], [1; 32], [2; 32]], 100, 2);
        assert_eq!(request.len(), 3);
        assert!(!request.is_empty());
    }

    #[test]
    fn test_schedule_request_deadline() {
        let past_deadline = 1000;
        let request = ScheduleRequest::with_deadline(vec![[0; 32]], 100, 2, past_deadline);
        assert!(request.is_past_deadline());
        let future_deadline = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            + 10000;
        let request = ScheduleRequest::with_deadline(vec![[0; 32]], 100, 2, future_deadline);
        assert!(!request.is_past_deadline());
        let no_deadline = ScheduleRequest::new(vec![[0; 32]], 100, 2);
        assert!(no_deadline.time_remaining_ms().is_none());
        let future_deadline = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            + 5000;
        let with_deadline = ScheduleRequest::with_deadline(vec![[0; 32]], 100, 2, future_deadline);
        let remaining = with_deadline.time_remaining_ms().unwrap();
        assert!(remaining > 0 && remaining <= 5000);
    }

    #[test]
    fn test_scheduler_metrics_basic() {
        let metrics = SchedulerMetrics::new();
        assert_eq!(metrics.total_chunks, 0);
        assert_eq!(metrics.scheduled_chunks, 0);
        assert_eq!(metrics.active_transfers, 0);
        assert_eq!(metrics.failed_chunks, 0);
        assert_eq!(metrics.avg_schedule_time_us, 0);
        assert_eq!(metrics.avg_failover_time_us, 0);
        assert_eq!(metrics.tick_count, 0);
        let metrics = SchedulerMetrics::default();
        assert_eq!(metrics.total_chunks, 0);
        let mut metrics = SchedulerMetrics {
            total_chunks: 100,
            scheduled_chunks: 50,
            active_transfers: 25,
            failed_chunks: 5,
            avg_schedule_time_us: 1000,
            avg_failover_time_us: 5000,
            tick_count: 1000,
        };
        metrics.reset();
        assert_eq!(metrics.total_chunks, 0);
        assert_eq!(metrics.tick_count, 0);
    }

    #[test]
    fn test_scheduler_metrics_rates() {
        let mut metrics = SchedulerMetrics::default();
        assert_eq!(metrics.completion_rate(), 0.0);
        metrics.total_chunks = 100;
        metrics.scheduled_chunks = 20;
        metrics.active_transfers = 10;
        metrics.failed_chunks = 5;
        let rate = metrics.completion_rate();
        assert!((rate - 0.65).abs() < 0.01);
        let mut metrics = SchedulerMetrics::default();
        assert_eq!(metrics.failure_rate(), 0.0);
        metrics.total_chunks = 100;
        metrics.failed_chunks = 15;
        assert_eq!(metrics.failure_rate(), 0.15);
    }

    #[test]
    fn test_scheduler_metrics_health() {
        let mut metrics = SchedulerMetrics::default();
        metrics.total_chunks = 100;
        metrics.failed_chunks = 5;
        metrics.avg_failover_time_us = 30_000;
        assert!(metrics.is_healthy());
        metrics.failed_chunks = 15;
        assert!(!metrics.is_healthy());
        metrics.failed_chunks = 5;
        metrics.avg_failover_time_us = 60_000;
        assert!(!metrics.is_healthy());
    }

    #[test]
    fn test_scheduler_metrics_serialization() {
        let metrics = SchedulerMetrics {
            total_chunks: 1000,
            scheduled_chunks: 200,
            active_transfers: 50,
            failed_chunks: 10,
            avg_schedule_time_us: 5000,
            avg_failover_time_us: 25000,
            tick_count: 5000,
        };
        let serialized = rmp_serde::to_vec(&metrics).unwrap();
        let deserialized: SchedulerMetrics = rmp_serde::from_slice(&serialized).unwrap();
        assert_eq!(deserialized.total_chunks, metrics.total_chunks);
        assert_eq!(deserialized.tick_count, metrics.tick_count);
    }

    #[test]
    fn test_chunk_state_update_timestamp() {
        let mut state = ChunkState::new([0; 32], 1024, 100, 3);
        assert_eq!(state.last_update_ms, 0);
        state.update_timestamp();
        assert!(state.last_update_ms > 0);
    }

    #[test]
    fn test_edge_state_gpu_edge_cases() {
        let edge1 = EdgeStateGpu::new(EdgeIdx::new(0), 1_000_000, 1000, 1.5, 10);
        assert!((edge1.health_score_f32() - 1.0).abs() < 0.01);
        let edge2 = EdgeStateGpu::new(EdgeIdx::new(1), 1_000_000, 1000, -0.5, 10);
        assert!(edge2.health_score_f32() < 0.01);
        let edge = EdgeStateGpu::new(EdgeIdx::new(0), 0, 1000, 1.0, 10);
        let time = edge.estimate_transfer_time_ms(1024);
        assert_eq!(time, u32::MAX);
    }

    // ========================================================================
    // Tests for Dynamic Throughput Measurement Types (Phase 7)
    // ========================================================================

    #[test]
    fn test_rtt_trend_stable_with_few_samples() {
        // Less than 4 samples should always return Stable
        let samples = vec![1000, 1000, 1000];
        assert_eq!(RttTrend::from_samples(&samples, 0.20), RttTrend::Stable);

        let empty: Vec<u32> = vec![];
        assert_eq!(RttTrend::from_samples(&empty, 0.20), RttTrend::Stable);
    }

    #[test]
    fn test_rtt_trend_increasing() {
        // RTT increasing by >20%: older avg = 1000, recent avg = 1500 (50% increase)
        let samples = vec![1000, 1000, 1500, 1500];
        assert_eq!(RttTrend::from_samples(&samples, 0.20), RttTrend::Increasing);
    }

    #[test]
    fn test_rtt_trend_decreasing() {
        // RTT decreasing by >20%: older avg = 1500, recent avg = 1000 (33% decrease)
        let samples = vec![1500, 1500, 1000, 1000];
        assert_eq!(RttTrend::from_samples(&samples, 0.20), RttTrend::Decreasing);
    }

    #[test]
    fn test_rtt_trend_stable_within_threshold() {
        // RTT change within threshold: older avg = 1000, recent avg = 1100 (10% increase)
        let samples = vec![1000, 1000, 1100, 1100];
        assert_eq!(RttTrend::from_samples(&samples, 0.20), RttTrend::Stable);
    }

    #[test]
    fn test_path_throughput_new() {
        let throughput = PathThroughput::new(1_000_000_000); // 1 GB/s
        assert_eq!(throughput.capacity_bps, 1_000_000_000);
        assert_eq!(throughput.bytes_in_window, 0);
        assert_eq!(throughput.throughput_bps, 0);
        assert_eq!(throughput.saturation_ratio, 0.0);
    }

    #[test]
    fn test_path_throughput_record_bytes() {
        let mut throughput = PathThroughput::new(1_000_000_000);
        throughput.record_bytes(1_000_000);
        assert_eq!(throughput.bytes_in_window, 1_000_000);
        throughput.record_bytes(500_000);
        assert_eq!(throughput.bytes_in_window, 1_500_000);
    }

    #[test]
    fn test_path_throughput_saturation() {
        let mut throughput = PathThroughput::new(1_000_000); // 1 MB/s capacity
        throughput.throughput_bps = 900_000; // 900 KB/s actual
        throughput.saturation_ratio = 0.9;
        assert!(throughput.is_saturated(0.85));
        assert!(!throughput.is_saturated(0.95));
    }

    #[test]
    fn test_dynamic_edge_metrics_new() {
        let metrics = DynamicEdgeMetrics::new(EdgeIdx::new(5), 1_000_000_000);
        assert_eq!(metrics.edge_idx.get(), 5);
        assert_eq!(metrics.throughput.capacity_bps, 1_000_000_000);
        assert!(metrics.rtt_samples.is_empty());
        assert_eq!(metrics.rtt_trend, RttTrend::Stable);
        assert_eq!(metrics.queue_depth_bytes, 0);
    }

    #[test]
    fn test_dynamic_edge_metrics_record_rtt() {
        let mut metrics = DynamicEdgeMetrics::new(EdgeIdx::new(0), 1_000_000_000);

        // Add samples that show increasing RTT
        metrics.record_rtt(1000);
        metrics.record_rtt(1000);
        metrics.record_rtt(1500);
        metrics.record_rtt(1500);

        assert_eq!(metrics.rtt_samples.len(), 4);
        assert_eq!(metrics.rtt_trend, RttTrend::Increasing);
        assert_eq!(metrics.avg_rtt_us(), 1250);
    }

    #[test]
    fn test_dynamic_edge_metrics_max_samples() {
        let mut metrics = DynamicEdgeMetrics::new(EdgeIdx::new(0), 1_000_000_000);
        metrics.max_rtt_samples = 5;

        // Add more than max samples
        for i in 0..10 {
            metrics.record_rtt(i * 100);
        }

        // Should only keep last 5 samples
        assert_eq!(metrics.rtt_samples.len(), 5);
        assert_eq!(metrics.rtt_samples, vec![500, 600, 700, 800, 900]);
    }

    #[test]
    fn test_dynamic_edge_metrics_congestion() {
        let mut metrics = DynamicEdgeMetrics::new(EdgeIdx::new(0), 1_000_000);

        // Not congested initially
        assert!(!metrics.is_congested(0.85));

        // Congested due to saturation
        metrics.throughput.saturation_ratio = 0.90;
        assert!(metrics.is_congested(0.85));

        // Reset saturation, congested due to RTT trend
        metrics.throughput.saturation_ratio = 0.50;
        metrics.record_rtt(1000);
        metrics.record_rtt(1000);
        metrics.record_rtt(2000);
        metrics.record_rtt(2000);
        assert_eq!(metrics.rtt_trend, RttTrend::Increasing);
        assert!(metrics.is_congested(0.85));
    }

    #[test]
    fn test_dynamic_edge_metrics_queue_depth() {
        let mut metrics = DynamicEdgeMetrics::new(EdgeIdx::new(0), 1_000_000_000);
        assert_eq!(metrics.queue_depth_bytes, 0);

        metrics.update_queue_depth(1_000_000);
        assert_eq!(metrics.queue_depth_bytes, 1_000_000);
    }
}
