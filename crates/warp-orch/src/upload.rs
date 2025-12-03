//! Distributed upload system for pushing data to multiple edges
//!
//! This module provides parallel uploading of chunks to multiple edge nodes with:
//! - Concurrent chunk uploads up to configurable limit
//! - Replication factor for redundancy
//! - Automatic failover to alternative destinations
//! - Progress tracking and verification
//! - Connection pooling for efficient resource usage

use crate::pool::{ConnectionPool, PooledConnection};
use crate::progress::ProgressTracker;
use crate::types::{
    TransferDirection, TransferId, TransferRequest, TransferResult, TransferState, TransferStatus,
};
use crate::{OrchError, Result};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};
use warp_sched::{ChunkId, EdgeIdx};

/// Configuration for distributed uploads
#[derive(Debug, Clone)]
pub struct UploadConfig {
    pub max_concurrent_chunks: usize,
    pub replication_factor: usize,
    pub chunk_timeout_ms: u64,
    pub max_retries: u8,
    pub verify_upload: bool,
}

impl Default for UploadConfig {
    fn default() -> Self {
        Self {
            max_concurrent_chunks: 8,
            replication_factor: 3,
            chunk_timeout_ms: 30000,
            max_retries: 3,
            verify_upload: true,
        }
    }
}

impl UploadConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> Result<()> {
        if self.max_concurrent_chunks == 0 {
            return Err(OrchError::InvalidState(
                "max_concurrent_chunks must be > 0".to_string(),
            ));
        }
        if self.replication_factor == 0 {
            return Err(OrchError::InvalidState(
                "replication_factor must be > 0".to_string(),
            ));
        }
        Ok(())
    }

    pub fn with_max_concurrent_chunks(mut self, max: usize) -> Self {
        self.max_concurrent_chunks = max;
        self
    }

    pub fn with_replication_factor(mut self, factor: usize) -> Self {
        self.replication_factor = factor;
        self
    }

    pub fn with_chunk_timeout_ms(mut self, timeout: u64) -> Self {
        self.chunk_timeout_ms = timeout;
        self
    }

    pub fn with_max_retries(mut self, retries: u8) -> Self {
        self.max_retries = retries;
        self
    }

    pub fn with_verify_upload(mut self, verify: bool) -> Self {
        self.verify_upload = verify;
        self
    }
}

/// Tracks a single chunk being uploaded to potentially multiple destinations
#[derive(Debug, Clone)]
pub struct ActiveChunkUpload {
    pub chunk_id: ChunkId,
    pub chunk_hash: [u8; 32],
    pub chunk_size: u32,
    pub chunk_data: Option<Vec<u8>>,
    pub destinations: Vec<EdgeIdx>,
    pub successful_destinations: Vec<EdgeIdx>,
    pub failed_destinations: Vec<EdgeIdx>,
    pub bytes_sent: u64,
    pub started_at_ms: u64,
    pub retries: u8,
}

impl ActiveChunkUpload {
    pub fn new(
        chunk_id: ChunkId,
        chunk_hash: [u8; 32],
        chunk_size: u32,
        destinations: Vec<EdgeIdx>,
    ) -> Self {
        Self {
            chunk_id,
            chunk_hash,
            chunk_size,
            chunk_data: None,
            destinations,
            successful_destinations: Vec::new(),
            failed_destinations: Vec::new(),
            bytes_sent: 0,
            started_at_ms: current_time_ms(),
            retries: 0,
        }
    }

    pub fn is_complete(&self) -> bool {
        self.successful_destinations.len() >= self.destinations.len()
    }

    pub fn has_remaining_destinations(&self) -> bool {
        self.successful_destinations.len() < self.destinations.len()
    }

    pub fn next_destination(&self) -> Option<EdgeIdx> {
        for dest in &self.destinations {
            if !self.successful_destinations.contains(dest)
                && !self.failed_destinations.contains(dest)
            {
                return Some(*dest);
            }
        }
        None
    }

    pub fn mark_success(&mut self, edge: EdgeIdx) {
        if !self.successful_destinations.contains(&edge) {
            self.successful_destinations.push(edge);
        }
    }

    pub fn mark_failed(&mut self, edge: EdgeIdx) {
        if !self.failed_destinations.contains(&edge) {
            self.failed_destinations.push(edge);
        }
    }

    pub fn is_timed_out(&self, timeout_ms: u64) -> bool {
        let now = current_time_ms();
        now - self.started_at_ms > timeout_ms
    }

    pub fn can_retry(&self, max_retries: u8) -> bool {
        self.retries < max_retries
    }

    pub fn increment_retry(&mut self) {
        self.retries += 1;
    }
}

/// Chunk metadata for uploads (hash and size)
#[derive(Debug, Clone, Copy)]
pub struct ChunkMeta {
    pub hash: [u8; 32],
    pub size: u32,
}

/// Active upload session tracking in-progress upload
#[derive(Debug, Clone)]
pub struct UploadSession {
    pub transfer_id: TransferId,
    pub state: TransferState,
    pub active_chunks: HashMap<ChunkId, ActiveChunkUpload>,
    pub pending_chunks: VecDeque<ChunkId>,
    pub completed_chunks: HashSet<ChunkId>,
    /// Chunk metadata indexed by chunk ID
    pub chunk_metadata: HashMap<ChunkId, ChunkMeta>,
    /// Destinations for each chunk
    pub destinations: HashMap<ChunkId, Vec<EdgeIdx>>,
}

impl UploadSession {
    pub fn new(transfer_id: TransferId, state: TransferState) -> Self {
        Self {
            transfer_id,
            state,
            active_chunks: HashMap::new(),
            pending_chunks: VecDeque::new(),
            completed_chunks: HashSet::new(),
            chunk_metadata: HashMap::new(),
            destinations: HashMap::new(),
        }
    }

    pub fn is_complete(&self) -> bool {
        self.pending_chunks.is_empty()
            && self.active_chunks.is_empty()
            && !self.completed_chunks.is_empty()
    }

    pub fn has_pending_work(&self) -> bool {
        !self.pending_chunks.is_empty() || !self.active_chunks.is_empty()
    }

    pub fn total_chunks(&self) -> usize {
        self.state.total_chunks
    }

    pub fn progress_percent(&self) -> f64 {
        if self.total_chunks() == 0 {
            return 100.0;
        }
        (self.completed_chunks.len() as f64 / self.total_chunks() as f64 * 100.0).min(100.0)
    }
}

/// Main distributed uploader - coordinates parallel uploads to multiple edges
pub struct DistributedUploader {
    config: UploadConfig,
    pool: ConnectionPool,
    progress: ProgressTracker,
}

impl DistributedUploader {
    pub fn new(config: UploadConfig, pool: ConnectionPool, progress: ProgressTracker) -> Self {
        Self {
            config,
            pool,
            progress,
        }
    }

    /// Start a new upload session
    pub async fn start(
        &self,
        request: TransferRequest,
        destinations: HashMap<ChunkId, Vec<EdgeIdx>>,
    ) -> Result<UploadSession> {
        self.config.validate()?;
        request
            .validate()
            .map_err(|e| OrchError::InvalidState(e))?;

        if request.direction != TransferDirection::Upload {
            return Err(OrchError::InvalidState(
                "Request must be for upload".to_string(),
            ));
        }

        if request.chunks.is_empty() {
            return Err(OrchError::InvalidState("No chunks to upload".to_string()));
        }

        let transfer_id = TransferId::new(current_time_ms());
        let chunk_states = Vec::new();
        let now = current_time_ms();

        let mut state = TransferState::new(transfer_id, TransferDirection::Upload, chunk_states, now);
        state.start(now);

        let mut session = UploadSession::new(transfer_id, state);

        // Store destinations mapping
        session.destinations = destinations;

        // Queue all chunks and store metadata
        for (idx, chunk_hash) in request.chunks.iter().enumerate() {
            let chunk_id = ChunkId::from_hash(chunk_hash);
            let chunk_size = request.chunk_sizes.get(idx).copied().unwrap_or(0);

            session.chunk_metadata.insert(chunk_id, ChunkMeta {
                hash: *chunk_hash,
                size: chunk_size,
            });
            session.pending_chunks.push_back(chunk_id);
        }

        // Register with progress tracker
        self.progress.register(
            transfer_id,
            request.chunks.len(),
            request.total_bytes(),
        );
        self.progress.start(transfer_id);

        Ok(session)
    }

    /// Queue chunk data for upload
    pub fn queue_chunk(
        &self,
        session: &mut UploadSession,
        chunk_id: ChunkId,
        data: Vec<u8>,
    ) -> Result<()> {
        // Check if chunk is pending
        if !session.pending_chunks.contains(&chunk_id) {
            return Err(OrchError::InvalidState(format!(
                "Chunk {:?} not found in pending queue",
                chunk_id
            )));
        }

        // Store data for later use
        if let Some(active) = session.active_chunks.get_mut(&chunk_id) {
            active.chunk_data = Some(data);
        }

        Ok(())
    }

    /// Process upload for one tick - send chunks to edges
    pub async fn tick(&self, session: &mut UploadSession) -> Result<Vec<ChunkId>> {
        let mut completed_chunks = Vec::new();

        // Start new chunk uploads if we have capacity
        while session.active_chunks.len() < self.config.max_concurrent_chunks
            && !session.pending_chunks.is_empty()
        {
            let chunk_id = session.pending_chunks.pop_front().unwrap();

            // Get chunk metadata from session (populated in start())
            let meta = session.chunk_metadata.get(&chunk_id).copied().unwrap_or(ChunkMeta {
                hash: [0u8; 32],
                size: 0,
            });

            // Get destinations for this chunk, or use default
            let destinations = session.destinations.get(&chunk_id)
                .cloned()
                .unwrap_or_else(|| vec![EdgeIdx::new(0)]);

            let active = ActiveChunkUpload::new(chunk_id, meta.hash, meta.size, destinations);
            session.active_chunks.insert(chunk_id, active);
        }

        // Process active chunks
        let active_chunk_ids: Vec<ChunkId> = session.active_chunks.keys().copied().collect();

        for chunk_id in active_chunk_ids {
            let mut should_complete = false;
            let mut should_retry = false;
            let mut chunk_bytes = 0u64;

            if let Some(active) = session.active_chunks.get_mut(&chunk_id) {
                // Check timeout
                if active.is_timed_out(self.config.chunk_timeout_ms) {
                    if active.can_retry(self.config.max_retries) {
                        active.increment_retry();
                        active.started_at_ms = current_time_ms();
                        should_retry = true;
                    } else {
                        // Max retries exceeded, mark as failed
                        self.progress.record_chunk_failed(session.transfer_id);
                        should_complete = true;
                    }
                }

                // Try to upload to next destination
                if !should_retry && active.has_remaining_destinations() {
                    if let Some(dest) = active.next_destination() {
                        // Simulate upload
                        let upload_result = self.upload_chunk_to_edge(active, dest).await;

                        match upload_result {
                            Ok(bytes) => {
                                active.mark_success(dest);
                                active.bytes_sent += bytes;
                                chunk_bytes = bytes;

                                // Check if we've met replication factor
                                if active.successful_destinations.len()
                                    >= self.config.replication_factor
                                {
                                    should_complete = true;
                                }
                            }
                            Err(_) => {
                                active.mark_failed(dest);
                            }
                        }
                    }
                }

                // Check if chunk is complete or failed
                if active.is_complete()
                    || active.successful_destinations.len() >= self.config.replication_factor
                {
                    should_complete = true;
                }
            }

            // Complete chunk if needed
            if should_complete {
                if let Some(active) = session.active_chunks.remove(&chunk_id) {
                    if active.successful_destinations.len() >= self.config.replication_factor {
                        session.completed_chunks.insert(chunk_id);
                        completed_chunks.push(chunk_id);
                        self.progress
                            .record_chunk_complete(session.transfer_id, chunk_bytes);
                    } else {
                        // Failed to meet replication factor
                        self.progress.record_chunk_failed(session.transfer_id);
                    }
                }
            }
        }

        // Update session state
        if session.is_complete() {
            session.state.status = TransferStatus::Completed;
            self.progress.complete(session.transfer_id);
        }

        Ok(completed_chunks)
    }

    /// Upload chunk data to specific edge
    async fn upload_chunk_to_edge(
        &self,
        chunk: &ActiveChunkUpload,
        edge: EdgeIdx,
    ) -> Result<u64> {
        // Acquire connection from pool
        let conn = self
            .pool
            .acquire(edge)
            .await
            .map_err(|e| OrchError::Pool(e.to_string()))?;

        // Simulate sending data
        let data = chunk.chunk_data.as_ref().map(|d| d.as_slice()).unwrap_or(&[]);
        conn.send(data)
            .map_err(|e| OrchError::Network(e.to_string()))?;

        // Return bytes sent
        Ok(data.len() as u64)
    }

    /// Cancel an upload session
    pub fn cancel(&self, session: &mut UploadSession) {
        session.state.status = TransferStatus::Cancelled;
        session.active_chunks.clear();
        session.pending_chunks.clear();
        self.progress.cancel(session.transfer_id);
    }

    /// Get upload result when complete
    pub fn finalize(&self, session: UploadSession) -> TransferResult {
        let now = current_time_ms();
        TransferResult::from_state(&session.state, now)
    }
}

fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::PoolConfig;

    #[test]
    fn test_upload_config_default_and_validation() {
        let config = UploadConfig::default();
        assert_eq!(config.max_concurrent_chunks, 8);
        assert_eq!(config.replication_factor, 3);
        assert!(config.verify_upload);
        assert!(config.validate().is_ok());

        assert!(UploadConfig { max_concurrent_chunks: 0, ..Default::default() }.validate().is_err());
        assert!(UploadConfig { replication_factor: 0, ..Default::default() }.validate().is_err());
    }

    #[test]
    fn test_upload_session_new() {
        let transfer_id = TransferId::new(1);
        let state = TransferState::new(transfer_id, TransferDirection::Upload, vec![], 1000);
        let session = UploadSession::new(transfer_id, state);

        assert_eq!(session.transfer_id, transfer_id);
        assert!(session.active_chunks.is_empty());
        assert!(session.pending_chunks.is_empty());
        assert!(session.completed_chunks.is_empty());
    }

    #[test]
    fn test_active_chunk_upload_new() {
        let chunk_id = ChunkId::new(1);
        let chunk_hash = [1u8; 32];
        let destinations = vec![EdgeIdx::new(0), EdgeIdx::new(1)];

        let active = ActiveChunkUpload::new(chunk_id, chunk_hash, 1024, destinations.clone());

        assert_eq!(active.chunk_id, chunk_id);
        assert_eq!(active.chunk_hash, chunk_hash);
        assert_eq!(active.chunk_size, 1024);
        assert_eq!(active.destinations, destinations);
        assert!(active.successful_destinations.is_empty());
        assert!(active.failed_destinations.is_empty());
        assert_eq!(active.bytes_sent, 0);
        assert_eq!(active.retries, 0);
    }

    #[test]
    fn test_distributed_uploader_new() {
        let config = UploadConfig::default();
        let pool = ConnectionPool::new(PoolConfig::default()).unwrap();
        let progress = ProgressTracker::new();

        let uploader = DistributedUploader::new(config, pool, progress);
        assert_eq!(uploader.config.max_concurrent_chunks, 8);
    }

    #[tokio::test]
    async fn test_start_upload_empty_request() {
        let config = UploadConfig::default();
        let pool = ConnectionPool::new(PoolConfig::default()).unwrap();
        let progress = ProgressTracker::new();
        let uploader = DistributedUploader::new(config, pool, progress);

        let request = TransferRequest::new(vec![], vec![], TransferDirection::Upload);
        let destinations = HashMap::new();

        let result = uploader.start(request, destinations).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_start_upload_valid_request() {
        let config = UploadConfig::default();
        let pool = ConnectionPool::new(PoolConfig::default()).unwrap();
        let progress = ProgressTracker::new();
        let uploader = DistributedUploader::new(config, pool, progress);

        let chunks = vec![[1u8; 32], [2u8; 32]];
        let sizes = vec![1024, 2048];
        let request = TransferRequest::new(chunks.clone(), sizes, TransferDirection::Upload);
        let destinations = HashMap::new();

        let result = uploader.start(request, destinations).await;
        assert!(result.is_ok());

        let session = result.unwrap();
        assert_eq!(session.pending_chunks.len(), 2);
    }

    #[tokio::test]
    async fn test_queue_chunk_valid() {
        let config = UploadConfig::default();
        let pool = ConnectionPool::new(PoolConfig::default()).unwrap();
        let progress = ProgressTracker::new();
        let uploader = DistributedUploader::new(config, pool, progress);

        let chunks = vec![[1u8; 32]];
        let sizes = vec![1024];
        let request = TransferRequest::new(chunks.clone(), sizes, TransferDirection::Upload);
        let destinations = HashMap::new();

        let mut session = uploader.start(request, destinations).await.unwrap();
        let chunk_id = ChunkId::from_hash(&chunks[0]);

        // Create active chunk first
        let active = ActiveChunkUpload::new(chunk_id, chunks[0], 1024, vec![EdgeIdx::new(0)]);
        session.active_chunks.insert(chunk_id, active);

        let data = vec![1, 2, 3, 4];
        let result = uploader.queue_chunk(&mut session, chunk_id, data);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_queue_chunk_invalid_id() {
        let config = UploadConfig::default();
        let pool = ConnectionPool::new(PoolConfig::default()).unwrap();
        let progress = ProgressTracker::new();
        let uploader = DistributedUploader::new(config, pool, progress);

        let chunks = vec![[1u8; 32]];
        let sizes = vec![1024];
        let request = TransferRequest::new(chunks, sizes, TransferDirection::Upload);
        let destinations = HashMap::new();

        let mut session = uploader.start(request, destinations).await.unwrap();
        let invalid_chunk = ChunkId::new(999);

        let data = vec![1, 2, 3, 4];
        let result = uploader.queue_chunk(&mut session, invalid_chunk, data);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_tick_no_pending_chunks() {
        let config = UploadConfig::default();
        let pool = ConnectionPool::new(PoolConfig::default()).unwrap();
        let progress = ProgressTracker::new();
        let uploader = DistributedUploader::new(config, pool, progress);

        let transfer_id = TransferId::new(1);
        let state = TransferState::new(transfer_id, TransferDirection::Upload, vec![], 1000);
        let mut session = UploadSession::new(transfer_id, state);

        let completed = uploader.tick(&mut session).await.unwrap();
        assert!(completed.is_empty());
    }

    #[tokio::test]
    async fn test_tick_uploads_chunk() {
        let config = UploadConfig {
            replication_factor: 1,  // Set replication to 1 so chunk completes immediately
            ..Default::default()
        };
        let pool = ConnectionPool::new(PoolConfig::default()).unwrap();
        let progress = ProgressTracker::new();
        let uploader = DistributedUploader::new(config, pool, progress);

        let chunks = vec![[1u8; 32]];
        let sizes = vec![1024];
        let request = TransferRequest::new(chunks, sizes, TransferDirection::Upload);
        let destinations = HashMap::new();

        let mut session = uploader.start(request, destinations).await.unwrap();

        // First tick should start and complete the upload (replication factor 1)
        let completed = uploader.tick(&mut session).await.unwrap();
        assert_eq!(session.active_chunks.len(), 0);
        assert_eq!(completed.len(), 1);
    }

    #[tokio::test]
    async fn test_tick_multiple_chunks() {
        let config = UploadConfig {
            replication_factor: 1,  // Set replication to 1 so chunks complete immediately
            ..Default::default()
        };
        let pool = ConnectionPool::new(PoolConfig::default()).unwrap();
        let progress = ProgressTracker::new();
        let uploader = DistributedUploader::new(config, pool, progress);

        let chunks = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let sizes = vec![1024, 2048, 512];
        let request = TransferRequest::new(chunks, sizes, TransferDirection::Upload);
        let destinations = HashMap::new();

        let mut session = uploader.start(request, destinations).await.unwrap();

        // First tick should process all 3 chunks
        let completed = uploader.tick(&mut session).await.unwrap();
        assert_eq!(completed.len(), 3);
        assert_eq!(session.completed_chunks.len(), 3);
    }

    #[tokio::test]
    async fn test_chunk_completion_updates_progress() {
        let config = UploadConfig::default();
        let pool = ConnectionPool::new(PoolConfig::default()).unwrap();
        let progress = ProgressTracker::new();
        let uploader = DistributedUploader::new(config, pool, progress.clone());

        let chunks = vec![[1u8; 32]];
        let sizes = vec![1024];
        let request = TransferRequest::new(chunks, sizes, TransferDirection::Upload);
        let destinations = HashMap::new();

        let session = uploader.start(request, destinations).await.unwrap();

        // Check progress was registered
        let transfer_progress = progress.get_progress(session.transfer_id);
        assert!(transfer_progress.is_some());
    }

    #[test]
    fn test_chunk_retries() {
        let mut active = ActiveChunkUpload::new(ChunkId::new(1), [0u8; 32], 1024, vec![EdgeIdx::new(0)]);
        assert_eq!(active.retries, 0);
        assert!(active.can_retry(3));

        active.increment_retry();
        assert_eq!(active.retries, 1);

        for _ in 0..4 { active.increment_retry(); }
        assert_eq!(active.retries, 5);
        assert!(!active.can_retry(3));
    }

    #[test]
    fn test_replication_factor() {
        let chunk_id = ChunkId::new(1);
        let destinations = vec![EdgeIdx::new(0), EdgeIdx::new(1), EdgeIdx::new(2)];
        let mut active = ActiveChunkUpload::new(chunk_id, [0u8; 32], 1024, destinations);

        assert!(!active.is_complete());

        active.mark_success(EdgeIdx::new(0));
        assert!(!active.is_complete());

        active.mark_success(EdgeIdx::new(1));
        assert!(!active.is_complete());

        active.mark_success(EdgeIdx::new(2));
        assert!(active.is_complete());
    }

    #[tokio::test]
    async fn test_cancel_upload() {
        let config = UploadConfig::default();
        let pool = ConnectionPool::new(PoolConfig::default()).unwrap();
        let progress = ProgressTracker::new();
        let uploader = DistributedUploader::new(config, pool, progress);

        let chunks = vec![[1u8; 32], [2u8; 32]];
        let sizes = vec![1024, 2048];
        let request = TransferRequest::new(chunks, sizes, TransferDirection::Upload);
        let destinations = HashMap::new();

        let mut session = uploader.start(request, destinations).await.unwrap();

        uploader.cancel(&mut session);

        assert_eq!(session.state.status, TransferStatus::Cancelled);
        assert!(session.active_chunks.is_empty());
        assert!(session.pending_chunks.is_empty());
    }

    #[tokio::test]
    async fn test_finalize_uploads() {
        let uploader = DistributedUploader::new(
            UploadConfig::default(),
            ConnectionPool::new(PoolConfig::default()).unwrap(),
            ProgressTracker::new(),
        );

        let mut session = uploader.start(
            TransferRequest::new(vec![[1u8; 32]], vec![1024], TransferDirection::Upload),
            HashMap::new()
        ).await.unwrap();
        session.state.status = TransferStatus::Completed;
        assert!(uploader.finalize(session).success);

        let mut session = uploader.start(
            TransferRequest::new(vec![[2u8; 32]], vec![2048], TransferDirection::Upload),
            HashMap::new()
        ).await.unwrap();
        session.state.status = TransferStatus::Failed { reason: "test".to_string() };
        assert!(!uploader.finalize(session).success);
    }

    #[test]
    fn test_destination_selection() {
        let chunk_id = ChunkId::new(1);
        let destinations = vec![EdgeIdx::new(0), EdgeIdx::new(1), EdgeIdx::new(2)];
        let mut active = ActiveChunkUpload::new(chunk_id, [0u8; 32], 1024, destinations);

        let next = active.next_destination();
        assert_eq!(next, Some(EdgeIdx::new(0)));

        active.mark_success(EdgeIdx::new(0));
        let next = active.next_destination();
        assert_eq!(next, Some(EdgeIdx::new(1)));

        active.mark_failed(EdgeIdx::new(1));
        let next = active.next_destination();
        assert_eq!(next, Some(EdgeIdx::new(2)));

        active.mark_success(EdgeIdx::new(2));
        let next = active.next_destination();
        assert!(next.is_none());
    }

    #[test]
    fn test_state_and_results() {
        let mut state = TransferState::new(TransferId::new(1), TransferDirection::Upload, vec![], 1000);
        assert_eq!(state.status, TransferStatus::Pending);
        state.start(2000);
        assert_eq!(state.status, TransferStatus::Active);
        state.transferred_bytes = 5000;
        state.complete(3000);
        assert_eq!(state.status, TransferStatus::Completed);

        let result = TransferResult::from_state(&state, 3000);
        assert_eq!(result.bytes_transferred, 5000);
        assert_eq!(result.duration_ms, 1000);
    }

    #[test]
    fn test_active_chunk_completion() {
        let destinations = vec![EdgeIdx::new(0), EdgeIdx::new(1)];
        let mut active = ActiveChunkUpload::new(ChunkId::new(1), [0u8; 32], 1024, destinations);

        assert!(!active.is_complete());
        assert!(active.has_remaining_destinations());

        active.mark_success(EdgeIdx::new(0));
        assert!(!active.is_complete());
        assert!(active.has_remaining_destinations());

        active.mark_success(EdgeIdx::new(1));
        assert!(active.is_complete());
        assert!(!active.has_remaining_destinations());
    }

    #[test]
    fn test_upload_session_states() {
        let mut session = UploadSession::new(
            TransferId::new(1),
            TransferState::new(TransferId::new(1), TransferDirection::Upload, vec![], 1000)
        );

        assert!(!session.is_complete());
        assert!(!session.has_pending_work());

        session.pending_chunks.push_back(ChunkId::new(1));
        assert!(session.has_pending_work());

        session.pending_chunks.clear();
        session.active_chunks.insert(ChunkId::new(2), ActiveChunkUpload::new(ChunkId::new(2), [0u8; 32], 1024, vec![]));
        assert!(session.has_pending_work());

        session.active_chunks.clear();
        session.completed_chunks.insert(ChunkId::new(1));
        assert!(session.is_complete());
    }

    #[test]
    fn test_upload_session_progress_percent() {
        let transfer_id = TransferId::new(1);
        let mut state = TransferState::new(transfer_id, TransferDirection::Upload, vec![], 1000);
        state.total_chunks = 10;

        let mut session = UploadSession::new(transfer_id, state);

        assert_eq!(session.progress_percent(), 0.0);

        for i in 0..5 {
            session.completed_chunks.insert(ChunkId::new(i));
        }
        assert_eq!(session.progress_percent(), 50.0);

        for i in 5..10 {
            session.completed_chunks.insert(ChunkId::new(i));
        }
        assert_eq!(session.progress_percent(), 100.0);
    }

    #[test]
    fn test_active_chunk_timeout() {
        let chunk_id = ChunkId::new(1);
        let mut active = ActiveChunkUpload::new(chunk_id, [0u8; 32], 1024, vec![]);

        // Set started time in the past
        active.started_at_ms = current_time_ms() - 60000;

        assert!(active.is_timed_out(30000));
        assert!(!active.is_timed_out(100000));
    }

    #[test]
    fn test_config_builders() {
        let config = UploadConfig::new()
            .with_max_concurrent_chunks(16)
            .with_replication_factor(5)
            .with_chunk_timeout_ms(60000)
            .with_max_retries(5)
            .with_verify_upload(false);

        assert_eq!(config.max_concurrent_chunks, 16);
        assert_eq!(config.replication_factor, 5);
        assert_eq!(config.chunk_timeout_ms, 60000);
        assert_eq!(config.max_retries, 5);
        assert!(!config.verify_upload);
    }

    #[tokio::test]
    async fn test_upload_with_replication() {
        let config = UploadConfig {
            replication_factor: 2,
            ..Default::default()
        };
        let pool = ConnectionPool::new(PoolConfig::default()).unwrap();
        let progress = ProgressTracker::new();
        let _uploader = DistributedUploader::new(config, pool, progress);

        let chunk_id = ChunkId::new(1);
        let destinations = vec![EdgeIdx::new(0), EdgeIdx::new(1), EdgeIdx::new(2)];
        let mut active = ActiveChunkUpload::new(chunk_id, [0u8; 32], 1024, destinations);

        // Mark two successful - should meet replication factor of 2
        active.mark_success(EdgeIdx::new(0));
        active.mark_success(EdgeIdx::new(1));

        assert!(active.successful_destinations.len() >= 2);
    }

    #[test]
    fn test_current_time_ms() {
        let time1 = current_time_ms();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let time2 = current_time_ms();

        assert!(time2 > time1);
        assert!(time2 - time1 >= 10);
    }

    #[tokio::test]
    async fn test_start_with_wrong_direction() {
        let config = UploadConfig::default();
        let pool = ConnectionPool::new(PoolConfig::default()).unwrap();
        let progress = ProgressTracker::new();
        let uploader = DistributedUploader::new(config, pool, progress);

        let request = TransferRequest::new(vec![[1u8; 32]], vec![1024], TransferDirection::Download);
        let destinations = HashMap::new();

        let result = uploader.start(request, destinations).await;
        assert!(result.is_err());
    }
}
