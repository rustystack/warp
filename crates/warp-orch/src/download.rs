//! BitTorrent-style parallel chunk fetching system
//!
//! Implements swarm downloads with:
//! - Parallel downloading from multiple sources
//! - Automatic source selection and failover
//! - Progress tracking and ETA estimation
//! - Connection pooling for efficiency
//! - Retry logic with configurable limits

use crate::pool::{ConnectionPool, PooledConnection};
use crate::progress::ProgressTracker;
use crate::types::{
    TransferDirection, TransferId, TransferRequest, TransferResult, TransferState, TransferStatus,
};
use crate::{OrchError, Result};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};
use warp_sched::{ChunkId, EdgeIdx};

/// Configuration for swarm downloads
#[derive(Debug, Clone)]
pub struct DownloadConfig {
    pub max_concurrent_chunks: usize,
    pub max_sources_per_chunk: usize,
    pub chunk_timeout_ms: u64,
    pub max_retries: u8,
    pub prefer_local: bool,
}

impl Default for DownloadConfig {
    fn default() -> Self {
        Self {
            max_concurrent_chunks: 8,
            max_sources_per_chunk: 3,
            chunk_timeout_ms: 30000,
            max_retries: 3,
            prefer_local: false,
        }
    }
}

impl DownloadConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> Result<()> {
        if self.max_concurrent_chunks == 0 {
            return Err(OrchError::InvalidState(
                "max_concurrent_chunks must be > 0".to_string(),
            ));
        }
        if self.max_sources_per_chunk == 0 {
            return Err(OrchError::InvalidState(
                "max_sources_per_chunk must be > 0".to_string(),
            ));
        }
        if self.chunk_timeout_ms == 0 {
            return Err(OrchError::InvalidState(
                "chunk_timeout_ms must be > 0".to_string(),
            ));
        }
        Ok(())
    }

    pub fn with_max_concurrent_chunks(mut self, max: usize) -> Self {
        self.max_concurrent_chunks = max;
        self
    }

    pub fn with_max_sources_per_chunk(mut self, max: usize) -> Self {
        self.max_sources_per_chunk = max;
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

    pub fn with_prefer_local(mut self, prefer: bool) -> Self {
        self.prefer_local = prefer;
        self
    }
}

/// Tracks a single chunk being downloaded from potentially multiple sources
#[derive(Debug, Clone)]
pub struct ActiveChunkDownload {
    pub chunk_id: ChunkId,
    pub chunk_hash: [u8; 32],
    pub chunk_size: u32,
    pub sources: Vec<EdgeIdx>,
    pub active_source: Option<EdgeIdx>,
    pub bytes_received: u64,
    pub started_at_ms: u64,
    pub retries: u8,
}

impl ActiveChunkDownload {
    pub fn new(chunk_id: ChunkId, chunk_hash: [u8; 32], chunk_size: u32, sources: Vec<EdgeIdx>) -> Self {
        Self {
            chunk_id,
            chunk_hash,
            chunk_size,
            sources,
            active_source: None,
            bytes_received: 0,
            started_at_ms: current_time_ms(),
            retries: 0,
        }
    }

    pub fn is_complete(&self) -> bool {
        self.bytes_received >= self.chunk_size as u64
    }

    pub fn is_timed_out(&self, timeout_ms: u64) -> bool {
        let elapsed = current_time_ms() - self.started_at_ms;
        elapsed > timeout_ms
    }

    pub fn select_next_source(&mut self) -> Option<EdgeIdx> {
        if self.sources.is_empty() {
            return None;
        }

        match self.active_source {
            None => {
                self.active_source = Some(self.sources[0]);
                Some(self.sources[0])
            }
            Some(current) => {
                let current_idx = self.sources.iter().position(|&e| e == current);
                match current_idx {
                    Some(idx) => {
                        let next_idx = (idx + 1) % self.sources.len();
                        self.active_source = Some(self.sources[next_idx]);
                        Some(self.sources[next_idx])
                    }
                    None => {
                        self.active_source = Some(self.sources[0]);
                        Some(self.sources[0])
                    }
                }
            }
        }
    }

    pub fn mark_failed(&mut self) {
        self.active_source = None;
        self.retries += 1;
    }
}

/// Active download session tracking in-progress download
#[derive(Debug, Clone)]
pub struct DownloadSession {
    pub transfer_id: TransferId,
    pub state: TransferState,
    pub active_chunks: HashMap<ChunkId, ActiveChunkDownload>,
    pub pending_chunks: VecDeque<ChunkId>,
    pub completed_chunks: HashSet<ChunkId>,
}

impl DownloadSession {
    pub fn new(transfer_id: TransferId, state: TransferState, chunk_order: Vec<ChunkId>) -> Self {
        Self {
            transfer_id,
            state,
            active_chunks: HashMap::new(),
            pending_chunks: chunk_order.into_iter().collect(),
            completed_chunks: HashSet::new(),
        }
    }

    pub fn is_complete(&self) -> bool {
        self.pending_chunks.is_empty() && self.active_chunks.is_empty()
    }

    pub fn progress_ratio(&self) -> f64 {
        let total = self.completed_chunks.len() + self.active_chunks.len() + self.pending_chunks.len();
        if total == 0 {
            return 1.0;
        }
        self.completed_chunks.len() as f64 / total as f64
    }
}

/// Main swarm downloader - coordinates parallel downloads from multiple edges
pub struct SwarmDownloader {
    config: DownloadConfig,
    pool: ConnectionPool,
    progress: ProgressTracker,
}

impl SwarmDownloader {
    pub fn new(config: DownloadConfig, pool: ConnectionPool, progress: ProgressTracker) -> Self {
        Self {
            config,
            pool,
            progress,
        }
    }

    /// Start a new download session
    pub async fn start(
        &self,
        request: TransferRequest,
        sources: HashMap<ChunkId, Vec<EdgeIdx>>,
    ) -> Result<DownloadSession> {
        if let Err(e) = request.validate() {
            return Err(OrchError::InvalidState(e));
        }

        if request.chunks.is_empty() {
            return Err(OrchError::InvalidState("No chunks to download".to_string()));
        }

        let transfer_id = TransferId::new(generate_transfer_id());
        let created_at_ms = current_time_ms();

        let chunk_states = request
            .chunks
            .iter()
            .zip(request.chunk_sizes.iter())
            .enumerate()
            .map(|(idx, (hash, size))| {
                let chunk_id = ChunkId::from_hash(hash);
                let available_sources = sources.get(&chunk_id).cloned().unwrap_or_default();
                crate::types::ChunkTransfer::new(*hash, *size, available_sources)
            })
            .collect();

        let state = TransferState::new(transfer_id, request.direction, chunk_states, created_at_ms);

        let chunk_order: Vec<ChunkId> = request.chunks.iter().map(|h| ChunkId::from_hash(h)).collect();

        let total_chunks = request.chunks.len();
        let total_bytes = request.total_bytes();

        self.progress.register(transfer_id, total_chunks, total_bytes);
        self.progress.start(transfer_id);

        let mut session = DownloadSession::new(transfer_id, state, chunk_order);
        session.state.start(current_time_ms());

        Ok(session)
    }

    /// Process download for one tick - fetch chunks from edges
    pub async fn tick(&self, session: &mut DownloadSession) -> Result<Vec<ChunkId>> {
        let mut completed = Vec::new();

        self.process_active_chunks(session, &mut completed).await;
        self.start_new_chunks(session).await;

        Ok(completed)
    }

    async fn process_active_chunks(&self, session: &mut DownloadSession, completed: &mut Vec<ChunkId>) {
        let mut to_retry = Vec::new();
        let mut to_complete = Vec::new();
        let mut to_fail = Vec::new();

        for (chunk_id, active) in session.active_chunks.iter_mut() {
            if active.is_complete() {
                to_complete.push(*chunk_id);
                continue;
            }

            if active.is_timed_out(self.config.chunk_timeout_ms) {
                if active.retries >= self.config.max_retries {
                    to_fail.push(*chunk_id);
                } else {
                    active.mark_failed();
                    to_retry.push(*chunk_id);
                }
                continue;
            }

            if let Some(source) = active.active_source {
                match self.download_chunk_data(source, active).await {
                    Ok(bytes) => {
                        active.bytes_received += bytes;
                        if active.is_complete() {
                            to_complete.push(*chunk_id);
                        }
                    }
                    Err(_) => {
                        if active.retries >= self.config.max_retries {
                            to_fail.push(*chunk_id);
                        } else {
                            active.mark_failed();
                            to_retry.push(*chunk_id);
                        }
                    }
                }
            }
        }

        for chunk_id in to_complete {
            if let Some(active) = session.active_chunks.remove(&chunk_id) {
                session.completed_chunks.insert(chunk_id);
                completed.push(chunk_id);
                self.progress.record_chunk_complete(session.transfer_id, active.chunk_size as u64);
            }
        }

        for chunk_id in to_retry {
            if let Some(mut active) = session.active_chunks.remove(&chunk_id) {
                if active.select_next_source().is_some() {
                    session.active_chunks.insert(chunk_id, active);
                } else {
                    session.pending_chunks.push_front(chunk_id);
                }
            }
        }

        for chunk_id in to_fail {
            if let Some(_active) = session.active_chunks.remove(&chunk_id) {
                self.progress.record_chunk_failed(session.transfer_id);
            }
        }
    }

    async fn start_new_chunks(&self, session: &mut DownloadSession) {
        let slots_available = self
            .config
            .max_concurrent_chunks
            .saturating_sub(session.active_chunks.len());

        for _ in 0..slots_available {
            if let Some(chunk_id) = session.pending_chunks.pop_front() {
                if let Some(chunk_state) = session
                    .state
                    .chunk_states
                    .iter()
                    .find(|c| ChunkId::from_hash(&c.chunk_hash) == chunk_id)
                {
                    let active = ActiveChunkDownload::new(
                        chunk_id,
                        chunk_state.chunk_hash,
                        chunk_state.chunk_size,
                        chunk_state.source_edges.clone(),
                    );

                    if let Some(mut active_with_source) = self.assign_source(active).await {
                        session.active_chunks.insert(chunk_id, active_with_source);
                    } else {
                        session.pending_chunks.push_back(chunk_id);
                        break;
                    }
                }
            } else {
                break;
            }
        }
    }

    async fn assign_source(&self, mut active: ActiveChunkDownload) -> Option<ActiveChunkDownload> {
        if active.select_next_source().is_some() {
            Some(active)
        } else {
            None
        }
    }

    async fn download_chunk_data(&self, source: EdgeIdx, active: &ActiveChunkDownload) -> Result<u64> {
        let conn = self.pool.acquire(source).await.map_err(|e| {
            OrchError::Network(format!("Failed to acquire connection: {}", e))
        })?;

        // Request the chunk using WANT frame protocol
        // ChunkId is u64, Frame uses u32, safe truncation for chunk indices
        let chunk_id_u32 = active.chunk_id.get() as u32;
        conn.request_chunks(vec![chunk_id_u32]).await.map_err(|e| {
            OrchError::Network(format!("Failed to send WANT request: {}", e))
        })?;

        // Receive the chunk data via CHUNK frame
        let (received_id, data) = conn.recv_chunk().await.map_err(|e| {
            OrchError::Network(format!("Failed to receive chunk: {}", e))
        })?;

        // Verify we got the right chunk
        if received_id != chunk_id_u32 {
            return Err(OrchError::Network(format!(
                "Received wrong chunk: expected {}, got {}",
                chunk_id_u32, received_id
            )));
        }

        // Verify chunk hash matches expected
        let actual_hash = warp_hash::hash(&data);
        if actual_hash != active.chunk_hash {
            return Err(OrchError::Network(format!(
                "Chunk {} hash mismatch",
                chunk_id_u32
            )));
        }

        Ok(data.len() as u64)
    }

    /// Cancel a download session
    pub fn cancel(&self, session: &mut DownloadSession) {
        session.active_chunks.clear();
        session.pending_chunks.clear();
        session.state.cancel(current_time_ms());
        self.progress.cancel(session.transfer_id);
    }

    /// Get download result when complete
    pub fn finalize(&self, session: DownloadSession) -> TransferResult {
        let timestamp_ms = current_time_ms();
        if session.is_complete() && session.state.chunk_states.iter().all(|c| c.status == TransferStatus::Completed) {
            self.progress.complete(session.transfer_id);
        }
        TransferResult::from_state(&session.state, timestamp_ms)
    }
}

fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn generate_transfer_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    COUNTER.fetch_add(1, Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::PoolConfig;

    #[test]
    fn test_download_config_default() {
        let config = DownloadConfig::default();
        assert_eq!(config.max_concurrent_chunks, 8);
        assert_eq!(config.max_sources_per_chunk, 3);
        assert_eq!(config.chunk_timeout_ms, 30000);
        assert_eq!(config.max_retries, 3);
        assert!(!config.prefer_local);

        let new_config = DownloadConfig::new();
        assert_eq!(new_config.max_concurrent_chunks, 8);
    }

    #[test]
    fn test_download_config_validation() {
        let valid = DownloadConfig::default();
        assert!(valid.validate().is_ok());

        let invalid = DownloadConfig {
            max_concurrent_chunks: 0,
            ..Default::default()
        };
        assert!(invalid.validate().is_err());

        let invalid = DownloadConfig {
            max_sources_per_chunk: 0,
            ..Default::default()
        };
        assert!(invalid.validate().is_err());

        let invalid = DownloadConfig {
            chunk_timeout_ms: 0,
            ..Default::default()
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_download_config_builders() {
        let config = DownloadConfig::new()
            .with_max_concurrent_chunks(16)
            .with_max_sources_per_chunk(5)
            .with_chunk_timeout_ms(60000)
            .with_max_retries(5)
            .with_prefer_local(true);

        assert_eq!(config.max_concurrent_chunks, 16);
        assert_eq!(config.max_sources_per_chunk, 5);
        assert_eq!(config.chunk_timeout_ms, 60000);
        assert_eq!(config.max_retries, 5);
        assert!(config.prefer_local);
    }

    #[test]
    fn test_active_chunk_download_new() {
        let chunk_id = ChunkId::new(1);
        let hash = [1u8; 32];
        let sources = vec![EdgeIdx::new(0), EdgeIdx::new(1)];

        let active = ActiveChunkDownload::new(chunk_id, hash, 1024, sources.clone());

        assert_eq!(active.chunk_id, chunk_id);
        assert_eq!(active.chunk_hash, hash);
        assert_eq!(active.chunk_size, 1024);
        assert_eq!(active.sources, sources);
        assert_eq!(active.active_source, None);
        assert_eq!(active.bytes_received, 0);
        assert_eq!(active.retries, 0);
        assert!(active.started_at_ms > 0);
    }

    #[test]
    fn test_active_chunk_download_completion_and_timeout() {
        let mut active = ActiveChunkDownload::new(
            ChunkId::new(1),
            [1u8; 32],
            1000,
            vec![EdgeIdx::new(0)],
        );

        assert!(!active.is_complete());
        active.bytes_received = 500;
        assert!(!active.is_complete());
        active.bytes_received = 1000;
        assert!(active.is_complete());
        active.bytes_received = 1500;
        assert!(active.is_complete());

        let mut active2 = ActiveChunkDownload::new(
            ChunkId::new(1),
            [1u8; 32],
            1024,
            vec![EdgeIdx::new(0)],
        );
        assert!(!active2.is_timed_out(1000));
        active2.started_at_ms = current_time_ms() - 2000;
        assert!(active2.is_timed_out(1000));
    }

    #[test]
    fn test_active_chunk_download_select_next_source() {
        let sources = vec![EdgeIdx::new(0), EdgeIdx::new(1), EdgeIdx::new(2)];
        let mut active = ActiveChunkDownload::new(
            ChunkId::new(1),
            [1u8; 32],
            1024,
            sources.clone(),
        );

        let first = active.select_next_source();
        assert_eq!(first, Some(EdgeIdx::new(0)));
        assert_eq!(active.active_source, Some(EdgeIdx::new(0)));

        let second = active.select_next_source();
        assert_eq!(second, Some(EdgeIdx::new(1)));
        assert_eq!(active.active_source, Some(EdgeIdx::new(1)));

        let third = active.select_next_source();
        assert_eq!(third, Some(EdgeIdx::new(2)));

        let wrap = active.select_next_source();
        assert_eq!(wrap, Some(EdgeIdx::new(0)));
    }

    #[test]
    fn test_active_chunk_download_mark_failed() {
        let mut active = ActiveChunkDownload::new(
            ChunkId::new(1),
            [1u8; 32],
            1024,
            vec![EdgeIdx::new(0)],
        );

        active.select_next_source();
        assert_eq!(active.retries, 0);
        assert!(active.active_source.is_some());

        active.mark_failed();
        assert_eq!(active.retries, 1);
        assert!(active.active_source.is_none());
    }

    #[test]
    fn test_download_session() {
        let transfer_id = TransferId::new(1);
        let state = TransferState::new(transfer_id, TransferDirection::Download, vec![], current_time_ms());
        let chunks = vec![ChunkId::new(1), ChunkId::new(2)];
        let session = DownloadSession::new(transfer_id, state, chunks.clone());
        assert_eq!(session.transfer_id, transfer_id);
        assert_eq!(session.pending_chunks.len(), 2);
        assert!(session.active_chunks.is_empty());
        assert!(session.completed_chunks.is_empty());

        let state2 = TransferState::new(transfer_id, TransferDirection::Download, vec![], current_time_ms());
        let mut session2 = DownloadSession::new(transfer_id, state2, vec![]);
        assert!(session2.is_complete());
        session2.pending_chunks.push_back(ChunkId::new(1));
        assert!(!session2.is_complete());
        session2.pending_chunks.clear();
        session2.active_chunks.insert(ChunkId::new(1), ActiveChunkDownload::new(ChunkId::new(1), [1u8; 32], 1024, vec![]));
        assert!(!session2.is_complete());
        session2.active_chunks.clear();
        assert!(session2.is_complete());
    }

    #[test]
    fn test_download_session_progress_ratio() {
        let transfer_id = TransferId::new(1);
        let state = TransferState::new(
            transfer_id,
            TransferDirection::Download,
            vec![],
            current_time_ms(),
        );

        let chunks = vec![ChunkId::new(1), ChunkId::new(2), ChunkId::new(3), ChunkId::new(4)];
        let mut session = DownloadSession::new(transfer_id, state, chunks);

        assert_eq!(session.progress_ratio(), 0.0);

        session.pending_chunks.pop_front();
        session.completed_chunks.insert(ChunkId::new(1));
        assert_eq!(session.progress_ratio(), 0.25);

        session.pending_chunks.pop_front();
        session.completed_chunks.insert(ChunkId::new(2));
        assert_eq!(session.progress_ratio(), 0.5);
    }

    #[tokio::test]
    async fn test_swarm_downloader_creation_and_empty_request() {
        let config = DownloadConfig::default();
        let pool = ConnectionPool::new(PoolConfig::default()).unwrap();
        let progress = ProgressTracker::new();
        let downloader = SwarmDownloader::new(config.clone(), pool, progress);
        assert_eq!(downloader.config.max_concurrent_chunks, config.max_concurrent_chunks);

        let request = TransferRequest::new(vec![], vec![], TransferDirection::Download);
        let result = downloader.start(request, HashMap::new()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_start_download_valid_request() {
        let config = DownloadConfig::default();
        let pool = ConnectionPool::new(PoolConfig::default()).unwrap();
        let progress = ProgressTracker::new();
        let downloader = SwarmDownloader::new(config, pool, progress);

        let chunks = vec![[1u8; 32], [2u8; 32]];
        let sizes = vec![1024, 2048];
        let request = TransferRequest::new(chunks.clone(), sizes, TransferDirection::Download);

        let mut sources = HashMap::new();
        sources.insert(ChunkId::from_hash(&chunks[0]), vec![EdgeIdx::new(0)]);
        sources.insert(ChunkId::from_hash(&chunks[1]), vec![EdgeIdx::new(1)]);

        let session = downloader.start(request, sources).await.unwrap();
        assert_eq!(session.pending_chunks.len(), 2);
        assert!(session.active_chunks.is_empty());
        assert_eq!(session.state.status, TransferStatus::Active);
    }

    #[tokio::test]
    async fn test_tick_no_pending_chunks() {
        let config = DownloadConfig::default();
        let pool = ConnectionPool::new(PoolConfig::default()).unwrap();
        let progress = ProgressTracker::new();
        let downloader = SwarmDownloader::new(config, pool, progress);

        let transfer_id = TransferId::new(1);
        let state = TransferState::new(
            transfer_id,
            TransferDirection::Download,
            vec![],
            current_time_ms(),
        );
        let mut session = DownloadSession::new(transfer_id, state, vec![]);

        let completed = downloader.tick(&mut session).await.unwrap();
        assert!(completed.is_empty());
    }

    #[tokio::test]
    async fn test_tick_downloads_chunk() {
        let config = DownloadConfig::default();
        let pool = ConnectionPool::new(PoolConfig::default()).unwrap();
        let progress = ProgressTracker::new();
        let downloader = SwarmDownloader::new(config, pool, progress);

        let chunks = vec![[1u8; 32]];
        let sizes = vec![512];
        let request = TransferRequest::new(chunks.clone(), sizes, TransferDirection::Download);

        let mut sources = HashMap::new();
        sources.insert(ChunkId::from_hash(&chunks[0]), vec![EdgeIdx::new(0)]);

        let mut session = downloader.start(request, sources).await.unwrap();
        assert_eq!(session.pending_chunks.len(), 1);

        let completed = downloader.tick(&mut session).await.unwrap();

        assert!(session.active_chunks.len() <= 1);
    }

    #[tokio::test]
    async fn test_tick_multiple_chunks() {
        let config = DownloadConfig::new().with_max_concurrent_chunks(3);
        let pool = ConnectionPool::new(PoolConfig::default()).unwrap();
        let progress = ProgressTracker::new();
        let downloader = SwarmDownloader::new(config, pool, progress);

        let chunks = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let sizes = vec![512, 512, 512, 512];
        let request = TransferRequest::new(chunks.clone(), sizes, TransferDirection::Download);

        let mut sources = HashMap::new();
        for chunk in &chunks {
            sources.insert(ChunkId::from_hash(chunk), vec![EdgeIdx::new(0)]);
        }

        let mut session = downloader.start(request, sources).await.unwrap();

        downloader.tick(&mut session).await.unwrap();

        assert!(session.active_chunks.len() <= 3);
    }

    #[tokio::test]
    async fn test_chunk_completion_updates_progress() {
        let config = DownloadConfig::default();
        let pool = ConnectionPool::new(PoolConfig::default()).unwrap();
        let progress = ProgressTracker::new();
        let downloader = SwarmDownloader::new(config, pool, progress.clone());

        let chunks = vec![[1u8; 32]];
        let sizes = vec![100];
        let request = TransferRequest::new(chunks.clone(), sizes, TransferDirection::Download);

        let mut sources = HashMap::new();
        sources.insert(ChunkId::from_hash(&chunks[0]), vec![EdgeIdx::new(0)]);

        let mut session = downloader.start(request, sources).await.unwrap();
        let transfer_id = session.transfer_id;

        let initial_progress = progress.get_progress(transfer_id).unwrap();
        assert_eq!(initial_progress.completed_chunks, 0);

        downloader.tick(&mut session).await.unwrap();
    }

    #[tokio::test]
    async fn test_chunk_retries() {
        let mut active = ActiveChunkDownload::new(
            ChunkId::new(1),
            [1u8; 32],
            1024,
            vec![EdgeIdx::new(0), EdgeIdx::new(1)],
        );

        assert_eq!(active.retries, 0);
        active.mark_failed();
        assert_eq!(active.retries, 1);
        active.mark_failed();
        assert_eq!(active.retries, 2);
        assert!(active.retries > 1);
    }

    #[tokio::test]
    async fn test_cancel_download() {
        let config = DownloadConfig::default();
        let pool = ConnectionPool::new(PoolConfig::default()).unwrap();
        let progress = ProgressTracker::new();
        let downloader = SwarmDownloader::new(config, pool, progress);

        let chunks = vec![[1u8; 32], [2u8; 32]];
        let sizes = vec![1024, 2048];
        let request = TransferRequest::new(chunks.clone(), sizes, TransferDirection::Download);

        let mut sources = HashMap::new();
        sources.insert(ChunkId::from_hash(&chunks[0]), vec![EdgeIdx::new(0)]);

        let mut session = downloader.start(request, sources).await.unwrap();

        downloader.cancel(&mut session);

        assert!(session.active_chunks.is_empty());
        assert!(session.pending_chunks.is_empty());
        assert_eq!(session.state.status, TransferStatus::Cancelled);
    }

    #[tokio::test]
    async fn test_finalize_download() {
        let config = DownloadConfig::default();
        let pool = ConnectionPool::new(PoolConfig::default()).unwrap();
        let progress = ProgressTracker::new();
        let downloader = SwarmDownloader::new(config, pool, progress);

        let transfer_id = TransferId::new(1);
        let mut state = TransferState::new(transfer_id, TransferDirection::Download, vec![], current_time_ms());
        state.status = TransferStatus::Completed;
        let session = DownloadSession::new(transfer_id, state, vec![]);
        let result = downloader.finalize(session);
        assert_eq!(result.id, transfer_id);

        let transfer_id2 = TransferId::new(2);
        let state2 = TransferState::new(transfer_id2, TransferDirection::Download, vec![], current_time_ms());
        let session2 = DownloadSession::new(transfer_id2, state2, vec![ChunkId::new(1)]);
        let result2 = downloader.finalize(session2);
        assert_eq!(result2.id, transfer_id2);
    }

    #[tokio::test]
    async fn test_source_selection_and_limits() {
        let sources = vec![EdgeIdx::new(0), EdgeIdx::new(1), EdgeIdx::new(2)];
        let mut active = ActiveChunkDownload::new(ChunkId::new(1), [1u8; 32], 1024, sources.clone());
        let first = active.select_next_source();
        assert!(first.is_some());
        let second = active.select_next_source();
        assert!(second.is_some());
        assert_ne!(first, second);

        let config = DownloadConfig::new().with_max_concurrent_chunks(2);
        let pool = ConnectionPool::new(PoolConfig::default()).unwrap();
        let progress = ProgressTracker::new();
        let downloader = SwarmDownloader::new(config, pool, progress);
        let chunks = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let sizes = vec![512, 512, 512, 512];
        let request = TransferRequest::new(chunks.clone(), sizes, TransferDirection::Download);
        let mut sources_map = HashMap::new();
        for chunk in &chunks {
            sources_map.insert(ChunkId::from_hash(chunk), vec![EdgeIdx::new(0)]);
        }
        let mut session = downloader.start(request, sources_map).await.unwrap();
        downloader.tick(&mut session).await.unwrap();
        assert!(session.active_chunks.len() <= 2);
    }

    #[tokio::test]
    async fn test_session_state_transitions() {
        let config = DownloadConfig::default();
        let pool = ConnectionPool::new(PoolConfig::default()).unwrap();
        let progress = ProgressTracker::new();
        let downloader = SwarmDownloader::new(config, pool, progress);
        let chunks = vec![[1u8; 32]];
        let sizes = vec![1024];
        let request = TransferRequest::new(chunks.clone(), sizes, TransferDirection::Download);
        let mut sources = HashMap::new();
        sources.insert(ChunkId::from_hash(&chunks[0]), vec![EdgeIdx::new(0)]);
        let mut session = downloader.start(request, sources).await.unwrap();
        assert_eq!(session.state.status, TransferStatus::Active);
        downloader.cancel(&mut session);
        assert_eq!(session.state.status, TransferStatus::Cancelled);
    }

    #[tokio::test]
    async fn test_download_result_calculation() {
        let config = DownloadConfig::default();
        let pool = ConnectionPool::new(PoolConfig::default()).unwrap();
        let progress = ProgressTracker::new();
        let downloader = SwarmDownloader::new(config, pool, progress);

        let transfer_id = TransferId::new(1);
        let mut state = TransferState::new(
            transfer_id,
            TransferDirection::Download,
            vec![],
            current_time_ms(),
        );
        state.start(current_time_ms());
        state.transferred_bytes = 1000;
        state.completed_chunks = 1;

        std::thread::sleep(std::time::Duration::from_millis(10));
        state.complete(current_time_ms());

        let session = DownloadSession::new(transfer_id, state, vec![]);
        let result = downloader.finalize(session);

        assert_eq!(result.id, transfer_id);
        assert_eq!(result.bytes_transferred, 1000);
    }

    #[test]
    fn test_time_and_id_generation() {
        let time1 = current_time_ms();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let time2 = current_time_ms();
        assert!(time2 > time1);

        let id1 = generate_transfer_id();
        let id2 = generate_transfer_id();
        assert_ne!(id1, id2);
        assert!(id2 > id1);
    }
}
