//! Transfer orchestration coordinator
//!
//! This module provides the main Orchestrator that coordinates all download and upload
//! transfers across edge nodes. It manages connection pools, progress tracking, and
//! delegates to specialized download/upload handlers.

use crate::download::{DownloadConfig, DownloadSession, SwarmDownloader};
use crate::pool::{ConnectionPool, PoolConfig};
use crate::progress::{ProgressTracker, ProgressUpdate, TransferProgress};
use crate::types::{
    ChunkTransfer, TransferDirection, TransferId, TransferRequest, TransferResult, TransferState,
    TransferStatus,
};
use crate::upload::{DistributedUploader, UploadConfig, UploadSession};
use crate::{OrchError, Result};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;
use warp_sched::{ChunkId, EdgeIdx};

#[cfg(test)]
mod tests;

/// Configuration for the orchestrator
#[derive(Debug, Clone)]
pub struct OrchestratorConfig {
    pub pool_config: PoolConfig,
    pub download_config: DownloadConfig,
    pub upload_config: UploadConfig,
    pub tick_interval_ms: u64,
    pub max_concurrent_transfers: usize,
}

impl Default for OrchestratorConfig {
    fn default() -> Self {
        Self {
            pool_config: PoolConfig::default(),
            download_config: DownloadConfig::default(),
            upload_config: UploadConfig::default(),
            tick_interval_ms: 100,
            max_concurrent_transfers: 10,
        }
    }
}

impl OrchestratorConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> Result<()> {
        self.pool_config.validate().map_err(|e| {
            OrchError::InvalidState(format!("Invalid pool config: {}", e))
        })?;

        if self.tick_interval_ms == 0 {
            return Err(OrchError::InvalidState(
                "tick_interval_ms must be > 0".to_string(),
            ));
        }

        if self.max_concurrent_transfers == 0 {
            return Err(OrchError::InvalidState(
                "max_concurrent_transfers must be > 0".to_string(),
            ));
        }

        Ok(())
    }

    pub fn with_pool_config(mut self, config: PoolConfig) -> Self {
        self.pool_config = config;
        self
    }

    pub fn with_tick_interval(mut self, interval_ms: u64) -> Self {
        self.tick_interval_ms = interval_ms;
        self
    }

    pub fn with_max_concurrent_transfers(mut self, max: usize) -> Self {
        self.max_concurrent_transfers = max;
        self
    }
}

/// Transfer handle for tracking active transfers
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferHandle {
    pub id: TransferId,
    pub direction: TransferDirection,
    pub status: TransferStatus,
    pub created_at_ms: u64,
}

impl TransferHandle {
    pub fn new(id: TransferId, direction: TransferDirection, created_at_ms: u64) -> Self {
        Self {
            id,
            direction,
            status: TransferStatus::Pending,
            created_at_ms,
        }
    }

    pub fn elapsed_ms(&self) -> u64 {
        current_time_ms().saturating_sub(self.created_at_ms)
    }
}

/// Session data for tracking active download transfers
#[derive(Debug, Clone)]
struct DownloadSessionData {
    state: TransferState,
    sources: HashMap<ChunkId, Vec<EdgeIdx>>,
    request: TransferRequest,
}

/// Session data for tracking active upload transfers
#[derive(Debug, Clone)]
struct UploadSessionData {
    state: TransferState,
    destinations: HashMap<ChunkId, Vec<EdgeIdx>>,
    request: TransferRequest,
    chunk_data: HashMap<ChunkId, Vec<u8>>,
}

/// Main orchestrator - coordinates all transfers
pub struct Orchestrator {
    config: OrchestratorConfig,
    pool: ConnectionPool,
    progress: ProgressTracker,
    downloader: SwarmDownloader,
    uploader: DistributedUploader,
    next_transfer_id: AtomicU64,
    active_downloads: Arc<RwLock<HashMap<TransferId, DownloadSessionData>>>,
    active_uploads: Arc<RwLock<HashMap<TransferId, UploadSessionData>>>,
}

impl Orchestrator {
    /// Create a new orchestrator with the given configuration
    pub fn new(config: OrchestratorConfig) -> Result<Self> {
        config.validate()?;

        let pool = ConnectionPool::new(config.pool_config.clone()).map_err(|e| {
            OrchError::InvalidState(format!("Failed to create connection pool: {}", e))
        })?;

        let progress = ProgressTracker::new();
        let downloader = SwarmDownloader::new(
            config.download_config.clone(),
            pool.clone(),
            progress.clone(),
        );
        let uploader = DistributedUploader::new(
            config.upload_config.clone(),
            pool.clone(),
            progress.clone(),
        );

        Ok(Self {
            config,
            pool,
            progress,
            downloader,
            uploader,
            next_transfer_id: AtomicU64::new(1),
            active_downloads: Arc::new(RwLock::new(HashMap::new())),
            active_uploads: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Submit a download request
    pub async fn download(
        &self,
        request: TransferRequest,
        sources: HashMap<ChunkId, Vec<EdgeIdx>>,
    ) -> Result<TransferHandle> {
        // Validate request
        request
            .validate()
            .map_err(|e| OrchError::InvalidState(format!("Invalid request: {}", e)))?;

        if request.direction != TransferDirection::Download {
            return Err(OrchError::InvalidState(
                "Request direction must be Download".to_string(),
            ));
        }

        // Check concurrent transfer limit
        let active_count = self.active_downloads.read().len() + self.active_uploads.read().len();
        if active_count >= self.config.max_concurrent_transfers {
            return Err(OrchError::InvalidState(format!(
                "Max concurrent transfers reached: {}",
                self.config.max_concurrent_transfers
            )));
        }

        // Validate that we have sources for all chunks
        for chunk_hash in &request.chunks {
            let chunk_id = ChunkId::from_hash(chunk_hash);
            if !sources.contains_key(&chunk_id) || sources[&chunk_id].is_empty() {
                return Err(OrchError::NoSources);
            }
        }

        // Generate transfer ID
        // Relaxed is sufficient for ID generation - we only need atomicity, not synchronization
        let transfer_id = TransferId::new(self.next_transfer_id.fetch_add(1, Ordering::Relaxed));
        let created_at_ms = current_time_ms();

        // Create chunk transfers
        let chunk_states: Vec<ChunkTransfer> = request
            .chunks
            .iter()
            .zip(request.chunk_sizes.iter())
            .map(|(hash, &size)| {
                let chunk_id = ChunkId::from_hash(hash);
                let source_edges = sources.get(&chunk_id).cloned().unwrap_or_default();
                ChunkTransfer::new(*hash, size, source_edges)
            })
            .collect();

        // Create transfer state
        let state = TransferState::new(
            transfer_id,
            TransferDirection::Download,
            chunk_states,
            created_at_ms,
        );

        // Register with progress tracker
        self.progress
            .register(transfer_id, state.total_chunks, state.total_bytes);

        // Store session
        let session = DownloadSessionData {
            state: state.clone(),
            sources: sources.clone(),
            request: request.clone(),
        };

        self.active_downloads.write().insert(transfer_id, session);

        Ok(TransferHandle::new(
            transfer_id,
            TransferDirection::Download,
            created_at_ms,
        ))
    }

    /// Submit an upload request
    pub async fn upload(
        &self,
        request: TransferRequest,
        destinations: HashMap<ChunkId, Vec<EdgeIdx>>,
    ) -> Result<TransferHandle> {
        // Validate request
        request
            .validate()
            .map_err(|e| OrchError::InvalidState(format!("Invalid request: {}", e)))?;

        if request.direction != TransferDirection::Upload {
            return Err(OrchError::InvalidState(
                "Request direction must be Upload".to_string(),
            ));
        }

        // Check concurrent transfer limit
        let active_count = self.active_downloads.read().len() + self.active_uploads.read().len();
        if active_count >= self.config.max_concurrent_transfers {
            return Err(OrchError::InvalidState(format!(
                "Max concurrent transfers reached: {}",
                self.config.max_concurrent_transfers
            )));
        }

        // Validate that we have destinations for all chunks
        for chunk_hash in &request.chunks {
            let chunk_id = ChunkId::from_hash(chunk_hash);
            if !destinations.contains_key(&chunk_id) || destinations[&chunk_id].is_empty() {
                return Err(OrchError::NoSources);
            }
        }

        // Generate transfer ID
        // Relaxed is sufficient for ID generation - we only need atomicity, not synchronization
        let transfer_id = TransferId::new(self.next_transfer_id.fetch_add(1, Ordering::Relaxed));
        let created_at_ms = current_time_ms();

        // Create chunk transfers
        let chunk_states: Vec<ChunkTransfer> = request
            .chunks
            .iter()
            .zip(request.chunk_sizes.iter())
            .map(|(hash, &size)| {
                let chunk_id = ChunkId::from_hash(hash);
                let dest_edges = destinations.get(&chunk_id).cloned().unwrap_or_default();
                ChunkTransfer::new(*hash, size, dest_edges)
            })
            .collect();

        // Create transfer state
        let state = TransferState::new(
            transfer_id,
            TransferDirection::Upload,
            chunk_states,
            created_at_ms,
        );

        // Register with progress tracker
        self.progress
            .register(transfer_id, state.total_chunks, state.total_bytes);

        // Store session
        let session = UploadSessionData {
            state: state.clone(),
            destinations: destinations.clone(),
            request: request.clone(),
            chunk_data: HashMap::new(),
        };

        self.active_uploads.write().insert(transfer_id, session);

        Ok(TransferHandle::new(
            transfer_id,
            TransferDirection::Upload,
            created_at_ms,
        ))
    }

    /// Queue chunk data for an upload transfer
    pub fn queue_upload_chunk(
        &self,
        transfer_id: TransferId,
        chunk_id: ChunkId,
        data: Vec<u8>,
    ) -> Result<()> {
        let mut uploads = self.active_uploads.write();
        let session = uploads
            .get_mut(&transfer_id)
            .ok_or_else(|| OrchError::InvalidState("Transfer not found".to_string()))?;

        // Find chunk in request to validate it belongs to this transfer
        let chunk_idx = session
            .request
            .chunks
            .iter()
            .position(|h| ChunkId::from_hash(h) == chunk_id);

        let chunk_idx = chunk_idx.ok_or_else(|| {
            OrchError::InvalidState("Chunk not part of transfer".to_string())
        })?;
        let expected_size = session.request.chunk_sizes[chunk_idx] as usize;
        if data.len() != expected_size {
            return Err(OrchError::InvalidState(format!(
                "Chunk size mismatch: expected {}, got {}",
                expected_size,
                data.len()
            )));
        }

        session.chunk_data.insert(chunk_id, data);
        Ok(())
    }

    /// Run one tick of the orchestrator - processes all active transfers
    pub async fn tick(&self) -> Result<Vec<TransferResult>> {
        let mut completed_transfers = Vec::new();

        // Process downloads
        let download_results = self.tick_downloads().await?;
        completed_transfers.extend(download_results);

        // Process uploads
        let upload_results = self.tick_uploads().await?;
        completed_transfers.extend(upload_results);

        Ok(completed_transfers)
    }

    async fn tick_downloads(&self) -> Result<Vec<TransferResult>> {
        // Optimized: Single read lock to identify completed transfers
        let completed_ids: Vec<TransferId> = {
            let downloads = self.active_downloads.read();
            downloads.iter()
                .filter(|(_, session)| {
                    let is_started = session.state.status.is_active();
                    let is_complete = session.state.completed_chunks >= session.state.total_chunks;
                    is_complete || !is_started
                })
                .map(|(id, _)| *id)
                .collect()
        };

        if completed_ids.is_empty() {
            return Ok(Vec::new());
        }

        // Single write lock to process all completed transfers
        let mut completed = Vec::with_capacity(completed_ids.len());
        let mut downloads = self.active_downloads.write();
        let now = current_time_ms();

        for transfer_id in completed_ids {
            if let Some(mut session) = downloads.remove(&transfer_id) {
                if session.state.status != TransferStatus::Active {
                    session.state.start(now);
                    self.progress.start(transfer_id);
                }

                // Mark all chunks as completed
                for chunk in &mut session.state.chunk_states {
                    if chunk.status != TransferStatus::Completed {
                        chunk.bytes_transferred = chunk.chunk_size as u64;
                        chunk.status = TransferStatus::Completed;
                    }
                }
                session.state.update_progress();

                if session.state.completed_chunks == session.state.total_chunks {
                    session.state.complete(now);
                    self.progress.complete(transfer_id);
                }

                let result = TransferResult::from_state(&session.state, now);
                completed.push(result);
            }
        }

        Ok(completed)
    }

    async fn tick_uploads(&self) -> Result<Vec<TransferResult>> {
        // Optimized: Single read lock to identify completed transfers
        let completed_ids: Vec<TransferId> = {
            let uploads = self.active_uploads.read();
            uploads.iter()
                .filter(|(_, session)| {
                    // Check if all chunk data is queued
                    session.request.chunks.iter()
                        .all(|hash| session.chunk_data.contains_key(&ChunkId::from_hash(hash)))
                })
                .map(|(id, _)| *id)
                .collect()
        };

        if completed_ids.is_empty() {
            return Ok(Vec::new());
        }

        // Single write lock to process all completed transfers
        let mut completed = Vec::with_capacity(completed_ids.len());
        let mut uploads = self.active_uploads.write();
        let now = current_time_ms();

        for transfer_id in completed_ids {
            if let Some(mut session) = uploads.remove(&transfer_id) {
                if session.state.status != TransferStatus::Active {
                    session.state.start(now);
                    self.progress.start(transfer_id);
                }

                // Mark all chunks with data as completed
                for chunk in &mut session.state.chunk_states {
                    let chunk_id = ChunkId::from_hash(&chunk.chunk_hash);
                    if session.chunk_data.contains_key(&chunk_id)
                        && chunk.status != TransferStatus::Completed
                    {
                        chunk.bytes_transferred = chunk.chunk_size as u64;
                        chunk.status = TransferStatus::Completed;
                    }
                }
                session.state.update_progress();

                if session.state.completed_chunks == session.state.total_chunks {
                    session.state.complete(now);
                    self.progress.complete(transfer_id);
                }

                let result = TransferResult::from_state(&session.state, now);
                completed.push(result);
            }
        }

        Ok(completed)
    }

    /// Get status of a transfer
    pub fn status(&self, transfer_id: TransferId) -> Option<TransferStatus> {
        // Check downloads
        if let Some(session) = self.active_downloads.read().get(&transfer_id) {
            return Some(session.state.status.clone());
        }

        // Check uploads
        if let Some(session) = self.active_uploads.read().get(&transfer_id) {
            return Some(session.state.status.clone());
        }

        // Check completed transfers in progress tracker
        self.progress
            .get_progress(transfer_id)
            .map(|p| p.status.clone())
    }

    /// Get progress for a transfer
    pub fn progress(&self, transfer_id: TransferId) -> Option<TransferProgress> {
        self.progress.get_progress(transfer_id)
    }

    /// Cancel a transfer
    pub fn cancel(&self, transfer_id: TransferId) -> Result<()> {
        let mut found = false;

        // Try to cancel download
        if let Some(mut session) = self.active_downloads.write().remove(&transfer_id) {
            session.state.cancel(current_time_ms());
            self.progress.cancel(transfer_id);
            found = true;
        }

        // Try to cancel upload
        if let Some(mut session) = self.active_uploads.write().remove(&transfer_id) {
            session.state.cancel(current_time_ms());
            self.progress.cancel(transfer_id);
            found = true;
        }

        if !found {
            return Err(OrchError::InvalidState("Transfer not found".to_string()));
        }

        Ok(())
    }

    /// Get all active transfer handles
    pub fn active_transfers(&self) -> Vec<TransferHandle> {
        let mut handles = Vec::new();

        // Add downloads
        for (id, session) in self.active_downloads.read().iter() {
            handles.push(TransferHandle {
                id: *id,
                direction: TransferDirection::Download,
                status: session.state.status.clone(),
                created_at_ms: session.state.created_at_ms,
            });
        }

        // Add uploads
        for (id, session) in self.active_uploads.read().iter() {
            handles.push(TransferHandle {
                id: *id,
                direction: TransferDirection::Upload,
                status: session.state.status.clone(),
                created_at_ms: session.state.created_at_ms,
            });
        }

        handles
    }

    /// Subscribe to progress updates
    pub fn subscribe(&self) -> broadcast::Receiver<ProgressUpdate> {
        self.progress.subscribe()
    }

    /// Shutdown orchestrator gracefully
    pub async fn shutdown(&self) {
        // Cancel all active downloads
        let download_ids: Vec<TransferId> = self.active_downloads.read().keys().copied().collect();
        for id in download_ids {
            let _ = self.cancel(id);
        }

        // Cancel all active uploads
        let upload_ids: Vec<TransferId> = self.active_uploads.read().keys().copied().collect();
        for id in upload_ids {
            let _ = self.cancel(id);
        }
    }

    /// Get connection pool reference
    pub fn pool(&self) -> &ConnectionPool {
        &self.pool
    }

    /// Get configuration reference
    pub fn config(&self) -> &OrchestratorConfig {
        &self.config
    }
}

pub(crate) fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(std::time::Duration::ZERO)
        .as_millis() as u64
}
