//! Session management with persistence

use crate::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Erasure coding state for resumable transfers
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ErasureState {
    /// Number of data shards per chunk
    pub data_shards: usize,
    /// Number of parity shards per chunk
    pub parity_shards: usize,
    /// Received shards per chunk: chunk_id -> received shard indices
    pub received_shards: HashMap<u64, Vec<u16>>,
    /// Decoded chunks that have been fully recovered
    pub decoded_chunks: HashSet<u64>,
}

impl ErasureState {
    /// Create a new erasure state
    pub fn new(data_shards: usize, parity_shards: usize) -> Self {
        Self {
            data_shards,
            parity_shards,
            received_shards: HashMap::new(),
            decoded_chunks: HashSet::new(),
        }
    }

    /// Record a received shard
    pub fn record_shard(&mut self, chunk_id: u64, shard_idx: u16) {
        self.received_shards
            .entry(chunk_id)
            .or_default()
            .push(shard_idx);
    }

    /// Check if enough shards received to decode a chunk
    pub fn can_decode(&self, chunk_id: u64) -> bool {
        if let Some(shards) = self.received_shards.get(&chunk_id) {
            shards.len() >= self.data_shards
        } else {
            false
        }
    }

    /// Mark chunk as decoded
    pub fn mark_decoded(&mut self, chunk_id: u64) {
        self.decoded_chunks.insert(chunk_id);
    }

    /// Check if chunk is already decoded
    pub fn is_decoded(&self, chunk_id: u64) -> bool {
        self.decoded_chunks.contains(&chunk_id)
    }

    /// Get chunks that are partially received but not yet decoded
    pub fn partial_chunks(&self) -> Vec<u64> {
        self.received_shards
            .keys()
            .filter(|&&chunk_id| !self.is_decoded(chunk_id))
            .copied()
            .collect()
    }

    /// Get missing shard indices for a chunk
    pub fn missing_shards(&self, chunk_id: u64) -> Vec<u16> {
        let total_shards = (self.data_shards + self.parity_shards) as u16;
        let received: HashSet<u16> = self
            .received_shards
            .get(&chunk_id)
            .map(|v| v.iter().copied().collect())
            .unwrap_or_default();

        (0..total_shards)
            .filter(|idx| !received.contains(idx))
            .collect()
    }

    /// Calculate how many more shards needed to decode a chunk
    pub fn shards_needed(&self, chunk_id: u64) -> usize {
        if let Some(shards) = self.received_shards.get(&chunk_id) {
            self.data_shards.saturating_sub(shards.len())
        } else {
            self.data_shards
        }
    }
}

/// Transfer session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Unique session ID
    pub id: String,
    /// Session creation time
    pub created_at: SystemTime,
    /// Last update time
    pub updated_at: SystemTime,
    /// Source path
    pub source: PathBuf,
    /// Destination
    pub destination: String,
    /// Current state
    pub state: SessionState,
    /// Completed chunks
    pub completed_chunks: Vec<u64>,
    /// Total chunks
    pub total_chunks: u64,
    /// Total bytes
    pub total_bytes: u64,
    /// Transferred bytes
    pub transferred_bytes: u64,
    /// Merkle root hash
    pub merkle_root: Option<[u8; 32]>,
    /// Error message if failed
    pub error_message: Option<String>,
    /// Erasure coding state for resumable transfers
    #[serde(default)]
    pub erasure_state: Option<ErasureState>,
}

/// Session state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    /// Session created, not started
    Created,
    /// Analyzing payload
    Analyzing,
    /// Negotiating with remote
    Negotiating,
    /// Transfer in progress
    Transferring,
    /// Verifying integrity
    Verifying,
    /// Completed successfully
    Completed,
    /// Failed with error
    Failed,
    /// Paused/interrupted
    Paused,
}

impl Session {
    /// Create a new session
    pub fn new(source: PathBuf, destination: String) -> Self {
        Self {
            id: generate_session_id(),
            created_at: SystemTime::now(),
            updated_at: SystemTime::now(),
            source,
            destination,
            state: SessionState::Created,
            completed_chunks: Vec::new(),
            total_chunks: 0,
            total_bytes: 0,
            transferred_bytes: 0,
            merkle_root: None,
            error_message: None,
            erasure_state: None,
        }
    }

    /// Create a new session with erasure coding enabled
    pub fn new_with_erasure(
        source: PathBuf,
        destination: String,
        data_shards: usize,
        parity_shards: usize,
    ) -> Self {
        let mut session = Self::new(source, destination);
        session.erasure_state = Some(ErasureState::new(data_shards, parity_shards));
        session
    }

    /// Initialize erasure state for an existing session
    pub fn init_erasure(&mut self, data_shards: usize, parity_shards: usize) {
        self.erasure_state = Some(ErasureState::new(data_shards, parity_shards));
        self.updated_at = SystemTime::now();
    }

    /// Record a received shard for erasure-coded transfer
    pub fn record_shard(&mut self, chunk_id: u64, shard_idx: u16) {
        if let Some(ref mut state) = self.erasure_state {
            state.record_shard(chunk_id, shard_idx);
            self.updated_at = SystemTime::now();
        }
    }

    /// Check if enough shards received to decode chunk
    pub fn can_decode_chunk(&self, chunk_id: u64) -> bool {
        self.erasure_state
            .as_ref()
            .map(|s| s.can_decode(chunk_id))
            .unwrap_or(false)
    }

    /// Mark chunk as decoded (for erasure-coded transfers)
    pub fn mark_chunk_decoded(&mut self, chunk_id: u64) {
        if let Some(ref mut state) = self.erasure_state {
            state.mark_decoded(chunk_id);
        }
        self.complete_chunk(chunk_id);
    }

    /// Get chunks that are partially received but not decoded
    pub fn partial_erasure_chunks(&self) -> Vec<u64> {
        self.erasure_state
            .as_ref()
            .map(|s| s.partial_chunks())
            .unwrap_or_default()
    }

    /// Check if this is an erasure-coded transfer
    pub fn is_erasure_coded(&self) -> bool {
        self.erasure_state.is_some()
    }

    /// Save session to disk for resume
    pub fn save(&self, sessions_dir: &Path) -> Result<()> {
        fs::create_dir_all(sessions_dir)?;

        let session_path = sessions_dir.join(format!("{}.session", self.id));
        let encoded = rmp_serde::to_vec(self)
            .map_err(|e| crate::Error::Session(format!("Failed to serialize session: {}", e)))?;

        fs::write(session_path, encoded)?;
        Ok(())
    }

    /// Load session from disk
    pub fn load(sessions_dir: &Path, id: &str) -> Result<Self> {
        let session_path = sessions_dir.join(format!("{}.session", id));

        if !session_path.exists() {
            return Err(crate::Error::Session(format!("Session not found: {}", id)));
        }

        let data = fs::read(session_path)?;
        let session: Session = rmp_serde::from_slice(&data)
            .map_err(|e| crate::Error::Session(format!("Failed to deserialize session: {}", e)))?;

        Ok(session)
    }

    /// List all sessions
    pub fn list(sessions_dir: &Path) -> Result<Vec<Self>> {
        if !sessions_dir.exists() {
            return Ok(Vec::new());
        }

        let mut sessions = Vec::new();

        for entry in fs::read_dir(sessions_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file()
                && path.extension().and_then(|s| s.to_str()) == Some("session")
                && let Ok(data) = fs::read(&path)
                && let Ok(session) = rmp_serde::from_slice::<Session>(&data)
            {
                sessions.push(session);
            }
        }

        sessions.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(sessions)
    }

    /// Delete session file
    pub fn delete(sessions_dir: &Path, id: &str) -> Result<()> {
        let session_path = sessions_dir.join(format!("{}.session", id));

        if session_path.exists() {
            fs::remove_file(session_path)?;
        }

        Ok(())
    }

    /// Mark chunk as completed
    pub fn complete_chunk(&mut self, chunk_id: u64) {
        if !self.is_chunk_completed(chunk_id) {
            self.completed_chunks.push(chunk_id);
            self.updated_at = SystemTime::now();
        }
    }

    /// Check if chunk is completed
    ///
    /// For erasure-coded transfers, a chunk is considered completed if it
    /// has been decoded (present in erasure_state.decoded_chunks).
    /// For regular transfers, it checks completed_chunks.
    pub fn is_chunk_completed(&self, chunk_id: u64) -> bool {
        // For erasure-coded transfers, check decoded_chunks
        if let Some(ref erasure_state) = self.erasure_state {
            return erasure_state.decoded_chunks.contains(&chunk_id);
        }
        // For regular transfers, check completed_chunks
        self.completed_chunks.contains(&chunk_id)
    }

    /// Update state
    pub fn set_state(&mut self, state: SessionState) {
        self.state = state;
        self.updated_at = SystemTime::now();
    }

    /// Set error message and state
    pub fn set_error(&mut self, message: String) {
        self.error_message = Some(message);
        self.state = SessionState::Failed;
        self.updated_at = SystemTime::now();
    }

    /// Calculate progress percentage
    ///
    /// For erasure-coded transfers, uses decoded_chunks count.
    /// For regular transfers, uses completed_chunks count.
    pub fn progress(&self) -> f64 {
        if self.total_chunks == 0 {
            return 0.0;
        }
        // For erasure-coded transfers, use decoded_chunks
        if let Some(ref erasure_state) = self.erasure_state {
            return erasure_state.decoded_chunks.len() as f64 / self.total_chunks as f64 * 100.0;
        }
        // For regular transfers, use completed_chunks
        self.completed_chunks.len() as f64 / self.total_chunks as f64 * 100.0
    }

    /// Get remaining chunks
    ///
    /// For erasure-coded transfers, returns chunks not yet decoded.
    /// For regular transfers, returns chunks not yet completed.
    pub fn remaining_chunks(&self) -> Vec<u64> {
        // For erasure-coded transfers, check decoded_chunks
        if let Some(ref erasure_state) = self.erasure_state {
            return (0..self.total_chunks)
                .filter(|i| !erasure_state.decoded_chunks.contains(i))
                .collect();
        }
        // For regular transfers, check completed_chunks
        let completed_set: HashSet<u64> = self.completed_chunks.iter().copied().collect();
        (0..self.total_chunks)
            .filter(|i| !completed_set.contains(i))
            .collect()
    }

    /// Update transfer progress
    pub fn update_progress(&mut self, bytes_transferred: u64) {
        self.transferred_bytes = bytes_transferred;
        self.updated_at = SystemTime::now();
    }

    /// Get sessions directory (default: ~/.warp/sessions)
    pub fn sessions_dir() -> PathBuf {
        if let Some(home) = dirs::home_dir() {
            home.join(".warp").join("sessions")
        } else {
            PathBuf::from(".warp/sessions")
        }
    }

    /// Check if session can be resumed
    pub fn can_resume(&self) -> bool {
        matches!(
            self.state,
            SessionState::Paused | SessionState::Failed | SessionState::Transferring
        ) && !self.completed_chunks.is_empty()
    }
}

fn generate_session_id() -> String {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_nanos();
    format!("{:x}", now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_session_new() {
        let session = Session::new(PathBuf::from("/src"), "dest".to_string());
        assert_eq!(session.state, SessionState::Created);
        assert_eq!(session.source, PathBuf::from("/src"));
        assert_eq!(session.destination, "dest");
    }

    #[test]
    fn test_session_progress() {
        let mut session = Session::new(PathBuf::from("/src"), "dest".to_string());
        session.total_chunks = 10;
        session.complete_chunk(0);
        session.complete_chunk(1);
        session.complete_chunk(2);

        assert_eq!(session.progress(), 30.0);
    }

    #[test]
    fn test_chunk_completion() {
        let mut session = Session::new(PathBuf::from("/src"), "dest".to_string());
        assert!(!session.is_chunk_completed(5));

        session.complete_chunk(5);
        assert!(session.is_chunk_completed(5));

        session.complete_chunk(5);
        assert_eq!(session.completed_chunks.len(), 1);
    }

    #[test]
    fn test_remaining_chunks() {
        let mut session = Session::new(PathBuf::from("/src"), "dest".to_string());
        session.total_chunks = 5;
        session.complete_chunk(1);
        session.complete_chunk(3);

        let remaining = session.remaining_chunks();
        assert_eq!(remaining, vec![0, 2, 4]);
    }

    #[test]
    fn test_save_load() {
        let dir = tempdir().unwrap();
        let mut session = Session::new(PathBuf::from("/src"), "dest".to_string());
        session.total_chunks = 10;
        session.complete_chunk(5);

        session.save(dir.path()).unwrap();

        let loaded = Session::load(dir.path(), &session.id).unwrap();
        assert_eq!(loaded.id, session.id);
        assert_eq!(loaded.total_chunks, 10);
        assert_eq!(loaded.completed_chunks.len(), 1);
    }

    #[test]
    fn test_list_sessions() {
        let dir = tempdir().unwrap();

        let session1 = Session::new(PathBuf::from("/src1"), "dest1".to_string());
        let session2 = Session::new(PathBuf::from("/src2"), "dest2".to_string());

        session1.save(dir.path()).unwrap();
        session2.save(dir.path()).unwrap();

        let sessions = Session::list(dir.path()).unwrap();
        assert_eq!(sessions.len(), 2);
    }

    #[test]
    fn test_delete() {
        let dir = tempdir().unwrap();
        let session = Session::new(PathBuf::from("/src"), "dest".to_string());

        session.save(dir.path()).unwrap();
        assert!(dir.path().join(format!("{}.session", session.id)).exists());

        Session::delete(dir.path(), &session.id).unwrap();
        assert!(!dir.path().join(format!("{}.session", session.id)).exists());
    }

    #[test]
    fn test_can_resume() {
        let mut session = Session::new(PathBuf::from("/src"), "dest".to_string());
        assert!(!session.can_resume());

        session.total_chunks = 10;
        session.complete_chunk(0);
        session.set_state(SessionState::Paused);
        assert!(session.can_resume());

        session.set_state(SessionState::Completed);
        assert!(!session.can_resume());
    }
}
