//! Session management with persistence

use crate::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

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
        }
    }

    /// Save session to disk for resume
    pub fn save(&self, sessions_dir: &Path) -> Result<()> {
        fs::create_dir_all(sessions_dir)?;

        let session_path = sessions_dir.join(format!("{}.session", self.id));
        let encoded = rmp_serde::to_vec(self).map_err(|e| {
            crate::Error::Session(format!("Failed to serialize session: {}", e))
        })?;

        fs::write(session_path, encoded)?;
        Ok(())
    }

    /// Load session from disk
    pub fn load(sessions_dir: &Path, id: &str) -> Result<Self> {
        let session_path = sessions_dir.join(format!("{}.session", id));

        if !session_path.exists() {
            return Err(crate::Error::Session(format!(
                "Session not found: {}",
                id
            )));
        }

        let data = fs::read(session_path)?;
        let session: Session = rmp_serde::from_slice(&data).map_err(|e| {
            crate::Error::Session(format!("Failed to deserialize session: {}", e))
        })?;

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

            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("session") {
                if let Ok(data) = fs::read(&path) {
                    if let Ok(session) = rmp_serde::from_slice::<Session>(&data) {
                        sessions.push(session);
                    }
                }
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
    pub fn is_chunk_completed(&self, chunk_id: u64) -> bool {
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
    pub fn progress(&self) -> f64 {
        if self.total_chunks == 0 {
            0.0
        } else {
            self.completed_chunks.len() as f64 / self.total_chunks as f64 * 100.0
        }
    }

    /// Get remaining chunks
    pub fn remaining_chunks(&self) -> Vec<u64> {
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
