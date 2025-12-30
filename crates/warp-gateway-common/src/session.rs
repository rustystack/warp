//! Client session management for protocol gateways
//!
//! Tracks client sessions for stateful protocols like NFSv4.1 and SMB3.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::RwLock;

use crate::error::{GatewayError, GatewayResult};
use crate::filehandle::FileHandle;
use crate::lock::LockToken;

/// Unique identifier for a client
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClientId(u64);

impl ClientId {
    /// Create a new client ID
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    /// Get the ID value
    pub fn value(&self) -> u64 {
        self.0
    }
}

/// Unique identifier for a session
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(u64);

impl SessionId {
    /// Create a new session ID
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    /// Get the ID value
    pub fn value(&self) -> u64 {
        self.0
    }
}

/// Open file state within a session
#[derive(Debug, Clone)]
pub struct OpenFileState {
    /// File handle
    pub handle: FileHandle,
    /// Open flags
    pub flags: u32,
    /// Current file position
    pub position: u64,
    /// Locks held on this file
    pub locks: Vec<LockToken>,
    /// Time of last access
    pub last_access: Instant,
}

/// Session configuration
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Maximum idle time before session expires
    pub idle_timeout: Duration,
    /// Maximum session lifetime
    pub max_lifetime: Duration,
    /// Maximum open files per session
    pub max_open_files: usize,
    /// Maximum locks per session
    pub max_locks: usize,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_secs(300),      // 5 minutes
            max_lifetime: Duration::from_secs(86400),    // 24 hours
            max_open_files: 1024,
            max_locks: 4096,
        }
    }
}

/// Client session
pub struct ClientSession {
    /// Session ID
    pub session_id: SessionId,
    /// Client ID
    pub client_id: ClientId,
    /// Client address
    pub client_addr: SocketAddr,
    /// Session creation time
    pub created_at: Instant,
    /// Last activity time
    last_activity: RwLock<Instant>,
    /// Sequence counter for exactly-once semantics
    sequence_id: AtomicU64,
    /// Open files in this session
    open_files: DashMap<u64, OpenFileState>,
    /// Next file handle ID
    next_file_id: AtomicU64,
    /// Session configuration
    config: SessionConfig,
}

impl ClientSession {
    /// Create a new session
    pub fn new(
        session_id: SessionId,
        client_id: ClientId,
        client_addr: SocketAddr,
        config: SessionConfig,
    ) -> Self {
        let now = Instant::now();
        Self {
            session_id,
            client_id,
            client_addr,
            created_at: now,
            last_activity: RwLock::new(now),
            sequence_id: AtomicU64::new(0),
            open_files: DashMap::new(),
            next_file_id: AtomicU64::new(1),
            config,
        }
    }

    /// Update last activity time
    pub fn touch(&self) {
        *self.last_activity.write() = Instant::now();
    }

    /// Get last activity time
    pub fn last_activity(&self) -> Instant {
        *self.last_activity.read()
    }

    /// Check if session has expired due to idle timeout
    pub fn is_idle_expired(&self) -> bool {
        self.last_activity().elapsed() > self.config.idle_timeout
    }

    /// Check if session has exceeded max lifetime
    pub fn is_lifetime_expired(&self) -> bool {
        self.created_at.elapsed() > self.config.max_lifetime
    }

    /// Check if session is expired (either idle or lifetime)
    pub fn is_expired(&self) -> bool {
        self.is_idle_expired() || self.is_lifetime_expired()
    }

    /// Get and increment sequence ID
    pub fn next_sequence(&self) -> u64 {
        self.sequence_id.fetch_add(1, Ordering::SeqCst)
    }

    /// Get current sequence ID
    pub fn current_sequence(&self) -> u64 {
        self.sequence_id.load(Ordering::SeqCst)
    }

    /// Open a file in this session
    pub fn open_file(&self, handle: FileHandle, flags: u32) -> GatewayResult<u64> {
        if self.open_files.len() >= self.config.max_open_files {
            return Err(GatewayError::Internal("too many open files".to_string()));
        }

        let file_id = self.next_file_id.fetch_add(1, Ordering::SeqCst);
        let state = OpenFileState {
            handle,
            flags,
            position: 0,
            locks: Vec::new(),
            last_access: Instant::now(),
        };
        self.open_files.insert(file_id, state);
        self.touch();
        Ok(file_id)
    }

    /// Close a file
    pub fn close_file(&self, file_id: u64) -> Option<OpenFileState> {
        self.touch();
        self.open_files.remove(&file_id).map(|(_, state)| state)
    }

    /// Get an open file
    pub fn get_file(&self, file_id: u64) -> Option<OpenFileState> {
        self.open_files.get(&file_id).map(|r| r.clone())
    }

    /// Update file position
    pub fn set_file_position(&self, file_id: u64, position: u64) -> bool {
        if let Some(mut entry) = self.open_files.get_mut(&file_id) {
            entry.position = position;
            entry.last_access = Instant::now();
            self.touch();
            true
        } else {
            false
        }
    }

    /// Add a lock to a file
    pub fn add_lock(&self, file_id: u64, token: LockToken) -> bool {
        if let Some(mut entry) = self.open_files.get_mut(&file_id) {
            if entry.locks.len() >= self.config.max_locks {
                return false;
            }
            entry.locks.push(token);
            true
        } else {
            false
        }
    }

    /// Remove a lock from a file
    pub fn remove_lock(&self, file_id: u64, token: LockToken) -> bool {
        if let Some(mut entry) = self.open_files.get_mut(&file_id) {
            let before = entry.locks.len();
            entry.locks.retain(|t| *t != token);
            before != entry.locks.len()
        } else {
            false
        }
    }

    /// Get all open file IDs
    pub fn open_file_ids(&self) -> Vec<u64> {
        self.open_files.iter().map(|r| *r.key()).collect()
    }

    /// Get number of open files
    pub fn open_file_count(&self) -> usize {
        self.open_files.len()
    }

    /// Get all lock tokens in this session
    pub fn all_locks(&self) -> Vec<LockToken> {
        self.open_files
            .iter()
            .flat_map(|r| r.locks.clone())
            .collect()
    }
}

/// Session manager
pub struct SessionManager {
    /// Sessions by ID
    sessions: DashMap<SessionId, ClientSession>,
    /// Client ID to session ID mapping
    client_to_session: DashMap<ClientId, SessionId>,
    /// Next session ID
    next_session_id: AtomicU64,
    /// Next client ID
    next_client_id: AtomicU64,
    /// Configuration
    config: SessionConfig,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new(config: SessionConfig) -> Self {
        Self {
            sessions: DashMap::new(),
            client_to_session: DashMap::new(),
            next_session_id: AtomicU64::new(1),
            next_client_id: AtomicU64::new(1),
            config,
        }
    }

    /// Allocate a new client ID
    pub fn allocate_client_id(&self) -> ClientId {
        ClientId::new(self.next_client_id.fetch_add(1, Ordering::SeqCst))
    }

    /// Create a new session for a client
    pub fn create_session(&self, client_id: ClientId, addr: SocketAddr) -> SessionId {
        let session_id = SessionId::new(self.next_session_id.fetch_add(1, Ordering::SeqCst));
        let session = ClientSession::new(session_id, client_id, addr, self.config.clone());

        self.sessions.insert(session_id, session);
        self.client_to_session.insert(client_id, session_id);

        session_id
    }

    /// Get a session by ID
    pub fn get_session(&self, session_id: SessionId) -> Option<dashmap::mapref::one::Ref<'_, SessionId, ClientSession>> {
        let session = self.sessions.get(&session_id)?;
        if session.is_expired() {
            drop(session);
            self.destroy_session(session_id);
            return None;
        }
        Some(session)
    }

    /// Get session by client ID
    pub fn get_session_by_client(&self, client_id: ClientId) -> Option<dashmap::mapref::one::Ref<'_, SessionId, ClientSession>> {
        let session_id = *self.client_to_session.get(&client_id)?;
        self.get_session(session_id)
    }

    /// Destroy a session
    pub fn destroy_session(&self, session_id: SessionId) -> Option<ClientSession> {
        let (_, session) = self.sessions.remove(&session_id)?;
        self.client_to_session.remove(&session.client_id);
        Some(session)
    }

    /// Expire idle sessions
    pub fn expire_idle_sessions(&self) -> Vec<SessionId> {
        let expired: Vec<SessionId> = self
            .sessions
            .iter()
            .filter(|r| r.is_expired())
            .map(|r| r.session_id)
            .collect();

        for session_id in &expired {
            self.destroy_session(*session_id);
        }

        expired
    }

    /// Get number of active sessions
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Get all session IDs
    pub fn session_ids(&self) -> Vec<SessionId> {
        self.sessions.iter().map(|r| *r.key()).collect()
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new(SessionConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filehandle::FileHandle;

    #[test]
    fn test_session_creation() {
        let manager = SessionManager::default();
        let client_id = manager.allocate_client_id();
        let addr = "127.0.0.1:1234".parse().unwrap();

        let session_id = manager.create_session(client_id, addr);
        assert!(manager.get_session(session_id).is_some());
        assert_eq!(manager.session_count(), 1);
    }

    #[test]
    fn test_session_destroy() {
        let manager = SessionManager::default();
        let client_id = manager.allocate_client_id();
        let addr = "127.0.0.1:1234".parse().unwrap();

        let session_id = manager.create_session(client_id, addr);
        manager.destroy_session(session_id);

        assert!(manager.get_session(session_id).is_none());
        assert_eq!(manager.session_count(), 0);
    }

    #[test]
    fn test_open_close_file() {
        let manager = SessionManager::default();
        let client_id = manager.allocate_client_id();
        let addr = "127.0.0.1:1234".parse().unwrap();

        let session_id = manager.create_session(client_id, addr);
        let session = manager.get_session(session_id).unwrap();

        let handle = FileHandle::new(1, 1, "test");
        let file_id = session.open_file(handle, 0).unwrap();

        assert_eq!(session.open_file_count(), 1);

        let state = session.close_file(file_id).unwrap();
        assert_eq!(state.position, 0);
        assert_eq!(session.open_file_count(), 0);
    }

    #[test]
    fn test_sequence_counter() {
        let manager = SessionManager::default();
        let client_id = manager.allocate_client_id();
        let addr = "127.0.0.1:1234".parse().unwrap();

        let session_id = manager.create_session(client_id, addr);
        let session = manager.get_session(session_id).unwrap();

        assert_eq!(session.next_sequence(), 0);
        assert_eq!(session.next_sequence(), 1);
        assert_eq!(session.next_sequence(), 2);
        assert_eq!(session.current_sequence(), 3);
    }
}
