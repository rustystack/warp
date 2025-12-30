//! NFSv4.1 session management
//!
//! Sessions provide exactly-once semantics for NFSv4.1 operations.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;
use parking_lot::RwLock;

use crate::error::NfsStatus;

/// Session ID (16 bytes, opaque)
pub type SessionId = [u8; 16];

/// NFSv4.1 session
#[derive(Debug)]
pub struct Nfs4Session {
    /// Session ID
    pub id: SessionId,
    /// Client ID
    pub client_id: u64,
    /// Fore channel attributes
    pub fore_channel: ChannelAttrs,
    /// Back channel attributes
    pub back_channel: Option<ChannelAttrs>,
    /// Session slots
    pub slots: Vec<RwLock<SessionSlot>>,
    /// Creation time
    pub created: Instant,
    /// Last activity
    pub last_active: RwLock<Instant>,
}

impl Nfs4Session {
    /// Create a new session
    pub fn new(id: SessionId, client_id: u64, fore_channel: ChannelAttrs) -> Self {
        let slot_count = fore_channel.max_requests as usize;
        let slots = (0..slot_count)
            .map(|_| RwLock::new(SessionSlot::new()))
            .collect();

        Self {
            id,
            client_id,
            fore_channel,
            back_channel: None,
            slots,
            created: Instant::now(),
            last_active: RwLock::new(Instant::now()),
        }
    }

    /// Get a slot by ID
    pub fn get_slot(&self, slot_id: u32) -> Option<&RwLock<SessionSlot>> {
        self.slots.get(slot_id as usize)
    }

    /// Update last activity time
    pub fn touch(&self) {
        *self.last_active.write() = Instant::now();
    }

    /// Check if session has expired
    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.last_active.read().elapsed() > timeout
    }
}

/// Channel attributes
#[derive(Debug, Clone)]
pub struct ChannelAttrs {
    /// Header padding (for RDMA)
    pub header_pad_size: u32,
    /// Maximum request size
    pub max_request_size: u32,
    /// Maximum response size
    pub max_response_size: u32,
    /// Maximum response size with cached data
    pub max_response_size_cached: u32,
    /// Maximum operations per COMPOUND
    pub max_ops: u32,
    /// Maximum concurrent requests
    pub max_requests: u32,
}

impl Default for ChannelAttrs {
    fn default() -> Self {
        Self {
            header_pad_size: 0,
            max_request_size: 1024 * 1024,      // 1 MB
            max_response_size: 1024 * 1024,     // 1 MB
            max_response_size_cached: 64 * 1024, // 64 KB
            max_ops: 16,
            max_requests: 16,
        }
    }
}

/// Session slot (for exactly-once semantics)
#[derive(Debug)]
pub struct SessionSlot {
    /// Expected sequence ID
    pub sequence_id: u32,
    /// Cached reply (for replay detection)
    pub cached_reply: Option<CachedReply>,
    /// Slot in use
    pub in_use: bool,
}

impl SessionSlot {
    /// Create a new slot
    pub fn new() -> Self {
        Self {
            sequence_id: 0,
            cached_reply: None,
            in_use: false,
        }
    }

    /// Validate sequence ID
    pub fn validate_sequence(&self, seq_id: u32) -> SequenceResult {
        if seq_id == self.sequence_id {
            SequenceResult::Ok
        } else if seq_id == self.sequence_id.wrapping_sub(1) {
            // Replay - return cached response
            SequenceResult::Replay
        } else {
            SequenceResult::Misordered
        }
    }

    /// Mark slot as in use
    pub fn acquire(&mut self, seq_id: u32) -> bool {
        if self.in_use {
            return false;
        }
        self.in_use = true;
        true
    }

    /// Release slot and cache reply
    pub fn release(&mut self, reply: CachedReply) {
        self.sequence_id = self.sequence_id.wrapping_add(1);
        self.cached_reply = Some(reply);
        self.in_use = false;
    }
}

impl Default for SessionSlot {
    fn default() -> Self {
        Self::new()
    }
}

/// Sequence validation result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequenceResult {
    /// Sequence ID is correct
    Ok,
    /// This is a replay of the previous request
    Replay,
    /// Sequence ID is out of order
    Misordered,
}

/// Cached reply for replay detection
#[derive(Debug, Clone)]
pub struct CachedReply {
    /// Sequence ID this reply is for
    pub sequence_id: u32,
    /// Cached response data
    pub data: Bytes,
    /// Status of the operation
    pub status: NfsStatus,
}

/// NFSv4.1 session manager
#[derive(Debug)]
pub struct Nfs4SessionManager {
    /// Sessions by ID
    sessions: DashMap<SessionId, Nfs4Session>,
    /// Sessions by client ID
    sessions_by_client: DashMap<u64, Vec<SessionId>>,
    /// Session timeout
    timeout: Duration,
    /// Next session ID counter
    counter: AtomicU32,
}

impl Nfs4SessionManager {
    /// Create a new session manager
    pub fn new(timeout: Duration) -> Self {
        Self {
            sessions: DashMap::new(),
            sessions_by_client: DashMap::new(),
            timeout,
            counter: AtomicU32::new(1),
        }
    }

    /// Create a new session
    pub fn create_session(
        &self,
        client_id: u64,
        fore_channel: ChannelAttrs,
    ) -> Result<SessionId, NfsStatus> {
        let counter = self.counter.fetch_add(1, Ordering::SeqCst);
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&client_id.to_be_bytes());
        id[8..12].copy_from_slice(&counter.to_be_bytes());

        let session = Nfs4Session::new(id, client_id, fore_channel);
        self.sessions.insert(id, session);

        self.sessions_by_client
            .entry(client_id)
            .or_default()
            .push(id);

        Ok(id)
    }

    /// Get a session by ID
    pub fn get_session(&self, id: &SessionId) -> Option<dashmap::mapref::one::Ref<SessionId, Nfs4Session>> {
        self.sessions.get(id)
    }

    /// Destroy a session
    pub fn destroy_session(&self, id: &SessionId) -> Result<(), NfsStatus> {
        if let Some((_, session)) = self.sessions.remove(id) {
            if let Some(mut sessions) = self.sessions_by_client.get_mut(&session.client_id) {
                sessions.retain(|s| s != id);
            }
            Ok(())
        } else {
            Err(NfsStatus::BadSession)
        }
    }

    /// Get all sessions for a client
    pub fn get_client_sessions(&self, client_id: u64) -> Vec<SessionId> {
        self.sessions_by_client
            .get(&client_id)
            .map(|s| s.clone())
            .unwrap_or_default()
    }

    /// Cleanup expired sessions
    pub fn cleanup_expired(&self) -> usize {
        let mut expired = Vec::new();
        for entry in self.sessions.iter() {
            if entry.value().is_expired(self.timeout) {
                expired.push(*entry.key());
            }
        }

        for id in &expired {
            let _ = self.destroy_session(id);
        }

        expired.len()
    }
}

impl Default for Nfs4SessionManager {
    fn default() -> Self {
        Self::new(Duration::from_secs(90))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_slot_sequence() {
        let slot = SessionSlot::new();
        assert_eq!(slot.validate_sequence(0), SequenceResult::Ok);
        assert_eq!(slot.validate_sequence(1), SequenceResult::Misordered);
    }

    #[test]
    fn test_session_manager() {
        let mgr = Nfs4SessionManager::default();
        let id = mgr
            .create_session(12345, ChannelAttrs::default())
            .unwrap();

        assert!(mgr.get_session(&id).is_some());

        let sessions = mgr.get_client_sessions(12345);
        assert_eq!(sessions.len(), 1);

        mgr.destroy_session(&id).unwrap();
        assert!(mgr.get_session(&id).is_none());
    }

    #[test]
    fn test_channel_attrs_default() {
        let attrs = ChannelAttrs::default();
        assert_eq!(attrs.max_requests, 16);
        assert_eq!(attrs.max_ops, 16);
    }
}
