//! NFSv4.1 state management
//!
//! Manages open files, locks, delegations, and layout state.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::RwLock;

use super::{Nfs4FileHandle, StateId};
use crate::error::NfsStatus;

/// Open state for a file
#[derive(Debug, Clone)]
pub struct OpenState {
    /// Stateid for this open
    pub stateid: StateId,
    /// Filehandle
    pub filehandle: Nfs4FileHandle,
    /// Client ID
    pub client_id: u64,
    /// Open owner
    pub owner: OpenOwner,
    /// Share access mode
    pub share_access: ShareAccess,
    /// Share deny mode
    pub share_deny: ShareDeny,
    /// Creation time
    pub created: Instant,
    /// Last access time
    pub last_access: Instant,
}

impl OpenState {
    /// Create a new open state
    pub fn new(
        stateid: StateId,
        filehandle: Nfs4FileHandle,
        client_id: u64,
        owner: OpenOwner,
        share_access: ShareAccess,
        share_deny: ShareDeny,
    ) -> Self {
        let now = Instant::now();
        Self {
            stateid,
            filehandle,
            client_id,
            owner,
            share_access,
            share_deny,
            created: now,
            last_access: now,
        }
    }

    /// Check if read access is allowed
    pub fn can_read(&self) -> bool {
        self.share_access.contains(ShareAccess::READ)
    }

    /// Check if write access is allowed
    pub fn can_write(&self) -> bool {
        self.share_access.contains(ShareAccess::WRITE)
    }
}

/// Open owner (identifies the open owner at the client)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OpenOwner {
    /// Client ID
    pub client_id: u64,
    /// Owner identifier (opaque)
    pub owner: Vec<u8>,
}

impl OpenOwner {
    /// Create a new open owner
    pub fn new(client_id: u64, owner: Vec<u8>) -> Self {
        Self { client_id, owner }
    }
}

/// Share access mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShareAccess(u32);

impl ShareAccess {
    /// Read access
    pub const READ: Self = Self(0x00000001);
    /// Write access
    pub const WRITE: Self = Self(0x00000002);
    /// Both read and write
    pub const BOTH: Self = Self(0x00000003);
    /// Want read delegation
    pub const WANT_READ_DELEG: Self = Self(0x00000100);
    /// Want write delegation
    pub const WANT_WRITE_DELEG: Self = Self(0x00000200);
    /// Want any delegation
    pub const WANT_ANY_DELEG: Self = Self(0x00000300);
    /// Want no delegation
    pub const WANT_NO_DELEG: Self = Self(0x00000400);
    /// Want cancel
    pub const WANT_CANCEL: Self = Self(0x00000500);
    /// Signal deleg when resrc avail
    pub const WANT_SIGNAL_DELEG_WHEN_RESRC_AVAIL: Self = Self(0x00010000);
    /// Push deleg when uncontended
    pub const WANT_PUSH_DELEG_WHEN_UNCONTENDED: Self = Self(0x00020000);

    /// Check if contains a flag
    pub fn contains(&self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    /// Get raw value
    pub fn bits(&self) -> u32 {
        self.0
    }

    /// Create from raw value
    pub fn from_bits(bits: u32) -> Self {
        Self(bits)
    }
}

/// Share deny mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShareDeny(u32);

impl ShareDeny {
    /// No deny
    pub const NONE: Self = Self(0x00000000);
    /// Deny read
    pub const READ: Self = Self(0x00000001);
    /// Deny write
    pub const WRITE: Self = Self(0x00000002);
    /// Deny both
    pub const BOTH: Self = Self(0x00000003);

    /// Check if contains a flag
    pub fn contains(&self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    /// Get raw value
    pub fn bits(&self) -> u32 {
        self.0
    }

    /// Create from raw value
    pub fn from_bits(bits: u32) -> Self {
        Self(bits)
    }
}

/// Lock state
#[derive(Debug, Clone)]
pub struct LockState {
    /// Stateid for this lock
    pub stateid: StateId,
    /// Open stateid this lock is associated with
    pub open_stateid: StateId,
    /// Lock owner
    pub owner: LockOwner,
    /// Lock type
    pub lock_type: LockType,
    /// Offset
    pub offset: u64,
    /// Length (0 = EOF)
    pub length: u64,
}

/// Lock owner
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LockOwner {
    /// Client ID
    pub client_id: u64,
    /// Owner identifier (opaque)
    pub owner: Vec<u8>,
}

impl LockOwner {
    /// Create a new lock owner
    pub fn new(client_id: u64, owner: Vec<u8>) -> Self {
        Self { client_id, owner }
    }
}

/// Lock type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LockType {
    /// Read lock
    ReadLt = 1,
    /// Write lock
    WriteLt = 2,
    /// Read lock with wait
    ReadW = 3,
    /// Write lock with wait
    WriteW = 4,
}

impl TryFrom<u32> for LockType {
    type Error = NfsStatus;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::ReadLt),
            2 => Ok(Self::WriteLt),
            3 => Ok(Self::ReadW),
            4 => Ok(Self::WriteW),
            _ => Err(NfsStatus::Inval),
        }
    }
}

impl LockType {
    /// Check if this is a write lock
    pub fn is_write(&self) -> bool {
        matches!(self, Self::WriteLt | Self::WriteW)
    }

    /// Check if this lock should block
    pub fn should_wait(&self) -> bool {
        matches!(self, Self::ReadW | Self::WriteW)
    }
}

/// Delegation state
#[derive(Debug, Clone)]
pub struct DelegationState {
    /// Stateid for this delegation
    pub stateid: StateId,
    /// Filehandle
    pub filehandle: Nfs4FileHandle,
    /// Client ID
    pub client_id: u64,
    /// Delegation type
    pub deleg_type: DelegationType,
    /// Recall in progress
    pub recalling: bool,
}

/// Delegation type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DelegationType {
    /// No delegation
    None = 0,
    /// Read delegation
    Read = 1,
    /// Write delegation
    Write = 2,
}

impl TryFrom<u32> for DelegationType {
    type Error = NfsStatus;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Read),
            2 => Ok(Self::Write),
            _ => Err(NfsStatus::Inval),
        }
    }
}

/// NFSv4.1 state manager
#[derive(Debug)]
pub struct Nfs4StateManager {
    /// Open states by stateid
    opens: DashMap<[u8; 12], OpenState>,
    /// Lock states by stateid
    locks: DashMap<[u8; 12], LockState>,
    /// Delegations by stateid
    delegations: DashMap<[u8; 12], DelegationState>,
    /// State counter for generating stateids
    counter: AtomicU64,
}

impl Nfs4StateManager {
    /// Create a new state manager
    pub fn new() -> Self {
        Self {
            opens: DashMap::new(),
            locks: DashMap::new(),
            delegations: DashMap::new(),
            counter: AtomicU64::new(1),
        }
    }

    /// Generate a new stateid
    pub fn generate_stateid(&self) -> StateId {
        let counter = self.counter.fetch_add(1, Ordering::SeqCst);
        let mut other = [0u8; 12];
        other[..8].copy_from_slice(&counter.to_be_bytes());
        StateId::new(1, other)
    }

    /// Create a new open state
    pub fn create_open(
        &self,
        filehandle: Nfs4FileHandle,
        client_id: u64,
        owner: OpenOwner,
        share_access: ShareAccess,
        share_deny: ShareDeny,
    ) -> StateId {
        let stateid = self.generate_stateid();
        let state = OpenState::new(
            stateid,
            filehandle,
            client_id,
            owner,
            share_access,
            share_deny,
        );
        self.opens.insert(stateid.other, state);
        stateid
    }

    /// Get open state by stateid
    pub fn get_open(&self, stateid: &StateId) -> Option<OpenState> {
        self.opens.get(&stateid.other).map(|s| s.clone())
    }

    /// Remove open state
    pub fn remove_open(&self, stateid: &StateId) -> Option<OpenState> {
        self.opens.remove(&stateid.other).map(|(_, s)| s)
    }

    /// Create a new lock state
    pub fn create_lock(
        &self,
        open_stateid: StateId,
        owner: LockOwner,
        lock_type: LockType,
        offset: u64,
        length: u64,
    ) -> StateId {
        let stateid = self.generate_stateid();
        let state = LockState {
            stateid,
            open_stateid,
            owner,
            lock_type,
            offset,
            length,
        };
        self.locks.insert(stateid.other, state);
        stateid
    }

    /// Get lock state by stateid
    pub fn get_lock(&self, stateid: &StateId) -> Option<LockState> {
        self.locks.get(&stateid.other).map(|s| s.clone())
    }

    /// Remove lock state
    pub fn remove_lock(&self, stateid: &StateId) -> Option<LockState> {
        self.locks.remove(&stateid.other).map(|(_, s)| s)
    }

    /// Create a new delegation
    pub fn create_delegation(
        &self,
        filehandle: Nfs4FileHandle,
        client_id: u64,
        deleg_type: DelegationType,
    ) -> StateId {
        let stateid = self.generate_stateid();
        let state = DelegationState {
            stateid,
            filehandle,
            client_id,
            deleg_type,
            recalling: false,
        };
        self.delegations.insert(stateid.other, state);
        stateid
    }

    /// Get delegation state
    pub fn get_delegation(&self, stateid: &StateId) -> Option<DelegationState> {
        self.delegations.get(&stateid.other).map(|s| s.clone())
    }

    /// Remove delegation
    pub fn remove_delegation(&self, stateid: &StateId) -> Option<DelegationState> {
        self.delegations.remove(&stateid.other).map(|(_, s)| s)
    }

    /// Free all state for a client
    pub fn free_client_state(&self, client_id: u64) {
        self.opens.retain(|_, v| v.client_id != client_id);
        self.locks.retain(|_, v| v.owner.client_id != client_id);
        self.delegations.retain(|_, v| v.client_id != client_id);
    }
}

impl Default for Nfs4StateManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn test_share_access() {
        let access = ShareAccess::BOTH;
        assert!(access.contains(ShareAccess::READ));
        assert!(access.contains(ShareAccess::WRITE));
    }

    #[test]
    fn test_lock_type() {
        assert!(LockType::WriteLt.is_write());
        assert!(!LockType::ReadLt.is_write());
        assert!(LockType::ReadW.should_wait());
        assert!(!LockType::ReadLt.should_wait());
    }

    #[test]
    fn test_state_manager_open() {
        let mgr = Nfs4StateManager::new();
        let fh = Nfs4FileHandle::new(vec![1, 2, 3]);
        let owner = OpenOwner::new(1, vec![1, 2, 3]);

        let stateid = mgr.create_open(fh, 1, owner, ShareAccess::READ, ShareDeny::NONE);

        let state = mgr.get_open(&stateid).unwrap();
        assert!(state.can_read());
        assert!(!state.can_write());
    }

    #[test]
    fn test_state_manager_lock() {
        let mgr = Nfs4StateManager::new();
        let open_stateid = mgr.generate_stateid();
        let owner = LockOwner::new(1, vec![1, 2, 3]);

        let stateid = mgr.create_lock(open_stateid, owner, LockType::WriteLt, 0, 100);

        let state = mgr.get_lock(&stateid).unwrap();
        assert_eq!(state.lock_type, LockType::WriteLt);
        assert_eq!(state.offset, 0);
        assert_eq!(state.length, 100);
    }
}
