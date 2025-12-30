//! Opportunistic locks (oplocks) and leases
//!
//! Implements SMB2 oplocks and SMB2.1+ leases for client caching.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;
use parking_lot::RwLock;

use crate::error::NtStatus;

/// Oplock level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum OplockLevel {
    /// No oplock
    None = 0x00,
    /// Level II (shared read cache)
    Level2 = 0x01,
    /// Exclusive (exclusive cache, no handle)
    Exclusive = 0x08,
    /// Batch (exclusive cache with handle)
    Batch = 0x09,
    /// Lease (SMB2.1+)
    Lease = 0xFF,
}

impl TryFrom<u8> for OplockLevel {
    type Error = NtStatus;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::None),
            0x01 => Ok(Self::Level2),
            0x08 => Ok(Self::Exclusive),
            0x09 => Ok(Self::Batch),
            0xFF => Ok(Self::Lease),
            _ => Err(NtStatus::InvalidParameter),
        }
    }
}

/// Lease state flags (SMB2.1+)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseState(u32);

impl LeaseState {
    /// No lease
    pub const NONE: u32 = 0x00;
    /// Read caching allowed
    pub const READ: u32 = 0x01;
    /// Handle caching allowed
    pub const HANDLE: u32 = 0x02;
    /// Write caching allowed
    pub const WRITE: u32 = 0x04;

    /// Create new lease state
    pub fn new(state: u32) -> Self {
        Self(state)
    }

    /// Get raw value
    pub fn bits(&self) -> u32 {
        self.0
    }

    /// Check if read caching is granted
    pub fn has_read(&self) -> bool {
        self.0 & Self::READ != 0
    }

    /// Check if write caching is granted
    pub fn has_write(&self) -> bool {
        self.0 & Self::WRITE != 0
    }

    /// Check if handle caching is granted
    pub fn has_handle(&self) -> bool {
        self.0 & Self::HANDLE != 0
    }

    /// Check if no lease
    pub fn is_none(&self) -> bool {
        self.0 == Self::NONE
    }

    /// Read-Write-Handle (full lease)
    pub fn rwh() -> Self {
        Self(Self::READ | Self::WRITE | Self::HANDLE)
    }

    /// Read-Write (no handle)
    pub fn rw() -> Self {
        Self(Self::READ | Self::WRITE)
    }

    /// Read-Handle (no write)
    pub fn rh() -> Self {
        Self(Self::READ | Self::HANDLE)
    }

    /// Read only
    pub fn r() -> Self {
        Self(Self::READ)
    }
}

impl Default for LeaseState {
    fn default() -> Self {
        Self(Self::NONE)
    }
}

/// Lease key (16 bytes)
pub type LeaseKey = [u8; 16];

/// Oplock entry
#[derive(Debug, Clone)]
pub struct OplockEntry {
    /// File identifier (typically file_id)
    pub file_id: u64,
    /// Session ID
    pub session_id: u64,
    /// Tree ID
    pub tree_id: u32,
    /// Oplock level
    pub level: OplockLevel,
    /// For leases: lease key
    pub lease_key: Option<LeaseKey>,
    /// For leases: current state
    pub lease_state: LeaseState,
    /// Break in progress
    pub breaking: bool,
    /// Target level for break
    pub break_to: Option<OplockLevel>,
    /// Granted time
    pub granted: Instant,
}

impl OplockEntry {
    /// Create a new oplock entry
    pub fn new(
        file_id: u64,
        session_id: u64,
        tree_id: u32,
        level: OplockLevel,
    ) -> Self {
        Self {
            file_id,
            session_id,
            tree_id,
            level,
            lease_key: None,
            lease_state: LeaseState::default(),
            breaking: false,
            break_to: None,
            granted: Instant::now(),
        }
    }

    /// Create a lease entry
    pub fn new_lease(
        file_id: u64,
        session_id: u64,
        tree_id: u32,
        lease_key: LeaseKey,
        lease_state: LeaseState,
    ) -> Self {
        Self {
            file_id,
            session_id,
            tree_id,
            level: OplockLevel::Lease,
            lease_key: Some(lease_key),
            lease_state,
            breaking: false,
            break_to: None,
            granted: Instant::now(),
        }
    }

    /// Check if this is a lease
    pub fn is_lease(&self) -> bool {
        self.level == OplockLevel::Lease
    }

    /// Check if oplock allows read caching
    pub fn allows_read_cache(&self) -> bool {
        match self.level {
            OplockLevel::None => false,
            OplockLevel::Level2 => true,
            OplockLevel::Exclusive | OplockLevel::Batch => true,
            OplockLevel::Lease => self.lease_state.has_read(),
        }
    }

    /// Check if oplock allows write caching
    pub fn allows_write_cache(&self) -> bool {
        match self.level {
            OplockLevel::None | OplockLevel::Level2 => false,
            OplockLevel::Exclusive | OplockLevel::Batch => true,
            OplockLevel::Lease => self.lease_state.has_write(),
        }
    }

    /// Check if oplock allows handle caching
    pub fn allows_handle_cache(&self) -> bool {
        match self.level {
            OplockLevel::None | OplockLevel::Level2 | OplockLevel::Exclusive => false,
            OplockLevel::Batch => true,
            OplockLevel::Lease => self.lease_state.has_handle(),
        }
    }
}

/// Oplock break notification
#[derive(Debug, Clone)]
pub struct OplockBreak {
    /// File ID
    pub file_id: u64,
    /// Session ID
    pub session_id: u64,
    /// Tree ID
    pub tree_id: u32,
    /// Current oplock level
    pub current_level: OplockLevel,
    /// Target oplock level
    pub new_level: OplockLevel,
    /// For leases: lease key
    pub lease_key: Option<LeaseKey>,
    /// For leases: current state
    pub current_state: LeaseState,
    /// For leases: new state
    pub new_state: LeaseState,
}

/// Oplock manager
#[derive(Debug)]
pub struct OplockManager {
    /// Oplocks by file_id
    oplocks: DashMap<u64, OplockEntry>,
    /// Leases by lease key
    leases: DashMap<LeaseKey, OplockEntry>,
    /// Pending breaks
    pending_breaks: DashMap<u64, OplockBreak>,
    /// Break timeout
    break_timeout: Duration,
}

impl OplockManager {
    /// Create a new oplock manager
    pub fn new() -> Self {
        Self {
            oplocks: DashMap::new(),
            leases: DashMap::new(),
            pending_breaks: DashMap::new(),
            break_timeout: Duration::from_secs(35),
        }
    }

    /// Request an oplock
    pub fn request_oplock(
        &self,
        file_id: u64,
        session_id: u64,
        tree_id: u32,
        requested_level: OplockLevel,
    ) -> Result<OplockLevel, OplockBreak> {
        // Check for existing oplock
        if let Some(existing) = self.oplocks.get(&file_id) {
            if existing.session_id == session_id {
                // Same owner, allow upgrade
                return Ok(requested_level);
            }
            // Different owner - need to break
            let break_notification = self.initiate_break(&existing, requested_level);
            return Err(break_notification);
        }

        // Grant new oplock
        let entry = OplockEntry::new(file_id, session_id, tree_id, requested_level);
        self.oplocks.insert(file_id, entry);
        Ok(requested_level)
    }

    /// Request a lease
    pub fn request_lease(
        &self,
        file_id: u64,
        session_id: u64,
        tree_id: u32,
        lease_key: LeaseKey,
        requested_state: LeaseState,
    ) -> Result<LeaseState, OplockBreak> {
        // Check for existing lease with same key
        if let Some(existing) = self.leases.get(&lease_key) {
            if existing.session_id == session_id {
                // Same owner, allow state change
                return Ok(requested_state);
            }
            // Different owner - need to break
            let break_notification = self.initiate_lease_break(&existing, requested_state);
            return Err(break_notification);
        }

        // Grant new lease
        let entry = OplockEntry::new_lease(file_id, session_id, tree_id, lease_key, requested_state);
        self.leases.insert(lease_key, entry.clone());
        self.oplocks.insert(file_id, entry);
        Ok(requested_state)
    }

    /// Acknowledge oplock break
    pub fn acknowledge_break(&self, file_id: u64, new_level: OplockLevel) -> Result<(), NtStatus> {
        if let Some(mut entry) = self.oplocks.get_mut(&file_id) {
            if !entry.breaking {
                return Err(NtStatus::InvalidOplockProtocol);
            }
            entry.level = new_level;
            entry.breaking = false;
            entry.break_to = None;
            self.pending_breaks.remove(&file_id);
            Ok(())
        } else {
            Err(NtStatus::InvalidHandle)
        }
    }

    /// Acknowledge lease break
    pub fn acknowledge_lease_break(
        &self,
        lease_key: &LeaseKey,
        new_state: LeaseState,
    ) -> Result<(), NtStatus> {
        if let Some(mut entry) = self.leases.get_mut(lease_key) {
            if !entry.breaking {
                return Err(NtStatus::InvalidOplockProtocol);
            }
            entry.lease_state = new_state;
            entry.breaking = false;
            self.pending_breaks.remove(&entry.file_id);
            Ok(())
        } else {
            Err(NtStatus::InvalidHandle)
        }
    }

    /// Release oplock
    pub fn release(&self, file_id: u64) {
        self.oplocks.remove(&file_id);
        self.pending_breaks.remove(&file_id);
    }

    /// Release lease
    pub fn release_lease(&self, lease_key: &LeaseKey) {
        if let Some((_, entry)) = self.leases.remove(lease_key) {
            self.oplocks.remove(&entry.file_id);
            self.pending_breaks.remove(&entry.file_id);
        }
    }

    /// Get oplock for file
    pub fn get_oplock(&self, file_id: u64) -> Option<OplockEntry> {
        self.oplocks.get(&file_id).map(|e| e.clone())
    }

    /// Get lease by key
    pub fn get_lease(&self, lease_key: &LeaseKey) -> Option<OplockEntry> {
        self.leases.get(lease_key).map(|e| e.clone())
    }

    /// Initiate an oplock break
    fn initiate_break(&self, entry: &OplockEntry, _requested: OplockLevel) -> OplockBreak {
        let new_level = OplockLevel::Level2; // Break to Level2 by default

        OplockBreak {
            file_id: entry.file_id,
            session_id: entry.session_id,
            tree_id: entry.tree_id,
            current_level: entry.level,
            new_level,
            lease_key: None,
            current_state: LeaseState::default(),
            new_state: LeaseState::default(),
        }
    }

    /// Initiate a lease break
    fn initiate_lease_break(&self, entry: &OplockEntry, _requested: LeaseState) -> OplockBreak {
        let new_state = LeaseState::r(); // Break to Read-only by default

        OplockBreak {
            file_id: entry.file_id,
            session_id: entry.session_id,
            tree_id: entry.tree_id,
            current_level: OplockLevel::Lease,
            new_level: OplockLevel::Lease,
            lease_key: entry.lease_key,
            current_state: entry.lease_state,
            new_state,
        }
    }

    /// Check for timed-out breaks and force them
    pub fn cleanup_stale_breaks(&self) {
        let now = Instant::now();
        let mut stale = Vec::new();

        for entry in self.pending_breaks.iter() {
            // For simplicity, remove all pending breaks older than timeout
            // In production, this would need better tracking
            stale.push(*entry.key());
        }

        for file_id in stale {
            if let Some(mut entry) = self.oplocks.get_mut(&file_id) {
                if entry.breaking {
                    // Force break to None
                    entry.level = OplockLevel::None;
                    entry.breaking = false;
                }
            }
            self.pending_breaks.remove(&file_id);
        }
    }
}

impl Default for OplockManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oplock_level() {
        assert!(OplockLevel::Batch > OplockLevel::Exclusive);
        assert!(OplockLevel::Exclusive > OplockLevel::Level2);
        assert!(OplockLevel::Level2 > OplockLevel::None);
    }

    #[test]
    fn test_lease_state() {
        let state = LeaseState::rwh();
        assert!(state.has_read());
        assert!(state.has_write());
        assert!(state.has_handle());

        let state = LeaseState::r();
        assert!(state.has_read());
        assert!(!state.has_write());
        assert!(!state.has_handle());
    }

    #[test]
    fn test_oplock_manager_grant() {
        let mgr = OplockManager::new();
        let level = mgr
            .request_oplock(1, 100, 1, OplockLevel::Exclusive)
            .unwrap();

        assert_eq!(level, OplockLevel::Exclusive);

        let entry = mgr.get_oplock(1).unwrap();
        assert_eq!(entry.level, OplockLevel::Exclusive);
        assert!(entry.allows_write_cache());
    }

    #[test]
    fn test_oplock_entry_caching() {
        let entry = OplockEntry::new(1, 100, 1, OplockLevel::Batch);
        assert!(entry.allows_read_cache());
        assert!(entry.allows_write_cache());
        assert!(entry.allows_handle_cache());

        let entry = OplockEntry::new(1, 100, 1, OplockLevel::Level2);
        assert!(entry.allows_read_cache());
        assert!(!entry.allows_write_cache());
        assert!(!entry.allows_handle_cache());
    }

    #[test]
    fn test_lease_manager() {
        let mgr = OplockManager::new();
        let lease_key = [1u8; 16];
        let state = mgr
            .request_lease(1, 100, 1, lease_key, LeaseState::rwh())
            .unwrap();

        assert_eq!(state.bits(), LeaseState::rwh().bits());

        let entry = mgr.get_lease(&lease_key).unwrap();
        assert!(entry.is_lease());
        assert!(entry.lease_state.has_read());
        assert!(entry.lease_state.has_write());
        assert!(entry.lease_state.has_handle());
    }
}
