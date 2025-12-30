//! Delegation and oplock abstraction for protocol gateways
//!
//! Provides unified delegation management for NFS delegations and SMB oplocks.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;

use crate::error::{GatewayError, GatewayResult};
use crate::lock::FileId;
use crate::session::ClientId;

/// Delegation/oplock type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationType {
    /// Read delegation (NFS) / Level2 oplock (SMB)
    /// Client can cache reads
    Read,
    /// Write delegation (NFS) / Exclusive oplock (SMB)
    /// Client can cache reads and writes
    Write,
    /// Batch oplock (SMB only)
    /// Client can delay close
    Batch,
    /// Handle lease (SMB 2.1+)
    /// Client can delay close even after conflict
    Handle,
}

impl DelegationType {
    /// Check if this is a write/exclusive delegation
    pub fn is_exclusive(&self) -> bool {
        matches!(self, Self::Write | Self::Batch)
    }

    /// Check if this conflicts with another delegation
    pub fn conflicts_with(&self, other: &Self) -> bool {
        // Any write/exclusive delegation conflicts with any other delegation
        self.is_exclusive() || other.is_exclusive()
    }

    /// Convert NFS delegation type
    pub fn from_nfs(is_write: bool) -> Self {
        if is_write {
            Self::Write
        } else {
            Self::Read
        }
    }

    /// Convert to NFS style (read or write only)
    pub fn to_nfs(&self) -> bool {
        self.is_exclusive()
    }
}

/// Delegation state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationState {
    /// Delegation is active
    Active,
    /// Recall has been requested
    RecallPending,
    /// Delegation is being returned
    Returning,
    /// Delegation has been revoked (forced)
    Revoked,
}

/// State ID for NFS delegations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StateId {
    /// Sequence ID
    pub seqid: u32,
    /// Unique identifier
    pub other: [u8; 12],
}

impl StateId {
    /// Create a new state ID
    pub fn new(seqid: u32, other: [u8; 12]) -> Self {
        Self { seqid, other }
    }

    /// Generate a new random state ID
    pub fn generate(seqid: u32) -> Self {
        let mut other = [0u8; 12];
        // Use current time and random bytes
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        other[0..8].copy_from_slice(&(now as u64).to_le_bytes());
        other[8..12].copy_from_slice(&rand::random::<[u8; 4]>());
        Self { seqid, other }
    }

    /// Increment sequence ID
    pub fn increment(&mut self) {
        self.seqid = self.seqid.wrapping_add(1);
    }
}

mod rand {
    pub fn random<T: Default + AsMut<[u8]>>() -> T {
        let mut value = T::default();
        // Simple PRNG for testing - in production use proper random
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let bytes = value.as_mut();
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = ((seed >> (i * 8)) ^ (seed >> ((i + 4) * 8))) as u8;
        }
        value
    }
}

/// Delegation record
pub struct Delegation {
    /// State ID (for NFS)
    pub stateid: StateId,
    /// File being delegated
    pub file_id: FileId,
    /// Client holding the delegation
    pub client_id: ClientId,
    /// Type of delegation
    pub deleg_type: DelegationType,
    /// Current state
    state: DelegationState,
    /// When the delegation was granted
    pub granted_at: Instant,
    /// When recall was requested (if any)
    pub recall_at: Option<Instant>,
    /// Recall pending flag (atomic for fast checking)
    recall_pending: AtomicBool,
}

impl Delegation {
    /// Create a new delegation
    pub fn new(
        stateid: StateId,
        file_id: FileId,
        client_id: ClientId,
        deleg_type: DelegationType,
    ) -> Self {
        Self {
            stateid,
            file_id,
            client_id,
            deleg_type,
            state: DelegationState::Active,
            granted_at: Instant::now(),
            recall_at: None,
            recall_pending: AtomicBool::new(false),
        }
    }

    /// Get current state
    pub fn state(&self) -> DelegationState {
        self.state
    }

    /// Check if recall is pending
    pub fn is_recall_pending(&self) -> bool {
        self.recall_pending.load(Ordering::SeqCst)
    }

    /// Request recall
    pub fn request_recall(&mut self) {
        if self.state == DelegationState::Active {
            self.state = DelegationState::RecallPending;
            self.recall_at = Some(Instant::now());
            self.recall_pending.store(true, Ordering::SeqCst);
        }
    }

    /// Mark as returning
    pub fn mark_returning(&mut self) {
        self.state = DelegationState::Returning;
    }

    /// Mark as revoked
    pub fn revoke(&mut self) {
        self.state = DelegationState::Revoked;
    }

    /// Check if this delegation conflicts with a requested access
    pub fn conflicts_with_access(&self, want_write: bool) -> bool {
        if self.state != DelegationState::Active {
            return false;
        }
        // Write delegation conflicts with any access
        // Read delegation conflicts with write access
        self.deleg_type.is_exclusive() || want_write
    }
}

/// Delegation manager
pub struct DelegationManager {
    /// Delegations by file ID
    by_file: DashMap<FileId, Delegation>,
    /// Delegations by client ID (for cleanup)
    by_client: DashMap<ClientId, Vec<FileId>>,
    /// Next state ID sequence
    next_seqid: AtomicU64,
    /// Recall timeout (how long to wait for voluntary return)
    recall_timeout: Duration,
}

impl DelegationManager {
    /// Create a new delegation manager
    pub fn new() -> Self {
        Self {
            by_file: DashMap::new(),
            by_client: DashMap::new(),
            next_seqid: AtomicU64::new(1),
            recall_timeout: Duration::from_secs(30),
        }
    }

    /// Set recall timeout
    pub fn with_recall_timeout(mut self, timeout: Duration) -> Self {
        self.recall_timeout = timeout;
        self
    }

    /// Try to grant a delegation
    pub fn grant(
        &self,
        file_id: FileId,
        client_id: ClientId,
        deleg_type: DelegationType,
    ) -> GatewayResult<Delegation> {
        // Check for existing delegation
        if let Some(existing) = self.by_file.get(&file_id) {
            if existing.state() == DelegationState::Active {
                if existing.client_id == client_id {
                    // Same client - upgrade or keep
                    if deleg_type.is_exclusive() && !existing.deleg_type.is_exclusive() {
                        // Want to upgrade - need to recall first
                        return Err(GatewayError::DelegationConflict(
                            "upgrade requires recall".to_string(),
                        ));
                    }
                    // Return existing
                    return Ok(Delegation::new(
                        existing.stateid,
                        file_id,
                        client_id,
                        existing.deleg_type,
                    ));
                } else {
                    // Different client - conflict
                    return Err(GatewayError::DelegationConflict(
                        "file already delegated".to_string(),
                    ));
                }
            }
        }

        // Create new delegation
        let seqid = self.next_seqid.fetch_add(1, Ordering::SeqCst) as u32;
        let stateid = StateId::generate(seqid);
        let delegation = Delegation::new(stateid, file_id, client_id, deleg_type);

        // Store
        self.by_file.insert(file_id, Delegation::new(
            stateid,
            file_id,
            client_id,
            deleg_type,
        ));
        self.by_client
            .entry(client_id)
            .or_default()
            .push(file_id);

        Ok(delegation)
    }

    /// Request recall of a delegation
    pub fn recall(&self, file_id: FileId) -> GatewayResult<()> {
        if let Some(mut deleg) = self.by_file.get_mut(&file_id) {
            deleg.request_recall();
            Ok(())
        } else {
            Err(GatewayError::DelegationConflict(
                "no delegation to recall".to_string(),
            ))
        }
    }

    /// Return a delegation voluntarily
    pub fn return_delegation(&self, file_id: FileId, client_id: ClientId) -> GatewayResult<()> {
        if let Some((_, deleg)) = self.by_file.remove(&file_id) {
            if deleg.client_id != client_id {
                // Put it back - wrong client
                self.by_file.insert(file_id, deleg);
                return Err(GatewayError::PermissionDenied(
                    "not delegation owner".to_string(),
                ));
            }

            // Remove from client index
            if let Some(mut files) = self.by_client.get_mut(&client_id) {
                files.retain(|f| *f != file_id);
            }

            Ok(())
        } else {
            Err(GatewayError::DelegationConflict(
                "no delegation to return".to_string(),
            ))
        }
    }

    /// Revoke a delegation forcefully
    pub fn revoke(&self, file_id: FileId) -> Option<Delegation> {
        self.by_file.remove(&file_id).map(|(_, mut deleg)| {
            deleg.revoke();

            // Remove from client index
            if let Some(mut files) = self.by_client.get_mut(&deleg.client_id) {
                files.retain(|f| *f != file_id);
            }

            deleg
        })
    }

    /// Get delegation for a file
    pub fn get(&self, file_id: FileId) -> Option<dashmap::mapref::one::Ref<'_, FileId, Delegation>> {
        self.by_file.get(&file_id)
    }

    /// Check if file has an active delegation
    pub fn has_delegation(&self, file_id: FileId) -> bool {
        self.by_file
            .get(&file_id)
            .map(|d| d.state() == DelegationState::Active)
            .unwrap_or(false)
    }

    /// Get all delegations for a client
    pub fn client_delegations(&self, client_id: ClientId) -> Vec<FileId> {
        self.by_client
            .get(&client_id)
            .map(|files| files.clone())
            .unwrap_or_default()
    }

    /// Revoke all delegations for a client
    pub fn revoke_all(&self, client_id: ClientId) -> Vec<FileId> {
        let files = self.client_delegations(client_id);
        for file_id in &files {
            self.revoke(*file_id);
        }
        self.by_client.remove(&client_id);
        files
    }

    /// Check if access requires recall
    pub fn requires_recall(&self, file_id: FileId, want_write: bool) -> bool {
        self.by_file
            .get(&file_id)
            .map(|d| d.conflicts_with_access(want_write))
            .unwrap_or(false)
    }

    /// Clean up expired recalls
    pub fn cleanup_expired_recalls(&self) -> Vec<FileId> {
        let mut expired = Vec::new();

        for entry in self.by_file.iter() {
            if entry.state() == DelegationState::RecallPending {
                if let Some(recall_at) = entry.recall_at {
                    if recall_at.elapsed() > self.recall_timeout {
                        expired.push(*entry.key());
                    }
                }
            }
        }

        // Revoke expired
        for file_id in &expired {
            self.revoke(*file_id);
        }

        expired
    }
}

impl Default for DelegationManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grant_delegation() {
        let manager = DelegationManager::new();
        let client = ClientId::new(1);

        let deleg = manager.grant(1, client, DelegationType::Read).unwrap();
        assert_eq!(deleg.deleg_type, DelegationType::Read);
        assert!(manager.has_delegation(1));
    }

    #[test]
    fn test_delegation_conflict() {
        let manager = DelegationManager::new();

        manager.grant(1, ClientId::new(1), DelegationType::Write).unwrap();

        // Different client should fail
        assert!(manager.grant(1, ClientId::new(2), DelegationType::Read).is_err());
    }

    #[test]
    fn test_recall_and_return() {
        let manager = DelegationManager::new();
        let client = ClientId::new(1);

        manager.grant(1, client, DelegationType::Read).unwrap();
        manager.recall(1).unwrap();

        {
            let deleg = manager.get(1).unwrap();
            assert!(deleg.is_recall_pending());
        }

        manager.return_delegation(1, client).unwrap();
        assert!(!manager.has_delegation(1));
    }

    #[test]
    fn test_revoke_all() {
        let manager = DelegationManager::new();
        let client = ClientId::new(1);

        manager.grant(1, client, DelegationType::Read).unwrap();
        manager.grant(2, client, DelegationType::Write).unwrap();

        let revoked = manager.revoke_all(client);
        assert_eq!(revoked.len(), 2);
        assert!(!manager.has_delegation(1));
        assert!(!manager.has_delegation(2));
    }
}
