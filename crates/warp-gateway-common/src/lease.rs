//! Lease management for protocol gateways
//!
//! Provides time-based lease management for NFS and SMB protocols.
//! Leases grant clients temporary exclusive or shared access rights.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;

use crate::error::{GatewayError, GatewayResult};
use crate::lock::FileId;
use crate::session::ClientId;

/// Lease state flags (SMB 2.1 style)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseState(u32);

impl LeaseState {
    /// No lease
    pub const NONE: Self = Self(0);
    /// Read caching (client can cache reads)
    pub const READ: Self = Self(0x01);
    /// Write caching (client can cache writes)
    pub const WRITE: Self = Self(0x02);
    /// Handle caching (client can delay close)
    pub const HANDLE: Self = Self(0x04);

    /// Read + Write
    pub const READ_WRITE: Self = Self(0x03);
    /// Read + Write + Handle
    pub const READ_WRITE_HANDLE: Self = Self(0x07);

    /// Create from raw value
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Get raw value
    pub const fn value(&self) -> u32 {
        self.0
    }

    /// Check if state includes read caching
    pub const fn has_read(&self) -> bool {
        (self.0 & Self::READ.0) != 0
    }

    /// Check if state includes write caching
    pub const fn has_write(&self) -> bool {
        (self.0 & Self::WRITE.0) != 0
    }

    /// Check if state includes handle caching
    pub const fn has_handle(&self) -> bool {
        (self.0 & Self::HANDLE.0) != 0
    }

    /// Check if this is an empty/no lease
    pub const fn is_none(&self) -> bool {
        self.0 == 0
    }

    /// Combine with another state
    pub const fn with(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Remove flags
    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Check if state conflicts with another (for breaking)
    pub fn conflicts_with(&self, other: &Self) -> bool {
        // Write conflicts with read/write
        // Handle conflicts with nothing by itself
        (self.has_write() && (other.has_read() || other.has_write()))
            || (other.has_write() && (self.has_read() || self.has_write()))
    }

    /// Compute what state must be broken for a new request
    pub fn break_to(&self, requested: &Self) -> Self {
        if !self.conflicts_with(requested) {
            return *self; // No break needed
        }

        let mut new_state = *self;

        // If requester wants write, existing must give up write
        if requested.has_write() {
            new_state = new_state.without(Self::WRITE);
        }

        // If requester wants read or write, existing exclusive must break
        if requested.has_read() || requested.has_write() {
            if self.has_write() {
                new_state = new_state.without(Self::WRITE);
            }
        }

        new_state
    }
}

/// Lease key (SMB uses 16-byte client-chosen key)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LeaseKey([u8; 16]);

impl LeaseKey {
    /// Create from bytes
    pub fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Create from client ID and a sequence
    pub fn from_client(client_id: ClientId, seq: u64) -> Self {
        let mut bytes = [0u8; 16];
        bytes[0..8].copy_from_slice(&client_id.value().to_le_bytes());
        bytes[8..16].copy_from_slice(&seq.to_le_bytes());
        Self(bytes)
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Lease record
pub struct Lease {
    /// Lease key
    pub key: LeaseKey,
    /// Client holding the lease
    pub client_id: ClientId,
    /// Current state
    pub state: LeaseState,
    /// Files under this lease
    pub files: Vec<FileId>,
    /// When the lease was granted
    pub granted_at: Instant,
    /// Lease expiration
    pub expires_at: Instant,
    /// Parent lease key (for directory leases)
    pub parent_key: Option<LeaseKey>,
    /// Break notification pending
    pub break_pending: bool,
    /// State to break to (if break is pending)
    pub break_to: LeaseState,
}

impl Lease {
    /// Create a new lease
    pub fn new(key: LeaseKey, client_id: ClientId, state: LeaseState, duration: Duration) -> Self {
        let now = Instant::now();
        Self {
            key,
            client_id,
            state,
            files: Vec::new(),
            granted_at: now,
            expires_at: now + duration,
            parent_key: None,
            break_pending: false,
            break_to: LeaseState::NONE,
        }
    }

    /// Check if lease has expired
    pub fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }

    /// Renew the lease
    pub fn renew(&mut self, duration: Duration) {
        self.expires_at = Instant::now() + duration;
    }

    /// Add a file to this lease
    pub fn add_file(&mut self, file_id: FileId) {
        if !self.files.contains(&file_id) {
            self.files.push(file_id);
        }
    }

    /// Remove a file from this lease
    pub fn remove_file(&mut self, file_id: FileId) {
        self.files.retain(|f| *f != file_id);
    }

    /// Initiate a break to a new state
    pub fn break_to_state(&mut self, new_state: LeaseState) {
        self.break_pending = true;
        self.break_to = new_state;
    }

    /// Acknowledge the break
    pub fn acknowledge_break(&mut self) {
        self.state = self.break_to;
        self.break_pending = false;
        self.break_to = LeaseState::NONE;
    }
}

/// Lease manager
pub struct LeaseManager {
    /// Leases by key
    leases: DashMap<LeaseKey, Lease>,
    /// Leases by client
    by_client: DashMap<ClientId, Vec<LeaseKey>>,
    /// Leases by file
    by_file: DashMap<FileId, Vec<LeaseKey>>,
    /// Default lease duration
    lease_duration: Duration,
    /// Next sequence for generating keys
    next_seq: AtomicU64,
}

impl LeaseManager {
    /// Create a new lease manager
    pub fn new(lease_duration: Duration) -> Self {
        Self {
            leases: DashMap::new(),
            by_client: DashMap::new(),
            by_file: DashMap::new(),
            lease_duration,
            next_seq: AtomicU64::new(1),
        }
    }

    /// Generate a new lease key for a client
    pub fn generate_key(&self, client_id: ClientId) -> LeaseKey {
        let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);
        LeaseKey::from_client(client_id, seq)
    }

    /// Request a lease
    pub fn request(
        &self,
        key: LeaseKey,
        client_id: ClientId,
        state: LeaseState,
        files: Vec<FileId>,
    ) -> GatewayResult<LeaseState> {
        // Check for conflicts with existing leases on these files
        let mut granted_state = state;

        for file_id in &files {
            if let Some(existing_keys) = self.by_file.get(file_id) {
                for existing_key in existing_keys.iter() {
                    if *existing_key == key {
                        continue; // Same lease
                    }

                    if let Some(existing) = self.leases.get(existing_key) {
                        if existing.state.conflicts_with(&state) {
                            // Need to break the existing lease
                            let break_to = existing.state.break_to(&state);
                            granted_state = granted_state.without(LeaseState::WRITE);

                            // Initiate break (would normally notify client)
                            drop(existing);
                            if let Some(mut e) = self.leases.get_mut(existing_key) {
                                e.break_to_state(break_to);
                            }
                        }
                    }
                }
            }
        }

        // Create or update lease
        if let Some(mut existing) = self.leases.get_mut(&key) {
            // Update existing
            existing.state = existing.state.with(granted_state);
            existing.renew(self.lease_duration);
            for file_id in files {
                existing.add_file(file_id);
            }
        } else {
            // Create new
            let mut lease = Lease::new(key, client_id, granted_state, self.lease_duration);
            lease.files = files.clone();

            self.leases.insert(key, lease);
            self.by_client.entry(client_id).or_default().push(key);

            for file_id in &files {
                self.by_file.entry(*file_id).or_default().push(key);
            }
        }

        Ok(granted_state)
    }

    /// Renew a lease
    pub fn renew(&self, key: LeaseKey) -> GatewayResult<()> {
        if let Some(mut lease) = self.leases.get_mut(&key) {
            lease.renew(self.lease_duration);
            Ok(())
        } else {
            Err(GatewayError::LeaseExpired("lease not found".to_string()))
        }
    }

    /// Release a lease
    pub fn release(&self, key: LeaseKey) -> GatewayResult<()> {
        if let Some((_, lease)) = self.leases.remove(&key) {
            // Remove from client index
            if let Some(mut keys) = self.by_client.get_mut(&lease.client_id) {
                keys.retain(|k| *k != key);
            }

            // Remove from file index
            for file_id in &lease.files {
                if let Some(mut keys) = self.by_file.get_mut(file_id) {
                    keys.retain(|k| *k != key);
                }
            }

            Ok(())
        } else {
            Err(GatewayError::LeaseExpired("lease not found".to_string()))
        }
    }

    /// Get a lease
    pub fn get(&self, key: LeaseKey) -> Option<dashmap::mapref::one::Ref<'_, LeaseKey, Lease>> {
        self.leases.get(&key)
    }

    /// Get leases for a file
    pub fn get_file_leases(&self, file_id: FileId) -> Vec<LeaseKey> {
        self.by_file
            .get(&file_id)
            .map(|keys| keys.clone())
            .unwrap_or_default()
    }

    /// Expire old leases
    pub fn expire_leases(&self) -> Vec<LeaseKey> {
        let expired: Vec<LeaseKey> = self
            .leases
            .iter()
            .filter(|entry| entry.is_expired())
            .map(|entry| *entry.key())
            .collect();

        for key in &expired {
            let _ = self.release(*key);
        }

        expired
    }

    /// Release all leases for a client
    pub fn release_client(&self, client_id: ClientId) -> Vec<LeaseKey> {
        let keys: Vec<LeaseKey> = self
            .by_client
            .remove(&client_id)
            .map(|(_, keys)| keys)
            .unwrap_or_default();

        for key in &keys {
            let _ = self.release(*key);
        }

        keys
    }
}

impl Default for LeaseManager {
    fn default() -> Self {
        Self::new(Duration::from_secs(300)) // 5 minute default
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lease_state_operations() {
        let state = LeaseState::READ.with(LeaseState::WRITE);
        assert!(state.has_read());
        assert!(state.has_write());
        assert!(!state.has_handle());

        let state = state.without(LeaseState::WRITE);
        assert!(state.has_read());
        assert!(!state.has_write());
    }

    #[test]
    fn test_lease_request() {
        let manager = LeaseManager::default();
        let client = ClientId::new(1);
        let key = manager.generate_key(client);

        let granted = manager
            .request(key, client, LeaseState::READ_WRITE, vec![1, 2])
            .unwrap();

        assert!(granted.has_read());
        assert!(granted.has_write());
    }

    #[test]
    fn test_lease_conflict() {
        let manager = LeaseManager::default();

        let client1 = ClientId::new(1);
        let key1 = manager.generate_key(client1);
        manager
            .request(key1, client1, LeaseState::READ_WRITE, vec![1])
            .unwrap();

        // Second client requests write - should cause break
        let client2 = ClientId::new(2);
        let key2 = manager.generate_key(client2);
        let granted = manager
            .request(key2, client2, LeaseState::WRITE, vec![1])
            .unwrap();

        // Write was removed due to conflict
        assert!(!granted.has_write());
    }

    #[test]
    fn test_lease_release() {
        let manager = LeaseManager::default();
        let client = ClientId::new(1);
        let key = manager.generate_key(client);

        manager
            .request(key, client, LeaseState::READ, vec![1])
            .unwrap();
        assert!(manager.get(key).is_some());

        manager.release(key).unwrap();
        assert!(manager.get(key).is_none());
    }
}
