//! Distributed lock manager for protocol gateways
//!
//! Provides byte-range and whole-file locking for NFS and SMB protocols.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use dashmap::DashMap;
use parking_lot::RwLock;

use crate::error::{GatewayError, GatewayResult};
use crate::session::ClientId;

/// Unique identifier for a file (inode number)
pub type FileId = u64;

/// Lock token for tracking active locks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LockToken(u64);

impl LockToken {
    /// Create a new lock token
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    /// Get the token value
    pub fn value(&self) -> u64 {
        self.0
    }
}

/// Lock mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockMode {
    /// Shared/read lock (multiple allowed)
    Shared,
    /// Exclusive/write lock (single holder)
    Exclusive,
}

/// Byte-range lock
#[derive(Debug, Clone)]
pub struct ByteRangeLock {
    /// Lock token
    pub token: LockToken,
    /// Lock owner (client)
    pub owner: ClientId,
    /// File being locked
    pub file_id: FileId,
    /// Start offset (0 = beginning)
    pub offset: u64,
    /// Length of range (0 = to end of file)
    pub length: u64,
    /// Lock mode
    pub mode: LockMode,
    /// When the lock was acquired
    pub acquired_at: Instant,
    /// When the lock expires (None = no expiry)
    pub expires: Option<Instant>,
}

impl ByteRangeLock {
    /// Create a new byte-range lock
    pub fn new(
        token: LockToken,
        owner: ClientId,
        file_id: FileId,
        offset: u64,
        length: u64,
        mode: LockMode,
    ) -> Self {
        Self {
            token,
            owner,
            file_id,
            offset,
            length,
            mode,
            acquired_at: Instant::now(),
            expires: None,
        }
    }

    /// Set expiration time
    pub fn with_expiry(mut self, duration: Duration) -> Self {
        self.expires = Some(Instant::now() + duration);
        self
    }

    /// Check if lock has expired
    pub fn is_expired(&self) -> bool {
        self.expires.map_or(false, |exp| Instant::now() > exp)
    }

    /// Check if this lock overlaps with a range
    pub fn overlaps(&self, offset: u64, length: u64) -> bool {
        let self_end = if self.length == 0 {
            u64::MAX
        } else {
            self.offset.saturating_add(self.length)
        };
        let other_end = if length == 0 {
            u64::MAX
        } else {
            offset.saturating_add(length)
        };

        self.offset < other_end && offset < self_end
    }

    /// Check if this lock conflicts with another lock request
    pub fn conflicts_with(&self, offset: u64, length: u64, mode: LockMode) -> bool {
        if !self.overlaps(offset, length) {
            return false;
        }
        // Shared locks don't conflict with each other
        !(self.mode == LockMode::Shared && mode == LockMode::Shared)
    }
}

/// Lock error types
#[derive(Debug, Clone)]
pub enum LockError {
    /// Lock conflicts with existing lock
    Conflict(ByteRangeLock),
    /// Lock not found
    NotFound,
    /// Deadlock detected
    Deadlock,
    /// Invalid lock parameters
    Invalid(String),
}

impl From<LockError> for GatewayError {
    fn from(err: LockError) -> Self {
        match err {
            LockError::Conflict(lock) => {
                GatewayError::LockConflict(format!("conflicts with lock {:?}", lock.token))
            }
            LockError::NotFound => GatewayError::LockNotFound("lock not found".to_string()),
            LockError::Deadlock => GatewayError::Deadlock,
            LockError::Invalid(msg) => GatewayError::LockConflict(msg),
        }
    }
}

/// Lock manager trait
#[async_trait]
pub trait LockManager: Send + Sync {
    /// Acquire a byte-range lock
    async fn acquire(&self, lock: ByteRangeLock) -> Result<LockToken, LockError>;

    /// Release a lock by token
    async fn release(&self, token: LockToken) -> Result<(), LockError>;

    /// Test if a lock can be acquired (without acquiring)
    async fn test(
        &self,
        file_id: FileId,
        offset: u64,
        length: u64,
        mode: LockMode,
    ) -> Option<ByteRangeLock>;

    /// Upgrade a shared lock to exclusive
    async fn upgrade(&self, token: LockToken) -> Result<LockToken, LockError>;

    /// Downgrade an exclusive lock to shared
    async fn downgrade(&self, token: LockToken) -> Result<LockToken, LockError>;

    /// Release all locks held by a client
    async fn release_all(&self, owner: ClientId) -> usize;

    /// Get all locks for a file
    async fn get_file_locks(&self, file_id: FileId) -> Vec<ByteRangeLock>;

    /// Expire old locks
    async fn expire_locks(&self) -> usize;
}

/// File lock state
struct FileLockState {
    locks: BTreeMap<u64, ByteRangeLock>, // offset -> lock
}

impl FileLockState {
    fn new() -> Self {
        Self {
            locks: BTreeMap::new(),
        }
    }

    fn find_conflict(
        &self,
        offset: u64,
        length: u64,
        mode: LockMode,
        exclude_owner: Option<ClientId>,
    ) -> Option<&ByteRangeLock> {
        for lock in self.locks.values() {
            if lock.is_expired() {
                continue;
            }
            if let Some(owner) = exclude_owner {
                if lock.owner == owner {
                    continue;
                }
            }
            if lock.conflicts_with(offset, length, mode) {
                return Some(lock);
            }
        }
        None
    }
}

/// In-memory lock manager for single-node deployments
pub struct InMemoryLockManager {
    /// Locks by file ID
    file_locks: DashMap<FileId, RwLock<FileLockState>>,
    /// Locks by token (for fast lookup)
    token_index: DashMap<LockToken, FileId>,
    /// Locks by owner (for cleanup)
    owner_index: DashMap<ClientId, Vec<LockToken>>,
    /// Next token ID
    next_token: AtomicU64,
}

impl InMemoryLockManager {
    /// Create a new in-memory lock manager
    pub fn new() -> Self {
        Self {
            file_locks: DashMap::new(),
            token_index: DashMap::new(),
            owner_index: DashMap::new(),
            next_token: AtomicU64::new(1),
        }
    }

    fn allocate_token(&self) -> LockToken {
        LockToken::new(self.next_token.fetch_add(1, Ordering::SeqCst))
    }
}

impl Default for InMemoryLockManager {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl LockManager for InMemoryLockManager {
    async fn acquire(&self, mut lock: ByteRangeLock) -> Result<LockToken, LockError> {
        let token = self.allocate_token();
        lock.token = token;

        // Get or create file lock state
        let state = self
            .file_locks
            .entry(lock.file_id)
            .or_insert_with(|| RwLock::new(FileLockState::new()));

        let mut state = state.write();

        // Check for conflicts
        if let Some(conflict) = state.find_conflict(lock.offset, lock.length, lock.mode, None) {
            return Err(LockError::Conflict(conflict.clone()));
        }

        // Add lock
        let file_id = lock.file_id;
        let owner = lock.owner;
        state.locks.insert(lock.offset, lock);

        // Update indices
        self.token_index.insert(token, file_id);
        self.owner_index
            .entry(owner)
            .or_default()
            .push(token);

        Ok(token)
    }

    async fn release(&self, token: LockToken) -> Result<(), LockError> {
        // Find the file
        let file_id = self
            .token_index
            .remove(&token)
            .map(|(_, id)| id)
            .ok_or(LockError::NotFound)?;

        // Remove from file locks
        if let Some(state) = self.file_locks.get(&file_id) {
            let mut state = state.write();
            state.locks.retain(|_, lock| lock.token != token);
        }

        // Remove from owner index
        for mut entry in self.owner_index.iter_mut() {
            entry.value_mut().retain(|t| *t != token);
        }

        Ok(())
    }

    async fn test(
        &self,
        file_id: FileId,
        offset: u64,
        length: u64,
        mode: LockMode,
    ) -> Option<ByteRangeLock> {
        let state = self.file_locks.get(&file_id)?;
        let state = state.read();
        state.find_conflict(offset, length, mode, None).cloned()
    }

    async fn upgrade(&self, token: LockToken) -> Result<LockToken, LockError> {
        let file_id = *self.token_index.get(&token).ok_or(LockError::NotFound)?;

        let state = self.file_locks.get(&file_id).ok_or(LockError::NotFound)?;
        let mut state = state.write();

        // Find the lock and extract info
        let (offset, length, owner, current_mode) = {
            let lock = state
                .locks
                .values()
                .find(|l| l.token == token)
                .ok_or(LockError::NotFound)?;
            (lock.offset, lock.length, lock.owner, lock.mode)
        };

        if current_mode == LockMode::Exclusive {
            return Ok(token); // Already exclusive
        }

        // Check for conflicts (excluding our own lock)
        if let Some(conflict) =
            state.find_conflict(offset, length, LockMode::Exclusive, Some(owner))
        {
            return Err(LockError::Conflict(conflict.clone()));
        }

        // Now mutate
        if let Some(lock) = state.locks.values_mut().find(|l| l.token == token) {
            lock.mode = LockMode::Exclusive;
        }
        Ok(token)
    }

    async fn downgrade(&self, token: LockToken) -> Result<LockToken, LockError> {
        let file_id = *self.token_index.get(&token).ok_or(LockError::NotFound)?;

        let state = self.file_locks.get(&file_id).ok_or(LockError::NotFound)?;
        let mut state = state.write();

        // Find and downgrade
        let lock = state
            .locks
            .values_mut()
            .find(|l| l.token == token)
            .ok_or(LockError::NotFound)?;

        lock.mode = LockMode::Shared;
        Ok(token)
    }

    async fn release_all(&self, owner: ClientId) -> usize {
        let tokens: Vec<LockToken> = self
            .owner_index
            .remove(&owner)
            .map(|(_, tokens)| tokens)
            .unwrap_or_default();

        let count = tokens.len();
        for token in tokens {
            let _ = self.release(token).await;
        }
        count
    }

    async fn get_file_locks(&self, file_id: FileId) -> Vec<ByteRangeLock> {
        self.file_locks
            .get(&file_id)
            .map(|state| state.read().locks.values().cloned().collect())
            .unwrap_or_default()
    }

    async fn expire_locks(&self) -> usize {
        let mut expired = 0;

        for entry in self.file_locks.iter() {
            let mut state = entry.write();
            let before = state.locks.len();
            state.locks.retain(|_, lock| !lock.is_expired());
            expired += before - state.locks.len();
        }

        // Clean up token index
        self.token_index.retain(|token, _| {
            // Check if lock still exists
            for entry in self.file_locks.iter() {
                let state = entry.read();
                if state.locks.values().any(|l| l.token == *token) {
                    return true;
                }
            }
            false
        });

        expired
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_acquire_release() {
        let manager = InMemoryLockManager::new();
        let client = ClientId::new(1);

        let lock = ByteRangeLock::new(
            LockToken::new(0), // Will be replaced
            client,
            1, // file_id
            0,
            100,
            LockMode::Exclusive,
        );

        let token = manager.acquire(lock).await.unwrap();
        assert!(manager.release(token).await.is_ok());
    }

    #[tokio::test]
    async fn test_shared_locks_compatible() {
        let manager = InMemoryLockManager::new();

        let lock1 = ByteRangeLock::new(
            LockToken::new(0),
            ClientId::new(1),
            1,
            0,
            100,
            LockMode::Shared,
        );

        let lock2 = ByteRangeLock::new(
            LockToken::new(0),
            ClientId::new(2),
            1,
            0,
            100,
            LockMode::Shared,
        );

        let _token1 = manager.acquire(lock1).await.unwrap();
        let _token2 = manager.acquire(lock2).await.unwrap();
    }

    #[tokio::test]
    async fn test_exclusive_lock_conflict() {
        let manager = InMemoryLockManager::new();

        let lock1 = ByteRangeLock::new(
            LockToken::new(0),
            ClientId::new(1),
            1,
            0,
            100,
            LockMode::Exclusive,
        );

        let lock2 = ByteRangeLock::new(
            LockToken::new(0),
            ClientId::new(2),
            1,
            50,
            100,
            LockMode::Exclusive,
        );

        let _token1 = manager.acquire(lock1).await.unwrap();
        assert!(matches!(
            manager.acquire(lock2).await,
            Err(LockError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn test_non_overlapping_locks() {
        let manager = InMemoryLockManager::new();

        let lock1 = ByteRangeLock::new(
            LockToken::new(0),
            ClientId::new(1),
            1,
            0,
            100,
            LockMode::Exclusive,
        );

        let lock2 = ByteRangeLock::new(
            LockToken::new(0),
            ClientId::new(2),
            1,
            200,
            100,
            LockMode::Exclusive,
        );

        let _token1 = manager.acquire(lock1).await.unwrap();
        let _token2 = manager.acquire(lock2).await.unwrap();
    }

    #[tokio::test]
    async fn test_upgrade_downgrade() {
        let manager = InMemoryLockManager::new();

        let lock = ByteRangeLock::new(
            LockToken::new(0),
            ClientId::new(1),
            1,
            0,
            100,
            LockMode::Shared,
        );

        let token = manager.acquire(lock).await.unwrap();

        // Upgrade to exclusive
        manager.upgrade(token).await.unwrap();

        // Downgrade back to shared
        manager.downgrade(token).await.unwrap();
    }
}
