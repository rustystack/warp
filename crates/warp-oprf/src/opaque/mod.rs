//! OPAQUE Password-Authenticated Key Exchange
//!
//! This module implements the OPAQUE protocol (RFC 9807) for secure password
//! authentication without exposing passwords to the server.
//!
//! # Security Properties
//!
//! - Server never sees the password (only a derived value)
//! - Resistant to offline dictionary attacks
//! - Mutual authentication between client and server
//! - Session key established for secure communication
//!
//! # Protocol Overview
//!
//! ## Registration
//! 1. Client sends registration request with blinded password
//! 2. Server evaluates and returns registration response
//! 3. Client creates password file to store on server
//!
//! ## Login
//! 1. Client sends login request with blinded password
//! 2. Server evaluates and returns login response with envelope
//! 3. Client decrypts envelope and sends final message
//! 4. Both parties derive shared session key
//!
//! # Example
//!
//! ```ignore
//! use warp_oprf::opaque::{OpaqueServer, OpaqueClient};
//!
//! // Registration
//! let server_setup = OpaqueServer::new()?;
//! let (client_reg, server_reg) = register("user@example.com", "password123")?;
//! let password_file = server_reg.finish()?;
//!
//! // Login
//! let (client_login, server_login) = login(
//!     "user@example.com",
//!     "password123",
//!     &password_file
//! )?;
//!
//! let session_key = client_login.session_key();
//! ```

// NOTE: Full OPAQUE implementation is temporarily disabled due to version
// compatibility issues between opaque-ke 3.0 and the voprf crate.
// The basic types are available for future integration.
//
// TODO: Re-enable when opaque-ke releases a compatible version.
// #[cfg(feature = "opaque")]
// mod registration;
// #[cfg(feature = "opaque")]
// mod login;
// #[cfg(feature = "opaque")]
// mod server;
//
// #[cfg(feature = "opaque")]
// pub use registration::*;
// #[cfg(feature = "opaque")]
// pub use login::*;
// #[cfg(feature = "opaque")]
// pub use server::*;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Password file stored on the server
///
/// Contains the user's registration record without the actual password.
#[derive(Clone, Serialize, Deserialize)]
pub struct PasswordFile {
    /// User identifier
    pub user_id: String,
    /// Serialized registration record
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
    /// Creation timestamp
    pub created_at: u64,
    /// Last updated timestamp
    pub updated_at: u64,
}

impl PasswordFile {
    /// Create a new password file
    pub fn new(user_id: impl Into<String>, data: Vec<u8>) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            user_id: user_id.into(),
            data,
            created_at: now,
            updated_at: now,
        }
    }
}

impl std::fmt::Debug for PasswordFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordFile")
            .field("user_id", &self.user_id)
            .field("data", &format!("[{} bytes]", self.data.len()))
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// Result of successful client login
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ClientLoginResult {
    /// Session key for encrypting further communication
    #[zeroize(skip)]
    session_key: [u8; 64],
    /// Export key for additional key derivation
    #[zeroize(skip)]
    export_key: [u8; 64],
}

impl ClientLoginResult {
    /// Create a new login result
    pub fn new(session_key: [u8; 64], export_key: [u8; 64]) -> Self {
        Self {
            session_key,
            export_key,
        }
    }

    /// Get the session key
    pub fn session_key(&self) -> &[u8; 64] {
        &self.session_key
    }

    /// Get the export key (for deriving additional keys)
    pub fn export_key(&self) -> &[u8; 64] {
        &self.export_key
    }

    /// Derive a 32-byte key from the session key
    pub fn derive_key(&self) -> [u8; 32] {
        warp_hash::hash(&self.session_key)
    }
}

impl std::fmt::Debug for ClientLoginResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientLoginResult")
            .field("session_key", &"[REDACTED]")
            .field("export_key", &"[REDACTED]")
            .finish()
    }
}

/// Result of successful server login
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ServerLoginResult {
    /// Session key (same as client's)
    #[zeroize(skip)]
    session_key: [u8; 64],
}

impl ServerLoginResult {
    /// Create a new server login result
    pub fn new(session_key: [u8; 64]) -> Self {
        Self { session_key }
    }

    /// Get the session key
    pub fn session_key(&self) -> &[u8; 64] {
        &self.session_key
    }

    /// Derive a 32-byte key from the session key
    pub fn derive_key(&self) -> [u8; 32] {
        warp_hash::hash(&self.session_key)
    }
}

impl std::fmt::Debug for ServerLoginResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerLoginResult")
            .field("session_key", &"[REDACTED]")
            .finish()
    }
}

/// Trait for password file storage
#[async_trait::async_trait]
pub trait PasswordStore: Send + Sync {
    /// Store a password file
    async fn store(&self, file: &PasswordFile) -> crate::error::Result<()>;

    /// Retrieve a password file
    async fn get(&self, user_id: &str) -> crate::error::Result<Option<PasswordFile>>;

    /// Delete a password file
    async fn delete(&self, user_id: &str) -> crate::error::Result<bool>;

    /// Check if a user exists
    async fn exists(&self, user_id: &str) -> crate::error::Result<bool> {
        Ok(self.get(user_id).await?.is_some())
    }
}

/// In-memory password store for testing
#[derive(Default)]
pub struct MemoryPasswordStore {
    files: std::sync::RwLock<std::collections::HashMap<String, PasswordFile>>,
}

impl MemoryPasswordStore {
    /// Create a new in-memory store
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait::async_trait]
impl PasswordStore for MemoryPasswordStore {
    async fn store(&self, file: &PasswordFile) -> crate::error::Result<()> {
        self.files
            .write()
            .unwrap()
            .insert(file.user_id.clone(), file.clone());
        Ok(())
    }

    async fn get(&self, user_id: &str) -> crate::error::Result<Option<PasswordFile>> {
        Ok(self.files.read().unwrap().get(user_id).cloned())
    }

    async fn delete(&self, user_id: &str) -> crate::error::Result<bool> {
        Ok(self.files.write().unwrap().remove(user_id).is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_file() {
        let file = PasswordFile::new("user@test.com", vec![1, 2, 3]);
        assert_eq!(file.user_id, "user@test.com");
        assert!(file.created_at > 0);
    }

    #[test]
    fn test_client_login_result() {
        let result = ClientLoginResult::new([0x42; 64], [0x24; 64]);
        assert_eq!(result.session_key().len(), 64);
        assert_eq!(result.export_key().len(), 64);

        let key = result.derive_key();
        assert_eq!(key.len(), 32);
    }

    #[tokio::test]
    async fn test_memory_store() {
        let store = MemoryPasswordStore::new();
        let file = PasswordFile::new("test@user.com", vec![1, 2, 3]);

        store.store(&file).await.unwrap();
        assert!(store.exists("test@user.com").await.unwrap());

        let retrieved = store.get("test@user.com").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().user_id, "test@user.com");

        store.delete("test@user.com").await.unwrap();
        assert!(!store.exists("test@user.com").await.unwrap());
    }
}
