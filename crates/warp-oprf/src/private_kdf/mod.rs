//! Private Key Derivation using OPRF
//!
//! This module enables key derivation where the server helps derive keys
//! without learning the input material. Useful for:
//!
//! - Password-derived encryption keys
//! - User-specific keys from a master secret
//! - Key wrapping with server-side contribution
//!
//! # Security Properties
//!
//! - Server contributes to key derivation without learning the input
//! - Keys are deterministic for same input + server key
//! - Client cannot derive keys without server participation
//! - Rate limiting can prevent brute-force attacks
//!
//! # Example
//!
//! ```ignore
//! use warp_oprf::private_kdf::{PrivateKdfClient, PrivateKdfServer};
//!
//! // Setup
//! let server = PrivateKdfServer::new("kdf-key-v1")?;
//! let client = PrivateKdfClient::new(server.public_key())?;
//!
//! // Derive a key from password
//! let (request, state) = client.derive_request(b"user-password", b"encryption-key")?;
//! let response = server.evaluate(&request)?;
//! let derived_key = client.derive_key(state, &response)?;
//!
//! // Use derived_key for encryption
//! ```

mod client;
mod server;

pub use client::PrivateKdfClient;
pub use server::PrivateKdfServer;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A derived key from the private KDF
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DerivedKey {
    /// The derived key material
    key: [u8; 32],
    /// The server key ID used for derivation
    #[zeroize(skip)]
    key_id: String,
    /// Context/purpose of this key
    #[zeroize(skip)]
    context: String,
}

impl DerivedKey {
    /// Create a new derived key
    pub fn new(key: [u8; 32], key_id: impl Into<String>, context: impl Into<String>) -> Self {
        Self {
            key,
            key_id: key_id.into(),
            context: context.into(),
        }
    }

    /// Get the key bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    /// Get the server key ID
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Get the context/purpose
    pub fn context(&self) -> &str {
        &self.context
    }

    /// Derive a subkey for a specific purpose
    pub fn derive_subkey(&self, purpose: &[u8]) -> [u8; 32] {
        let input = [self.key.as_slice(), purpose].concat();
        warp_hash::hash(&input)
    }
}

impl AsRef<[u8]> for DerivedKey {
    fn as_ref(&self) -> &[u8] {
        &self.key
    }
}

impl std::fmt::Debug for DerivedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DerivedKey")
            .field("key", &"[REDACTED]")
            .field("key_id", &self.key_id)
            .field("context", &self.context)
            .finish()
    }
}

/// Request for key derivation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfRequest {
    /// Blinded input
    #[serde(with = "serde_bytes")]
    pub blinded: Vec<u8>,
    /// Context for key derivation
    pub context: String,
    /// Optional additional data
    #[serde(with = "serde_bytes")]
    pub info: Vec<u8>,
}

/// Response from key derivation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfResponse {
    /// Evaluated blinded element
    #[serde(with = "serde_bytes")]
    pub evaluated: Vec<u8>,
    /// Optional proof (VOPRF mode)
    #[serde(with = "serde_bytes")]
    pub proof: Vec<u8>,
    /// Server key ID
    pub key_id: String,
}

/// State preserved during key derivation
pub struct KdfState {
    /// Client state from OPRF
    pub(crate) oprf_state: crate::oprf::ClientState,
    /// Context for derivation
    pub(crate) context: String,
    /// Additional info
    pub(crate) info: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derived_key() {
        let key = DerivedKey::new([0x42; 32], "key-v1", "encryption");
        assert_eq!(key.as_bytes(), &[0x42; 32]);
        assert_eq!(key.key_id(), "key-v1");
        assert_eq!(key.context(), "encryption");
    }

    #[test]
    fn test_subkey_derivation() {
        let key = DerivedKey::new([0x42; 32], "key-v1", "master");
        let subkey1 = key.derive_subkey(b"encryption");
        let subkey2 = key.derive_subkey(b"signing");

        // Different purposes produce different subkeys
        assert_ne!(subkey1, subkey2);

        // Same purpose produces same subkey
        let subkey1_again = key.derive_subkey(b"encryption");
        assert_eq!(subkey1, subkey1_again);
    }
}
