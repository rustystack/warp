//! Oblivious Pseudorandom Functions for Warp
//!
//! This crate provides privacy-preserving cryptographic operations using
//! Oblivious Pseudorandom Functions (OPRF) as defined in RFC 9497.
//!
//! # Features
//!
//! - **Core OPRF** - Basic and verifiable OPRF with Ristretto255
//! - **BlindDedup** - Content-blind deduplication
//! - **OPAQUE** - Password-authenticated key exchange (RFC 9807)
//! - **PrivateKDF** - Private key derivation with server participation
//!
//! # Security Model
//!
//! All operations are designed to be:
//! - **Oblivious** - Server cannot learn client's input
//! - **Verifiable** - Client can verify server used correct key (VOPRF)
//! - **Rate-limitable** - Server can limit queries to prevent attacks
//!
//! # Cipher Suites
//!
//! Supports the following RFC 9497 cipher suites:
//! - `Ristretto255-SHA512` (default, recommended)
//! - `P256-SHA256` (with `p256` feature)
//!
//! # Example: Content-Blind Deduplication
//!
//! ```ignore
//! use warp_oprf::dedup::{BlindDedupClient, BlindDedupServer};
//!
//! // Server setup (once, persisted)
//! let server = BlindDedupServer::new("dedup-key-v1")?;
//!
//! // Client setup (uses server's public key)
//! let client = BlindDedupClient::new(&server.public_key())?;
//!
//! // Generate dedup token for content
//! let content = b"file content to deduplicate";
//! let token = client.compute_token_with_server(content, &server)?;
//!
//! // Token is deterministic - same content always produces same token
//! // Server never sees the content hash, only blinded values
//! ```
//!
//! # Example: Private Key Derivation
//!
//! ```ignore
//! use warp_oprf::private_kdf::{PrivateKdfClient, PrivateKdfServer};
//!
//! // Server with master KDF key
//! let server = PrivateKdfServer::new("kdf-master-v1")?;
//! let client = PrivateKdfClient::new(&server.public_key())?;
//!
//! // Derive encryption key from password
//! let key = client.derive_with_server(b"user-password", "encryption", &server)?;
//!
//! // Server contributed to derivation without seeing the password
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]
#![allow(dead_code)]

pub mod error;
pub mod suite;

pub mod oprf;

#[cfg(feature = "ristretto255")]
pub mod dedup;

#[cfg(feature = "opaque")]
pub mod opaque;

#[cfg(feature = "ristretto255")]
pub mod private_kdf;

// Re-exports for convenience
pub use error::{OprfError, Result};
pub use suite::{CipherSuite, OprfConfig, OprfMode};

#[cfg(feature = "ristretto255")]
pub use oprf::{Ristretto255Client, Ristretto255Server};

#[cfg(feature = "ristretto255")]
pub use dedup::{BlindDedupClient, BlindDedupServer, DedupToken};

#[cfg(feature = "opaque")]
pub use opaque::{ClientLoginResult, PasswordFile, ServerLoginResult};

#[cfg(feature = "ristretto255")]
pub use private_kdf::{DerivedKey, PrivateKdfClient, PrivateKdfServer};

/// Prelude for common imports
pub mod prelude {
    pub use crate::error::{OprfError, Result};
    pub use crate::suite::{CipherSuite, OprfConfig, OprfMode};

    #[cfg(feature = "ristretto255")]
    pub use crate::dedup::{BlindDedupClient, BlindDedupServer, DedupToken};

    #[cfg(feature = "ristretto255")]
    pub use crate::private_kdf::{DerivedKey, PrivateKdfClient, PrivateKdfServer};

    #[cfg(feature = "opaque")]
    pub use crate::opaque::{ClientLoginResult, PasswordFile, ServerLoginResult};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crate_compiles() {
        // Basic smoke test
        let config = OprfConfig::new();
        assert_eq!(config.mode, OprfMode::Verifiable);
    }

    #[cfg(feature = "ristretto255")]
    #[test]
    fn test_full_oprf_flow() {
        use crate::oprf::{OprfClientTrait, OprfServerTrait};

        // Create server
        let server = Ristretto255Server::new().unwrap();
        let pk = server.public_key();

        // Create client
        let client = Ristretto255Client::new(&pk).unwrap();

        // Blind input
        let input = b"test input";
        let (blinded, state) = client.blind(input).unwrap();

        // Server evaluates
        let evaluation = server.evaluate(&blinded).unwrap();

        // Client finalizes
        let output = client.finalize(state, &evaluation).unwrap();

        // Output should be deterministic
        assert!(!output.as_bytes().is_empty());
    }

    #[cfg(feature = "ristretto255")]
    #[test]
    fn test_dedup_integration() {
        let server = BlindDedupServer::new("test").unwrap();
        let client = BlindDedupClient::new(&server.public_key()).unwrap();

        let token1 = client
            .compute_token_with_server(b"content1", &server)
            .unwrap();
        let token2 = client
            .compute_token_with_server(b"content1", &server)
            .unwrap();
        let token3 = client
            .compute_token_with_server(b"content2", &server)
            .unwrap();

        assert_eq!(token1, token2); // Same content = same token
        assert_ne!(token1, token3); // Different content = different token
    }

    #[cfg(feature = "ristretto255")]
    #[test]
    fn test_private_kdf_integration() {
        let server = PrivateKdfServer::new("kdf-key").unwrap();
        let client = PrivateKdfClient::new(&server.public_key()).unwrap();

        let key1 = client
            .derive_with_server(b"password", "context1", &server)
            .unwrap();
        let key2 = client
            .derive_with_server(b"password", "context1", &server)
            .unwrap();
        let key3 = client
            .derive_with_server(b"password", "context2", &server)
            .unwrap();

        assert_eq!(key1.as_bytes(), key2.as_bytes()); // Same input = same key
        assert_ne!(key1.as_bytes(), key3.as_bytes()); // Different context = different key
    }
}
