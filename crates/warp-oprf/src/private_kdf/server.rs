//! Private KDF Server

use super::{KdfRequest, KdfResponse};
use crate::error::Result;
use crate::oprf::{BlindedInput, OprfServerTrait};
use crate::suite::{CipherSuite, OprfMode};

#[cfg(feature = "ristretto255")]
use crate::oprf::Ristretto255Server;

/// Server for private key derivation
#[cfg(feature = "ristretto255")]
pub struct PrivateKdfServer {
    oprf_server: Ristretto255Server,
}

#[cfg(feature = "ristretto255")]
impl PrivateKdfServer {
    /// Create a new KDF server with a random key
    pub fn new(key_id: impl Into<String>) -> Result<Self> {
        Ok(Self {
            oprf_server: Ristretto255Server::with_key_id(key_id)?,
        })
    }

    /// Create from an existing secret key (64 bytes serialized state)
    pub fn from_secret_key(secret_key: &[u8], key_id: impl Into<String>) -> Result<Self> {
        Ok(Self {
            oprf_server: Ristretto255Server::from_secret_key(secret_key, key_id)?,
        })
    }

    /// Get the server's public key
    pub fn public_key(&self) -> Vec<u8> {
        self.oprf_server.public_key()
    }

    /// Get the key identifier
    pub fn key_id(&self) -> &str {
        self.oprf_server.key_id()
    }

    /// Evaluate a key derivation request
    pub fn evaluate(&self, request: &KdfRequest) -> Result<KdfResponse> {
        // Reconstruct blinded input
        let blinded = BlindedInput::new(
            request.blinded.clone(),
            CipherSuite::default(),
            OprfMode::Verifiable,
        );

        // Evaluate with OPRF
        let evaluation = self.oprf_server.evaluate(&blinded)?;

        Ok(KdfResponse {
            evaluated: evaluation.element,
            proof: evaluation.proof,
            key_id: self.key_id().to_string(),
        })
    }

    /// Export the secret key for backup
    pub fn export_secret_key(&self) -> Vec<u8> {
        self.oprf_server.export_secret_key()
    }
}

/// KDF Server with rate limiting support
#[cfg(feature = "ristretto255")]
pub struct RateLimitedKdfServer {
    server: PrivateKdfServer,
    /// Maximum requests per minute per client
    rate_limit: usize,
    /// Request counter (would be per-client in production)
    request_count: std::sync::atomic::AtomicUsize,
}

#[cfg(feature = "ristretto255")]
impl RateLimitedKdfServer {
    /// Create a new rate-limited KDF server
    pub fn new(key_id: impl Into<String>, rate_limit: usize) -> Result<Self> {
        Ok(Self {
            server: PrivateKdfServer::new(key_id)?,
            rate_limit,
            request_count: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    /// Get the underlying server
    pub fn inner(&self) -> &PrivateKdfServer {
        &self.server
    }

    /// Check if rate limit is exceeded
    pub fn check_rate_limit(&self) -> bool {
        let count = self
            .request_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        count < self.rate_limit
    }

    /// Reset the rate limit counter
    pub fn reset_counter(&self) {
        self.request_count
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    /// Evaluate with rate limiting
    pub fn evaluate(&self, request: &KdfRequest) -> Result<KdfResponse> {
        if !self.check_rate_limit() {
            return Err(crate::error::OprfError::Internal(
                "rate limit exceeded".to_string(),
            ));
        }
        self.server.evaluate(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "ristretto255")]
    #[test]
    fn test_server_creation() {
        let server = PrivateKdfServer::new("kdf-key");
        assert!(server.is_ok());

        let server = server.unwrap();
        assert_eq!(server.key_id(), "kdf-key");
        assert_eq!(server.public_key().len(), 32);
    }

    #[cfg(feature = "ristretto255")]
    #[test]
    fn test_server_persistence() {
        let server = PrivateKdfServer::new("kdf-key").unwrap();
        let sk = server.export_secret_key();
        let pk1 = server.public_key();

        let restored = PrivateKdfServer::from_secret_key(&sk, "kdf-key").unwrap();
        let pk2 = restored.public_key();

        assert_eq!(pk1, pk2);
    }

    #[cfg(feature = "ristretto255")]
    #[test]
    fn test_rate_limiting() {
        let server = RateLimitedKdfServer::new("kdf-key", 3).unwrap();

        // First 3 should succeed
        assert!(server.check_rate_limit());
        assert!(server.check_rate_limit());
        assert!(server.check_rate_limit());

        // 4th should fail
        assert!(!server.check_rate_limit());

        // Reset and try again
        server.reset_counter();
        assert!(server.check_rate_limit());
    }
}
