//! Blind deduplication server

use crate::error::Result;
use crate::oprf::{BlindedInput, Evaluation, OprfServerTrait};

#[cfg(feature = "ristretto255")]
use crate::oprf::Ristretto255Server;

/// Server for content-blind deduplication
#[cfg(feature = "ristretto255")]
pub struct BlindDedupServer {
    server: Ristretto255Server,
}

#[cfg(feature = "ristretto255")]
impl BlindDedupServer {
    /// Create a new dedup server with a random key
    pub fn new(key_id: impl Into<String>) -> Result<Self> {
        Ok(Self {
            server: Ristretto255Server::with_key_id(key_id)?,
        })
    }

    /// Create a server from an existing secret key (64 bytes serialized state)
    pub fn from_secret_key(secret_key: &[u8], key_id: impl Into<String>) -> Result<Self> {
        Ok(Self {
            server: Ristretto255Server::from_secret_key(secret_key, key_id)?,
        })
    }

    /// Get the server's public key
    pub fn public_key(&self) -> Vec<u8> {
        self.server.public_key()
    }

    /// Get the key identifier
    pub fn key_id(&self) -> &str {
        self.server.key_id()
    }

    /// Evaluate a blinded hash
    pub fn evaluate(&self, blinded: &BlindedInput) -> Result<Evaluation> {
        self.server.evaluate(blinded)
    }

    /// Evaluate a batch of blinded hashes
    pub fn evaluate_batch(&self, blinded: &[BlindedInput]) -> Result<Vec<Evaluation>> {
        blinded.iter().map(|b| self.evaluate(b)).collect()
    }

    /// Export the secret key for backup
    pub fn export_secret_key(&self) -> Vec<u8> {
        self.server.export_secret_key()
    }
}

/// Key rotation manager for dedup servers
#[cfg(feature = "ristretto255")]
pub struct DedupKeyManager {
    /// Current active server
    current: BlindDedupServer,
    /// Previous servers for reading old tokens (key rotation)
    previous: Vec<BlindDedupServer>,
    /// Maximum number of previous keys to keep
    max_previous: usize,
}

#[cfg(feature = "ristretto255")]
impl DedupKeyManager {
    /// Create a new key manager with an initial key
    pub fn new(initial_key_id: impl Into<String>) -> Result<Self> {
        Ok(Self {
            current: BlindDedupServer::new(initial_key_id)?,
            previous: Vec::new(),
            max_previous: 3,
        })
    }

    /// Create from an existing server
    pub fn with_server(server: BlindDedupServer) -> Self {
        Self {
            current: server,
            previous: Vec::new(),
            max_previous: 3,
        }
    }

    /// Get the current server
    pub fn current(&self) -> &BlindDedupServer {
        &self.current
    }

    /// Get all servers (current + previous)
    pub fn all_servers(&self) -> impl Iterator<Item = &BlindDedupServer> {
        std::iter::once(&self.current).chain(self.previous.iter())
    }

    /// Rotate to a new key
    pub fn rotate(&mut self, new_key_id: impl Into<String>) -> Result<()> {
        let new_server = BlindDedupServer::new(new_key_id)?;

        // Move current to previous
        let old = std::mem::replace(&mut self.current, new_server);
        self.previous.insert(0, old);

        // Trim old keys
        while self.previous.len() > self.max_previous {
            self.previous.pop();
        }

        Ok(())
    }

    /// Get the current public key
    pub fn public_key(&self) -> Vec<u8> {
        self.current.public_key()
    }

    /// Get the current key ID
    pub fn key_id(&self) -> &str {
        self.current.key_id()
    }

    /// Evaluate using current key
    pub fn evaluate(&self, blinded: &BlindedInput) -> Result<Evaluation> {
        self.current.evaluate(blinded)
    }

    /// Set maximum previous keys to keep
    pub fn set_max_previous(&mut self, max: usize) {
        self.max_previous = max;
        while self.previous.len() > self.max_previous {
            self.previous.pop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "ristretto255")]
    #[test]
    fn test_server_creation() {
        let server = BlindDedupServer::new("test-key").unwrap();
        assert_eq!(server.key_id(), "test-key");
        assert_eq!(server.public_key().len(), 32);
    }

    #[cfg(feature = "ristretto255")]
    #[test]
    fn test_server_persistence() {
        let server = BlindDedupServer::new("test-key").unwrap();
        let sk = server.export_secret_key();
        let pk1 = server.public_key();

        let restored = BlindDedupServer::from_secret_key(&sk, "test-key").unwrap();
        let pk2 = restored.public_key();

        assert_eq!(pk1, pk2);
    }

    #[cfg(feature = "ristretto255")]
    #[test]
    fn test_key_rotation() {
        let mut manager = DedupKeyManager::new("key-v1").unwrap();
        let pk1 = manager.public_key();

        manager.rotate("key-v2").unwrap();
        let pk2 = manager.public_key();

        assert_ne!(pk1, pk2);
        assert_eq!(manager.key_id(), "key-v2");
        assert_eq!(manager.all_servers().count(), 2);
    }

    #[cfg(feature = "ristretto255")]
    #[test]
    fn test_key_rotation_trimming() {
        let mut manager = DedupKeyManager::new("key-v1").unwrap();
        manager.set_max_previous(2);

        manager.rotate("key-v2").unwrap();
        manager.rotate("key-v3").unwrap();
        manager.rotate("key-v4").unwrap();

        // Should have current + 2 previous = 3 total
        assert_eq!(manager.all_servers().count(), 3);
    }
}
