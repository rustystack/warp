//! OPRF Server implementation
//!
//! Uses a simplified OPRF construction based on Diffie-Hellman:
//! Server receives blinded point P^r and computes (P^r)^k = P^(rk)

use super::{BatchOprfServer, BlindedInput, Evaluation, OprfServerTrait};
use crate::error::{OprfError, Result};
use crate::suite::{CipherSuite, OprfMode};
use zeroize::ZeroizeOnDrop;

#[cfg(feature = "ristretto255")]
use curve25519_dalek::scalar::Scalar;
#[cfg(feature = "ristretto255")]
use rand::rngs::OsRng;

/// OPRF server using Ristretto255 curve
#[cfg(feature = "ristretto255")]
#[derive(ZeroizeOnDrop)]
pub struct Ristretto255Server {
    /// The server's secret key (scalar)
    secret_key: Scalar,
    /// Key identifier for rotation tracking
    #[zeroize(skip)]
    key_id: String,
    /// Mode of operation
    #[zeroize(skip)]
    mode: OprfMode,
}

#[cfg(feature = "ristretto255")]
impl Ristretto255Server {
    /// Create a new server with a random key
    pub fn new() -> Result<Self> {
        Self::with_key_id("default")
    }

    /// Create a new server with a specific key ID
    pub fn with_key_id(key_id: impl Into<String>) -> Result<Self> {
        use rand::RngCore;

        // Generate random secret key scalar
        let mut scalar_bytes = [0u8; 64];
        OsRng.fill_bytes(&mut scalar_bytes);
        let secret_key = Scalar::from_bytes_mod_order_wide(&scalar_bytes);

        Ok(Self {
            secret_key,
            key_id: key_id.into(),
            mode: OprfMode::Verifiable,
        })
    }

    /// Create a server from an existing secret key (32 bytes scalar)
    pub fn from_secret_key(secret_key: &[u8], key_id: impl Into<String>) -> Result<Self> {
        if secret_key.len() != 32 {
            return Err(OprfError::InvalidInput(format!(
                "secret key must be 32 bytes, got {}",
                secret_key.len()
            )));
        }

        let sk_bytes: [u8; 32] = secret_key
            .try_into()
            .map_err(|_| OprfError::InvalidInput("invalid secret key".to_string()))?;

        let secret_key = Scalar::from_canonical_bytes(sk_bytes);
        if secret_key.is_none().into() {
            return Err(OprfError::InvalidInput("invalid scalar".to_string()));
        }

        Ok(Self {
            secret_key: secret_key.unwrap(),
            key_id: key_id.into(),
            mode: OprfMode::Verifiable,
        })
    }

    /// Set the mode of operation
    pub fn with_mode(mut self, mode: OprfMode) -> Self {
        self.mode = mode;
        self
    }

    /// Export the secret key (for backup/restore)
    pub fn export_secret_key(&self) -> Vec<u8> {
        self.secret_key.to_bytes().to_vec()
    }
}

#[cfg(feature = "ristretto255")]
impl OprfServerTrait for Ristretto255Server {
    fn public_key(&self) -> Vec<u8> {
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
        let public_key = RISTRETTO_BASEPOINT_POINT * self.secret_key;
        public_key.compress().to_bytes().to_vec()
    }

    fn evaluate(&self, blinded: &BlindedInput) -> Result<Evaluation> {
        // Validate cipher suite matches
        if blinded.suite != CipherSuite::Ristretto255Sha512 {
            return Err(OprfError::InvalidConfig(format!(
                "suite mismatch: expected Ristretto255, got {:?}",
                blinded.suite
            )));
        }

        // Deserialize the blinded point
        let element_bytes: [u8; 32] = blinded
            .element
            .as_slice()
            .try_into()
            .map_err(|_| OprfError::InvalidBlindedElement)?;

        let blinded_point = curve25519_dalek::ristretto::CompressedRistretto(element_bytes)
            .decompress()
            .ok_or(OprfError::InvalidBlindedElement)?;

        // Evaluate: (P^r)^k = P^(rk)
        let eval_point = blinded_point * self.secret_key;
        let eval_bytes = eval_point.compress().to_bytes().to_vec();

        // For now, we don't implement DLEQ proofs (verifiable mode)
        Ok(Evaluation::new(eval_bytes))
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn suite(&self) -> CipherSuite {
        CipherSuite::Ristretto255Sha512
    }

    fn mode(&self) -> OprfMode {
        self.mode
    }
}

#[cfg(feature = "ristretto255")]
impl BatchOprfServer for Ristretto255Server {
    fn evaluate_batch(&self, blinded: &[BlindedInput]) -> Result<Vec<Evaluation>> {
        blinded.iter().map(|b| self.evaluate(b)).collect()
    }
}

/// Server key pair for persistence
#[derive(Debug, Clone)]
pub struct ServerKeyPair {
    /// Secret key bytes
    pub secret_key: Vec<u8>,
    /// Public key bytes
    pub public_key: Vec<u8>,
    /// Key identifier
    pub key_id: String,
    /// Creation timestamp
    pub created_at: u64,
}

impl ServerKeyPair {
    /// Generate a new key pair
    #[cfg(feature = "ristretto255")]
    pub fn generate(key_id: impl Into<String>) -> Result<Self> {
        use std::time::{SystemTime, UNIX_EPOCH};

        let server = Ristretto255Server::with_key_id(key_id.into())?;
        let secret_key = server.export_secret_key();
        let public_key = server.public_key();
        let key_id = server.key_id().to_string();

        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Ok(Self {
            secret_key,
            public_key,
            key_id,
            created_at,
        })
    }

    /// Restore a server from this key pair
    #[cfg(feature = "ristretto255")]
    pub fn to_server(&self) -> Result<Ristretto255Server> {
        Ristretto255Server::from_secret_key(&self.secret_key, &self.key_id)
    }
}

impl Drop for ServerKeyPair {
    fn drop(&mut self) {
        // Zeroize the secret key on drop
        self.secret_key.iter_mut().for_each(|b| *b = 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "ristretto255")]
    #[test]
    fn test_server_creation() {
        let server = Ristretto255Server::new();
        assert!(server.is_ok());

        let server = server.unwrap();
        let pk = server.public_key();
        assert_eq!(pk.len(), 32);
    }

    #[cfg(feature = "ristretto255")]
    #[test]
    fn test_server_key_export_import() {
        let server = Ristretto255Server::with_key_id("test-key").unwrap();
        let sk = server.export_secret_key();
        let pk1 = server.public_key();

        let restored = Ristretto255Server::from_secret_key(&sk, "test-key").unwrap();
        let pk2 = restored.public_key();

        assert_eq!(pk1, pk2);
    }

    #[cfg(feature = "ristretto255")]
    #[test]
    fn test_key_pair_generation() {
        let kp = ServerKeyPair::generate("my-key").unwrap();
        assert_eq!(kp.key_id, "my-key");
        assert_eq!(kp.secret_key.len(), 32);
        assert_eq!(kp.public_key.len(), 32);
    }

    #[cfg(feature = "ristretto255")]
    #[test]
    fn test_server_key_id() {
        let server = Ristretto255Server::with_key_id("my-server-key-v1").unwrap();
        assert_eq!(server.key_id(), "my-server-key-v1");
    }
}
