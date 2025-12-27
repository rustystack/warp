//! OPAQUE Server Setup

use super::PasswordFile;
use crate::error::{OprfError, Result};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use opaque_ke::{
    CipherSuite, Ristretto255,
    ServerSetup as OpaqueServerSetup,
};

/// The cipher suite used for OPAQUE
pub struct DefaultCipherSuite;

impl CipherSuite for DefaultCipherSuite {
    type OprfCs = Ristretto255;
    type KeGroup = Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = opaque_ke::ksf::Identity;
}

/// OPAQUE server configuration
///
/// This holds the server's long-term keys and configuration.
/// Should be persisted and reused across server restarts.
#[derive(ZeroizeOnDrop)]
pub struct OpaqueServer {
    #[zeroize(skip)]
    setup: OpaqueServerSetup<DefaultCipherSuite>,
    #[zeroize(skip)]
    server_id: String,
}

impl OpaqueServer {
    /// Create a new OPAQUE server with random keys
    pub fn new(server_id: impl Into<String>) -> Result<Self> {
        let setup = OpaqueServerSetup::<DefaultCipherSuite>::new(&mut OsRng);

        Ok(Self {
            setup,
            server_id: server_id.into(),
        })
    }

    /// Serialize the server setup for persistence
    pub fn serialize(&self) -> Vec<u8> {
        self.setup.serialize().to_vec()
    }

    /// Deserialize a server setup
    pub fn deserialize(data: &[u8], server_id: impl Into<String>) -> Result<Self> {
        let setup = OpaqueServerSetup::<DefaultCipherSuite>::deserialize(data)
            .map_err(|e| OprfError::Deserialization(format!("{:?}", e)))?;

        Ok(Self {
            setup,
            server_id: server_id.into(),
        })
    }

    /// Get the server ID
    pub fn server_id(&self) -> &str {
        &self.server_id
    }

    /// Get the internal setup for protocol operations
    pub(crate) fn setup(&self) -> &OpaqueServerSetup<DefaultCipherSuite> {
        &self.setup
    }
}

impl std::fmt::Debug for OpaqueServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpaqueServer")
            .field("server_id", &self.server_id)
            .finish()
    }
}

/// Persistent server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpaqueServerConfig {
    /// Server identifier
    pub server_id: String,
    /// Serialized server setup
    #[serde(with = "serde_bytes")]
    pub setup_data: Vec<u8>,
    /// Creation timestamp
    pub created_at: u64,
}

impl OpaqueServerConfig {
    /// Create a new server config
    pub fn new(server_id: impl Into<String>) -> Result<Self> {
        use std::time::{SystemTime, UNIX_EPOCH};

        let server_id = server_id.into();
        let server = OpaqueServer::new(&server_id)?;

        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Ok(Self {
            server_id,
            setup_data: server.serialize(),
            created_at,
        })
    }

    /// Restore an OPAQUE server from this config
    pub fn to_server(&self) -> Result<OpaqueServer> {
        OpaqueServer::deserialize(&self.setup_data, &self.server_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_creation() {
        let server = OpaqueServer::new("test-server");
        assert!(server.is_ok());
    }

    #[test]
    fn test_server_persistence() {
        let server = OpaqueServer::new("test-server").unwrap();
        let data = server.serialize();

        let restored = OpaqueServer::deserialize(&data, "test-server");
        assert!(restored.is_ok());
    }

    #[test]
    fn test_server_config() {
        let config = OpaqueServerConfig::new("my-server").unwrap();
        assert_eq!(config.server_id, "my-server");

        let server = config.to_server();
        assert!(server.is_ok());
    }
}
