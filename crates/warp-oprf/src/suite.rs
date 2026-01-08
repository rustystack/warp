//! Cipher suite configuration for OPRF operations
//!
//! Supports the cipher suites defined in RFC 9497:
//! - Ristretto255-SHA512 (default, recommended)

use serde::{Deserialize, Serialize};

/// Supported OPRF cipher suites
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
#[derive(Default)]
pub enum CipherSuite {
    /// Ristretto255 with SHA-512 (RFC 9497)
    ///
    /// Recommended for new applications. Provides ~128-bit security
    /// with constant-time operations.
    #[cfg(feature = "ristretto255")]
    #[default]
    Ristretto255Sha512,
}

impl CipherSuite {
    /// Get the output size in bytes for this cipher suite
    pub const fn output_size(&self) -> usize {
        match self {
            #[cfg(feature = "ristretto255")]
            CipherSuite::Ristretto255Sha512 => 64, // SHA-512 output
        }
    }

    /// Get the group element size in bytes
    pub const fn element_size(&self) -> usize {
        match self {
            #[cfg(feature = "ristretto255")]
            CipherSuite::Ristretto255Sha512 => 32,
        }
    }

    /// Get the scalar size in bytes
    pub const fn scalar_size(&self) -> usize {
        match self {
            #[cfg(feature = "ristretto255")]
            CipherSuite::Ristretto255Sha512 => 32,
        }
    }

    /// Get the suite identifier string (for key derivation context)
    pub const fn identifier(&self) -> &'static str {
        match self {
            #[cfg(feature = "ristretto255")]
            CipherSuite::Ristretto255Sha512 => "OPRF-Ristretto255-SHA512",
        }
    }

    /// Get the suite ID as used in RFC 9497
    pub const fn suite_id(&self) -> u16 {
        match self {
            #[cfg(feature = "ristretto255")]
            CipherSuite::Ristretto255Sha512 => 0x0001,
        }
    }
}

impl std::fmt::Display for CipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.identifier())
    }
}

/// OPRF mode of operation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum OprfMode {
    /// Base OPRF - no verification
    Base,
    /// Verifiable OPRF - server provides proof
    #[default]
    Verifiable,
    /// Partially-oblivious PRF - includes public info
    PartiallyOblivious,
}

impl OprfMode {
    /// Get the mode identifier byte
    pub const fn mode_id(&self) -> u8 {
        match self {
            OprfMode::Base => 0x00,
            OprfMode::Verifiable => 0x01,
            OprfMode::PartiallyOblivious => 0x02,
        }
    }
}

/// Configuration for OPRF operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OprfConfig {
    /// Cipher suite to use
    pub suite: CipherSuite,
    /// Mode of operation
    pub mode: OprfMode,
    /// Server key identifier (for key rotation)
    pub key_id: Option<String>,
    /// Additional info for POPRF (partially oblivious)
    pub info: Option<Vec<u8>>,
}

impl Default for OprfConfig {
    fn default() -> Self {
        Self {
            suite: CipherSuite::default(),
            mode: OprfMode::Verifiable,
            key_id: None,
            info: None,
        }
    }
}

impl OprfConfig {
    /// Create a new config with the default Ristretto255 suite
    pub fn new() -> Self {
        Self::default()
    }

    /// Use base OPRF mode (no verification)
    pub fn base(mut self) -> Self {
        self.mode = OprfMode::Base;
        self
    }

    /// Use verifiable OPRF mode (with proof)
    pub fn verifiable(mut self) -> Self {
        self.mode = OprfMode::Verifiable;
        self
    }

    /// Set the server key identifier
    pub fn with_key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = Some(key_id.into());
        self
    }

    /// Set additional info for POPRF
    pub fn with_info(mut self, info: impl Into<Vec<u8>>) -> Self {
        self.info = Some(info.into());
        self.mode = OprfMode::PartiallyOblivious;
        self
    }

    /// Use Ristretto255 cipher suite
    #[cfg(feature = "ristretto255")]
    pub fn ristretto255(mut self) -> Self {
        self.suite = CipherSuite::Ristretto255Sha512;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_suite() {
        let suite = CipherSuite::default();
        #[cfg(feature = "ristretto255")]
        assert_eq!(suite, CipherSuite::Ristretto255Sha512);
    }

    #[test]
    fn test_suite_properties() {
        #[cfg(feature = "ristretto255")]
        {
            let suite = CipherSuite::Ristretto255Sha512;
            assert_eq!(suite.output_size(), 64);
            assert_eq!(suite.element_size(), 32);
            assert_eq!(suite.scalar_size(), 32);
            assert_eq!(suite.suite_id(), 0x0001);
        }
    }

    #[test]
    fn test_config_builder() {
        let config = OprfConfig::new().verifiable().with_key_id("key-v1");

        assert_eq!(config.mode, OprfMode::Verifiable);
        assert_eq!(config.key_id, Some("key-v1".to_string()));
    }

    #[test]
    fn test_mode_id() {
        assert_eq!(OprfMode::Base.mode_id(), 0x00);
        assert_eq!(OprfMode::Verifiable.mode_id(), 0x01);
        assert_eq!(OprfMode::PartiallyOblivious.mode_id(), 0x02);
    }
}
