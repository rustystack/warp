//! SMB server configuration
//!
//! Configuration types for the SMB3 server.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

/// SMB dialect versions
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u16)]
#[derive(Default)]
pub enum SmbDialect {
    /// SMB 2.0.2
    Smb202 = 0x0202,
    /// SMB 2.1
    Smb210 = 0x0210,
    /// SMB 3.0
    Smb300 = 0x0300,
    /// SMB 3.0.2
    Smb302 = 0x0302,
    /// SMB 3.1.1
    #[default]
    Smb311 = 0x0311,
}

impl SmbDialect {
    /// Get the dialect value for the protocol
    pub fn as_u16(&self) -> u16 {
        *self as u16
    }

    /// Create from raw value
    pub fn from_u16(val: u16) -> Option<Self> {
        match val {
            0x0202 => Some(Self::Smb202),
            0x0210 => Some(Self::Smb210),
            0x0300 => Some(Self::Smb300),
            0x0302 => Some(Self::Smb302),
            0x0311 => Some(Self::Smb311),
            _ => None,
        }
    }

    /// Check if this dialect supports encryption
    pub fn supports_encryption(&self) -> bool {
        matches!(self, Self::Smb300 | Self::Smb302 | Self::Smb311)
    }

    /// Check if this dialect supports leases
    pub fn supports_leases(&self) -> bool {
        matches!(
            self,
            Self::Smb210 | Self::Smb300 | Self::Smb302 | Self::Smb311
        )
    }

    /// Check if this dialect supports directory leases
    pub fn supports_directory_leases(&self) -> bool {
        matches!(self, Self::Smb300 | Self::Smb302 | Self::Smb311)
    }

    /// Check if this dialect supports multi-credit
    pub fn supports_multi_credit(&self) -> bool {
        matches!(
            self,
            Self::Smb210 | Self::Smb300 | Self::Smb302 | Self::Smb311
        )
    }
}

/// SMB server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmbConfig {
    /// TCP bind address
    pub bind_addr: SocketAddr,
    /// Server name (NetBIOS name)
    pub server_name: String,
    /// Server GUID
    pub server_guid: [u8; 16],
    /// Supported dialects (minimum to maximum)
    pub dialects: Vec<SmbDialect>,
    /// Require message signing
    pub require_signing: bool,
    /// Require encryption
    pub require_encryption: bool,
    /// Enable DFS
    pub dfs_enabled: bool,
    /// Enable oplocks
    pub oplocks_enabled: bool,
    /// Enable leases
    pub leases_enabled: bool,
    /// Maximum read size
    pub max_read_size: u32,
    /// Maximum write size
    pub max_write_size: u32,
    /// Maximum transact size
    pub max_transact_size: u32,
    /// Session timeout (seconds)
    pub session_timeout: u32,
}

impl Default for SmbConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:445".parse().unwrap(),
            server_name: "WARP".to_string(),
            server_guid: rand_guid(),
            dialects: vec![
                SmbDialect::Smb210,
                SmbDialect::Smb300,
                SmbDialect::Smb302,
                SmbDialect::Smb311,
            ],
            require_signing: false,
            require_encryption: false,
            dfs_enabled: true,
            oplocks_enabled: true,
            leases_enabled: true,
            max_read_size: 8 * 1024 * 1024,     // 8 MB
            max_write_size: 8 * 1024 * 1024,    // 8 MB
            max_transact_size: 8 * 1024 * 1024, // 8 MB
            session_timeout: 600,               // 10 minutes
        }
    }
}

impl SmbConfig {
    /// Create a new configuration with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Set bind address
    pub fn bind(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = addr;
        self
    }

    /// Set server name
    pub fn server_name(mut self, name: impl Into<String>) -> Self {
        self.server_name = name.into();
        self
    }

    /// Require message signing
    pub fn require_signing(mut self) -> Self {
        self.require_signing = true;
        self
    }

    /// Require encryption
    pub fn require_encryption(mut self) -> Self {
        self.require_encryption = true;
        self.require_signing = true; // Encryption requires signing
        self
    }

    /// Disable DFS
    pub fn disable_dfs(mut self) -> Self {
        self.dfs_enabled = false;
        self
    }

    /// Disable oplocks
    pub fn disable_oplocks(mut self) -> Self {
        self.oplocks_enabled = false;
        self
    }

    /// Get the highest supported dialect
    pub fn max_dialect(&self) -> SmbDialect {
        self.dialects
            .iter()
            .max()
            .copied()
            .unwrap_or(SmbDialect::Smb311)
    }

    /// Check if a dialect is supported
    pub fn supports_dialect(&self, dialect: SmbDialect) -> bool {
        self.dialects.contains(&dialect)
    }
}

/// Generate a random GUID (for testing/default purposes)
fn rand_guid() -> [u8; 16] {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let mut guid = [0u8; 16];
    guid[..8].copy_from_slice(&now.to_le_bytes()[..8]);
    guid[8..16].copy_from_slice(&(now >> 64).to_le_bytes()[..8]);
    guid
}

/// Capabilities flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities(u32);

impl Capabilities {
    /// DFS support
    pub const DFS: u32 = 0x00000001;
    /// Leasing support
    pub const LEASING: u32 = 0x00000002;
    /// Large MTU support
    pub const LARGE_MTU: u32 = 0x00000004;
    /// Multi-credit support
    pub const MULTI_CREDIT: u32 = 0x00000008;
    /// Persistent handles
    pub const PERSISTENT_HANDLES: u32 = 0x00000010;
    /// Directory leasing
    pub const DIRECTORY_LEASING: u32 = 0x00000020;
    /// Encryption support
    pub const ENCRYPTION: u32 = 0x00000040;

    /// Create from config
    pub fn from_config(config: &SmbConfig, dialect: SmbDialect) -> Self {
        let mut caps = 0u32;

        if config.dfs_enabled {
            caps |= Self::DFS;
        }

        if config.leases_enabled && dialect.supports_leases() {
            caps |= Self::LEASING;
        }

        if dialect.supports_multi_credit() {
            caps |= Self::LARGE_MTU | Self::MULTI_CREDIT;
        }

        if config.leases_enabled && dialect.supports_directory_leases() {
            caps |= Self::DIRECTORY_LEASING;
        }

        if dialect.supports_encryption() {
            caps |= Self::ENCRYPTION;
        }

        Self(caps)
    }

    /// Get raw value
    pub fn bits(&self) -> u32 {
        self.0
    }

    /// Check if capability is set
    pub fn has(&self, cap: u32) -> bool {
        self.0 & cap != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dialect_ordering() {
        assert!(SmbDialect::Smb311 > SmbDialect::Smb302);
        assert!(SmbDialect::Smb302 > SmbDialect::Smb300);
    }

    #[test]
    fn test_dialect_features() {
        assert!(SmbDialect::Smb311.supports_encryption());
        assert!(!SmbDialect::Smb210.supports_encryption());
        assert!(SmbDialect::Smb210.supports_leases());
        assert!(!SmbDialect::Smb202.supports_leases());
    }

    #[test]
    fn test_config_builder() {
        let config = SmbConfig::new()
            .server_name("TEST")
            .require_signing()
            .disable_dfs();

        assert_eq!(config.server_name, "TEST");
        assert!(config.require_signing);
        assert!(!config.dfs_enabled);
    }

    #[test]
    fn test_capabilities() {
        let config = SmbConfig::new();
        let caps = Capabilities::from_config(&config, SmbDialect::Smb311);

        assert!(caps.has(Capabilities::DFS));
        assert!(caps.has(Capabilities::LEASING));
        assert!(caps.has(Capabilities::ENCRYPTION));
    }
}
