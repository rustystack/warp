//! SMB share management
//!
//! Defines share types and share management.

use std::net::IpAddr;

use dashmap::DashMap;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// Share type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
#[derive(Default)]
pub enum ShareType {
    /// Disk share
    #[default]
    Disk = 0x00000000,
    /// Print queue
    PrintQueue = 0x00000001,
    /// Named pipe
    NamedPipe = 0x00000002,
    /// Communication device
    CommDevice = 0x00000003,
}

/// Share flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShareFlags(u32);

impl ShareFlags {
    /// Manual caching
    pub const MANUAL_CACHING: u32 = 0x00000000;
    /// Auto caching
    pub const AUTO_CACHING: u32 = 0x00000010;
    /// VDO caching
    pub const VDO_CACHING: u32 = 0x00000020;
    /// No caching
    pub const NO_CACHING: u32 = 0x00000030;
    /// DFS share
    pub const DFS: u32 = 0x00000001;
    /// DFS root
    pub const DFS_ROOT: u32 = 0x00000002;
    /// Restrict exclusive opens
    pub const RESTRICT_EXCLUSIVE_OPENS: u32 = 0x00000100;
    /// Force shared delete
    pub const FORCE_SHARED_DELETE: u32 = 0x00000200;
    /// Allow namespace caching
    pub const ALLOW_NAMESPACE_CACHING: u32 = 0x00000400;
    /// Access based directory enumeration
    pub const ABE: u32 = 0x00000800;
    /// Force level II oplock
    pub const FORCE_LEVEL2_OPLOCK: u32 = 0x00001000;
    /// Enable hash v1
    pub const ENABLE_HASH_V1: u32 = 0x00002000;
    /// Enable hash v2
    pub const ENABLE_HASH_V2: u32 = 0x00004000;
    /// Encrypt data
    pub const ENCRYPT_DATA: u32 = 0x00008000;
    /// Identity remoting
    pub const IDENTITY_REMOTING: u32 = 0x00040000;
    /// Cluster share
    pub const CLUSTER: u32 = 0x00080000;

    /// Create new flags
    pub fn new(flags: u32) -> Self {
        Self(flags)
    }

    /// Get raw value
    pub fn bits(&self) -> u32 {
        self.0
    }

    /// Check if flag is set
    pub fn has(&self, flag: u32) -> bool {
        self.0 & flag != 0
    }
}

impl Default for ShareFlags {
    fn default() -> Self {
        Self(Self::MANUAL_CACHING)
    }
}

/// Share capabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ShareCapabilities(u32);

impl ShareCapabilities {
    /// DFS available
    pub const DFS: u32 = 0x00000008;
    /// Continuous availability
    pub const CONTINUOUS_AVAILABILITY: u32 = 0x00000010;
    /// Scale-out
    pub const SCALEOUT: u32 = 0x00000020;
    /// Cluster support
    pub const CLUSTER: u32 = 0x00000040;
    /// Asymmetric
    pub const ASYMMETRIC: u32 = 0x00000080;
    /// Redirect to owner
    pub const REDIRECT_TO_OWNER: u32 = 0x00000100;

    /// Create new capabilities
    pub fn new(caps: u32) -> Self {
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

/// SMB share configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmbShare {
    /// Share name (\\server\name)
    pub name: String,
    /// Share path in warp-store
    pub bucket: String,
    /// Path within the bucket
    pub path: String,
    /// Share type
    pub share_type: ShareType,
    /// Read-only share
    pub read_only: bool,
    /// Allowed client networks
    pub allowed_clients: Vec<IpNet>,
    /// Comment/description
    pub comment: String,
    /// Maximum concurrent users (0 = unlimited)
    pub max_users: u32,
    /// Require encryption for this share
    pub require_encryption: bool,
    /// Enable ABE (Access Based Enumeration)
    pub access_based_enumeration: bool,
    /// Enable caching
    pub caching_mode: CachingMode,
}

/// Client-side caching mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum CachingMode {
    /// Manual caching
    #[default]
    Manual,
    /// Automatic caching of documents
    Documents,
    /// Automatic caching of programs
    Programs,
    /// No caching
    None,
    /// Branch cache
    BranchCache,
}

impl Default for SmbShare {
    fn default() -> Self {
        Self {
            name: String::new(),
            bucket: String::new(),
            path: "/".to_string(),
            share_type: ShareType::Disk,
            read_only: false,
            allowed_clients: vec!["0.0.0.0/0".parse().unwrap()],
            comment: String::new(),
            max_users: 0,
            require_encryption: false,
            access_based_enumeration: false,
            caching_mode: CachingMode::Manual,
        }
    }
}

impl SmbShare {
    /// Create a new share
    pub fn new(name: impl Into<String>, bucket: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            bucket: bucket.into(),
            ..Default::default()
        }
    }

    /// Set share path
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = path.into();
        self
    }

    /// Set as read-only
    pub fn read_only(mut self) -> Self {
        self.read_only = true;
        self
    }

    /// Set comment
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = comment.into();
        self
    }

    /// Require encryption
    pub fn require_encryption(mut self) -> Self {
        self.require_encryption = true;
        self
    }

    /// Enable access-based enumeration
    pub fn with_abe(mut self) -> Self {
        self.access_based_enumeration = true;
        self
    }

    /// Set caching mode
    pub fn with_caching(mut self, mode: CachingMode) -> Self {
        self.caching_mode = mode;
        self
    }

    /// Check if a client IP is allowed
    pub fn is_client_allowed(&self, addr: &IpAddr) -> bool {
        self.allowed_clients.iter().any(|net| net.contains(addr))
    }

    /// Get share flags
    pub fn flags(&self) -> ShareFlags {
        let mut flags = match self.caching_mode {
            CachingMode::Manual => ShareFlags::MANUAL_CACHING,
            CachingMode::Documents => ShareFlags::AUTO_CACHING,
            CachingMode::Programs => ShareFlags::VDO_CACHING,
            CachingMode::None | CachingMode::BranchCache => ShareFlags::NO_CACHING,
        };

        if self.access_based_enumeration {
            flags |= ShareFlags::ABE;
        }

        if self.require_encryption {
            flags |= ShareFlags::ENCRYPT_DATA;
        }

        ShareFlags::new(flags)
    }
}

/// Share manager
#[derive(Debug)]
pub struct ShareManager {
    /// Shares by name (case-insensitive)
    shares: DashMap<String, SmbShare>,
}

impl ShareManager {
    /// Create a new share manager
    pub fn new() -> Self {
        Self {
            shares: DashMap::new(),
        }
    }

    /// Add a share
    pub fn add_share(&self, share: SmbShare) {
        let name = share.name.to_uppercase();
        self.shares.insert(name, share);
    }

    /// Get a share by name (case-insensitive)
    pub fn get_share(&self, name: &str) -> Option<SmbShare> {
        self.shares.get(&name.to_uppercase()).map(|s| s.clone())
    }

    /// Remove a share
    pub fn remove_share(&self, name: &str) -> Option<SmbShare> {
        self.shares.remove(&name.to_uppercase()).map(|(_, s)| s)
    }

    /// List all shares
    pub fn list_shares(&self) -> Vec<SmbShare> {
        self.shares.iter().map(|e| e.value().clone()).collect()
    }

    /// Check if share exists
    pub fn has_share(&self, name: &str) -> bool {
        self.shares.contains_key(&name.to_uppercase())
    }
}

impl Default for ShareManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_share_builder() {
        let share = SmbShare::new("test", "bucket1")
            .with_path("/data")
            .read_only()
            .with_comment("Test share");

        assert_eq!(share.name, "test");
        assert_eq!(share.bucket, "bucket1");
        assert_eq!(share.path, "/data");
        assert!(share.read_only);
        assert_eq!(share.comment, "Test share");
    }

    #[test]
    fn test_share_client_allowed() {
        let mut share = SmbShare::new("test", "bucket");
        share.allowed_clients = vec!["10.0.0.0/8".parse().unwrap()];

        assert!(share.is_client_allowed(&"10.1.2.3".parse().unwrap()));
        assert!(!share.is_client_allowed(&"192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn test_share_manager() {
        let mgr = ShareManager::new();
        mgr.add_share(SmbShare::new("Test", "bucket"));

        // Case-insensitive lookup
        assert!(mgr.get_share("test").is_some());
        assert!(mgr.get_share("TEST").is_some());
        assert!(mgr.get_share("TeSt").is_some());
        assert!(mgr.get_share("nonexistent").is_none());
    }

    #[test]
    fn test_share_flags() {
        let share = SmbShare::new("test", "bucket")
            .with_caching(CachingMode::None)
            .with_abe()
            .require_encryption();

        let flags = share.flags();
        assert!(flags.has(ShareFlags::NO_CACHING));
        assert!(flags.has(ShareFlags::ABE));
        assert!(flags.has(ShareFlags::ENCRYPT_DATA));
    }
}
