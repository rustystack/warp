//! Distributed File System (DFS) namespace support
//!
//! Implements DFS referral handling for SMB clients.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use dashmap::DashMap;

/// DFS referral entry
#[derive(Debug, Clone)]
pub struct DfsReferral {
    /// Target server
    pub server: String,
    /// Target share
    pub share: String,
    /// Full path
    pub path: String,
    /// Priority (lower = better)
    pub priority: u16,
    /// Time to live
    pub ttl: Duration,
    /// Target type
    pub target_type: DfsTargetType,
}

impl DfsReferral {
    /// Create a new referral
    pub fn new(server: impl Into<String>, share: impl Into<String>) -> Self {
        let server = server.into();
        let share = share.into();
        let path = format!("\\\\{}\\{}", server, share);

        Self {
            server,
            share,
            path,
            priority: 0,
            ttl: Duration::from_secs(300),
            target_type: DfsTargetType::Server,
        }
    }

    /// Set priority
    pub fn with_priority(mut self, priority: u16) -> Self {
        self.priority = priority;
        self
    }

    /// Set TTL
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Get the UNC path
    pub fn unc_path(&self) -> String {
        self.path.clone()
    }
}

/// DFS target type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DfsTargetType {
    /// Server target
    Server,
    /// Domain controller
    Domain,
    /// Standalone namespace root
    Root,
    /// Link target
    Link,
}

/// DFS referral version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum DfsReferralVersion {
    /// Version 1
    V1 = 1,
    /// Version 2
    V2 = 2,
    /// Version 3
    V3 = 3,
    /// Version 4
    V4 = 4,
}

/// DFS referral request flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReferralFlags(u32);

impl ReferralFlags {
    /// Site aware referral
    pub const SITE_AWARE: u32 = 0x00000001;
    /// Target fail back
    pub const TARGET_FAIL_BACK: u32 = 0x00000002;
    /// Target is outside site
    pub const TARGET_SET_OUTSIDE_SITE: u32 = 0x00000004;

    /// Create new flags
    pub fn new(flags: u32) -> Self {
        Self(flags)
    }

    /// Get raw value
    pub fn bits(&self) -> u32 {
        self.0
    }
}

/// DFS namespace entry
#[derive(Debug, Clone)]
pub struct DfsNamespace {
    /// Namespace name
    pub name: String,
    /// Root path
    pub root: String,
    /// Links in namespace
    pub links: HashMap<String, Vec<DfsReferral>>,
    /// Namespace type
    pub ns_type: DfsNamespaceType,
    /// TTL for referrals
    pub ttl: Duration,
}

impl DfsNamespace {
    /// Create a new standalone namespace
    pub fn standalone(name: impl Into<String>, server: impl Into<String>) -> Self {
        let name = name.into();
        let server = server.into();

        Self {
            root: format!("\\\\{}\\{}", server, name),
            name,
            links: HashMap::new(),
            ns_type: DfsNamespaceType::Standalone,
            ttl: Duration::from_secs(300),
        }
    }

    /// Add a link
    pub fn add_link(&mut self, link_name: impl Into<String>, referrals: Vec<DfsReferral>) {
        self.links.insert(link_name.into(), referrals);
    }

    /// Get referrals for a path
    pub fn get_referrals(&self, path: &str) -> Option<&Vec<DfsReferral>> {
        // Remove namespace root from path
        let relative = path.strip_prefix(&self.root).unwrap_or(path);
        let relative = relative.trim_start_matches('\\');

        // Look up link
        if relative.is_empty() {
            return None; // Root referral
        }

        // Get first path component as link name
        let link_name = relative.split('\\').next()?;
        self.links.get(link_name)
    }
}

/// DFS namespace type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DfsNamespaceType {
    /// Standalone (single server)
    Standalone,
    /// Domain-based (Active Directory integrated)
    DomainBased,
}

/// DFS referral response
#[derive(Debug, Clone)]
pub struct DfsReferralResponse {
    /// Path consumed (bytes)
    pub path_consumed: u16,
    /// Number of referrals
    pub number_of_referrals: u16,
    /// Referral header flags
    pub header_flags: ReferralHeaderFlags,
    /// Referrals
    pub referrals: Vec<DfsReferralEntry>,
}

/// Referral header flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReferralHeaderFlags(u32);

impl ReferralHeaderFlags {
    /// Storage servers (not namespace servers)
    pub const STORAGE_SERVER: u32 = 0x00000002;
    /// Target failback enabled
    pub const TARGET_FAIL_BACK: u32 = 0x00000004;

    /// Create new flags
    pub fn new(flags: u32) -> Self {
        Self(flags)
    }

    /// Get raw value
    pub fn bits(&self) -> u32 {
        self.0
    }
}

impl Default for ReferralHeaderFlags {
    fn default() -> Self {
        Self(0)
    }
}

/// DFS referral entry (v3/v4)
#[derive(Debug, Clone)]
pub struct DfsReferralEntry {
    /// Version
    pub version: DfsReferralVersion,
    /// Entry size
    pub size: u16,
    /// Server type (0=link, 1=root)
    pub server_type: u16,
    /// Entry flags
    pub flags: u16,
    /// Time to live (seconds)
    pub ttl: u32,
    /// DFS path
    pub dfs_path: String,
    /// DFS alternate path
    pub dfs_alt_path: String,
    /// Network address (target path)
    pub network_address: String,
}

impl DfsReferralEntry {
    /// Create from a DfsReferral
    pub fn from_referral(referral: &DfsReferral, dfs_path: &str) -> Self {
        Self {
            version: DfsReferralVersion::V4,
            size: 0, // Calculated during encoding
            server_type: match referral.target_type {
                DfsTargetType::Root => 1,
                _ => 0,
            },
            flags: 0,
            ttl: referral.ttl.as_secs() as u32,
            dfs_path: dfs_path.to_string(),
            dfs_alt_path: dfs_path.to_string(),
            network_address: referral.unc_path(),
        }
    }
}

/// DFS manager
#[derive(Debug)]
pub struct DfsManager {
    /// Namespaces by name
    namespaces: DashMap<String, DfsNamespace>,
    /// Server name
    server_name: String,
}

impl DfsManager {
    /// Create a new DFS manager
    pub fn new(server_name: impl Into<String>) -> Self {
        Self {
            namespaces: DashMap::new(),
            server_name: server_name.into(),
        }
    }

    /// Add a namespace
    pub fn add_namespace(&self, namespace: DfsNamespace) {
        self.namespaces
            .insert(namespace.name.to_uppercase(), namespace);
    }

    /// Get namespace by name (case-insensitive)
    pub fn get_namespace(&self, name: &str) -> Option<DfsNamespace> {
        self.namespaces.get(&name.to_uppercase()).map(|n| n.clone())
    }

    /// Check if path is a DFS path
    pub fn is_dfs_path(&self, path: &str) -> bool {
        // Parse path to get namespace name
        let path = path.trim_start_matches("\\\\");
        let parts: Vec<&str> = path.split('\\').collect();

        if parts.len() < 2 {
            return false;
        }

        let server = parts[0];
        let share = parts[1];

        // Check if server matches and share is a DFS namespace
        if server.eq_ignore_ascii_case(&self.server_name) {
            self.namespaces.contains_key(&share.to_uppercase())
        } else {
            false
        }
    }

    /// Get referrals for a DFS path
    pub fn get_referrals(&self, path: &str) -> Option<DfsReferralResponse> {
        let path = path.trim_start_matches("\\\\");
        let parts: Vec<&str> = path.split('\\').collect();

        if parts.len() < 2 {
            return None;
        }

        let share = parts[1];
        let namespace = self.namespaces.get(&share.to_uppercase())?;

        // Build remaining path
        let remaining = if parts.len() > 2 {
            parts[2..].join("\\")
        } else {
            String::new()
        };

        let referrals = if remaining.is_empty() {
            // Root referral
            vec![DfsReferralEntry {
                version: DfsReferralVersion::V4,
                size: 0,
                server_type: 1, // Root
                flags: 0,
                ttl: namespace.ttl.as_secs() as u32,
                dfs_path: namespace.root.clone(),
                dfs_alt_path: namespace.root.clone(),
                network_address: namespace.root.clone(),
            }]
        } else {
            // Link referral
            let link_name = remaining.split('\\').next()?;
            let link_referrals = namespace.links.get(link_name)?;

            link_referrals
                .iter()
                .map(|r| DfsReferralEntry::from_referral(r, &format!("{}\\{}", namespace.root, link_name)))
                .collect()
        };

        Some(DfsReferralResponse {
            path_consumed: (path.len() * 2) as u16, // UTF-16
            number_of_referrals: referrals.len() as u16,
            header_flags: ReferralHeaderFlags::new(ReferralHeaderFlags::STORAGE_SERVER),
            referrals,
        })
    }
}

impl Default for DfsManager {
    fn default() -> Self {
        Self::new("WARP")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dfs_referral() {
        let referral = DfsReferral::new("server1", "share1")
            .with_priority(0)
            .with_ttl(Duration::from_secs(600));

        assert_eq!(referral.unc_path(), "\\\\server1\\share1");
        assert_eq!(referral.priority, 0);
    }

    #[test]
    fn test_dfs_namespace() {
        let mut ns = DfsNamespace::standalone("dfs", "WARP");
        ns.add_link(
            "data",
            vec![DfsReferral::new("storage1", "data")],
        );

        assert_eq!(ns.root, "\\\\WARP\\dfs");
        assert!(ns.get_referrals("\\\\WARP\\dfs\\data").is_some());
    }

    #[test]
    fn test_dfs_manager() {
        let mgr = DfsManager::new("WARP");

        let mut ns = DfsNamespace::standalone("shares", "WARP");
        ns.add_link(
            "data",
            vec![
                DfsReferral::new("storage1", "data").with_priority(0),
                DfsReferral::new("storage2", "data").with_priority(1),
            ],
        );

        mgr.add_namespace(ns);

        assert!(mgr.is_dfs_path("\\\\WARP\\shares\\data"));
        assert!(!mgr.is_dfs_path("\\\\WARP\\regular\\data"));

        let referrals = mgr.get_referrals("\\\\WARP\\shares\\data").unwrap();
        assert_eq!(referrals.number_of_referrals, 2);
    }
}
