//! NFS server configuration

use std::net::SocketAddr;
use std::time::Duration;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// Security flavor for NFS authentication
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityFlavor {
    /// AUTH_SYS (traditional UNIX authentication)
    Sys,
    /// RPCSEC_GSS with Kerberos (authentication only)
    Krb5,
    /// RPCSEC_GSS with Kerberos (authentication + integrity)
    Krb5i,
    /// RPCSEC_GSS with Kerberos (authentication + integrity + privacy)
    Krb5p,
}

impl Default for SecurityFlavor {
    fn default() -> Self {
        Self::Sys
    }
}

/// UID/GID squashing mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SquashMode {
    /// No squashing
    None,
    /// Squash root (UID 0) to anonymous
    RootSquash,
    /// Squash all UIDs to anonymous
    AllSquash,
}

impl Default for SquashMode {
    fn default() -> Self {
        Self::RootSquash
    }
}

/// NFS export configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NfsExport {
    /// Export ID (unique identifier)
    pub export_id: u32,
    /// Export path (relative to bucket)
    pub path: String,
    /// WARP storage bucket
    pub bucket: String,
    /// Allowed client networks
    pub allowed_clients: Vec<IpNet>,
    /// Read-only export
    pub read_only: bool,
    /// UID/GID squashing mode
    pub squash: SquashMode,
    /// Anonymous UID (for squashed users)
    pub anon_uid: u32,
    /// Anonymous GID (for squashed users)
    pub anon_gid: u32,
    /// Allowed security flavors
    pub security: Vec<SecurityFlavor>,
}

impl Default for NfsExport {
    fn default() -> Self {
        Self {
            export_id: 0,
            path: "/".to_string(),
            bucket: String::new(),
            allowed_clients: vec!["0.0.0.0/0".parse().unwrap()],
            read_only: false,
            squash: SquashMode::RootSquash,
            anon_uid: 65534,
            anon_gid: 65534,
            security: vec![SecurityFlavor::Sys],
        }
    }
}

impl NfsExport {
    /// Create a new export with the given bucket
    pub fn new(bucket: impl Into<String>) -> Self {
        Self {
            bucket: bucket.into(),
            ..Default::default()
        }
    }

    /// Set export ID
    pub fn with_id(mut self, id: u32) -> Self {
        self.export_id = id;
        self
    }

    /// Set export path
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = path.into();
        self
    }

    /// Set read-only
    pub fn read_only(mut self) -> Self {
        self.read_only = true;
        self
    }

    /// Add allowed client network
    pub fn allow_client(mut self, network: IpNet) -> Self {
        self.allowed_clients.push(network);
        self
    }

    /// Set allowed client networks (replaces default)
    pub fn with_allowed_clients(mut self, clients: Vec<IpNet>) -> Self {
        self.allowed_clients = clients;
        self
    }

    /// Check if client IP is allowed
    pub fn is_client_allowed(&self, addr: &std::net::IpAddr) -> bool {
        self.allowed_clients.iter().any(|net| net.contains(addr))
    }
}

/// NFS server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NfsConfig {
    /// TCP bind address
    pub bind_addr: SocketAddr,
    /// Enable NFSv4.1 (required for pNFS and sessions)
    pub nfs41_enabled: bool,
    /// Enable pNFS (parallel NFS)
    pub pnfs_enabled: bool,
    /// Enable client delegations
    pub delegations_enabled: bool,
    /// Lease time (how long clients can cache without renewal)
    pub lease_time: Duration,
    /// Grace period (time for clients to reclaim state after server restart)
    pub grace_period: Duration,
    /// Maximum COMPOUND operations per request
    pub max_compound_ops: usize,
    /// Maximum number of session slots
    pub max_session_slots: u32,
    /// Maximum read size
    pub max_read_size: usize,
    /// Maximum write size
    pub max_write_size: usize,
    /// Exports
    pub exports: Vec<NfsExport>,
}

impl Default for NfsConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:2049".parse().unwrap(),
            nfs41_enabled: true,
            pnfs_enabled: true,
            delegations_enabled: true,
            lease_time: Duration::from_secs(90),
            grace_period: Duration::from_secs(90),
            max_compound_ops: 16,
            max_session_slots: 16,
            max_read_size: 1024 * 1024,  // 1 MB
            max_write_size: 1024 * 1024, // 1 MB
            exports: Vec::new(),
        }
    }
}

impl NfsConfig {
    /// Create a new configuration with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Set bind address
    pub fn bind(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = addr;
        self
    }

    /// Add an export
    pub fn add_export(mut self, export: NfsExport) -> Self {
        self.exports.push(export);
        self
    }

    /// Disable pNFS
    pub fn disable_pnfs(mut self) -> Self {
        self.pnfs_enabled = false;
        self
    }

    /// Disable delegations
    pub fn disable_delegations(mut self) -> Self {
        self.delegations_enabled = false;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_export_client_allowed() {
        let export = NfsExport::new("test-bucket")
            .with_allowed_clients(vec!["10.0.0.0/8".parse().unwrap()]);

        assert!(export.is_client_allowed(&"10.1.2.3".parse().unwrap()));
        assert!(!export.is_client_allowed(&"192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn test_config_builder() {
        let config = NfsConfig::new()
            .bind("0.0.0.0:12049".parse().unwrap())
            .add_export(NfsExport::new("bucket1").with_id(1))
            .disable_pnfs();

        assert_eq!(config.bind_addr.port(), 12049);
        assert_eq!(config.exports.len(), 1);
        assert!(!config.pnfs_enabled);
    }
}
