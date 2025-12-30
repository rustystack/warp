//! SMB server implementation
//!
//! Main SMB3 server that handles client connections.

use std::net::SocketAddr;
use std::sync::Arc;

use dashmap::DashMap;
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

use warp_gateway_common::{DelegationManager, InMemoryLockManager, SessionManager};
use warp_store::Store;

use crate::config::SmbConfig;
use crate::error::{SmbError, SmbResult};
use crate::oplocks::OplockManager;
use crate::share::{ShareManager, SmbShare};

/// SMB server
pub struct SmbServer {
    /// Server configuration
    config: SmbConfig,
    /// Storage backend
    store: Arc<Store>,
    /// Lock manager
    lock_manager: Arc<InMemoryLockManager>,
    /// Session manager
    session_manager: Arc<SessionManager>,
    /// Oplock manager
    oplock_manager: Arc<OplockManager>,
    /// Share manager
    share_manager: Arc<ShareManager>,
}

impl SmbServer {
    /// Create a new SMB server
    pub fn new(store: Arc<Store>, config: SmbConfig) -> Self {
        let lock_manager = Arc::new(InMemoryLockManager::new());
        let session_manager = Arc::new(SessionManager::default());
        let oplock_manager = Arc::new(OplockManager::new());
        let share_manager = Arc::new(ShareManager::new());

        Self {
            config,
            store,
            lock_manager,
            session_manager,
            oplock_manager,
            share_manager,
        }
    }

    /// Get the bind address
    pub fn bind_addr(&self) -> SocketAddr {
        self.config.bind_addr
    }

    /// Get the server name
    pub fn server_name(&self) -> &str {
        &self.config.server_name
    }

    /// Get the server GUID
    pub fn server_guid(&self) -> &[u8; 16] {
        &self.config.server_guid
    }

    /// Add a share
    pub fn add_share(&self, share: SmbShare) {
        self.share_manager.add_share(share);
    }

    /// Get a share by name
    pub fn get_share(&self, name: &str) -> Option<SmbShare> {
        self.share_manager.get_share(name)
    }

    /// List all shares
    pub fn list_shares(&self) -> Vec<SmbShare> {
        self.share_manager.list_shares()
    }

    /// Run the SMB server
    pub async fn run(&self) -> SmbResult<()> {
        let listener = TcpListener::bind(self.config.bind_addr).await?;
        info!(
            "SMB server '{}' listening on {}",
            self.config.server_name, self.config.bind_addr
        );

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    debug!("Accepted connection from {}", addr);
                    // Handle connection in background
                    let _server = self.clone_for_connection();
                    tokio::spawn(async move {
                        // TODO: Handle SMB protocol connection
                        let _ = stream;
                        debug!("Connection handler for {} started", addr);
                    });
                }
                Err(e) => {
                    warn!("Failed to accept connection: {}", e);
                }
            }
        }
    }

    /// Clone server state for a connection handler
    fn clone_for_connection(&self) -> SmbServerHandle {
        SmbServerHandle {
            config: self.config.clone(),
            store: self.store.clone(),
            lock_manager: self.lock_manager.clone(),
            session_manager: self.session_manager.clone(),
            oplock_manager: self.oplock_manager.clone(),
            share_manager: self.share_manager.clone(),
        }
    }
}

/// Handle to server resources for connection handlers
#[derive(Clone)]
struct SmbServerHandle {
    config: SmbConfig,
    store: Arc<Store>,
    lock_manager: Arc<InMemoryLockManager>,
    session_manager: Arc<SessionManager>,
    oplock_manager: Arc<OplockManager>,
    share_manager: Arc<ShareManager>,
}

/// SMB session state
#[derive(Debug)]
pub struct SmbSession {
    /// Session ID
    pub session_id: u64,
    /// Client GUID
    pub client_guid: [u8; 16],
    /// Authenticated user
    pub user: Option<String>,
    /// Session flags
    pub flags: SessionFlags,
    /// Connected tree IDs
    pub trees: DashMap<u32, TreeConnect>,
}

impl SmbSession {
    /// Create a new session
    pub fn new(session_id: u64, client_guid: [u8; 16]) -> Self {
        Self {
            session_id,
            client_guid,
            user: None,
            flags: SessionFlags::default(),
            trees: DashMap::new(),
        }
    }

    /// Check if session is guest
    pub fn is_guest(&self) -> bool {
        self.flags.is_guest
    }

    /// Check if session is encrypted
    pub fn is_encrypted(&self) -> bool {
        self.flags.encrypt_data
    }
}

/// Session flags
#[derive(Debug, Clone, Default)]
pub struct SessionFlags {
    /// Guest session
    pub is_guest: bool,
    /// Null session
    pub is_null: bool,
    /// Encrypt data
    pub encrypt_data: bool,
}

/// Tree connection (share connection)
#[derive(Debug, Clone)]
pub struct TreeConnect {
    /// Tree ID
    pub tree_id: u32,
    /// Share name
    pub share_name: String,
    /// Share path (bucket + path)
    pub share_path: String,
    /// Share type
    pub share_type: u8,
    /// Share flags
    pub share_flags: u32,
    /// Share capabilities
    pub share_capabilities: u32,
    /// Max access
    pub max_access: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use warp_store::StoreConfig;

    #[tokio::test]
    async fn test_server_creation() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = StoreConfig {
            root_path: temp_dir.path().to_path_buf(),
            ..Default::default()
        };
        let store = Arc::new(Store::new(config).await.unwrap());
        let smb_config = SmbConfig::default();
        let server = SmbServer::new(store, smb_config);

        assert_eq!(server.server_name(), "WARP");
    }

    #[test]
    fn test_session() {
        let session = SmbSession::new(1, [0; 16]);
        assert!(!session.is_guest());
        assert!(!session.is_encrypted());
    }
}
