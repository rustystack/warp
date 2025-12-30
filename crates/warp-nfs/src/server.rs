//! NFS server implementation

use std::net::SocketAddr;
use std::sync::Arc;

use dashmap::DashMap;
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

use warp_gateway_common::{
    DelegationManager, InMemoryLockManager, LockManager, SessionManager,
};
use warp_store::Store;

use crate::config::{NfsConfig, NfsExport};
use crate::error::{NfsError, NfsResult};
use crate::nfs4::StateManager;

/// NFS server
pub struct NfsServer {
    /// Server configuration
    config: NfsConfig,
    /// Storage backend
    store: Arc<Store>,
    /// Lock manager
    lock_manager: Arc<InMemoryLockManager>,
    /// Session manager
    session_manager: Arc<SessionManager>,
    /// Delegation manager
    delegation_manager: Arc<DelegationManager>,
    /// State manager (for stateids)
    state_manager: Arc<StateManager>,
    /// Exports by ID
    exports: DashMap<u32, NfsExport>,
    /// Exports by path
    exports_by_path: DashMap<String, u32>,
}

impl NfsServer {
    /// Create a new NFS server
    pub fn new(store: Arc<Store>, config: NfsConfig) -> Self {
        let lock_manager = Arc::new(InMemoryLockManager::new());
        let session_manager = Arc::new(SessionManager::default());
        let delegation_manager = Arc::new(DelegationManager::new());
        let state_manager = Arc::new(StateManager::new());

        let exports = DashMap::new();
        let exports_by_path = DashMap::new();

        for export in &config.exports {
            exports.insert(export.export_id, export.clone());
            exports_by_path.insert(export.path.clone(), export.export_id);
        }

        Self {
            config,
            store,
            lock_manager,
            session_manager,
            delegation_manager,
            state_manager,
            exports,
            exports_by_path,
        }
    }

    /// Get the bind address
    pub fn bind_addr(&self) -> SocketAddr {
        self.config.bind_addr
    }

    /// Get an export by ID
    pub fn get_export(&self, id: u32) -> Option<NfsExport> {
        self.exports.get(&id).map(|e| e.clone())
    }

    /// Get an export by path
    pub fn get_export_by_path(&self, path: &str) -> Option<NfsExport> {
        self.exports_by_path
            .get(path)
            .and_then(|id| self.get_export(*id))
    }

    /// Run the NFS server
    pub async fn run(&self) -> NfsResult<()> {
        let listener = TcpListener::bind(self.config.bind_addr).await?;
        info!("NFS server listening on {}", self.config.bind_addr);

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    debug!("Accepted connection from {}", addr);
                    // Handle connection in background
                    let _server = self.clone_for_connection();
                    tokio::spawn(async move {
                        // TODO: Handle NFS RPC connection
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
    fn clone_for_connection(&self) -> NfsServerHandle {
        NfsServerHandle {
            store: self.store.clone(),
            lock_manager: self.lock_manager.clone(),
            session_manager: self.session_manager.clone(),
            delegation_manager: self.delegation_manager.clone(),
            state_manager: self.state_manager.clone(),
            exports: self.exports.clone(),
        }
    }
}

/// Handle to server resources for connection handlers
struct NfsServerHandle {
    store: Arc<Store>,
    lock_manager: Arc<InMemoryLockManager>,
    session_manager: Arc<SessionManager>,
    delegation_manager: Arc<DelegationManager>,
    state_manager: Arc<StateManager>,
    exports: DashMap<u32, NfsExport>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use warp_store::StoreConfig;

    #[tokio::test]
    async fn test_server_creation() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store_config = StoreConfig {
            root_path: temp_dir.path().to_path_buf(),
            ..Default::default()
        };
        let store = Arc::new(Store::new(store_config).await.unwrap());
        let config = NfsConfig::default()
            .add_export(crate::config::NfsExport::new("test").with_id(1));

        let server = NfsServer::new(store, config);
        assert!(server.get_export(1).is_some());
    }
}
