//! NFS server implementation

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::BytesMut;
use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, trace, warn};

use warp_gateway_common::{DelegationManager, InMemoryLockManager, SessionManager};
use warp_store::Store;

use crate::config::{NfsConfig, NfsExport};
use crate::error::NfsResult;
use crate::nfs4::StateManager;
use crate::rpc::{
    NFS_PROGRAM, NFS_V41, RpcAcceptStatus, RpcCallHeader, RpcError, RpcRejectReason, RpcReplyHeader,
};

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
                    let server = self.clone_for_connection();
                    tokio::spawn(async move {
                        if let Err(e) = server.handle_nfs_connection(stream).await {
                            error!("NFS connection error from {}: {}", addr, e);
                        }
                        debug!("Connection from {} closed", addr);
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

impl NfsServerHandle {
    /// Handle an NFS RPC connection
    async fn handle_nfs_connection(&self, mut stream: TcpStream) -> NfsResult<()> {
        debug!("Starting NFS RPC connection handler");

        loop {
            // Read RPC record marker (4 bytes)
            // Format: MSB indicates last fragment, lower 31 bits = length
            let mut record_marker = [0u8; 4];
            match stream.read_exact(&mut record_marker).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    debug!("NFS connection closed by peer");
                    break;
                }
                Err(e) => return Err(e.into()),
            }

            let marker = u32::from_be_bytes(record_marker);
            let _is_last_fragment = (marker >> 31) == 1;
            let fragment_length = (marker & 0x7FFFFFFF) as usize;

            if fragment_length == 0 || fragment_length > 1024 * 1024 {
                warn!("Invalid RPC fragment length: {}", fragment_length);
                continue;
            }

            // Read RPC message
            let mut message = vec![0u8; fragment_length];
            stream.read_exact(&mut message).await?;

            // Process RPC message
            let response = match self.process_rpc_message(&message).await {
                Ok(resp) => resp,
                Err(e) => {
                    warn!("Error processing RPC message: {}", e);
                    self.create_rpc_error_response(&message, e)?
                }
            };

            // Send response with record marker
            let mut response_buf = BytesMut::with_capacity(4 + response.len());
            let response_marker = 0x80000000 | (response.len() as u32); // Last fragment
            response_buf.extend_from_slice(&response_marker.to_be_bytes());
            response_buf.extend_from_slice(&response);

            stream.write_all(&response_buf).await?;
        }

        Ok(())
    }

    /// Process an RPC message
    async fn process_rpc_message(&self, message: &[u8]) -> Result<Vec<u8>, RpcError> {
        // Parse RPC call header
        let (call_header, header_size) = RpcCallHeader::parse(message)?;

        trace!(
            "RPC CALL: xid={:#x}, program={}, version={}, procedure={}",
            call_header.xid, call_header.program, call_header.version, call_header.procedure
        );

        // Validate program and version
        if call_header.program != NFS_PROGRAM {
            debug!("Unknown program: {}", call_header.program);
            return self.create_prog_unavail_response(call_header.xid);
        }

        if call_header.version != NFS_V41 && call_header.version != 4 {
            debug!("Unsupported NFS version: {}", call_header.version);
            return self.create_prog_mismatch_response(call_header.xid, 4, 4);
        }

        // Get procedure arguments
        let args = &message[header_size..];

        // Dispatch to procedure handler
        match call_header.procedure {
            0 => self.handle_null(call_header.xid).await,
            1 => self.handle_compound(call_header.xid, args).await,
            _ => {
                debug!("Unknown procedure: {}", call_header.procedure);
                self.create_proc_unavail_response(call_header.xid)
            }
        }
    }

    /// Handle NULL procedure (procedure 0)
    async fn handle_null(&self, xid: u32) -> Result<Vec<u8>, RpcError> {
        trace!("NFS NULL procedure");

        let reply = RpcReplyHeader::success(xid);
        let mut buf = BytesMut::new();
        reply.encode(&mut buf);

        Ok(buf.to_vec())
    }

    /// Handle COMPOUND procedure (procedure 1)
    async fn handle_compound(&self, xid: u32, _args: &[u8]) -> Result<Vec<u8>, RpcError> {
        trace!("NFS COMPOUND procedure");

        // For now, return a minimal successful response
        // A full implementation would parse COMPOUND operations and execute them
        let reply = RpcReplyHeader::success(xid);
        let mut buf = BytesMut::new();
        reply.encode(&mut buf);

        // Add minimal COMPOUND response
        // Status: NFS4_OK (0)
        buf.extend_from_slice(&0u32.to_be_bytes());
        // Tag length: 0
        buf.extend_from_slice(&0u32.to_be_bytes());
        // Resarray count: 0
        buf.extend_from_slice(&0u32.to_be_bytes());

        Ok(buf.to_vec())
    }

    /// Create PROG_UNAVAIL error response
    fn create_prog_unavail_response(&self, xid: u32) -> Result<Vec<u8>, RpcError> {
        let reply = RpcReplyHeader::error(xid, RpcAcceptStatus::ProgUnavail);
        let mut buf = BytesMut::new();
        reply.encode(&mut buf);
        Ok(buf.to_vec())
    }

    /// Create PROG_MISMATCH error response
    fn create_prog_mismatch_response(
        &self,
        xid: u32,
        low: u32,
        high: u32,
    ) -> Result<Vec<u8>, RpcError> {
        let reply = RpcReplyHeader::error(xid, RpcAcceptStatus::ProgMismatch);
        let mut buf = BytesMut::new();
        reply.encode(&mut buf);
        // Add supported version range
        buf.extend_from_slice(&low.to_be_bytes());
        buf.extend_from_slice(&high.to_be_bytes());
        Ok(buf.to_vec())
    }

    /// Create PROC_UNAVAIL error response
    fn create_proc_unavail_response(&self, xid: u32) -> Result<Vec<u8>, RpcError> {
        let reply = RpcReplyHeader::error(xid, RpcAcceptStatus::ProcUnavail);
        let mut buf = BytesMut::new();
        reply.encode(&mut buf);
        Ok(buf.to_vec())
    }

    /// Create an RPC error response from a parse error
    fn create_rpc_error_response(&self, message: &[u8], error: RpcError) -> Result<Vec<u8>, RpcError> {
        // Try to extract XID from the message
        let xid = if message.len() >= 4 {
            u32::from_be_bytes(message[0..4].try_into().unwrap())
        } else {
            0
        };

        let reply = match error {
            RpcError::ProgUnavail => RpcReplyHeader::error(xid, RpcAcceptStatus::ProgUnavail),
            RpcError::ProcUnavail => RpcReplyHeader::error(xid, RpcAcceptStatus::ProcUnavail),
            RpcError::VersionMismatch { .. } => {
                RpcReplyHeader::denied(xid, RpcRejectReason::RpcMismatch)
            }
            _ => RpcReplyHeader::error(xid, RpcAcceptStatus::GarbageArgs),
        };

        let mut buf = BytesMut::new();
        reply.encode(&mut buf);
        Ok(buf.to_vec())
    }
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
        let config =
            NfsConfig::default().add_export(crate::config::NfsExport::new("test").with_id(1));

        let server = NfsServer::new(store, config);
        assert!(server.get_export(1).is_some());
    }
}
