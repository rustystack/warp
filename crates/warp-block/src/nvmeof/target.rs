//! NVMe-oF Target Implementation
//!
//! This module provides the main NvmeOfTarget server that exposes
//! WARP storage as NVMe namespaces.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use bytes::Bytes;
use parking_lot::RwLock;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

use super::capsule::ResponseCapsule;
use super::config::{NvmeOfConfig, SubsystemConfig, TransportType};
use super::connection::{NamespaceHandler, NvmeOfConnection};
use super::discovery::DiscoveryService;
use super::error::{NvmeOfError, NvmeOfResult, NvmeStatus};
use super::namespace::{AsyncVolume, NamespaceHandlerImpl, NamespaceId, NvmeOfNamespace};
use super::subsystem::{NvmeOfSubsystem, SubsystemManager};
use super::transport::tcp::TcpTransport;
use super::transport::{ConnectionState, NvmeOfTransport, TransportConnection};

/// Namespace handler that routes to a subsystem's namespace manager
type SubsystemNamespaceHandler = NamespaceHandlerImpl;

/// NVMe-oF Target Server
///
/// The main entry point for running an NVMe-oF target that exposes
/// WARP storage as NVMe namespaces.
pub struct NvmeOfTarget {
    /// Configuration
    config: NvmeOfConfig,

    /// Subsystem manager
    subsystems: Arc<SubsystemManager>,

    /// Discovery service
    discovery: Arc<DiscoveryService>,

    /// Active connections
    connections: RwLock<HashMap<u64, Arc<NvmeOfConnection>>>,

    /// Connection ID counter
    connection_counter: AtomicU64,

    /// Running flag
    running: AtomicBool,

    /// Shutdown signal sender
    shutdown_tx: broadcast::Sender<()>,

    /// Statistics
    stats: RwLock<TargetStats>,
}

impl NvmeOfTarget {
    /// Create a new NVMe-oF target
    pub async fn new(config: NvmeOfConfig) -> NvmeOfResult<Arc<Self>> {
        let subsystems = Arc::new(SubsystemManager::new());
        let discovery = Arc::new(DiscoveryService::new(subsystems.clone()));

        let (shutdown_tx, _) = broadcast::channel(1);

        let target = Arc::new(Self {
            config,
            subsystems,
            discovery,
            connections: RwLock::new(HashMap::new()),
            connection_counter: AtomicU64::new(0),
            running: AtomicBool::new(false),
            shutdown_tx,
            stats: RwLock::new(TargetStats::default()),
        });

        info!("NVMe-oF target created");
        Ok(target)
    }

    /// Get the configuration
    pub fn config(&self) -> &NvmeOfConfig {
        &self.config
    }

    /// Get the subsystem manager
    pub fn subsystems(&self) -> &Arc<SubsystemManager> {
        &self.subsystems
    }

    /// Get the discovery service
    pub fn discovery(&self) -> &Arc<DiscoveryService> {
        &self.discovery
    }

    // ======== Subsystem Management ========

    /// Create a new subsystem
    pub fn create_subsystem(&self, config: SubsystemConfig) -> NvmeOfResult<String> {
        let subsystem = self.subsystems.create(config)?;
        let nqn = subsystem.nqn().to_string();
        info!("Created subsystem: {}", nqn);
        Ok(nqn)
    }

    /// Delete a subsystem
    pub async fn delete_subsystem(&self, nqn: &str) -> NvmeOfResult<()> {
        self.subsystems.delete(nqn).await?;
        info!("Deleted subsystem: {}", nqn);
        Ok(())
    }

    /// Get a subsystem by NQN
    pub fn get_subsystem(&self, nqn: &str) -> Option<Arc<NvmeOfSubsystem>> {
        self.subsystems.get(nqn)
    }

    /// List all subsystem NQNs
    pub fn list_subsystems(&self) -> Vec<String> {
        self.subsystems.list()
    }

    // ======== Namespace Management ========

    /// Add a namespace to a subsystem
    pub fn add_namespace(
        &self,
        subsystem_nqn: &str,
        nsid: NamespaceId,
        volume: Arc<dyn AsyncVolume>,
    ) -> NvmeOfResult<Arc<NvmeOfNamespace>> {
        let subsystem = self.subsystems.get(subsystem_nqn).ok_or_else(|| {
            NvmeOfError::Subsystem(format!("Subsystem {} not found", subsystem_nqn))
        })?;

        let namespace = subsystem.add_namespace(nsid, volume)?;
        info!("Added namespace {} to subsystem {}", nsid, subsystem_nqn);

        Ok(namespace)
    }

    /// Add a namespace with auto-assigned ID
    pub fn add_namespace_auto(
        &self,
        subsystem_nqn: &str,
        volume: Arc<dyn AsyncVolume>,
    ) -> NvmeOfResult<(NamespaceId, Arc<NvmeOfNamespace>)> {
        let subsystem = self.subsystems.get(subsystem_nqn).ok_or_else(|| {
            NvmeOfError::Subsystem(format!("Subsystem {} not found", subsystem_nqn))
        })?;

        let (nsid, namespace) = subsystem.add_namespace_auto(volume)?;
        info!(
            "Added namespace {} (auto) to subsystem {}",
            nsid, subsystem_nqn
        );

        Ok((nsid, namespace))
    }

    /// Remove a namespace from a subsystem
    pub fn remove_namespace(&self, subsystem_nqn: &str, nsid: NamespaceId) -> NvmeOfResult<()> {
        let subsystem = self.subsystems.get(subsystem_nqn).ok_or_else(|| {
            NvmeOfError::Subsystem(format!("Subsystem {} not found", subsystem_nqn))
        })?;

        subsystem.remove_namespace(nsid)?;
        info!(
            "Removed namespace {} from subsystem {}",
            nsid, subsystem_nqn
        );

        Ok(())
    }

    // ======== Server Control ========

    /// Start the target server
    pub async fn run(self: &Arc<Self>) -> NvmeOfResult<()> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Err(NvmeOfError::Internal("Target already running".to_string()));
        }

        info!("Starting NVMe-oF target");

        let bind_addr = SocketAddr::new(self.config.bind_addr, self.config.port);

        // Start TCP transport if configured
        if let Some(ref tcp_config) = self.config.tcp {
            if tcp_config.enabled {
                let target = self.clone();
                let mut transport = TcpTransport::new(tcp_config.clone());
                transport.bind(bind_addr).await?;

                // Register listen address with discovery
                self.discovery
                    .add_listen_addr(TransportType::Tcp, bind_addr);

                // Spawn accept loop
                let shutdown_rx = self.shutdown_tx.subscribe();
                tokio::spawn(async move {
                    target.accept_loop(transport, shutdown_rx).await;
                });

                info!("TCP transport listening on {}", bind_addr);
            }
        }

        // TODO: Add RDMA transport support
        // TODO: Add QUIC transport support

        Ok(())
    }

    /// Accept loop for incoming connections
    async fn accept_loop<T: NvmeOfTransport>(
        self: &Arc<Self>,
        transport: T,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) {
        loop {
            tokio::select! {
                result = transport.accept() => {
                    match result {
                        Ok(conn) => {
                            if let Err(e) = self.handle_new_connection(conn).await {
                                warn!("Failed to handle connection: {}", e);
                            }
                        }
                        Err(e) => {
                            error!("Accept error: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("Accept loop shutting down");
                    break;
                }
            }
        }
    }

    /// Handle a new incoming connection
    async fn handle_new_connection(
        self: &Arc<Self>,
        transport_conn: Box<dyn TransportConnection>,
    ) -> NvmeOfResult<()> {
        let conn_id = self.connection_counter.fetch_add(1, Ordering::Relaxed);
        let remote_addr = transport_conn.remote_addr();

        info!("New connection {} from {}", conn_id, remote_addr);

        let connection = Arc::new(NvmeOfConnection::new(
            conn_id,
            Arc::from(transport_conn),
            &self.config,
        ));

        // Store connection
        self.connections.write().insert(conn_id, connection.clone());
        self.stats.write().connections_accepted += 1;

        // Spawn connection handler
        let target = self.clone();
        tokio::spawn(async move {
            if let Err(e) = target.connection_loop(connection.clone()).await {
                debug!("Connection {} ended: {}", conn_id, e);
            }
            target.connections.write().remove(&conn_id);
        });

        Ok(())
    }

    /// Connection processing loop
    async fn connection_loop(
        self: &Arc<Self>,
        connection: Arc<NvmeOfConnection>,
    ) -> NvmeOfResult<()> {
        let conn_id = connection.id();
        let transport = connection.transport().clone();

        // Perform ICReq/ICResp handshake
        if let Err(e) = transport.initialize_as_target().await {
            warn!("Connection {} handshake failed: {}", conn_id, e);
            return Err(e);
        }

        info!("Connection {} handshake complete", conn_id);

        // Start with no namespace handler - will be set after Connect command
        let mut namespace_handler: Option<SubsystemNamespaceHandler> = None;

        // Command processing loop
        loop {
            // Check if connection is still active
            if !connection.is_active() || !transport.is_connected() {
                debug!("Connection {} no longer active", conn_id);
                break;
            }

            // Receive next command
            let capsule = match transport.recv_command().await {
                Ok(capsule) => capsule,
                Err(e) => {
                    // Check if this is a clean disconnect
                    if !transport.is_connected() {
                        debug!("Connection {} closed by peer", conn_id);
                        break;
                    }
                    warn!("Connection {} recv error: {}", conn_id, e);
                    break;
                }
            };

            // Process the command
            let handler: &dyn NamespaceHandler = match &namespace_handler {
                Some(h) => h,
                None => &DummyNamespaceHandler, // Before Connect command
            };

            let response = match connection.process_command(capsule.clone(), handler).await {
                Ok(response) => {
                    // After Connect command, set up the real namespace handler
                    if namespace_handler.is_none() && connection.state() == ConnectionState::Ready
                    {
                        let subsystem_nqn = connection.subsystem_nqn();
                        if let Some(subsystem) = self.subsystems.get(&subsystem_nqn) {
                            namespace_handler = Some(SubsystemNamespaceHandler::new(
                                subsystem.namespace_manager().clone(),
                            ));
                            info!(
                                "Connection {} connected to subsystem {}",
                                conn_id, subsystem_nqn
                            );
                        }
                    }
                    response
                }
                Err(e) => {
                    warn!("Connection {} command processing error: {}", conn_id, e);
                    // Create error response
                    ResponseCapsule::error(
                        capsule.command.cid(),
                        0,
                        0,
                        NvmeStatus::InternalError,
                    )
                }
            };

            // Send response
            if let Err(e) = transport.send_response(&response).await {
                warn!("Connection {} send error: {}", conn_id, e);
                break;
            }

            // Update stats
            self.stats.write().commands_processed += 1;
        }

        debug!("Connection loop ended for {}", conn_id);
        Ok(())
    }

    /// Stop the target server
    pub async fn stop(&self) -> NvmeOfResult<()> {
        if !self.running.swap(false, Ordering::SeqCst) {
            return Ok(()); // Already stopped
        }

        info!("Stopping NVMe-oF target");

        // Signal shutdown
        let _ = self.shutdown_tx.send(());

        // Close all connections
        let connections: Vec<_> = self.connections.write().drain().collect();
        for (conn_id, conn) in connections {
            info!("Closing connection {}", conn_id);
            if let Err(e) = conn.close().await {
                warn!("Error closing connection {}: {}", conn_id, e);
            }
        }

        // Clear discovery addresses
        self.discovery.clear_listen_addrs();

        info!("NVMe-oF target stopped");
        Ok(())
    }

    /// Check if target is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Get number of active connections
    pub fn connection_count(&self) -> usize {
        self.connections.read().len()
    }

    /// Get statistics
    pub fn stats(&self) -> TargetStats {
        self.stats.read().clone()
    }

    /// Get a connection by ID
    pub fn get_connection(&self, conn_id: u64) -> Option<Arc<NvmeOfConnection>> {
        self.connections.read().get(&conn_id).cloned()
    }

    /// List all connection IDs
    pub fn list_connections(&self) -> Vec<u64> {
        self.connections.read().keys().copied().collect()
    }
}

/// Dummy namespace handler for testing
struct DummyNamespaceHandler;

#[async_trait::async_trait]
impl NamespaceHandler for DummyNamespaceHandler {
    async fn read(&self, _nsid: u32, _slba: u64, _nlb: u32) -> NvmeOfResult<Bytes> {
        Ok(Bytes::new())
    }

    async fn write(&self, _nsid: u32, _slba: u64, _nlb: u32, _data: Bytes) -> NvmeOfResult<()> {
        Ok(())
    }

    async fn flush(&self, _nsid: u32) -> NvmeOfResult<()> {
        Ok(())
    }

    async fn write_zeroes(&self, _nsid: u32, _slba: u64, _nlb: u32) -> NvmeOfResult<()> {
        Ok(())
    }

    async fn trim(&self, _nsid: u32, _slba: u64, _nlb: u32) -> NvmeOfResult<()> {
        Ok(())
    }

    async fn size(&self, _nsid: u32) -> NvmeOfResult<u64> {
        Ok(0)
    }

    async fn block_size(&self, _nsid: u32) -> NvmeOfResult<u32> {
        Ok(4096)
    }
}

/// Target statistics
#[derive(Debug, Clone, Default)]
pub struct TargetStats {
    /// Total connections accepted
    pub connections_accepted: u64,

    /// Total connections rejected
    pub connections_rejected: u64,

    /// Total commands processed
    pub commands_processed: u64,

    /// Total bytes read
    pub bytes_read: u64,

    /// Total bytes written
    pub bytes_written: u64,

    /// Uptime in seconds
    pub uptime_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_target_creation() {
        let config = NvmeOfConfig::default();
        let target = NvmeOfTarget::new(config).await.unwrap();

        assert!(!target.is_running());
        assert_eq!(target.connection_count(), 0);
    }

    #[tokio::test]
    async fn test_subsystem_management() {
        let config = NvmeOfConfig::default();
        let target = NvmeOfTarget::new(config).await.unwrap();

        // Create subsystem
        let nqn = target
            .create_subsystem(SubsystemConfig {
                name: "test-storage".to_string(),
                ..Default::default()
            })
            .unwrap();

        assert_eq!(nqn, "nqn.2024-01.io.warp:test-storage");

        // List subsystems (should include discovery + our new one)
        let subsystems = target.list_subsystems();
        assert_eq!(subsystems.len(), 2);

        // Get subsystem
        let subsystem = target.get_subsystem(&nqn).unwrap();
        assert_eq!(subsystem.nqn(), &nqn);
    }
}
