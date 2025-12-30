//! NBD server implementation
//!
//! Main NBD server that handles client connections.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

use warp_store::Store;

use crate::config::{BlockConfig, ThinPoolConfig, ThinVolumeConfig};
use crate::error::{BlockError, BlockResult};
use crate::nbd::{ExportInfo, GlobalFlags, TransmissionFlags};
use crate::snapshot::SnapshotManager;
use crate::thin::{ThinPool, ThinVolume};
use crate::volume::{VolumeId, VolumeInfo, VolumeState};

/// NBD server
pub struct NbdServer {
    /// Server configuration
    config: BlockConfig,
    /// Storage backend
    store: Arc<Store>,
    /// Thin pools
    pools: DashMap<String, Arc<ThinPool>>,
    /// Snapshot manager
    snapshot_manager: Arc<SnapshotManager>,
    /// Active connections
    connections: AtomicU64,
    /// Export info cache
    exports: DashMap<String, ExportInfo>,
}

impl NbdServer {
    /// Create a new NBD server
    pub fn new(store: Arc<Store>, config: BlockConfig) -> Self {
        Self {
            config,
            store,
            pools: DashMap::new(),
            snapshot_manager: Arc::new(SnapshotManager::new()),
            connections: AtomicU64::new(0),
            exports: DashMap::new(),
        }
    }

    /// Get the bind address
    pub fn bind_addr(&self) -> SocketAddr {
        self.config.bind_addr
    }

    /// Get connection count
    pub fn connection_count(&self) -> u64 {
        self.connections.load(Ordering::Relaxed)
    }

    /// Create a thin pool
    pub fn create_pool(&self, config: ThinPoolConfig) -> BlockResult<()> {
        let name = config.name.clone();
        if self.pools.contains_key(&name) {
            return Err(BlockError::Protocol(format!("Pool {} already exists", name)));
        }

        let pool = Arc::new(ThinPool::new(config));
        self.pools.insert(name, pool);
        Ok(())
    }

    /// Get a pool by name
    pub fn get_pool(&self, name: &str) -> Option<Arc<ThinPool>> {
        self.pools.get(name).map(|p| p.clone())
    }

    /// List all pools
    pub fn list_pools(&self) -> Vec<PoolInfo> {
        self.pools
            .iter()
            .map(|entry| {
                let pool = entry.value();
                PoolInfo {
                    name: pool.name().to_string(),
                    chunk_size: pool.chunk_size(),
                    allocated_bytes: pool.allocated_bytes(),
                    max_size: pool.max_size(),
                    volume_count: pool.list_volumes().len(),
                }
            })
            .collect()
    }

    /// Create a volume
    pub fn create_volume(&self, config: ThinVolumeConfig) -> BlockResult<VolumeId> {
        let pool = self
            .pools
            .get(&config.pool)
            .ok_or_else(|| BlockError::PoolNotFound(config.pool.clone()))?;

        let volume_id = pool.create_volume(config.clone())?;

        // Register export
        let volume = pool.get_volume(&volume_id).unwrap();
        let export = ExportInfo::new(&volume.name, volume.size())
            .block_sizes(
                1,
                volume.block_size,
                32 * 1024 * 1024,
            );

        let export = if volume.is_read_only() {
            ExportInfo {
                flags: TransmissionFlags::default_ro(),
                ..export
            }
        } else {
            export
        };

        self.exports.insert(volume.name.clone(), export);
        Ok(volume_id)
    }

    /// Get a volume by ID
    pub fn get_volume(&self, pool_name: &str, volume_id: &VolumeId) -> Option<VolumeInfo> {
        let pool = self.pools.get(pool_name)?;
        let volume = pool.get_volume(volume_id)?;

        Some(VolumeInfo {
            id: volume.id,
            name: volume.name.clone(),
            size: volume.size(),
            allocated: volume.allocated(),
            block_size: volume.block_size,
            read_only: volume.is_read_only(),
            state: volume.state,
            pool: Some(pool_name.to_string()),
            parent: volume.parent,
            child_count: volume.children.read().len(),
            connections: volume.connection_count(),
        })
    }

    /// Get volume by name
    pub fn get_volume_by_name(&self, name: &str) -> Option<(String, VolumeId)> {
        for pool in self.pools.iter() {
            for volume_id in pool.list_volumes() {
                if let Some(volume) = pool.get_volume(&volume_id) {
                    if volume.name == name {
                        return Some((pool.name().to_string(), volume_id));
                    }
                }
            }
        }
        None
    }

    /// Delete a volume
    pub fn delete_volume(&self, pool_name: &str, volume_id: &VolumeId) -> BlockResult<()> {
        let pool = self
            .pools
            .get(pool_name)
            .ok_or_else(|| BlockError::PoolNotFound(pool_name.to_string()))?;

        // Check if volume exists and is not busy
        let volume = pool
            .get_volume(volume_id)
            .ok_or_else(|| BlockError::VolumeNotFound(format!("{}", volume_id)))?;

        if volume.connection_count() > 0 {
            return Err(BlockError::VolumeBusy {
                clients: volume.connection_count() as usize,
            });
        }

        if volume.has_children() {
            return Err(BlockError::SnapshotHasChildren);
        }

        // Remove export
        self.exports.remove(&volume.name);

        // Remove from pool
        drop(volume);
        pool.remove_volume(volume_id);
        Ok(())
    }

    /// Create a snapshot
    pub fn create_snapshot(
        &self,
        pool_name: &str,
        volume_id: &VolumeId,
        name: impl Into<String>,
    ) -> BlockResult<VolumeId> {
        let pool = self
            .pools
            .get(pool_name)
            .ok_or_else(|| BlockError::PoolNotFound(pool_name.to_string()))?;

        let volume = pool
            .get_volume(volume_id)
            .ok_or_else(|| BlockError::VolumeNotFound(format!("{}", volume_id)))?;

        let snap_id = self.snapshot_manager.create_snapshot(name, &volume)?;

        // Register the snapshot as a read-only volume
        let snapshot = self.snapshot_manager.get_snapshot(&snap_id).unwrap();
        let export = ExportInfo::new(&snapshot.name, snapshot.size()).read_only();
        self.exports.insert(snapshot.name.clone(), export);

        Ok(snap_id)
    }

    /// Get export info by name
    pub fn get_export(&self, name: &str) -> Option<ExportInfo> {
        self.exports.get(name).map(|e| e.clone())
    }

    /// List all exports
    pub fn list_exports(&self) -> Vec<ExportInfo> {
        self.exports.iter().map(|e| e.value().clone()).collect()
    }

    /// Run the NBD server
    pub async fn run(&self) -> BlockResult<()> {
        let listener = TcpListener::bind(self.config.bind_addr).await?;
        info!("NBD server listening on {}", self.config.bind_addr);

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    debug!("Accepted NBD connection from {}", addr);
                    self.connections.fetch_add(1, Ordering::Relaxed);

                    // Handle connection in background
                    let _server = self.clone_for_connection();
                    tokio::spawn(async move {
                        // TODO: Handle NBD protocol handshake and commands
                        let _ = stream;
                        debug!("NBD connection handler for {} started", addr);
                    });
                }
                Err(e) => {
                    warn!("Failed to accept NBD connection: {}", e);
                }
            }
        }
    }

    /// Clone server state for a connection handler
    fn clone_for_connection(&self) -> NbdServerHandle {
        NbdServerHandle {
            config: self.config.clone(),
            store: self.store.clone(),
            pools: self.pools.clone(),
            snapshot_manager: self.snapshot_manager.clone(),
            exports: self.exports.clone(),
        }
    }
}

/// Handle to server resources for connection handlers
#[derive(Clone)]
struct NbdServerHandle {
    config: BlockConfig,
    store: Arc<Store>,
    pools: DashMap<String, Arc<ThinPool>>,
    snapshot_manager: Arc<SnapshotManager>,
    exports: DashMap<String, ExportInfo>,
}

/// Pool information
#[derive(Debug, Clone)]
pub struct PoolInfo {
    /// Pool name
    pub name: String,
    /// Chunk size
    pub chunk_size: u64,
    /// Allocated bytes
    pub allocated_bytes: u64,
    /// Max size (0 = unlimited)
    pub max_size: u64,
    /// Number of volumes
    pub volume_count: usize,
}

impl PoolInfo {
    /// Get utilization percentage
    pub fn utilization(&self) -> Option<f64> {
        if self.max_size == 0 {
            None // Unlimited
        } else {
            Some((self.allocated_bytes as f64 / self.max_size as f64) * 100.0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use warp_store::StoreConfig;

    #[tokio::test]
    async fn test_nbd_server_creation() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store_config = StoreConfig {
            root_path: temp_dir.path().to_path_buf(),
            ..Default::default()
        };
        let store = Arc::new(Store::new(store_config).await.unwrap());
        let config = BlockConfig::default();
        let server = NbdServer::new(store, config);

        assert_eq!(server.connection_count(), 0);
    }

    #[tokio::test]
    async fn test_pool_creation() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store_config = StoreConfig {
            root_path: temp_dir.path().to_path_buf(),
            ..Default::default()
        };
        let store = Arc::new(Store::new(store_config).await.unwrap());
        let config = BlockConfig::default();
        let server = NbdServer::new(store, config);

        let pool_config = ThinPoolConfig::new("test-pool", "test-bucket");
        server.create_pool(pool_config).unwrap();

        assert!(server.get_pool("test-pool").is_some());
        assert!(server.get_pool("nonexistent").is_none());
    }

    #[tokio::test]
    async fn test_volume_creation() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store_config = StoreConfig {
            root_path: temp_dir.path().to_path_buf(),
            ..Default::default()
        };
        let store = Arc::new(Store::new(store_config).await.unwrap());
        let config = BlockConfig::default();
        let server = NbdServer::new(store, config);

        let pool_config = ThinPoolConfig::new("test-pool", "test-bucket");
        server.create_pool(pool_config).unwrap();

        let volume_config = ThinVolumeConfig::new("test-vol", "test-pool", 1024 * 1024 * 1024);
        let volume_id = server.create_volume(volume_config).unwrap();

        let volume_info = server.get_volume("test-pool", &volume_id).unwrap();
        assert_eq!(volume_info.name, "test-vol");
        assert_eq!(volume_info.size, 1024 * 1024 * 1024);
    }

    #[tokio::test]
    async fn test_export_listing() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store_config = StoreConfig {
            root_path: temp_dir.path().to_path_buf(),
            ..Default::default()
        };
        let store = Arc::new(Store::new(store_config).await.unwrap());
        let config = BlockConfig::default();
        let server = NbdServer::new(store, config);

        let pool_config = ThinPoolConfig::new("test-pool", "test-bucket");
        server.create_pool(pool_config).unwrap();

        let volume_config = ThinVolumeConfig::new("test-vol", "test-pool", 1024 * 1024 * 1024);
        server.create_volume(volume_config).unwrap();

        let exports = server.list_exports();
        assert_eq!(exports.len(), 1);
        assert_eq!(exports[0].name, "test-vol");
    }
}
