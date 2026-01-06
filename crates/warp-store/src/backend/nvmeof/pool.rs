//! NVMe-oF Connection Pool
//!
//! Manages connections to multiple NVMe-oF targets.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use tokio::sync::Semaphore;
use tracing::{debug, info, trace, warn};

use super::config::{ConnectionPoolConfig, NvmeOfTargetConfig, TransportPreference};
use super::error::{NvmeOfBackendError, NvmeOfBackendResult};
use super::transport::TcpConnection;

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Connecting
    Connecting,
    /// Connected and ready
    Ready,
    /// Reconnecting after disconnect
    Reconnecting,
    /// Disconnected
    Disconnected,
    /// Failed (won't reconnect)
    Failed,
}

/// A pooled connection to an NVMe-oF target
pub struct PooledConnection {
    /// Connection ID
    pub id: u64,

    /// Target NQN
    pub target_nqn: String,

    /// Transport connection (actual network connection)
    pub transport: Arc<TcpConnection>,

    /// Current state
    state: RwLock<ConnectionState>,

    /// Last activity time
    last_activity: RwLock<Instant>,

    /// Commands in flight
    in_flight: AtomicU64,
}

impl PooledConnection {
    /// Create a new connection
    pub fn new(id: u64, target_nqn: String, transport: Arc<TcpConnection>) -> Self {
        Self {
            id,
            target_nqn,
            transport,
            state: RwLock::new(ConnectionState::Connecting),
            last_activity: RwLock::new(Instant::now()),
            in_flight: AtomicU64::new(0),
        }
    }

    /// Get connection state
    pub fn state(&self) -> ConnectionState {
        *self.state.read()
    }

    /// Set connection state
    pub fn set_state(&self, state: ConnectionState) {
        *self.state.write() = state;
    }

    /// Check if connection is usable
    pub fn is_usable(&self) -> bool {
        self.state() == ConnectionState::Ready
    }

    /// Touch connection (update last activity)
    pub fn touch(&self) {
        *self.last_activity.write() = Instant::now();
    }

    /// Get idle duration
    pub fn idle_duration(&self) -> Duration {
        self.last_activity.read().elapsed()
    }

    /// Increment in-flight count
    pub fn begin_command(&self) -> u64 {
        self.in_flight.fetch_add(1, Ordering::Relaxed)
    }

    /// Decrement in-flight count
    pub fn end_command(&self) {
        self.in_flight.fetch_sub(1, Ordering::Relaxed);
    }

    /// Get in-flight count
    pub fn in_flight_count(&self) -> u64 {
        self.in_flight.load(Ordering::Relaxed)
    }
}

/// Target connection pool
struct TargetPool {
    /// Target configuration
    config: NvmeOfTargetConfig,

    /// Connections
    connections: RwLock<Vec<Arc<PooledConnection>>>,

    /// Connection semaphore
    semaphore: Arc<Semaphore>,

    /// Connection counter
    connection_counter: AtomicU64,

    /// Pool state
    state: RwLock<TargetPoolState>,
}

/// Target pool state
#[derive(Debug, Clone, Copy)]
struct TargetPoolState {
    /// Total connections created
    total_created: u64,

    /// Total connections failed
    total_failed: u64,

    /// Currently active connections
    active: u32,
}

impl TargetPool {
    fn new(config: NvmeOfTargetConfig, pool_config: &ConnectionPoolConfig) -> Self {
        Self {
            config,
            connections: RwLock::new(Vec::new()),
            semaphore: Arc::new(Semaphore::new(pool_config.max_connections as usize)),
            connection_counter: AtomicU64::new(0),
            state: RwLock::new(TargetPoolState {
                total_created: 0,
                total_failed: 0,
                active: 0,
            }),
        }
    }

    fn get_connection(&self) -> Option<Arc<PooledConnection>> {
        let conns = self.connections.read();

        // Find a usable connection with lowest in-flight count
        conns
            .iter()
            .filter(|c| c.is_usable())
            .min_by_key(|c| c.in_flight_count())
            .cloned()
    }

    fn add_connection(&self, conn: Arc<PooledConnection>) {
        let mut conns = self.connections.write();
        conns.push(conn);
        self.state.write().active += 1;
    }

    fn remove_connection(&self, id: u64) {
        let mut conns = self.connections.write();
        if let Some(pos) = conns.iter().position(|c| c.id == id) {
            conns.remove(pos);
            self.state.write().active = self.state.read().active.saturating_sub(1);
        }
    }

    fn connection_count(&self) -> usize {
        self.connections.read().len()
    }
}

/// NVMe-oF connection pool
pub struct NvmeOfConnectionPool {
    /// Pool configuration
    config: ConnectionPoolConfig,

    /// Target pools by NQN
    targets: RwLock<HashMap<String, Arc<TargetPool>>>,

    /// Transport preference
    transport_preference: Vec<TransportPreference>,

    /// Statistics
    stats: RwLock<PoolStats>,
}

impl NvmeOfConnectionPool {
    /// Create a new connection pool
    pub fn new(
        config: ConnectionPoolConfig,
        transport_preference: Vec<TransportPreference>,
    ) -> Self {
        Self {
            config,
            targets: RwLock::new(HashMap::new()),
            transport_preference,
            stats: RwLock::new(PoolStats::default()),
        }
    }

    /// Add a target to the pool
    pub fn add_target(&self, target_config: NvmeOfTargetConfig) -> NvmeOfBackendResult<()> {
        let nqn = target_config.nqn.clone();
        let pool = Arc::new(TargetPool::new(target_config, &self.config));

        self.targets.write().insert(nqn.clone(), pool);
        info!("Added target to pool: {}", nqn);

        Ok(())
    }

    /// Remove a target from the pool
    pub fn remove_target(&self, nqn: &str) -> NvmeOfBackendResult<()> {
        self.targets.write().remove(nqn);
        info!("Removed target from pool: {}", nqn);
        Ok(())
    }

    /// Get a connection to a target
    pub async fn get_connection(&self, nqn: &str) -> NvmeOfBackendResult<Arc<PooledConnection>> {
        // Get pool and clone it before releasing lock
        let pool = {
            let targets = self.targets.read();
            targets
                .get(nqn)
                .cloned()
                .ok_or_else(|| NvmeOfBackendError::TargetNotFound(nqn.to_string()))?
        };

        // Try to get existing connection
        if let Some(conn) = pool.get_connection() {
            trace!("Reusing connection {} for target {}", conn.id, nqn);
            return Ok(conn);
        }

        // Need to create new connection
        // Acquire semaphore permit
        let _permit = tokio::time::timeout(
            self.config.acquire_timeout,
            pool.semaphore.clone().acquire_owned(),
        )
        .await
        .map_err(|_| NvmeOfBackendError::Timeout("Connection acquire timeout".to_string()))?
        .map_err(|_| NvmeOfBackendError::PoolExhausted)?;

        // Get target address
        let target_addr = pool
            .config
            .addresses
            .first()
            .ok_or_else(|| NvmeOfBackendError::Config("No target addresses configured".to_string()))?;

        // Create TCP connection
        let transport_conn = TcpConnection::connect(*target_addr).await?;

        // Initialize connection (ICReq/ICResp handshake)
        transport_conn.initialize().await?;

        // Create pooled connection
        let conn_id = pool.connection_counter.fetch_add(1, Ordering::Relaxed);
        let conn = Arc::new(PooledConnection::new(
            conn_id,
            nqn.to_string(),
            Arc::new(transport_conn),
        ));

        conn.set_state(ConnectionState::Ready);

        pool.add_connection(conn.clone());
        self.stats.write().connections_created += 1;

        info!("Created new connection {} to target {}", conn_id, nqn);
        Ok(conn)
    }

    /// Return a connection to the pool
    pub fn return_connection(&self, conn: Arc<PooledConnection>) {
        conn.touch();
        trace!("Returned connection {} to pool", conn.id);
    }

    /// Close a connection
    pub fn close_connection(&self, conn: Arc<PooledConnection>) {
        let targets = self.targets.read();
        if let Some(pool) = targets.get(&conn.target_nqn) {
            pool.remove_connection(conn.id);
            self.stats.write().connections_closed += 1;
            debug!("Closed connection {}", conn.id);
        }
    }

    /// Get pool statistics
    pub fn stats(&self) -> PoolStats {
        self.stats.read().clone()
    }

    /// Get connection count for a target
    pub fn connection_count(&self, nqn: &str) -> usize {
        self.targets
            .read()
            .get(nqn)
            .map(|p| p.connection_count())
            .unwrap_or(0)
    }

    /// Get total connection count
    pub fn total_connections(&self) -> usize {
        self.targets
            .read()
            .values()
            .map(|p| p.connection_count())
            .sum()
    }
}

/// Pool statistics
#[derive(Debug, Clone, Default)]
pub struct PoolStats {
    /// Total connections created
    pub connections_created: u64,

    /// Total connections closed
    pub connections_closed: u64,

    /// Total connection failures
    pub connection_failures: u64,

    /// Total commands executed
    pub commands_executed: u64,

    /// Total command failures
    pub command_failures: u64,

    /// Total bytes read
    pub bytes_read: u64,

    /// Total bytes written
    pub bytes_written: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn test_pooled_connection() {
        let conn = PooledConnection::new(1, "nqn.test".to_string());

        assert_eq!(conn.state(), ConnectionState::Connecting);
        assert_eq!(conn.in_flight_count(), 0);

        conn.set_state(ConnectionState::Ready);
        assert!(conn.is_usable());

        conn.begin_command();
        assert_eq!(conn.in_flight_count(), 1);

        conn.end_command();
        assert_eq!(conn.in_flight_count(), 0);
    }

    #[tokio::test]
    async fn test_connection_pool() {
        let config = ConnectionPoolConfig::default();
        let pool = NvmeOfConnectionPool::new(config, vec![TransportPreference::Tcp]);

        let target_config = NvmeOfTargetConfig {
            nqn: "nqn.2024-01.io.warp:test".to_string(),
            addresses: vec!["127.0.0.1:4420".parse().unwrap()],
            ..Default::default()
        };

        pool.add_target(target_config).unwrap();

        // Get a connection
        let conn = pool
            .get_connection("nqn.2024-01.io.warp:test")
            .await
            .unwrap();
        assert!(conn.is_usable());

        // Return it
        pool.return_connection(conn.clone());

        // Get again (should reuse)
        let conn2 = pool
            .get_connection("nqn.2024-01.io.warp:test")
            .await
            .unwrap();
        assert_eq!(conn.id, conn2.id);
    }
}
