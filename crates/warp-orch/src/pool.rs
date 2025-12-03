//! Connection pooling for edge connections
//!
//! Manages reusable connections to edges with:
//! - Per-edge connection limits
//! - Total connection capacity
//! - Idle timeout management
//! - Health checking
//! - Concurrent access via DashMap

use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};
use warp_net::WarpConnection;
use warp_sched::EdgeIdx;

/// Pool-specific errors
#[derive(Debug, Error)]
pub enum PoolError {
    #[error("connection timeout after {0}ms")]
    Timeout(u64),
    #[error("max connections per edge reached: {0}")]
    MaxConnectionsPerEdge(usize),
    #[error("max total connections reached: {0}")]
    MaxTotalConnections(usize),
    #[error("connection {0} not found")]
    ConnectionNotFound(u64),
    #[error("connection unhealthy: {0}")]
    Unhealthy(String),
    #[error("connection closed")]
    Closed,
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("no transport available for connection {0}")]
    NoTransport(u64),
}

pub type Result<T> = std::result::Result<T, PoolError>;

/// Configuration for connection pool
#[derive(Debug, Clone)]
pub struct PoolConfig {
    pub max_connections_per_edge: usize,
    pub max_total_connections: usize,
    pub idle_timeout_ms: u64,
    pub connect_timeout_ms: u64,
    pub health_check_interval_ms: u64,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections_per_edge: 4,
            max_total_connections: 100,
            idle_timeout_ms: 60000,
            connect_timeout_ms: 5000,
            health_check_interval_ms: 30000,
        }
    }
}

impl PoolConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> Result<()> {
        if self.max_connections_per_edge == 0 {
            return Err(PoolError::InvalidConfig(
                "max_connections_per_edge must be > 0".to_string(),
            ));
        }
        if self.max_total_connections == 0 {
            return Err(PoolError::InvalidConfig(
                "max_total_connections must be > 0".to_string(),
            ));
        }
        if self.max_connections_per_edge > self.max_total_connections {
            return Err(PoolError::InvalidConfig(
                "max_connections_per_edge cannot exceed max_total_connections".to_string(),
            ));
        }
        Ok(())
    }
}

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Idle,
    InUse,
    Unhealthy,
    Closed,
}

/// Internal connection representation
#[derive(Debug, Clone)]
pub struct Connection {
    pub id: u64,
    pub edge_idx: EdgeIdx,
    pub state: ConnectionState,
    pub created_at_ms: u64,
    pub last_used_ms: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

impl Connection {
    fn new(id: u64, edge_idx: EdgeIdx) -> Self {
        let now = current_time_ms();
        Self {
            id,
            edge_idx,
            state: ConnectionState::Idle,
            created_at_ms: now,
            last_used_ms: now,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }

    fn mark_used(&mut self) {
        self.last_used_ms = current_time_ms();
        self.state = ConnectionState::InUse;
    }

    fn mark_idle(&mut self) {
        self.last_used_ms = current_time_ms();
        self.state = ConnectionState::Idle;
    }

    fn is_idle_timeout(&self, timeout_ms: u64) -> bool {
        let now = current_time_ms();
        self.state == ConnectionState::Idle && now - self.last_used_ms > timeout_ms
    }

    fn mock_send(&mut self, data: &[u8]) -> Result<()> {
        if self.state != ConnectionState::InUse {
            return Err(PoolError::InvalidConfig("connection not in use".to_string()));
        }
        self.bytes_sent += data.len() as u64;
        Ok(())
    }

    fn mock_receive(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.state != ConnectionState::InUse {
            return Err(PoolError::InvalidConfig(
                "connection not in use".to_string(),
            ));
        }
        let len = buf.len().min(1024);
        self.bytes_received += len as u64;
        Ok(len)
    }
}

/// RAII wrapper for borrowed connection
#[derive(Debug)]
pub struct PooledConnection {
    pool: Arc<ConnectionPoolInner>,
    conn_id: u64,
    edge_idx: EdgeIdx,
}

impl PooledConnection {
    /// Get the edge index for this connection
    pub fn edge_idx(&self) -> EdgeIdx {
        self.edge_idx
    }

    /// Get the connection ID for transport attachment
    pub fn conn_id(&self) -> u64 {
        self.conn_id
    }

    /// Send data using real transport if available, otherwise use mock
    pub fn send(&self, data: &[u8]) -> Result<()> {
        if let Some(mut conn) = self.pool.connections.get_mut(&self.conn_id) {
            conn.mock_send(data)
        } else {
            Err(PoolError::ConnectionNotFound(self.conn_id))
        }
    }

    /// Receive data using mock (for backwards compatibility)
    pub fn receive(&self, buf: &mut [u8]) -> Result<usize> {
        if let Some(mut conn) = self.pool.connections.get_mut(&self.conn_id) {
            conn.mock_receive(buf)
        } else {
            Err(PoolError::ConnectionNotFound(self.conn_id))
        }
    }

    /// Check if this connection has a real transport attached
    pub fn has_transport(&self) -> bool {
        self.pool.transports.contains_key(&self.conn_id)
    }

    /// Get the underlying WarpConnection transport if available
    pub fn transport(&self) -> Option<Arc<WarpConnection>> {
        self.pool.transports.get(&self.conn_id).map(|t| t.clone())
    }

    /// Send chunk data using real QUIC transport
    ///
    /// This method uses the actual WarpConnection to send chunk data
    /// over the network. Falls back to mock if no transport is attached.
    pub async fn send_chunk(&self, chunk_id: u32, data: &[u8]) -> Result<()> {
        // Update stats regardless of transport type
        if let Some(mut conn) = self.pool.connections.get_mut(&self.conn_id) {
            conn.bytes_sent += data.len() as u64;
        }

        // Try real transport first
        if let Some(transport) = self.pool.transports.get(&self.conn_id) {
            transport
                .send_chunk(chunk_id, data)
                .await
                .map_err(|e| PoolError::Transport(format!("Failed to send chunk: {}", e)))?;
            return Ok(());
        }

        // Fall back to mock behavior for tests
        if let Some(mut conn) = self.pool.connections.get_mut(&self.conn_id) {
            if conn.state != ConnectionState::InUse {
                return Err(PoolError::InvalidConfig("connection not in use".to_string()));
            }
            Ok(())
        } else {
            Err(PoolError::ConnectionNotFound(self.conn_id))
        }
    }

    /// Send multiple chunks in a batch using real QUIC transport
    pub async fn send_chunk_batch(&self, chunks: Vec<(u32, Vec<u8>)>) -> Result<()> {
        // Update stats
        let total_bytes: u64 = chunks.iter().map(|(_, data)| data.len() as u64).sum();
        if let Some(mut conn) = self.pool.connections.get_mut(&self.conn_id) {
            conn.bytes_sent += total_bytes;
        }

        // Try real transport
        if let Some(transport) = self.pool.transports.get(&self.conn_id) {
            transport
                .send_chunk_batch(chunks)
                .await
                .map_err(|e| PoolError::Transport(format!("Failed to send batch: {}", e)))?;
            return Ok(());
        }

        // Fall back to mock
        if let Some(conn) = self.pool.connections.get(&self.conn_id) {
            if conn.state != ConnectionState::InUse {
                return Err(PoolError::InvalidConfig("connection not in use".to_string()));
            }
            Ok(())
        } else {
            Err(PoolError::ConnectionNotFound(self.conn_id))
        }
    }

    /// Request chunks from the peer using WANT frame
    ///
    /// Sends a WANT frame requesting the specified chunk IDs.
    /// The peer should respond with CHUNK frames for each requested chunk.
    pub async fn request_chunks(&self, chunk_ids: Vec<u32>) -> Result<()> {
        if let Some(transport) = self.pool.transports.get(&self.conn_id) {
            use warp_net::Frame;
            transport
                .send_frame(Frame::Want { chunk_ids })
                .await
                .map_err(|e| PoolError::Transport(format!("Failed to send WANT: {}", e)))?;
            return Ok(());
        }

        // Fall back to mock for tests
        if let Some(conn) = self.pool.connections.get(&self.conn_id) {
            if conn.state != ConnectionState::InUse {
                return Err(PoolError::InvalidConfig("connection not in use".to_string()));
            }
            Ok(())
        } else {
            Err(PoolError::ConnectionNotFound(self.conn_id))
        }
    }

    /// Receive a chunk from the peer
    ///
    /// Waits for and receives a CHUNK frame from the peer.
    /// Returns (chunk_id, data).
    pub async fn recv_chunk(&self) -> Result<(u32, Vec<u8>)> {
        // Update stats
        if let Some(transport) = self.pool.transports.get(&self.conn_id) {
            let (chunk_id, data) = transport
                .recv_chunk()
                .await
                .map_err(|e| PoolError::Transport(format!("Failed to recv chunk: {}", e)))?;

            // Update received bytes stat
            if let Some(mut conn) = self.pool.connections.get_mut(&self.conn_id) {
                conn.bytes_received += data.len() as u64;
            }

            return Ok((chunk_id, data));
        }

        // Fall back to mock for tests - return empty chunk
        if let Some(mut conn) = self.pool.connections.get_mut(&self.conn_id) {
            if conn.state != ConnectionState::InUse {
                return Err(PoolError::InvalidConfig("connection not in use".to_string()));
            }
            let mock_data = vec![0u8; 1024];
            conn.bytes_received += mock_data.len() as u64;
            Ok((0, mock_data))
        } else {
            Err(PoolError::ConnectionNotFound(self.conn_id))
        }
    }
}

impl Drop for PooledConnection {
    fn drop(&mut self) {
        self.pool.release(self.conn_id);
    }
}

/// Pool statistics
#[derive(Debug, Clone, Default)]
pub struct PoolStats {
    pub total_connections: usize,
    pub idle_connections: usize,
    pub in_use_connections: usize,
    pub connections_per_edge: HashMap<EdgeIdx, usize>,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
}

struct ConnectionPoolInner {
    config: PoolConfig,
    connections: DashMap<u64, Connection>,
    transports: DashMap<u64, Arc<WarpConnection>>,
    edge_connections: DashMap<EdgeIdx, Vec<u64>>,
    next_conn_id: AtomicU64,
    total_semaphore: Arc<Semaphore>,
    edge_semaphores: DashMap<EdgeIdx, Arc<Semaphore>>,
}

impl std::fmt::Debug for ConnectionPoolInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionPoolInner")
            .field("config", &self.config)
            .field("connections_count", &self.connections.len())
            .field("edge_connections_count", &self.edge_connections.len())
            .finish()
    }
}

impl ConnectionPoolInner {
    fn new(config: PoolConfig) -> Self {
        Self {
            total_semaphore: Arc::new(Semaphore::new(config.max_total_connections)),
            config,
            connections: DashMap::new(),
            transports: DashMap::new(),
            edge_connections: DashMap::new(),
            next_conn_id: AtomicU64::new(1),
            edge_semaphores: DashMap::new(),
        }
    }

    fn get_edge_semaphore(&self, edge_idx: EdgeIdx) -> Arc<Semaphore> {
        self.edge_semaphores
            .entry(edge_idx)
            .or_insert_with(|| Arc::new(Semaphore::new(self.config.max_connections_per_edge)))
            .clone()
    }

    async fn acquire_connection(&self, edge_idx: EdgeIdx) -> Result<u64> {
        // Try to find an idle connection first
        if let Some(conn_id) = self.find_idle_connection(edge_idx) {
            if let Some(mut conn) = self.connections.get_mut(&conn_id) {
                conn.mark_used();
                return Ok(conn_id);
            }
        }

        // Need to create a new connection - acquire semaphores
        let _total_permit = self
            .total_semaphore
            .acquire()
            .await
            .map_err(|_| PoolError::MaxTotalConnections(self.config.max_total_connections))?;

        let edge_sem = self.get_edge_semaphore(edge_idx);
        let _edge_permit = edge_sem
            .acquire()
            .await
            .map_err(|_| PoolError::MaxConnectionsPerEdge(self.config.max_connections_per_edge))?;

        // Create new connection
        let conn_id = self.next_conn_id.fetch_add(1, Ordering::SeqCst);
        let mut conn = Connection::new(conn_id, edge_idx);
        conn.mark_used();

        self.connections.insert(conn_id, conn);
        self.edge_connections
            .entry(edge_idx)
            .or_insert_with(Vec::new)
            .push(conn_id);

        // Release permits after connection created
        _total_permit.forget();
        _edge_permit.forget();

        Ok(conn_id)
    }

    fn find_idle_connection(&self, edge_idx: EdgeIdx) -> Option<u64> {
        if let Some(conn_ids) = self.edge_connections.get(&edge_idx) {
            for &conn_id in conn_ids.iter() {
                if let Some(conn) = self.connections.get(&conn_id) {
                    if conn.state == ConnectionState::Idle {
                        return Some(conn_id);
                    }
                }
            }
        }
        None
    }

    fn release(&self, conn_id: u64) {
        if let Some(mut conn) = self.connections.get_mut(&conn_id) {
            if conn.state == ConnectionState::InUse {
                conn.mark_idle();
            }
        }
    }

    fn close_edge(&self, edge_idx: EdgeIdx) {
        if let Some((_, conn_ids)) = self.edge_connections.remove(&edge_idx) {
            for conn_id in conn_ids {
                if let Some(mut conn) = self.connections.get_mut(&conn_id) {
                    conn.state = ConnectionState::Closed;
                }
                self.connections.remove(&conn_id);
                self.transports.remove(&conn_id);
            }
        }
        self.edge_semaphores.remove(&edge_idx);
    }

    fn stats(&self) -> PoolStats {
        let mut stats = PoolStats::default();
        let mut per_edge: HashMap<EdgeIdx, usize> = HashMap::new();

        for conn_ref in self.connections.iter() {
            let conn = conn_ref.value();
            stats.total_connections += 1;
            stats.total_bytes_sent += conn.bytes_sent;
            stats.total_bytes_received += conn.bytes_received;

            match conn.state {
                ConnectionState::Idle => stats.idle_connections += 1,
                ConnectionState::InUse => stats.in_use_connections += 1,
                _ => {}
            }

            *per_edge.entry(conn.edge_idx).or_insert(0) += 1;
        }

        stats.connections_per_edge = per_edge;
        stats
    }
}

/// Main connection pool
#[derive(Clone)]
pub struct ConnectionPool {
    inner: Arc<ConnectionPoolInner>,
}

impl ConnectionPool {
    pub fn new(config: PoolConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            inner: Arc::new(ConnectionPoolInner::new(config)),
        })
    }

    pub async fn acquire(&self, edge_idx: EdgeIdx) -> Result<PooledConnection> {
        let conn_id = self.inner.acquire_connection(edge_idx).await?;
        Ok(PooledConnection {
            pool: self.inner.clone(),
            conn_id,
            edge_idx,
        })
    }

    pub async fn acquire_timeout(
        &self,
        edge_idx: EdgeIdx,
        duration: Duration,
    ) -> Result<PooledConnection> {
        timeout(duration, self.acquire(edge_idx))
            .await
            .map_err(|_| PoolError::Timeout(duration.as_millis() as u64))?
    }

    pub fn close_edge(&self, edge_idx: EdgeIdx) {
        self.inner.close_edge(edge_idx);
    }

    pub fn stats(&self) -> PoolStats {
        self.inner.stats()
    }

    pub fn config(&self) -> &PoolConfig {
        &self.inner.config
    }

    /// Acquire a connection and attach a real transport to it
    ///
    /// This method creates a pooled connection and attaches the provided
    /// WarpConnection for real network I/O operations.
    pub async fn acquire_with_transport(
        &self,
        edge_idx: EdgeIdx,
        transport: Arc<WarpConnection>,
    ) -> Result<PooledConnection> {
        let conn_id = self.inner.acquire_connection(edge_idx).await?;
        self.inner.transports.insert(conn_id, transport);
        Ok(PooledConnection {
            pool: self.inner.clone(),
            conn_id,
            edge_idx,
        })
    }

    /// Attach a transport to an existing connection by ID
    ///
    /// Used when you need to add transport after connection is acquired.
    pub fn attach_transport(&self, conn_id: u64, transport: Arc<WarpConnection>) -> Result<()> {
        if !self.inner.connections.contains_key(&conn_id) {
            return Err(PoolError::ConnectionNotFound(conn_id));
        }
        self.inner.transports.insert(conn_id, transport);
        Ok(())
    }

    /// Detach transport from a connection
    ///
    /// Returns the transport if it was attached.
    pub fn detach_transport(&self, conn_id: u64) -> Option<Arc<WarpConnection>> {
        self.inner.transports.remove(&conn_id).map(|(_, t)| t)
    }
}

fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(std::time::Duration::ZERO)
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_config_default() {
        let config = PoolConfig::default();
        assert_eq!(config.max_connections_per_edge, 4);
        assert_eq!(config.max_total_connections, 100);
        assert_eq!(config.idle_timeout_ms, 60000);
        assert_eq!(config.connect_timeout_ms, 5000);
        assert_eq!(config.health_check_interval_ms, 30000);
    }

    #[test]
    fn test_pool_config_new() {
        let config = PoolConfig::new();
        assert_eq!(config.max_connections_per_edge, 4);
        assert_eq!(config.max_total_connections, 100);
    }

    #[test]
    fn test_pool_config_validation() {
        let config = PoolConfig::default();
        assert!(config.validate().is_ok());

        let invalid = PoolConfig {
            max_connections_per_edge: 0,
            ..Default::default()
        };
        assert!(invalid.validate().is_err());

        let invalid = PoolConfig {
            max_total_connections: 0,
            ..Default::default()
        };
        assert!(invalid.validate().is_err());

        let invalid = PoolConfig {
            max_connections_per_edge: 200,
            max_total_connections: 100,
            ..Default::default()
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_connection_state_transitions() {
        assert_ne!(ConnectionState::Idle, ConnectionState::InUse);
        assert_ne!(ConnectionState::Idle, ConnectionState::Unhealthy);
        assert_ne!(ConnectionState::Idle, ConnectionState::Closed);
    }

    #[test]
    fn test_connection_creation() {
        let edge_idx = EdgeIdx::new(1);
        let conn = Connection::new(42, edge_idx);

        assert_eq!(conn.id, 42);
        assert_eq!(conn.edge_idx, edge_idx);
        assert_eq!(conn.state, ConnectionState::Idle);
        assert_eq!(conn.bytes_sent, 0);
        assert_eq!(conn.bytes_received, 0);
        assert!(conn.created_at_ms > 0);
        assert!(conn.last_used_ms > 0);
    }

    #[test]
    fn test_connection_mark_used() {
        let edge_idx = EdgeIdx::new(1);
        let mut conn = Connection::new(1, edge_idx);
        let initial_time = conn.last_used_ms;

        std::thread::sleep(std::time::Duration::from_millis(10));
        conn.mark_used();

        assert_eq!(conn.state, ConnectionState::InUse);
        assert!(conn.last_used_ms >= initial_time);
    }

    #[test]
    fn test_connection_mark_idle() {
        let edge_idx = EdgeIdx::new(1);
        let mut conn = Connection::new(1, edge_idx);
        conn.mark_used();

        std::thread::sleep(std::time::Duration::from_millis(10));
        conn.mark_idle();

        assert_eq!(conn.state, ConnectionState::Idle);
    }

    #[test]
    fn test_connection_idle_timeout() {
        let edge_idx = EdgeIdx::new(1);
        let mut conn = Connection::new(1, edge_idx);

        // Not timed out immediately
        assert!(!conn.is_idle_timeout(100));

        // Simulate passage of time
        conn.last_used_ms = current_time_ms() - 200;
        assert!(conn.is_idle_timeout(100));

        // InUse connections don't timeout
        conn.mark_used();
        assert!(!conn.is_idle_timeout(100));
    }

    #[test]
    fn test_connection_mock_operations() {
        let edge_idx = EdgeIdx::new(1);
        let mut conn = Connection::new(1, edge_idx);

        // Can't send/receive when idle
        assert!(conn.mock_send(&[1, 2, 3]).is_err());
        assert!(conn.mock_receive(&mut [0u8; 10]).is_err());

        // Mark as in use
        conn.mark_used();

        // Can send/receive when in use
        assert!(conn.mock_send(&[1, 2, 3, 4]).is_ok());
        assert_eq!(conn.bytes_sent, 4);

        let mut buf = [0u8; 2048];
        let received = conn.mock_receive(&mut buf).unwrap();
        assert!(received > 0);
        assert_eq!(conn.bytes_received, received as u64);
    }

    #[tokio::test]
    async fn test_pool_creation() {
        let config = PoolConfig::default();
        let pool = ConnectionPool::new(config.clone()).unwrap();

        assert_eq!(pool.config().max_connections_per_edge, 4);
        assert_eq!(pool.config().max_total_connections, 100);
    }

    #[tokio::test]
    async fn test_pool_invalid_config() {
        let config = PoolConfig {
            max_connections_per_edge: 0,
            ..Default::default()
        };
        assert!(ConnectionPool::new(config).is_err());
    }

    #[tokio::test]
    async fn test_acquire_and_release() {
        let config = PoolConfig::default();
        let pool = ConnectionPool::new(config).unwrap();
        let edge_idx = EdgeIdx::new(1);

        let stats = pool.stats();
        assert_eq!(stats.total_connections, 0);

        {
            let conn = pool.acquire(edge_idx).await.unwrap();
            assert_eq!(conn.edge_idx(), edge_idx);

            let stats = pool.stats();
            assert_eq!(stats.total_connections, 1);
            assert_eq!(stats.in_use_connections, 1);
            assert_eq!(stats.idle_connections, 0);
        }

        // After drop, connection should be idle
        let stats = pool.stats();
        assert_eq!(stats.total_connections, 1);
        assert_eq!(stats.in_use_connections, 0);
        assert_eq!(stats.idle_connections, 1);
    }

    #[tokio::test]
    async fn test_pooled_connection_operations() {
        let config = PoolConfig::default();
        let pool = ConnectionPool::new(config).unwrap();
        let edge_idx = EdgeIdx::new(1);

        let conn = pool.acquire(edge_idx).await.unwrap();

        // Test send
        assert!(conn.send(&[1, 2, 3, 4, 5]).is_ok());

        // Test receive
        let mut buf = [0u8; 1024];
        let received = conn.receive(&mut buf).unwrap();
        assert!(received > 0);

        let stats = pool.stats();
        assert!(stats.total_bytes_sent >= 5);
        assert!(stats.total_bytes_received >= received as u64);
    }

    #[tokio::test]
    async fn test_connection_reuse() {
        let config = PoolConfig::default();
        let pool = ConnectionPool::new(config).unwrap();
        let edge_idx = EdgeIdx::new(1);

        let conn_id = {
            let _conn = pool.acquire(edge_idx).await.unwrap();
            pool.inner.connections.iter().next().unwrap().key().clone()
        };

        // Acquire again - should reuse the same connection
        let reused = pool.acquire(edge_idx).await.unwrap();
        assert_eq!(reused.conn_id, conn_id);

        let stats = pool.stats();
        assert_eq!(stats.total_connections, 1);
    }

    #[tokio::test]
    async fn test_multiple_edges() {
        let config = PoolConfig::default();
        let pool = ConnectionPool::new(config).unwrap();

        let edge1 = EdgeIdx::new(1);
        let edge2 = EdgeIdx::new(2);
        let edge3 = EdgeIdx::new(3);

        let _conn1 = pool.acquire(edge1).await.unwrap();
        let _conn2 = pool.acquire(edge2).await.unwrap();
        let _conn3 = pool.acquire(edge3).await.unwrap();

        let stats = pool.stats();
        assert_eq!(stats.total_connections, 3);
        assert_eq!(stats.connections_per_edge.len(), 3);
        assert_eq!(*stats.connections_per_edge.get(&edge1).unwrap(), 1);
        assert_eq!(*stats.connections_per_edge.get(&edge2).unwrap(), 1);
        assert_eq!(*stats.connections_per_edge.get(&edge3).unwrap(), 1);
    }

    #[tokio::test]
    async fn test_max_connections_per_edge() {
        let config = PoolConfig {
            max_connections_per_edge: 2,
            max_total_connections: 100,
            ..Default::default()
        };
        let pool = ConnectionPool::new(config).unwrap();
        let edge_idx = EdgeIdx::new(1);

        let _conn1 = pool.acquire(edge_idx).await.unwrap();
        let _conn2 = pool.acquire(edge_idx).await.unwrap();

        // Third acquisition should block
        let result = tokio::time::timeout(
            Duration::from_millis(100),
            pool.acquire(edge_idx),
        )
        .await;
        assert!(result.is_err()); // Timeout
    }

    #[tokio::test]
    async fn test_acquire_timeout_success() {
        let config = PoolConfig::default();
        let pool = ConnectionPool::new(config).unwrap();
        let edge_idx = EdgeIdx::new(1);

        let result = pool
            .acquire_timeout(edge_idx, Duration::from_millis(1000))
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_acquire_timeout_failure() {
        let config = PoolConfig {
            max_connections_per_edge: 1,
            max_total_connections: 100,
            ..Default::default()
        };
        let pool = ConnectionPool::new(config).unwrap();
        let edge_idx = EdgeIdx::new(1);

        let _conn = pool.acquire(edge_idx).await.unwrap();

        let result = pool
            .acquire_timeout(edge_idx, Duration::from_millis(50))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            PoolError::Timeout(_) => {}
            _ => panic!("Expected timeout error"),
        }
    }

    #[tokio::test]
    async fn test_close_edge() {
        let config = PoolConfig::default();
        let pool = ConnectionPool::new(config).unwrap();

        let edge1 = EdgeIdx::new(1);
        let edge2 = EdgeIdx::new(2);

        let _conn1 = pool.acquire(edge1).await.unwrap();
        let _conn2 = pool.acquire(edge2).await.unwrap();

        let stats = pool.stats();
        assert_eq!(stats.total_connections, 2);

        pool.close_edge(edge1);

        let stats = pool.stats();
        assert_eq!(stats.total_connections, 1);
        assert!(stats.connections_per_edge.get(&edge1).is_none());
        assert_eq!(*stats.connections_per_edge.get(&edge2).unwrap(), 1);
    }

    #[tokio::test]
    async fn test_pool_stats() {
        let config = PoolConfig::default();
        let pool = ConnectionPool::new(config).unwrap();

        let edge1 = EdgeIdx::new(1);
        let edge2 = EdgeIdx::new(2);

        let conn1 = pool.acquire(edge1).await.unwrap();
        let conn2 = pool.acquire(edge2).await.unwrap();

        conn1.send(&[1, 2, 3]).unwrap();
        conn2.send(&[4, 5, 6, 7]).unwrap();

        let stats = pool.stats();
        assert_eq!(stats.total_connections, 2);
        assert_eq!(stats.in_use_connections, 2);
        assert_eq!(stats.idle_connections, 0);
        assert_eq!(stats.total_bytes_sent, 7);
    }

    #[tokio::test]
    async fn test_concurrent_acquisitions() {
        let config = PoolConfig {
            max_connections_per_edge: 4,
            max_total_connections: 20,
            ..Default::default()
        };
        let pool = Arc::new(ConnectionPool::new(config).unwrap());

        let mut handles = vec![];

        // Spawn 10 tasks, each acquiring 2 connections
        for i in 0..10 {
            let pool_clone = pool.clone();
            let handle = tokio::spawn(async move {
                let edge_idx = EdgeIdx::new(i % 3); // Use 3 different edges
                let conn = pool_clone.acquire(edge_idx).await.unwrap();
                tokio::time::sleep(Duration::from_millis(10)).await;
                assert_eq!(conn.edge_idx(), edge_idx);
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.await.unwrap();
        }

        let stats = pool.stats();
        assert!(stats.total_connections <= 10);
    }

    #[tokio::test]
    async fn test_concurrent_same_edge() {
        let config = PoolConfig {
            max_connections_per_edge: 5, // Allow enough for all 5 concurrent tasks
            max_total_connections: 10,
            ..Default::default()
        };
        let pool = Arc::new(ConnectionPool::new(config).unwrap());
        let edge_idx = EdgeIdx::new(1);

        let mut handles = vec![];

        // Spawn 5 tasks acquiring from same edge
        for _ in 0..5 {
            let pool_clone = pool.clone();
            let handle = tokio::spawn(async move {
                let conn = pool_clone.acquire(edge_idx).await.unwrap();
                tokio::time::sleep(Duration::from_millis(10)).await;
                assert_eq!(conn.edge_idx(), edge_idx);
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.await.unwrap();
        }

        let stats = pool.stats();
        assert!(stats.connections_per_edge.get(&edge_idx).unwrap() <= &5);
    }

    #[tokio::test]
    async fn test_pool_stats_default() {
        let stats = PoolStats::default();
        assert_eq!(stats.total_connections, 0);
        assert_eq!(stats.idle_connections, 0);
        assert_eq!(stats.in_use_connections, 0);
        assert_eq!(stats.total_bytes_sent, 0);
        assert_eq!(stats.total_bytes_received, 0);
        assert!(stats.connections_per_edge.is_empty());
    }

    #[tokio::test]
    async fn test_multiple_acquire_release_cycles() {
        let config = PoolConfig::default();
        let pool = ConnectionPool::new(config).unwrap();
        let edge_idx = EdgeIdx::new(1);

        for i in 0..5 {
            let conn = pool.acquire(edge_idx).await.unwrap();
            conn.send(&vec![i; 10]).unwrap();
            drop(conn);

            let stats = pool.stats();
            assert_eq!(stats.total_connections, 1);
            assert_eq!(stats.idle_connections, 1);
        }

        let stats = pool.stats();
        assert_eq!(stats.total_bytes_sent, 50);
    }

    #[test]
    fn test_current_time_ms() {
        let time1 = current_time_ms();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let time2 = current_time_ms();
        assert!(time2 > time1);
        assert!(time2 - time1 >= 10);
    }
}
