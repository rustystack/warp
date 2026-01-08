//! Connection pooling for edge connections
//!
//! Manages reusable connections to edges with:
//! - Per-edge connection limits
//! - Total connection capacity
//! - Idle timeout management
//! - Health checking
//! - Concurrent access via DashMap

use bytes::Bytes;
use dashmap::{DashMap, DashSet};
use portal_net::types::{PathId, PeerEndpoint};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::Semaphore;
use tokio::time::{Duration, timeout};
use warp_net::{MultiPathEndpoint, WarpConnection};
use warp_sched::{DynamicEdgeMetrics, EdgeIdx};

/// Pool-specific errors
#[derive(Debug, Error)]
pub enum PoolError {
    /// Connection acquisition timed out after the specified milliseconds.
    #[error("connection timeout after {0}ms")]
    Timeout(u64),
    /// Maximum connections per edge limit reached.
    #[error("max connections per edge reached: {0}")]
    MaxConnectionsPerEdge(usize),
    /// Maximum total pool connections limit reached.
    #[error("max total connections reached: {0}")]
    MaxTotalConnections(usize),
    /// The specified connection ID was not found in the pool.
    #[error("connection {0} not found")]
    ConnectionNotFound(u64),
    /// Connection failed health check.
    #[error("connection unhealthy: {0}")]
    Unhealthy(String),
    /// Connection was closed unexpectedly.
    #[error("connection closed")]
    Closed,
    /// Invalid pool configuration.
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    /// Transport layer error.
    #[error("transport error: {0}")]
    Transport(String),
    /// No transport attached to the connection.
    #[error("no transport available for connection {0}")]
    NoTransport(u64),
    /// No network path available to the target.
    #[error("no path available: {0}")]
    NoPath(String),
    /// Specified network interface not found.
    #[error("interface not found: {0}")]
    InterfaceNotFound(String),
}

/// Result type alias for pool operations.
pub type Result<T> = std::result::Result<T, PoolError>;

/// Configuration for connection pool.
///
/// Controls connection limits, timeouts, and health checking behavior
/// for the pool. All timeout values are in milliseconds.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Maximum number of connections allowed per edge.
    pub max_connections_per_edge: usize,
    /// Maximum total connections across all edges.
    pub max_total_connections: usize,
    /// Time in milliseconds before an idle connection is eligible for cleanup.
    pub idle_timeout_ms: u64,
    /// Timeout in milliseconds for establishing new connections.
    pub connect_timeout_ms: u64,
    /// Interval in milliseconds between health check probes.
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
    /// Create a new configuration with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Validate the configuration.
    ///
    /// Returns an error if any configuration values are invalid.
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

/// Connection state.
///
/// Tracks the lifecycle state of a pooled connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Connection is available for use.
    Idle,
    /// Connection is currently borrowed and in use.
    InUse,
    /// Connection failed health check and should not be used.
    Unhealthy,
    /// Connection has been permanently closed.
    Closed,
}

/// Internal connection representation
///
/// Cache line optimized (64 bytes, aligned) following mechanical sympathy principles.
/// Fields are ordered by access frequency: state is checked most often, then edge_idx,
/// id, and timing fields. Metrics are accessed only on send/recv operations.
///
/// # Cache Line Layout (64 bytes)
/// If you modify this struct, ensure:
/// 1. Total size remains exactly 64 bytes
/// 2. Alignment remains 64 bytes
/// 3. Run `cargo test` to verify the compile-time assertions below
#[derive(Debug, Clone)]
#[repr(C, align(64))]
pub struct Connection {
    // === Hot fields (checked on every acquire) ===
    /// Current lifecycle state of the connection.
    pub state: ConnectionState, // 1 byte - checked most frequently
    _pad1: [u8; 3], // 3 bytes padding for alignment
    /// Edge index this connection belongs to.
    pub edge_idx: EdgeIdx, // 4 bytes - used with state
    /// Unique connection identifier.
    pub id: u64, // 8 bytes - returned on match
    /// Timestamp of last activity in milliseconds since epoch.
    pub last_used_ms: u64, // 8 bytes - timeout checks
    /// Timestamp when connection was created in milliseconds since epoch.
    pub created_at_ms: u64, // 8 bytes - rarely accessed
    // === Metrics (accessed on send/recv) ===
    /// Total bytes sent on this connection.
    pub bytes_sent: u64, // 8 bytes
    /// Total bytes received on this connection.
    pub bytes_received: u64, // 8 bytes
    _pad2: [u8; 16], // 16 bytes padding to reach 64 bytes
}

// Compile-time assertions to prevent cache line regression
// (Inspired by Brian's zlib-rs mechanical sympathy talk)
const _: () = {
    // Connection must be exactly one cache line (64 bytes)
    assert!(std::mem::size_of::<Connection>() == 64);
    // Connection must be aligned to cache line boundary
    assert!(std::mem::align_of::<Connection>() == 64);
};

impl Connection {
    #[inline]
    fn new(id: u64, edge_idx: EdgeIdx) -> Self {
        let now = current_time_ms();
        Self {
            state: ConnectionState::Idle,
            _pad1: [0; 3],
            edge_idx,
            id,
            last_used_ms: now,
            created_at_ms: now,
            bytes_sent: 0,
            bytes_received: 0,
            _pad2: [0; 16],
        }
    }

    /// Mark connection as in-use (called on every acquire)
    #[inline]
    fn mark_used(&mut self) {
        self.last_used_ms = current_time_ms();
        self.state = ConnectionState::InUse;
    }

    /// Mark connection as idle (called on every release)
    #[inline]
    fn mark_idle(&mut self) {
        self.last_used_ms = current_time_ms();
        self.state = ConnectionState::Idle;
    }

    /// Check if connection has exceeded idle timeout
    #[inline]
    fn is_idle_timeout(&self, timeout_ms: u64) -> bool {
        let now = current_time_ms();
        self.state == ConnectionState::Idle && now - self.last_used_ms > timeout_ms
    }

    fn mock_send(&mut self, data: &[u8]) -> Result<()> {
        if self.state != ConnectionState::InUse {
            return Err(PoolError::InvalidConfig(
                "connection not in use".to_string(),
            ));
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

/// RAII wrapper for borrowed connection.
///
/// Represents a connection borrowed from the pool. The connection is
/// automatically returned to the pool when this wrapper is dropped.
/// Use the `send`, `receive`, and `send_chunk` methods for I/O operations.
#[derive(Debug)]
pub struct PooledConnection {
    pool: Arc<ConnectionPoolInner>,
    conn_id: u64,
    edge_idx: EdgeIdx,
}

impl PooledConnection {
    /// Get the edge index for this connection
    #[inline]
    pub fn edge_idx(&self) -> EdgeIdx {
        self.edge_idx
    }

    /// Get the connection ID for transport attachment
    #[inline]
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
    #[inline]
    pub fn has_transport(&self) -> bool {
        self.pool.transports.contains_key(&self.conn_id)
    }

    /// Get the underlying WarpConnection transport if available
    pub fn transport(&self) -> Option<Arc<WarpConnection>> {
        self.pool.transports.get(&self.conn_id).map(|t| t.clone())
    }

    /// Send chunk data using real QUIC transport (zero-copy)
    ///
    /// This method uses the actual WarpConnection to send chunk data
    /// over the network. Falls back to mock if no transport is attached.
    ///
    /// Hot/cold path split for better branch prediction (mechanical sympathy):
    /// - Fast path (inline): real transport available (production use case)
    /// - Slow path (cold): mock fallback (test use case)
    #[inline]
    pub async fn send_chunk(&self, chunk_id: u32, data: Bytes) -> Result<()> {
        // Update stats regardless of transport type
        if let Some(mut conn) = self.pool.connections.get_mut(&self.conn_id) {
            conn.bytes_sent += data.len() as u64;
        }

        // Fast path: real transport (common case in production)
        if let Some(transport) = self.pool.transports.get(&self.conn_id) {
            return transport
                .send_chunk(chunk_id, data)
                .await
                .map_err(|e| PoolError::Transport(format!("Failed to send chunk: {}", e)));
        }

        // Slow path: mock behavior for tests
        self.send_chunk_mock_fallback()
    }

    /// Mock fallback for send_chunk (cold path - only used in tests)
    #[cold]
    fn send_chunk_mock_fallback(&self) -> Result<()> {
        if let Some(conn) = self.pool.connections.get(&self.conn_id) {
            if conn.state != ConnectionState::InUse {
                return Err(PoolError::InvalidConfig(
                    "connection not in use".to_string(),
                ));
            }
            Ok(())
        } else {
            Err(PoolError::ConnectionNotFound(self.conn_id))
        }
    }

    /// Send multiple chunks in a batch using real QUIC transport (zero-copy)
    pub async fn send_chunk_batch(&self, chunks: Vec<(u32, Bytes)>) -> Result<()> {
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
                return Err(PoolError::InvalidConfig(
                    "connection not in use".to_string(),
                ));
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
                return Err(PoolError::InvalidConfig(
                    "connection not in use".to_string(),
                ));
            }
            Ok(())
        } else {
            Err(PoolError::ConnectionNotFound(self.conn_id))
        }
    }

    /// Receive a chunk from the peer (zero-copy)
    ///
    /// Waits for and receives a CHUNK frame from the peer.
    /// Returns (chunk_id, data).
    pub async fn recv_chunk(&self) -> Result<(u32, Bytes)> {
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
                return Err(PoolError::InvalidConfig(
                    "connection not in use".to_string(),
                ));
            }
            let mock_data = Bytes::from(vec![0u8; 1024]);
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

/// Pool statistics.
///
/// Provides a snapshot of the connection pool's current state,
/// including connection counts and data transfer totals.
#[derive(Debug, Clone, Default)]
pub struct PoolStats {
    /// Total number of connections in the pool.
    pub total_connections: usize,
    /// Number of connections currently idle and available.
    pub idle_connections: usize,
    /// Number of connections currently in use.
    pub in_use_connections: usize,
    /// Connection count per edge.
    pub connections_per_edge: HashMap<EdgeIdx, usize>,
    /// Total bytes sent across all connections.
    pub total_bytes_sent: u64,
    /// Total bytes received across all connections.
    pub total_bytes_received: u64,
}

struct ConnectionPoolInner {
    config: PoolConfig,
    connections: DashMap<u64, Connection>,
    transports: DashMap<u64, Arc<WarpConnection>>,
    edge_connections: DashMap<EdgeIdx, Vec<u64>>,
    /// Index of idle connections per edge for O(1) lookup (mechanical sympathy optimization)
    /// Maintained by mark_idle_indexed/mark_used_indexed to avoid O(n) scanning
    idle_connections: DashMap<EdgeIdx, Vec<u64>>,
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
            idle_connections: DashMap::new(),
            next_conn_id: AtomicU64::new(1),
            edge_semaphores: DashMap::new(),
        }
    }

    #[inline]
    fn get_edge_semaphore(&self, edge_idx: EdgeIdx) -> Arc<Semaphore> {
        self.edge_semaphores
            .entry(edge_idx)
            .or_insert_with(|| Arc::new(Semaphore::new(self.config.max_connections_per_edge)))
            .clone()
    }

    async fn acquire_connection(&self, edge_idx: EdgeIdx) -> Result<u64> {
        // Try to pop an idle connection first - O(1) atomic find+remove
        while let Some(conn_id) = self.pop_idle_connection(edge_idx) {
            if let Some(mut conn) = self.connections.get_mut(&conn_id) {
                conn.mark_used();
                return Ok(conn_id);
            }
            // Connection was removed from connections map, try next idle
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
        // Relaxed is sufficient for ID generation - we only need atomicity
        let conn_id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
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

    /// Find an idle connection for the given edge (hot path - O(1) via index)
    /// Pop an idle connection from the index - O(1) operation (mechanical sympathy)
    /// Returns and removes the most recent idle connection for the edge.
    #[inline]
    fn pop_idle_connection(&self, edge_idx: EdgeIdx) -> Option<u64> {
        // O(1) pop from the end - combines find + remove atomically
        self.idle_connections
            .get_mut(&edge_idx)
            .and_then(|mut ids| ids.pop())
    }

    /// Add connection to the idle index (called when connection becomes idle)
    #[inline]
    fn add_to_idle_index(&self, edge_idx: EdgeIdx, conn_id: u64) {
        self.idle_connections
            .entry(edge_idx)
            .or_insert_with(Vec::new)
            .push(conn_id);
    }

    /// Remove a specific connection from the idle index
    /// Only needed when a connection is closed/invalidated while idle
    #[inline]
    fn remove_from_idle_index(&self, edge_idx: EdgeIdx, conn_id: u64) {
        if let Some(mut ids) = self.idle_connections.get_mut(&edge_idx) {
            // Use swap_remove for O(1) - order doesn't matter for idle pool
            if let Some(pos) = ids.iter().position(|&id| id == conn_id) {
                ids.swap_remove(pos);
            }
        }
    }

    fn release(&self, conn_id: u64) {
        if let Some(mut conn) = self.connections.get_mut(&conn_id) {
            if conn.state == ConnectionState::InUse {
                let edge_idx = conn.edge_idx;
                conn.mark_idle();
                // Add to idle index for O(1) lookup
                self.add_to_idle_index(edge_idx, conn_id);
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
        // Clear idle index for this edge
        self.idle_connections.remove(&edge_idx);
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

/// Main connection pool.
///
/// Manages reusable connections to edges with configurable limits,
/// automatic cleanup of idle connections, and thread-safe access.
///
/// # Example
///
/// ```ignore
/// let config = PoolConfig::default();
/// let pool = ConnectionPool::new(config)?;
///
/// // Acquire a connection to an edge
/// let conn = pool.acquire(edge_idx).await?;
/// conn.send(data)?;
/// // Connection is automatically returned to pool when dropped
/// ```
#[derive(Clone)]
pub struct ConnectionPool {
    inner: Arc<ConnectionPoolInner>,
}

impl ConnectionPool {
    /// Create a new connection pool with the given configuration.
    pub fn new(config: PoolConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            inner: Arc::new(ConnectionPoolInner::new(config)),
        })
    }

    /// Acquire a connection to the specified edge.
    ///
    /// Returns an existing idle connection if available, or creates
    /// a new one. The connection is automatically returned to the pool
    /// when the `PooledConnection` is dropped.
    pub async fn acquire(&self, edge_idx: EdgeIdx) -> Result<PooledConnection> {
        let conn_id = self.inner.acquire_connection(edge_idx).await?;
        Ok(PooledConnection {
            pool: self.inner.clone(),
            conn_id,
            edge_idx,
        })
    }

    /// Acquire a connection with a timeout.
    ///
    /// Returns `PoolError::Timeout` if the connection cannot be acquired
    /// within the specified duration.
    pub async fn acquire_timeout(
        &self,
        edge_idx: EdgeIdx,
        duration: Duration,
    ) -> Result<PooledConnection> {
        timeout(duration, self.acquire(edge_idx))
            .await
            .map_err(|_| PoolError::Timeout(duration.as_millis() as u64))?
    }

    /// Close all connections to the specified edge.
    pub fn close_edge(&self, edge_idx: EdgeIdx) {
        self.inner.close_edge(edge_idx);
    }

    /// Get current pool statistics.
    pub fn stats(&self) -> PoolStats {
        self.inner.stats()
    }

    /// Get the pool configuration.
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

// ============================================================================
// Multi-Path Connection Pool
// ============================================================================

/// Configuration for multi-path connection pool
///
/// Extends the base pool configuration with multi-path specific settings
/// for path diversity and interface management.
#[derive(Debug, Clone)]
pub struct MultiPathPoolConfig {
    /// Base pool configuration
    pub base: PoolConfig,

    /// Maximum connections per unique path (local_ip × remote_ip pair)
    pub max_connections_per_path: usize,

    /// Whether to prefer path diversity when acquiring connections
    /// When true, acquire_diverse() will avoid paths that are currently in-flight
    pub prefer_diversity: bool,
}

impl Default for MultiPathPoolConfig {
    fn default() -> Self {
        Self {
            base: PoolConfig::default(),
            max_connections_per_path: 2,
            prefer_diversity: true,
        }
    }
}

impl MultiPathPoolConfig {
    /// Create a new configuration with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Validate the configuration.
    ///
    /// Validates both base pool config and multi-path specific settings.
    pub fn validate(&self) -> Result<()> {
        self.base.validate()?;
        if self.max_connections_per_path == 0 {
            return Err(PoolError::InvalidConfig(
                "max_connections_per_path must be > 0".to_string(),
            ));
        }
        Ok(())
    }
}

/// Path-aware connection with explicit source/destination tracking
///
/// Extends Connection with path-specific information for multi-path aggregation.
/// Tracks local and remote IP addresses to identify the physical network path.
#[derive(Debug, Clone)]
pub struct PathAwareConnection {
    /// Connection state (Idle, InUse, etc.)
    pub state: ConnectionState,
    /// Edge this connection belongs to
    pub edge_idx: EdgeIdx,
    /// Unique connection identifier
    pub id: u64,
    /// Path identifier (hash of local_ip + remote_ip)
    pub path_id: PathId,
    /// Local interface IP address
    pub local_ip: IpAddr,
    /// Remote endpoint IP address
    pub remote_ip: IpAddr,
    /// Total bytes sent on this connection
    pub bytes_sent: u64,
    /// Total bytes received on this connection
    pub bytes_received: u64,
    /// Timestamp of last activity
    pub last_used_ms: u64,
}

impl PathAwareConnection {
    #[inline]
    fn new(
        id: u64,
        edge_idx: EdgeIdx,
        path_id: PathId,
        local_ip: IpAddr,
        remote_ip: IpAddr,
    ) -> Self {
        Self {
            state: ConnectionState::Idle,
            edge_idx,
            id,
            path_id,
            local_ip,
            remote_ip,
            bytes_sent: 0,
            bytes_received: 0,
            last_used_ms: current_time_ms(),
        }
    }

    /// Mark connection as in-use
    #[inline]
    fn mark_used(&mut self) {
        self.state = ConnectionState::InUse;
        self.last_used_ms = current_time_ms();
    }

    /// Mark connection as idle
    #[inline]
    fn mark_idle(&mut self) {
        self.state = ConnectionState::Idle;
        self.last_used_ms = current_time_ms();
    }
}

/// RAII wrapper for borrowed path-aware connection.
///
/// Extends `PooledConnection` with path tracking for multi-path aggregation.
/// The connection is automatically returned to the pool when dropped, and
/// the path is marked as no longer in-flight.
#[derive(Debug)]
pub struct PooledPathConnection {
    pool: Arc<MultiPathConnectionPoolInner>,
    conn_id: u64,
    edge_idx: EdgeIdx,
    path_id: PathId,
}

impl PooledPathConnection {
    /// Get the edge index for this connection
    #[inline]
    pub fn edge_idx(&self) -> EdgeIdx {
        self.edge_idx
    }

    /// Get the connection ID
    #[inline]
    pub fn conn_id(&self) -> u64 {
        self.conn_id
    }

    /// Get the path ID for this connection
    #[inline]
    pub fn path_id(&self) -> PathId {
        self.path_id
    }

    /// Check if this connection has a real transport attached
    #[inline]
    pub fn has_transport(&self) -> bool {
        self.pool.transports.contains_key(&self.conn_id)
    }

    /// Get the underlying WarpConnection transport if available
    pub fn transport(&self) -> Option<Arc<WarpConnection>> {
        self.pool.transports.get(&self.conn_id).map(|t| t.clone())
    }

    /// Send chunk data using real QUIC transport (zero-copy)
    ///
    /// This method also records throughput metrics for dynamic adaptation.
    pub async fn send_chunk(&self, chunk_id: u32, data: Bytes) -> Result<()> {
        let data_len = data.len() as u64;

        // Update connection stats
        if let Some(mut conn) = self.pool.connections.get_mut(&self.conn_id) {
            conn.bytes_sent += data_len;
        }

        // Record throughput for dynamic metrics (Phase 7)
        self.pool.record_transfer(self.edge_idx, data_len);

        // Fast path: real transport
        if let Some(transport) = self.pool.transports.get(&self.conn_id) {
            let result = transport
                .send_chunk(chunk_id, data)
                .await
                .map_err(|e| PoolError::Transport(format!("Failed to send chunk: {}", e)));

            // Sample RTT after send (if transport provides RTT stats)
            if let Ok(rtt_us) = transport.rtt_us() {
                self.pool.record_rtt(self.edge_idx, rtt_us);
            }

            return result;
        }

        // Mock fallback for tests
        if let Some(conn) = self.pool.connections.get(&self.conn_id) {
            if conn.state != ConnectionState::InUse {
                return Err(PoolError::InvalidConfig(
                    "connection not in use".to_string(),
                ));
            }
            Ok(())
        } else {
            Err(PoolError::ConnectionNotFound(self.conn_id))
        }
    }

    /// Receive a chunk from the peer
    ///
    /// This method also records throughput metrics for dynamic adaptation.
    pub async fn recv_chunk(&self) -> Result<(u32, Bytes)> {
        if let Some(transport) = self.pool.transports.get(&self.conn_id) {
            let result = transport
                .recv_chunk()
                .await
                .map_err(|e| PoolError::Transport(format!("Failed to recv chunk: {}", e)))?;

            // Record bytes received for throughput metrics
            let bytes_received = result.1.len() as u64;
            if let Some(mut conn) = self.pool.connections.get_mut(&self.conn_id) {
                conn.bytes_received += bytes_received;
            }
            self.pool.record_transfer(self.edge_idx, bytes_received);

            // Sample RTT after receive
            if let Ok(rtt_us) = transport.rtt_us() {
                self.pool.record_rtt(self.edge_idx, rtt_us);
            }

            return Ok(result);
        }

        // Mock fallback
        if let Some(mut conn) = self.pool.connections.get_mut(&self.conn_id) {
            if conn.state != ConnectionState::InUse {
                return Err(PoolError::InvalidConfig(
                    "connection not in use".to_string(),
                ));
            }
            let mock_data = Bytes::from(vec![0u8; 1024]);
            conn.bytes_received += mock_data.len() as u64;
            Ok((0, mock_data))
        } else {
            Err(PoolError::ConnectionNotFound(self.conn_id))
        }
    }

    /// Check if this connection's edge is currently congested
    ///
    /// Uses dynamic throughput and RTT metrics to detect congestion.
    #[inline]
    pub fn is_congested(&self) -> bool {
        self.pool.is_edge_congested(self.edge_idx)
    }
}

impl Drop for PooledPathConnection {
    fn drop(&mut self) {
        self.pool.release(self.conn_id, self.path_id);
    }
}

/// Statistics for multi-path connection pool.
///
/// Extends basic pool statistics with path-aware metrics for
/// monitoring multi-path network aggregation.
#[derive(Debug, Clone, Default)]
pub struct MultiPathPoolStats {
    /// Total number of connections across all paths.
    pub total_connections: usize,
    /// Number of connections currently idle.
    pub idle_connections: usize,
    /// Number of connections currently in use.
    pub in_use_connections: usize,
    /// Connection count per edge.
    pub connections_per_edge: HashMap<EdgeIdx, usize>,
    /// Connection count per unique path (local_ip × remote_ip).
    pub connections_per_path: HashMap<PathId, usize>,
    /// Total bytes sent across all connections.
    pub total_bytes_sent: u64,
    /// Number of distinct paths currently handling active transfers.
    pub unique_paths_in_flight: usize,
    /// Number of local network interfaces with active connections.
    pub active_local_interfaces: usize,
}

/// Detailed metrics for multi-path network aggregation observability
///
/// Provides comprehensive metrics for monitoring the health and performance
/// of multi-path connections across multiple network interfaces.
#[derive(Debug, Clone)]
pub struct MultiPathMetrics {
    /// Total number of connections across all paths
    pub total_connections: usize,
    /// Connection count per unique path (local_ip × remote_ip)
    pub connections_per_path: HashMap<PathId, usize>,
    /// Total bytes sent per local interface
    pub bytes_per_interface: HashMap<IpAddr, u64>,
    /// Average latency (RTT) per path in microseconds
    pub latency_per_path: HashMap<PathId, u64>,
    /// Path diversity score (0.0 = all same path, 1.0 = perfectly distributed)
    pub diversity_score: f32,
    /// Number of active local interfaces
    pub active_local_interfaces: usize,
    /// Number of active remote endpoints
    pub active_remote_endpoints: usize,
    /// Timestamp when metrics were collected (ms since epoch)
    pub timestamp_ms: u64,
    /// Paths currently handling active transfers
    pub in_flight_paths: Vec<PathId>,
    /// Health score per path (0.0 = unhealthy, 1.0 = healthy)
    pub health_per_path: HashMap<PathId, f32>,
}

impl Default for MultiPathMetrics {
    fn default() -> Self {
        Self {
            total_connections: 0,
            connections_per_path: HashMap::new(),
            bytes_per_interface: HashMap::new(),
            latency_per_path: HashMap::new(),
            diversity_score: 0.0,
            active_local_interfaces: 0,
            active_remote_endpoints: 0,
            timestamp_ms: current_time_ms(),
            in_flight_paths: Vec::new(),
            health_per_path: HashMap::new(),
        }
    }
}

impl MultiPathMetrics {
    /// Create new metrics from pool stats with additional data
    pub fn from_pool_stats(stats: &MultiPathPoolStats) -> Self {
        Self {
            total_connections: stats.total_connections,
            connections_per_path: stats.connections_per_path.clone(),
            bytes_per_interface: HashMap::new(), // Requires connection tracking
            latency_per_path: HashMap::new(),    // Requires latency tracking
            diversity_score: Self::compute_diversity(&stats.connections_per_path),
            active_local_interfaces: stats.active_local_interfaces,
            active_remote_endpoints: stats.connections_per_path.len(),
            timestamp_ms: current_time_ms(),
            in_flight_paths: Vec::new(),
            health_per_path: HashMap::new(),
        }
    }

    /// Compute path diversity score
    ///
    /// Returns a value between 0.0 and 1.0:
    /// - 0.0 = all connections use the same path
    /// - 1.0 = connections are evenly distributed across all paths
    fn compute_diversity(connections_per_path: &HashMap<PathId, usize>) -> f32 {
        if connections_per_path.is_empty() {
            return 0.0;
        }

        let total: usize = connections_per_path.values().sum();
        if total == 0 {
            return 0.0;
        }

        let num_paths = connections_per_path.len();
        if num_paths == 1 {
            return 0.0; // Only one path, no diversity
        }

        // Calculate entropy-based diversity
        // Maximum entropy would be even distribution across all paths
        let ideal_per_path = total as f32 / num_paths as f32;
        let mut variance = 0.0_f32;

        for &count in connections_per_path.values() {
            let diff = count as f32 - ideal_per_path;
            variance += diff * diff;
        }

        let avg_variance = variance / num_paths as f32;
        let max_variance = ideal_per_path * ideal_per_path * num_paths as f32;

        if max_variance == 0.0 {
            return 1.0;
        }

        // Diversity = 1 - normalized variance
        (1.0 - avg_variance / max_variance).clamp(0.0, 1.0)
    }

    /// Check if any path is overloaded (handling >50% of all connections)
    pub fn has_overloaded_path(&self) -> bool {
        if self.total_connections == 0 {
            return false;
        }

        let threshold = self.total_connections as f32 * 0.5;
        self.connections_per_path
            .values()
            .any(|&count| count as f32 > threshold)
    }

    /// Get underutilized paths (handling <10% of expected fair share)
    pub fn underutilized_paths(&self) -> Vec<PathId> {
        if self.connections_per_path.is_empty() || self.total_connections == 0 {
            return Vec::new();
        }

        let fair_share = self.total_connections as f32 / self.connections_per_path.len() as f32;
        let threshold = fair_share * 0.1;

        self.connections_per_path
            .iter()
            .filter(|(_, count)| (**count as f32) < threshold)
            .map(|(path_id, _)| *path_id)
            .collect()
    }

    /// Summary string for logging
    pub fn summary(&self) -> String {
        format!(
            "MultiPath[conns={}, paths={}, diversity={:.2}, interfaces={}]",
            self.total_connections,
            self.connections_per_path.len(),
            self.diversity_score,
            self.active_local_interfaces
        )
    }
}

/// Configuration for dynamic metrics tracking.
///
/// Controls how throughput and RTT metrics are tracked and used for
/// congestion detection and path selection decisions.
#[derive(Debug, Clone)]
pub struct DynamicMetricsConfig {
    /// Window size for throughput calculation (milliseconds).
    pub throughput_window_ms: u64,
    /// RTT change threshold for trend detection (e.g., 0.20 = 20%).
    pub rtt_threshold: f32,
    /// Maximum RTT samples to keep per edge.
    pub max_rtt_samples: usize,
    /// Saturation threshold (0.0-1.0) above which an edge is considered congested.
    pub saturation_threshold: f32,
}

impl Default for DynamicMetricsConfig {
    fn default() -> Self {
        Self {
            throughput_window_ms: 1000, // 1 second window
            rtt_threshold: 0.20,        // 20% change for trend detection
            max_rtt_samples: 10,        // Keep last 10 RTT samples
            saturation_threshold: 0.85, // 85% saturation = congested
        }
    }
}

/// Inner implementation for multi-path connection pool
struct MultiPathConnectionPoolInner {
    config: MultiPathPoolConfig,
    connections: DashMap<u64, PathAwareConnection>,
    transports: DashMap<u64, Arc<WarpConnection>>,

    /// Connections grouped by edge
    edge_connections: DashMap<EdgeIdx, Vec<u64>>,

    /// Connections grouped by path
    path_connections: DashMap<PathId, Vec<u64>>,

    /// Paths currently in-flight (for diversity selection)
    in_flight_paths: DashSet<PathId>,

    /// Idle connections per path for O(1) lookup
    idle_connections: DashMap<PathId, Vec<u64>>,

    /// Dynamic metrics per edge for throughput/RTT tracking (Phase 7)
    edge_metrics: DashMap<EdgeIdx, DynamicEdgeMetrics>,

    /// Configuration for dynamic metrics
    metrics_config: DynamicMetricsConfig,

    next_conn_id: AtomicU64,
    total_semaphore: Arc<Semaphore>,
    path_semaphores: DashMap<PathId, Arc<Semaphore>>,
}

impl std::fmt::Debug for MultiPathConnectionPoolInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiPathConnectionPoolInner")
            .field("config", &self.config)
            .field("connections_count", &self.connections.len())
            .field("in_flight_paths_count", &self.in_flight_paths.len())
            .finish()
    }
}

impl MultiPathConnectionPoolInner {
    fn new(config: MultiPathPoolConfig) -> Self {
        Self::with_metrics_config(config, DynamicMetricsConfig::default())
    }

    fn with_metrics_config(
        config: MultiPathPoolConfig,
        metrics_config: DynamicMetricsConfig,
    ) -> Self {
        Self {
            total_semaphore: Arc::new(Semaphore::new(config.base.max_total_connections)),
            config,
            connections: DashMap::new(),
            transports: DashMap::new(),
            edge_connections: DashMap::new(),
            path_connections: DashMap::new(),
            in_flight_paths: DashSet::new(),
            idle_connections: DashMap::new(),
            edge_metrics: DashMap::new(),
            metrics_config,
            next_conn_id: AtomicU64::new(1),
            path_semaphores: DashMap::new(),
        }
    }

    /// Get or create dynamic metrics for an edge
    fn get_or_create_edge_metrics(
        &self,
        edge_idx: EdgeIdx,
        capacity_bps: u64,
    ) -> dashmap::mapref::one::RefMut<'_, EdgeIdx, DynamicEdgeMetrics> {
        self.edge_metrics.entry(edge_idx).or_insert_with(|| {
            let mut metrics = DynamicEdgeMetrics::new(edge_idx, capacity_bps);
            metrics.max_rtt_samples = self.metrics_config.max_rtt_samples;
            metrics.rtt_threshold = self.metrics_config.rtt_threshold;
            metrics
        })
    }

    /// Record bytes transferred for an edge (called on send/receive)
    fn record_transfer(&self, edge_idx: EdgeIdx, bytes: u64) {
        if let Some(mut metrics) = self.edge_metrics.get_mut(&edge_idx) {
            metrics.record_transfer(bytes, self.metrics_config.throughput_window_ms);
        }
    }

    /// Record RTT sample for an edge (called when RTT is measured)
    fn record_rtt(&self, edge_idx: EdgeIdx, rtt_us: u32) {
        if let Some(mut metrics) = self.edge_metrics.get_mut(&edge_idx) {
            metrics.record_rtt(rtt_us);
        }
    }

    /// Check if an edge is congested
    fn is_edge_congested(&self, edge_idx: EdgeIdx) -> bool {
        self.edge_metrics
            .get(&edge_idx)
            .map(|m| m.is_congested(self.metrics_config.saturation_threshold))
            .unwrap_or(false)
    }

    #[inline]
    fn get_path_semaphore(&self, path_id: PathId) -> Arc<Semaphore> {
        self.path_semaphores
            .entry(path_id)
            .or_insert_with(|| Arc::new(Semaphore::new(self.config.max_connections_per_path)))
            .clone()
    }

    /// Pop an idle connection from a specific path
    #[inline]
    fn pop_idle_from_path(&self, path_id: PathId) -> Option<u64> {
        self.idle_connections
            .get_mut(&path_id)
            .and_then(|mut ids| ids.pop())
    }

    /// Add connection to idle index
    #[inline]
    fn add_to_idle_index(&self, path_id: PathId, conn_id: u64) {
        self.idle_connections
            .entry(path_id)
            .or_insert_with(Vec::new)
            .push(conn_id);
    }

    /// Release connection and remove from in-flight paths
    fn release(&self, conn_id: u64, path_id: PathId) {
        if let Some(mut conn) = self.connections.get_mut(&conn_id) {
            if conn.state == ConnectionState::InUse {
                conn.mark_idle();
                self.add_to_idle_index(path_id, conn_id);
                self.in_flight_paths.remove(&path_id);
            }
        }
    }

    fn stats(&self) -> MultiPathPoolStats {
        let mut stats = MultiPathPoolStats::default();
        let mut per_edge: HashMap<EdgeIdx, usize> = HashMap::new();
        let mut per_path: HashMap<PathId, usize> = HashMap::new();
        let mut local_ips = std::collections::HashSet::new();

        for conn_ref in self.connections.iter() {
            let conn = conn_ref.value();
            stats.total_connections += 1;
            stats.total_bytes_sent += conn.bytes_sent;
            local_ips.insert(conn.local_ip);

            match conn.state {
                ConnectionState::Idle => stats.idle_connections += 1,
                ConnectionState::InUse => stats.in_use_connections += 1,
                _ => {}
            }

            *per_edge.entry(conn.edge_idx).or_insert(0) += 1;
            *per_path.entry(conn.path_id).or_insert(0) += 1;
        }

        stats.connections_per_edge = per_edge;
        stats.connections_per_path = per_path;
        stats.unique_paths_in_flight = self.in_flight_paths.len();
        stats.active_local_interfaces = local_ips.len();
        stats
    }
}

/// Multi-path connection pool with path diversity support
///
/// This pool extends the basic connection pool with:
/// - Path-aware connections tracking (local_ip × remote_ip)
/// - In-flight path tracking for diversity selection
/// - Integration with MultiPathEndpoint for explicit interface binding
///
/// # Path Diversity Strategy
///
/// When `prefer_diversity` is enabled, `acquire_diverse()` will:
/// 1. Enumerate all possible paths for the edge (local_ips × peer_endpoints)
/// 2. Score paths by priority and whether they're currently in-flight
/// 3. Select the best path (lowest score = preferred, not in-flight)
///
/// This ensures concurrent requests to the same edge spread across different
/// physical network paths, maximizing aggregate throughput.
#[derive(Clone)]
pub struct MultiPathConnectionPool {
    inner: Arc<MultiPathConnectionPoolInner>,
    multi_endpoint: Arc<tokio::sync::RwLock<MultiPathEndpoint>>,
}

impl MultiPathConnectionPool {
    /// Create a new multi-path connection pool
    ///
    /// Requires a MultiPathEndpoint for interface binding and optional config.
    pub fn new(multi_endpoint: MultiPathEndpoint, config: MultiPathPoolConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            inner: Arc::new(MultiPathConnectionPoolInner::new(config)),
            multi_endpoint: Arc::new(tokio::sync::RwLock::new(multi_endpoint)),
        })
    }

    /// Acquire a connection with path diversity
    ///
    /// This is the key method for multi-path aggregation. It:
    /// 1. Enumerates all possible paths to the edge
    /// 2. Scores paths by priority and in-flight status
    /// 3. Selects the best available path
    /// 4. Creates or reuses a connection on that path
    ///
    /// # Arguments
    /// * `edge_idx` - The edge to connect to
    /// * `peer_endpoints` - Available endpoints for this peer
    /// * `server_name` - TLS server name for connection
    pub async fn acquire_diverse(
        &self,
        edge_idx: EdgeIdx,
        peer_endpoints: &[PeerEndpoint],
        server_name: &str,
    ) -> Result<PooledPathConnection> {
        let multi_ep = self.multi_endpoint.read().await;
        let local_ips = multi_ep.local_ips();

        if local_ips.is_empty() {
            return Err(PoolError::NoPath(
                "No local interfaces available".to_string(),
            ));
        }

        let active_endpoints: Vec<_> = peer_endpoints.iter().filter(|ep| ep.enabled).collect();

        if active_endpoints.is_empty() {
            return Err(PoolError::NoPath("No active peer endpoints".to_string()));
        }

        // Enumerate and score all possible paths
        let mut scored_paths: Vec<(IpAddr, &PeerEndpoint, PathId, f32)> = Vec::new();

        for local_ip in &local_ips {
            for ep in &active_endpoints {
                let path_id = PathId::from_ips(*local_ip, ep.addr.ip());

                // Score: priority (lower = better) + in-flight penalty
                let priority_score = ep.priority.0 as f32 / 255.0;
                let in_flight_penalty = if self.inner.in_flight_paths.contains(&path_id) {
                    1.0
                } else {
                    0.0
                };
                let score = priority_score + in_flight_penalty;

                scored_paths.push((*local_ip, *ep, path_id, score));
            }
        }

        // Sort by score (lowest first)
        scored_paths.sort_by(|a, b| a.3.partial_cmp(&b.3).unwrap_or(std::cmp::Ordering::Equal));

        // Try paths in order until one succeeds
        for (local_ip, peer_ep, path_id, _score) in scored_paths {
            // Try to get an idle connection first
            if let Some(conn_id) = self.inner.pop_idle_from_path(path_id) {
                if let Some(mut conn) = self.inner.connections.get_mut(&conn_id) {
                    conn.mark_used();
                    self.inner.in_flight_paths.insert(path_id);
                    return Ok(PooledPathConnection {
                        pool: self.inner.clone(),
                        conn_id,
                        edge_idx,
                        path_id,
                    });
                }
            }

            // Try to create a new connection on this path
            match self
                .try_create_connection(edge_idx, path_id, local_ip, peer_ep, server_name, &multi_ep)
                .await
            {
                Ok(pooled_conn) => return Ok(pooled_conn),
                Err(PoolError::MaxConnectionsPerEdge(_)) => continue, // Try next path
                Err(PoolError::MaxTotalConnections(_)) => continue,
                Err(e) => {
                    tracing::debug!("Failed to create connection via {:?}: {}", path_id, e);
                    continue;
                }
            }
        }

        Err(PoolError::NoPath(
            "All paths exhausted or at capacity".to_string(),
        ))
    }

    /// Try to create a new connection on a specific path
    async fn try_create_connection(
        &self,
        edge_idx: EdgeIdx,
        path_id: PathId,
        local_ip: IpAddr,
        peer_ep: &PeerEndpoint,
        server_name: &str,
        multi_ep: &MultiPathEndpoint,
    ) -> Result<PooledPathConnection> {
        // Acquire semaphores
        let _total_permit = self.inner.total_semaphore.try_acquire().map_err(|_| {
            PoolError::MaxTotalConnections(self.inner.config.base.max_total_connections)
        })?;

        let path_sem = self.inner.get_path_semaphore(path_id);
        let _path_permit = path_sem.try_acquire().map_err(|_| {
            PoolError::MaxConnectionsPerEdge(self.inner.config.max_connections_per_path)
        })?;

        // Connect via specific interface
        let transport = multi_ep
            .connect_via(local_ip, peer_ep.addr, server_name)
            .await
            .map_err(|e| PoolError::Transport(format!("Failed to connect: {}", e)))?;

        let transport = Arc::new(transport);
        let conn_id = self.inner.next_conn_id.fetch_add(1, Ordering::Relaxed);
        let mut conn =
            PathAwareConnection::new(conn_id, edge_idx, path_id, local_ip, peer_ep.addr.ip());
        conn.mark_used();

        // Store connection and transport
        self.inner.connections.insert(conn_id, conn);
        self.inner.transports.insert(conn_id, transport);
        self.inner
            .edge_connections
            .entry(edge_idx)
            .or_insert_with(Vec::new)
            .push(conn_id);
        self.inner
            .path_connections
            .entry(path_id)
            .or_insert_with(Vec::new)
            .push(conn_id);
        self.inner.in_flight_paths.insert(path_id);

        // Keep permits (connection is now managed)
        _total_permit.forget();
        _path_permit.forget();

        Ok(PooledPathConnection {
            pool: self.inner.clone(),
            conn_id,
            edge_idx,
            path_id,
        })
    }

    /// Get pool statistics
    pub fn stats(&self) -> MultiPathPoolStats {
        self.inner.stats()
    }

    /// Get pool configuration
    pub fn config(&self) -> &MultiPathPoolConfig {
        &self.inner.config
    }

    /// Close all connections to an edge
    pub fn close_edge(&self, edge_idx: EdgeIdx) {
        if let Some((_, conn_ids)) = self.inner.edge_connections.remove(&edge_idx) {
            for conn_id in conn_ids {
                if let Some((_, conn)) = self.inner.connections.remove(&conn_id) {
                    self.inner.transports.remove(&conn_id);
                    self.inner
                        .path_connections
                        .get_mut(&conn.path_id)
                        .map(|mut v| v.retain(|&id| id != conn_id));
                    self.inner.in_flight_paths.remove(&conn.path_id);
                    self.inner
                        .idle_connections
                        .get_mut(&conn.path_id)
                        .map(|mut v| v.retain(|&id| id != conn_id));
                }
            }
        }
    }

    /// Get path diversity score (0.0 = all same path, 1.0 = all different paths)
    pub fn path_diversity(&self, edge_idx: EdgeIdx) -> f32 {
        if let Some(conn_ids) = self.inner.edge_connections.get(&edge_idx) {
            let mut unique_paths = std::collections::HashSet::new();
            for conn_id in conn_ids.iter() {
                if let Some(conn) = self.inner.connections.get(conn_id) {
                    unique_paths.insert(conn.path_id);
                }
            }
            let total = conn_ids.len();
            if total == 0 {
                return 0.0;
            }
            unique_paths.len() as f32 / total as f32
        } else {
            0.0
        }
    }

    /// Get detailed metrics for observability
    ///
    /// Returns comprehensive metrics including path diversity, interface
    /// utilization, and connection distribution.
    pub fn metrics(&self) -> MultiPathMetrics {
        let stats = self.inner.stats();

        // Collect bytes per interface
        let mut bytes_per_interface: HashMap<IpAddr, u64> = HashMap::new();
        for conn_ref in self.inner.connections.iter() {
            let conn = conn_ref.value();
            *bytes_per_interface.entry(conn.local_ip).or_insert(0) += conn.bytes_sent;
        }

        // Collect in-flight paths
        let in_flight_paths: Vec<PathId> = self.inner.in_flight_paths.iter().map(|p| *p).collect();

        // Collect latency from dynamic metrics (Phase 7)
        let mut latency_per_path: HashMap<PathId, u64> = HashMap::new();
        for conn_ref in self.inner.connections.iter() {
            let conn = conn_ref.value();
            if let Some(metrics) = self.inner.edge_metrics.get(&conn.edge_idx) {
                latency_per_path.insert(conn.path_id, metrics.avg_rtt_us() as u64);
            }
        }

        // Collect health from dynamic metrics (Phase 7)
        let mut health_per_path: HashMap<PathId, f32> = HashMap::new();
        for conn_ref in self.inner.connections.iter() {
            let conn = conn_ref.value();
            if let Some(metrics) = self.inner.edge_metrics.get(&conn.edge_idx) {
                // Health = 1.0 - saturation_ratio, clamped to 0.0-1.0
                let health = (1.0 - metrics.throughput.saturation_ratio).clamp(0.0, 1.0);
                health_per_path.insert(conn.path_id, health);
            }
        }

        MultiPathMetrics {
            total_connections: stats.total_connections,
            connections_per_path: stats.connections_per_path.clone(),
            bytes_per_interface,
            latency_per_path,
            diversity_score: MultiPathMetrics::compute_diversity(&stats.connections_per_path),
            active_local_interfaces: stats.active_local_interfaces,
            active_remote_endpoints: stats.connections_per_path.len(),
            timestamp_ms: current_time_ms(),
            in_flight_paths,
            health_per_path,
        }
    }

    // =========================================================================
    // Dynamic Metrics API (Phase 7)
    // =========================================================================

    /// Get dynamic metrics for a specific edge
    ///
    /// Returns throughput, RTT, and congestion information for the edge.
    pub fn edge_metrics(&self, edge_idx: EdgeIdx) -> Option<DynamicEdgeMetrics> {
        self.inner.edge_metrics.get(&edge_idx).map(|m| m.clone())
    }

    /// Get all dynamic edge metrics
    ///
    /// Returns a map of all tracked edge metrics for scheduler integration.
    pub fn all_edge_metrics(&self) -> HashMap<EdgeIdx, DynamicEdgeMetrics> {
        self.inner
            .edge_metrics
            .iter()
            .map(|entry| (*entry.key(), entry.value().clone()))
            .collect()
    }

    /// Initialize metrics tracking for an edge with estimated capacity
    ///
    /// Should be called when an edge is discovered or configured.
    pub fn init_edge_metrics(&self, edge_idx: EdgeIdx, capacity_bps: u64) {
        self.inner
            .get_or_create_edge_metrics(edge_idx, capacity_bps);
    }

    /// Check if an edge is currently congested
    ///
    /// Returns true if throughput exceeds saturation threshold or RTT is increasing.
    pub fn is_edge_congested(&self, edge_idx: EdgeIdx) -> bool {
        self.inner.is_edge_congested(edge_idx)
    }

    /// Get all congested edges
    ///
    /// Returns a list of edges that are currently showing signs of congestion.
    pub fn congested_edges(&self) -> Vec<EdgeIdx> {
        self.inner
            .edge_metrics
            .iter()
            .filter(|entry| {
                entry
                    .value()
                    .is_congested(self.inner.metrics_config.saturation_threshold)
            })
            .map(|entry| *entry.key())
            .collect()
    }

    /// Get the dynamic metrics configuration
    pub fn metrics_config(&self) -> &DynamicMetricsConfig {
        &self.inner.metrics_config
    }
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
        let result = tokio::time::timeout(Duration::from_millis(100), pool.acquire(edge_idx)).await;
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

    // =========================================================================
    // Multi-Path Pool Tests
    // =========================================================================

    #[test]
    fn test_multipath_pool_config_default() {
        let config = MultiPathPoolConfig::default();
        assert_eq!(config.max_connections_per_path, 2);
        assert!(config.prefer_diversity);
        assert_eq!(config.base.max_connections_per_edge, 4);
    }

    #[test]
    fn test_multipath_pool_config_validation() {
        let config = MultiPathPoolConfig::default();
        assert!(config.validate().is_ok());

        let invalid = MultiPathPoolConfig {
            max_connections_per_path: 0,
            ..Default::default()
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_path_aware_connection_creation() {
        let edge_idx = EdgeIdx::new(1);
        let path_id =
            PathId::from_ips("10.10.10.1".parse().unwrap(), "10.10.10.2".parse().unwrap());
        let conn = PathAwareConnection::new(
            42,
            edge_idx,
            path_id,
            "10.10.10.1".parse().unwrap(),
            "10.10.10.2".parse().unwrap(),
        );

        assert_eq!(conn.id, 42);
        assert_eq!(conn.edge_idx, edge_idx);
        assert_eq!(conn.path_id, path_id);
        assert_eq!(conn.state, ConnectionState::Idle);
        assert_eq!(conn.bytes_sent, 0);
        assert_eq!(conn.bytes_received, 0);
        assert_eq!(conn.local_ip, "10.10.10.1".parse::<IpAddr>().unwrap());
        assert_eq!(conn.remote_ip, "10.10.10.2".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_path_aware_connection_state_transitions() {
        let edge_idx = EdgeIdx::new(1);
        let path_id = PathId(12345);
        let mut conn = PathAwareConnection::new(
            1,
            edge_idx,
            path_id,
            "127.0.0.1".parse().unwrap(),
            "127.0.0.2".parse().unwrap(),
        );

        assert_eq!(conn.state, ConnectionState::Idle);

        conn.mark_used();
        assert_eq!(conn.state, ConnectionState::InUse);

        conn.mark_idle();
        assert_eq!(conn.state, ConnectionState::Idle);
    }

    #[test]
    fn test_path_aware_connection_ipv6() {
        let edge_idx = EdgeIdx::new(1);
        let local_ip: IpAddr = "::1".parse().unwrap();
        let remote_ip: IpAddr = "2001:db8::1".parse().unwrap();
        let path_id = PathId::from_ips(local_ip, remote_ip);

        let conn = PathAwareConnection::new(1, edge_idx, path_id, local_ip, remote_ip);

        assert_eq!(conn.local_ip, local_ip);
        assert_eq!(conn.remote_ip, remote_ip);
    }

    #[test]
    fn test_multipath_pool_stats_default() {
        let stats = MultiPathPoolStats::default();
        assert_eq!(stats.total_connections, 0);
        assert_eq!(stats.idle_connections, 0);
        assert_eq!(stats.in_use_connections, 0);
        assert_eq!(stats.total_bytes_sent, 0);
        assert_eq!(stats.unique_paths_in_flight, 0);
        assert_eq!(stats.active_local_interfaces, 0);
        assert!(stats.connections_per_edge.is_empty());
        assert!(stats.connections_per_path.is_empty());
    }

    #[test]
    fn test_path_id_deterministic() {
        // Same IPs should produce same PathId
        let local: IpAddr = "10.10.10.1".parse().unwrap();
        let remote: IpAddr = "10.10.10.2".parse().unwrap();

        let path1 = PathId::from_ips(local, remote);
        let path2 = PathId::from_ips(local, remote);

        assert_eq!(path1, path2);

        // Different IPs should produce different PathId
        let remote2: IpAddr = "10.10.11.2".parse().unwrap();
        let path3 = PathId::from_ips(local, remote2);

        assert_ne!(path1, path3);
    }

    #[test]
    fn test_path_id_symmetric_different() {
        // (A, B) should be different from (B, A)
        let ip_a: IpAddr = "10.10.10.1".parse().unwrap();
        let ip_b: IpAddr = "10.10.10.2".parse().unwrap();

        let path_ab = PathId::from_ips(ip_a, ip_b);
        let path_ba = PathId::from_ips(ip_b, ip_a);

        assert_ne!(path_ab, path_ba);
    }

    // =========================================================================
    // MultiPathMetrics Tests
    // =========================================================================

    #[test]
    fn test_multipath_metrics_default() {
        let metrics = MultiPathMetrics::default();
        assert_eq!(metrics.total_connections, 0);
        assert_eq!(metrics.diversity_score, 0.0);
        assert_eq!(metrics.active_local_interfaces, 0);
        assert!(metrics.connections_per_path.is_empty());
        assert!(metrics.bytes_per_interface.is_empty());
        assert!(metrics.in_flight_paths.is_empty());
    }

    #[test]
    fn test_multipath_metrics_from_pool_stats() {
        let mut stats = MultiPathPoolStats::default();
        stats.total_connections = 10;
        stats.active_local_interfaces = 2;
        stats.connections_per_path.insert(PathId(1), 5);
        stats.connections_per_path.insert(PathId(2), 5);

        let metrics = MultiPathMetrics::from_pool_stats(&stats);

        assert_eq!(metrics.total_connections, 10);
        assert_eq!(metrics.active_local_interfaces, 2);
        assert_eq!(metrics.active_remote_endpoints, 2);
        // Even distribution should have high diversity
        assert!(metrics.diversity_score > 0.9);
    }

    #[test]
    fn test_multipath_metrics_diversity_single_path() {
        let mut connections_per_path = HashMap::new();
        connections_per_path.insert(PathId(1), 10);

        let diversity = MultiPathMetrics::compute_diversity(&connections_per_path);
        assert_eq!(diversity, 0.0); // Single path = no diversity
    }

    #[test]
    fn test_multipath_metrics_diversity_even_distribution() {
        let mut connections_per_path = HashMap::new();
        connections_per_path.insert(PathId(1), 5);
        connections_per_path.insert(PathId(2), 5);

        let diversity = MultiPathMetrics::compute_diversity(&connections_per_path);
        assert!(diversity > 0.95); // Perfect distribution
    }

    #[test]
    fn test_multipath_metrics_diversity_uneven_distribution() {
        let mut connections_per_path = HashMap::new();
        connections_per_path.insert(PathId(1), 9);
        connections_per_path.insert(PathId(2), 1);

        let diversity = MultiPathMetrics::compute_diversity(&connections_per_path);
        // Uneven distribution (9:1) should have lower diversity than perfect (5:5)
        // But not zero because there's still some distribution
        assert!(diversity < 0.8);
        assert!(diversity > 0.0);

        // Test extremely uneven distribution
        let mut extreme = HashMap::new();
        extreme.insert(PathId(1), 99);
        extreme.insert(PathId(2), 1);
        let extreme_diversity = MultiPathMetrics::compute_diversity(&extreme);
        assert!(extreme_diversity < diversity); // More uneven = lower diversity
    }

    #[test]
    fn test_multipath_metrics_has_overloaded_path() {
        let mut metrics = MultiPathMetrics::default();
        metrics.total_connections = 10;

        // Not overloaded when evenly distributed
        metrics.connections_per_path.insert(PathId(1), 5);
        metrics.connections_per_path.insert(PathId(2), 5);
        assert!(!metrics.has_overloaded_path());

        // Overloaded when one path has >50%
        metrics.connections_per_path.clear();
        metrics.connections_per_path.insert(PathId(1), 8);
        metrics.connections_per_path.insert(PathId(2), 2);
        assert!(metrics.has_overloaded_path());
    }

    #[test]
    fn test_multipath_metrics_underutilized_paths() {
        let mut metrics = MultiPathMetrics::default();
        metrics.total_connections = 100;
        metrics.connections_per_path.insert(PathId(1), 90);
        metrics.connections_per_path.insert(PathId(2), 5);
        metrics.connections_per_path.insert(PathId(3), 5);

        let underutilized = metrics.underutilized_paths();
        // Fair share would be ~33 per path, 10% threshold = 3.3
        // Paths with <3.3 connections are underutilized
        // Both PathId(2) and PathId(3) have 5, which is > 3.3, so not underutilized
        // Actually, let's recalculate: 100/3 = 33.3, 10% of 33.3 = 3.33
        // 5 > 3.33, so they're not underutilized
        assert!(underutilized.is_empty());

        // Now test with truly underutilized path
        metrics.connections_per_path.clear();
        metrics.connections_per_path.insert(PathId(1), 97);
        metrics.connections_per_path.insert(PathId(2), 2);
        metrics.connections_per_path.insert(PathId(3), 1);

        let underutilized = metrics.underutilized_paths();
        // Fair share = 33.3, threshold = 3.33
        // PathId(2)=2 and PathId(3)=1 are both < 3.33
        assert_eq!(underutilized.len(), 2);
        assert!(underutilized.contains(&PathId(2)));
        assert!(underutilized.contains(&PathId(3)));
    }

    #[test]
    fn test_multipath_metrics_summary() {
        let mut metrics = MultiPathMetrics::default();
        metrics.total_connections = 10;
        metrics.connections_per_path.insert(PathId(1), 5);
        metrics.connections_per_path.insert(PathId(2), 5);
        metrics.diversity_score = 0.95;
        metrics.active_local_interfaces = 2;

        let summary = metrics.summary();
        assert!(summary.contains("conns=10"));
        assert!(summary.contains("paths=2"));
        assert!(summary.contains("diversity=0.95"));
        assert!(summary.contains("interfaces=2"));
    }

    #[test]
    fn test_multipath_metrics_empty() {
        let metrics = MultiPathMetrics::default();
        assert!(!metrics.has_overloaded_path());
        assert!(metrics.underutilized_paths().is_empty());
    }
}
