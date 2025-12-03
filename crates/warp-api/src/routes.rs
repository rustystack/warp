//! API route handlers

use crate::{
    ApiError, EdgeInfo, EdgeListResponse, ErrorResponse, HealthStatus, MetricsResponse,
    SystemCapabilities, SystemInfo, TransferListResponse, TransferRequest,
    TransferResponse, TransferStatus,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// CPU sample for usage calculation
#[derive(Clone, Default)]
struct CpuSample {
    /// Total CPU time (user + system) in ticks
    cpu_ticks: u64,
    /// Wall clock time when sample was taken
    timestamp: Option<std::time::Instant>,
}

/// Shared application state
#[derive(Clone)]
pub struct ApiState {
    /// Active transfers
    transfers: Arc<RwLock<HashMap<Uuid, TransferResponse>>>,
    /// Connected edge nodes
    edges: Arc<RwLock<HashMap<String, EdgeInfo>>>,
    /// Server start time
    start_time: std::time::Instant,
    /// Total bytes transferred counter
    bytes_transferred: warp_telemetry::Counter,
    /// Last CPU sample for usage calculation
    last_cpu_sample: Arc<RwLock<CpuSample>>,
}

impl ApiState {
    /// Create new API state
    pub fn new() -> Self {
        let registry = warp_telemetry::MetricRegistry::global();
        Self {
            transfers: Arc::new(RwLock::new(HashMap::new())),
            edges: Arc::new(RwLock::new(HashMap::new())),
            start_time: std::time::Instant::now(),
            bytes_transferred: registry.counter("bytes_transferred", "Total bytes transferred"),
            last_cpu_sample: Arc::new(RwLock::new(CpuSample::default())),
        }
    }

    /// Get uptime in seconds
    pub fn uptime_seconds(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Record bytes transferred
    pub fn record_bytes(&self, bytes: u64) {
        self.bytes_transferred.inc_by(bytes);
    }

    /// Get total bytes transferred
    pub fn total_bytes_transferred(&self) -> u64 {
        self.bytes_transferred.get()
    }

    /// Calculate average throughput in Mbps
    pub fn average_throughput_mbps(&self) -> f64 {
        let uptime = self.uptime_seconds();
        if uptime == 0 {
            return 0.0;
        }
        let bytes = self.total_bytes_transferred();
        // bytes/second * 8 = bits/second, /1_000_000 = Mbps
        (bytes as f64 / uptime as f64) * 8.0 / 1_000_000.0
    }

    /// Get process memory usage in bytes (Linux /proc/self/statm)
    pub fn memory_usage_bytes(&self) -> u64 {
        #[cfg(target_os = "linux")]
        {
            if let Ok(statm) = std::fs::read_to_string("/proc/self/statm") {
                // Format: size resident shared text lib data dt (in pages)
                // Second field is resident set size
                if let Some(rss_pages) = statm.split_whitespace().nth(1) {
                    if let Ok(pages) = rss_pages.parse::<u64>() {
                        return pages * 4096; // Assume 4KB pages
                    }
                }
            }
            0
        }
        #[cfg(not(target_os = "linux"))]
        {
            0
        }
    }

    /// Get CPU usage percent by sampling /proc/self/stat
    ///
    /// Returns CPU usage as percentage (0-100 per core, can exceed 100% on multi-core).
    /// First call returns 0.0 as baseline sample. Subsequent calls calculate delta.
    pub async fn cpu_usage_percent(&self) -> f64 {
        #[cfg(target_os = "linux")]
        {
            // Read current CPU ticks from /proc/self/stat
            // Format: pid (comm) state ppid pgrp ... utime stime ...
            // utime (14th field) and stime (15th field) are in clock ticks
            let current_ticks = match std::fs::read_to_string("/proc/self/stat") {
                Ok(stat) => {
                    let fields: Vec<&str> = stat.split_whitespace().collect();
                    if fields.len() > 14 {
                        let utime = fields[13].parse::<u64>().unwrap_or(0);
                        let stime = fields[14].parse::<u64>().unwrap_or(0);
                        utime + stime
                    } else {
                        return 0.0;
                    }
                }
                Err(_) => return 0.0,
            };

            let now = std::time::Instant::now();

            // Get clock ticks per second (usually 100 on Linux)
            let ticks_per_sec = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as f64;
            if ticks_per_sec <= 0.0 {
                return 0.0;
            }

            // Update sample and calculate delta
            let mut last_sample = self.last_cpu_sample.write().await;
            let cpu_percent = if let Some(prev_time) = last_sample.timestamp {
                let elapsed_secs = now.duration_since(prev_time).as_secs_f64();
                if elapsed_secs > 0.0 {
                    let tick_delta = current_ticks.saturating_sub(last_sample.cpu_ticks);
                    let cpu_secs = tick_delta as f64 / ticks_per_sec;
                    (cpu_secs / elapsed_secs) * 100.0
                } else {
                    0.0
                }
            } else {
                0.0 // First sample, no previous data
            };

            // Store current sample for next call
            last_sample.cpu_ticks = current_ticks;
            last_sample.timestamp = Some(now);

            cpu_percent
        }
        #[cfg(not(target_os = "linux"))]
        {
            0.0
        }
    }
}

impl Default for ApiState {
    fn default() -> Self {
        Self::new()
    }
}

/// Create API router
pub fn create_router(state: ApiState) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/info", get(info_handler))
        .route("/metrics", get(metrics_handler))
        .route("/transfers", post(create_transfer_handler))
        .route("/transfers", get(list_transfers_handler))
        .route("/transfers/{id}", get(get_transfer_handler))
        .route("/transfers/{id}", delete(cancel_transfer_handler))
        .route("/edges", get(list_edges_handler))
        .with_state(state)
}

/// Health check endpoint
#[utoipa::path(
    get,
    path = "/health",
    responses(
        (status = 200, description = "Service is healthy", body = HealthStatus)
    ),
    tag = "health"
)]
async fn health_handler() -> Json<HealthStatus> {
    let mut checks = HashMap::new();
    checks.insert("database".to_string(), "ok".to_string());
    checks.insert("storage".to_string(), "ok".to_string());
    checks.insert("network".to_string(), "ok".to_string());

    Json(HealthStatus {
        status: "healthy".to_string(),
        checks,
    })
}

/// System information endpoint
#[utoipa::path(
    get,
    path = "/info",
    responses(
        (status = 200, description = "System information", body = SystemInfo)
    ),
    tag = "system"
)]
async fn info_handler(State(state): State<ApiState>) -> Json<SystemInfo> {
    Json(SystemInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: state.uptime_seconds(),
        capabilities: SystemCapabilities {
            gpu_available: false, // Can be detected dynamically
            max_transfers: 100,
            supported_compression: vec![
                "zstd".to_string(),
                "lz4".to_string(),
                "none".to_string(),
            ],
            supported_encryption: vec!["chacha20poly1305".to_string()],
        },
    })
}

/// Metrics endpoint
#[utoipa::path(
    get,
    path = "/metrics",
    responses(
        (status = 200, description = "System metrics", body = MetricsResponse)
    ),
    tag = "metrics"
)]
async fn metrics_handler(State(state): State<ApiState>) -> Json<MetricsResponse> {
    let transfers = state.transfers.read().await;
    let active_count = transfers
        .values()
        .filter(|t| matches!(t.status, TransferStatus::InProgress))
        .count();

    Json(MetricsResponse {
        active_transfers: active_count,
        total_bytes_transferred: state.total_bytes_transferred(),
        average_throughput_mbps: state.average_throughput_mbps(),
        cpu_usage_percent: state.cpu_usage_percent().await,
        memory_usage_bytes: state.memory_usage_bytes(),
    })
}

/// Create transfer endpoint
#[utoipa::path(
    post,
    path = "/transfers",
    request_body = TransferRequest,
    responses(
        (status = 201, description = "Transfer created", body = TransferResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse)
    ),
    tag = "transfers"
)]
async fn create_transfer_handler(
    State(state): State<ApiState>,
    Json(request): Json<TransferRequest>,
) -> std::result::Result<(StatusCode, Json<TransferResponse>), ApiErrorResponse> {
    // Validate request
    if request.source.is_empty() {
        return Err(ApiError::InvalidRequest("source cannot be empty".to_string()).into());
    }
    if request.destination.is_empty() {
        return Err(ApiError::InvalidRequest("destination cannot be empty".to_string()).into());
    }

    let transfer = TransferResponse {
        id: Uuid::new_v4(),
        status: TransferStatus::Pending,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        progress: 0.0,
    };

    state
        .transfers
        .write()
        .await
        .insert(transfer.id, transfer.clone());

    Ok((StatusCode::CREATED, Json(transfer)))
}

/// List transfers endpoint
#[utoipa::path(
    get,
    path = "/transfers",
    responses(
        (status = 200, description = "List of transfers", body = TransferListResponse)
    ),
    tag = "transfers"
)]
async fn list_transfers_handler(
    State(state): State<ApiState>,
) -> Json<TransferListResponse> {
    let transfers = state.transfers.read().await;
    let transfer_list: Vec<TransferResponse> = transfers.values().cloned().collect();
    let total = transfer_list.len();

    Json(TransferListResponse {
        transfers: transfer_list,
        total,
    })
}

/// Get transfer status endpoint
#[utoipa::path(
    get,
    path = "/transfers/{id}",
    params(
        ("id" = Uuid, Path, description = "Transfer ID")
    ),
    responses(
        (status = 200, description = "Transfer details", body = TransferResponse),
        (status = 404, description = "Transfer not found", body = ErrorResponse)
    ),
    tag = "transfers"
)]
async fn get_transfer_handler(
    State(state): State<ApiState>,
    Path(id): Path<Uuid>,
) -> std::result::Result<Json<TransferResponse>, ApiErrorResponse> {
    let transfers = state.transfers.read().await;

    transfers
        .get(&id)
        .cloned()
        .map(Json)
        .ok_or_else(|| ApiError::TransferNotFound(id).into())
}

/// Cancel transfer endpoint
#[utoipa::path(
    delete,
    path = "/transfers/{id}",
    params(
        ("id" = Uuid, Path, description = "Transfer ID")
    ),
    responses(
        (status = 200, description = "Transfer cancelled", body = TransferResponse),
        (status = 404, description = "Transfer not found", body = ErrorResponse)
    ),
    tag = "transfers"
)]
async fn cancel_transfer_handler(
    State(state): State<ApiState>,
    Path(id): Path<Uuid>,
) -> std::result::Result<Json<TransferResponse>, ApiErrorResponse> {
    let mut transfers = state.transfers.write().await;

    if let Some(transfer) = transfers.get_mut(&id) {
        transfer.status = TransferStatus::Cancelled;
        Ok(Json(transfer.clone()))
    } else {
        Err(ApiError::TransferNotFound(id).into())
    }
}

/// List edge nodes endpoint
#[utoipa::path(
    get,
    path = "/edges",
    responses(
        (status = 200, description = "List of edge nodes", body = EdgeListResponse)
    ),
    tag = "edges"
)]
async fn list_edges_handler(State(state): State<ApiState>) -> Json<EdgeListResponse> {
    let edges = state.edges.read().await;
    let edge_list: Vec<EdgeInfo> = edges.values().cloned().collect();
    let total = edge_list.len();

    Json(EdgeListResponse {
        edges: edge_list,
        total,
    })
}

/// Error response wrapper for Axum
#[derive(Debug)]
pub struct ApiErrorResponse(ApiError);

impl From<ApiError> for ApiErrorResponse {
    fn from(err: ApiError) -> Self {
        Self(err)
    }
}

impl IntoResponse for ApiErrorResponse {
    fn into_response(self) -> Response {
        let (status, message) = match self.0 {
            ApiError::TransferNotFound(_) => (StatusCode::NOT_FOUND, self.0.to_string()),
            ApiError::InvalidRequest(_) => (StatusCode::BAD_REQUEST, self.0.to_string()),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, self.0.to_string()),
        };

        let body = Json(ErrorResponse {
            error: message,
            status: status.as_u16(),
        });

        (status, body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_health_handler() {
        let response = health_handler().await;
        assert_eq!(response.status, "healthy");
        assert!(response.checks.contains_key("database"));
        assert_eq!(response.checks.get("database").unwrap(), "ok");
    }

    #[tokio::test]
    async fn test_info_handler() {
        let state = ApiState::new();
        let response = info_handler(State(state)).await;
        assert_eq!(response.version, env!("CARGO_PKG_VERSION"));
        assert!(response.capabilities.supported_compression.contains(&"zstd".to_string()));
    }

    #[tokio::test]
    async fn test_metrics_handler() {
        let state = ApiState::new();
        let response = metrics_handler(State(state)).await;
        assert_eq!(response.active_transfers, 0);
    }

    #[tokio::test]
    async fn test_create_transfer_handler() {
        let state = ApiState::new();
        let request = TransferRequest {
            source: "/data/test.bin".to_string(),
            destination: "edge-01:/mnt/test.bin".to_string(),
            compress: Some("zstd".to_string()),
            encrypt: true,
        };

        let result = create_transfer_handler(State(state.clone()), Json(request))
            .await
            .unwrap();

        assert_eq!(result.0, StatusCode::CREATED);
        assert_eq!(result.1.status, TransferStatus::Pending);
        assert_eq!(result.1.progress, 0.0);

        // Verify it was stored
        let transfers = state.transfers.read().await;
        assert_eq!(transfers.len(), 1);
    }

    #[tokio::test]
    async fn test_create_transfer_empty_source() {
        let state = ApiState::new();
        let request = TransferRequest {
            source: "".to_string(),
            destination: "edge-01:/mnt/test.bin".to_string(),
            compress: None,
            encrypt: false,
        };

        let result = create_transfer_handler(State(state), Json(request)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_transfer_empty_destination() {
        let state = ApiState::new();
        let request = TransferRequest {
            source: "/data/test.bin".to_string(),
            destination: "".to_string(),
            compress: None,
            encrypt: false,
        };

        let result = create_transfer_handler(State(state), Json(request)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_list_transfers_empty() {
        let state = ApiState::new();
        let response = list_transfers_handler(State(state)).await;
        assert_eq!(response.total, 0);
        assert!(response.transfers.is_empty());
    }

    #[tokio::test]
    async fn test_list_transfers_with_data() {
        let state = ApiState::new();

        // Add some transfers
        let transfer1 = TransferResponse {
            id: Uuid::new_v4(),
            status: TransferStatus::InProgress,
            created_at: 1701234567,
            progress: 50.0,
        };

        state
            .transfers
            .write()
            .await
            .insert(transfer1.id, transfer1.clone());

        let response = list_transfers_handler(State(state)).await;
        assert_eq!(response.total, 1);
        assert_eq!(response.transfers.len(), 1);
    }

    #[tokio::test]
    async fn test_get_transfer_handler() {
        let state = ApiState::new();
        let transfer = TransferResponse {
            id: Uuid::new_v4(),
            status: TransferStatus::InProgress,
            created_at: 1701234567,
            progress: 50.0,
        };

        state
            .transfers
            .write()
            .await
            .insert(transfer.id, transfer.clone());

        let result = get_transfer_handler(State(state), Path(transfer.id))
            .await
            .unwrap();

        assert_eq!(result.id, transfer.id);
        assert_eq!(result.status, TransferStatus::InProgress);
    }

    #[tokio::test]
    async fn test_get_transfer_not_found() {
        let state = ApiState::new();
        let id = Uuid::new_v4();

        let result = get_transfer_handler(State(state), Path(id)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_cancel_transfer_handler() {
        let state = ApiState::new();
        let transfer = TransferResponse {
            id: Uuid::new_v4(),
            status: TransferStatus::InProgress,
            created_at: 1701234567,
            progress: 50.0,
        };

        state
            .transfers
            .write()
            .await
            .insert(transfer.id, transfer.clone());

        let result = cancel_transfer_handler(State(state.clone()), Path(transfer.id))
            .await
            .unwrap();

        assert_eq!(result.status, TransferStatus::Cancelled);

        // Verify it was updated
        let transfers = state.transfers.read().await;
        let updated = transfers.get(&transfer.id).unwrap();
        assert_eq!(updated.status, TransferStatus::Cancelled);
    }

    #[tokio::test]
    async fn test_cancel_transfer_not_found() {
        let state = ApiState::new();
        let id = Uuid::new_v4();

        let result = cancel_transfer_handler(State(state), Path(id)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_list_edges_empty() {
        let state = ApiState::new();
        let response = list_edges_handler(State(state)).await;
        assert_eq!(response.total, 0);
        assert!(response.edges.is_empty());
    }

    #[tokio::test]
    async fn test_list_edges_with_data() {
        let state = ApiState::new();
        let edge = EdgeInfo {
            id: "edge-01".to_string(),
            address: "192.168.1.100:5000".to_string(),
            status: "online".to_string(),
            active_transfers: 3,
            total_storage_bytes: 1_000_000_000,
            available_storage_bytes: 500_000_000,
        };

        state
            .edges
            .write()
            .await
            .insert(edge.id.clone(), edge.clone());

        let response = list_edges_handler(State(state)).await;
        assert_eq!(response.total, 1);
        assert_eq!(response.edges.len(), 1);
    }

    #[tokio::test]
    async fn test_api_state_uptime() {
        let state = ApiState::new();
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        let uptime = state.uptime_seconds();
        // Uptime is u64, so it's always non-negative
        assert!(uptime < 1000); // Should be less than 1000 seconds in test
    }

    #[tokio::test]
    async fn test_create_router() {
        let state = ApiState::new();
        let router = create_router(state);

        // Test health endpoint
        let request = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
