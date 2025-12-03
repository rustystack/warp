//! API server implementation with OpenAPI documentation

use crate::{
    create_router, ApiError, ApiState, ChunkInfo, EdgeInfo, EdgeListResponse, ErrorResponse,
    HealthStatus, MetricsResponse, Result, SystemInfo, TransferListResponse, TransferRequest,
    TransferResponse, TransferStatus,
};
use axum::Router;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

/// API server configuration
#[derive(Debug, Clone)]
pub struct ApiConfig {
    /// Host to bind to
    pub host: String,

    /// Port to bind to
    pub port: u16,

    /// Enable CORS
    pub enable_cors: bool,

    /// Enable request tracing
    pub enable_tracing: bool,

    /// Enable Swagger UI
    pub enable_swagger: bool,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 3000,
            enable_cors: true,
            enable_tracing: true,
            enable_swagger: true,
        }
    }
}

impl ApiConfig {
    /// Create new API configuration
    pub fn new(host: String, port: u16) -> Self {
        Self {
            host,
            port,
            ..Default::default()
        }
    }

    /// Get the socket address
    pub fn socket_addr(&self) -> Result<SocketAddr> {
        format!("{}:{}", self.host, self.port)
            .parse()
            .map_err(|e| ApiError::Config(format!("Invalid address: {}", e)))
    }
}

/// OpenAPI documentation
#[derive(OpenApi)]
#[openapi(
    paths(
        crate::routes::health_handler,
        crate::routes::info_handler,
        crate::routes::metrics_handler,
        crate::routes::create_transfer_handler,
        crate::routes::list_transfers_handler,
        crate::routes::get_transfer_handler,
        crate::routes::cancel_transfer_handler,
        crate::routes::list_edges_handler,
    ),
    components(
        schemas(
            TransferRequest,
            TransferResponse,
            TransferStatus,
            TransferListResponse,
            SystemInfo,
            crate::SystemCapabilities,
            HealthStatus,
            MetricsResponse,
            EdgeInfo,
            EdgeListResponse,
            ChunkInfo,
            ErrorResponse,
        )
    ),
    tags(
        (name = "health", description = "Health check endpoints"),
        (name = "system", description = "System information endpoints"),
        (name = "metrics", description = "Metrics endpoints"),
        (name = "transfers", description = "Transfer management endpoints"),
        (name = "edges", description = "Edge node endpoints"),
    ),
    info(
        title = "Warp API",
        version = "0.1.0",
        description = "REST API for Warp distributed file transfer system",
        license(name = "MIT OR Apache-2.0"),
    )
)]
pub struct ApiDoc;

/// API server
pub struct ApiServer {
    /// Configuration
    config: ApiConfig,

    /// Shared state
    state: ApiState,

    /// Shutdown signal
    shutdown: Arc<Notify>,
}

impl ApiServer {
    /// Create new API server
    pub fn new(config: ApiConfig) -> Self {
        Self {
            config,
            state: ApiState::new(),
            shutdown: Arc::new(Notify::new()),
        }
    }

    /// Create with custom state
    pub fn with_state(config: ApiConfig, state: ApiState) -> Self {
        Self {
            config,
            state,
            shutdown: Arc::new(Notify::new()),
        }
    }

    /// Get the server configuration
    pub fn config(&self) -> &ApiConfig {
        &self.config
    }

    /// Get the server state
    pub fn state(&self) -> &ApiState {
        &self.state
    }

    /// Get OpenAPI specification as JSON
    pub fn openapi_spec(&self) -> String {
        serde_json::to_string_pretty(&ApiDoc::openapi()).unwrap_or_default()
    }

    /// Build the router with all middleware
    fn build_router(&self) -> Router {
        let mut router = create_router(self.state.clone());

        // Add Swagger UI if enabled
        if self.config.enable_swagger {
            router = router.merge(SwaggerUi::new("/swagger-ui").url("/openapi.json", ApiDoc::openapi()));
        }

        // Add CORS if enabled
        if self.config.enable_cors {
            let cors = CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any);
            router = router.layer(cors);
        }

        // Add tracing if enabled
        if self.config.enable_tracing {
            router = router.layer(TraceLayer::new_for_http());
        }

        router
    }

    /// Start the API server
    pub async fn start(&self) -> Result<()> {
        let addr = self.config.socket_addr()?;
        let router = self.build_router();

        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| ApiError::Bind {
                address: addr.to_string(),
                source: e,
            })?;

        tracing::info!("API server listening on {}", addr);

        let shutdown = self.shutdown.clone();
        axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                shutdown.notified().await;
            })
            .await
            .map_err(|e| ApiError::Server(e.to_string()))?;

        Ok(())
    }

    /// Shutdown the API server
    pub async fn shutdown(&self) {
        tracing::info!("Shutting down API server");
        self.shutdown.notify_one();
    }

    /// Run the server until shutdown
    pub async fn run(&self) -> Result<()> {
        self.start().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_config_default() {
        let config = ApiConfig::default();
        assert_eq!(config.host, "127.0.0.1");
        assert_eq!(config.port, 3000);
        assert!(config.enable_cors);
        assert!(config.enable_tracing);
        assert!(config.enable_swagger);
    }

    #[test]
    fn test_api_config_new() {
        let config = ApiConfig::new("0.0.0.0".to_string(), 8080);
        assert_eq!(config.host, "0.0.0.0");
        assert_eq!(config.port, 8080);
    }

    #[test]
    fn test_api_config_socket_addr() {
        let config = ApiConfig::new("127.0.0.1".to_string(), 3000);
        let addr = config.socket_addr().unwrap();
        assert_eq!(addr.to_string(), "127.0.0.1:3000");
    }

    #[test]
    fn test_api_config_invalid_host() {
        let config = ApiConfig::new("invalid_host".to_string(), 3000);
        let result = config.socket_addr();
        assert!(result.is_err());
    }

    #[test]
    fn test_api_server_new() {
        let config = ApiConfig::default();
        let server = ApiServer::new(config.clone());
        assert_eq!(server.config().host, config.host);
        assert_eq!(server.config().port, config.port);
    }

    #[test]
    fn test_api_server_with_state() {
        let config = ApiConfig::default();
        let state = ApiState::new();
        let server = ApiServer::with_state(config, state);
        assert_eq!(server.config().port, 3000);
    }

    #[test]
    fn test_api_server_openapi_spec() {
        let config = ApiConfig::default();
        let server = ApiServer::new(config);
        let spec = server.openapi_spec();

        assert!(!spec.is_empty());
        // Note: serde_json::to_string_pretty adds space after colon
        assert!(spec.contains("\"title\": \"Warp API\""));
        assert!(spec.contains("\"version\": \"0.1.0\""));
    }

    #[test]
    fn test_openapi_spec_contains_paths() {
        let spec = serde_json::to_string_pretty(&ApiDoc::openapi()).unwrap();

        assert!(spec.contains("/health"));
        assert!(spec.contains("/info"));
        assert!(spec.contains("/metrics"));
        assert!(spec.contains("/transfers"));
        assert!(spec.contains("/edges"));
    }

    #[test]
    fn test_openapi_spec_contains_schemas() {
        let spec = serde_json::to_string_pretty(&ApiDoc::openapi()).unwrap();

        assert!(spec.contains("TransferRequest"));
        assert!(spec.contains("TransferResponse"));
        assert!(spec.contains("TransferStatus"));
        assert!(spec.contains("SystemInfo"));
        assert!(spec.contains("HealthStatus"));
        assert!(spec.contains("MetricsResponse"));
        assert!(spec.contains("EdgeInfo"));
    }

    #[tokio::test]
    async fn test_api_server_build_router() {
        let config = ApiConfig::default();
        let server = ApiServer::new(config);
        let router = server.build_router();

        // Router should be created without panicking
        assert!(format!("{:?}", router).contains("Router"));
    }

    #[tokio::test]
    async fn test_api_server_build_router_no_cors() {
        let mut config = ApiConfig::default();
        config.enable_cors = false;
        let server = ApiServer::new(config);
        let router = server.build_router();

        assert!(format!("{:?}", router).contains("Router"));
    }

    #[tokio::test]
    async fn test_api_server_build_router_no_tracing() {
        let mut config = ApiConfig::default();
        config.enable_tracing = false;
        let server = ApiServer::new(config);
        let router = server.build_router();

        assert!(format!("{:?}", router).contains("Router"));
    }

    #[tokio::test]
    async fn test_api_server_build_router_no_swagger() {
        let mut config = ApiConfig::default();
        config.enable_swagger = false;
        let server = ApiServer::new(config);
        let router = server.build_router();

        assert!(format!("{:?}", router).contains("Router"));
    }

    #[tokio::test]
    async fn test_api_server_shutdown_signal() {
        let config = ApiConfig::default();
        let server = ApiServer::new(config);

        // Spawn a task to shutdown after a delay
        let server_clone = ApiServer::with_state(server.config().clone(), server.state().clone());
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            server_clone.shutdown().await;
        });

        // Wait for shutdown notification
        server.shutdown.notified().await;
    }

    #[test]
    fn test_api_doc_openapi() {
        let openapi = ApiDoc::openapi();

        assert_eq!(openapi.info.title, "Warp API");
        assert_eq!(openapi.info.version, "0.1.0");
    }

    #[test]
    fn test_config_clone() {
        let config = ApiConfig::default();
        let cloned = config.clone();

        assert_eq!(config.host, cloned.host);
        assert_eq!(config.port, cloned.port);
    }

    #[test]
    fn test_config_debug() {
        let config = ApiConfig::default();
        let debug_str = format!("{:?}", config);

        assert!(debug_str.contains("ApiConfig"));
        assert!(debug_str.contains("127.0.0.1"));
    }
}
