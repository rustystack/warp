//! Portal Hub server implementation
//!
//! This module provides the Axum-based HTTP server for Portal Hub.
//! It sets up routes, middleware, and server lifecycle management.

use crate::{routes, storage::HubStorage};
use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{get, post, put},
};
use std::{net::SocketAddr, sync::Arc};
use tower::ServiceBuilder;
use tower_http::{
    cors::CorsLayer,
    trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer},
};
use tracing::Level;

/// Hub server configuration
#[derive(Debug, Clone)]
pub struct HubConfig {
    /// Address to bind the server to
    pub bind_addr: SocketAddr,
    /// Maximum chunk size in bytes (default 4MB)
    pub max_chunk_size: usize,
}

impl Default for HubConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:8080".parse().unwrap(),
            max_chunk_size: 4 * 1024 * 1024, // 4MB
        }
    }
}

/// Portal Hub server
pub struct HubServer {
    storage: Arc<HubStorage>,
    config: HubConfig,
}

impl HubServer {
    /// Create a new Hub server with the given configuration
    #[must_use]
    pub fn new(config: HubConfig) -> Self {
        Self {
            storage: Arc::new(HubStorage::new()),
            config,
        }
    }

    /// Create a Hub server with custom storage
    #[must_use]
    pub const fn with_storage(config: HubConfig, storage: Arc<HubStorage>) -> Self {
        Self { storage, config }
    }

    /// Run the server
    ///
    /// # Errors
    ///
    /// Returns an error if the server fails to bind or encounters a runtime error
    pub async fn run(self) -> crate::Result<()> {
        let app = Self::router(self.storage.clone(), self.config.max_chunk_size);

        tracing::info!("Starting Hub server on {}", self.config.bind_addr);

        let listener = tokio::net::TcpListener::bind(self.config.bind_addr)
            .await
            .map_err(crate::Error::Io)?;

        axum::serve(listener, app).await.map_err(crate::Error::Io)?;

        Ok(())
    }

    /// Create the router with all routes configured
    ///
    /// This is exposed for testing purposes
    pub fn router(storage: Arc<HubStorage>, max_chunk_size: usize) -> Router {
        // API routes
        let api_routes = Router::new()
            // Edge registration (unauthenticated)
            .route("/edges/register", post(routes::register_edge))
            // Portal management
            .route("/portals", post(routes::create_portal))
            .route("/portals/{id}", get(routes::get_portal))
            .route("/portals/{id}", put(routes::update_portal))
            // Manifest management
            .route("/portals/{id}/manifest", post(routes::upload_manifest))
            .route("/portals/{id}/manifest", get(routes::get_manifest))
            // Chunk management
            .route("/chunks/{content_id}", post(routes::upload_chunk))
            .route("/chunks/{content_id}", get(routes::get_chunk))
            .route("/chunks/check", post(routes::check_chunks))
            .with_state(storage);

        // Main router with middleware
        Router::new().nest("/api/v1", api_routes).layer(
            ServiceBuilder::new()
                // Request tracing
                .layer(
                    TraceLayer::new_for_http()
                        .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                        .on_response(DefaultOnResponse::new().level(Level::INFO)),
                )
                // CORS
                .layer(CorsLayer::permissive())
                // Body size limit
                .layer(DefaultBodyLimit::max(max_chunk_size)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        auth::{AuthToken, serialize_auth_token},
        routes::{CreatePortalRequest, RegisterEdgeRequest},
        storage::StoredPortal,
    };
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode, header},
    };
    use ed25519_dalek::SigningKey;
    use portal_core::{AccessControlList, Portal};
    use rand::rngs::OsRng;
    use tower::ServiceExt; // for `oneshot`
    use uuid::Uuid;

    fn create_test_signing_key() -> (SigningKey, ed25519_dalek::VerifyingKey) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    #[test]
    fn test_hub_config_default() {
        let config = HubConfig::default();
        assert_eq!(config.bind_addr.port(), 8080);
        assert_eq!(config.max_chunk_size, 4 * 1024 * 1024);
    }

    #[test]
    fn test_hub_server_new() {
        let config = HubConfig::default();
        let server = HubServer::new(config);
        assert_eq!(server.config.max_chunk_size, 4 * 1024 * 1024);
    }

    #[test]
    fn test_hub_server_with_storage() {
        let config = HubConfig::default();
        let storage = Arc::new(HubStorage::new());

        // Add some test data
        let (_, verifying_key) = create_test_signing_key();
        storage
            .register_edge(Uuid::new_v4(), verifying_key, "Test Edge".to_string())
            .unwrap();

        let server = HubServer::with_storage(config, storage.clone());
        assert_eq!(server.storage.list_edges().len(), 1);
    }

    #[tokio::test]
    async fn test_register_edge_endpoint() {
        let storage = Arc::new(HubStorage::new());
        let app = HubServer::router(storage.clone(), 4 * 1024 * 1024);

        let (_, verifying_key) = create_test_signing_key();
        let request_body = RegisterEdgeRequest {
            name: "Test Edge".to_string(),
            public_key: hex::encode(verifying_key.to_bytes()),
        };

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/edges/register")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let response_data: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(response_data["edge"]["name"], "Test Edge");
    }

    #[tokio::test]
    async fn test_create_portal_requires_auth() {
        let storage = Arc::new(HubStorage::new());
        let app = HubServer::router(storage.clone(), 4 * 1024 * 1024);

        let (_, verifying_key) = create_test_signing_key();
        let request_body = CreatePortalRequest {
            name: "Test Portal".to_string(),
            owner_key: hex::encode(verifying_key.to_bytes()),
        };

        // Request without auth should fail
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/portals")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_create_portal_with_auth() {
        let storage = Arc::new(HubStorage::new());
        let app = HubServer::router(storage.clone(), 4 * 1024 * 1024);

        let (signing_key, verifying_key) = create_test_signing_key();
        let edge_id = Uuid::new_v4();

        // Register edge
        storage
            .register_edge(edge_id, verifying_key, "Test Edge".to_string())
            .unwrap();

        // Create auth token
        let token = AuthToken::new(edge_id, &signing_key);
        let auth_header = serialize_auth_token(&token).unwrap();

        let request_body = CreatePortalRequest {
            name: "Test Portal".to_string(),
            owner_key: hex::encode(verifying_key.to_bytes()),
        };

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/portals")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, auth_header)
                    .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let response_data: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(response_data["portal"]["name"], "Test Portal");
    }

    #[tokio::test]
    async fn test_get_portal() {
        let storage = Arc::new(HubStorage::new());
        let app = HubServer::router(storage.clone(), 4 * 1024 * 1024);

        let (signing_key, verifying_key) = create_test_signing_key();
        let edge_id = Uuid::new_v4();

        // Register edge
        storage
            .register_edge(edge_id, verifying_key, "Test Edge".to_string())
            .unwrap();

        // Create portal
        let portal = Portal::new("Test Portal".to_string(), verifying_key);
        let portal_id = portal.id;
        storage
            .store_portal(StoredPortal::new(
                portal,
                AccessControlList::new(),
                verifying_key,
            ))
            .unwrap();

        // Create auth token
        let token = AuthToken::new(edge_id, &signing_key);
        let auth_header = serialize_auth_token(&token).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/api/v1/portals/{portal_id}"))
                    .header(header::AUTHORIZATION, auth_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let response_data: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(response_data["portal"]["name"], "Test Portal");
    }

    #[tokio::test]
    async fn test_portal_not_found() {
        let storage = Arc::new(HubStorage::new());
        let app = HubServer::router(storage.clone(), 4 * 1024 * 1024);

        let (signing_key, verifying_key) = create_test_signing_key();
        let edge_id = Uuid::new_v4();

        // Register edge
        storage
            .register_edge(edge_id, verifying_key, "Test Edge".to_string())
            .unwrap();

        let token = AuthToken::new(edge_id, &signing_key);
        let auth_header = serialize_auth_token(&token).unwrap();

        let portal_id = Uuid::new_v4(); // Non-existent portal

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/api/v1/portals/{portal_id}"))
                    .header(header::AUTHORIZATION, auth_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_upload_download_chunk() {
        let storage = Arc::new(HubStorage::new());
        let app_upload = HubServer::router(storage.clone(), 4 * 1024 * 1024);
        let app_download = HubServer::router(storage.clone(), 4 * 1024 * 1024);

        let (signing_key, verifying_key) = create_test_signing_key();
        let edge_id = Uuid::new_v4();

        // Register edge
        storage
            .register_edge(edge_id, verifying_key, "Test Edge".to_string())
            .unwrap();

        let token = AuthToken::new(edge_id, &signing_key);
        let auth_header = serialize_auth_token(&token).unwrap();

        let content_id = [42u8; 32];
        let content_id_hex = hex::encode(content_id);
        let chunk_data = b"test chunk data";

        // Upload chunk
        let upload_response = app_upload
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/chunks/{content_id_hex}"))
                    .header(header::AUTHORIZATION, auth_header.clone())
                    .body(Body::from(chunk_data.as_slice()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(upload_response.status(), StatusCode::CREATED);

        // Download chunk
        let download_response = app_download
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/api/v1/chunks/{content_id_hex}"))
                    .header(header::AUTHORIZATION, auth_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(download_response.status(), StatusCode::OK);

        let body = to_bytes(download_response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body.as_ref(), chunk_data);
    }

    #[tokio::test]
    async fn test_upload_download_manifest() {
        let storage = Arc::new(HubStorage::new());
        let app_upload = HubServer::router(storage.clone(), 4 * 1024 * 1024);
        let app_download = HubServer::router(storage.clone(), 4 * 1024 * 1024);

        let (signing_key, verifying_key) = create_test_signing_key();
        let edge_id = Uuid::new_v4();

        // Register edge
        storage
            .register_edge(edge_id, verifying_key, "Test Edge".to_string())
            .unwrap();

        // Create portal owned by edge
        let portal = Portal::new("Test Portal".to_string(), verifying_key);
        let portal_id = portal.id;
        storage
            .store_portal(StoredPortal::new(
                portal,
                AccessControlList::new(),
                verifying_key,
            ))
            .unwrap();

        let token = AuthToken::new(edge_id, &signing_key);
        let auth_header = serialize_auth_token(&token).unwrap();

        let manifest_data = b"encrypted manifest data";

        // Upload manifest
        let upload_response = app_upload
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/portals/{portal_id}/manifest"))
                    .header(header::AUTHORIZATION, auth_header.clone())
                    .body(Body::from(manifest_data.as_slice()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(upload_response.status(), StatusCode::CREATED);

        // Download manifest
        let download_response = app_download
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/api/v1/portals/{portal_id}/manifest"))
                    .header(header::AUTHORIZATION, auth_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(download_response.status(), StatusCode::OK);

        let body = to_bytes(download_response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body.as_ref(), manifest_data);
    }

    #[tokio::test]
    async fn test_chunk_size_limit() {
        let max_size = 1024; // 1KB limit for test
        let storage = Arc::new(HubStorage::new());
        let app = HubServer::router(storage.clone(), max_size);

        let (signing_key, verifying_key) = create_test_signing_key();
        let edge_id = Uuid::new_v4();

        storage
            .register_edge(edge_id, verifying_key, "Test Edge".to_string())
            .unwrap();

        let token = AuthToken::new(edge_id, &signing_key);
        let auth_header = serialize_auth_token(&token).unwrap();

        let content_id_hex = hex::encode([1u8; 32]);
        let large_data = vec![0u8; max_size + 1]; // Exceeds limit

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/chunks/{content_id_hex}"))
                    .header(header::AUTHORIZATION, auth_header)
                    .body(Body::from(large_data))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn test_check_chunks_endpoint() {
        let storage = Arc::new(HubStorage::new());
        let app = HubServer::router(storage.clone(), 4 * 1024 * 1024);

        let (signing_key, verifying_key) = create_test_signing_key();
        let edge_id = Uuid::new_v4();

        storage
            .register_edge(edge_id, verifying_key, "Test Edge".to_string())
            .unwrap();

        // Store some chunks
        let cid1 = [1u8; 32];
        let cid2 = [2u8; 32];
        storage.store_chunk(cid1, &[1, 2, 3]);

        let token = AuthToken::new(edge_id, &signing_key);
        let auth_header = serialize_auth_token(&token).unwrap();

        let request_body = serde_json::json!({
            "content_ids": [hex::encode(cid1), hex::encode(cid2)]
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/chunks/check")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, auth_header)
                    .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let response_data: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let existing = response_data["existing"].as_array().unwrap();
        assert_eq!(existing.len(), 1);
        assert_eq!(existing[0], hex::encode(cid1));
    }
}
