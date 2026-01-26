//! API route handlers for Portal Hub
//!
//! This module implements all HTTP API endpoints:
//! - Edge registration
//! - Portal CRUD operations
//! - Chunk upload/download
//! - Manifest upload/download
//! - Chunk existence checking

use crate::{
    Error, Result,
    auth::AuthenticatedEdge,
    storage::{EdgeInfo, HubStorage, StoredPortal},
};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use ed25519_dalek::VerifyingKey;
use portal_core::{AccessControlList, ContentId, Portal};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

// ========== Request/Response Types ==========

/// Request to register a new edge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterEdgeRequest {
    /// Edge name
    pub name: String,
    /// Edge's public key (hex encoded)
    pub public_key: String,
}

/// Response from edge registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterEdgeResponse {
    /// Assigned edge ID
    pub edge_id: Uuid,
    /// Authentication token for subsequent requests
    pub auth_token: String,
    /// Edge information
    pub edge: EdgeInfoResponse,
}

/// Edge information response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeInfoResponse {
    /// Edge ID
    pub id: Uuid,
    /// Edge name
    pub name: String,
    /// Public key (hex encoded)
    pub public_key: String,
    /// Last seen timestamp
    pub last_seen: String,
}

impl From<EdgeInfo> for EdgeInfoResponse {
    fn from(edge: EdgeInfo) -> Self {
        Self {
            id: edge.id,
            name: edge.name,
            public_key: hex::encode(edge.public_key.to_bytes()),
            last_seen: edge.last_seen.to_rfc3339(),
        }
    }
}

/// Request to create a portal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePortalRequest {
    /// Portal name
    pub name: String,
    /// Owner's public key (hex encoded)
    pub owner_key: String,
}

/// Portal response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortalResponse {
    /// Portal metadata (serialized as JSON)
    pub portal: serde_json::Value,
    /// Owner's public key (hex encoded)
    pub owner_key: String,
}

/// Request to update a portal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatePortalRequest {
    /// Updated portal (serialized as JSON)
    pub portal: serde_json::Value,
}

/// Chunk check request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkCheckRequest {
    /// List of content IDs to check (hex encoded)
    pub content_ids: Vec<String>,
}

/// Chunk check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkCheckResponse {
    /// Content IDs that exist (hex encoded)
    pub existing: Vec<String>,
}

/// Upload chunk request (content ID in path, body is raw bytes)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadChunkRequest {
    /// Content ID (hex encoded)
    pub content_id: String,
}

// ========== Route Handlers ==========

/// POST /api/v1/edges/register - Register a new edge
///
/// This is the only unauthenticated endpoint. It registers a new edge device
/// and returns an authentication token for subsequent requests.
///
/// # Errors
///
/// Returns an error if the public key is invalid or edge registration fails
pub async fn register_edge(
    State(storage): State<Arc<HubStorage>>,
    Json(req): Json<RegisterEdgeRequest>,
) -> Result<Json<RegisterEdgeResponse>> {
    // Parse public key from hex
    let public_key = parse_public_key(&req.public_key)?;

    // Generate new edge ID
    let edge_id = Uuid::new_v4();

    // Register edge
    let edge = storage.register_edge(edge_id, public_key, req.name)?;

    // Create authentication token (for demo, we need the signing key)
    // In production, the edge would create and sign the token itself
    // For now, we'll return edge info and let client create token
    let edge_response = EdgeInfoResponse::from(edge);

    Ok(Json(RegisterEdgeResponse {
        edge_id,
        auth_token: String::new(), // Client creates their own token
        edge: edge_response,
    }))
}

/// POST /api/v1/portals - Create a new portal
///
/// # Errors
///
/// Returns an error if the owner key is invalid or portal storage fails
pub async fn create_portal(
    State(storage): State<Arc<HubStorage>>,
    _auth: AuthenticatedEdge,
    Json(req): Json<CreatePortalRequest>,
) -> Result<Json<PortalResponse>> {
    // Parse owner key
    let owner_key = parse_public_key(&req.owner_key)?;

    // Create portal
    let portal = Portal::new(req.name, owner_key);
    let acl = AccessControlList::new();

    // Store portal
    let stored_portal = StoredPortal::new(portal.clone(), acl, owner_key);
    storage.store_portal(stored_portal)?;

    // Serialize portal to JSON
    let portal_json =
        serde_json::to_value(&portal).map_err(|e| Error::Serialization(e.to_string()))?;

    Ok(Json(PortalResponse {
        portal: portal_json,
        owner_key: hex::encode(owner_key.to_bytes()),
    }))
}

/// GET /api/v1/portals/:id - Get portal metadata
///
/// # Errors
///
/// Returns an error if the portal is not found or serialization fails
pub async fn get_portal(
    State(storage): State<Arc<HubStorage>>,
    _auth: AuthenticatedEdge,
    Path(portal_id): Path<Uuid>,
) -> Result<Json<PortalResponse>> {
    let stored_portal = storage.get_portal(&portal_id)?;

    let portal_json = serde_json::to_value(&stored_portal.portal)
        .map_err(|e| Error::Serialization(e.to_string()))?;

    Ok(Json(PortalResponse {
        portal: portal_json,
        owner_key: hex::encode(stored_portal.owner_key.to_bytes()),
    }))
}

/// PUT /api/v1/portals/:id - Update portal
///
/// # Errors
///
/// Returns an error if the portal is not found, authentication fails, or storage operation fails
pub async fn update_portal(
    State(storage): State<Arc<HubStorage>>,
    auth: AuthenticatedEdge,
    Path(portal_id): Path<Uuid>,
    Json(req): Json<UpdatePortalRequest>,
) -> Result<Json<PortalResponse>> {
    // Get existing portal
    let stored_portal = storage.get_portal(&portal_id)?;

    // Verify ownership (only owner can update)
    if stored_portal.owner_key != auth.public_key {
        return Err(Error::AuthFailed);
    }

    // Deserialize updated portal
    let updated_portal: Portal =
        serde_json::from_value(req.portal).map_err(|e| Error::Serialization(e.to_string()))?;

    // Ensure portal ID hasn't changed
    if updated_portal.id != portal_id {
        return Err(Error::Storage("Portal ID mismatch".into()));
    }

    // Update storage
    let updated_stored = StoredPortal::new(
        updated_portal.clone(),
        stored_portal.acl,
        stored_portal.owner_key,
    );
    storage.update_portal(&portal_id, updated_stored)?;

    let portal_json =
        serde_json::to_value(&updated_portal).map_err(|e| Error::Serialization(e.to_string()))?;

    Ok(Json(PortalResponse {
        portal: portal_json,
        owner_key: hex::encode(auth.public_key.to_bytes()),
    }))
}

/// POST /api/v1/portals/:id/manifest - Upload encrypted manifest
///
/// # Errors
///
/// Returns an error if the portal is not found or authentication fails
pub async fn upload_manifest(
    State(storage): State<Arc<HubStorage>>,
    auth: AuthenticatedEdge,
    Path(portal_id): Path<Uuid>,
    body: Bytes,
) -> Result<StatusCode> {
    // Verify portal exists and user has access
    let stored_portal = storage.get_portal(&portal_id)?;

    // Verify ownership (only owner can upload manifest)
    if stored_portal.owner_key != auth.public_key {
        return Err(Error::AuthFailed);
    }

    // Store encrypted manifest
    storage.store_manifest(portal_id, &body);

    Ok(StatusCode::CREATED)
}

/// GET /api/v1/portals/:id/manifest - Download encrypted manifest
///
/// # Errors
///
/// Returns an error if the portal or manifest is not found
pub async fn get_manifest(
    State(storage): State<Arc<HubStorage>>,
    _auth: AuthenticatedEdge,
    Path(portal_id): Path<Uuid>,
) -> Result<Bytes> {
    // Verify portal exists
    let _ = storage.get_portal(&portal_id)?;

    // Get manifest
    let manifest = storage.get_manifest(&portal_id)?;

    Ok(Bytes::from(manifest))
}

/// POST /api/v1/chunks - Upload encrypted chunk
///
/// # Errors
///
/// Returns an error if the content ID is invalid
pub async fn upload_chunk(
    State(storage): State<Arc<HubStorage>>,
    _auth: AuthenticatedEdge,
    Path(content_id_hex): Path<String>,
    body: Bytes,
) -> Result<StatusCode> {
    // Parse content ID from hex
    let content_id = parse_content_id(&content_id_hex)?;

    // Store chunk
    storage.store_chunk(content_id, &body);

    Ok(StatusCode::CREATED)
}

/// GET /api/v1/chunks/:cid - Download encrypted chunk
///
/// # Errors
///
/// Returns an error if the content ID is invalid or chunk is not found
pub async fn get_chunk(
    State(storage): State<Arc<HubStorage>>,
    _auth: AuthenticatedEdge,
    Path(content_id_hex): Path<String>,
) -> Result<Bytes> {
    // Parse content ID from hex
    let content_id = parse_content_id(&content_id_hex)?;

    // Get chunk
    let chunk = storage.get_chunk(&content_id)?;

    Ok(Bytes::from(chunk))
}

/// POST /api/v1/chunks/check - Check which chunks exist
///
/// # Errors
///
/// Returns an error if any content ID is invalid
pub async fn check_chunks(
    State(storage): State<Arc<HubStorage>>,
    _auth: AuthenticatedEdge,
    Json(req): Json<ChunkCheckRequest>,
) -> Result<Json<ChunkCheckResponse>> {
    // Parse all content IDs
    let content_ids: Result<Vec<ContentId>> = req
        .content_ids
        .iter()
        .map(|hex| parse_content_id(hex))
        .collect();
    let content_ids = content_ids?;

    // Check which ones exist
    let existing = storage.check_chunks(&content_ids);

    // Convert back to hex
    let existing_hex: Vec<String> = existing.iter().map(hex::encode).collect();

    Ok(Json(ChunkCheckResponse {
        existing: existing_hex,
    }))
}

// ========== Helper Functions ==========

/// Parse hex-encoded public key
fn parse_public_key(hex: &str) -> Result<VerifyingKey> {
    let bytes =
        hex::decode(hex).map_err(|_| Error::Serialization("Invalid hex encoding".into()))?;

    if bytes.len() != 32 {
        return Err(Error::Serialization(format!(
            "Invalid public key length: expected 32, got {}",
            bytes.len()
        )));
    }

    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);

    VerifyingKey::from_bytes(&array)
        .map_err(|e| Error::Serialization(format!("Invalid public key: {e}")))
}

/// Parse hex-encoded content ID
fn parse_content_id(hex: &str) -> Result<ContentId> {
    let bytes =
        hex::decode(hex).map_err(|_| Error::Serialization("Invalid hex encoding".into()))?;

    if bytes.len() != 32 {
        return Err(Error::InvalidContentId);
    }

    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);

    Ok(array)
}

/// Error response wrapper
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::PortalNotFound(_)
            | Self::ChunkNotFound(_)
            | Self::EdgeNotFound(_)
            | Self::ManifestNotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            Self::AuthFailed | Self::InvalidSignature => {
                (StatusCode::UNAUTHORIZED, self.to_string())
            }
            Self::InvalidContentId | Self::Serialization(_) => {
                (StatusCode::BAD_REQUEST, self.to_string())
            }
            Self::ChunkTooLarge(_, _) => (StatusCode::PAYLOAD_TOO_LARGE, self.to_string()),
            Self::InvalidEdgeName(_) | Self::InvalidPortalName(_) => {
                (StatusCode::BAD_REQUEST, self.to_string())
            }
            _ => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };

        (status, message).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn create_test_signing_key() -> (SigningKey, VerifyingKey) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    #[test]
    fn test_parse_public_key_valid() {
        let (_, verifying_key) = create_test_signing_key();
        let hex = hex::encode(verifying_key.to_bytes());
        let parsed = parse_public_key(&hex).unwrap();
        assert_eq!(parsed, verifying_key);
    }

    #[test]
    fn test_parse_public_key_invalid_hex() {
        let result = parse_public_key("invalid-hex");
        assert!(matches!(result, Err(Error::Serialization(_))));
    }

    #[test]
    fn test_parse_public_key_wrong_length() {
        let hex = hex::encode(&[0u8; 16]); // Too short
        let result = parse_public_key(&hex);
        assert!(matches!(result, Err(Error::Serialization(_))));
    }

    #[test]
    fn test_parse_content_id_valid() {
        let content_id = [42u8; 32];
        let hex = hex::encode(content_id);
        let parsed = parse_content_id(&hex).unwrap();
        assert_eq!(parsed, content_id);
    }

    #[test]
    fn test_parse_content_id_invalid_hex() {
        let result = parse_content_id("not-hex");
        assert!(matches!(result, Err(Error::Serialization(_))));
    }

    #[test]
    fn test_parse_content_id_wrong_length() {
        let hex = hex::encode(&[0u8; 16]); // Too short
        let result = parse_content_id(&hex);
        assert!(matches!(result, Err(Error::InvalidContentId)));
    }

    #[tokio::test]
    async fn test_register_edge() {
        let storage = Arc::new(HubStorage::new());
        let (_, verifying_key) = create_test_signing_key();

        let req = RegisterEdgeRequest {
            name: "Test Edge".to_string(),
            public_key: hex::encode(verifying_key.to_bytes()),
        };

        let response = register_edge(State(storage.clone()), Json(req))
            .await
            .unwrap();

        assert_eq!(response.edge.name, "Test Edge");
        assert!(storage.get_edge(&response.edge_id).is_ok());
    }

    #[tokio::test]
    async fn test_create_portal() {
        let storage = Arc::new(HubStorage::new());
        let (_signing_key, verifying_key) = create_test_signing_key();
        let edge_id = Uuid::new_v4();

        // Register edge first
        storage
            .register_edge(edge_id, verifying_key, "Test Edge".to_string())
            .unwrap();

        let auth = AuthenticatedEdge {
            edge_id,
            public_key: verifying_key,
        };

        let req = CreatePortalRequest {
            name: "Test Portal".to_string(),
            owner_key: hex::encode(verifying_key.to_bytes()),
        };

        let response = create_portal(State(storage.clone()), auth, Json(req))
            .await
            .unwrap();

        assert!(response.portal.get("id").is_some());
        assert_eq!(
            response.portal.get("name").and_then(|v| v.as_str()),
            Some("Test Portal")
        );
    }

    #[tokio::test]
    async fn test_get_portal() {
        let storage = Arc::new(HubStorage::new());
        let (_, verifying_key) = create_test_signing_key();
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

        let auth = AuthenticatedEdge {
            edge_id,
            public_key: verifying_key,
        };

        let response = get_portal(State(storage), auth, Path(portal_id))
            .await
            .unwrap();

        assert_eq!(
            response.portal.get("name").and_then(|v| v.as_str()),
            Some("Test Portal")
        );
    }

    #[tokio::test]
    async fn test_get_portal_not_found() {
        let storage = Arc::new(HubStorage::new());
        let (_, verifying_key) = create_test_signing_key();
        let edge_id = Uuid::new_v4();

        storage
            .register_edge(edge_id, verifying_key, "Test Edge".to_string())
            .unwrap();

        let auth = AuthenticatedEdge {
            edge_id,
            public_key: verifying_key,
        };

        let portal_id = Uuid::new_v4();
        let result = get_portal(State(storage), auth, Path(portal_id)).await;

        assert!(matches!(result, Err(Error::PortalNotFound(_))));
    }

    #[tokio::test]
    async fn test_upload_download_chunk() {
        let storage = Arc::new(HubStorage::new());
        let (_, verifying_key) = create_test_signing_key();
        let edge_id = Uuid::new_v4();

        storage
            .register_edge(edge_id, verifying_key, "Test Edge".to_string())
            .unwrap();

        let auth = AuthenticatedEdge {
            edge_id,
            public_key: verifying_key,
        };

        let content_id = [42u8; 32];
        let content_id_hex = hex::encode(content_id);
        let data = Bytes::from_static(b"test chunk data");

        // Upload
        let status = upload_chunk(
            State(storage.clone()),
            auth.clone(),
            Path(content_id_hex.clone()),
            data.clone(),
        )
        .await
        .unwrap();
        assert_eq!(status, StatusCode::CREATED);

        // Download
        let retrieved = get_chunk(State(storage), auth, Path(content_id_hex))
            .await
            .unwrap();
        assert_eq!(retrieved, data);
    }

    #[tokio::test]
    async fn test_upload_download_manifest() {
        let storage = Arc::new(HubStorage::new());
        let (_, verifying_key) = create_test_signing_key();
        let edge_id = Uuid::new_v4();

        storage
            .register_edge(edge_id, verifying_key, "Test Edge".to_string())
            .unwrap();

        // Create portal owned by this edge
        let portal = Portal::new("Test Portal".to_string(), verifying_key);
        let portal_id = portal.id;
        storage
            .store_portal(StoredPortal::new(
                portal,
                AccessControlList::new(),
                verifying_key,
            ))
            .unwrap();

        let auth = AuthenticatedEdge {
            edge_id,
            public_key: verifying_key,
        };

        let manifest_data = Bytes::from_static(b"encrypted manifest data");

        // Upload
        let status = upload_manifest(
            State(storage.clone()),
            auth.clone(),
            Path(portal_id),
            manifest_data.clone(),
        )
        .await
        .unwrap();
        assert_eq!(status, StatusCode::CREATED);

        // Download
        let retrieved = get_manifest(State(storage), auth, Path(portal_id))
            .await
            .unwrap();
        assert_eq!(retrieved, manifest_data);
    }

    #[tokio::test]
    async fn test_check_chunks() {
        let storage = Arc::new(HubStorage::new());
        let (_, verifying_key) = create_test_signing_key();
        let edge_id = Uuid::new_v4();

        storage
            .register_edge(edge_id, verifying_key, "Test Edge".to_string())
            .unwrap();

        let auth = AuthenticatedEdge {
            edge_id,
            public_key: verifying_key,
        };

        // Store some chunks
        let cid1 = [1u8; 32];
        let cid2 = [2u8; 32];
        let cid3 = [3u8; 32];

        storage.store_chunk(cid1, &[1, 2, 3]);
        storage.store_chunk(cid3, &[7, 8, 9]);

        let req = ChunkCheckRequest {
            content_ids: vec![hex::encode(cid1), hex::encode(cid2), hex::encode(cid3)],
        };

        let response = check_chunks(State(storage), auth, Json(req)).await.unwrap();

        assert_eq!(response.existing.len(), 2);
        assert!(response.existing.contains(&hex::encode(cid1)));
        assert!(response.existing.contains(&hex::encode(cid3)));
        assert!(!response.existing.contains(&hex::encode(cid2)));
    }

    #[tokio::test]
    async fn test_update_portal_ownership_check() {
        let storage = Arc::new(HubStorage::new());
        let (_, owner_key) = create_test_signing_key();
        let (_, other_key) = create_test_signing_key();
        let edge_id = Uuid::new_v4();

        // Register edge with different key
        storage
            .register_edge(edge_id, other_key, "Other Edge".to_string())
            .unwrap();

        // Create portal with owner_key
        let portal = Portal::new("Test Portal".to_string(), owner_key);
        let portal_id = portal.id;
        storage
            .store_portal(StoredPortal::new(
                portal.clone(),
                AccessControlList::new(),
                owner_key,
            ))
            .unwrap();

        // Try to update with other_key (should fail)
        let auth = AuthenticatedEdge {
            edge_id,
            public_key: other_key,
        };

        let portal_json = serde_json::to_value(&portal).unwrap();
        let req = UpdatePortalRequest {
            portal: portal_json,
        };

        let result = update_portal(State(storage), auth, Path(portal_id), Json(req)).await;
        assert!(matches!(result, Err(Error::AuthFailed)));
    }

    #[test]
    fn test_error_into_response() {
        let err = Error::PortalNotFound(Uuid::new_v4());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let err = Error::AuthFailed;
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let err = Error::InvalidContentId;
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_edge_info_response_conversion() {
        let (_, verifying_key) = create_test_signing_key();
        let edge_id = Uuid::new_v4();
        let edge = EdgeInfo::new(edge_id, verifying_key, "Test Edge".to_string());

        let response: EdgeInfoResponse = edge.into();
        assert_eq!(response.id, edge_id);
        assert_eq!(response.name, "Test Edge");
        assert_eq!(response.public_key, hex::encode(verifying_key.to_bytes()));
    }
}
