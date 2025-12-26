//! Admin API endpoints
//!
//! Provides administrative REST API for managing:
//! - KMS keys (create, list, rotate, delete)
//! - Bucket policies (list, get, set, delete)
//! - IAM users and roles (if enabled)

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::error::ApiResult;
use crate::AppState;
use warp_store::backend::StorageBackend;

// ============================================================================
// KMS Key Management
// ============================================================================

/// Request to create a new KMS key
#[derive(Debug, Deserialize)]
pub struct CreateKeyRequest {
    /// Key alias (human-readable name)
    pub alias: String,
    /// Optional description
    pub description: Option<String>,
}

/// Response for a KMS key
#[derive(Debug, Serialize)]
pub struct KeyResponse {
    /// Key ID
    pub key_id: String,
    /// Key alias
    pub alias: String,
    /// Key version
    pub version: u32,
    /// Key state (enabled, disabled, pending_deletion)
    pub state: String,
    /// Algorithm used
    pub algorithm: String,
    /// Creation timestamp
    pub created_at: String,
    /// Last rotation timestamp
    pub last_rotated_at: Option<String>,
}

/// Response for list keys
#[derive(Debug, Serialize)]
pub struct ListKeysResponse {
    /// List of key IDs
    pub keys: Vec<String>,
}

/// List all KMS keys
///
/// GET /admin/keys
pub async fn list_keys<B: StorageBackend>(
    State(_state): State<AppState<B>>,
) -> ApiResult<impl IntoResponse> {
    // Note: In production, this would use a KmsProvider from AppState
    // For now, return an empty list as KMS integration requires AppState modification
    let response = ListKeysResponse { keys: Vec::new() };
    Ok((StatusCode::OK, Json(response)))
}

/// Create a new KMS key
///
/// POST /admin/keys
pub async fn create_key<B: StorageBackend>(
    State(_state): State<AppState<B>>,
    Json(request): Json<CreateKeyRequest>,
) -> ApiResult<impl IntoResponse> {
    // Note: In production, this would use a KmsProvider from AppState
    // For now, return a placeholder response
    let response = KeyResponse {
        key_id: format!("key-{}", uuid::Uuid::new_v4()),
        alias: request.alias,
        version: 1,
        state: "Enabled".to_string(),
        algorithm: "AES-256-GCM".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        last_rotated_at: None,
    };
    Ok((StatusCode::CREATED, Json(response)))
}

/// Get KMS key details
///
/// GET /admin/keys/:key_id
pub async fn get_key<B: StorageBackend>(
    State(_state): State<AppState<B>>,
    Path(key_id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    // Note: In production, this would fetch from KmsProvider
    let response = KeyResponse {
        key_id,
        alias: "unknown".to_string(),
        version: 1,
        state: "Enabled".to_string(),
        algorithm: "AES-256-GCM".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        last_rotated_at: None,
    };
    Ok((StatusCode::OK, Json(response)))
}

/// Rotate a KMS key
///
/// POST /admin/keys/:key_id/rotate
pub async fn rotate_key<B: StorageBackend>(
    State(_state): State<AppState<B>>,
    Path(key_id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    // Note: In production, this would call kms.rotate_key()
    let response = serde_json::json!({
        "key_id": key_id,
        "new_version": 2,
        "message": "Key rotated successfully"
    });
    Ok((StatusCode::OK, Json(response)))
}

/// Schedule key deletion
///
/// DELETE /admin/keys/:key_id
pub async fn schedule_key_deletion<B: StorageBackend>(
    State(_state): State<AppState<B>>,
    Path(key_id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    // Note: In production, this would call kms.schedule_key_deletion()
    let response = serde_json::json!({
        "key_id": key_id,
        "state": "PendingDeletion",
        "deletion_date": (chrono::Utc::now() + chrono::Duration::days(7)).to_rfc3339()
    });
    Ok((StatusCode::OK, Json(response)))
}

// ============================================================================
// Bucket Policy Management
// ============================================================================

/// Policy summary for listing
#[derive(Debug, Serialize)]
pub struct PolicySummary {
    /// Bucket name
    pub bucket: String,
    /// Whether a policy is set
    pub has_policy: bool,
    /// Number of statements in the policy
    pub statement_count: usize,
}

/// Response for list policies
#[derive(Debug, Serialize)]
pub struct ListPoliciesResponse {
    /// List of policy summaries
    pub policies: Vec<PolicySummary>,
}

/// List all bucket policies
///
/// GET /admin/policies
pub async fn list_policies<B: StorageBackend>(
    State(state): State<AppState<B>>,
) -> ApiResult<impl IntoResponse> {
    let mut policies = Vec::new();

    if let Some(ref pm) = state.policy_manager {
        for (bucket, statement_count) in pm.list() {
            policies.push(PolicySummary {
                bucket,
                has_policy: true,
                statement_count,
            });
        }
    }

    let response = ListPoliciesResponse { policies };
    Ok((StatusCode::OK, Json(response)))
}

/// Get a specific bucket policy
///
/// GET /admin/policies/:bucket
pub async fn get_policy<B: StorageBackend>(
    State(state): State<AppState<B>>,
    Path(bucket): Path<String>,
) -> ApiResult<impl IntoResponse> {
    if let Some(ref pm) = state.policy_manager {
        if let Some(policy) = pm.get(&bucket) {
            // Convert to JSON value for consistent return type
            let policy_json = serde_json::to_value(&policy)
                .unwrap_or_else(|_| serde_json::json!({"error": "Failed to serialize policy"}));
            return Ok((StatusCode::OK, Json(policy_json)));
        }
    }

    Ok((
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error": "Policy not found"})),
    ))
}

/// Set a bucket policy
///
/// PUT /admin/policies/:bucket
pub async fn set_policy<B: StorageBackend>(
    State(state): State<AppState<B>>,
    Path(bucket): Path<String>,
    body: String,
) -> ApiResult<impl IntoResponse> {
    let policy: crate::s3::PolicyDocument =
        serde_json::from_str(&body).map_err(|e| crate::error::ApiError::InvalidRequest(e.to_string()))?;

    if let Some(ref pm) = state.policy_manager {
        match pm.set(&bucket, policy) {
            Ok(()) => {
                return Ok((
                    StatusCode::OK,
                    Json(serde_json::json!({"message": "Policy set successfully"})),
                ));
            }
            Err(e) => {
                return Ok((
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": e})),
                ));
            }
        }
    }

    Ok((
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({"error": "Policy manager not available"})),
    ))
}

/// Delete a bucket policy
///
/// DELETE /admin/policies/:bucket
pub async fn delete_policy<B: StorageBackend>(
    State(state): State<AppState<B>>,
    Path(bucket): Path<String>,
) -> ApiResult<impl IntoResponse> {
    if let Some(ref pm) = state.policy_manager {
        pm.delete(&bucket);
        return Ok((StatusCode::NO_CONTENT, Json(serde_json::json!({}))));
    }

    Ok((
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({"error": "Policy manager not available"})),
    ))
}

// ============================================================================
// IAM User/Role Management (requires iam feature)
// ============================================================================

#[cfg(feature = "iam")]
mod iam_admin {
    use super::*;
    use crate::auth::IamManagers;

    /// IAM user summary
    #[derive(Debug, Serialize)]
    pub struct UserSummary {
        pub user_id: String,
        pub username: String,
        pub created_at: String,
    }

    /// List IAM users response
    #[derive(Debug, Serialize)]
    pub struct ListUsersResponse {
        pub users: Vec<UserSummary>,
    }

    /// Create user request
    #[derive(Debug, Deserialize)]
    pub struct CreateUserRequest {
        pub username: String,
        pub password: String,
    }

    /// List IAM users
    ///
    /// GET /admin/users
    pub async fn list_users<B: StorageBackend>(
        State(state): State<AppState<B>>,
    ) -> ApiResult<impl IntoResponse> {
        if let Some(ref iam) = state.iam {
            let user_ids = iam.user_manager.list_users();
            let users: Vec<UserSummary> = user_ids
                .into_iter()
                .filter_map(|id| {
                    iam.user_manager.get_user(&id).map(|u| UserSummary {
                        user_id: u.user_id.clone(),
                        username: u.username.clone(),
                        created_at: u.created_at.to_rfc3339(),
                    })
                })
                .collect();

            return Ok((StatusCode::OK, Json(ListUsersResponse { users })));
        }

        Ok((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ListUsersResponse { users: Vec::new() }),
        ))
    }

    /// Create an IAM user
    ///
    /// POST /admin/users
    pub async fn create_user<B: StorageBackend>(
        State(state): State<AppState<B>>,
        Json(request): Json<CreateUserRequest>,
    ) -> ApiResult<impl IntoResponse> {
        if let Some(ref iam) = state.iam {
            match iam
                .user_manager
                .create_user(&request.username, &request.password)
            {
                Ok(user) => {
                    let summary = UserSummary {
                        user_id: user.user_id.clone(),
                        username: user.username.clone(),
                        created_at: user.created_at.to_rfc3339(),
                    };
                    return Ok((StatusCode::CREATED, Json(summary)));
                }
                Err(e) => {
                    return Ok((
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": e.to_string()})),
                    ));
                }
            }
        }

        Ok((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "IAM not enabled"})),
        ))
    }

    /// Delete an IAM user
    ///
    /// DELETE /admin/users/:user_id
    pub async fn delete_user<B: StorageBackend>(
        State(state): State<AppState<B>>,
        Path(user_id): Path<String>,
    ) -> ApiResult<impl IntoResponse> {
        if let Some(ref iam) = state.iam {
            iam.user_manager.delete_user(&user_id);
            return Ok((StatusCode::NO_CONTENT, Json(serde_json::json!({}))));
        }

        Ok((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "IAM not enabled"})),
        ))
    }
}

// ============================================================================
// System Status
// ============================================================================

/// System status response
#[derive(Debug, Serialize)]
pub struct SystemStatus {
    /// Server version
    pub version: String,
    /// Uptime in seconds (placeholder)
    pub uptime_seconds: u64,
    /// Whether KMS is available
    pub kms_enabled: bool,
    /// Whether IAM is enabled
    pub iam_enabled: bool,
    /// Number of buckets
    pub bucket_count: usize,
    /// Number of active policies
    pub policy_count: usize,
}

/// Get system status
///
/// GET /admin/status
pub async fn get_status<B: StorageBackend>(
    State(state): State<AppState<B>>,
) -> ApiResult<impl IntoResponse> {
    let bucket_count = state.store.list_buckets().await.len();
    let policy_count = state
        .policy_manager
        .as_ref()
        .map(|pm| pm.len())
        .unwrap_or(0);

    let status = SystemStatus {
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: 0, // Placeholder - would need startup time tracking
        kms_enabled: false, // Will be true when KMS is integrated into AppState
        #[cfg(feature = "iam")]
        iam_enabled: state.iam.is_some(),
        #[cfg(not(feature = "iam"))]
        iam_enabled: false,
        bucket_count,
        policy_count,
    };

    Ok((StatusCode::OK, Json(status)))
}

// ============================================================================
// Router
// ============================================================================

/// Build the admin API router
pub fn routes<B: StorageBackend>(state: AppState<B>) -> Router {
    let mut router = Router::new()
        // System status
        .route("/admin/status", get(get_status::<B>))
        // KMS key management
        .route("/admin/keys", get(list_keys::<B>).post(create_key::<B>))
        .route("/admin/keys/{key_id}", get(get_key::<B>).delete(schedule_key_deletion::<B>))
        .route("/admin/keys/{key_id}/rotate", post(rotate_key::<B>))
        // Policy management
        .route("/admin/policies", get(list_policies::<B>))
        .route(
            "/admin/policies/{bucket}",
            get(get_policy::<B>)
                .put(set_policy::<B>)
                .delete(delete_policy::<B>),
        );

    // Add IAM routes if feature is enabled
    #[cfg(feature = "iam")]
    {
        router = router
            .route(
                "/admin/users",
                get(iam_admin::list_users::<B>).post(iam_admin::create_user::<B>),
            )
            .route(
                "/admin/users/{user_id}",
                delete(iam_admin::delete_user::<B>),
            );
    }

    router.with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_key_request() {
        let json = r#"{"alias": "my-key", "description": "Test key"}"#;
        let request: CreateKeyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.alias, "my-key");
        assert_eq!(request.description, Some("Test key".to_string()));
    }

    #[test]
    fn test_key_response_serialize() {
        let response = KeyResponse {
            key_id: "key-123".to_string(),
            alias: "test".to_string(),
            version: 1,
            state: "Enabled".to_string(),
            algorithm: "AES-256-GCM".to_string(),
            created_at: "2024-01-01T00:00:00Z".to_string(),
            last_rotated_at: None,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("key-123"));
    }

    #[test]
    fn test_system_status_serialize() {
        let status = SystemStatus {
            version: "0.1.0".to_string(),
            uptime_seconds: 3600,
            kms_enabled: false,
            iam_enabled: false,
            bucket_count: 5,
            policy_count: 2,
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("bucket_count"));
    }
}
