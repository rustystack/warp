//! IAM middleware for session validation and policy-based authorization
//!
//! This module integrates warp-iam with the S3 API to provide:
//! - Session token validation (Bearer tokens)
//! - Policy-based authorization for S3 operations
//! - OIDC token verification
//!
//! # Feature Flag
//!
//! This module requires the `iam` feature to be enabled.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use dashmap::DashMap;
use tracing::{debug, warn};

use warp_iam::{
    policy::{AuthorizationDecision, Effect, PolicyDocument, PolicyEngine, Resource, Statement},
    session::SessionManager,
    identity::Identity,
};

/// IAM authentication context extracted from request
#[derive(Debug, Clone)]
pub struct IamContext {
    /// The authenticated identity
    pub identity: Identity,
    /// The session ID
    pub session_id: String,
}

/// IAM managers for authentication and authorization
#[derive(Clone)]
pub struct IamManagers {
    /// Session manager for token validation
    pub session_manager: Arc<SessionManager>,
    /// Policy engine for authorization evaluation
    pub policy_engine: Arc<PolicyEngine>,
    /// User policies (user_id -> PolicyDocument)
    pub user_policies: Arc<DashMap<String, PolicyDocument>>,
}

impl IamManagers {
    /// Create new IAM managers with default configuration
    pub fn new() -> Self {
        Self {
            session_manager: Arc::new(SessionManager::new(3600)), // 1 hour TTL
            policy_engine: Arc::new(PolicyEngine::new()),
            user_policies: Arc::new(DashMap::new()),
        }
    }

    /// Create with custom TTL
    pub fn with_ttl(ttl_seconds: u64) -> Self {
        Self {
            session_manager: Arc::new(SessionManager::new(ttl_seconds)),
            policy_engine: Arc::new(PolicyEngine::new()),
            user_policies: Arc::new(DashMap::new()),
        }
    }

    /// Add a default admin policy for a user
    pub fn add_admin_policy(&self, user_id: &str) {
        let policy = PolicyDocument::new()
            .add_statement(
                Statement::allow("s3:*", "*")
                    .with_sid(format!("{}-admin", user_id))
            );
        self.user_policies.insert(user_id.to_string(), policy);
    }

    /// Add a read-only policy for a user on specific bucket
    pub fn add_readonly_policy(&self, user_id: &str, bucket: &str) {
        let policy = PolicyDocument::new()
            .add_statement(
                Statement::allow("s3:GetObject", format!("arn:aws:s3:::{}/*", bucket))
                    .with_sid(format!("{}-readonly-{}-objects", user_id, bucket))
            )
            .add_statement(
                Statement::allow("s3:ListBucket", format!("arn:aws:s3:::{}", bucket))
                    .with_sid(format!("{}-readonly-{}-list", user_id, bucket))
            )
            .add_statement(
                Statement::allow("s3:HeadObject", format!("arn:aws:s3:::{}/*", bucket))
                    .with_sid(format!("{}-readonly-{}-head", user_id, bucket))
            )
            .add_statement(
                Statement::allow("s3:GetObjectVersion", format!("arn:aws:s3:::{}/*", bucket))
                    .with_sid(format!("{}-readonly-{}-versions", user_id, bucket))
            );
        self.user_policies.insert(user_id.to_string(), policy);
    }

    /// Add a custom policy for a user
    pub fn add_policy(&self, user_id: &str, policy: PolicyDocument) {
        self.user_policies.insert(user_id.to_string(), policy);
    }

    /// Check if a user is allowed to perform an action on a resource
    pub fn is_allowed(&self, identity: &Identity, action: &str, resource: &str) -> bool {
        // Check if user has a policy
        if let Some(policy) = self.user_policies.get(&identity.id) {
            match self.policy_engine.evaluate(&policy, identity, action, resource) {
                Ok(AuthorizationDecision::Allow) => true,
                Ok(AuthorizationDecision::Deny { .. }) => false,
                Ok(AuthorizationDecision::NotApplicable) => false,
                Err(_) => false,
            }
        } else {
            // No policy = no access
            false
        }
    }
}

impl Default for IamManagers {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract bearer token from Authorization header
fn extract_bearer_token(request: &Request) -> Option<String> {
    request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|auth| {
            if auth.to_lowercase().starts_with("bearer ") {
                Some(auth[7..].to_string())
            } else {
                None
            }
        })
}

/// Extract session token from X-Warp-Session header
fn extract_session_header(request: &Request) -> Option<String> {
    request
        .headers()
        .get("x-warp-session")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
}

/// Extract token from cookie
fn extract_cookie_token(request: &Request) -> Option<String> {
    request
        .headers()
        .get(header::COOKIE)
        .and_then(|h| h.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|cookie| {
                let cookie = cookie.trim();
                if cookie.starts_with("warp_session=") {
                    Some(cookie["warp_session=".len()..].to_string())
                } else {
                    None
                }
            })
        })
}

/// Map S3 operation from HTTP method and path
fn map_s3_action(method: &str, path: &str, query: Option<&str>) -> String {
    let has_key = path.matches('/').count() > 1;

    // Check query parameters for special operations
    if let Some(q) = query {
        if q.contains("uploads") || q.contains("uploadId") {
            return match method {
                "POST" if q.contains("uploads") => "s3:CreateMultipartUpload".to_string(),
                "PUT" if q.contains("uploadId") => "s3:UploadPart".to_string(),
                "POST" if q.contains("uploadId") => "s3:CompleteMultipartUpload".to_string(),
                "DELETE" if q.contains("uploadId") => "s3:AbortMultipartUpload".to_string(),
                _ => "s3:*".to_string(),
            };
        }
        if q.contains("versioning") {
            return match method {
                "GET" => "s3:GetBucketVersioning".to_string(),
                "PUT" => "s3:PutBucketVersioning".to_string(),
                _ => "s3:*".to_string(),
            };
        }
        if q.contains("lifecycle") {
            return match method {
                "GET" => "s3:GetLifecycleConfiguration".to_string(),
                "PUT" => "s3:PutLifecycleConfiguration".to_string(),
                "DELETE" => "s3:DeleteLifecycleConfiguration".to_string(),
                _ => "s3:*".to_string(),
            };
        }
        if q.contains("notification") {
            return match method {
                "GET" => "s3:GetBucketNotification".to_string(),
                "PUT" => "s3:PutBucketNotification".to_string(),
                _ => "s3:*".to_string(),
            };
        }
        if q.contains("object-lock") {
            return match method {
                "GET" => "s3:GetObjectLockConfiguration".to_string(),
                "PUT" => "s3:PutObjectLockConfiguration".to_string(),
                _ => "s3:*".to_string(),
            };
        }
        if q.contains("retention") {
            return match method {
                "GET" => "s3:GetObjectRetention".to_string(),
                "PUT" => "s3:PutObjectRetention".to_string(),
                _ => "s3:*".to_string(),
            };
        }
        if q.contains("legal-hold") {
            return match method {
                "GET" => "s3:GetObjectLegalHold".to_string(),
                "PUT" => "s3:PutObjectLegalHold".to_string(),
                _ => "s3:*".to_string(),
            };
        }
    }

    // Standard operations
    match (method, has_key) {
        ("GET", false) if path == "/" => "s3:ListBuckets".to_string(),
        ("GET", false) => "s3:ListBucket".to_string(),
        ("GET", true) => "s3:GetObject".to_string(),
        ("HEAD", false) => "s3:HeadBucket".to_string(),
        ("HEAD", true) => "s3:HeadObject".to_string(),
        ("PUT", false) => "s3:CreateBucket".to_string(),
        ("PUT", true) => "s3:PutObject".to_string(),
        ("DELETE", false) => "s3:DeleteBucket".to_string(),
        ("DELETE", true) => "s3:DeleteObject".to_string(),
        ("POST", true) => "s3:PostObject".to_string(),
        _ => "s3:*".to_string(),
    }
}

/// Extract bucket and key from path
fn extract_bucket_key(path: &str) -> (Option<String>, Option<String>) {
    let path = path.trim_start_matches('/');
    if path.is_empty() {
        return (None, None);
    }

    let mut parts = path.splitn(2, '/');
    let bucket = parts.next().map(|s| s.to_string());
    let key = parts.next().map(|s| s.to_string());

    (bucket, key)
}

/// Build S3 ARN from bucket and key
fn build_s3_arn(bucket: Option<&str>, key: Option<&str>) -> String {
    match (bucket, key) {
        (Some(b), Some(k)) => format!("arn:aws:s3:::{}/{}", b, k),
        (Some(b), None) => format!("arn:aws:s3:::{}", b),
        _ => "*".to_string(),
    }
}

/// IAM authentication middleware
///
/// Validates session tokens and adds IAM context to request extensions.
/// Falls back to S3 Signature V4 if no IAM token is present.
pub async fn iam_auth_middleware(
    State(iam): State<Arc<IamManagers>>,
    mut request: Request,
    next: Next,
) -> Response {
    // Try to extract token from various sources
    let token = extract_bearer_token(&request)
        .or_else(|| extract_session_header(&request))
        .or_else(|| extract_cookie_token(&request));

    if let Some(token) = token {
        // Validate the session token
        match iam.session_manager.get_session(&token) {
            Ok(session) => {
                debug!(user_id = %session.identity.id, session_id = %session.id, "IAM session validated");

                // Add IAM context to request extensions
                let context = IamContext {
                    identity: session.identity.clone(),
                    session_id: session.id.clone(),
                };
                request.extensions_mut().insert(context);

                // Continue to authorization middleware
                next.run(request).await
            }
            Err(e) => {
                warn!(error = %e, "IAM session validation failed");
                (
                    StatusCode::UNAUTHORIZED,
                    [("Content-Type", "application/xml")],
                    format!(
                        r#"<?xml version="1.0" encoding="UTF-8"?>
<Error>
    <Code>InvalidToken</Code>
    <Message>The provided token is invalid or expired</Message>
    <RequestId>{}</RequestId>
</Error>"#,
                        uuid::Uuid::new_v4()
                    ),
                )
                    .into_response()
            }
        }
    } else {
        // No IAM token, proceed without IAM context (will fall back to SigV4)
        debug!("No IAM token found, proceeding without IAM context");
        next.run(request).await
    }
}

/// IAM authorization middleware
///
/// Checks if the authenticated user has permission to perform the requested operation.
/// Must be applied after `iam_auth_middleware`.
pub async fn iam_authz_middleware(
    State(iam): State<Arc<IamManagers>>,
    request: Request,
    next: Next,
) -> Response {
    // Get IAM context if present
    let context = request.extensions().get::<IamContext>().cloned();

    if let Some(ctx) = context {
        // Map request to S3 action
        let method = request.method().as_str();
        let path = request.uri().path();
        let query = request.uri().query();
        let action = map_s3_action(method, path, query);

        // Extract bucket and key from path
        let (bucket, key) = extract_bucket_key(path);
        let resource_arn = build_s3_arn(bucket.as_deref(), key.as_deref());

        debug!(
            user_id = %ctx.identity.id,
            action = %action,
            resource = %resource_arn,
            "Checking IAM authorization"
        );

        // Evaluate policy
        if iam.is_allowed(&ctx.identity, &action, &resource_arn) {
            debug!(user_id = %ctx.identity.id, action = %action, "IAM authorization granted");
            next.run(request).await
        } else {
            warn!(
                user_id = %ctx.identity.id,
                action = %action,
                resource = %resource_arn,
                "IAM authorization denied"
            );
            (
                StatusCode::FORBIDDEN,
                [("Content-Type", "application/xml")],
                format!(
                    r#"<?xml version="1.0" encoding="UTF-8"?>
<Error>
    <Code>AccessDenied</Code>
    <Message>Access Denied</Message>
    <Resource>{}</Resource>
    <RequestId>{}</RequestId>
</Error>"#,
                    resource_arn,
                    uuid::Uuid::new_v4()
                ),
            )
                .into_response()
        }
    } else {
        // No IAM context, allow request to proceed (will be validated by SigV4 or other auth)
        next.run(request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_s3_action_basic() {
        assert_eq!(map_s3_action("GET", "/", None), "s3:ListBuckets");
        assert_eq!(map_s3_action("GET", "/bucket", None), "s3:ListBucket");
        assert_eq!(map_s3_action("GET", "/bucket/key", None), "s3:GetObject");
        assert_eq!(map_s3_action("PUT", "/bucket", None), "s3:CreateBucket");
        assert_eq!(map_s3_action("PUT", "/bucket/key", None), "s3:PutObject");
        assert_eq!(map_s3_action("DELETE", "/bucket", None), "s3:DeleteBucket");
        assert_eq!(map_s3_action("DELETE", "/bucket/key", None), "s3:DeleteObject");
        assert_eq!(map_s3_action("HEAD", "/bucket", None), "s3:HeadBucket");
        assert_eq!(map_s3_action("HEAD", "/bucket/key", None), "s3:HeadObject");
    }

    #[test]
    fn test_map_s3_action_special() {
        assert_eq!(
            map_s3_action("POST", "/bucket/key", Some("uploads")),
            "s3:CreateMultipartUpload"
        );
        assert_eq!(
            map_s3_action("PUT", "/bucket/key", Some("uploadId=123")),
            "s3:UploadPart"
        );
        assert_eq!(
            map_s3_action("GET", "/bucket", Some("versioning")),
            "s3:GetBucketVersioning"
        );
        assert_eq!(
            map_s3_action("GET", "/bucket", Some("lifecycle")),
            "s3:GetLifecycleConfiguration"
        );
    }

    #[test]
    fn test_extract_bucket_key() {
        assert_eq!(extract_bucket_key("/"), (None, None));
        assert_eq!(
            extract_bucket_key("/bucket"),
            (Some("bucket".to_string()), None)
        );
        assert_eq!(
            extract_bucket_key("/bucket/key"),
            (Some("bucket".to_string()), Some("key".to_string()))
        );
        assert_eq!(
            extract_bucket_key("/bucket/path/to/key"),
            (Some("bucket".to_string()), Some("path/to/key".to_string()))
        );
    }

    #[test]
    fn test_build_s3_arn() {
        assert_eq!(build_s3_arn(None, None), "*");
        assert_eq!(
            build_s3_arn(Some("bucket"), None),
            "arn:aws:s3:::bucket"
        );
        assert_eq!(
            build_s3_arn(Some("bucket"), Some("key")),
            "arn:aws:s3:::bucket/key"
        );
    }

    #[tokio::test]
    async fn test_iam_managers_policies() {
        let iam = IamManagers::new();

        // Add admin policy
        iam.add_admin_policy("admin-user");

        // Create admin identity
        let admin = Identity::user("admin-user", "Admin User", "local");

        // Verify admin has access
        assert!(iam.is_allowed(&admin, "s3:GetObject", "arn:aws:s3:::any-bucket/any-key"));
        assert!(iam.is_allowed(&admin, "s3:PutObject", "arn:aws:s3:::any-bucket/any-key"));
        assert!(iam.is_allowed(&admin, "s3:DeleteBucket", "arn:aws:s3:::any-bucket"));

        // Add readonly policy
        iam.add_readonly_policy("reader", "test-bucket");

        // Create reader identity
        let reader = Identity::user("reader", "Reader User", "local");

        // Verify reader has read access
        assert!(iam.is_allowed(&reader, "s3:GetObject", "arn:aws:s3:::test-bucket/file.txt"));
        assert!(iam.is_allowed(&reader, "s3:ListBucket", "arn:aws:s3:::test-bucket"));

        // Verify reader doesn't have write access
        assert!(!iam.is_allowed(&reader, "s3:PutObject", "arn:aws:s3:::test-bucket/file.txt"));
        assert!(!iam.is_allowed(&reader, "s3:DeleteObject", "arn:aws:s3:::test-bucket/file.txt"));
    }

    #[tokio::test]
    async fn test_session_create_and_validate() {
        let iam = IamManagers::new();

        // Create an identity
        let identity = Identity::user("test-user", "Test User", "local");

        // Create a session
        let session = iam.session_manager.create_session(identity).unwrap();

        // Validate the session
        let retrieved = iam.session_manager.get_session(session.token.as_str()).unwrap();
        assert_eq!(retrieved.identity.id, "test-user");

        // Invalidate the session
        iam.session_manager.invalidate(&session.id).unwrap();

        // Session should no longer be valid
        assert!(!iam.session_manager.is_valid(&session.id));
    }
}
