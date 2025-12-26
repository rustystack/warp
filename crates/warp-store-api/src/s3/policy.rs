//! S3-compatible bucket policy API
//!
//! Implements:
//! - GET /{bucket}?policy - Get bucket policy
//! - PUT /{bucket}?policy - Set bucket policy
//! - DELETE /{bucket}?policy - Delete bucket policy
//!
//! # Policy Format
//!
//! Bucket policies use AWS IAM policy document format:
//!
//! ```json
//! {
//!     "Version": "2012-10-17",
//!     "Statement": [{
//!         "Sid": "PublicRead",
//!         "Effect": "Allow",
//!         "Principal": "*",
//!         "Action": "s3:GetObject",
//!         "Resource": "arn:aws:s3:::my-bucket/*"
//!     }]
//! }
//! ```
//!
//! # Supported Elements
//!
//! - **Effect**: `Allow` or `Deny`
//! - **Principal**: `*`, `{"AWS": "..."}`, `{"Federated": "..."}`, `{"Service": "..."}`
//! - **Action**: S3 actions like `s3:GetObject`, `s3:PutObject`, `s3:*`
//! - **Resource**: ARN format `arn:aws:s3:::bucket/*` or path format
//! - **Condition**: Various condition operators (StringEquals, IpAddress, etc.)

use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use warp_store::backend::StorageBackend;

use crate::error::{ApiError, ApiResult};
use crate::AppState;

// Re-export policy types from warp-iam when available
#[cfg(feature = "iam")]
pub use warp_iam::{
    Action, AuthorizationDecision, Effect, PolicyDocument, PolicyEngine, PrincipalSpec, Resource,
    Statement,
};

// Standalone policy types when IAM feature is disabled
#[cfg(not(feature = "iam"))]
mod standalone {
    use super::*;

    /// Policy document version
    pub const POLICY_VERSION: &str = "2012-10-17";

    /// Policy effect - Allow or Deny
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub enum Effect {
        #[serde(rename = "Allow")]
        Allow,
        #[serde(rename = "Deny")]
        Deny,
    }

    /// An action in a policy (e.g., "s3:GetObject")
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(untagged)]
    pub enum Action {
        Single(String),
        Multiple(Vec<String>),
    }

    /// A resource in a policy (e.g., "arn:aws:s3:::bucket/*")
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(untagged)]
    pub enum Resource {
        Single(String),
        Multiple(Vec<String>),
    }

    /// Principal specification in a policy
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(untagged)]
    pub enum PrincipalSpec {
        Wildcard(String),
        Aws {
            #[serde(rename = "AWS")]
            aws: PrincipalList,
        },
        Federated {
            #[serde(rename = "Federated")]
            federated: PrincipalList,
        },
        Service {
            #[serde(rename = "Service")]
            service: PrincipalList,
        },
    }

    /// List of principals (single or multiple)
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(untagged)]
    pub enum PrincipalList {
        Single(String),
        Multiple(Vec<String>),
    }

    /// A policy statement
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Statement {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub sid: Option<String>,
        pub effect: Effect,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub principal: Option<PrincipalSpec>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub not_principal: Option<PrincipalSpec>,
        pub action: Action,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub not_action: Option<Action>,
        pub resource: Resource,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub not_resource: Option<Resource>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub condition: Option<serde_json::Value>,
    }

    /// A complete policy document
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct PolicyDocument {
        #[serde(default = "default_version")]
        pub version: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        pub statement: Vec<Statement>,
    }

    fn default_version() -> String {
        POLICY_VERSION.to_string()
    }

    impl PolicyDocument {
        /// Parse a policy from JSON
        pub fn parse(json: &str) -> Result<Self, serde_json::Error> {
            serde_json::from_str(json)
        }

        /// Validate the policy document
        pub fn validate(&self) -> Result<(), String> {
            if self.version != POLICY_VERSION {
                return Err(format!(
                    "Unsupported policy version: {}. Expected: {}",
                    self.version, POLICY_VERSION
                ));
            }

            if self.statement.is_empty() {
                return Err("Policy must have at least one statement".to_string());
            }

            Ok(())
        }

        /// Convert to JSON string
        pub fn to_json(&self) -> Result<String, serde_json::Error> {
            serde_json::to_string_pretty(self)
        }
    }
}

#[cfg(not(feature = "iam"))]
pub use standalone::*;

/// Bucket policy storage (in-memory for now, should be persisted)
use dashmap::DashMap;

/// Policy manager for bucket policies
pub struct BucketPolicyManager {
    /// Bucket name -> Policy document
    policies: DashMap<String, PolicyDocument>,
}

impl BucketPolicyManager {
    /// Create a new policy manager
    pub fn new() -> Self {
        Self {
            policies: DashMap::new(),
        }
    }

    /// Get a bucket policy
    pub fn get(&self, bucket: &str) -> Option<PolicyDocument> {
        self.policies.get(bucket).map(|p| p.clone())
    }

    /// Set a bucket policy
    pub fn set(&self, bucket: &str, policy: PolicyDocument) -> Result<(), String> {
        #[cfg(feature = "iam")]
        policy.validate().map_err(|e| e.to_string())?;

        #[cfg(not(feature = "iam"))]
        policy.validate()?;

        self.policies.insert(bucket.to_string(), policy);
        Ok(())
    }

    /// Delete a bucket policy
    pub fn delete(&self, bucket: &str) -> Option<PolicyDocument> {
        self.policies.remove(bucket).map(|(_, p)| p)
    }

    /// Check if a bucket has a policy
    pub fn has_policy(&self, bucket: &str) -> bool {
        self.policies.contains_key(bucket)
    }
}

impl Default for BucketPolicyManager {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// API Handlers
// =============================================================================

/// Get bucket policy
///
/// GET /{bucket}?policy
pub async fn get_policy<B: StorageBackend>(
    State(state): State<AppState<B>>,
    Path(bucket): Path<String>,
) -> ApiResult<Response> {
    // Verify bucket exists
    let buckets = state.store.list_buckets().await;
    if !buckets.contains(&bucket) {
        return Err(ApiError::NotFound(format!("Bucket '{}' not found", bucket)));
    }

    // Get policy from manager
    let policy = state
        .policy_manager
        .as_ref()
        .and_then(|pm| pm.get(&bucket));

    match policy {
        Some(policy) => {
            let json = serde_json::to_string_pretty(&policy)
                .map_err(|e| ApiError::Internal(e.to_string()))?;

            Ok((
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                json,
            )
                .into_response())
        }
        None => {
            // S3 returns NoSuchBucketPolicy error
            let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<Error>
    <Code>NoSuchBucketPolicy</Code>
    <Message>The bucket policy does not exist</Message>
</Error>"#;
            Ok((
                StatusCode::NOT_FOUND,
                [(header::CONTENT_TYPE, "application/xml")],
                xml,
            )
                .into_response())
        }
    }
}

/// Set bucket policy
///
/// PUT /{bucket}?policy
pub async fn put_policy<B: StorageBackend>(
    State(state): State<AppState<B>>,
    Path(bucket): Path<String>,
    body: Bytes,
) -> ApiResult<Response> {
    // Verify bucket exists
    let buckets = state.store.list_buckets().await;
    if !buckets.contains(&bucket) {
        return Err(ApiError::NotFound(format!("Bucket '{}' not found", bucket)));
    }

    // Parse the policy JSON
    let json_str = std::str::from_utf8(&body)
        .map_err(|e| ApiError::InvalidRequest(format!("Invalid UTF-8: {}", e)))?;

    #[cfg(feature = "iam")]
    let policy = PolicyDocument::parse(json_str)
        .map_err(|e| ApiError::InvalidRequest(format!("Invalid policy JSON: {}", e)))?;

    #[cfg(not(feature = "iam"))]
    let policy = PolicyDocument::parse(json_str)
        .map_err(|e| ApiError::InvalidRequest(format!("Invalid policy JSON: {}", e)))?;

    // Validate the policy
    #[cfg(feature = "iam")]
    policy
        .validate()
        .map_err(|e| ApiError::InvalidRequest(format!("Invalid policy: {}", e)))?;

    #[cfg(not(feature = "iam"))]
    policy
        .validate()
        .map_err(|e| ApiError::InvalidRequest(format!("Invalid policy: {}", e)))?;

    // Validate resource ARNs match the bucket
    validate_policy_resources(&policy, &bucket)?;

    // Store the policy
    if let Some(pm) = &state.policy_manager {
        pm.set(&bucket, policy)
            .map_err(|e| ApiError::InvalidRequest(e))?;
    } else {
        return Err(ApiError::Internal(
            "Policy manager not configured".to_string(),
        ));
    }

    tracing::info!(bucket = %bucket, "Bucket policy set");

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Delete bucket policy
///
/// DELETE /{bucket}?policy
pub async fn delete_policy<B: StorageBackend>(
    State(state): State<AppState<B>>,
    Path(bucket): Path<String>,
) -> ApiResult<Response> {
    // Verify bucket exists
    let buckets = state.store.list_buckets().await;
    if !buckets.contains(&bucket) {
        return Err(ApiError::NotFound(format!("Bucket '{}' not found", bucket)));
    }

    // Delete the policy
    if let Some(pm) = &state.policy_manager {
        pm.delete(&bucket);
    }

    tracing::info!(bucket = %bucket, "Bucket policy deleted");

    Ok(StatusCode::NO_CONTENT.into_response())
}

// =============================================================================
// Policy Validation Helpers
// =============================================================================

/// Validate that policy resources reference the correct bucket
fn validate_policy_resources(policy: &PolicyDocument, bucket: &str) -> ApiResult<()> {
    let bucket_arn = format!("arn:aws:s3:::{}", bucket);
    let bucket_arn_with_objects = format!("arn:aws:s3:::{}/*", bucket);

    for (i, stmt) in policy.statement.iter().enumerate() {
        let resources = match &stmt.resource {
            #[cfg(feature = "iam")]
            Resource::Single(r) => vec![r.as_str()],
            #[cfg(feature = "iam")]
            Resource::Multiple(rs) => rs.iter().map(|s| s.as_str()).collect(),
            #[cfg(not(feature = "iam"))]
            Resource::Single(r) => vec![r.as_str()],
            #[cfg(not(feature = "iam"))]
            Resource::Multiple(rs) => rs.iter().map(|s| s.as_str()).collect(),
        };

        for resource in resources {
            // Allow wildcard
            if resource == "*" {
                continue;
            }

            // Must reference this bucket
            if !resource.starts_with(&bucket_arn) && !resource.starts_with(&bucket_arn_with_objects)
            {
                // Also allow path-style references
                let path_prefix = format!("/{}/", bucket);
                let path_bucket = format!("/{}", bucket);
                if !resource.starts_with(&path_prefix)
                    && resource != path_bucket
                    && resource != bucket
                {
                    return Err(ApiError::InvalidRequest(format!(
                        "Statement {} resource '{}' does not reference bucket '{}'",
                        i, resource, bucket
                    )));
                }
            }
        }
    }

    Ok(())
}

/// Check if path refers to an object (vs a bucket)
fn is_object_path(path: &str) -> bool {
    // Trim leading slash and check if there's a second component (key)
    let trimmed = path.trim_start_matches('/');
    // If there's a slash in the remaining path, it's an object
    trimmed.contains('/')
}

/// Get the S3 action for a request (used for policy evaluation)
pub fn get_s3_action(method: &str, path: &str, query: &str) -> &'static str {
    match method {
        "GET" => {
            if is_object_path(path) {
                // Object operation
                if query.contains("acl") {
                    "s3:GetObjectAcl"
                } else if query.contains("tagging") {
                    "s3:GetObjectTagging"
                } else if query.contains("retention") {
                    "s3:GetObjectRetention"
                } else if query.contains("legal-hold") {
                    "s3:GetObjectLegalHold"
                } else {
                    "s3:GetObject"
                }
            } else {
                // Bucket operation
                if query.contains("policy") {
                    "s3:GetBucketPolicy"
                } else if query.contains("lifecycle") {
                    "s3:GetLifecycleConfiguration"
                } else if query.contains("notification") {
                    "s3:GetBucketNotification"
                } else if query.contains("versioning") {
                    "s3:GetBucketVersioning"
                } else if query.contains("location") {
                    "s3:GetBucketLocation"
                } else {
                    "s3:ListBucket"
                }
            }
        }
        "PUT" => {
            if is_object_path(path) {
                // Object operation
                if query.contains("acl") {
                    "s3:PutObjectAcl"
                } else if query.contains("tagging") {
                    "s3:PutObjectTagging"
                } else if query.contains("retention") {
                    "s3:PutObjectRetention"
                } else if query.contains("legal-hold") {
                    "s3:PutObjectLegalHold"
                } else {
                    "s3:PutObject"
                }
            } else {
                // Bucket operation
                if query.contains("policy") {
                    "s3:PutBucketPolicy"
                } else if query.contains("lifecycle") {
                    "s3:PutLifecycleConfiguration"
                } else if query.contains("notification") {
                    "s3:PutBucketNotification"
                } else if query.contains("versioning") {
                    "s3:PutBucketVersioning"
                } else {
                    "s3:CreateBucket"
                }
            }
        }
        "DELETE" => {
            if is_object_path(path) {
                // Object operation
                if query.contains("tagging") {
                    "s3:DeleteObjectTagging"
                } else {
                    "s3:DeleteObject"
                }
            } else {
                // Bucket operation
                if query.contains("policy") {
                    "s3:DeleteBucketPolicy"
                } else if query.contains("lifecycle") {
                    "s3:DeleteLifecycleConfiguration"
                } else {
                    "s3:DeleteBucket"
                }
            }
        }
        "HEAD" => {
            if is_object_path(path) {
                "s3:GetObject"
            } else {
                "s3:ListBucket"
            }
        }
        "POST" => {
            if query.contains("select") {
                "s3:GetObject" // S3 Select uses GetObject permission
            } else if query.contains("uploads") {
                "s3:PutObject" // Multipart upload initiation
            } else if query.contains("uploadId") {
                "s3:PutObject" // Complete multipart upload
            } else {
                "s3:PutObject"
            }
        }
        _ => "s3:*",
    }
}

// =============================================================================
// Condition Evaluation (for advanced policy features)
// =============================================================================

/// Condition context for policy evaluation
#[derive(Debug, Clone, Default)]
pub struct ConditionContext {
    /// Source IP address
    pub source_ip: Option<String>,
    /// Current time (ISO 8601)
    pub current_time: Option<String>,
    /// Is secure transport (HTTPS)
    pub secure_transport: bool,
    /// Request headers
    pub headers: std::collections::HashMap<String, String>,
    /// User agent
    pub user_agent: Option<String>,
    /// Referer
    pub referer: Option<String>,
}

impl ConditionContext {
    /// Create a new condition context from request info
    pub fn from_request(
        source_ip: Option<String>,
        secure: bool,
        headers: std::collections::HashMap<String, String>,
    ) -> Self {
        let user_agent = headers.get("user-agent").cloned();
        let referer = headers.get("referer").cloned();

        Self {
            source_ip,
            current_time: Some(chrono::Utc::now().to_rfc3339()),
            secure_transport: secure,
            headers,
            user_agent,
            referer,
        }
    }
}

/// Evaluate a condition block against a context
#[cfg(feature = "iam")]
pub fn evaluate_condition(
    condition: &Option<serde_json::Value>,
    context: &ConditionContext,
) -> bool {
    let Some(cond) = condition else {
        return true; // No condition = always match
    };

    let Some(cond_obj) = cond.as_object() else {
        return false; // Invalid condition format
    };

    for (operator, conditions) in cond_obj {
        let Some(conditions) = conditions.as_object() else {
            continue;
        };

        for (key, expected) in conditions {
            let actual = get_condition_value(key, context);

            let matches = match operator.as_str() {
                "StringEquals" => string_equals(&actual, expected),
                "StringNotEquals" => !string_equals(&actual, expected),
                "StringEqualsIgnoreCase" => string_equals_ignore_case(&actual, expected),
                "StringLike" => string_like(&actual, expected),
                "StringNotLike" => !string_like(&actual, expected),
                "IpAddress" => ip_address_matches(&actual, expected),
                "NotIpAddress" => !ip_address_matches(&actual, expected),
                "Bool" => bool_matches(&actual, expected),
                "Null" => null_matches(&actual, expected),
                _ => true, // Unknown operator - allow (permissive)
            };

            if !matches {
                return false;
            }
        }
    }

    true
}

#[cfg(feature = "iam")]
fn get_condition_value(key: &str, context: &ConditionContext) -> Option<String> {
    match key {
        "aws:SourceIp" => context.source_ip.clone(),
        "aws:CurrentTime" => context.current_time.clone(),
        "aws:SecureTransport" => Some(context.secure_transport.to_string()),
        "aws:UserAgent" => context.user_agent.clone(),
        "aws:Referer" => context.referer.clone(),
        _ => {
            // Check custom headers
            let header_key = key.strip_prefix("aws:").unwrap_or(key);
            context.headers.get(header_key).cloned()
        }
    }
}

#[cfg(feature = "iam")]
fn string_equals(actual: &Option<String>, expected: &serde_json::Value) -> bool {
    let Some(actual) = actual else {
        return false;
    };

    match expected {
        serde_json::Value::String(s) => actual == s,
        serde_json::Value::Array(arr) => arr.iter().any(|v| {
            v.as_str()
                .map(|s| actual == s)
                .unwrap_or(false)
        }),
        _ => false,
    }
}

#[cfg(feature = "iam")]
fn string_equals_ignore_case(actual: &Option<String>, expected: &serde_json::Value) -> bool {
    let Some(actual) = actual else {
        return false;
    };

    let actual_lower = actual.to_lowercase();

    match expected {
        serde_json::Value::String(s) => actual_lower == s.to_lowercase(),
        serde_json::Value::Array(arr) => arr.iter().any(|v| {
            v.as_str()
                .map(|s| actual_lower == s.to_lowercase())
                .unwrap_or(false)
        }),
        _ => false,
    }
}

#[cfg(feature = "iam")]
fn string_like(actual: &Option<String>, expected: &serde_json::Value) -> bool {
    let Some(actual) = actual else {
        return false;
    };

    let patterns: Vec<&str> = match expected {
        serde_json::Value::String(s) => vec![s.as_str()],
        serde_json::Value::Array(arr) => arr
            .iter()
            .filter_map(|v| v.as_str())
            .collect(),
        _ => return false,
    };

    for pattern in patterns {
        // Convert glob to regex
        let regex_pattern = pattern
            .replace('.', "\\.")
            .replace('*', ".*")
            .replace('?', ".");

        if let Ok(re) = regex::Regex::new(&format!("^{}$", regex_pattern)) {
            if re.is_match(actual) {
                return true;
            }
        }
    }

    false
}

#[cfg(feature = "iam")]
fn ip_address_matches(actual: &Option<String>, expected: &serde_json::Value) -> bool {
    let Some(actual) = actual else {
        return false;
    };

    let cidrs: Vec<&str> = match expected {
        serde_json::Value::String(s) => vec![s.as_str()],
        serde_json::Value::Array(arr) => arr
            .iter()
            .filter_map(|v| v.as_str())
            .collect(),
        _ => return false,
    };

    // Parse the actual IP
    let actual_ip: std::net::IpAddr = match actual.parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };

    for cidr in cidrs {
        // Simple CIDR check (for full support, use ipnetwork crate)
        if cidr.contains('/') {
            // CIDR notation
            let parts: Vec<&str> = cidr.split('/').collect();
            if parts.len() != 2 {
                continue;
            }

            let network_ip: std::net::IpAddr = match parts[0].parse() {
                Ok(ip) => ip,
                Err(_) => continue,
            };

            let prefix_len: u8 = match parts[1].parse() {
                Ok(len) => len,
                Err(_) => continue,
            };

            if ip_in_cidr(&actual_ip, &network_ip, prefix_len) {
                return true;
            }
        } else {
            // Single IP
            if let Ok(expected_ip) = cidr.parse::<std::net::IpAddr>() {
                if actual_ip == expected_ip {
                    return true;
                }
            }
        }
    }

    false
}

#[cfg(feature = "iam")]
fn ip_in_cidr(ip: &std::net::IpAddr, network: &std::net::IpAddr, prefix_len: u8) -> bool {
    match (ip, network) {
        (std::net::IpAddr::V4(ip), std::net::IpAddr::V4(network)) => {
            let ip_bits = u32::from(*ip);
            let network_bits = u32::from(*network);
            let mask = if prefix_len >= 32 {
                u32::MAX
            } else {
                u32::MAX << (32 - prefix_len)
            };
            (ip_bits & mask) == (network_bits & mask)
        }
        (std::net::IpAddr::V6(ip), std::net::IpAddr::V6(network)) => {
            let ip_bits = u128::from(*ip);
            let network_bits = u128::from(*network);
            let mask = if prefix_len >= 128 {
                u128::MAX
            } else {
                u128::MAX << (128 - prefix_len)
            };
            (ip_bits & mask) == (network_bits & mask)
        }
        _ => false,
    }
}

#[cfg(feature = "iam")]
fn bool_matches(actual: &Option<String>, expected: &serde_json::Value) -> bool {
    let Some(actual) = actual else {
        return false;
    };

    let actual_bool = matches!(actual.to_lowercase().as_str(), "true" | "1" | "yes");

    match expected {
        serde_json::Value::Bool(b) => actual_bool == *b,
        serde_json::Value::String(s) => {
            let expected_bool = matches!(s.to_lowercase().as_str(), "true" | "1" | "yes");
            actual_bool == expected_bool
        }
        _ => false,
    }
}

#[cfg(feature = "iam")]
fn null_matches(actual: &Option<String>, expected: &serde_json::Value) -> bool {
    let is_null = actual.is_none();

    match expected {
        serde_json::Value::Bool(b) => is_null == *b,
        serde_json::Value::String(s) => {
            let expected_null = matches!(s.to_lowercase().as_str(), "true" | "1" | "yes");
            is_null == expected_null
        }
        _ => false,
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_policy() {
        let json = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "PublicRead",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*"
            }]
        }"#;

        let policy = PolicyDocument::parse(json).unwrap();
        assert_eq!(policy.version, "2012-10-17");
        assert_eq!(policy.statement.len(), 1);
    }

    #[test]
    fn test_policy_validation() {
        let json = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::bucket/*"
            }]
        }"#;

        let policy = PolicyDocument::parse(json).unwrap();
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn test_empty_policy_fails() {
        let json = r#"{
            "Version": "2012-10-17",
            "Statement": []
        }"#;

        let policy = PolicyDocument::parse(json).unwrap();
        assert!(policy.validate().is_err());
    }

    #[test]
    fn test_get_s3_action() {
        assert_eq!(get_s3_action("GET", "/bucket/key", ""), "s3:GetObject");
        assert_eq!(get_s3_action("PUT", "/bucket/key", ""), "s3:PutObject");
        assert_eq!(get_s3_action("DELETE", "/bucket/key", ""), "s3:DeleteObject");
        assert_eq!(get_s3_action("GET", "/bucket", ""), "s3:ListBucket");
        assert_eq!(
            get_s3_action("PUT", "/bucket", "policy"),
            "s3:PutBucketPolicy"
        );
        assert_eq!(
            get_s3_action("GET", "/bucket", "lifecycle"),
            "s3:GetLifecycleConfiguration"
        );
    }

    #[test]
    fn test_policy_to_json() {
        let json = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*"
            }]
        }"#;

        let policy = PolicyDocument::parse(json).unwrap();
        let output = policy.to_json().unwrap();
        assert!(output.contains("2012-10-17"));
        assert!(output.contains("Allow"));
    }

    #[cfg(feature = "iam")]
    #[test]
    fn test_ip_address_condition() {
        let ctx = ConditionContext {
            source_ip: Some("192.168.1.100".to_string()),
            ..Default::default()
        };

        // Test single IP match
        assert!(ip_address_matches(
            &ctx.source_ip,
            &serde_json::json!("192.168.1.100")
        ));

        // Test CIDR match
        assert!(ip_address_matches(
            &ctx.source_ip,
            &serde_json::json!("192.168.1.0/24")
        ));

        // Test non-match
        assert!(!ip_address_matches(
            &ctx.source_ip,
            &serde_json::json!("10.0.0.0/8")
        ));
    }
}
