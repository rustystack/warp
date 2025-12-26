//! S3-compatible Bucket CORS API
//!
//! Implements:
//! - GET /{bucket}?cors - Get bucket CORS configuration
//! - PUT /{bucket}?cors - Set bucket CORS configuration
//! - DELETE /{bucket}?cors - Delete bucket CORS configuration

use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use warp_store::backend::StorageBackend;
use warp_store::bucket::{CorsConfig, CorsRule};

use crate::error::{ApiError, ApiResult};
use crate::AppState;

// =============================================================================
// XML Types for S3 CORS API
// =============================================================================

/// CORS configuration (S3 XML format)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename = "CORSConfiguration")]
pub struct CorsConfigurationXml {
    /// CORS rules
    #[serde(rename = "CORSRule", default)]
    pub rules: Vec<CorsRuleXml>,
}

/// A CORS rule in S3 XML format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsRuleXml {
    /// Rule ID (optional)
    #[serde(rename = "ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Allowed origins (required)
    #[serde(rename = "AllowedOrigin", default)]
    pub allowed_origins: Vec<String>,

    /// Allowed HTTP methods (required)
    #[serde(rename = "AllowedMethod", default)]
    pub allowed_methods: Vec<String>,

    /// Allowed headers (optional)
    #[serde(rename = "AllowedHeader", default)]
    pub allowed_headers: Vec<String>,

    /// Headers to expose to browser (optional)
    #[serde(rename = "ExposeHeader", default)]
    pub expose_headers: Vec<String>,

    /// Max age in seconds for preflight caching (optional)
    #[serde(rename = "MaxAgeSeconds", skip_serializing_if = "Option::is_none")]
    pub max_age_seconds: Option<u32>,
}

// =============================================================================
// CORS Handlers
// =============================================================================

/// Get CORS configuration for a bucket
///
/// GET /{bucket}?cors
pub async fn get_cors<B: StorageBackend>(
    State(state): State<AppState<B>>,
    Path(bucket): Path<String>,
) -> ApiResult<Response> {
    // Verify bucket exists
    let buckets = state.store.list_buckets().await;
    if !buckets.contains(&bucket) {
        return Err(ApiError::NotFound(format!("Bucket '{}' not found", bucket)));
    }

    // Get CORS config from state
    let config = state
        .cors_configs
        .get(&bucket)
        .map(|r| r.value().clone());

    match config {
        Some(config) if !config.rules.is_empty() => {
            let xml_config = to_cors_xml(&config);
            let xml = quick_xml::se::to_string(&xml_config)
                .map_err(|e| ApiError::Internal(format!("XML serialization error: {}", e)))?;

            Ok((
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/xml")],
                format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}", xml),
            )
                .into_response())
        }
        _ => {
            // No CORS configured
            let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<Error>
    <Code>NoSuchCORSConfiguration</Code>
    <Message>The CORS configuration does not exist</Message>
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

/// Set CORS configuration for a bucket
///
/// PUT /{bucket}?cors
pub async fn put_cors<B: StorageBackend>(
    State(state): State<AppState<B>>,
    Path(bucket): Path<String>,
    body: Bytes,
) -> ApiResult<Response> {
    // Verify bucket exists
    let buckets = state.store.list_buckets().await;
    if !buckets.contains(&bucket) {
        return Err(ApiError::NotFound(format!("Bucket '{}' not found", bucket)));
    }

    // Parse XML body
    let xml_str = std::str::from_utf8(&body)
        .map_err(|e| ApiError::InvalidRequest(format!("Invalid UTF-8: {}", e)))?;

    let xml_config: CorsConfigurationXml = quick_xml::de::from_str(xml_str)
        .map_err(|e| ApiError::InvalidRequest(format!("Invalid XML: {}", e)))?;

    // Validate CORS rules
    for rule in &xml_config.rules {
        if rule.allowed_origins.is_empty() {
            return Err(ApiError::InvalidRequest(
                "At least one AllowedOrigin is required".to_string(),
            ));
        }
        if rule.allowed_methods.is_empty() {
            return Err(ApiError::InvalidRequest(
                "At least one AllowedMethod is required".to_string(),
            ));
        }
        // Validate methods
        for method in &rule.allowed_methods {
            match method.as_str() {
                "GET" | "PUT" | "POST" | "DELETE" | "HEAD" => {}
                other => {
                    return Err(ApiError::InvalidRequest(format!(
                        "Invalid HTTP method: {}. Allowed: GET, PUT, POST, DELETE, HEAD",
                        other
                    )));
                }
            }
        }
    }

    // Convert to internal config
    let config = from_cors_xml(&xml_config);

    // Store CORS config
    state.cors_configs.insert(bucket.clone(), config);

    tracing::info!(bucket = %bucket, rules = xml_config.rules.len(), "Bucket CORS configured");

    Ok(StatusCode::OK.into_response())
}

/// Delete CORS configuration for a bucket
///
/// DELETE /{bucket}?cors
pub async fn delete_cors<B: StorageBackend>(
    State(state): State<AppState<B>>,
    Path(bucket): Path<String>,
) -> ApiResult<Response> {
    // Verify bucket exists
    let buckets = state.store.list_buckets().await;
    if !buckets.contains(&bucket) {
        return Err(ApiError::NotFound(format!("Bucket '{}' not found", bucket)));
    }

    // Remove CORS config
    state.cors_configs.remove(&bucket);

    tracing::info!(bucket = %bucket, "Bucket CORS removed");

    Ok(StatusCode::NO_CONTENT.into_response())
}

// =============================================================================
// Conversion Helpers
// =============================================================================

fn to_cors_xml(config: &CorsConfig) -> CorsConfigurationXml {
    let rules = config
        .rules
        .iter()
        .map(|rule| CorsRuleXml {
            id: None,
            allowed_origins: rule.allowed_origins.clone(),
            allowed_methods: rule.allowed_methods.clone(),
            allowed_headers: rule.allowed_headers.clone(),
            expose_headers: rule.expose_headers.clone(),
            max_age_seconds: rule.max_age_seconds,
        })
        .collect();

    CorsConfigurationXml { rules }
}

fn from_cors_xml(xml: &CorsConfigurationXml) -> CorsConfig {
    let rules = xml
        .rules
        .iter()
        .map(|rule| CorsRule {
            allowed_origins: rule.allowed_origins.clone(),
            allowed_methods: rule.allowed_methods.clone(),
            allowed_headers: rule.allowed_headers.clone(),
            expose_headers: rule.expose_headers.clone(),
            max_age_seconds: rule.max_age_seconds,
        })
        .collect();

    CorsConfig { rules }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cors_xml_basic() {
        let config = CorsConfig {
            rules: vec![CorsRule {
                allowed_origins: vec!["*".to_string()],
                allowed_methods: vec!["GET".to_string(), "PUT".to_string()],
                allowed_headers: vec!["*".to_string()],
                expose_headers: vec!["ETag".to_string()],
                max_age_seconds: Some(3600),
            }],
        };

        let xml = to_cors_xml(&config);
        assert_eq!(xml.rules.len(), 1);
        assert_eq!(xml.rules[0].allowed_origins, vec!["*"]);
        assert_eq!(xml.rules[0].allowed_methods, vec!["GET", "PUT"]);
        assert_eq!(xml.rules[0].max_age_seconds, Some(3600));
    }

    #[test]
    fn test_parse_cors_xml() {
        let xml = CorsConfigurationXml {
            rules: vec![CorsRuleXml {
                id: Some("rule1".to_string()),
                allowed_origins: vec!["https://example.com".to_string()],
                allowed_methods: vec!["GET".to_string()],
                allowed_headers: vec!["Authorization".to_string()],
                expose_headers: vec!["x-amz-request-id".to_string()],
                max_age_seconds: Some(600),
            }],
        };

        let config = from_cors_xml(&xml);
        assert_eq!(config.rules.len(), 1);
        assert_eq!(
            config.rules[0].allowed_origins,
            vec!["https://example.com"]
        );
        assert_eq!(config.rules[0].allowed_methods, vec!["GET"]);
        assert_eq!(config.rules[0].max_age_seconds, Some(600));
    }

    #[test]
    fn test_cors_xml_multiple_rules() {
        let config = CorsConfig {
            rules: vec![
                CorsRule {
                    allowed_origins: vec!["https://app1.example.com".to_string()],
                    allowed_methods: vec!["GET".to_string()],
                    allowed_headers: vec![],
                    expose_headers: vec![],
                    max_age_seconds: None,
                },
                CorsRule {
                    allowed_origins: vec!["https://app2.example.com".to_string()],
                    allowed_methods: vec!["PUT".to_string(), "DELETE".to_string()],
                    allowed_headers: vec!["Content-Type".to_string()],
                    expose_headers: vec![],
                    max_age_seconds: Some(1800),
                },
            ],
        };

        let xml = to_cors_xml(&config);
        assert_eq!(xml.rules.len(), 2);
        assert_eq!(xml.rules[1].allowed_methods, vec!["PUT", "DELETE"]);
    }

    #[test]
    fn test_cors_xml_empty_rules() {
        let config = CorsConfig { rules: vec![] };
        let xml = to_cors_xml(&config);
        assert!(xml.rules.is_empty());
    }
}
