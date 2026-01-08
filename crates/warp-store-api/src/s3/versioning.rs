//! S3-compatible Bucket Versioning API
//!
//! Implements:
//! - GET /{bucket}?versioning - Get bucket versioning status
//! - PUT /{bucket}?versioning - Set bucket versioning status

use axum::{
    extract::{Path, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use warp_store::backend::StorageBackend;
use warp_store::version::VersioningMode;

use crate::AppState;
use crate::error::{ApiError, ApiResult};

// =============================================================================
// XML Types for S3 Versioning API
// =============================================================================

/// Versioning configuration (S3 XML format)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename = "VersioningConfiguration")]
#[derive(Default)]
pub struct VersioningConfigurationXml {
    /// Status: Enabled or Suspended (omitted if never enabled)
    #[serde(rename = "Status", skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,

    /// MFA Delete status (not implemented, but included for S3 compatibility)
    #[serde(rename = "MfaDelete", skip_serializing_if = "Option::is_none")]
    pub mfa_delete: Option<String>,
}

// =============================================================================
// Versioning Handlers
// =============================================================================

/// Get versioning status for a bucket
///
/// GET /{bucket}?versioning
pub async fn get_versioning<B: StorageBackend>(
    State(state): State<AppState<B>>,
    Path(bucket): Path<String>,
) -> ApiResult<Response> {
    // Verify bucket exists
    let buckets = state.store.list_buckets().await;
    if !buckets.contains(&bucket) {
        return Err(ApiError::NotFound(format!("Bucket '{}' not found", bucket)));
    }

    // Get versioning config from state
    let mode = state
        .versioning_configs
        .get(&bucket)
        .map(|r| *r.value())
        .unwrap_or(VersioningMode::Disabled);

    let xml_config = to_versioning_xml(mode);
    let xml = quick_xml::se::to_string(&xml_config)
        .map_err(|e| ApiError::Internal(format!("XML serialization error: {}", e)))?;

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/xml")],
        format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}", xml),
    )
        .into_response())
}

/// Set versioning status for a bucket
///
/// PUT /{bucket}?versioning
pub async fn put_versioning<B: StorageBackend>(
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

    let xml_config: VersioningConfigurationXml = quick_xml::de::from_str(xml_str)
        .map_err(|e| ApiError::InvalidRequest(format!("Invalid XML: {}", e)))?;

    // Convert to internal mode
    let mode = from_versioning_xml(&xml_config)?;

    // Check if we're trying to disable versioning (not allowed)
    let current_mode = state
        .versioning_configs
        .get(&bucket)
        .map(|r| *r.value())
        .unwrap_or(VersioningMode::Disabled);

    if current_mode.was_enabled() && mode == VersioningMode::Disabled {
        return Err(ApiError::InvalidRequest(
            "Cannot disable versioning once enabled. Use Suspended instead.".to_string(),
        ));
    }

    // Store versioning config
    if mode == VersioningMode::Disabled {
        state.versioning_configs.remove(&bucket);
    } else {
        state.versioning_configs.insert(bucket.clone(), mode);
    }

    tracing::info!(bucket = %bucket, mode = ?mode, "Bucket versioning updated");

    Ok(StatusCode::OK.into_response())
}

// =============================================================================
// Conversion Helpers
// =============================================================================

fn to_versioning_xml(mode: VersioningMode) -> VersioningConfigurationXml {
    match mode {
        VersioningMode::Disabled => VersioningConfigurationXml {
            status: None,
            mfa_delete: None,
        },
        VersioningMode::Enabled => VersioningConfigurationXml {
            status: Some("Enabled".to_string()),
            mfa_delete: None,
        },
        VersioningMode::Suspended => VersioningConfigurationXml {
            status: Some("Suspended".to_string()),
            mfa_delete: None,
        },
    }
}

fn from_versioning_xml(xml: &VersioningConfigurationXml) -> ApiResult<VersioningMode> {
    match xml.status.as_deref() {
        None => Ok(VersioningMode::Disabled),
        Some("Enabled") => Ok(VersioningMode::Enabled),
        Some("Suspended") => Ok(VersioningMode::Suspended),
        Some(other) => Err(ApiError::InvalidRequest(format!(
            "Invalid versioning status: {}. Must be 'Enabled' or 'Suspended'.",
            other
        ))),
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_versioning_xml_disabled() {
        let xml = to_versioning_xml(VersioningMode::Disabled);
        assert!(xml.status.is_none());
    }

    #[test]
    fn test_versioning_xml_enabled() {
        let xml = to_versioning_xml(VersioningMode::Enabled);
        assert_eq!(xml.status, Some("Enabled".to_string()));
    }

    #[test]
    fn test_versioning_xml_suspended() {
        let xml = to_versioning_xml(VersioningMode::Suspended);
        assert_eq!(xml.status, Some("Suspended".to_string()));
    }

    #[test]
    fn test_parse_versioning_xml() {
        let xml = VersioningConfigurationXml {
            status: Some("Enabled".to_string()),
            mfa_delete: None,
        };
        let mode = from_versioning_xml(&xml).unwrap();
        assert_eq!(mode, VersioningMode::Enabled);
    }

    #[test]
    fn test_parse_versioning_xml_suspended() {
        let xml = VersioningConfigurationXml {
            status: Some("Suspended".to_string()),
            mfa_delete: None,
        };
        let mode = from_versioning_xml(&xml).unwrap();
        assert_eq!(mode, VersioningMode::Suspended);
    }

    #[test]
    fn test_parse_versioning_xml_empty() {
        let xml = VersioningConfigurationXml {
            status: None,
            mfa_delete: None,
        };
        let mode = from_versioning_xml(&xml).unwrap();
        assert_eq!(mode, VersioningMode::Disabled);
    }
}
