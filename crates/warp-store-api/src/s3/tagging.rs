//! S3-compatible Bucket and Object Tagging API
//!
//! Implements:
//! - GET /{bucket}?tagging - Get bucket tags
//! - PUT /{bucket}?tagging - Set bucket tags
//! - DELETE /{bucket}?tagging - Delete bucket tags
//! - GET /{bucket}/{key}?tagging - Get object tags
//! - PUT /{bucket}/{key}?tagging - Set object tags
//! - DELETE /{bucket}/{key}?tagging - Delete object tags

use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use warp_store::backend::StorageBackend;
use warp_store::ObjectKey;

use crate::error::{ApiError, ApiResult};
use crate::AppState;

// =============================================================================
// XML Types for S3 Tagging API
// =============================================================================

/// Tagging configuration (S3 XML format)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename = "Tagging")]
pub struct TaggingXml {
    /// Tag set
    #[serde(rename = "TagSet")]
    pub tag_set: TagSetXml,
}

/// Tag set containing tags
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TagSetXml {
    /// List of tags
    #[serde(rename = "Tag", default)]
    pub tags: Vec<TagXml>,
}

/// A single tag
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagXml {
    /// Tag key
    #[serde(rename = "Key")]
    pub key: String,

    /// Tag value
    #[serde(rename = "Value")]
    pub value: String,
}

// =============================================================================
// Internal Types
// =============================================================================

/// Internal representation of tags (key -> value)
pub type TagSet = Vec<(String, String)>;

// =============================================================================
// Bucket Tagging Handlers
// =============================================================================

/// Get tags for a bucket
///
/// GET /{bucket}?tagging
pub async fn get_bucket_tagging<B: StorageBackend>(
    State(state): State<AppState<B>>,
    Path(bucket): Path<String>,
) -> ApiResult<Response> {
    // Verify bucket exists
    let buckets = state.store.list_buckets().await;
    if !buckets.contains(&bucket) {
        return Err(ApiError::NotFound(format!("Bucket '{}' not found", bucket)));
    }

    // Get tags from state
    let tags = state
        .bucket_tags
        .get(&bucket)
        .map(|r| r.value().clone())
        .unwrap_or_default();

    let xml_config = to_tagging_xml(&tags);
    let xml = quick_xml::se::to_string(&xml_config)
        .map_err(|e| ApiError::Internal(format!("XML serialization error: {}", e)))?;

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/xml")],
        format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}", xml),
    )
        .into_response())
}

/// Set tags for a bucket
///
/// PUT /{bucket}?tagging
pub async fn put_bucket_tagging<B: StorageBackend>(
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

    let xml_config: TaggingXml = quick_xml::de::from_str(xml_str)
        .map_err(|e| ApiError::InvalidRequest(format!("Invalid XML: {}", e)))?;

    // Validate tags
    validate_tags(&xml_config.tag_set.tags)?;

    // Convert to internal format
    let tags = from_tagging_xml(&xml_config);

    // Store tags
    if tags.is_empty() {
        state.bucket_tags.remove(&bucket);
    } else {
        state.bucket_tags.insert(bucket.clone(), tags);
    }

    tracing::info!(bucket = %bucket, "Bucket tags updated");

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Delete tags for a bucket
///
/// DELETE /{bucket}?tagging
pub async fn delete_bucket_tagging<B: StorageBackend>(
    State(state): State<AppState<B>>,
    Path(bucket): Path<String>,
) -> ApiResult<Response> {
    // Verify bucket exists
    let buckets = state.store.list_buckets().await;
    if !buckets.contains(&bucket) {
        return Err(ApiError::NotFound(format!("Bucket '{}' not found", bucket)));
    }

    // Remove tags
    state.bucket_tags.remove(&bucket);

    tracing::info!(bucket = %bucket, "Bucket tags removed");

    Ok(StatusCode::NO_CONTENT.into_response())
}

// =============================================================================
// Object Tagging Handlers
// =============================================================================

/// Get tags for an object
///
/// GET /{bucket}/{key}?tagging
pub async fn get_object_tagging<B: StorageBackend>(
    State(state): State<AppState<B>>,
    Path((bucket, key)): Path<(String, String)>,
) -> ApiResult<Response> {
    // Verify object exists
    let object_key = ObjectKey::new(&bucket, &key)?;
    let _ = state.store.head(&object_key).await?;

    // Get tags from state
    let tag_key = (bucket.clone(), key.clone());
    let tags = state
        .object_tags
        .get(&tag_key)
        .map(|r| r.value().clone())
        .unwrap_or_default();

    let xml_config = to_tagging_xml(&tags);
    let xml = quick_xml::se::to_string(&xml_config)
        .map_err(|e| ApiError::Internal(format!("XML serialization error: {}", e)))?;

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/xml")],
        format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}", xml),
    )
        .into_response())
}

/// Set tags for an object
///
/// PUT /{bucket}/{key}?tagging
pub async fn put_object_tagging<B: StorageBackend>(
    State(state): State<AppState<B>>,
    Path((bucket, key)): Path<(String, String)>,
    body: Bytes,
) -> ApiResult<Response> {
    // Verify object exists
    let object_key = ObjectKey::new(&bucket, &key)?;
    let _ = state.store.head(&object_key).await?;

    // Parse XML body
    let xml_str = std::str::from_utf8(&body)
        .map_err(|e| ApiError::InvalidRequest(format!("Invalid UTF-8: {}", e)))?;

    let xml_config: TaggingXml = quick_xml::de::from_str(xml_str)
        .map_err(|e| ApiError::InvalidRequest(format!("Invalid XML: {}", e)))?;

    // Validate tags
    validate_tags(&xml_config.tag_set.tags)?;

    // Convert to internal format
    let tags = from_tagging_xml(&xml_config);

    // Store tags
    let tag_key = (bucket.clone(), key.clone());
    if tags.is_empty() {
        state.object_tags.remove(&tag_key);
    } else {
        state.object_tags.insert(tag_key, tags);
    }

    tracing::info!(bucket = %bucket, key = %key, "Object tags updated");

    Ok(StatusCode::OK.into_response())
}

/// Delete tags for an object
///
/// DELETE /{bucket}/{key}?tagging
pub async fn delete_object_tagging<B: StorageBackend>(
    State(state): State<AppState<B>>,
    Path((bucket, key)): Path<(String, String)>,
) -> ApiResult<Response> {
    // Verify object exists
    let object_key = ObjectKey::new(&bucket, &key)?;
    let _ = state.store.head(&object_key).await?;

    // Remove tags
    let tag_key = (bucket.clone(), key.clone());
    state.object_tags.remove(&tag_key);

    tracing::info!(bucket = %bucket, key = %key, "Object tags removed");

    Ok(StatusCode::NO_CONTENT.into_response())
}

// =============================================================================
// Validation and Conversion Helpers
// =============================================================================

/// Validate tag keys and values per S3 requirements
fn validate_tags(tags: &[TagXml]) -> ApiResult<()> {
    // S3 allows up to 50 tags per object
    if tags.len() > 50 {
        return Err(ApiError::InvalidRequest(
            "Maximum of 50 tags allowed".to_string(),
        ));
    }

    for tag in tags {
        // Key must be 1-128 characters
        if tag.key.is_empty() || tag.key.len() > 128 {
            return Err(ApiError::InvalidRequest(format!(
                "Tag key must be 1-128 characters, got {}",
                tag.key.len()
            )));
        }

        // Value must be 0-256 characters
        if tag.value.len() > 256 {
            return Err(ApiError::InvalidRequest(format!(
                "Tag value must be 0-256 characters, got {}",
                tag.value.len()
            )));
        }

        // Keys cannot start with "aws:"
        if tag.key.starts_with("aws:") {
            return Err(ApiError::InvalidRequest(
                "Tag keys cannot start with 'aws:'".to_string(),
            ));
        }
    }

    // Check for duplicate keys
    let mut seen_keys = std::collections::HashSet::new();
    for tag in tags {
        if !seen_keys.insert(&tag.key) {
            return Err(ApiError::InvalidRequest(format!(
                "Duplicate tag key: {}",
                tag.key
            )));
        }
    }

    Ok(())
}

fn to_tagging_xml(tags: &TagSet) -> TaggingXml {
    let tags: Vec<TagXml> = tags
        .iter()
        .map(|(key, value)| TagXml {
            key: key.clone(),
            value: value.clone(),
        })
        .collect();

    TaggingXml {
        tag_set: TagSetXml { tags },
    }
}

fn from_tagging_xml(xml: &TaggingXml) -> TagSet {
    xml.tag_set
        .tags
        .iter()
        .map(|tag| (tag.key.clone(), tag.value.clone()))
        .collect()
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tagging_xml_basic() {
        let tags = vec![
            ("Environment".to_string(), "Production".to_string()),
            ("Project".to_string(), "MyApp".to_string()),
        ];

        let xml = to_tagging_xml(&tags);
        assert_eq!(xml.tag_set.tags.len(), 2);
        assert_eq!(xml.tag_set.tags[0].key, "Environment");
        assert_eq!(xml.tag_set.tags[0].value, "Production");
    }

    #[test]
    fn test_parse_tagging_xml() {
        let xml = TaggingXml {
            tag_set: TagSetXml {
                tags: vec![
                    TagXml {
                        key: "Cost-Center".to_string(),
                        value: "12345".to_string(),
                    },
                    TagXml {
                        key: "Owner".to_string(),
                        value: "admin@example.com".to_string(),
                    },
                ],
            },
        };

        let tags = from_tagging_xml(&xml);
        assert_eq!(tags.len(), 2);
        assert_eq!(tags[0], ("Cost-Center".to_string(), "12345".to_string()));
    }

    #[test]
    fn test_tagging_xml_empty() {
        let tags: TagSet = vec![];
        let xml = to_tagging_xml(&tags);
        assert!(xml.tag_set.tags.is_empty());
    }

    #[test]
    fn test_validate_tags_ok() {
        let tags = vec![
            TagXml {
                key: "Name".to_string(),
                value: "Test".to_string(),
            },
        ];
        assert!(validate_tags(&tags).is_ok());
    }

    #[test]
    fn test_validate_tags_empty_key() {
        let tags = vec![
            TagXml {
                key: "".to_string(),
                value: "Test".to_string(),
            },
        ];
        assert!(validate_tags(&tags).is_err());
    }

    #[test]
    fn test_validate_tags_aws_prefix() {
        let tags = vec![
            TagXml {
                key: "aws:reserved".to_string(),
                value: "value".to_string(),
            },
        ];
        let result = validate_tags(&tags);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("aws:"));
    }

    #[test]
    fn test_validate_tags_duplicate_keys() {
        let tags = vec![
            TagXml {
                key: "Name".to_string(),
                value: "Value1".to_string(),
            },
            TagXml {
                key: "Name".to_string(),
                value: "Value2".to_string(),
            },
        ];
        let result = validate_tags(&tags);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Duplicate"));
    }

    #[test]
    fn test_validate_tags_too_many() {
        let tags: Vec<TagXml> = (0..51)
            .map(|i| TagXml {
                key: format!("key{}", i),
                value: "value".to_string(),
            })
            .collect();
        let result = validate_tags(&tags);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("50"));
    }
}
