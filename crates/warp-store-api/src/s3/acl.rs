//! S3-compatible Bucket and Object ACL API
//!
//! Implements:
//! - GET /{bucket}?acl - Get bucket ACL
//! - PUT /{bucket}?acl - Set bucket ACL
//! - GET /{bucket}/{key}?acl - Get object ACL
//! - PUT /{bucket}/{key}?acl - Set object ACL

use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use warp_store::backend::StorageBackend;
use warp_store::ObjectKey;

use crate::error::{ApiError, ApiResult};
use crate::AppState;

// =============================================================================
// XML Types for S3 ACL API
// =============================================================================

/// Access Control Policy (S3 XML format)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename = "AccessControlPolicy")]
pub struct AccessControlPolicyXml {
    /// Owner of the resource
    #[serde(rename = "Owner")]
    pub owner: OwnerXml,

    /// Access control list
    #[serde(rename = "AccessControlList")]
    pub access_control_list: AccessControlListXml,
}

/// Owner information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnerXml {
    /// Canonical user ID
    #[serde(rename = "ID")]
    pub id: String,

    /// Display name (optional)
    #[serde(rename = "DisplayName", skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

/// Access Control List
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AccessControlListXml {
    /// List of grants
    #[serde(rename = "Grant", default)]
    pub grants: Vec<GrantXml>,
}

/// A single grant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantXml {
    /// The grantee
    #[serde(rename = "Grantee")]
    pub grantee: GranteeXml,

    /// Permission: FULL_CONTROL, WRITE, WRITE_ACP, READ, READ_ACP
    #[serde(rename = "Permission")]
    pub permission: String,
}

/// Grantee information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GranteeXml {
    /// Grantee type (attribute in S3)
    #[serde(rename = "@xmlns:xsi", skip_serializing_if = "Option::is_none")]
    pub xmlns_xsi: Option<String>,

    /// Grantee type: CanonicalUser, Group, or AmazonCustomerByEmail
    #[serde(rename = "@xsi:type", skip_serializing_if = "Option::is_none")]
    pub xsi_type: Option<String>,

    /// Canonical user ID (for CanonicalUser type)
    #[serde(rename = "ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Display name (for CanonicalUser type)
    #[serde(rename = "DisplayName", skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    /// URI (for Group type)
    #[serde(rename = "URI", skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,

    /// Email (for AmazonCustomerByEmail type)
    #[serde(rename = "EmailAddress", skip_serializing_if = "Option::is_none")]
    pub email_address: Option<String>,
}

// =============================================================================
// Internal Types
// =============================================================================

/// Internal representation of an ACL
#[derive(Debug, Clone, Default)]
pub struct AccessControlPolicy {
    /// Owner ID
    pub owner_id: String,
    /// Owner display name
    pub owner_display_name: Option<String>,
    /// List of grants
    pub grants: Vec<Grant>,
}

/// Internal representation of a grant
#[derive(Debug, Clone)]
pub struct Grant {
    /// Grantee type
    pub grantee_type: GranteeType,
    /// Grantee ID or URI
    pub grantee_id: String,
    /// Grantee display name (optional)
    pub grantee_display_name: Option<String>,
    /// Permission
    pub permission: Permission,
}

/// Types of grantees
#[derive(Debug, Clone, PartialEq)]
pub enum GranteeType {
    /// A specific user by canonical ID
    CanonicalUser,
    /// A predefined group
    Group,
    /// A user by email
    AmazonCustomerByEmail,
}

/// Permissions that can be granted
#[derive(Debug, Clone, PartialEq)]
pub enum Permission {
    /// Full control (all permissions)
    FullControl,
    /// Write objects
    Write,
    /// Write ACL
    WriteAcp,
    /// Read objects
    Read,
    /// Read ACL
    ReadAcp,
}

/// Canned ACL values
#[derive(Debug, Clone, PartialEq)]
pub enum CannedAcl {
    /// Owner gets FULL_CONTROL (default)
    Private,
    /// Owner gets FULL_CONTROL, AllUsers get READ
    PublicRead,
    /// Owner gets FULL_CONTROL, AllUsers get READ and WRITE
    PublicReadWrite,
    /// Owner gets FULL_CONTROL, AuthenticatedUsers get READ
    AuthenticatedRead,
    /// Object owner gets FULL_CONTROL, bucket owner gets READ
    BucketOwnerRead,
    /// Bucket owner gets FULL_CONTROL
    BucketOwnerFullControl,
}

impl CannedAcl {
    /// Parse from x-amz-acl header value
    pub fn from_header(value: &str) -> Option<Self> {
        match value {
            "private" => Some(Self::Private),
            "public-read" => Some(Self::PublicRead),
            "public-read-write" => Some(Self::PublicReadWrite),
            "authenticated-read" => Some(Self::AuthenticatedRead),
            "bucket-owner-read" => Some(Self::BucketOwnerRead),
            "bucket-owner-full-control" => Some(Self::BucketOwnerFullControl),
            _ => None,
        }
    }
}

impl Permission {
    fn as_str(&self) -> &'static str {
        match self {
            Permission::FullControl => "FULL_CONTROL",
            Permission::Write => "WRITE",
            Permission::WriteAcp => "WRITE_ACP",
            Permission::Read => "READ",
            Permission::ReadAcp => "READ_ACP",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "FULL_CONTROL" => Some(Self::FullControl),
            "WRITE" => Some(Self::Write),
            "WRITE_ACP" => Some(Self::WriteAcp),
            "READ" => Some(Self::Read),
            "READ_ACP" => Some(Self::ReadAcp),
            _ => None,
        }
    }
}

// Well-known group URIs
const ALL_USERS_GROUP: &str = "http://acs.amazonaws.com/groups/global/AllUsers";
const AUTHENTICATED_USERS_GROUP: &str = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers";

// =============================================================================
// Bucket ACL Handlers
// =============================================================================

/// Get ACL for a bucket
///
/// GET /{bucket}?acl
pub async fn get_bucket_acl<B: StorageBackend>(
    State(state): State<AppState<B>>,
    Path(bucket): Path<String>,
) -> ApiResult<Response> {
    // Verify bucket exists
    let buckets = state.store.list_buckets().await;
    if !buckets.contains(&bucket) {
        return Err(ApiError::NotFound(format!("Bucket '{}' not found", bucket)));
    }

    // Get ACL from state or return default (private)
    let acl = state
        .bucket_acls
        .get(&bucket)
        .map(|r| r.value().clone())
        .unwrap_or_else(|| default_acl(&bucket));

    let xml_config = to_acl_xml(&acl);
    let xml = quick_xml::se::to_string(&xml_config)
        .map_err(|e| ApiError::Internal(format!("XML serialization error: {}", e)))?;

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/xml")],
        format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}", xml),
    )
        .into_response())
}

/// Set ACL for a bucket
///
/// PUT /{bucket}?acl
pub async fn put_bucket_acl<B: StorageBackend>(
    State(state): State<AppState<B>>,
    Path(bucket): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Response> {
    // Verify bucket exists
    let buckets = state.store.list_buckets().await;
    if !buckets.contains(&bucket) {
        return Err(ApiError::NotFound(format!("Bucket '{}' not found", bucket)));
    }

    // Check for canned ACL header
    if let Some(canned_acl) = headers.get("x-amz-acl") {
        let canned_str = canned_acl.to_str()
            .map_err(|_| ApiError::InvalidRequest("Invalid x-amz-acl header".to_string()))?;

        let canned = CannedAcl::from_header(canned_str)
            .ok_or_else(|| ApiError::InvalidRequest(format!("Invalid canned ACL: {}", canned_str)))?;

        let acl = canned_acl_to_policy(&bucket, canned);
        state.bucket_acls.insert(bucket.clone(), acl);

        tracing::info!(bucket = %bucket, acl = canned_str, "Bucket ACL updated (canned)");
        return Ok(StatusCode::OK.into_response());
    }

    // Parse XML body
    if body.is_empty() {
        return Err(ApiError::InvalidRequest(
            "ACL body is required when x-amz-acl header is not provided".to_string(),
        ));
    }

    let xml_str = std::str::from_utf8(&body)
        .map_err(|e| ApiError::InvalidRequest(format!("Invalid UTF-8: {}", e)))?;

    let xml_config: AccessControlPolicyXml = quick_xml::de::from_str(xml_str)
        .map_err(|e| ApiError::InvalidRequest(format!("Invalid XML: {}", e)))?;

    // Validate and convert to internal format
    let acl = from_acl_xml(&xml_config)?;

    // Store ACL
    state.bucket_acls.insert(bucket.clone(), acl);

    tracing::info!(bucket = %bucket, "Bucket ACL updated");

    Ok(StatusCode::OK.into_response())
}

// =============================================================================
// Object ACL Handlers
// =============================================================================

/// Get ACL for an object
///
/// GET /{bucket}/{key}?acl
pub async fn get_object_acl<B: StorageBackend>(
    State(state): State<AppState<B>>,
    Path((bucket, key)): Path<(String, String)>,
) -> ApiResult<Response> {
    // Verify object exists
    let object_key = ObjectKey::new(&bucket, &key)?;
    let _ = state.store.head(&object_key).await?;

    // Get ACL from state or return default (private)
    let acl_key = (bucket.clone(), key.clone());
    let acl = state
        .object_acls
        .get(&acl_key)
        .map(|r| r.value().clone())
        .unwrap_or_else(|| default_acl(&bucket));

    let xml_config = to_acl_xml(&acl);
    let xml = quick_xml::se::to_string(&xml_config)
        .map_err(|e| ApiError::Internal(format!("XML serialization error: {}", e)))?;

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/xml")],
        format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}", xml),
    )
        .into_response())
}

/// Set ACL for an object
///
/// PUT /{bucket}/{key}?acl
pub async fn put_object_acl<B: StorageBackend>(
    State(state): State<AppState<B>>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Response> {
    // Verify object exists
    let object_key = ObjectKey::new(&bucket, &key)?;
    let _ = state.store.head(&object_key).await?;

    let acl_key = (bucket.clone(), key.clone());

    // Check for canned ACL header
    if let Some(canned_acl) = headers.get("x-amz-acl") {
        let canned_str = canned_acl.to_str()
            .map_err(|_| ApiError::InvalidRequest("Invalid x-amz-acl header".to_string()))?;

        let canned = CannedAcl::from_header(canned_str)
            .ok_or_else(|| ApiError::InvalidRequest(format!("Invalid canned ACL: {}", canned_str)))?;

        let acl = canned_acl_to_policy(&bucket, canned);
        state.object_acls.insert(acl_key, acl);

        tracing::info!(bucket = %bucket, key = %key, acl = canned_str, "Object ACL updated (canned)");
        return Ok(StatusCode::OK.into_response());
    }

    // Parse XML body
    if body.is_empty() {
        return Err(ApiError::InvalidRequest(
            "ACL body is required when x-amz-acl header is not provided".to_string(),
        ));
    }

    let xml_str = std::str::from_utf8(&body)
        .map_err(|e| ApiError::InvalidRequest(format!("Invalid UTF-8: {}", e)))?;

    let xml_config: AccessControlPolicyXml = quick_xml::de::from_str(xml_str)
        .map_err(|e| ApiError::InvalidRequest(format!("Invalid XML: {}", e)))?;

    // Validate and convert to internal format
    let acl = from_acl_xml(&xml_config)?;

    // Store ACL
    state.object_acls.insert(acl_key, acl);

    tracing::info!(bucket = %bucket, key = %key, "Object ACL updated");

    Ok(StatusCode::OK.into_response())
}

// =============================================================================
// Conversion Helpers
// =============================================================================

fn default_acl(owner_id: &str) -> AccessControlPolicy {
    AccessControlPolicy {
        owner_id: owner_id.to_string(),
        owner_display_name: None,
        grants: vec![Grant {
            grantee_type: GranteeType::CanonicalUser,
            grantee_id: owner_id.to_string(),
            grantee_display_name: None,
            permission: Permission::FullControl,
        }],
    }
}

fn canned_acl_to_policy(owner_id: &str, canned: CannedAcl) -> AccessControlPolicy {
    let mut grants = vec![Grant {
        grantee_type: GranteeType::CanonicalUser,
        grantee_id: owner_id.to_string(),
        grantee_display_name: None,
        permission: Permission::FullControl,
    }];

    match canned {
        CannedAcl::Private => {}
        CannedAcl::PublicRead => {
            grants.push(Grant {
                grantee_type: GranteeType::Group,
                grantee_id: ALL_USERS_GROUP.to_string(),
                grantee_display_name: None,
                permission: Permission::Read,
            });
        }
        CannedAcl::PublicReadWrite => {
            grants.push(Grant {
                grantee_type: GranteeType::Group,
                grantee_id: ALL_USERS_GROUP.to_string(),
                grantee_display_name: None,
                permission: Permission::Read,
            });
            grants.push(Grant {
                grantee_type: GranteeType::Group,
                grantee_id: ALL_USERS_GROUP.to_string(),
                grantee_display_name: None,
                permission: Permission::Write,
            });
        }
        CannedAcl::AuthenticatedRead => {
            grants.push(Grant {
                grantee_type: GranteeType::Group,
                grantee_id: AUTHENTICATED_USERS_GROUP.to_string(),
                grantee_display_name: None,
                permission: Permission::Read,
            });
        }
        CannedAcl::BucketOwnerRead | CannedAcl::BucketOwnerFullControl => {
            // These are same as private for now since bucket owner is the same
        }
    }

    AccessControlPolicy {
        owner_id: owner_id.to_string(),
        owner_display_name: None,
        grants,
    }
}

fn to_acl_xml(acl: &AccessControlPolicy) -> AccessControlPolicyXml {
    let grants = acl
        .grants
        .iter()
        .map(|grant| {
            let (xsi_type, id, uri) = match &grant.grantee_type {
                GranteeType::CanonicalUser => (
                    Some("CanonicalUser".to_string()),
                    Some(grant.grantee_id.clone()),
                    None,
                ),
                GranteeType::Group => (
                    Some("Group".to_string()),
                    None,
                    Some(grant.grantee_id.clone()),
                ),
                GranteeType::AmazonCustomerByEmail => (
                    Some("AmazonCustomerByEmail".to_string()),
                    None,
                    None,
                ),
            };

            GrantXml {
                grantee: GranteeXml {
                    xmlns_xsi: Some("http://www.w3.org/2001/XMLSchema-instance".to_string()),
                    xsi_type,
                    id,
                    display_name: grant.grantee_display_name.clone(),
                    uri,
                    email_address: None,
                },
                permission: grant.permission.as_str().to_string(),
            }
        })
        .collect();

    AccessControlPolicyXml {
        owner: OwnerXml {
            id: acl.owner_id.clone(),
            display_name: acl.owner_display_name.clone(),
        },
        access_control_list: AccessControlListXml { grants },
    }
}

fn from_acl_xml(xml: &AccessControlPolicyXml) -> ApiResult<AccessControlPolicy> {
    let grants = xml
        .access_control_list
        .grants
        .iter()
        .map(|grant| {
            let permission = Permission::from_str(&grant.permission).ok_or_else(|| {
                ApiError::InvalidRequest(format!("Invalid permission: {}", grant.permission))
            })?;

            let (grantee_type, grantee_id) = if let Some(ref id) = grant.grantee.id {
                (GranteeType::CanonicalUser, id.clone())
            } else if let Some(ref uri) = grant.grantee.uri {
                (GranteeType::Group, uri.clone())
            } else if let Some(ref email) = grant.grantee.email_address {
                (GranteeType::AmazonCustomerByEmail, email.clone())
            } else {
                return Err(ApiError::InvalidRequest(
                    "Grantee must have ID, URI, or EmailAddress".to_string(),
                ));
            };

            Ok(Grant {
                grantee_type,
                grantee_id,
                grantee_display_name: grant.grantee.display_name.clone(),
                permission,
            })
        })
        .collect::<ApiResult<Vec<_>>>()?;

    Ok(AccessControlPolicy {
        owner_id: xml.owner.id.clone(),
        owner_display_name: xml.owner.display_name.clone(),
        grants,
    })
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_acl() {
        let acl = default_acl("user123");
        assert_eq!(acl.owner_id, "user123");
        assert_eq!(acl.grants.len(), 1);
        assert_eq!(acl.grants[0].permission, Permission::FullControl);
    }

    #[test]
    fn test_canned_acl_private() {
        let acl = canned_acl_to_policy("owner", CannedAcl::Private);
        assert_eq!(acl.grants.len(), 1);
        assert_eq!(acl.grants[0].permission, Permission::FullControl);
    }

    #[test]
    fn test_canned_acl_public_read() {
        let acl = canned_acl_to_policy("owner", CannedAcl::PublicRead);
        assert_eq!(acl.grants.len(), 2);
        assert_eq!(acl.grants[1].grantee_id, ALL_USERS_GROUP);
        assert_eq!(acl.grants[1].permission, Permission::Read);
    }

    #[test]
    fn test_canned_acl_public_read_write() {
        let acl = canned_acl_to_policy("owner", CannedAcl::PublicReadWrite);
        assert_eq!(acl.grants.len(), 3);
        // Owner FULL_CONTROL + AllUsers READ + AllUsers WRITE
    }

    #[test]
    fn test_to_acl_xml() {
        let acl = AccessControlPolicy {
            owner_id: "owner123".to_string(),
            owner_display_name: Some("Owner Name".to_string()),
            grants: vec![Grant {
                grantee_type: GranteeType::CanonicalUser,
                grantee_id: "owner123".to_string(),
                grantee_display_name: None,
                permission: Permission::FullControl,
            }],
        };

        let xml = to_acl_xml(&acl);
        assert_eq!(xml.owner.id, "owner123");
        assert_eq!(xml.owner.display_name, Some("Owner Name".to_string()));
        assert_eq!(xml.access_control_list.grants.len(), 1);
        assert_eq!(
            xml.access_control_list.grants[0].permission,
            "FULL_CONTROL"
        );
    }

    #[test]
    fn test_from_acl_xml() {
        let xml = AccessControlPolicyXml {
            owner: OwnerXml {
                id: "user456".to_string(),
                display_name: None,
            },
            access_control_list: AccessControlListXml {
                grants: vec![GrantXml {
                    grantee: GranteeXml {
                        xmlns_xsi: None,
                        xsi_type: Some("CanonicalUser".to_string()),
                        id: Some("user456".to_string()),
                        display_name: None,
                        uri: None,
                        email_address: None,
                    },
                    permission: "READ".to_string(),
                }],
            },
        };

        let acl = from_acl_xml(&xml).unwrap();
        assert_eq!(acl.owner_id, "user456");
        assert_eq!(acl.grants.len(), 1);
        assert_eq!(acl.grants[0].permission, Permission::Read);
    }

    #[test]
    fn test_canned_acl_from_header() {
        assert_eq!(
            CannedAcl::from_header("private"),
            Some(CannedAcl::Private)
        );
        assert_eq!(
            CannedAcl::from_header("public-read"),
            Some(CannedAcl::PublicRead)
        );
        assert_eq!(
            CannedAcl::from_header("public-read-write"),
            Some(CannedAcl::PublicReadWrite)
        );
        assert_eq!(CannedAcl::from_header("invalid"), None);
    }

    #[test]
    fn test_permission_from_str() {
        assert_eq!(
            Permission::from_str("FULL_CONTROL"),
            Some(Permission::FullControl)
        );
        assert_eq!(Permission::from_str("READ"), Some(Permission::Read));
        assert_eq!(Permission::from_str("WRITE"), Some(Permission::Write));
        assert_eq!(Permission::from_str("INVALID"), None);
    }
}
