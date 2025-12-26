//! S3-compatible API endpoints
//!
//! Implements the core S3 REST API:
//! - Object operations: GET, PUT, DELETE, HEAD
//! - Bucket operations: GET (list), PUT (create), DELETE
//! - ListObjectsV2 with prefix and delimiter support
//! - SelectObjectContent (S3 Select) for SQL queries on objects

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, head, post, put},
    Router,
};
use bytes::Bytes;
use serde::Deserialize;

use warp_store::backend::StorageBackend;
use warp_store::{ObjectKey, ObjectData, PutOptions, ListOptions};

use crate::error::ApiResult;
use crate::AppState;

#[cfg(feature = "s3-select")]
mod select;

mod acl;
mod cors;
mod encryption;
mod lifecycle;
mod notifications;
mod object_lock;
mod policy;
mod replication;
mod tagging;
mod versioning;

#[cfg(feature = "s3-select")]
pub use select::{SelectObjectContentRequest, SelectQuery};

pub use acl::{AccessControlPolicy, AccessControlPolicyXml};
pub use cors::CorsConfigurationXml;
pub use encryption::ServerSideEncryptionConfigurationXml;
pub use lifecycle::{LifecycleConfigurationXml, LifecycleQuery};
pub use notifications::NotificationConfigurationXml;
pub use object_lock::{ObjectLockConfigurationXml, RetentionXml, LegalHoldXml};
pub use policy::{BucketPolicyManager, PolicyDocument, get_s3_action};
pub use replication::ReplicationConfigurationXml;
pub use tagging::TaggingXml;
pub use versioning::VersioningConfigurationXml;

/// Create S3 API routes
pub fn routes<B: StorageBackend>(state: AppState<B>) -> Router {
    Router::new()
        // Bucket operations
        .route("/", get(list_buckets::<B>))
        .route("/{bucket}", put(create_bucket::<B>))
        .route("/{bucket}", delete(delete_bucket::<B>))
        .route("/{bucket}", get(list_objects::<B>))
        // Object operations
        .route("/{bucket}/{*key}", get(get_object::<B>))
        .route("/{bucket}/{*key}", put(put_or_upload_part::<B>))
        .route("/{bucket}/{*key}", delete(delete_or_abort::<B>))
        .route("/{bucket}/{*key}", head(head_object::<B>))
        .route("/{bucket}/{*key}", post(multipart_handler::<B>))
        .with_state(state)
}

/// List all buckets
async fn list_buckets<B: StorageBackend>(
    State(state): State<AppState<B>>,
) -> ApiResult<Response> {
    let buckets = state.store.list_buckets().await;

    let bucket_xml: String = buckets
        .iter()
        .map(|name| format!("<Bucket><Name>{}</Name></Bucket>", name))
        .collect();

    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult>
    <Buckets>{}</Buckets>
</ListAllMyBucketsResult>"#,
        bucket_xml
    );

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/xml")],
        xml,
    ).into_response())
}

/// Query parameters for bucket PUT operations
#[derive(Debug, Deserialize, Default)]
struct BucketPutQuery {
    /// ACL query parameter (presence indicates ACL request)
    acl: Option<String>,
    /// CORS query parameter (presence indicates CORS request)
    cors: Option<String>,
    /// Lifecycle query parameter (presence indicates lifecycle request)
    lifecycle: Option<String>,
    /// Notification query parameter (presence indicates notification request)
    notification: Option<String>,
    /// Policy query parameter (presence indicates policy request)
    policy: Option<String>,
    /// Object Lock query parameter (presence indicates object-lock request)
    #[serde(rename = "object-lock")]
    object_lock: Option<String>,
    /// Tagging query parameter (presence indicates tagging request)
    tagging: Option<String>,
    /// Versioning query parameter (presence indicates versioning request)
    versioning: Option<String>,
    /// Encryption query parameter (presence indicates encryption request)
    encryption: Option<String>,
    /// Replication query parameter (presence indicates replication request)
    replication: Option<String>,
}

/// Create a bucket or set bucket configuration
async fn create_bucket<B: StorageBackend>(
    State(state): State<AppState<B>>,
    Path(bucket): Path<String>,
    Query(query): Query<BucketPutQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Response> {
    // Check if this is an ACL request
    if query.acl.is_some() {
        return acl::put_bucket_acl(State(state), Path(bucket), headers, body).await;
    }

    // Check if this is a CORS request
    if query.cors.is_some() {
        return cors::put_cors(State(state), Path(bucket), body).await;
    }

    // Check if this is a lifecycle request
    if query.lifecycle.is_some() {
        return lifecycle::put_lifecycle(State(state), Path(bucket), body).await;
    }

    // Check if this is a notification request
    if query.notification.is_some() {
        return notifications::put_notifications(State(state), Path(bucket), body).await;
    }

    // Check if this is a policy request
    if query.policy.is_some() {
        return policy::put_policy(State(state), Path(bucket), body).await;
    }

    // Check if this is an object-lock request
    if query.object_lock.is_some() {
        return object_lock::put_object_lock_config(State(state), Path(bucket), body).await;
    }

    // Check if this is a tagging request
    if query.tagging.is_some() {
        return tagging::put_bucket_tagging(State(state), Path(bucket), body).await;
    }

    // Check if this is a versioning request
    if query.versioning.is_some() {
        return versioning::put_versioning(State(state), Path(bucket), body).await;
    }

    // Check if this is an encryption request
    if query.encryption.is_some() {
        return encryption::put_encryption(State(state), Path(bucket), body).await;
    }

    // Check if this is a replication request
    if query.replication.is_some() {
        return replication::put_replication(State(state), Path(bucket), body).await;
    }

    state.store.create_bucket(&bucket, Default::default()).await?;

    Ok((
        StatusCode::OK,
        [(header::LOCATION, format!("/{}", bucket))],
        "",
    ).into_response())
}

/// Query parameters for bucket DELETE operations
#[derive(Debug, Deserialize, Default)]
struct BucketDeleteQuery {
    /// CORS query parameter (presence indicates CORS request)
    cors: Option<String>,
    /// Lifecycle query parameter (presence indicates lifecycle request)
    lifecycle: Option<String>,
    /// Notification query parameter (presence indicates notification request)
    notification: Option<String>,
    /// Policy query parameter (presence indicates policy request)
    policy: Option<String>,
    /// Tagging query parameter (presence indicates tagging request)
    tagging: Option<String>,
    /// Encryption query parameter (presence indicates encryption request)
    encryption: Option<String>,
    /// Replication query parameter (presence indicates replication request)
    replication: Option<String>,
}

/// Delete a bucket or delete bucket configuration
async fn delete_bucket<B: StorageBackend>(
    State(state): State<AppState<B>>,
    Path(bucket): Path<String>,
    Query(query): Query<BucketDeleteQuery>,
) -> ApiResult<Response> {
    // Check if this is a CORS request
    if query.cors.is_some() {
        return cors::delete_cors(State(state), Path(bucket)).await;
    }

    // Check if this is a lifecycle request
    if query.lifecycle.is_some() {
        return lifecycle::delete_lifecycle(State(state), Path(bucket)).await;
    }

    // Check if this is a notification request
    if query.notification.is_some() {
        return notifications::delete_notifications(State(state), Path(bucket)).await;
    }

    // Check if this is a policy request
    if query.policy.is_some() {
        return policy::delete_policy(State(state), Path(bucket)).await;
    }

    // Check if this is a tagging request
    if query.tagging.is_some() {
        return tagging::delete_bucket_tagging(State(state), Path(bucket)).await;
    }

    // Check if this is an encryption request
    if query.encryption.is_some() {
        return encryption::delete_encryption(State(state), Path(bucket)).await;
    }

    // Check if this is a replication request
    if query.replication.is_some() {
        return replication::delete_replication(State(state), Path(bucket)).await;
    }

    state.store.delete_bucket(&bucket).await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// List objects query parameters (also handles bucket configuration requests)
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
struct ListObjectsQuery {
    prefix: Option<String>,
    delimiter: Option<String>,
    max_keys: Option<usize>,
    continuation_token: Option<String>,
    start_after: Option<String>,
    #[serde(rename = "list-type")]
    #[allow(dead_code)]
    list_type: Option<String>,
    /// ACL query parameter (presence indicates ACL request)
    acl: Option<String>,
    /// CORS query parameter (presence indicates CORS request)
    cors: Option<String>,
    /// Lifecycle query parameter (presence indicates lifecycle request)
    lifecycle: Option<String>,
    /// Notification query parameter (presence indicates notification request)
    notification: Option<String>,
    /// Policy query parameter (presence indicates policy request)
    policy: Option<String>,
    /// Object Lock query parameter (presence indicates object-lock request)
    object_lock: Option<String>,
    /// Tagging query parameter (presence indicates tagging request)
    tagging: Option<String>,
    /// Versioning query parameter (presence indicates versioning request)
    versioning: Option<String>,
    /// Encryption query parameter (presence indicates encryption request)
    encryption: Option<String>,
    /// Replication query parameter (presence indicates replication request)
    replication: Option<String>,
}

/// List objects in a bucket (ListObjectsV2) or get bucket configuration
async fn list_objects<B: StorageBackend>(
    State(state): State<AppState<B>>,
    Path(bucket): Path<String>,
    Query(query): Query<ListObjectsQuery>,
) -> ApiResult<Response> {
    // Check if this is an ACL request
    if query.acl.is_some() {
        return acl::get_bucket_acl(State(state), Path(bucket)).await;
    }

    // Check if this is a CORS request
    if query.cors.is_some() {
        return cors::get_cors(State(state), Path(bucket)).await;
    }

    // Check if this is a lifecycle request
    if query.lifecycle.is_some() {
        return lifecycle::get_lifecycle(State(state), Path(bucket)).await;
    }

    // Check if this is a notification request
    if query.notification.is_some() {
        return notifications::get_notifications(State(state), Path(bucket)).await;
    }

    // Check if this is a policy request
    if query.policy.is_some() {
        return policy::get_policy(State(state), Path(bucket)).await;
    }

    // Check if this is an object-lock request
    if query.object_lock.is_some() {
        return object_lock::get_object_lock_config(State(state), Path(bucket)).await;
    }

    // Check if this is a tagging request
    if query.tagging.is_some() {
        return tagging::get_bucket_tagging(State(state), Path(bucket)).await;
    }

    // Check if this is a versioning request
    if query.versioning.is_some() {
        return versioning::get_versioning(State(state), Path(bucket)).await;
    }

    // Check if this is an encryption request
    if query.encryption.is_some() {
        return encryption::get_encryption(State(state), Path(bucket)).await;
    }

    // Check if this is a replication request
    if query.replication.is_some() {
        return replication::get_replication(State(state), Path(bucket)).await;
    }

    let prefix = query.prefix.unwrap_or_default();
    let opts = ListOptions {
        max_keys: query.max_keys.unwrap_or(1000),
        delimiter: query.delimiter,
        continuation_token: query.continuation_token,
        start_after: query.start_after,
        include_versions: false,
    };

    let list = state.store.list_with_options(&bucket, &prefix, opts).await?;

    // Build XML response
    let contents: String = list
        .objects
        .iter()
        .map(|obj| {
            format!(
                r#"<Contents>
    <Key>{}</Key>
    <LastModified>{}</LastModified>
    <ETag>{}</ETag>
    <Size>{}</Size>
    <StorageClass>STANDARD</StorageClass>
</Contents>"#,
                obj.key,
                obj.last_modified.format("%Y-%m-%dT%H:%M:%S%.3fZ"),
                obj.etag,
                obj.size
            )
        })
        .collect();

    let common_prefixes: String = list
        .common_prefixes
        .iter()
        .map(|p| format!("<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>", p))
        .collect();

    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
    <Name>{}</Name>
    <Prefix>{}</Prefix>
    <KeyCount>{}</KeyCount>
    <MaxKeys>{}</MaxKeys>
    <IsTruncated>{}</IsTruncated>
    {}
    {}
</ListBucketResult>"#,
        bucket,
        prefix,
        list.key_count,
        1000,
        list.is_truncated,
        contents,
        common_prefixes
    );

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/xml")],
        xml,
    ).into_response())
}

/// Query parameters for object GET operations
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
struct ObjectGetQuery {
    /// ACL query parameter (presence indicates ACL request)
    acl: Option<String>,
    /// Retention query parameter (presence indicates retention request)
    retention: Option<String>,
    /// Legal hold query parameter (presence indicates legal-hold request)
    legal_hold: Option<String>,
    /// Tagging query parameter (presence indicates tagging request)
    tagging: Option<String>,
    /// Version ID for versioned objects
    #[serde(rename = "versionId")]
    version_id: Option<String>,
}

/// Get an object (or retention/legal-hold status)
async fn get_object<B: StorageBackend>(
    State(state): State<AppState<B>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(query): Query<ObjectGetQuery>,
) -> ApiResult<Response> {
    // Check if this is an ACL request
    if query.acl.is_some() {
        return acl::get_object_acl(State(state), Path((bucket, key))).await;
    }

    // Check if this is a retention request
    if query.retention.is_some() {
        let lock_query = object_lock::ObjectLockQuery {
            version_id: query.version_id,
        };
        return object_lock::get_retention(State(state), Path((bucket, key)), Query(lock_query)).await;
    }

    // Check if this is a legal-hold request
    if query.legal_hold.is_some() {
        let lock_query = object_lock::ObjectLockQuery {
            version_id: query.version_id,
        };
        return object_lock::get_legal_hold(State(state), Path((bucket, key)), Query(lock_query)).await;
    }

    // Check if this is a tagging request
    if query.tagging.is_some() {
        return tagging::get_object_tagging(State(state), Path((bucket, key))).await;
    }

    let object_key = ObjectKey::new(&bucket, &key)?;
    let data = state.store.get(&object_key).await?;
    let meta = state.store.head(&object_key).await?;

    let content_type = meta.content_type.unwrap_or_else(|| "application/octet-stream".to_string());

    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_LENGTH, data.len().to_string()),
            (header::ETAG, meta.etag),
            (header::CONTENT_TYPE, content_type),
        ],
        data.into_bytes(),
    ).into_response())
}

/// Head an object (get metadata only)
async fn head_object<B: StorageBackend>(
    State(state): State<AppState<B>>,
    Path((bucket, key)): Path<(String, String)>,
) -> ApiResult<Response> {
    let object_key = ObjectKey::new(&bucket, &key)?;
    let meta = state.store.head(&object_key).await?;

    let content_type = meta.content_type.unwrap_or_else(|| "application/octet-stream".to_string());

    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_LENGTH, meta.size.to_string()),
            (header::ETAG, meta.etag),
            (header::CONTENT_TYPE, content_type),
        ],
    ).into_response())
}

// =============================================================================
// Multipart Upload API
// =============================================================================

/// Query parameters for multipart operations, S3 Select, and Object Lock
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
struct MultipartQuery {
    /// Upload ID for existing uploads
    #[serde(rename = "uploadId")]
    upload_id: Option<String>,
    /// Part number for part uploads
    #[serde(rename = "partNumber")]
    part_number: Option<u32>,
    /// Flag to initiate upload (presence of "uploads" key)
    uploads: Option<String>,
    /// Flag for S3 Select (presence of "select" key)
    #[cfg(feature = "s3-select")]
    select: Option<String>,
    /// S3 Select type
    #[cfg(feature = "s3-select")]
    #[serde(rename = "select-type")]
    select_type: Option<String>,
    /// ACL query parameter (presence indicates ACL request)
    acl: Option<String>,
    /// Retention query parameter (presence indicates retention request)
    retention: Option<String>,
    /// Legal hold query parameter (presence indicates legal-hold request)
    legal_hold: Option<String>,
    /// Tagging query parameter (presence indicates tagging request)
    tagging: Option<String>,
    /// Version ID for versioned objects
    #[serde(rename = "versionId")]
    version_id: Option<String>,
}

/// PUT handler that handles regular puts, part uploads, retention, and legal-hold
async fn put_or_upload_part<B: StorageBackend>(
    State(state): State<AppState<B>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(query): Query<MultipartQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Response> {
    // Check if this is an ACL request
    if query.acl.is_some() {
        return acl::put_object_acl(State(state), Path((bucket, key)), headers, body).await;
    }

    // Check if this is a retention request
    if query.retention.is_some() {
        let lock_query = object_lock::ObjectLockQuery {
            version_id: query.version_id,
        };
        return object_lock::put_retention(State(state), Path((bucket, key)), Query(lock_query), headers, body).await;
    }

    // Check if this is a legal-hold request
    if query.legal_hold.is_some() {
        let lock_query = object_lock::ObjectLockQuery {
            version_id: query.version_id,
        };
        return object_lock::put_legal_hold(State(state), Path((bucket, key)), Query(lock_query), body).await;
    }

    // Check if this is a tagging request
    if query.tagging.is_some() {
        return tagging::put_object_tagging(State(state), Path((bucket, key)), body).await;
    }

    // Check if this is a part upload
    if let (Some(upload_id), Some(part_number)) = (query.upload_id, query.part_number) {
        return upload_part_handler(&state, &bucket, &key, &upload_id, part_number, body).await;
    }

    // Regular PUT object
    put_object(state, bucket, key, headers, body).await
}

/// Regular put object handler (extracted)
async fn put_object<B: StorageBackend>(
    state: AppState<B>,
    bucket: String,
    key: String,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Response> {
    let object_key = ObjectKey::new(&bucket, &key)?;

    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let opts = PutOptions {
        content_type,
        ..Default::default()
    };

    let data = ObjectData::from(body.to_vec());
    let meta = state.store.put_with_options(&object_key, data, opts).await?;

    Ok((
        StatusCode::OK,
        [(header::ETAG, meta.etag)],
        "",
    ).into_response())
}

/// Upload a part to a multipart upload
async fn upload_part_handler<B: StorageBackend>(
    state: &AppState<B>,
    _bucket: &str,
    _key: &str,
    upload_id: &str,
    part_number: u32,
    body: Bytes,
) -> ApiResult<Response> {

    // Get upload from state
    let upload = state.get_upload(upload_id).ok_or_else(|| {
        crate::error::ApiError::InvalidRequest(format!("Upload {} not found", upload_id))
    })?;

    let data = ObjectData::from(body.to_vec());
    let part_info = state.store.upload_part(&upload, part_number, data).await?;

    // Store part info
    state.add_part(upload_id, part_info.clone());

    Ok((
        StatusCode::OK,
        [(header::ETAG, part_info.etag)],
        "",
    ).into_response())
}

/// DELETE handler that handles both regular deletes and abort multipart
async fn delete_or_abort<B: StorageBackend>(
    State(state): State<AppState<B>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(query): Query<MultipartQuery>,
) -> ApiResult<Response> {
    // Check if this is a tagging request
    if query.tagging.is_some() {
        return tagging::delete_object_tagging(State(state), Path((bucket, key))).await;
    }

    // Check if this is an abort multipart
    if let Some(upload_id) = query.upload_id {
        return abort_multipart_handler(&state, &bucket, &key, &upload_id).await;
    }

    // Regular DELETE object
    let object_key = ObjectKey::new(&bucket, &key)?;
    state.store.delete(&object_key).await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Abort a multipart upload
async fn abort_multipart_handler<B: StorageBackend>(
    state: &AppState<B>,
    bucket: &str,
    key: &str,
    upload_id: &str,
) -> ApiResult<Response> {
    let upload = state.get_upload(upload_id).ok_or_else(|| {
        crate::error::ApiError::InvalidRequest(format!("Upload {} not found", upload_id))
    })?;

    state.store.abort_multipart(&upload).await?;
    state.remove_upload(upload_id);

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// POST handler for multipart operations (create and complete) and S3 Select
async fn multipart_handler<B: StorageBackend>(
    State(state): State<AppState<B>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(query): Query<MultipartQuery>,
    body: Bytes,
) -> ApiResult<Response> {
    // Check if this is an S3 Select request (POST with ?select or ?select-type)
    #[cfg(feature = "s3-select")]
    if query.select.is_some() || query.select_type.is_some() {
        let select_query = select::SelectQuery {
            select: query.select,
            select_type: query.select_type,
        };
        return select::select_object_content(
            State(state),
            Path((bucket, key)),
            Query(select_query),
            body,
        ).await;
    }

    // Check if this is create multipart (POST with ?uploads)
    if query.uploads.is_some() {
        return create_multipart_handler(&state, &bucket, &key).await;
    }

    // Otherwise it's complete multipart (POST with ?uploadId=xxx)
    if let Some(upload_id) = query.upload_id {
        return complete_multipart_handler(&state, &bucket, &key, &upload_id, body).await;
    }

    Err(crate::error::ApiError::InvalidRequest("Invalid multipart request".to_string()))
}

/// Create a new multipart upload
async fn create_multipart_handler<B: StorageBackend>(
    state: &AppState<B>,
    bucket: &str,
    key: &str,
) -> ApiResult<Response> {
    let object_key = ObjectKey::new(bucket, key)?;
    let upload = state.store.create_multipart(&object_key).await?;

    // Store upload in state
    state.add_upload(upload.upload_id.clone(), upload.clone());

    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<InitiateMultipartUploadResult>
    <Bucket>{}</Bucket>
    <Key>{}</Key>
    <UploadId>{}</UploadId>
</InitiateMultipartUploadResult>"#,
        bucket, key, upload.upload_id
    );

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/xml")],
        xml,
    ).into_response())
}

/// Complete a multipart upload
async fn complete_multipart_handler<B: StorageBackend>(
    state: &AppState<B>,
    bucket: &str,
    key: &str,
    upload_id: &str,
    _body: Bytes,
) -> ApiResult<Response> {
    let upload = state.get_upload(upload_id).ok_or_else(|| {
        crate::error::ApiError::InvalidRequest(format!("Upload {} not found", upload_id))
    })?;

    // Get parts from state (we track them as they're uploaded)
    let parts = state.get_parts(upload_id);

    let meta = state.store.complete_multipart(&upload, parts).await?;
    state.remove_upload(upload_id);

    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<CompleteMultipartUploadResult>
    <Location>/{}/{}</Location>
    <Bucket>{}</Bucket>
    <Key>{}</Key>
    <ETag>{}</ETag>
</CompleteMultipartUploadResult>"#,
        bucket, key, bucket, key, meta.etag
    );

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/xml")],
        xml,
    ).into_response())
}
