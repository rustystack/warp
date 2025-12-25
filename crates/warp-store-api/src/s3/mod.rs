//! S3-compatible API endpoints
//!
//! Implements the core S3 REST API:
//! - Object operations: GET, PUT, DELETE, HEAD
//! - Bucket operations: GET (list), PUT (create), DELETE
//! - ListObjectsV2 with prefix and delimiter support

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, HeaderMap, Method, Request, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, head, put},
    Router,
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use warp_store::backend::StorageBackend;
use warp_store::{ObjectKey, ObjectData, PutOptions, ListOptions};

use crate::error::ApiResult;
use crate::AppState;

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
        .route("/{bucket}/{*key}", put(put_object::<B>))
        .route("/{bucket}/{*key}", delete(delete_object::<B>))
        .route("/{bucket}/{*key}", head(head_object::<B>))
        .with_state(state)
}

/// List all buckets
async fn list_buckets<B: StorageBackend>(
    State(state): State<AppState<B>>,
) -> ApiResult<Response> {
    let buckets = state.store.list_buckets();

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

/// Create a bucket
async fn create_bucket<B: StorageBackend>(
    State(state): State<AppState<B>>,
    Path(bucket): Path<String>,
) -> ApiResult<Response> {
    state.store.create_bucket(&bucket, Default::default()).await?;

    Ok((
        StatusCode::OK,
        [(header::LOCATION, format!("/{}", bucket))],
        "",
    ).into_response())
}

/// Delete a bucket
async fn delete_bucket<B: StorageBackend>(
    State(state): State<AppState<B>>,
    Path(bucket): Path<String>,
) -> ApiResult<Response> {
    state.store.delete_bucket(&bucket).await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// List objects query parameters
#[derive(Debug, Deserialize)]
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
}

/// List objects in a bucket (ListObjectsV2)
async fn list_objects<B: StorageBackend>(
    State(state): State<AppState<B>>,
    Path(bucket): Path<String>,
    Query(query): Query<ListObjectsQuery>,
) -> ApiResult<Response> {
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

/// Get an object
async fn get_object<B: StorageBackend>(
    State(state): State<AppState<B>>,
    Path((bucket, key)): Path<(String, String)>,
) -> ApiResult<Response> {
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

/// Put an object
async fn put_object<B: StorageBackend>(
    State(state): State<AppState<B>>,
    Path((bucket, key)): Path<(String, String)>,
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

/// Delete an object
async fn delete_object<B: StorageBackend>(
    State(state): State<AppState<B>>,
    Path((bucket, key)): Path<(String, String)>,
) -> ApiResult<Response> {
    let object_key = ObjectKey::new(&bucket, &key)?;
    state.store.delete(&object_key).await?;

    Ok(StatusCode::NO_CONTENT.into_response())
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
