//! API error types

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

/// API result type
pub type ApiResult<T> = Result<T, ApiError>;

/// API errors
#[derive(Error, Debug)]
pub enum ApiError {
    /// Store error
    #[error("Store error: {0}")]
    Store(#[from] warp_store::Error),

    /// Invalid request
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    /// Authentication failed
    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    /// Access denied
    #[error("Access denied: {0}")]
    AccessDenied(String),

    /// Resource not found
    #[error("Not found: {0}")]
    NotFound(String),

    /// Method not allowed
    #[error("Method not allowed")]
    MethodNotAllowed,

    /// Internal server error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            ApiError::Store(e) => match e {
                warp_store::Error::BucketNotFound(_) => (StatusCode::NOT_FOUND, e.to_string()),
                warp_store::Error::ObjectNotFound { .. } => (StatusCode::NOT_FOUND, e.to_string()),
                warp_store::Error::BucketAlreadyExists(_) => (StatusCode::CONFLICT, e.to_string()),
                warp_store::Error::PermissionDenied(_) => (StatusCode::FORBIDDEN, e.to_string()),
                warp_store::Error::TokenExpired => (StatusCode::UNAUTHORIZED, e.to_string()),
                warp_store::Error::InvalidSignature => (StatusCode::UNAUTHORIZED, e.to_string()),
                _ => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            },
            ApiError::InvalidRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            ApiError::AuthFailed(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
            ApiError::AccessDenied(msg) => (StatusCode::FORBIDDEN, msg.clone()),
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            ApiError::MethodNotAllowed => (StatusCode::METHOD_NOT_ALLOWED, "Method not allowed".to_string()),
            ApiError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
        };

        // Return S3-style XML error for S3 API compatibility
        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<Error>
    <Code>{}</Code>
    <Message>{}</Message>
</Error>"#,
            status.as_str(),
            message
        );

        (status, [("content-type", "application/xml")], xml).into_response()
    }
}
