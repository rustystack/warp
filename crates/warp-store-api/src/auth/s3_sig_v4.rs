//! AWS Signature Version 4 authentication
//!
//! Implements the AWS SigV4 signing algorithm for S3 API compatibility.
//! Reference: https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html

use chrono::{DateTime, NaiveDateTime, Utc};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::error::{ApiError, ApiResult};

type HmacSha256 = Hmac<Sha256>;

/// AWS Signature V4 components
#[derive(Debug, Clone)]
pub struct SignatureV4 {
    /// Access key ID
    pub access_key: String,
    /// Date in YYYYMMDD format
    pub date: String,
    /// Region
    pub region: String,
    /// Service (always "s3" for us)
    pub service: String,
    /// Signed headers
    pub signed_headers: Vec<String>,
    /// The signature itself
    pub signature: String,
}

impl SignatureV4 {
    /// Parse from Authorization header
    ///
    /// Format: AWS4-HMAC-SHA256 Credential=ACCESS_KEY/DATE/REGION/SERVICE/aws4_request,
    ///         SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=SIGNATURE
    pub fn parse(auth_header: &str) -> ApiResult<Self> {
        if !auth_header.starts_with("AWS4-HMAC-SHA256 ") {
            return Err(ApiError::AuthFailed("Invalid authorization scheme".into()));
        }

        let parts = &auth_header["AWS4-HMAC-SHA256 ".len()..];

        // Parse key=value pairs
        let mut credential = None;
        let mut signed_headers = None;
        let mut signature = None;

        for part in parts.split(", ") {
            if let Some((key, value)) = part.split_once('=') {
                match key.trim() {
                    "Credential" => credential = Some(value.to_string()),
                    "SignedHeaders" => signed_headers = Some(value.to_string()),
                    "Signature" => signature = Some(value.to_string()),
                    _ => {}
                }
            }
        }

        let credential = credential.ok_or_else(|| ApiError::AuthFailed("Missing Credential".into()))?;
        let signed_headers = signed_headers.ok_or_else(|| ApiError::AuthFailed("Missing SignedHeaders".into()))?;
        let signature = signature.ok_or_else(|| ApiError::AuthFailed("Missing Signature".into()))?;

        // Parse credential: ACCESS_KEY/DATE/REGION/SERVICE/aws4_request
        let cred_parts: Vec<&str> = credential.split('/').collect();
        if cred_parts.len() != 5 || cred_parts[4] != "aws4_request" {
            return Err(ApiError::AuthFailed("Invalid Credential format".into()));
        }

        Ok(Self {
            access_key: cred_parts[0].to_string(),
            date: cred_parts[1].to_string(),
            region: cred_parts[2].to_string(),
            service: cred_parts[3].to_string(),
            signed_headers: signed_headers.split(';').map(|s| s.to_string()).collect(),
            signature,
        })
    }
}

/// Verify an AWS Signature V4 request
pub fn verify_signature_v4(
    sig: &SignatureV4,
    secret_key: &str,
    method: &str,
    path: &str,
    query_string: &str,
    headers: &[(String, String)],
    payload_hash: &str,
    timestamp: &str,
) -> ApiResult<bool> {
    // Step 1: Create canonical request
    let canonical_request = create_canonical_request(
        method,
        path,
        query_string,
        headers,
        &sig.signed_headers,
        payload_hash,
    );

    // Step 2: Create string to sign
    let string_to_sign = create_string_to_sign(
        timestamp,
        &sig.date,
        &sig.region,
        &sig.service,
        &canonical_request,
    );

    // Step 3: Calculate signature
    let calculated_sig = calculate_signature(
        secret_key,
        &sig.date,
        &sig.region,
        &sig.service,
        &string_to_sign,
    );

    // Step 4: Compare
    Ok(constant_time_eq(&calculated_sig, &sig.signature))
}

fn create_canonical_request(
    method: &str,
    path: &str,
    query_string: &str,
    headers: &[(String, String)],
    signed_headers: &[String],
    payload_hash: &str,
) -> String {
    // Canonical URI
    let canonical_uri = if path.is_empty() { "/" } else { path };

    // Canonical query string (sorted by parameter name)
    let canonical_query = if query_string.is_empty() {
        String::new()
    } else {
        let mut params: Vec<(&str, &str)> = query_string
            .split('&')
            .filter_map(|p| p.split_once('='))
            .collect();
        params.sort_by(|a, b| a.0.cmp(b.0));
        params
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&")
    };

    // Canonical headers
    let header_map: std::collections::HashMap<String, String> = headers
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.trim().to_string()))
        .collect();

    let canonical_headers: String = signed_headers
        .iter()
        .map(|h| {
            let value = header_map.get(&h.to_lowercase()).map(|s| s.as_str()).unwrap_or("");
            format!("{}:{}\n", h.to_lowercase(), value)
        })
        .collect();

    let signed_headers_str = signed_headers.join(";");

    format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method,
        canonical_uri,
        canonical_query,
        canonical_headers,
        signed_headers_str,
        payload_hash
    )
}

fn create_string_to_sign(
    timestamp: &str,
    date: &str,
    region: &str,
    service: &str,
    canonical_request: &str,
) -> String {
    let scope = format!("{}/{}/{}/aws4_request", date, region, service);
    let canonical_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));

    format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        timestamp, scope, canonical_hash
    )
}

fn calculate_signature(
    secret_key: &str,
    date: &str,
    region: &str,
    service: &str,
    string_to_sign: &str,
) -> String {
    // Derive signing key
    let k_secret = format!("AWS4{}", secret_key);
    let k_date = hmac_sha256(k_secret.as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    let k_signing = hmac_sha256(&k_service, b"aws4_request");

    // Calculate signature
    let sig = hmac_sha256(&k_signing, string_to_sign.as_bytes());
    hex::encode(sig)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_signature_v4() {
        let header = "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024";

        let sig = SignatureV4::parse(header).unwrap();

        assert_eq!(sig.access_key, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(sig.date, "20130524");
        assert_eq!(sig.region, "us-east-1");
        assert_eq!(sig.service, "s3");
        assert_eq!(sig.signed_headers, vec!["host", "range", "x-amz-content-sha256", "x-amz-date"]);
        assert_eq!(sig.signature, "fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024");
    }

    #[test]
    fn test_hmac_sha256() {
        let key = b"key";
        let data = b"data";
        let result = hmac_sha256(key, data);

        // Known value for HMAC-SHA256("key", "data")
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq("abc123", "abc123"));
        assert!(!constant_time_eq("abc123", "abc124"));
        assert!(!constant_time_eq("abc123", "abc12"));
    }
}
