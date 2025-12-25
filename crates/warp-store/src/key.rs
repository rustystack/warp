//! Object key parsing and validation

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fmt;

/// An object key consisting of bucket and key path
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ObjectKey {
    /// The bucket name
    bucket: String,
    /// The key path within the bucket
    key: String,
}

impl ObjectKey {
    /// Create a new object key
    ///
    /// # Arguments
    /// * `bucket` - The bucket name (3-63 chars, lowercase alphanumeric and hyphens)
    /// * `key` - The object key path (1-1024 chars, no null bytes)
    ///
    /// # Errors
    /// Returns an error if the bucket name or key is invalid
    pub fn new(bucket: impl Into<String>, key: impl Into<String>) -> Result<Self> {
        let bucket = bucket.into();
        let key = key.into();

        Self::validate_bucket(&bucket)?;
        Self::validate_key(&key)?;

        Ok(Self { bucket, key })
    }

    /// Get the bucket name
    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    /// Get the key path
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Get the key prefix (directory-like path before the last /)
    pub fn prefix(&self) -> Option<&str> {
        self.key.rfind('/').map(|i| &self.key[..i])
    }

    /// Get the key name (last component after /)
    pub fn name(&self) -> &str {
        self.key.rfind('/').map_or(&self.key, |i| &self.key[i + 1..])
    }

    /// Get the file extension, if any
    pub fn extension(&self) -> Option<&str> {
        let name = self.name();
        name.rfind('.').map(|i| &name[i + 1..])
    }

    /// Check if this key matches a prefix
    pub fn matches_prefix(&self, prefix: &str) -> bool {
        self.key.starts_with(prefix)
    }

    /// Create a child key
    pub fn child(&self, name: &str) -> Result<Self> {
        let new_key = if self.key.ends_with('/') {
            format!("{}{}", self.key, name)
        } else {
            format!("{}/{}", self.key, name)
        };
        Self::new(&self.bucket, new_key)
    }

    /// Parse from a path string like "bucket/path/to/object"
    pub fn parse(path: &str) -> Result<Self> {
        let path = path.trim_start_matches('/');
        let (bucket, key) = path.split_once('/')
            .ok_or_else(|| Error::InvalidKey("key must contain bucket/path".to_string()))?;
        Self::new(bucket, key)
    }

    /// Convert to path string
    pub fn to_path(&self) -> String {
        format!("{}/{}", self.bucket, self.key)
    }

    fn validate_bucket(bucket: &str) -> Result<()> {
        // S3-compatible bucket naming rules
        if bucket.len() < 3 || bucket.len() > 63 {
            return Err(Error::InvalidBucketName(
                "bucket name must be 3-63 characters".to_string()
            ));
        }

        if !bucket.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.') {
            return Err(Error::InvalidBucketName(
                "bucket name must contain only lowercase letters, numbers, hyphens, and periods".to_string()
            ));
        }

        if bucket.starts_with('-') || bucket.ends_with('-') {
            return Err(Error::InvalidBucketName(
                "bucket name cannot start or end with a hyphen".to_string()
            ));
        }

        if bucket.starts_with('.') || bucket.ends_with('.') {
            return Err(Error::InvalidBucketName(
                "bucket name cannot start or end with a period".to_string()
            ));
        }

        if bucket.contains("..") {
            return Err(Error::InvalidBucketName(
                "bucket name cannot contain consecutive periods".to_string()
            ));
        }

        Ok(())
    }

    fn validate_key(key: &str) -> Result<()> {
        if key.is_empty() || key.len() > 1024 {
            return Err(Error::InvalidKey(
                "key must be 1-1024 characters".to_string()
            ));
        }

        if key.contains('\0') {
            return Err(Error::InvalidKey(
                "key cannot contain null bytes".to_string()
            ));
        }

        // Prevent path traversal
        if key.contains("..") {
            return Err(Error::InvalidKey(
                "key cannot contain '..'".to_string()
            ));
        }

        Ok(())
    }
}

impl fmt::Display for ObjectKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.bucket, self.key)
    }
}

impl TryFrom<&str> for ObjectKey {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_keys() {
        let key = ObjectKey::new("my-bucket", "path/to/object.txt").unwrap();
        assert_eq!(key.bucket(), "my-bucket");
        assert_eq!(key.key(), "path/to/object.txt");
        assert_eq!(key.prefix(), Some("path/to"));
        assert_eq!(key.name(), "object.txt");
        assert_eq!(key.extension(), Some("txt"));
    }

    #[test]
    fn test_invalid_bucket() {
        // Too short
        assert!(ObjectKey::new("ab", "key").is_err());

        // Too long
        assert!(ObjectKey::new(&"a".repeat(64), "key").is_err());

        // Invalid characters
        assert!(ObjectKey::new("My-Bucket", "key").is_err());
        assert!(ObjectKey::new("my_bucket", "key").is_err());

        // Invalid format
        assert!(ObjectKey::new("-mybucket", "key").is_err());
        assert!(ObjectKey::new("mybucket-", "key").is_err());
        assert!(ObjectKey::new("my..bucket", "key").is_err());
    }

    #[test]
    fn test_invalid_key() {
        // Empty
        assert!(ObjectKey::new("bucket", "").is_err());

        // Path traversal
        assert!(ObjectKey::new("bucket", "../etc/passwd").is_err());
        assert!(ObjectKey::new("bucket", "path/../../etc/passwd").is_err());
    }

    #[test]
    fn test_parse() {
        let key = ObjectKey::parse("bucket/path/to/file.txt").unwrap();
        assert_eq!(key.bucket(), "bucket");
        assert_eq!(key.key(), "path/to/file.txt");

        let key = ObjectKey::parse("/bucket/path").unwrap();
        assert_eq!(key.bucket(), "bucket");
        assert_eq!(key.key(), "path");
    }

    #[test]
    fn test_prefix_matching() {
        let key = ObjectKey::new("bucket", "data/2024/01/file.csv").unwrap();
        assert!(key.matches_prefix("data/"));
        assert!(key.matches_prefix("data/2024/"));
        assert!(!key.matches_prefix("logs/"));
    }
}
