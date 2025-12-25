//! Object data and metadata types

use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::version::VersionId;

/// Object data - the actual bytes of an object
#[derive(Debug, Clone)]
pub struct ObjectData {
    /// The raw bytes
    data: Bytes,
}

impl ObjectData {
    /// Create new object data from bytes
    pub fn new(data: impl Into<Bytes>) -> Self {
        Self { data: data.into() }
    }

    /// Get the length in bytes
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get the raw bytes
    pub fn into_bytes(self) -> Bytes {
        self.data
    }

    /// Get a reference to the bytes
    pub fn as_bytes(&self) -> &Bytes {
        &self.data
    }
}

impl AsRef<[u8]> for ObjectData {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl From<Vec<u8>> for ObjectData {
    fn from(v: Vec<u8>) -> Self {
        Self::new(v)
    }
}

impl From<Bytes> for ObjectData {
    fn from(b: Bytes) -> Self {
        Self::new(b)
    }
}

impl From<&[u8]> for ObjectData {
    fn from(s: &[u8]) -> Self {
        Self::new(s.to_vec())
    }
}

/// Object metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectMeta {
    /// Object size in bytes
    pub size: u64,

    /// Content hash (BLAKE3)
    pub content_hash: [u8; 32],

    /// ETag (for S3 compatibility)
    pub etag: String,

    /// Content type (MIME type)
    pub content_type: Option<String>,

    /// Creation time
    pub created_at: DateTime<Utc>,

    /// Last modification time
    pub modified_at: DateTime<Utc>,

    /// Version ID (if versioning enabled)
    pub version_id: Option<VersionId>,

    /// User-defined metadata
    pub user_metadata: HashMap<String, String>,

    /// Whether this is a delete marker
    pub is_delete_marker: bool,
}

impl ObjectMeta {
    /// Create new metadata for an object
    pub fn new(data: &ObjectData) -> Self {
        let now = Utc::now();
        let hash = blake3::hash(data.as_ref());
        let hash_bytes = *hash.as_bytes();

        Self {
            size: data.len() as u64,
            content_hash: hash_bytes,
            etag: format!("\"{}\"", hex::encode(&hash_bytes[..16])),
            content_type: None,
            created_at: now,
            modified_at: now,
            version_id: None,
            user_metadata: HashMap::new(),
            is_delete_marker: false,
        }
    }

    /// Create a delete marker
    pub fn delete_marker(version_id: VersionId) -> Self {
        let now = Utc::now();
        Self {
            size: 0,
            content_hash: [0; 32],
            etag: String::new(),
            content_type: None,
            created_at: now,
            modified_at: now,
            version_id: Some(version_id),
            user_metadata: HashMap::new(),
            is_delete_marker: true,
        }
    }

    /// Set content type
    pub fn with_content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = Some(content_type.into());
        self
    }

    /// Add user metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.user_metadata.insert(key.into(), value.into());
        self
    }
}

/// Options for PUT operations
#[derive(Debug, Clone, Default)]
pub struct PutOptions {
    /// Content type override
    pub content_type: Option<String>,

    /// User metadata
    pub metadata: HashMap<String, String>,

    /// Expected ETag for conditional put
    pub if_match: Option<String>,

    /// Only put if object doesn't exist
    pub if_none_match: bool,

    /// Storage class hint
    pub storage_class: StorageClass,
}

impl PutOptions {
    /// Create new put options with content type
    pub fn with_content_type(content_type: impl Into<String>) -> Self {
        Self {
            content_type: Some(content_type.into()),
            ..Default::default()
        }
    }
}

/// Storage class for objects
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum StorageClass {
    /// Standard storage - fastest access
    #[default]
    Standard,

    /// Infrequent access - lower cost, slower retrieval
    InfrequentAccess,

    /// Archive - lowest cost, minutes to hours retrieval
    Archive,

    /// GPU-pinned - kept in GPU memory for fast access
    GpuPinned,
}

/// Options for LIST operations
#[derive(Debug, Clone)]
pub struct ListOptions {
    /// Maximum number of keys to return
    pub max_keys: usize,

    /// Continuation token for pagination
    pub continuation_token: Option<String>,

    /// Delimiter for grouping (typically "/")
    pub delimiter: Option<String>,

    /// Start listing after this key
    pub start_after: Option<String>,

    /// Include versions in listing
    pub include_versions: bool,
}

impl Default for ListOptions {
    fn default() -> Self {
        Self {
            max_keys: 1000,
            continuation_token: None,
            delimiter: None,
            start_after: None,
            include_versions: false,
        }
    }
}

impl ListOptions {
    /// Set max keys
    pub fn with_max_keys(mut self, max_keys: usize) -> Self {
        self.max_keys = max_keys;
        self
    }

    /// Set delimiter
    pub fn with_delimiter(mut self, delimiter: impl Into<String>) -> Self {
        self.delimiter = Some(delimiter.into());
        self
    }
}

/// Result of a LIST operation
#[derive(Debug, Clone, Default)]
pub struct ObjectList {
    /// Objects matching the query
    pub objects: Vec<ObjectEntry>,

    /// Common prefixes (when using delimiter)
    pub common_prefixes: Vec<String>,

    /// Continuation token for next page
    pub next_continuation_token: Option<String>,

    /// Whether the result was truncated
    pub is_truncated: bool,

    /// Number of keys returned
    pub key_count: usize,
}

/// An entry in an object listing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectEntry {
    /// Object key
    pub key: String,

    /// Object size
    pub size: u64,

    /// Last modified time
    pub last_modified: DateTime<Utc>,

    /// ETag
    pub etag: String,

    /// Storage class
    pub storage_class: StorageClass,

    /// Version ID (if versioning enabled)
    pub version_id: Option<VersionId>,

    /// Whether this is the latest version
    pub is_latest: bool,
}

/// Field data for lazy-loading (parcode integration)
#[derive(Debug, Clone, Default)]
pub struct FieldData {
    /// Field values by name
    fields: HashMap<String, Bytes>,
}

impl FieldData {
    /// Create new empty field data
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a field
    pub fn insert(&mut self, name: String, value: impl Into<Bytes>) {
        self.fields.insert(name, value.into());
    }

    /// Get a field
    pub fn get(&self, name: &str) -> Option<&Bytes> {
        self.fields.get(name)
    }

    /// Check if a field exists
    pub fn contains(&self, name: &str) -> bool {
        self.fields.contains_key(name)
    }

    /// Get all field names
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.fields.keys().map(|s| s.as_str())
    }

    /// Number of fields
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
}

// Add hex dependency for etag generation
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        super::hex_encode(bytes)
    }
}
