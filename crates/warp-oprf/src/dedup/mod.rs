//! Content-blind deduplication using OPRF
//!
//! This module enables deduplication without the server seeing content hashes.
//! The client blinds the content hash, the server evaluates it with their key,
//! and the result is a deterministic dedup token that can be used as a key.
//!
//! # Security Properties
//!
//! - Server cannot learn content hashes
//! - Tokens are deterministic for same content + server key
//! - Different server keys produce different tokens
//! - Client cannot forge tokens without server participation
//!
//! # Example
//!
//! ```ignore
//! use warp_oprf::dedup::{BlindDedupClient, BlindDedupServer};
//!
//! // Setup
//! let server = BlindDedupServer::new("dedup-key-v1")?;
//! let client = BlindDedupClient::new(server.public_key())?;
//!
//! // Generate dedup token for content
//! let content_hash = warp_hash::hash(data);
//! let (request, state) = client.blind_hash(&content_hash)?;
//! let response = server.evaluate(&request)?;
//! let token = client.finalize(state, &response)?;
//!
//! // Use token to check for duplicates
//! if let Some(existing) = dedup_index.get(&token) {
//!     // Content already exists
//! } else {
//!     // Store new content and index by token
//!     dedup_index.insert(token, object_ref);
//! }
//! ```

mod client;
mod server;

pub use client::BlindDedupClient;
pub use server::BlindDedupServer;

use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Deduplication token derived from OPRF
///
/// This token is deterministic for the same content + server key combination,
/// making it suitable for deduplication lookups without revealing the content hash.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct DedupToken([u8; 32]);

impl DedupToken {
    /// Create a new dedup token from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the token as bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to hex string for storage/display
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Parse from hex string
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s).map_err(|e| {
            crate::error::OprfError::Deserialization(format!("invalid hex: {}", e))
        })?;
        if bytes.len() != 32 {
            return Err(crate::error::OprfError::Deserialization(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl AsRef<[u8]> for DedupToken {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for DedupToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DedupToken({}...)", &self.to_hex()[..8])
    }
}

impl fmt::Display for DedupToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Reference to deduplicated content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DedupReference {
    /// Object key where content is stored
    pub object_key: String,
    /// Optional chunk index within the object
    pub chunk_index: Option<u64>,
    /// Size of the content in bytes
    pub size: u64,
    /// Server key ID used for this token
    pub key_id: String,
}

impl DedupReference {
    /// Create a new dedup reference
    pub fn new(object_key: impl Into<String>, size: u64, key_id: impl Into<String>) -> Self {
        Self {
            object_key: object_key.into(),
            chunk_index: None,
            size,
            key_id: key_id.into(),
        }
    }

    /// Create a reference to a specific chunk
    pub fn with_chunk(
        object_key: impl Into<String>,
        chunk_index: u64,
        size: u64,
        key_id: impl Into<String>,
    ) -> Self {
        Self {
            object_key: object_key.into(),
            chunk_index: Some(chunk_index),
            size,
            key_id: key_id.into(),
        }
    }
}

/// Trait for dedup index storage
#[async_trait::async_trait]
pub trait DedupIndex: Send + Sync {
    /// Look up a dedup token
    async fn lookup(&self, token: &DedupToken) -> Result<Option<DedupReference>>;

    /// Store a dedup token -> reference mapping
    async fn store(&self, token: &DedupToken, reference: DedupReference) -> Result<()>;

    /// Remove a dedup token
    async fn remove(&self, token: &DedupToken) -> Result<bool>;

    /// Check if a token exists
    async fn exists(&self, token: &DedupToken) -> Result<bool> {
        Ok(self.lookup(token).await?.is_some())
    }
}

/// In-memory dedup index for testing
#[derive(Default)]
pub struct MemoryDedupIndex {
    entries: std::sync::RwLock<std::collections::HashMap<[u8; 32], DedupReference>>,
}

impl MemoryDedupIndex {
    /// Create a new in-memory index
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the number of entries
    pub fn len(&self) -> usize {
        self.entries.read().unwrap().len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.entries.read().unwrap().is_empty()
    }
}

#[async_trait::async_trait]
impl DedupIndex for MemoryDedupIndex {
    async fn lookup(&self, token: &DedupToken) -> Result<Option<DedupReference>> {
        Ok(self.entries.read().unwrap().get(&token.0).cloned())
    }

    async fn store(&self, token: &DedupToken, reference: DedupReference) -> Result<()> {
        self.entries.write().unwrap().insert(token.0, reference);
        Ok(())
    }

    async fn remove(&self, token: &DedupToken) -> Result<bool> {
        Ok(self.entries.write().unwrap().remove(&token.0).is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dedup_token() {
        let token = DedupToken::from_bytes([0x42; 32]);
        assert_eq!(token.as_bytes(), &[0x42; 32]);

        let hex = token.to_hex();
        assert!(hex.starts_with("42424242"));

        let parsed = DedupToken::from_hex(&hex).unwrap();
        assert_eq!(token, parsed);
    }

    #[test]
    fn test_dedup_reference() {
        let reference = DedupReference::new("bucket/object", 1024, "key-v1");
        assert_eq!(reference.object_key, "bucket/object");
        assert_eq!(reference.size, 1024);
        assert!(reference.chunk_index.is_none());

        let chunk_ref = DedupReference::with_chunk("bucket/object", 5, 512, "key-v1");
        assert_eq!(chunk_ref.chunk_index, Some(5));
    }

    #[tokio::test]
    async fn test_memory_index() {
        let index = MemoryDedupIndex::new();
        let token = DedupToken::from_bytes([0x01; 32]);
        let reference = DedupReference::new("test/object", 100, "key-v1");

        // Initially empty
        assert!(index.lookup(&token).await.unwrap().is_none());

        // Store and lookup
        index.store(&token, reference.clone()).await.unwrap();
        let found = index.lookup(&token).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().object_key, "test/object");

        // Remove
        assert!(index.remove(&token).await.unwrap());
        assert!(index.lookup(&token).await.unwrap().is_none());
    }
}
