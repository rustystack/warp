//! Type definitions for the Raft consensus layer
//!
//! This module provides types for:
//! - Raft consensus for metadata operations
//! - Write ordering modes for data operations (Exclusive, Shared, WriteOnce)
//!
//! # Write Ordering Modes
//!
//! Multi-path network aggregation can cause writes from different paths to arrive
//! out of order. The consistency modes define how writes are serialized:
//!
//! - **Exclusive**: Single owner per object, lowest latency, no coordination needed
//! - **Shared**: Multiple writers, serialize at primary node for strong ordering
//! - **WriteOnce**: Immutable after creation, no conflicts possible

use std::collections::{BTreeMap, HashSet};
use std::io::Cursor;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

use openraft::{BasicNode, LogId, StoredMembership};
use serde::{Deserialize, Serialize};

use crate::ObjectKey;
use crate::bucket::BucketConfig;

/// Node ID type
pub type NodeId = u64;

/// Log entry ID
pub type LogEntryId = u64;

/// Raft type configuration for warp-store
///
/// Uses openraft's declare_raft_types macro with u64 for NodeId and BasicNode for Node.
openraft::declare_raft_types!(
    pub TypeConfig:
        D = MetadataRequest,
        R = MetadataResponse,
        Node = BasicNode,
);

/// The Raft node type alias
pub type RaftNode = openraft::Raft<TypeConfig>;

/// Metadata operation request (replicated via Raft)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetadataRequest {
    /// Create a new bucket
    CreateBucket {
        /// Bucket name
        name: String,
        /// Bucket configuration
        config: BucketConfig,
    },

    /// Delete a bucket
    DeleteBucket {
        /// Bucket name to delete
        name: String,
    },

    /// Put object metadata
    PutObjectMeta {
        /// Object key
        key: ObjectKey,
        /// Object metadata
        metadata: ObjectMetadataEntry,
    },

    /// Delete object metadata
    DeleteObjectMeta {
        /// Object key to delete
        key: ObjectKey,
    },

    /// Update bucket configuration
    UpdateBucketConfig {
        /// Bucket name
        name: String,
        /// New configuration
        config: BucketConfig,
    },
}

/// Response from metadata operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetadataResponse {
    /// Operation succeeded
    Ok,

    /// Bucket already exists
    BucketAlreadyExists(String),

    /// Bucket not found
    BucketNotFound(String),

    /// Object not found
    ObjectNotFound(String),

    /// Generic error
    Error(String),
}

/// Object metadata entry stored in the state machine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectMetadataEntry {
    /// Full key (bucket/path)
    pub key: String,

    /// Object size in bytes
    pub size: u64,

    /// ETag (content hash)
    pub etag: String,

    /// Content type
    pub content_type: Option<String>,

    /// Version ID (if versioning enabled)
    pub version_id: Option<String>,

    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// Custom metadata
    pub custom_metadata: BTreeMap<String, String>,
}

impl ObjectMetadataEntry {
    /// Create a new metadata entry
    pub fn new(key: &ObjectKey, size: u64, etag: String) -> Self {
        Self {
            key: key.to_string(),
            size,
            etag,
            content_type: None,
            version_id: None,
            created_at: chrono::Utc::now(),
            custom_metadata: BTreeMap::new(),
        }
    }

    /// Set content type
    pub fn with_content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = Some(content_type.into());
        self
    }

    /// Set version ID
    pub fn with_version(mut self, version_id: impl Into<String>) -> Self {
        self.version_id = Some(version_id.into());
        self
    }

    /// Add custom metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.custom_metadata.insert(key.into(), value.into());
        self
    }
}

/// Snapshot of the entire metadata state
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MetadataSnapshot {
    /// Last applied log ID
    pub last_applied_log: Option<LogId<NodeId>>,

    /// Last membership config
    pub last_membership: StoredMembership<NodeId, BasicNode>,

    /// All buckets
    pub buckets: BTreeMap<String, BucketConfig>,

    /// All object metadata (key -> metadata)
    pub objects: BTreeMap<String, ObjectMetadataEntry>,
}

impl MetadataSnapshot {
    /// Create an empty snapshot
    pub fn new() -> Self {
        Self::default()
    }

    /// Serialize snapshot to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        rmp_serde::to_vec(self).expect("Failed to serialize snapshot")
    }

    /// Deserialize snapshot from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, rmp_serde::decode::Error> {
        rmp_serde::from_slice(bytes)
    }
}

// ============================================================================
// Write Ordering / Consistency Modes
// ============================================================================

/// Write ordering mode for data operations
///
/// Different modes provide different tradeoffs between latency, throughput,
/// and consistency guarantees. The mode is set per-object or per-bucket.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConsistencyMode {
    /// Single owner, lowest latency - only owner can write
    ///
    /// Multi-path safe: only one writer exists, so no conflicts possible
    /// regardless of which path writes arrive on.
    Exclusive {
        /// Node that owns this object
        owner: NodeId,
        /// Lease expiration timestamp (milliseconds since epoch)
        lease_expires_ms: u64,
    },

    /// Multiple writers, serialized at primary node
    ///
    /// Multi-path safe: all writes converge at the primary node for
    /// serialization before being applied.
    Shared {
        /// Node responsible for serializing writes
        primary: NodeId,
        /// Set of authorized writers (empty = all allowed)
        writers: HashSet<NodeId>,
    },

    /// Immutable after creation - reject all overwrites
    ///
    /// Multi-path safe: no conflicts possible since object can't be modified.
    WriteOnce,
}

impl Default for ConsistencyMode {
    fn default() -> Self {
        // Default to Exclusive with no owner (must be set before use)
        ConsistencyMode::Exclusive {
            owner: 0,
            lease_expires_ms: 0,
        }
    }
}

impl ConsistencyMode {
    /// Create an Exclusive mode with the given owner and lease duration
    pub fn exclusive(owner: NodeId, lease_duration_ms: u64) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        ConsistencyMode::Exclusive {
            owner,
            lease_expires_ms: now + lease_duration_ms,
        }
    }

    /// Create a Shared mode with the given primary
    pub fn shared(primary: NodeId) -> Self {
        ConsistencyMode::Shared {
            primary,
            writers: HashSet::new(),
        }
    }

    /// Create a Shared mode with restricted writers
    pub fn shared_restricted(primary: NodeId, writers: impl IntoIterator<Item = NodeId>) -> Self {
        ConsistencyMode::Shared {
            primary,
            writers: writers.into_iter().collect(),
        }
    }

    /// Check if a node can write in this mode
    pub fn can_write(&self, node_id: NodeId, current_time_ms: u64) -> bool {
        match self {
            ConsistencyMode::Exclusive {
                owner,
                lease_expires_ms,
            } => *owner == node_id && current_time_ms < *lease_expires_ms,
            ConsistencyMode::Shared { writers, .. } => {
                writers.is_empty() || writers.contains(&node_id)
            }
            ConsistencyMode::WriteOnce => false,
        }
    }

    /// Check if a lease is expired (Exclusive mode only)
    pub fn is_lease_expired(&self, current_time_ms: u64) -> bool {
        match self {
            ConsistencyMode::Exclusive {
                lease_expires_ms, ..
            } => current_time_ms >= *lease_expires_ms,
            _ => false,
        }
    }

    /// Get the primary node (Shared mode only)
    pub fn primary(&self) -> Option<NodeId> {
        match self {
            ConsistencyMode::Shared { primary, .. } => Some(*primary),
            _ => None,
        }
    }

    /// Get the owner node (Exclusive mode only)
    pub fn owner(&self) -> Option<NodeId> {
        match self {
            ConsistencyMode::Exclusive { owner, .. } => Some(*owner),
            _ => None,
        }
    }
}

/// Object metadata with consistency information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectConsistencyMeta {
    /// Object identifier
    pub object_key: ObjectKey,
    /// Consistency mode
    pub mode: ConsistencyMode,
    /// Current write sequence (for Shared mode)
    pub sequence: u64,
    /// Size in bytes
    pub size: u64,
    /// Creation timestamp
    pub created_ms: u64,
    /// Last modification timestamp
    pub modified_ms: u64,
}

impl ObjectConsistencyMeta {
    /// Create new metadata with default settings
    pub fn new(object_key: ObjectKey, mode: ConsistencyMode) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        Self {
            object_key,
            mode,
            sequence: 0,
            size: 0,
            created_ms: now,
            modified_ms: now,
        }
    }

    /// Increment sequence and update timestamp
    pub fn increment_sequence(&mut self) -> u64 {
        self.sequence += 1;
        self.modified_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        self.sequence
    }
}

/// Sequenced write for Shared mode
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequencedWrite {
    /// Object identifier
    pub object_key: ObjectKey,
    /// Assigned sequence number
    pub sequence: u64,
    /// Writer node ID
    pub writer_id: NodeId,
    /// Hash of the data being written
    pub data_hash: [u8; 32],
    /// Timestamp when sequence was assigned
    pub timestamp_ms: u64,
}

/// Write result from primary serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WriteResult {
    /// Write accepted, here's the assigned sequence
    Accepted { sequence: u64 },
    /// Write rejected - not authorized
    Unauthorized,
    /// Write rejected - stale sequence (for optimistic writes)
    StaleSequence { expected: u64, received: u64 },
    /// Write rejected - object is immutable
    Immutable,
    /// Write rejected - not the owner (Exclusive mode)
    NotOwner { owner: NodeId },
    /// Write rejected - lease expired
    LeaseExpired,
}

/// Error types for consistency operations
#[derive(Debug, Clone, thiserror::Error)]
pub enum ConsistencyError {
    /// Not authorized to write
    #[error("not authorized to write to this object")]
    Unauthorized,

    /// Stale sequence number
    #[error("stale sequence: expected {expected}, got {received}")]
    StaleSequence { expected: u64, received: u64 },

    /// Object is immutable
    #[error("object is immutable (WriteOnce mode)")]
    Immutable,

    /// Not the owner
    #[error("not the owner of this object: owner is node {owner}")]
    NotOwner { owner: NodeId },

    /// Lease expired
    #[error("lease expired at {expired_ms}, current time is {current_ms}")]
    LeaseExpired { expired_ms: u64, current_ms: u64 },

    /// Primary node unavailable
    #[error("primary node unavailable: node {primary}")]
    PrimaryUnavailable { primary: NodeId },

    /// Object not found
    #[error("object not found: {0}")]
    ObjectNotFound(String),
}

/// Bucket-level consistency configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketConsistencyConfig {
    /// Default mode for new objects in this bucket
    pub default_mode: ConsistencyModeTemplate,
    /// Allow overriding mode per-object
    pub allow_per_object_override: bool,
}

impl Default for BucketConsistencyConfig {
    fn default() -> Self {
        Self {
            default_mode: ConsistencyModeTemplate::Exclusive {
                lease_duration_ms: 300_000, // 5 minutes
            },
            allow_per_object_override: true,
        }
    }
}

/// Template for creating consistency modes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConsistencyModeTemplate {
    /// Exclusive with automatic owner assignment
    Exclusive {
        /// Default lease duration in milliseconds
        lease_duration_ms: u64,
    },
    /// Shared with configurable primary selection
    Shared {
        /// How to select the primary node
        primary_selection: PrimarySelection,
    },
    /// Immutable
    WriteOnce,
}

/// How to select the primary node for Shared mode
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PrimarySelection {
    /// First writer becomes primary
    FirstWriter,
    /// Specific node is always primary
    Fixed(NodeId),
    /// Use Raft leader as primary
    RaftLeader,
}

impl Default for PrimarySelection {
    fn default() -> Self {
        PrimarySelection::RaftLeader
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn current_time_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    #[test]
    fn test_exclusive_mode_can_write() {
        let now = current_time_ms();
        let mode = ConsistencyMode::Exclusive {
            owner: 1,
            lease_expires_ms: now + 60_000,
        };

        // Owner can write
        assert!(mode.can_write(1, now));
        // Non-owner cannot
        assert!(!mode.can_write(2, now));
        // Owner cannot write after lease expires
        assert!(!mode.can_write(1, now + 120_000));
    }

    #[test]
    fn test_shared_mode_can_write() {
        // Open to all
        let open_mode = ConsistencyMode::Shared {
            primary: 1,
            writers: HashSet::new(),
        };
        assert!(open_mode.can_write(1, 0));
        assert!(open_mode.can_write(99, 0));

        // Restricted
        let mut writers = HashSet::new();
        writers.insert(1);
        writers.insert(2);
        let restricted = ConsistencyMode::Shared {
            primary: 1,
            writers,
        };
        assert!(restricted.can_write(1, 0));
        assert!(restricted.can_write(2, 0));
        assert!(!restricted.can_write(3, 0));
    }

    #[test]
    fn test_write_once_cannot_write() {
        let mode = ConsistencyMode::WriteOnce;
        assert!(!mode.can_write(1, 0));
        assert!(!mode.can_write(99, 0));
    }

    #[test]
    fn test_exclusive_lease_expired() {
        let now = current_time_ms();
        let mode = ConsistencyMode::Exclusive {
            owner: 1,
            lease_expires_ms: now - 1000, // Already expired
        };
        assert!(mode.is_lease_expired(now));

        let valid = ConsistencyMode::Exclusive {
            owner: 1,
            lease_expires_ms: now + 60_000,
        };
        assert!(!valid.is_lease_expired(now));
    }

    #[test]
    fn test_primary_getter() {
        let shared = ConsistencyMode::shared(42);
        assert_eq!(shared.primary(), Some(42));

        let exclusive = ConsistencyMode::exclusive(1, 60_000);
        assert_eq!(exclusive.primary(), None);
    }

    #[test]
    fn test_owner_getter() {
        let exclusive = ConsistencyMode::exclusive(42, 60_000);
        assert_eq!(exclusive.owner(), Some(42));

        let shared = ConsistencyMode::shared(1);
        assert_eq!(shared.owner(), None);
    }

    #[test]
    fn test_object_consistency_meta() {
        let key = ObjectKey::new("bucket", "key").unwrap();
        let mut meta = ObjectConsistencyMeta::new(key.clone(), ConsistencyMode::shared(1));

        assert_eq!(meta.sequence, 0);

        let seq1 = meta.increment_sequence();
        assert_eq!(seq1, 1);

        let seq2 = meta.increment_sequence();
        assert_eq!(seq2, 2);
    }

    #[test]
    fn test_bucket_consistency_config_default() {
        let config = BucketConsistencyConfig::default();
        assert!(config.allow_per_object_override);
        match config.default_mode {
            ConsistencyModeTemplate::Exclusive { lease_duration_ms } => {
                assert_eq!(lease_duration_ms, 300_000);
            }
            _ => panic!("Expected Exclusive mode"),
        }
    }
}
