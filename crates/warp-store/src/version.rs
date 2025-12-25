//! Object versioning and time-travel

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

/// A version identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VersionId(String);

impl VersionId {
    /// Create a new version ID
    pub fn new() -> Self {
        // Use timestamp + random for uniqueness
        let timestamp = Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64;
        let random: u64 = rand::random();
        Self(format!("{:016x}{:016x}", timestamp, random))
    }

    /// Create from string
    pub fn from_string(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Get the version ID as string
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The "null" version ID (for unversioned objects)
    pub fn null() -> Self {
        Self("null".to_string())
    }

    /// Check if this is the null version
    pub fn is_null(&self) -> bool {
        self.0 == "null"
    }
}

impl Default for VersionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for VersionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Versioning mode for a bucket
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum VersioningMode {
    /// Versioning is disabled
    #[default]
    Disabled,

    /// Versioning is enabled
    Enabled,

    /// Versioning was enabled but is now suspended
    Suspended,
}

impl VersioningMode {
    /// Check if versioning is active (enabled, not suspended)
    pub fn is_enabled(&self) -> bool {
        matches!(self, VersioningMode::Enabled)
    }

    /// Check if versioning was ever enabled
    pub fn was_enabled(&self) -> bool {
        matches!(self, VersioningMode::Enabled | VersioningMode::Suspended)
    }
}

/// A specific version of an object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Version {
    /// Version ID
    pub id: VersionId,

    /// Creation timestamp
    pub created_at: DateTime<Utc>,

    /// Content hash (BLAKE3)
    pub content_hash: [u8; 32],

    /// Object size
    pub size: u64,

    /// Whether this is the latest version
    pub is_latest: bool,

    /// Whether this is a delete marker
    pub is_delete_marker: bool,

    /// Previous version ID (for chaining)
    pub previous: Option<VersionId>,
}

impl Version {
    /// Create a new version
    pub fn new(content_hash: [u8; 32], size: u64) -> Self {
        Self {
            id: VersionId::new(),
            created_at: Utc::now(),
            content_hash,
            size,
            is_latest: true,
            is_delete_marker: false,
            previous: None,
        }
    }

    /// Create a delete marker version
    pub fn delete_marker() -> Self {
        Self {
            id: VersionId::new(),
            created_at: Utc::now(),
            content_hash: [0; 32],
            size: 0,
            is_latest: true,
            is_delete_marker: true,
            previous: None,
        }
    }

    /// Set the previous version
    pub fn with_previous(mut self, previous: VersionId) -> Self {
        self.previous = Some(previous);
        self
    }

    /// Mark as not latest
    pub fn as_historical(mut self) -> Self {
        self.is_latest = false;
        self
    }
}

/// Version list for an object
#[derive(Debug, Clone, Default)]
pub struct VersionList {
    /// All versions, newest first
    versions: Vec<Version>,
}

impl VersionList {
    /// Create new version list
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a new version (becomes latest)
    pub fn add(&mut self, mut version: Version) {
        // Mark existing latest as historical
        if let Some(current) = self.versions.first_mut() {
            version.previous = Some(current.id.clone());
            current.is_latest = false;
        }

        self.versions.insert(0, version);
    }

    /// Get the latest version
    pub fn latest(&self) -> Option<&Version> {
        self.versions.first()
    }

    /// Get a specific version by ID
    pub fn get(&self, id: &VersionId) -> Option<&Version> {
        self.versions.iter().find(|v| &v.id == id)
    }

    /// Get all versions
    pub fn all(&self) -> &[Version] {
        &self.versions
    }

    /// Number of versions
    pub fn len(&self) -> usize {
        self.versions.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.versions.is_empty()
    }

    /// Get versions at a point in time (time-travel)
    pub fn at_time(&self, timestamp: DateTime<Utc>) -> Option<&Version> {
        self.versions
            .iter()
            .find(|v| v.created_at <= timestamp && !v.is_delete_marker)
    }

    /// Prune old versions, keeping N most recent
    pub fn prune(&mut self, keep: usize) {
        if self.versions.len() > keep {
            self.versions.truncate(keep);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_id() {
        let v1 = VersionId::new();
        let v2 = VersionId::new();

        assert_ne!(v1, v2);
        assert!(!v1.is_null());
        assert!(VersionId::null().is_null());
    }

    #[test]
    fn test_versioning_mode() {
        assert!(!VersioningMode::Disabled.is_enabled());
        assert!(VersioningMode::Enabled.is_enabled());
        assert!(!VersioningMode::Suspended.is_enabled());

        assert!(!VersioningMode::Disabled.was_enabled());
        assert!(VersioningMode::Enabled.was_enabled());
        assert!(VersioningMode::Suspended.was_enabled());
    }

    #[test]
    fn test_version_list() {
        let mut list = VersionList::new();

        // Add first version
        let v1 = Version::new([1; 32], 100);
        let v1_id = v1.id.clone();
        list.add(v1);

        assert_eq!(list.len(), 1);
        assert!(list.latest().unwrap().is_latest);

        // Add second version
        let v2 = Version::new([2; 32], 200);
        list.add(v2);

        assert_eq!(list.len(), 2);
        assert!(list.latest().unwrap().is_latest);
        assert_eq!(list.latest().unwrap().size, 200);

        // First version should now be historical
        let v1_retrieved = list.get(&v1_id).unwrap();
        assert!(!v1_retrieved.is_latest);
    }

    #[test]
    fn test_time_travel() {
        let mut list = VersionList::new();

        // Add version at time T1
        let mut v1 = Version::new([1; 32], 100);
        v1.created_at = Utc::now() - chrono::Duration::hours(2);
        list.add(v1);

        // Add version at time T2
        let mut v2 = Version::new([2; 32], 200);
        v2.created_at = Utc::now() - chrono::Duration::hours(1);
        list.add(v2);

        // Query at T1.5 should return v1
        let query_time = Utc::now() - chrono::Duration::minutes(90);
        let result = list.at_time(query_time);
        assert!(result.is_some());
        assert_eq!(result.unwrap().size, 100);
    }
}
