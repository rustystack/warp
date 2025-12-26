//! Object Lock / WORM (Write Once Read Many) support
//!
//! Provides immutability guarantees for compliance and data protection:
//! - **Governance Mode**: Admins can override retention
//! - **Compliance Mode**: No one can delete/modify until retention expires
//! - **Legal Holds**: Indefinite hold regardless of retention
//!
//! # S3 Compatibility
//!
//! This implementation is compatible with S3 Object Lock API:
//! - `PUT /?object-lock` - Enable Object Lock on bucket
//! - `GET /?object-lock` - Get Object Lock configuration
//! - `PUT` with `x-amz-object-lock-*` headers - Set retention on upload
//! - `PUT /?retention` - Update object retention
//! - `GET /?retention` - Get object retention
//! - `PUT /?legal-hold` - Set legal hold
//! - `GET /?legal-hold` - Get legal hold status

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::version::VersionId;

/// Object Lock configuration for a bucket
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectLockConfig {
    /// Whether Object Lock is enabled on the bucket
    pub enabled: bool,

    /// Default retention mode (applied to new objects if not specified)
    pub default_retention: Option<DefaultRetention>,
}

impl Default for ObjectLockConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_retention: None,
        }
    }
}

impl ObjectLockConfig {
    /// Create a new Object Lock configuration with lock enabled
    pub fn enabled() -> Self {
        Self {
            enabled: true,
            default_retention: None,
        }
    }

    /// Create with default governance mode retention
    pub fn with_governance_days(days: u32) -> Self {
        Self {
            enabled: true,
            default_retention: Some(DefaultRetention {
                mode: RetentionMode::Governance,
                days: Some(days),
                years: None,
            }),
        }
    }

    /// Create with default compliance mode retention
    pub fn with_compliance_days(days: u32) -> Self {
        Self {
            enabled: true,
            default_retention: Some(DefaultRetention {
                mode: RetentionMode::Compliance,
                days: Some(days),
                years: None,
            }),
        }
    }

    /// Create with default retention in years
    pub fn with_retention_years(mode: RetentionMode, years: u32) -> Self {
        Self {
            enabled: true,
            default_retention: Some(DefaultRetention {
                mode,
                days: None,
                years: Some(years),
            }),
        }
    }

    /// Calculate retention expiry date based on default retention
    pub fn calculate_default_expiry(&self) -> Option<DateTime<Utc>> {
        self.default_retention.as_ref().map(|r| r.calculate_expiry())
    }
}

/// Default retention settings for a bucket
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultRetention {
    /// Retention mode
    pub mode: RetentionMode,

    /// Retention period in days (mutually exclusive with years)
    pub days: Option<u32>,

    /// Retention period in years (mutually exclusive with days)
    pub years: Option<u32>,
}

impl DefaultRetention {
    /// Calculate the expiry date from now
    pub fn calculate_expiry(&self) -> DateTime<Utc> {
        let now = Utc::now();
        if let Some(days) = self.days {
            now + Duration::days(days as i64)
        } else if let Some(years) = self.years {
            now + Duration::days(years as i64 * 365)
        } else {
            now
        }
    }
}

/// Retention mode
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RetentionMode {
    /// Governance mode - can be overridden by users with special permissions
    ///
    /// Use this for soft compliance where admins may need to delete data
    /// in exceptional circumstances (e.g., PII deletion requests).
    Governance,

    /// Compliance mode - cannot be overridden by anyone, including root
    ///
    /// Use this for strict regulatory compliance (SEC 17a-4, FINRA, etc.)
    /// where data MUST be retained for the specified period.
    Compliance,
}

impl std::fmt::Display for RetentionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RetentionMode::Governance => write!(f, "GOVERNANCE"),
            RetentionMode::Compliance => write!(f, "COMPLIANCE"),
        }
    }
}

impl std::str::FromStr for RetentionMode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_uppercase().as_str() {
            "GOVERNANCE" => Ok(RetentionMode::Governance),
            "COMPLIANCE" => Ok(RetentionMode::Compliance),
            _ => Err(Error::InvalidArgument(format!(
                "Invalid retention mode: {}. Must be GOVERNANCE or COMPLIANCE",
                s
            ))),
        }
    }
}

/// Object retention settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectRetention {
    /// Retention mode
    pub mode: RetentionMode,

    /// Date until which the object is locked
    pub retain_until_date: DateTime<Utc>,
}

impl ObjectRetention {
    /// Create a new retention with specified mode and duration in days
    pub fn new(mode: RetentionMode, days: u32) -> Self {
        Self {
            mode,
            retain_until_date: Utc::now() + Duration::days(days as i64),
        }
    }

    /// Create a new retention with specific expiry date
    pub fn until(mode: RetentionMode, until: DateTime<Utc>) -> Self {
        Self {
            mode,
            retain_until_date: until,
        }
    }

    /// Check if the retention has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.retain_until_date
    }

    /// Check if the object can be deleted
    pub fn can_delete(&self, bypass_governance: bool) -> bool {
        if self.is_expired() {
            return true;
        }

        match self.mode {
            RetentionMode::Governance => bypass_governance,
            RetentionMode::Compliance => false,
        }
    }

    /// Check if the object can be modified
    pub fn can_modify(&self, bypass_governance: bool) -> bool {
        // Same rules as deletion
        self.can_delete(bypass_governance)
    }

    /// Extend the retention period (only allowed to extend, not shorten)
    pub fn extend(&mut self, new_until: DateTime<Utc>) -> Result<()> {
        if new_until <= self.retain_until_date {
            return Err(Error::InvalidArgument(
                "Retention period can only be extended, not shortened".to_string(),
            ));
        }
        self.retain_until_date = new_until;
        Ok(())
    }

    /// Time remaining until retention expires
    pub fn time_remaining(&self) -> Option<Duration> {
        let remaining = self.retain_until_date - Utc::now();
        if remaining.num_seconds() > 0 {
            Some(remaining)
        } else {
            None
        }
    }
}

/// Legal hold status
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LegalHoldStatus {
    /// Legal hold is active - object cannot be deleted
    On,

    /// Legal hold is not active
    Off,
}

impl Default for LegalHoldStatus {
    fn default() -> Self {
        LegalHoldStatus::Off
    }
}

impl std::fmt::Display for LegalHoldStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LegalHoldStatus::On => write!(f, "ON"),
            LegalHoldStatus::Off => write!(f, "OFF"),
        }
    }
}

impl std::str::FromStr for LegalHoldStatus {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_uppercase().as_str() {
            "ON" => Ok(LegalHoldStatus::On),
            "OFF" => Ok(LegalHoldStatus::Off),
            _ => Err(Error::InvalidArgument(format!(
                "Invalid legal hold status: {}. Must be ON or OFF",
                s
            ))),
        }
    }
}

/// Complete lock status for an object version
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ObjectLockStatus {
    /// Retention settings (if any)
    pub retention: Option<ObjectRetention>,

    /// Legal hold status
    pub legal_hold: LegalHoldStatus,
}

impl ObjectLockStatus {
    /// Create a new lock status with retention
    pub fn with_retention(retention: ObjectRetention) -> Self {
        Self {
            retention: Some(retention),
            legal_hold: LegalHoldStatus::Off,
        }
    }

    /// Create a new lock status with legal hold
    pub fn with_legal_hold() -> Self {
        Self {
            retention: None,
            legal_hold: LegalHoldStatus::On,
        }
    }

    /// Check if the object is currently locked (cannot be deleted/modified)
    pub fn is_locked(&self) -> bool {
        // Legal hold always locks
        if self.legal_hold == LegalHoldStatus::On {
            return true;
        }

        // Check retention
        if let Some(ref retention) = self.retention {
            return !retention.is_expired();
        }

        false
    }

    /// Check if deletion is allowed
    pub fn can_delete(&self, bypass_governance: bool) -> bool {
        // Legal hold blocks deletion regardless of permissions
        if self.legal_hold == LegalHoldStatus::On {
            return false;
        }

        // Check retention
        if let Some(ref retention) = self.retention {
            return retention.can_delete(bypass_governance);
        }

        true
    }

    /// Check if modification is allowed
    pub fn can_modify(&self, bypass_governance: bool) -> bool {
        self.can_delete(bypass_governance)
    }

    /// Set legal hold
    pub fn set_legal_hold(&mut self, status: LegalHoldStatus) {
        self.legal_hold = status;
    }

    /// Set retention
    pub fn set_retention(&mut self, retention: ObjectRetention) {
        self.retention = Some(retention);
    }

    /// Clear retention (only if expired or governance mode with bypass)
    pub fn clear_retention(&mut self, bypass_governance: bool) -> Result<()> {
        if let Some(ref retention) = self.retention {
            if !retention.can_delete(bypass_governance) {
                return Err(Error::ObjectLocked(
                    "Cannot clear retention: object is locked".to_string(),
                ));
            }
        }
        self.retention = None;
        Ok(())
    }
}

/// Object Lock entry stored per object version
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectLockEntry {
    /// Bucket name
    pub bucket: String,

    /// Object key
    pub key: String,

    /// Version ID
    pub version_id: VersionId,

    /// Lock status
    pub status: ObjectLockStatus,

    /// When the lock was created/modified
    pub modified_at: DateTime<Utc>,
}

impl ObjectLockEntry {
    /// Create a new lock entry
    pub fn new(
        bucket: impl Into<String>,
        key: impl Into<String>,
        version_id: VersionId,
        status: ObjectLockStatus,
    ) -> Self {
        Self {
            bucket: bucket.into(),
            key: key.into(),
            version_id,
            status,
            modified_at: Utc::now(),
        }
    }
}

/// Manager for Object Lock operations
pub struct ObjectLockManager {
    /// Lock entries stored in memory (in production, use persistent storage)
    entries: dashmap::DashMap<(String, String, VersionId), ObjectLockEntry>,

    /// Bucket lock configurations
    bucket_configs: dashmap::DashMap<String, ObjectLockConfig>,
}

impl ObjectLockManager {
    /// Create a new Object Lock manager
    pub fn new() -> Self {
        Self {
            entries: dashmap::DashMap::new(),
            bucket_configs: dashmap::DashMap::new(),
        }
    }

    /// Enable Object Lock on a bucket
    pub fn enable_bucket_lock(&self, bucket: &str, config: ObjectLockConfig) -> Result<()> {
        if !config.enabled {
            return Err(Error::InvalidArgument(
                "Cannot set Object Lock config with enabled=false".to_string(),
            ));
        }

        // Object Lock can only be enabled at bucket creation
        // Check if already configured
        if self.bucket_configs.contains_key(bucket) {
            return Err(Error::InvalidArgument(
                "Object Lock is already configured on this bucket".to_string(),
            ));
        }

        self.bucket_configs.insert(bucket.to_string(), config);
        Ok(())
    }

    /// Get bucket Object Lock configuration
    pub fn get_bucket_config(&self, bucket: &str) -> Option<ObjectLockConfig> {
        self.bucket_configs.get(bucket).map(|c| c.clone())
    }

    /// Check if Object Lock is enabled on a bucket
    pub fn is_bucket_locked(&self, bucket: &str) -> bool {
        self.bucket_configs
            .get(bucket)
            .map(|c| c.enabled)
            .unwrap_or(false)
    }

    /// Set retention on an object version
    pub fn set_retention(
        &self,
        bucket: &str,
        key: &str,
        version_id: VersionId,
        retention: ObjectRetention,
    ) -> Result<()> {
        // Check if bucket has Object Lock enabled
        if !self.is_bucket_locked(bucket) {
            return Err(Error::InvalidArgument(
                "Object Lock is not enabled on this bucket".to_string(),
            ));
        }

        let entry_key = (bucket.to_string(), key.to_string(), version_id.clone());

        // Check if there's existing retention that blocks this
        if let Some(existing) = self.entries.get(&entry_key) {
            if let Some(ref existing_retention) = existing.status.retention {
                // Can only extend retention, not shorten
                if retention.retain_until_date < existing_retention.retain_until_date {
                    // For compliance mode, cannot shorten at all
                    if existing_retention.mode == RetentionMode::Compliance {
                        return Err(Error::ObjectLocked(
                            "Cannot shorten retention period in COMPLIANCE mode".to_string(),
                        ));
                    }
                    // For governance mode, would need bypass (not implemented in this call)
                    return Err(Error::ObjectLocked(
                        "Cannot shorten retention period without bypass".to_string(),
                    ));
                }
            }
        }

        // Set or update the entry
        self.entries
            .entry(entry_key)
            .and_modify(|e| {
                e.status.retention = Some(retention.clone());
                e.modified_at = Utc::now();
            })
            .or_insert_with(|| {
                ObjectLockEntry::new(
                    bucket,
                    key,
                    version_id,
                    ObjectLockStatus::with_retention(retention),
                )
            });

        Ok(())
    }

    /// Get retention for an object version
    pub fn get_retention(
        &self,
        bucket: &str,
        key: &str,
        version_id: &VersionId,
    ) -> Option<ObjectRetention> {
        let entry_key = (bucket.to_string(), key.to_string(), version_id.clone());
        self.entries
            .get(&entry_key)
            .and_then(|e| e.status.retention.clone())
    }

    /// Set legal hold on an object version
    pub fn set_legal_hold(
        &self,
        bucket: &str,
        key: &str,
        version_id: VersionId,
        status: LegalHoldStatus,
    ) -> Result<()> {
        // Check if bucket has Object Lock enabled
        if !self.is_bucket_locked(bucket) {
            return Err(Error::InvalidArgument(
                "Object Lock is not enabled on this bucket".to_string(),
            ));
        }

        let entry_key = (bucket.to_string(), key.to_string(), version_id.clone());

        self.entries
            .entry(entry_key)
            .and_modify(|e| {
                e.status.legal_hold = status;
                e.modified_at = Utc::now();
            })
            .or_insert_with(|| {
                let mut lock_status = ObjectLockStatus::default();
                lock_status.legal_hold = status;
                ObjectLockEntry::new(bucket, key, version_id, lock_status)
            });

        Ok(())
    }

    /// Get legal hold status for an object version
    pub fn get_legal_hold(
        &self,
        bucket: &str,
        key: &str,
        version_id: &VersionId,
    ) -> LegalHoldStatus {
        let entry_key = (bucket.to_string(), key.to_string(), version_id.clone());
        self.entries
            .get(&entry_key)
            .map(|e| e.status.legal_hold)
            .unwrap_or(LegalHoldStatus::Off)
    }

    /// Get full lock status for an object version
    pub fn get_lock_status(
        &self,
        bucket: &str,
        key: &str,
        version_id: &VersionId,
    ) -> ObjectLockStatus {
        let entry_key = (bucket.to_string(), key.to_string(), version_id.clone());
        self.entries
            .get(&entry_key)
            .map(|e| e.status.clone())
            .unwrap_or_default()
    }

    /// Check if an object can be deleted
    pub fn can_delete(
        &self,
        bucket: &str,
        key: &str,
        version_id: &VersionId,
        bypass_governance: bool,
    ) -> bool {
        let status = self.get_lock_status(bucket, key, version_id);
        status.can_delete(bypass_governance)
    }

    /// Check if an object can be modified
    pub fn can_modify(
        &self,
        bucket: &str,
        key: &str,
        version_id: &VersionId,
        bypass_governance: bool,
    ) -> bool {
        let status = self.get_lock_status(bucket, key, version_id);
        status.can_modify(bypass_governance)
    }

    /// Apply default retention from bucket config (called on object upload)
    pub fn apply_default_retention(
        &self,
        bucket: &str,
        key: &str,
        version_id: VersionId,
    ) -> Result<Option<ObjectRetention>> {
        if let Some(config) = self.get_bucket_config(bucket) {
            if let Some(ref default) = config.default_retention {
                let retention = ObjectRetention {
                    mode: default.mode,
                    retain_until_date: default.calculate_expiry(),
                };
                self.set_retention(bucket, key, version_id, retention.clone())?;
                return Ok(Some(retention));
            }
        }
        Ok(None)
    }
}

impl Default for ObjectLockManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retention_mode_parse() {
        assert_eq!(
            "GOVERNANCE".parse::<RetentionMode>().unwrap(),
            RetentionMode::Governance
        );
        assert_eq!(
            "governance".parse::<RetentionMode>().unwrap(),
            RetentionMode::Governance
        );
        assert_eq!(
            "COMPLIANCE".parse::<RetentionMode>().unwrap(),
            RetentionMode::Compliance
        );
        assert!("invalid".parse::<RetentionMode>().is_err());
    }

    #[test]
    fn test_retention_expiry() {
        let retention = ObjectRetention::new(RetentionMode::Governance, 30);
        assert!(!retention.is_expired());
        assert!(retention.time_remaining().is_some());

        let expired =
            ObjectRetention::until(RetentionMode::Compliance, Utc::now() - Duration::days(1));
        assert!(expired.is_expired());
        assert!(expired.time_remaining().is_none());
    }

    #[test]
    fn test_governance_bypass() {
        let retention = ObjectRetention::new(RetentionMode::Governance, 30);
        assert!(!retention.can_delete(false));
        assert!(retention.can_delete(true)); // Governance can be bypassed
    }

    #[test]
    fn test_compliance_no_bypass() {
        let retention = ObjectRetention::new(RetentionMode::Compliance, 30);
        assert!(!retention.can_delete(false));
        assert!(!retention.can_delete(true)); // Compliance cannot be bypassed
    }

    #[test]
    fn test_legal_hold_blocks_deletion() {
        let mut status = ObjectLockStatus::default();
        assert!(status.can_delete(false));

        status.set_legal_hold(LegalHoldStatus::On);
        assert!(!status.can_delete(false));
        assert!(!status.can_delete(true)); // Legal hold blocks even with bypass
    }

    #[test]
    fn test_retention_extend_only() {
        let mut retention = ObjectRetention::new(RetentionMode::Governance, 30);
        let original = retention.retain_until_date;

        // Can extend
        assert!(retention
            .extend(original + Duration::days(10))
            .is_ok());

        // Cannot shorten
        assert!(retention.extend(original).is_err());
    }

    #[test]
    fn test_object_lock_manager() {
        let manager = ObjectLockManager::new();
        let bucket = "test-bucket";
        let key = "test-key";
        let version_id = VersionId::new();

        // Enable lock on bucket
        manager
            .enable_bucket_lock(bucket, ObjectLockConfig::enabled())
            .unwrap();
        assert!(manager.is_bucket_locked(bucket));

        // Set retention
        let retention = ObjectRetention::new(RetentionMode::Governance, 30);
        manager
            .set_retention(bucket, key, version_id.clone(), retention)
            .unwrap();

        // Check lock status
        assert!(!manager.can_delete(bucket, key, &version_id, false));
        assert!(manager.can_delete(bucket, key, &version_id, true)); // Governance bypass

        // Set legal hold
        manager
            .set_legal_hold(bucket, key, version_id.clone(), LegalHoldStatus::On)
            .unwrap();

        // Now even bypass doesn't work
        assert!(!manager.can_delete(bucket, key, &version_id, true));
    }

    #[test]
    fn test_default_retention() {
        let manager = ObjectLockManager::new();
        let bucket = "compliance-bucket";

        // Enable with default compliance retention
        manager
            .enable_bucket_lock(bucket, ObjectLockConfig::with_compliance_days(365))
            .unwrap();

        let version_id = VersionId::new();
        let applied = manager
            .apply_default_retention(bucket, "new-object", version_id.clone())
            .unwrap();

        assert!(applied.is_some());
        let retention = applied.unwrap();
        assert_eq!(retention.mode, RetentionMode::Compliance);
    }

    #[test]
    fn test_lock_not_enabled_error() {
        let manager = ObjectLockManager::new();
        let version_id = VersionId::new();

        // Try to set retention on bucket without lock enabled
        let result = manager.set_retention(
            "unlocked-bucket",
            "key",
            version_id,
            ObjectRetention::new(RetentionMode::Governance, 30),
        );

        assert!(result.is_err());
    }
}
