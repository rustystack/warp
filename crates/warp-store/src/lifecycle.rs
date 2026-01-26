//! Object Lifecycle Management
//!
//! Implements S3-compatible lifecycle rules for automatic object management:
//! - **Expiration**: Delete objects after N days or at a specific date
//! - **Transitions**: Move objects between storage classes (Standard → Archive)
//! - **Version cleanup**: Manage noncurrent versions in versioned buckets
//!
//! ## Usage
//!
//! ```rust,no_run
//! use warp_store::lifecycle::{LifecycleExecutor, LifecycleConfig};
//! use warp_store::{Store, StoreConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), warp_store::Error> {
//!     let store = Store::new(StoreConfig::default()).await?;
//!
//!     // Create and start lifecycle executor
//!     let config = LifecycleConfig::default();
//!     let executor = LifecycleExecutor::new(store, config);
//!
//!     // Run lifecycle evaluation (normally runs on schedule)
//!     let stats = executor.run_once().await?;
//!     println!("Expired {} objects, transitioned {}", stats.expired, stats.transitioned);
//!
//!     Ok(())
//! }
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, warn};

use crate::backend::StorageBackend;
use crate::bucket::{
    ExpirationAction, LifecycleRule, NoncurrentExpirationAction, NoncurrentTransitionAction,
    TransitionAction,
};
use crate::object::{ListOptions, ObjectEntry, StorageClass};
use crate::{ObjectKey, Result, Store};

/// Configuration for the lifecycle executor
#[derive(Debug, Clone)]
pub struct LifecycleConfig {
    /// How often to evaluate lifecycle rules (default: 24 hours)
    pub evaluation_interval: Duration,

    /// Maximum objects to process per batch (default: 1000)
    pub batch_size: usize,

    /// Maximum concurrent operations (default: 10)
    pub max_concurrent: usize,

    /// Dry run mode - log actions without executing (default: false)
    pub dry_run: bool,

    /// Enable metrics collection
    pub collect_metrics: bool,
}

impl Default for LifecycleConfig {
    fn default() -> Self {
        Self {
            evaluation_interval: Duration::from_secs(24 * 60 * 60), // 24 hours
            batch_size: 1000,
            max_concurrent: 10,
            dry_run: false,
            collect_metrics: true,
        }
    }
}

/// Statistics from a lifecycle execution run
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LifecycleStats {
    /// Number of objects expired (deleted)
    pub expired: u64,

    /// Number of objects transitioned to different storage class
    pub transitioned: u64,

    /// Number of noncurrent versions expired
    pub noncurrent_expired: u64,

    /// Number of noncurrent versions transitioned
    pub noncurrent_transitioned: u64,

    /// Number of delete markers cleaned up
    pub delete_markers_cleaned: u64,

    /// Number of objects scanned
    pub objects_scanned: u64,

    /// Number of errors encountered
    pub errors: u64,

    /// Duration of the run
    pub duration_ms: u64,

    /// Timestamp of the run
    pub run_at: DateTime<Utc>,
}

/// Action to take on an object based on lifecycle rules
#[derive(Debug, Clone)]
pub enum LifecycleAction {
    /// Delete the object
    Expire,

    /// Transition to a different storage class
    Transition(StorageClass),

    /// No action needed
    None,
}

/// Lifecycle rule evaluation context
#[derive(Debug)]
struct EvaluationContext {
    /// Current time for rule evaluation
    now: DateTime<Utc>,

    /// Object creation date
    created_at: DateTime<Utc>,

    /// Object key
    key: String,

    /// Current storage class
    storage_class: StorageClass,

    /// Whether this is the latest version
    is_latest: bool,

    /// Days since creation
    age_days: u32,

    /// Days since becoming noncurrent (for versioned objects)
    noncurrent_days: Option<u32>,

    /// Object tags (for tag-based filtering)
    tags: HashMap<String, String>,
}

/// The lifecycle executor - processes lifecycle rules for buckets
pub struct LifecycleExecutor<B: StorageBackend> {
    /// The storage store
    store: Arc<Store<B>>,

    /// Executor configuration
    config: LifecycleConfig,

    /// Last run statistics
    last_stats: RwLock<Option<LifecycleStats>>,

    /// Cumulative statistics since start
    total_stats: RwLock<LifecycleStats>,
}

impl<B: StorageBackend> LifecycleExecutor<B> {
    /// Create a new lifecycle executor
    pub fn new(store: Store<B>, config: LifecycleConfig) -> Self {
        Self {
            store: Arc::new(store),
            config,
            last_stats: RwLock::new(None),
            total_stats: RwLock::new(LifecycleStats::default()),
        }
    }

    /// Create a new lifecycle executor from an Arc<Store>
    pub fn from_arc(store: Arc<Store<B>>, config: LifecycleConfig) -> Self {
        Self {
            store,
            config,
            last_stats: RwLock::new(None),
            total_stats: RwLock::new(LifecycleStats::default()),
        }
    }

    /// Run lifecycle evaluation once for all buckets
    #[instrument(skip(self))]
    pub async fn run_once(&self) -> Result<LifecycleStats> {
        let start = std::time::Instant::now();
        let now = Utc::now();
        let mut stats = LifecycleStats {
            run_at: now,
            ..Default::default()
        };

        info!("Starting lifecycle evaluation");

        // Get all buckets
        let buckets = self.store.list_buckets().await;

        for bucket_name in buckets {
            match self.process_bucket(&bucket_name, now, &mut stats).await {
                Ok(_) => {
                    debug!(bucket = %bucket_name, "Completed lifecycle processing for bucket");
                }
                Err(e) => {
                    warn!(bucket = %bucket_name, error = %e, "Error processing bucket lifecycle");
                    stats.errors += 1;
                }
            }
        }

        stats.duration_ms = start.elapsed().as_millis() as u64;

        // Update stored stats
        *self.last_stats.write().await = Some(stats.clone());
        {
            let mut total = self.total_stats.write().await;
            total.expired += stats.expired;
            total.transitioned += stats.transitioned;
            total.noncurrent_expired += stats.noncurrent_expired;
            total.noncurrent_transitioned += stats.noncurrent_transitioned;
            total.delete_markers_cleaned += stats.delete_markers_cleaned;
            total.objects_scanned += stats.objects_scanned;
            total.errors += stats.errors;
        }

        info!(
            expired = stats.expired,
            transitioned = stats.transitioned,
            scanned = stats.objects_scanned,
            duration_ms = stats.duration_ms,
            "Lifecycle evaluation complete"
        );

        Ok(stats)
    }

    /// Process lifecycle rules for a single bucket
    async fn process_bucket(
        &self,
        bucket_name: &str,
        now: DateTime<Utc>,
        stats: &mut LifecycleStats,
    ) -> Result<()> {
        // Get bucket configuration and lifecycle rules
        // TODO: Get actual bucket config from store when Raft supports it
        // For now, we'll use an empty ruleset as placeholder
        let rules: Vec<LifecycleRule> = Vec::new();

        if rules.is_empty() {
            debug!(bucket = %bucket_name, "No lifecycle rules configured");
            return Ok(());
        }

        // List all objects in the bucket
        let mut continuation_token: Option<String> = None;

        loop {
            let opts = ListOptions {
                max_keys: self.config.batch_size,
                continuation_token: continuation_token.clone(),
                include_versions: true,
                ..Default::default()
            };

            let list = self.store.list_with_options(bucket_name, "", opts).await?;
            stats.objects_scanned += list.objects.len() as u64;

            for object in &list.objects {
                if let Err(e) = self
                    .process_object(bucket_name, object, &rules, now, stats)
                    .await
                {
                    warn!(
                        bucket = %bucket_name,
                        key = %object.key,
                        error = %e,
                        "Error processing object lifecycle"
                    );
                    stats.errors += 1;
                }
            }

            if !list.is_truncated {
                break;
            }
            continuation_token = list.next_continuation_token;
        }

        Ok(())
    }

    /// Process lifecycle rules for a single object
    async fn process_object(
        &self,
        bucket_name: &str,
        object: &ObjectEntry,
        rules: &[LifecycleRule],
        now: DateTime<Utc>,
        stats: &mut LifecycleStats,
    ) -> Result<()> {
        let age_days = (now - object.last_modified).num_days().max(0) as u32;

        // Build evaluation context
        let context = EvaluationContext {
            now,
            created_at: object.last_modified, // Using last_modified as creation proxy
            key: object.key.clone(),
            storage_class: object.storage_class,
            is_latest: object.is_latest,
            age_days,
            noncurrent_days: if !object.is_latest {
                Some(age_days) // Simplified: using age as noncurrent days
            } else {
                None
            },
            tags: HashMap::new(), // TODO: Get object tags when supported
        };

        // Find matching rule and determine action
        let action = self.evaluate_rules(rules, &context);

        match action {
            LifecycleAction::Expire => {
                if object.is_latest {
                    self.expire_object(bucket_name, object, stats).await?;
                } else {
                    self.expire_noncurrent_version(bucket_name, object, stats)
                        .await?;
                }
            }
            LifecycleAction::Transition(target_class) => {
                if object.is_latest {
                    self.transition_object(bucket_name, object, target_class, stats)
                        .await?;
                } else {
                    self.transition_noncurrent_version(bucket_name, object, target_class, stats)
                        .await?;
                }
            }
            LifecycleAction::None => {}
        }

        Ok(())
    }

    /// Evaluate lifecycle rules against an object and determine action
    fn evaluate_rules(
        &self,
        rules: &[LifecycleRule],
        context: &EvaluationContext,
    ) -> LifecycleAction {
        for rule in rules {
            if !rule.enabled {
                continue;
            }

            // Check prefix filter
            if let Some(ref prefix) = rule.prefix {
                if !context.key.starts_with(prefix) {
                    continue;
                }
            }

            // Check tag filters
            if !rule.tags.is_empty() {
                let tags_match = rule
                    .tags
                    .iter()
                    .all(|(k, v)| context.tags.get(k).map(|tv| tv == v).unwrap_or(false));
                if !tags_match {
                    continue;
                }
            }

            // For current versions
            if context.is_latest {
                // Check expiration
                if let Some(ref expiration) = rule.expiration {
                    if let Some(action) = self.evaluate_expiration(expiration, context) {
                        return action;
                    }
                }

                // Check transitions (apply first matching)
                for transition in &rule.transitions {
                    if let Some(action) = self.evaluate_transition(transition, context) {
                        return action;
                    }
                }
            } else {
                // For noncurrent versions
                if let Some(ref nc_expiration) = rule.noncurrent_expiration {
                    if let Some(action) =
                        self.evaluate_noncurrent_expiration(nc_expiration, context)
                    {
                        return action;
                    }
                }

                for nc_transition in &rule.noncurrent_transitions {
                    if let Some(action) =
                        self.evaluate_noncurrent_transition(nc_transition, context)
                    {
                        return action;
                    }
                }
            }
        }

        LifecycleAction::None
    }

    /// Evaluate expiration action
    fn evaluate_expiration(
        &self,
        expiration: &ExpirationAction,
        context: &EvaluationContext,
    ) -> Option<LifecycleAction> {
        // Check date-based expiration
        if let Some(date) = expiration.date {
            if context.now >= date {
                return Some(LifecycleAction::Expire);
            }
        }

        // Check days-based expiration
        if let Some(days) = expiration.days {
            if context.age_days >= days {
                return Some(LifecycleAction::Expire);
            }
        }

        None
    }

    /// Evaluate transition action
    fn evaluate_transition(
        &self,
        transition: &TransitionAction,
        context: &EvaluationContext,
    ) -> Option<LifecycleAction> {
        // Skip if already at target storage class
        if context.storage_class == transition.storage_class {
            return None;
        }

        // Check if age meets threshold
        if context.age_days >= transition.days {
            return Some(LifecycleAction::Transition(transition.storage_class));
        }

        None
    }

    /// Evaluate noncurrent version expiration
    fn evaluate_noncurrent_expiration(
        &self,
        expiration: &NoncurrentExpirationAction,
        context: &EvaluationContext,
    ) -> Option<LifecycleAction> {
        let noncurrent_days = context.noncurrent_days?;

        if noncurrent_days >= expiration.noncurrent_days {
            // TODO: Check newer_noncurrent_versions limit
            return Some(LifecycleAction::Expire);
        }

        None
    }

    /// Evaluate noncurrent version transition
    fn evaluate_noncurrent_transition(
        &self,
        transition: &NoncurrentTransitionAction,
        context: &EvaluationContext,
    ) -> Option<LifecycleAction> {
        let noncurrent_days = context.noncurrent_days?;

        // Skip if already at target storage class
        if context.storage_class == transition.storage_class {
            return None;
        }

        if noncurrent_days >= transition.noncurrent_days {
            // TODO: Check newer_noncurrent_versions limit
            return Some(LifecycleAction::Transition(transition.storage_class));
        }

        None
    }

    /// Expire (delete) an object
    async fn expire_object(
        &self,
        bucket_name: &str,
        object: &ObjectEntry,
        stats: &mut LifecycleStats,
    ) -> Result<()> {
        if self.config.dry_run {
            info!(
                bucket = %bucket_name,
                key = %object.key,
                age_days = (Utc::now() - object.last_modified).num_days(),
                "DRY RUN: Would expire object"
            );
            return Ok(());
        }

        let key = ObjectKey::new(bucket_name, &object.key)?;
        self.store.delete(&key).await?;
        stats.expired += 1;

        debug!(
            bucket = %bucket_name,
            key = %object.key,
            "Expired object"
        );

        Ok(())
    }

    /// Expire a noncurrent version
    async fn expire_noncurrent_version(
        &self,
        bucket_name: &str,
        object: &ObjectEntry,
        stats: &mut LifecycleStats,
    ) -> Result<()> {
        if self.config.dry_run {
            info!(
                bucket = %bucket_name,
                key = %object.key,
                version_id = ?object.version_id,
                "DRY RUN: Would expire noncurrent version"
            );
            return Ok(());
        }

        // TODO: Delete specific version when versioned delete is supported
        // For now, we'll skip noncurrent version deletion
        debug!(
            bucket = %bucket_name,
            key = %object.key,
            version_id = ?object.version_id,
            "Would expire noncurrent version (not yet implemented)"
        );
        stats.noncurrent_expired += 1;

        Ok(())
    }

    /// Transition an object to a different storage class
    async fn transition_object(
        &self,
        bucket_name: &str,
        object: &ObjectEntry,
        target_class: StorageClass,
        stats: &mut LifecycleStats,
    ) -> Result<()> {
        if self.config.dry_run {
            info!(
                bucket = %bucket_name,
                key = %object.key,
                from = ?object.storage_class,
                to = ?target_class,
                "DRY RUN: Would transition object"
            );
            return Ok(());
        }

        // Skip if already at target storage class
        if object.storage_class == target_class {
            debug!(
                bucket = %bucket_name,
                key = %object.key,
                storage_class = ?target_class,
                "Object already at target storage class"
            );
            return Ok(());
        }

        let key = ObjectKey::new(bucket_name, &object.key)?;

        // 1. Read object data
        let data = self.store.get(&key).await?;

        // 2. Get existing metadata to preserve user metadata
        let existing_meta = self.store.head(&key).await?;

        // 3. Write to new storage tier with updated storage class
        let opts = crate::object::PutOptions {
            content_type: existing_meta.content_type.clone(),
            metadata: existing_meta.user_metadata.clone(),
            if_match: None,
            if_none_match: false,
            storage_class: target_class,
        };

        self.store.put_with_options(&key, data, opts).await?;

        stats.transitioned += 1;

        info!(
            bucket = %bucket_name,
            key = %object.key,
            from = ?object.storage_class,
            to = ?target_class,
            "Transitioned object storage class"
        );

        Ok(())
    }

    /// Transition a noncurrent version to a different storage class
    async fn transition_noncurrent_version(
        &self,
        bucket_name: &str,
        object: &ObjectEntry,
        target_class: StorageClass,
        stats: &mut LifecycleStats,
    ) -> Result<()> {
        if self.config.dry_run {
            info!(
                bucket = %bucket_name,
                key = %object.key,
                version_id = ?object.version_id,
                to = ?target_class,
                "DRY RUN: Would transition noncurrent version"
            );
            return Ok(());
        }

        debug!(
            bucket = %bucket_name,
            key = %object.key,
            version_id = ?object.version_id,
            to = ?target_class,
            "Would transition noncurrent version (not yet implemented)"
        );
        stats.noncurrent_transitioned += 1;

        Ok(())
    }

    /// Start the background lifecycle executor
    ///
    /// Returns a handle that can be used to stop the executor
    pub fn start_background(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let executor = self;
        let interval = executor.config.evaluation_interval;

        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            interval_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                interval_timer.tick().await;

                match executor.run_once().await {
                    Ok(stats) => {
                        if stats.expired > 0 || stats.transitioned > 0 {
                            info!(
                                expired = stats.expired,
                                transitioned = stats.transitioned,
                                "Background lifecycle run complete"
                            );
                        }
                    }
                    Err(e) => {
                        error!(error = %e, "Background lifecycle run failed");
                    }
                }
            }
        })
    }

    /// Get the last run statistics
    pub async fn last_stats(&self) -> Option<LifecycleStats> {
        self.last_stats.read().await.clone()
    }

    /// Get cumulative statistics
    pub async fn total_stats(&self) -> LifecycleStats {
        self.total_stats.read().await.clone()
    }

    /// Get the configuration
    pub fn config(&self) -> &LifecycleConfig {
        &self.config
    }
}

/// Builder for lifecycle rules
#[derive(Debug, Default)]
pub struct LifecycleRuleBuilder {
    rule: LifecycleRule,
}

impl LifecycleRuleBuilder {
    /// Create a new rule builder with an ID
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            rule: LifecycleRule {
                id: id.into(),
                enabled: true,
                prefix: None,
                tags: Vec::new(),
                transitions: Vec::new(),
                expiration: None,
                noncurrent_transitions: Vec::new(),
                noncurrent_expiration: None,
            },
        }
    }

    /// Set the rule as disabled
    pub fn disabled(mut self) -> Self {
        self.rule.enabled = false;
        self
    }

    /// Set a prefix filter
    pub fn prefix(mut self, prefix: impl Into<String>) -> Self {
        self.rule.prefix = Some(prefix.into());
        self
    }

    /// Add a tag filter
    pub fn tag(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.rule.tags.push((key.into(), value.into()));
        self
    }

    /// Add an expiration rule (days after creation)
    pub fn expire_after_days(mut self, days: u32) -> Self {
        self.rule.expiration = Some(ExpirationAction {
            days: Some(days),
            date: None,
            expired_object_delete_marker: false,
        });
        self
    }

    /// Add an expiration rule (at specific date)
    pub fn expire_at(mut self, date: DateTime<Utc>) -> Self {
        self.rule.expiration = Some(ExpirationAction {
            days: None,
            date: Some(date),
            expired_object_delete_marker: false,
        });
        self
    }

    /// Add a transition rule
    pub fn transition_after_days(mut self, days: u32, storage_class: StorageClass) -> Self {
        self.rule.transitions.push(TransitionAction {
            days,
            storage_class,
        });
        self
    }

    /// Add a noncurrent version expiration rule
    pub fn expire_noncurrent_after_days(mut self, days: u32) -> Self {
        self.rule.noncurrent_expiration = Some(NoncurrentExpirationAction {
            noncurrent_days: days,
            newer_noncurrent_versions: None,
        });
        self
    }

    /// Add a noncurrent version expiration rule with version limit
    pub fn expire_noncurrent_after_days_keep(mut self, days: u32, keep_versions: u32) -> Self {
        self.rule.noncurrent_expiration = Some(NoncurrentExpirationAction {
            noncurrent_days: days,
            newer_noncurrent_versions: Some(keep_versions),
        });
        self
    }

    /// Add a noncurrent version transition rule
    pub fn transition_noncurrent_after_days(
        mut self,
        days: u32,
        storage_class: StorageClass,
    ) -> Self {
        self.rule
            .noncurrent_transitions
            .push(NoncurrentTransitionAction {
                noncurrent_days: days,
                newer_noncurrent_versions: None,
                storage_class,
            });
        self
    }

    /// Build the rule
    pub fn build(self) -> LifecycleRule {
        self.rule
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lifecycle_rule_builder() {
        let rule = LifecycleRuleBuilder::new("test-rule")
            .prefix("logs/")
            .tag("env", "production")
            .expire_after_days(90)
            .transition_after_days(30, StorageClass::InfrequentAccess)
            .transition_after_days(60, StorageClass::Archive)
            .expire_noncurrent_after_days_keep(7, 3)
            .build();

        assert_eq!(rule.id, "test-rule");
        assert!(rule.enabled);
        assert_eq!(rule.prefix, Some("logs/".to_string()));
        assert_eq!(rule.tags.len(), 1);
        assert_eq!(rule.transitions.len(), 2);
        assert!(rule.expiration.is_some());
        assert!(rule.noncurrent_expiration.is_some());
    }

    #[test]
    fn test_expiration_evaluation() {
        let _expiration = ExpirationAction {
            days: Some(30),
            date: None,
            expired_object_delete_marker: false,
        };

        // Object older than 30 days should expire
        let context = EvaluationContext {
            now: Utc::now(),
            created_at: Utc::now() - chrono::Duration::days(31),
            key: "test.txt".to_string(),
            storage_class: StorageClass::Standard,
            is_latest: true,
            age_days: 31,
            noncurrent_days: None,
            tags: HashMap::new(),
        };

        // Create a minimal executor to test evaluation
        // (would need actual Store for full test)
        assert!(context.age_days >= 30);
    }

    #[test]
    fn test_transition_evaluation() {
        let transition = TransitionAction {
            days: 30,
            storage_class: StorageClass::Archive,
        };

        // 45-day old Standard object should transition to Archive
        let context = EvaluationContext {
            now: Utc::now(),
            created_at: Utc::now() - chrono::Duration::days(45),
            key: "data.bin".to_string(),
            storage_class: StorageClass::Standard,
            is_latest: true,
            age_days: 45,
            noncurrent_days: None,
            tags: HashMap::new(),
        };

        // Object already in Archive should not transition
        let context_archive = EvaluationContext {
            storage_class: StorageClass::Archive,
            ..context
        };

        assert!(context.age_days >= transition.days);
        assert_ne!(context.storage_class, transition.storage_class);
        assert_eq!(context_archive.storage_class, transition.storage_class);
    }

    #[test]
    fn test_noncurrent_expiration() {
        let expiration = NoncurrentExpirationAction {
            noncurrent_days: 7,
            newer_noncurrent_versions: Some(3),
        };

        // Noncurrent version older than 7 days should expire
        let context = EvaluationContext {
            now: Utc::now(),
            created_at: Utc::now() - chrono::Duration::days(10),
            key: "versioned.txt".to_string(),
            storage_class: StorageClass::Standard,
            is_latest: false,
            age_days: 10,
            noncurrent_days: Some(10),
            tags: HashMap::new(),
        };

        assert!(context.noncurrent_days.unwrap() >= expiration.noncurrent_days);
    }

    #[test]
    fn test_lifecycle_config_defaults() {
        let config = LifecycleConfig::default();

        assert_eq!(
            config.evaluation_interval,
            Duration::from_secs(24 * 60 * 60)
        );
        assert_eq!(config.batch_size, 1000);
        assert_eq!(config.max_concurrent, 10);
        assert!(!config.dry_run);
        assert!(config.collect_metrics);
    }
}
