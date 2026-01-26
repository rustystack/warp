//! SLAI-driven Auto-Tiering Engine
//!
//! Automatically transitions objects between storage classes based on access patterns
//! learned by the SLAI (Sentient Latency-Aware Infrastructure) system.
//!
//! ## Overview
//!
//! The auto-tiering engine monitors object access patterns and workload predictions
//! to make intelligent decisions about storage class transitions:
//!
//! - **Hot → Standard**: Frequently accessed objects stay in fast storage
//! - **Warm → InfrequentAccess**: Periodically accessed objects move to cheaper storage
//! - **Cold → Archive**: Rarely accessed objects move to archival storage
//! - **GPU Pinned**: ML workloads keep model weights in GPU memory
//!
//! ## Integration with SLAI
//!
//! The engine integrates with:
//! - `AccessTracker`: Monitors read/write patterns and access frequency
//! - `WorkloadPredictor`: Predicts ML workload phases to avoid premature archiving
//! - `PlacementEngine`: Coordinates with placement decisions
//!
//! ## Example
//!
//! ```rust,no_run
//! use warp_store::autotier::{AutoTierEngine, AutoTierConfig};
//! use warp_store::slai::PlacementEngine;
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() {
//!     let placement_engine = Arc::new(PlacementEngine::new());
//!     let config = AutoTierConfig::default();
//!     let engine = AutoTierEngine::new(placement_engine, config);
//!
//!     // Run a single tiering evaluation
//!     let stats = engine.evaluate().await;
//!     println!("Promoted {} objects, demoted {}", stats.promotions, stats.demotions);
//! }
//! ```

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tracing::{debug, info, instrument, warn};

use crate::backend::StorageBackend;
use crate::object::{PutOptions, StorageClass};
use crate::slai::{AccessPattern, AccessTracker, PlacementEngine, WorkloadPredictor, WorkloadType};
use crate::{ObjectKey, Store};

/// Configuration for the auto-tiering engine
#[derive(Debug, Clone)]
pub struct AutoTierConfig {
    /// Interval between tiering evaluations (default: 1 hour)
    pub evaluation_interval: Duration,

    /// Age threshold for cold object detection (default: 7 days)
    pub cold_threshold: Duration,

    /// Age threshold for archive transition (default: 30 days)
    pub archive_threshold: Duration,

    /// Minimum accesses per day to be considered "hot"
    pub hot_access_rate: u64,

    /// Maximum concurrent transitions (default: 10)
    pub max_concurrent_transitions: usize,

    /// Dry run mode - log actions without executing (default: false)
    pub dry_run: bool,

    /// Respect active workloads - don't transition objects during active ML training
    pub respect_workloads: bool,

    /// Protected prefixes - never auto-transition these paths
    pub protected_prefixes: Vec<String>,

    /// Minimum object size for tiering (smaller objects stay in Standard)
    pub min_object_size: u64,

    /// Enable GPU pinning for inference workloads
    pub enable_gpu_pinning: bool,

    // ========================================================================
    // BrainLink DPU Integration
    // ========================================================================

    /// Enable DPU-aware tiering decisions
    ///
    /// When enabled, the tiering engine considers DPU capabilities when making
    /// decisions. For example, objects that benefit from inline compression or
    /// encryption may be preferentially stored on DPU-enabled nodes.
    pub enable_dpu_awareness: bool,

    /// Prefer DPU inline compression for large objects
    ///
    /// When DPU is available, objects larger than this threshold may be
    /// compressed inline during tier transitions for faster movement.
    pub dpu_compress_threshold: u64,

    /// Prefer DPU inline encryption for sensitive data
    ///
    /// When enabled, objects in sensitive prefixes will be preferentially
    /// stored on DPU nodes with inline encryption.
    pub dpu_encrypt_prefixes: Vec<String>,

    /// Minimum chunk size for DPU offload (bytes)
    pub min_dpu_chunk_size: u64,
}

impl Default for AutoTierConfig {
    fn default() -> Self {
        Self {
            evaluation_interval: Duration::from_secs(60 * 60), // 1 hour
            cold_threshold: Duration::from_secs(7 * 24 * 60 * 60), // 7 days
            archive_threshold: Duration::from_secs(30 * 24 * 60 * 60), // 30 days
            hot_access_rate: 1,                                // 1 access per day
            max_concurrent_transitions: 10,
            dry_run: false,
            respect_workloads: true,
            protected_prefixes: vec![
                "system/".to_string(),
                ".warp/".to_string(),
                "_metadata/".to_string(),
            ],
            min_object_size: 1024, // 1KB minimum
            enable_gpu_pinning: true,
            // DPU integration defaults
            enable_dpu_awareness: true,
            dpu_compress_threshold: 1024 * 1024, // 1MB
            dpu_encrypt_prefixes: vec!["secrets/".to_string(), "credentials/".to_string()],
            min_dpu_chunk_size: 64 * 1024, // 64KB
        }
    }
}

impl AutoTierConfig {
    /// Create a conservative config (less aggressive tiering)
    pub fn conservative() -> Self {
        Self {
            cold_threshold: Duration::from_secs(14 * 24 * 60 * 60), // 14 days
            archive_threshold: Duration::from_secs(90 * 24 * 60 * 60), // 90 days
            hot_access_rate: 2,
            ..Default::default()
        }
    }

    /// Create an aggressive config (more aggressive tiering for cost savings)
    pub fn aggressive() -> Self {
        Self {
            cold_threshold: Duration::from_secs(3 * 24 * 60 * 60), // 3 days
            archive_threshold: Duration::from_secs(14 * 24 * 60 * 60), // 14 days
            hot_access_rate: 1,
            ..Default::default()
        }
    }

    /// Create config optimized for ML workloads
    pub fn ml_optimized() -> Self {
        Self {
            respect_workloads: true,
            enable_gpu_pinning: true,
            // Don't archive checkpoints too quickly
            archive_threshold: Duration::from_secs(60 * 24 * 60 * 60), // 60 days
            protected_prefixes: vec![
                "system/".to_string(),
                ".warp/".to_string(),
                "_metadata/".to_string(),
                "checkpoints/".to_string(),
                "models/".to_string(),
            ],
            ..Default::default()
        }
    }
}

/// Statistics from a tiering evaluation run
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AutoTierStats {
    /// Objects promoted to faster storage
    pub promotions: u64,
    /// Objects demoted to slower storage
    pub demotions: u64,
    /// Objects transitioned to InfrequentAccess
    pub to_infrequent: u64,
    /// Objects transitioned to Archive
    pub to_archive: u64,
    /// Objects transitioned to Standard (promotion)
    pub to_standard: u64,
    /// Objects pinned to GPU memory
    pub gpu_pinned: u64,
    /// Objects skipped due to active workload
    pub workload_skipped: u64,
    /// Objects skipped due to protected prefix
    pub protected_skipped: u64,
    /// Errors encountered
    pub errors: u64,
    /// Duration of evaluation
    pub duration_ms: u64,
    /// Timestamp of evaluation
    pub evaluated_at: DateTime<Utc>,
    /// Total objects scanned
    pub objects_scanned: u64,
    /// Transitions using DPU inline processing
    pub dpu_transitions: u64,
    /// Transitions using DPU compression
    pub dpu_compressed: u64,
    /// Transitions using DPU encryption
    pub dpu_encrypted: u64,
}

/// Tiering decision for an object
#[derive(Debug, Clone)]
pub struct TierDecision {
    /// Object key
    pub key: String,
    /// Current storage class
    pub current_class: StorageClass,
    /// Target storage class
    pub target_class: StorageClass,
    /// Reason for decision
    pub reason: TierReason,
    /// Confidence in decision (0.0-1.0)
    pub confidence: f64,
    /// Use DPU inline processing for this transition
    ///
    /// When true, the transition should use DPU inline compression/encryption
    /// if available. This is determined by BrainLink integration.
    pub use_dpu_inline: bool,
    /// Recommended DPU operations
    pub dpu_ops: DpuOpsHint,
}

/// Hints for DPU inline operations during tier transitions
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DpuOpsHint {
    /// Use DPU inline compression
    pub compress: bool,
    /// Use DPU inline encryption
    pub encrypt: bool,
    /// Use DPU inline erasure coding
    pub erasure_code: bool,
}

/// Reason for a tiering decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TierReason {
    /// Object is cold (not accessed recently)
    Cold {
        /// Number of days since the object was last accessed
        days_since_access: u64,
    },
    /// Object is very cold (archive candidate)
    VeryCold {
        /// Number of days since the object was last accessed
        days_since_access: u64,
    },
    /// Object is hot (frequently accessed)
    Hot {
        /// Average number of accesses per day
        accesses_per_day: f64,
    },
    /// Object is part of active ML workload
    ActiveWorkload {
        /// The type of workload currently using this object
        workload_type: WorkloadType,
    },
    /// Object is model weights for inference
    InferenceModel,
    /// Access pattern indicates different tier
    PatternBased {
        /// The detected access pattern for this object
        pattern: AccessPattern,
    },
    /// Predicted future access
    Predicted {
        /// Number of predicted future accesses
        predicted_accesses: usize,
    },
    /// Object was explicitly marked
    ExplicitMark,
}

/// SLAI-driven auto-tiering engine
pub struct AutoTierEngine {
    /// SLAI placement engine (provides predictor and tracker)
    placement: Arc<PlacementEngine>,
    /// Engine configuration
    config: AutoTierConfig,
    /// Current tier assignments (key -> StorageClass)
    tier_assignments: RwLock<HashMap<String, StorageClass>>,
    /// Objects protected from tiering (key -> reason)
    protected_objects: RwLock<HashSet<String>>,
    /// Active sessions to consider
    active_sessions: RwLock<HashSet<String>>,
    /// Cumulative statistics
    total_stats: RwLock<AutoTierStats>,
    /// Last evaluation stats
    last_stats: RwLock<Option<AutoTierStats>>,
    /// Transition semaphore for rate limiting
    transition_semaphore: Semaphore,
}

impl AutoTierEngine {
    /// Create a new auto-tiering engine
    pub fn new(placement: Arc<PlacementEngine>, config: AutoTierConfig) -> Self {
        let max_concurrent = config.max_concurrent_transitions;
        Self {
            placement,
            config,
            tier_assignments: RwLock::new(HashMap::new()),
            protected_objects: RwLock::new(HashSet::new()),
            active_sessions: RwLock::new(HashSet::new()),
            total_stats: RwLock::new(AutoTierStats::default()),
            last_stats: RwLock::new(None),
            transition_semaphore: Semaphore::new(max_concurrent),
        }
    }

    /// Get the access tracker from the placement engine
    fn tracker(&self) -> &Arc<AccessTracker> {
        self.placement.tracker()
    }

    /// Get the workload predictor from the placement engine
    fn predictor(&self) -> &Arc<WorkloadPredictor> {
        self.placement.predictor()
    }

    /// Register an active session (prevents aggressive tiering of related objects)
    pub fn register_session(&self, session_id: &str) {
        self.active_sessions.write().insert(session_id.to_string());
    }

    /// Unregister a session
    pub fn unregister_session(&self, session_id: &str) {
        self.active_sessions.write().remove(session_id);
    }

    /// Mark an object as protected from auto-tiering
    pub fn protect_object(&self, key: &str) {
        self.protected_objects.write().insert(key.to_string());
    }

    /// Remove protection from an object
    pub fn unprotect_object(&self, key: &str) {
        self.protected_objects.write().remove(key);
    }

    /// Set the current tier assignment for an object
    pub fn set_tier(&self, key: &str, class: StorageClass) {
        self.tier_assignments.write().insert(key.to_string(), class);
    }

    /// Get the current tier assignment for an object
    pub fn get_tier(&self, key: &str) -> Option<StorageClass> {
        self.tier_assignments.read().get(key).copied()
    }

    /// Run a tiering evaluation
    #[instrument(skip(self))]
    pub async fn evaluate(&self) -> AutoTierStats {
        let start = Instant::now();
        let mut stats = AutoTierStats {
            evaluated_at: Utc::now(),
            ..Default::default()
        };

        info!("Starting auto-tiering evaluation");

        // Get candidates for tiering
        let decisions = self.collect_decisions(&mut stats);

        // Execute transitions
        for decision in decisions {
            if let Err(e) = self.execute_transition(&decision, &mut stats).await {
                warn!(
                    key = %decision.key,
                    error = %e,
                    "Failed to execute tier transition"
                );
                stats.errors += 1;
            }
        }

        stats.duration_ms = start.elapsed().as_millis() as u64;

        // Update stored stats
        *self.last_stats.write() = Some(stats.clone());
        {
            let mut total = self.total_stats.write();
            total.promotions += stats.promotions;
            total.demotions += stats.demotions;
            total.to_infrequent += stats.to_infrequent;
            total.to_archive += stats.to_archive;
            total.to_standard += stats.to_standard;
            total.gpu_pinned += stats.gpu_pinned;
            total.workload_skipped += stats.workload_skipped;
            total.protected_skipped += stats.protected_skipped;
            total.errors += stats.errors;
            total.objects_scanned += stats.objects_scanned;
            total.dpu_transitions += stats.dpu_transitions;
            total.dpu_compressed += stats.dpu_compressed;
            total.dpu_encrypted += stats.dpu_encrypted;
        }

        info!(
            promotions = stats.promotions,
            demotions = stats.demotions,
            dpu_transitions = stats.dpu_transitions,
            duration_ms = stats.duration_ms,
            "Auto-tiering evaluation complete"
        );

        stats
    }

    /// Collect tiering decisions for all tracked objects
    fn collect_decisions(&self, stats: &mut AutoTierStats) -> Vec<TierDecision> {
        let mut decisions = Vec::new();
        let tracker = self.tracker();

        // Get cold objects (candidates for demotion)
        let cold_objects = tracker.get_cold_objects(self.config.cold_threshold);
        let very_cold_objects = tracker.get_cold_objects(self.config.archive_threshold);
        let very_cold_set: HashSet<_> = very_cold_objects.into_iter().collect();

        // Get hot objects (candidates for promotion)
        let hot_objects = tracker.get_hot_objects(100);

        // Get active workload info
        let active_workloads = self.get_active_workloads();

        // Process cold objects
        for key in cold_objects {
            stats.objects_scanned += 1;

            // Skip protected objects
            if self.is_protected(&key) {
                stats.protected_skipped += 1;
                continue;
            }

            // Skip objects involved in active workloads
            if self.config.respect_workloads {
                if let Some(workload) = self.is_in_active_workload(&key, &active_workloads) {
                    debug!(key = %key, workload = ?workload, "Skipping object in active workload");
                    stats.workload_skipped += 1;
                    continue;
                }
            }

            let current_class = self.get_tier(&key).unwrap_or(StorageClass::Standard);

            // Determine target class based on coldness
            let (target_class, reason) =
                if very_cold_set.contains(&key) && current_class != StorageClass::Archive {
                    let days = self.config.archive_threshold.as_secs() / (24 * 60 * 60);
                    (
                        StorageClass::Archive,
                        TierReason::VeryCold {
                            days_since_access: days,
                        },
                    )
                } else if current_class == StorageClass::Standard {
                    let days = self.config.cold_threshold.as_secs() / (24 * 60 * 60);
                    (
                        StorageClass::InfrequentAccess,
                        TierReason::Cold {
                            days_since_access: days,
                        },
                    )
                } else {
                    continue; // Already in appropriate tier
                };

            if current_class != target_class {
                // Determine DPU hints based on config and object characteristics
                let dpu_ops = self.compute_dpu_hints(&key, target_class);
                let use_dpu = self.config.enable_dpu_awareness && dpu_ops.compress;

                decisions.push(TierDecision {
                    key,
                    current_class,
                    target_class,
                    reason,
                    confidence: 0.8,
                    use_dpu_inline: use_dpu,
                    dpu_ops,
                });
            }
        }

        // Process hot objects (promotions)
        for (key, obj_stats) in hot_objects {
            stats.objects_scanned += 1;

            let current_class = self.get_tier(&key).unwrap_or(StorageClass::Standard);

            // Skip if already in Standard
            if current_class == StorageClass::Standard {
                continue;
            }

            // Calculate access rate
            let elapsed_days = obj_stats
                .last_access
                .map(|t| t.elapsed().as_secs() / (24 * 60 * 60) + 1)
                .unwrap_or(1);
            let total_accesses = obj_stats.reads + obj_stats.writes;
            let access_rate = total_accesses as f64 / elapsed_days as f64;

            if access_rate >= self.config.hot_access_rate as f64 {
                decisions.push(TierDecision {
                    key,
                    current_class,
                    target_class: StorageClass::Standard,
                    reason: TierReason::Hot {
                        accesses_per_day: access_rate,
                    },
                    confidence: 0.9,
                    use_dpu_inline: false, // No DPU for promotions
                    dpu_ops: DpuOpsHint::default(),
                });
            }
        }

        // Check for GPU pinning candidates
        if self.config.enable_gpu_pinning {
            self.collect_gpu_pinning_decisions(&mut decisions, &active_workloads, stats);
        }

        decisions
    }

    /// Collect GPU pinning decisions for inference workloads
    fn collect_gpu_pinning_decisions(
        &self,
        decisions: &mut Vec<TierDecision>,
        active_workloads: &HashMap<String, WorkloadType>,
        stats: &mut AutoTierStats,
    ) {
        // Find inference sessions
        for (session_id, workload_type) in active_workloads {
            if *workload_type == WorkloadType::Inference {
                // Get predictions to find model files
                let prediction = self.predictor().predict(session_id);

                for key in &prediction.predicted_objects {
                    // Check if it looks like a model file
                    if self.is_model_file(key) {
                        let current_class = self.get_tier(key).unwrap_or(StorageClass::Standard);

                        if current_class != StorageClass::GpuPinned {
                            decisions.push(TierDecision {
                                key: key.clone(),
                                current_class,
                                target_class: StorageClass::GpuPinned,
                                reason: TierReason::InferenceModel,
                                confidence: 0.85,
                                use_dpu_inline: false, // GPU pinning doesn't need DPU
                                dpu_ops: DpuOpsHint::default(),
                            });
                            stats.objects_scanned += 1;
                        }
                    }
                }
            }
        }
    }

    /// Check if a key represents a model file
    fn is_model_file(&self, key: &str) -> bool {
        key.contains("model")
            || key.contains("weight")
            || key.ends_with(".bin")
            || key.ends_with(".pt")
            || key.ends_with(".pth")
            || key.ends_with(".safetensors")
            || key.ends_with(".onnx")
    }

    /// Compute DPU operation hints for a tier transition
    ///
    /// Determines which DPU inline operations should be used based on:
    /// - Object characteristics (size, prefix)
    /// - Target storage class
    /// - Configuration settings
    fn compute_dpu_hints(&self, key: &str, target_class: StorageClass) -> DpuOpsHint {
        if !self.config.enable_dpu_awareness {
            return DpuOpsHint::default();
        }

        let mut hints = DpuOpsHint::default();

        // Enable compression for archive transitions (cold storage)
        if target_class == StorageClass::Archive || target_class == StorageClass::InfrequentAccess {
            // Check if object stats indicate it's compressible
            // (For now, enable compression for all demotions)
            hints.compress = true;
        }

        // Enable encryption for sensitive prefixes
        for prefix in &self.config.dpu_encrypt_prefixes {
            if key.starts_with(prefix) {
                hints.encrypt = true;
                break;
            }
        }

        // Enable erasure coding for archive tier (for durability)
        if target_class == StorageClass::Archive {
            hints.erasure_code = true;
        }

        hints
    }

    /// Check if DPU inline processing is recommended for an object
    ///
    /// This method considers:
    /// - Object size (must be above threshold)
    /// - Workload type (checkpointing benefits most)
    /// - Target storage class
    pub fn should_use_dpu(&self, key: &str, size: u64, target_class: StorageClass) -> bool {
        if !self.config.enable_dpu_awareness {
            return false;
        }

        // Check size threshold
        if size < self.config.min_dpu_chunk_size {
            return false;
        }

        // Always use DPU for archive transitions of large objects
        if target_class == StorageClass::Archive && size >= self.config.dpu_compress_threshold {
            return true;
        }

        // Use DPU for encryption-required prefixes
        for prefix in &self.config.dpu_encrypt_prefixes {
            if key.starts_with(prefix) {
                return true;
            }
        }

        false
    }

    /// Check if object is protected from tiering
    fn is_protected(&self, key: &str) -> bool {
        // Check explicit protection
        if self.protected_objects.read().contains(key) {
            return true;
        }

        // Check prefix protection
        for prefix in &self.config.protected_prefixes {
            if key.starts_with(prefix) {
                return true;
            }
        }

        false
    }

    /// Get active workloads from registered sessions
    fn get_active_workloads(&self) -> HashMap<String, WorkloadType> {
        let sessions = self.active_sessions.read();
        let predictor = self.predictor();

        sessions
            .iter()
            .map(|s| (s.clone(), predictor.get_workload(s)))
            .collect()
    }

    /// Check if an object is involved in an active workload
    fn is_in_active_workload(
        &self,
        key: &str,
        active_workloads: &HashMap<String, WorkloadType>,
    ) -> Option<WorkloadType> {
        for (session_id, workload_type) in active_workloads {
            // Skip unknown workloads
            if *workload_type == WorkloadType::Unknown {
                continue;
            }

            // Check if this object was predicted for the session
            let prediction = self.predictor().predict(session_id);
            if prediction.predicted_objects.contains(&key.to_string()) {
                return Some(*workload_type);
            }

            // Check pattern-based protection
            match workload_type {
                WorkloadType::Training => {
                    // Protect training data and checkpoints
                    if key.contains("batch") || key.contains("train") || key.contains("checkpoint")
                    {
                        return Some(*workload_type);
                    }
                }
                WorkloadType::Inference => {
                    // Protect model files
                    if self.is_model_file(key) {
                        return Some(*workload_type);
                    }
                }
                WorkloadType::Checkpointing => {
                    // Protect checkpoint files
                    if key.contains("checkpoint") || key.contains(".ckpt") {
                        return Some(*workload_type);
                    }
                }
                _ => {}
            }
        }

        None
    }

    /// Execute a tier transition
    async fn execute_transition(
        &self,
        decision: &TierDecision,
        stats: &mut AutoTierStats,
    ) -> Result<(), String> {
        // Acquire semaphore for rate limiting
        let _permit = self
            .transition_semaphore
            .acquire()
            .await
            .map_err(|e| e.to_string())?;

        if self.config.dry_run {
            info!(
                key = %decision.key,
                from = ?decision.current_class,
                to = ?decision.target_class,
                reason = ?decision.reason,
                use_dpu = decision.use_dpu_inline,
                dpu_compress = decision.dpu_ops.compress,
                dpu_encrypt = decision.dpu_ops.encrypt,
                "DRY RUN: Would transition object"
            );
        } else {
            debug!(
                key = %decision.key,
                from = ?decision.current_class,
                to = ?decision.target_class,
                reason = ?decision.reason,
                use_dpu = decision.use_dpu_inline,
                "Transitioning object"
            );

            // Update our tier assignment tracking
            self.set_tier(&decision.key, decision.target_class);

            // TODO: Actually move data between storage tiers when backend supports it
            // For now, we track the assignment and emit metrics
            // When BrainLink integration is complete, this will use DPU inline
            // processing based on decision.use_dpu_inline and decision.dpu_ops
        }

        // Track DPU usage
        if decision.use_dpu_inline {
            stats.dpu_transitions += 1;
            if decision.dpu_ops.compress {
                stats.dpu_compressed += 1;
            }
            if decision.dpu_ops.encrypt {
                stats.dpu_encrypted += 1;
            }
        }

        // Update stats
        match decision.target_class {
            StorageClass::Standard => {
                stats.promotions += 1;
                stats.to_standard += 1;
            }
            StorageClass::InfrequentAccess => {
                stats.demotions += 1;
                stats.to_infrequent += 1;
            }
            StorageClass::Archive => {
                stats.demotions += 1;
                stats.to_archive += 1;
            }
            StorageClass::GpuPinned => {
                stats.promotions += 1;
                stats.gpu_pinned += 1;
            }
        }

        Ok(())
    }

    /// Start the background auto-tiering daemon
    pub fn start_background(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let engine = self;
        let interval = engine.config.evaluation_interval;

        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            interval_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                interval_timer.tick().await;

                let stats = engine.evaluate().await;

                if stats.promotions > 0 || stats.demotions > 0 {
                    info!(
                        promotions = stats.promotions,
                        demotions = stats.demotions,
                        errors = stats.errors,
                        "Background auto-tiering complete"
                    );
                }
            }
        })
    }

    /// Get the last evaluation statistics
    pub fn last_stats(&self) -> Option<AutoTierStats> {
        self.last_stats.read().clone()
    }

    /// Get cumulative statistics
    pub fn total_stats(&self) -> AutoTierStats {
        self.total_stats.read().clone()
    }

    /// Get the configuration
    pub fn config(&self) -> &AutoTierConfig {
        &self.config
    }

    /// Get recommended tier for an object based on SLAI analysis
    pub fn recommend_tier(
        &self,
        key: &str,
        session_id: Option<&str>,
    ) -> (StorageClass, TierReason) {
        let tracker = self.tracker();

        // Check access pattern
        let pattern = tracker.detect_pattern(key);
        let obj_stats = tracker.get_object_stats(key);

        // Check for active workload context
        if let Some(sid) = session_id {
            let workload = self.predictor().get_workload(sid);
            match workload {
                WorkloadType::Training => {
                    if key.contains("batch") || key.contains("train") {
                        return (
                            StorageClass::Standard,
                            TierReason::ActiveWorkload {
                                workload_type: workload,
                            },
                        );
                    }
                }
                WorkloadType::Inference => {
                    if self.is_model_file(key) {
                        return (StorageClass::GpuPinned, TierReason::InferenceModel);
                    }
                }
                _ => {}
            }
        }

        // Analyze based on access pattern
        match pattern {
            AccessPattern::WriteOnceReadMany => {
                // Keep in Standard for fast reads
                (StorageClass::Standard, TierReason::PatternBased { pattern })
            }
            AccessPattern::WriteHeavy => {
                // Standard for write performance
                (StorageClass::Standard, TierReason::PatternBased { pattern })
            }
            AccessPattern::Repeated => {
                // Standard for hot data
                (StorageClass::Standard, TierReason::PatternBased { pattern })
            }
            AccessPattern::Sequential => {
                // Could be training data - check stats
                if let Some(stats) = obj_stats {
                    if stats.reads > 10 {
                        return (
                            StorageClass::Standard,
                            TierReason::Hot {
                                accesses_per_day: stats.reads as f64,
                            },
                        );
                    }
                }
                (
                    StorageClass::InfrequentAccess,
                    TierReason::PatternBased { pattern },
                )
            }
            AccessPattern::Random | AccessPattern::Unknown => {
                // Check coldness
                if let Some(stats) = obj_stats {
                    if let Some(last_access) = stats.last_access {
                        let days_cold = last_access.elapsed().as_secs() / (24 * 60 * 60);
                        if days_cold > 30 {
                            return (
                                StorageClass::Archive,
                                TierReason::VeryCold {
                                    days_since_access: days_cold,
                                },
                            );
                        } else if days_cold > 7 {
                            return (
                                StorageClass::InfrequentAccess,
                                TierReason::Cold {
                                    days_since_access: days_cold,
                                },
                            );
                        }
                    }
                }
                (StorageClass::Standard, TierReason::PatternBased { pattern })
            }
        }
    }
}

/// Auto-tiering executor that actually moves data between storage tiers
///
/// This combines the SLAI-driven decision engine with a Store to perform
/// actual object transitions between storage classes.
///
/// ## Example
///
/// ```rust,no_run
/// use warp_store::autotier::{AutoTierExecutor, AutoTierConfig};
/// use warp_store::slai::PlacementEngine;
/// use warp_store::{Store, StoreConfig};
/// use std::sync::Arc;
///
/// #[tokio::main]
/// async fn main() -> Result<(), warp_store::Error> {
///     let store = Store::new(StoreConfig::default()).await?;
///     let placement = Arc::new(PlacementEngine::new());
///     let config = AutoTierConfig::default();
///
///     let executor = AutoTierExecutor::new(store, placement, config);
///     let stats = executor.run_once().await?;
///     println!("Promoted {}, demoted {}", stats.promotions, stats.demotions);
///     Ok(())
/// }
/// ```
pub struct AutoTierExecutor<B: StorageBackend> {
    /// The storage store
    store: Arc<Store<B>>,
    /// The SLAI-driven decision engine
    engine: AutoTierEngine,
}

impl<B: StorageBackend> AutoTierExecutor<B> {
    /// Create a new auto-tier executor
    pub fn new(store: Store<B>, placement: Arc<PlacementEngine>, config: AutoTierConfig) -> Self {
        Self {
            store: Arc::new(store),
            engine: AutoTierEngine::new(placement, config),
        }
    }

    /// Create a new executor from an `Arc<Store>`
    pub fn from_arc(
        store: Arc<Store<B>>,
        placement: Arc<PlacementEngine>,
        config: AutoTierConfig,
    ) -> Self {
        Self {
            store,
            engine: AutoTierEngine::new(placement, config),
        }
    }

    /// Run a single auto-tiering evaluation and execute transitions
    #[instrument(skip(self))]
    pub async fn run_once(&self) -> crate::Result<AutoTierStats> {
        let start = Instant::now();
        let mut stats = AutoTierStats {
            evaluated_at: Utc::now(),
            ..Default::default()
        };

        info!("Starting auto-tiering evaluation with data movement");

        // Get decisions from the engine
        let decisions = self.engine.collect_decisions(&mut stats);

        // Execute transitions with actual data movement
        for decision in decisions {
            if let Err(e) = self
                .execute_transition_with_data(&decision, &mut stats)
                .await
            {
                warn!(
                    key = %decision.key,
                    error = %e,
                    "Failed to execute tier transition with data movement"
                );
                stats.errors += 1;
            }
        }

        stats.duration_ms = start.elapsed().as_millis() as u64;

        // Update engine stats
        *self.engine.last_stats.write() = Some(stats.clone());
        {
            let mut total = self.engine.total_stats.write();
            total.promotions += stats.promotions;
            total.demotions += stats.demotions;
            total.to_infrequent += stats.to_infrequent;
            total.to_archive += stats.to_archive;
            total.to_standard += stats.to_standard;
            total.gpu_pinned += stats.gpu_pinned;
            total.workload_skipped += stats.workload_skipped;
            total.protected_skipped += stats.protected_skipped;
            total.errors += stats.errors;
            total.objects_scanned += stats.objects_scanned;
            total.dpu_transitions += stats.dpu_transitions;
            total.dpu_compressed += stats.dpu_compressed;
            total.dpu_encrypted += stats.dpu_encrypted;
        }

        info!(
            promotions = stats.promotions,
            demotions = stats.demotions,
            dpu_transitions = stats.dpu_transitions,
            duration_ms = stats.duration_ms,
            "Auto-tiering evaluation with data movement complete"
        );

        Ok(stats)
    }

    /// Execute a tier transition with actual data movement
    async fn execute_transition_with_data(
        &self,
        decision: &TierDecision,
        stats: &mut AutoTierStats,
    ) -> crate::Result<()> {
        // Acquire semaphore for rate limiting
        let _permit = self
            .engine
            .transition_semaphore
            .acquire()
            .await
            .map_err(|e| crate::Error::Backend(format!("semaphore error: {}", e)))?;

        if self.engine.config.dry_run {
            info!(
                key = %decision.key,
                from = ?decision.current_class,
                to = ?decision.target_class,
                reason = ?decision.reason,
                "DRY RUN: Would transition object"
            );
        } else {
            debug!(
                key = %decision.key,
                from = ?decision.current_class,
                to = ?decision.target_class,
                reason = ?decision.reason,
                "Transitioning object with data movement"
            );

            // Parse the key into bucket and object key
            // The decision.key format should be "bucket/object/path"
            let parts: Vec<&str> = decision.key.splitn(2, '/').collect();
            if parts.len() != 2 {
                return Err(crate::Error::InvalidKey(format!(
                    "Invalid key format: {}",
                    decision.key
                )));
            }
            let bucket = parts[0];
            let object_key = parts[1];

            let key = ObjectKey::new(bucket, object_key)?;

            // 1. Read object data
            let data = self.store.get(&key).await?;

            // 2. Get existing metadata to preserve user metadata
            let existing_meta = self.store.head(&key).await?;

            // 3. Write to new storage tier with updated storage class
            let opts = PutOptions {
                content_type: existing_meta.content_type.clone(),
                metadata: existing_meta.user_metadata.clone(),
                if_match: None,
                if_none_match: false,
                storage_class: decision.target_class,
            };

            self.store.put_with_options(&key, data, opts).await?;

            // Update engine's tier tracking
            self.engine.set_tier(&decision.key, decision.target_class);

            info!(
                key = %decision.key,
                from = ?decision.current_class,
                to = ?decision.target_class,
                "Object transitioned to new storage tier"
            );
        }

        // Update stats
        match decision.target_class {
            StorageClass::Standard => {
                stats.promotions += 1;
                stats.to_standard += 1;
            }
            StorageClass::InfrequentAccess => {
                stats.demotions += 1;
                stats.to_infrequent += 1;
            }
            StorageClass::Archive => {
                stats.demotions += 1;
                stats.to_archive += 1;
            }
            StorageClass::GpuPinned => {
                stats.promotions += 1;
                stats.gpu_pinned += 1;
            }
        }

        Ok(())
    }

    /// Start the background auto-tiering daemon with data movement
    pub fn start_background(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let executor = self;
        let interval = executor.engine.config.evaluation_interval;

        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            interval_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                interval_timer.tick().await;

                match executor.run_once().await {
                    Ok(stats) => {
                        if stats.promotions > 0 || stats.demotions > 0 {
                            info!(
                                promotions = stats.promotions,
                                demotions = stats.demotions,
                                errors = stats.errors,
                                "Background auto-tiering with data movement complete"
                            );
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "Background auto-tiering failed");
                    }
                }
            }
        })
    }

    /// Get a reference to the underlying engine
    pub fn engine(&self) -> &AutoTierEngine {
        &self.engine
    }

    /// Get the last evaluation statistics
    pub fn last_stats(&self) -> Option<AutoTierStats> {
        self.engine.last_stats()
    }

    /// Get cumulative statistics
    pub fn total_stats(&self) -> AutoTierStats {
        self.engine.total_stats()
    }

    /// Get the configuration
    pub fn config(&self) -> &AutoTierConfig {
        self.engine.config()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = AutoTierConfig::default();
        assert_eq!(config.evaluation_interval, Duration::from_secs(60 * 60));
        assert_eq!(config.max_concurrent_transitions, 10);
        assert!(!config.dry_run);
        assert!(config.respect_workloads);
    }

    #[test]
    fn test_config_presets() {
        let conservative = AutoTierConfig::conservative();
        assert_eq!(
            conservative.cold_threshold,
            Duration::from_secs(14 * 24 * 60 * 60)
        );

        let aggressive = AutoTierConfig::aggressive();
        assert_eq!(
            aggressive.cold_threshold,
            Duration::from_secs(3 * 24 * 60 * 60)
        );

        let ml = AutoTierConfig::ml_optimized();
        assert!(ml.respect_workloads);
        assert!(ml.enable_gpu_pinning);
    }

    #[test]
    fn test_engine_creation() {
        let placement = Arc::new(PlacementEngine::new());
        let config = AutoTierConfig::default();
        let engine = AutoTierEngine::new(placement, config);

        assert!(engine.last_stats().is_none());
    }

    #[test]
    fn test_tier_assignment() {
        let placement = Arc::new(PlacementEngine::new());
        let engine = AutoTierEngine::new(placement, AutoTierConfig::default());

        engine.set_tier("test/file.bin", StorageClass::InfrequentAccess);
        assert_eq!(
            engine.get_tier("test/file.bin"),
            Some(StorageClass::InfrequentAccess)
        );
    }

    #[test]
    fn test_protection() {
        let placement = Arc::new(PlacementEngine::new());
        let engine = AutoTierEngine::new(placement, AutoTierConfig::default());

        // Test explicit protection
        engine.protect_object("important/file.bin");
        assert!(engine.is_protected("important/file.bin"));

        engine.unprotect_object("important/file.bin");
        assert!(!engine.is_protected("important/file.bin"));

        // Test prefix protection
        assert!(engine.is_protected("system/config.json"));
        assert!(engine.is_protected(".warp/metadata"));
    }

    #[test]
    fn test_session_management() {
        let placement = Arc::new(PlacementEngine::new());
        let engine = AutoTierEngine::new(placement, AutoTierConfig::default());

        engine.register_session("training-session-1");
        assert!(engine.active_sessions.read().contains("training-session-1"));

        engine.unregister_session("training-session-1");
        assert!(!engine.active_sessions.read().contains("training-session-1"));
    }

    #[test]
    fn test_is_model_file() {
        let placement = Arc::new(PlacementEngine::new());
        let engine = AutoTierEngine::new(placement, AutoTierConfig::default());

        assert!(engine.is_model_file("model.bin"));
        assert!(engine.is_model_file("weights.pt"));
        assert!(engine.is_model_file("bert.safetensors"));
        assert!(engine.is_model_file("model.onnx"));
        assert!(!engine.is_model_file("data.csv"));
        assert!(!engine.is_model_file("log.txt"));
    }

    #[test]
    fn test_recommend_tier_patterns() {
        let placement = Arc::new(PlacementEngine::new());
        let engine = AutoTierEngine::new(placement, AutoTierConfig::default());

        // Without any access history, should default to Standard
        let (tier, _reason) = engine.recommend_tier("unknown/file.bin", None);
        assert_eq!(tier, StorageClass::Standard);
    }

    #[tokio::test]
    async fn test_evaluate_empty() {
        let placement = Arc::new(PlacementEngine::new());
        let engine = AutoTierEngine::new(placement, AutoTierConfig::default());

        let stats = engine.evaluate().await;
        assert_eq!(stats.promotions, 0);
        assert_eq!(stats.demotions, 0);
        assert_eq!(stats.errors, 0);
    }

    #[test]
    fn test_tier_reason_serialization() {
        let reason = TierReason::Cold {
            days_since_access: 14,
        };
        let json = serde_json::to_string(&reason).unwrap();
        assert!(json.contains("Cold"));
        assert!(json.contains("14"));
    }
}
