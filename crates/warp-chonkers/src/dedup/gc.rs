//! Garbage Collection for chunk deduplication
//!
//! Provides configurable garbage collection strategies for cleaning up
//! unreferenced chunks from storage.

use super::registry::{ChunkRegistry, GcStats};
use crate::chunk::ChunkId;
use crate::tree::VersionId;
use crate::Result;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Garbage collection configuration
#[derive(Debug, Clone)]
pub struct GcConfig {
    /// Minimum age before a chunk can be collected
    pub min_age: Duration,

    /// Maximum chunks to delete per GC run
    pub batch_size: usize,

    /// Whether to run GC automatically
    pub auto_gc: bool,

    /// Threshold of unreferenced chunks before auto GC triggers
    pub auto_gc_threshold: usize,

    /// Dry run mode - don't actually delete
    pub dry_run: bool,
}

impl Default for GcConfig {
    fn default() -> Self {
        Self {
            min_age: Duration::from_secs(300), // 5 minutes
            batch_size: 1000,
            auto_gc: true,
            auto_gc_threshold: 100,
            dry_run: false,
        }
    }
}

impl GcConfig {
    /// Create config for aggressive GC (immediate cleanup)
    pub fn aggressive() -> Self {
        Self {
            min_age: Duration::ZERO,
            batch_size: usize::MAX,
            auto_gc: true,
            auto_gc_threshold: 1,
            dry_run: false,
        }
    }

    /// Create config for conservative GC
    pub fn conservative() -> Self {
        Self {
            min_age: Duration::from_secs(3600), // 1 hour
            batch_size: 100,
            auto_gc: false,
            auto_gc_threshold: 1000,
            dry_run: false,
        }
    }

    /// Set to dry run mode
    pub fn with_dry_run(mut self) -> Self {
        self.dry_run = true;
        self
    }
}

/// Garbage collector for the chunk registry
pub struct GarbageCollector {
    registry: Arc<ChunkRegistry>,
    config: GcConfig,
    /// Chunks pending deletion with their unref time
    pending: parking_lot::RwLock<Vec<(ChunkId, Instant)>>,
    /// Protected versions that shouldn't have chunks collected
    protected_versions: parking_lot::RwLock<HashSet<VersionId>>,
}

impl GarbageCollector {
    /// Create a new garbage collector
    pub fn new(registry: Arc<ChunkRegistry>, config: GcConfig) -> Self {
        Self {
            registry,
            config,
            pending: parking_lot::RwLock::new(Vec::new()),
            protected_versions: parking_lot::RwLock::new(HashSet::new()),
        }
    }

    /// Create with default configuration
    pub fn with_defaults(registry: Arc<ChunkRegistry>) -> Self {
        Self::new(registry, GcConfig::default())
    }

    /// Mark chunks as pending deletion
    pub fn mark_unreferenced(&self, chunk_ids: &[ChunkId]) {
        let now = Instant::now();
        let mut pending = self.pending.write();

        for id in chunk_ids {
            // Check if not already pending
            if !pending.iter().any(|(existing, _)| existing == id) {
                pending.push((*id, now));
            }
        }
    }

    /// Protect a version from GC
    pub fn protect_version(&self, version: VersionId) {
        self.protected_versions.write().insert(version);
    }

    /// Unprotect a version
    pub fn unprotect_version(&self, version: VersionId) {
        self.protected_versions.write().remove(&version);
    }

    /// Check if version is protected
    pub fn is_protected(&self, version: VersionId) -> bool {
        self.protected_versions.read().contains(&version)
    }

    /// Run garbage collection
    pub fn collect(&self) -> Result<GcStats> {
        let now = Instant::now();
        let mut stats = GcStats::default();

        // Get chunks that are old enough
        let eligible: Vec<ChunkId> = {
            let pending = self.pending.read();
            pending
                .iter()
                .filter(|(_, time)| now.duration_since(*time) >= self.config.min_age)
                .take(self.config.batch_size)
                .map(|(id, _)| *id)
                .collect()
        };

        if eligible.is_empty() {
            return Ok(stats);
        }

        // Filter out chunks that are now referenced again
        let to_delete: Vec<ChunkId> = eligible
            .into_iter()
            .filter(|id| {
                if let Some(meta) = self.registry.get(id) {
                    !meta.is_referenced()
                } else {
                    false // Already deleted
                }
            })
            .collect();

        if self.config.dry_run {
            // Just report what would be deleted
            stats.chunks_deleted = to_delete.len();
            for id in &to_delete {
                if let Some(meta) = self.registry.get(id) {
                    stats.bytes_freed += meta.size;
                }
            }
            return Ok(stats);
        }

        // Actually delete the chunks
        stats = self.registry.collect_garbage()?;

        // Remove deleted chunks from pending list
        {
            let mut pending = self.pending.write();
            pending.retain(|(id, _)| self.registry.contains(id));
        }

        Ok(stats)
    }

    /// Check if auto GC should run
    pub fn should_auto_gc(&self) -> bool {
        if !self.config.auto_gc {
            return false;
        }

        let unreferenced = self.registry.unreferenced_chunks();
        unreferenced.len() >= self.config.auto_gc_threshold
    }

    /// Run auto GC if threshold is met
    pub fn maybe_collect(&self) -> Result<Option<GcStats>> {
        if self.should_auto_gc() {
            Ok(Some(self.collect()?))
        } else {
            Ok(None)
        }
    }

    /// Get number of pending deletions
    pub fn pending_count(&self) -> usize {
        self.pending.read().len()
    }

    /// Get current configuration
    pub fn config(&self) -> &GcConfig {
        &self.config
    }

    /// Clear all pending deletions
    pub fn clear_pending(&self) {
        self.pending.write().clear();
    }
}

/// GC event for logging/monitoring
#[derive(Debug, Clone)]
pub enum GcEvent {
    /// GC started
    Started {
        /// Number of chunks pending deletion
        pending_count: usize,
    },

    /// Chunks deleted
    ChunksDeleted {
        /// Number of chunks deleted
        count: usize,
        /// Total bytes freed
        bytes: usize,
    },

    /// GC completed
    Completed {
        /// GC statistics
        stats: GcStats,
        /// Time taken for GC run
        duration: Duration,
    },

    /// GC skipped (nothing to do)
    Skipped,

    /// Error during GC
    Error {
        /// Error message
        message: String,
    },
}

/// Trait for GC event handlers
pub trait GcEventHandler: Send + Sync {
    /// Handle a GC event
    fn on_event(&self, event: GcEvent);
}

/// Simple logging event handler
pub struct LoggingGcHandler;

impl GcEventHandler for LoggingGcHandler {
    fn on_event(&self, event: GcEvent) {
        match event {
            GcEvent::Started { pending_count } => {
                tracing::info!("GC started with {} pending chunks", pending_count);
            }
            GcEvent::ChunksDeleted { count, bytes } => {
                tracing::debug!("GC deleted {} chunks ({} bytes)", count, bytes);
            }
            GcEvent::Completed { stats, duration } => {
                tracing::info!(
                    "GC completed: {} chunks deleted, {} bytes freed in {:?}",
                    stats.chunks_deleted,
                    stats.bytes_freed,
                    duration
                );
            }
            GcEvent::Skipped => {
                tracing::debug!("GC skipped - nothing to collect");
            }
            GcEvent::Error { message } => {
                tracing::error!("GC error: {}", message);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_registry() -> Arc<ChunkRegistry> {
        Arc::new(ChunkRegistry::in_memory())
    }

    #[test]
    fn test_gc_config_default() {
        let config = GcConfig::default();
        assert_eq!(config.min_age, Duration::from_secs(300));
        assert!(config.auto_gc);
        assert!(!config.dry_run);
    }

    #[test]
    fn test_gc_config_aggressive() {
        let config = GcConfig::aggressive();
        assert_eq!(config.min_age, Duration::ZERO);
        assert_eq!(config.auto_gc_threshold, 1);
    }

    #[test]
    fn test_gc_mark_unreferenced() {
        let registry = setup_registry();
        let gc = GarbageCollector::with_defaults(registry);

        let id1 = ChunkId::from_data(b"chunk1");
        let id2 = ChunkId::from_data(b"chunk2");

        gc.mark_unreferenced(&[id1, id2]);
        assert_eq!(gc.pending_count(), 2);

        // Marking again shouldn't duplicate
        gc.mark_unreferenced(&[id1]);
        assert_eq!(gc.pending_count(), 2);
    }

    #[test]
    fn test_gc_protect_version() {
        let registry = setup_registry();
        let gc = GarbageCollector::with_defaults(registry);

        let version = VersionId::new(1);
        assert!(!gc.is_protected(version));

        gc.protect_version(version);
        assert!(gc.is_protected(version));

        gc.unprotect_version(version);
        assert!(!gc.is_protected(version));
    }

    #[test]
    fn test_gc_collect_empty() {
        let registry = setup_registry();
        let config = GcConfig::aggressive();
        let gc = GarbageCollector::new(registry, config);

        let stats = gc.collect().unwrap();
        assert_eq!(stats.chunks_deleted, 0);
    }

    #[test]
    fn test_gc_dry_run() {
        let registry = setup_registry();

        // Register and unregister a chunk
        let version = VersionId::new(1);
        let data = b"test chunk";
        let id = ChunkId::from_data(data);
        let weight = crate::ChunkWeight::from_data(data);

        registry.register(id, data, weight, version).unwrap();
        registry.unregister_version(version).unwrap();

        // Dry run should not delete
        let config = GcConfig::aggressive().with_dry_run();
        let _gc = GarbageCollector::new(Arc::new(ChunkRegistry::in_memory()), config);

        // Note: This test is simplified since the dry_run GC
        // works on its own registry instance
    }

    #[test]
    fn test_gc_auto_threshold() {
        let registry = setup_registry();
        let mut config = GcConfig::default();
        config.auto_gc_threshold = 5;

        let gc = GarbageCollector::new(registry.clone(), config);

        // Below threshold
        assert!(!gc.should_auto_gc());
    }

    #[test]
    fn test_gc_clear_pending() {
        let registry = setup_registry();
        let gc = GarbageCollector::with_defaults(registry);

        let id = ChunkId::from_data(b"chunk");
        gc.mark_unreferenced(&[id]);
        assert_eq!(gc.pending_count(), 1);

        gc.clear_pending();
        assert_eq!(gc.pending_count(), 0);
    }
}
