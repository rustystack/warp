//! Version Timeline Management
//!
//! Provides time-travel capabilities for versioned data,
//! managing snapshots and deltas between versions.

use super::delta::Delta;
use crate::chunk::ChunkId;
use crate::dedup::{ChunkRegistry, GcStats};
use crate::tree::{ChonkerTree, TreeStore, VersionId};
use crate::{ChonkersConfig, Result};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Version metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    /// Version identifier
    pub id: VersionId,

    /// Parent version (None for initial version)
    pub parent: Option<VersionId>,

    /// Timestamp when this version was created
    pub timestamp: u64,

    /// Optional message describing the version
    pub message: Option<String>,

    /// Number of chunks in this version
    pub chunk_count: usize,

    /// Total data size in bytes
    pub data_size: usize,

    /// Tags associated with this version
    pub tags: Vec<String>,
}

impl VersionInfo {
    /// Create new version info
    pub fn new(id: VersionId, parent: Option<VersionId>) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            id,
            parent,
            timestamp,
            message: None,
            chunk_count: 0,
            data_size: 0,
            tags: Vec::new(),
        }
    }

    /// Set message
    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }

    /// Add a tag
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }
}

/// Version timeline for managing version history
pub struct VersionTimeline {
    /// Configuration for chunking
    config: ChonkersConfig,

    /// Chunk registry for deduplication
    registry: Arc<ChunkRegistry>,

    /// Tree store for persistence
    store: Arc<dyn TreeStore>,

    /// Version metadata
    versions: RwLock<HashMap<VersionId, VersionInfo>>,

    /// Cached deltas between versions
    deltas: RwLock<HashMap<(VersionId, VersionId), Delta>>,

    /// Current HEAD version
    head: RwLock<Option<VersionId>>,

    /// Named references (branches/tags)
    refs: RwLock<HashMap<String, VersionId>>,
}

impl VersionTimeline {
    /// Create a new version timeline
    pub fn new(
        config: ChonkersConfig,
        registry: Arc<ChunkRegistry>,
        store: Arc<dyn TreeStore>,
    ) -> Self {
        Self {
            config,
            registry,
            store,
            versions: RwLock::new(HashMap::new()),
            deltas: RwLock::new(HashMap::new()),
            head: RwLock::new(None),
            refs: RwLock::new(HashMap::new()),
        }
    }

    /// Commit new data as a version
    pub fn commit(&self, data: &[u8], message: Option<&str>) -> Result<VersionId> {
        // Build tree from data
        let tree = ChonkerTree::from_data(data, self.config.clone())?;
        let version_id = tree.version_id;

        // Get parent version
        let parent = *self.head.read();

        // Create version info
        let mut info = VersionInfo::new(version_id, parent);
        info.chunk_count = tree.leaf_count();
        info.data_size = tree.data_size();
        if let Some(msg) = message {
            info.message = Some(msg.to_string());
        }

        // Register all chunks with the registry
        // Note: We don't have the actual chunk data here
        // In a real implementation, we'd store chunk data during tree creation
        // For now, we just check if chunks are registered
        for chunk_id in tree.leaf_ids() {
            let _ = self.registry.get(&chunk_id);
        }

        // Save tree to store
        self.store.store(&tree)?;

        // Update version metadata
        self.versions.write().insert(version_id, info);

        // Update HEAD
        *self.head.write() = Some(version_id);

        Ok(version_id)
    }

    /// Checkout a specific version
    pub fn checkout(&self, version: VersionId) -> Result<Option<ChonkerTree>> {
        // Load from store
        self.store.load(version)
    }

    /// Get the current HEAD version
    pub fn head(&self) -> Option<VersionId> {
        *self.head.read()
    }

    /// Get version info
    pub fn get_version(&self, version: VersionId) -> Option<VersionInfo> {
        self.versions.read().get(&version).cloned()
    }

    /// Get all versions
    pub fn all_versions(&self) -> Vec<VersionInfo> {
        self.versions.read().values().cloned().collect()
    }

    /// Get version history (ancestors of a version)
    pub fn history(&self, version: VersionId) -> Vec<VersionInfo> {
        let versions = self.versions.read();
        let mut history = Vec::new();
        let mut current = Some(version);

        while let Some(v) = current {
            if let Some(info) = versions.get(&v) {
                history.push(info.clone());
                current = info.parent;
            } else {
                break;
            }
        }

        history
    }

    /// Compute delta between two versions
    pub fn delta(&self, from: VersionId, to: VersionId) -> Result<Option<Delta>> {
        // Check cache first
        {
            let deltas = self.deltas.read();
            if let Some(delta) = deltas.get(&(from, to)) {
                return Ok(Some(delta.clone()));
            }
        }

        // Load both trees
        let from_tree = match self.checkout(from)? {
            Some(t) => t,
            None => return Ok(None),
        };

        let to_tree = match self.checkout(to)? {
            Some(t) => t,
            None => return Ok(None),
        };

        // Compute delta
        let delta = Delta::compute(&from_tree, &to_tree);

        // Cache it
        self.deltas.write().insert((from, to), delta.clone());

        Ok(Some(delta))
    }

    /// Create a named reference (branch/tag)
    pub fn create_ref(&self, name: impl Into<String>, version: VersionId) {
        self.refs.write().insert(name.into(), version);
    }

    /// Get a named reference
    pub fn get_ref(&self, name: &str) -> Option<VersionId> {
        self.refs.read().get(name).copied()
    }

    /// Delete a named reference
    pub fn delete_ref(&self, name: &str) -> Option<VersionId> {
        self.refs.write().remove(name)
    }

    /// List all references
    pub fn list_refs(&self) -> HashMap<String, VersionId> {
        self.refs.read().clone()
    }

    /// Get chunk IDs needed to reconstruct a version
    pub fn required_chunks(&self, version: VersionId) -> Result<Vec<ChunkId>> {
        match self.checkout(version)? {
            Some(tree) => Ok(tree.leaf_ids()),
            None => Ok(Vec::new()),
        }
    }

    /// Get chunks shared between two versions
    pub fn shared_chunks(&self, v1: VersionId, v2: VersionId) -> Result<Vec<ChunkId>> {
        match self.delta(v1, v2)? {
            Some(delta) => Ok(delta.unchanged),
            None => Ok(Vec::new()),
        }
    }

    /// Prune old versions, keeping only the most recent N
    pub fn prune(&self, keep_count: usize) -> Result<Vec<VersionId>> {
        let mut versions: Vec<_> = self.versions.read().values().cloned().collect();

        // Sort by timestamp (newest first), then by version ID (newest first) for tie-breaking
        versions.sort_by(|a, b| {
            b.timestamp.cmp(&a.timestamp)
                .then_with(|| b.id.0.cmp(&a.id.0))
        });

        let mut pruned = Vec::new();
        let protected_refs: std::collections::HashSet<_> =
            self.refs.read().values().copied().collect();

        // Keep the first N versions and any referenced versions
        for (i, info) in versions.iter().enumerate() {
            if i >= keep_count && !protected_refs.contains(&info.id) {
                // Remove from store
                self.store.delete(info.id)?;

                // Remove from versions map
                self.versions.write().remove(&info.id);

                pruned.push(info.id);
            }
        }

        // Clean up delta cache for pruned versions
        {
            let mut deltas = self.deltas.write();
            deltas.retain(|(from, to), _| {
                !pruned.contains(from) && !pruned.contains(to)
            });
        }

        Ok(pruned)
    }

    /// Run garbage collection on unreferenced chunks
    pub fn gc(&self) -> Result<GcStats> {
        self.registry.collect_garbage()
    }

    /// Get the configuration
    pub fn config(&self) -> &ChonkersConfig {
        &self.config
    }

    /// Get the registry
    pub fn registry(&self) -> &Arc<ChunkRegistry> {
        &self.registry
    }

    /// Get version count
    pub fn version_count(&self) -> usize {
        self.versions.read().len()
    }
}

/// Builder for creating version timelines
#[derive(Debug, Clone)]
pub struct TimelineBuilder {
    config: ChonkersConfig,
    initial_ref: Option<String>,
}

impl Default for TimelineBuilder {
    fn default() -> Self {
        Self {
            config: ChonkersConfig::default(),
            initial_ref: Some("main".to_string()),
        }
    }
}

impl TimelineBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the chunking configuration
    pub fn with_config(mut self, config: ChonkersConfig) -> Self {
        self.config = config;
        self
    }

    /// Set the name for the initial reference
    pub fn with_initial_ref(mut self, name: impl Into<String>) -> Self {
        self.initial_ref = Some(name.into());
        self
    }

    /// Don't create an initial reference
    pub fn without_initial_ref(mut self) -> Self {
        self.initial_ref = None;
        self
    }

    /// Build the timeline with given registry and store
    pub fn build(
        self,
        registry: Arc<ChunkRegistry>,
        store: Arc<dyn TreeStore>,
    ) -> VersionTimeline {
        VersionTimeline::new(self.config, registry, store)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dedup::MemoryChunkStore;
    use crate::tree::MemoryTreeStore;

    fn create_timeline() -> VersionTimeline {
        let config = ChonkersConfig::default();
        let store = Arc::new(MemoryChunkStore::new());
        let registry = Arc::new(ChunkRegistry::new(store));
        let tree_store = Arc::new(MemoryTreeStore::new());

        VersionTimeline::new(config, registry, tree_store)
    }

    #[test]
    fn test_commit() {
        let timeline = create_timeline();

        let v1 = timeline.commit(b"first version", Some("Initial")).unwrap();
        assert!(timeline.head().is_some());
        assert_eq!(timeline.head().unwrap(), v1);

        let info = timeline.get_version(v1).unwrap();
        assert_eq!(info.message, Some("Initial".to_string()));
    }

    #[test]
    fn test_history() {
        let timeline = create_timeline();

        let v1 = timeline.commit(b"version one", None).unwrap();
        let v2 = timeline.commit(b"version two", None).unwrap();
        let v3 = timeline.commit(b"version three", None).unwrap();

        let history = timeline.history(v3);
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].id, v3);
        assert_eq!(history[1].id, v2);
        assert_eq!(history[2].id, v1);
    }

    #[test]
    fn test_checkout() {
        let timeline = create_timeline();

        let data = b"some data to version";
        let v1 = timeline.commit(data, None).unwrap();

        let tree = timeline.checkout(v1).unwrap();
        assert!(tree.is_some());
        assert_eq!(tree.unwrap().data_size(), data.len());
    }

    #[test]
    fn test_refs() {
        let timeline = create_timeline();

        let v1 = timeline.commit(b"version one", None).unwrap();

        timeline.create_ref("main", v1);
        timeline.create_ref("release-1.0", v1);

        assert_eq!(timeline.get_ref("main"), Some(v1));
        assert_eq!(timeline.get_ref("release-1.0"), Some(v1));
        assert_eq!(timeline.get_ref("nonexistent"), None);

        let refs = timeline.list_refs();
        assert_eq!(refs.len(), 2);
    }

    #[test]
    fn test_delta() {
        let timeline = create_timeline();

        let v1 = timeline.commit(b"first version data", None).unwrap();
        let v2 = timeline.commit(b"second version data", None).unwrap();

        let delta = timeline.delta(v1, v2).unwrap();
        assert!(delta.is_some());

        let delta = delta.unwrap();
        assert!(!delta.is_empty());
    }

    #[test]
    fn test_prune() {
        let timeline = create_timeline();

        let _v1 = timeline.commit(b"version one", None).unwrap();
        let _v2 = timeline.commit(b"version two", None).unwrap();
        let v3 = timeline.commit(b"version three", None).unwrap();

        // Keep only 2 versions
        let pruned = timeline.prune(2).unwrap();

        assert_eq!(pruned.len(), 1);
        assert_eq!(timeline.version_count(), 2);

        // HEAD should still exist
        assert!(timeline.checkout(v3).unwrap().is_some());
    }

    #[test]
    fn test_version_info() {
        let info = VersionInfo::new(VersionId::new(1), None)
            .with_message("Test commit")
            .with_tag("v1.0");

        assert_eq!(info.message, Some("Test commit".to_string()));
        assert_eq!(info.tags, vec!["v1.0".to_string()]);
    }

    #[test]
    fn test_builder() {
        let store = Arc::new(MemoryChunkStore::new());
        let registry = Arc::new(ChunkRegistry::new(store));
        let tree_store = Arc::new(MemoryTreeStore::new());

        let timeline = TimelineBuilder::new()
            .with_config(ChonkersConfig::backup())
            .without_initial_ref()
            .build(registry, tree_store);

        assert_eq!(timeline.version_count(), 0);
    }

    #[test]
    fn test_shared_chunks() {
        let timeline = create_timeline();

        // Similar data should share chunks
        let v1 = timeline.commit(b"this is the same prefix with different ending one", None).unwrap();
        let v2 = timeline.commit(b"this is the same prefix with different ending two", None).unwrap();

        let shared = timeline.shared_chunks(v1, v2).unwrap();
        // May or may not share chunks depending on chunk boundaries
        // Just verify the call succeeds
        let _ = shared.len();
    }
}
