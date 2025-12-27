//! Tree persistence and storage
//!
//! Provides serialization and storage for ChonkerTree structures.

use super::{ChonkerNode, ChonkerTree, VersionId};
use crate::chunk::ChunkId;
use crate::config::ChonkersConfig;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Serializable tree snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeSnapshot {
    /// Version ID
    pub version_id: VersionId,

    /// Root node ID
    pub root: Option<ChunkId>,

    /// All nodes
    pub nodes: HashMap<ChunkId, ChonkerNode>,

    /// Configuration
    pub config: ChonkersConfig,

    /// Total data size
    pub data_size: usize,
}

impl TreeSnapshot {
    /// Create a snapshot from a tree
    pub fn from_tree(tree: &ChonkerTree) -> Self {
        let nodes: HashMap<ChunkId, ChonkerNode> = tree
            .nodes
            .iter()
            .map(|entry| (*entry.key(), entry.value().clone()))
            .collect();

        Self {
            version_id: tree.version_id,
            root: tree.root.clone(),
            nodes,
            config: tree.config.clone(),
            data_size: tree.data_size,
        }
    }

    /// Restore a tree from this snapshot
    pub fn to_tree(&self) -> ChonkerTree {
        let nodes = dashmap::DashMap::new();
        for (id, node) in &self.nodes {
            nodes.insert(*id, node.clone());
        }

        ChonkerTree {
            version_id: self.version_id,
            root: self.root,
            nodes,
            config: self.config.clone(),
            data_size: self.data_size,
        }
    }

    /// Serialize to MessagePack bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        rmp_serde::to_vec(self).map_err(|e| {
            Error::Internal(format!("Failed to serialize tree: {}", e))
        })
    }

    /// Deserialize from MessagePack bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        rmp_serde::from_slice(bytes).map_err(|e| {
            Error::Internal(format!("Failed to deserialize tree: {}", e))
        })
    }

    /// Save to a file
    pub fn save(&self, path: &Path) -> Result<()> {
        let bytes = self.to_bytes()?;
        fs::write(path, bytes).map_err(|e| {
            Error::Internal(format!("Failed to write tree file: {}", e))
        })
    }

    /// Load from a file
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).map_err(|e| {
            Error::Internal(format!("Failed to read tree file: {}", e))
        })?;
        Self::from_bytes(&bytes)
    }
}

/// Tree storage interface
pub trait TreeStore: Send + Sync {
    /// Store a tree
    fn store(&self, tree: &ChonkerTree) -> Result<()>;

    /// Load a tree by version ID
    fn load(&self, version_id: VersionId) -> Result<Option<ChonkerTree>>;

    /// List all stored versions
    fn list_versions(&self) -> Result<Vec<VersionId>>;

    /// Delete a version
    fn delete(&self, version_id: VersionId) -> Result<()>;

    /// Get the latest version
    fn latest(&self) -> Result<Option<ChonkerTree>>;
}

/// File-based tree store
pub struct FileTreeStore {
    /// Base directory for storage
    base_dir: std::path::PathBuf,
}

impl FileTreeStore {
    /// Create a new file-based store
    pub fn new(base_dir: impl AsRef<Path>) -> Result<Self> {
        let base_dir = base_dir.as_ref().to_path_buf();
        fs::create_dir_all(&base_dir).map_err(|e| {
            Error::Internal(format!("Failed to create store directory: {}", e))
        })?;

        Ok(Self { base_dir })
    }

    /// Get the path for a version
    fn version_path(&self, version_id: VersionId) -> std::path::PathBuf {
        self.base_dir.join(format!("v{}.tree", version_id.0))
    }

    /// Get the metadata file path
    fn metadata_path(&self) -> std::path::PathBuf {
        self.base_dir.join("metadata.json")
    }
}

impl TreeStore for FileTreeStore {
    fn store(&self, tree: &ChonkerTree) -> Result<()> {
        let snapshot = TreeSnapshot::from_tree(tree);
        let path = self.version_path(tree.version_id);
        snapshot.save(&path)?;

        // Update metadata with latest version
        let metadata = StoreMetadata {
            latest_version: Some(tree.version_id),
        };
        let metadata_json = serde_json::to_string_pretty(&metadata).map_err(|e| {
            Error::Internal(format!("Failed to serialize metadata: {}", e))
        })?;
        fs::write(self.metadata_path(), metadata_json).map_err(|e| {
            Error::Internal(format!("Failed to write metadata: {}", e))
        })?;

        Ok(())
    }

    fn load(&self, version_id: VersionId) -> Result<Option<ChonkerTree>> {
        let path = self.version_path(version_id);
        if !path.exists() {
            return Ok(None);
        }

        let snapshot = TreeSnapshot::load(&path)?;
        Ok(Some(snapshot.to_tree()))
    }

    fn list_versions(&self) -> Result<Vec<VersionId>> {
        let mut versions = Vec::new();

        for entry in fs::read_dir(&self.base_dir).map_err(|e| {
            Error::Internal(format!("Failed to read store directory: {}", e))
        })? {
            let entry = entry.map_err(|e| {
                Error::Internal(format!("Failed to read directory entry: {}", e))
            })?;
            let path = entry.path();

            if let Some(ext) = path.extension() {
                if ext == "tree" {
                    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                        if let Some(id_str) = stem.strip_prefix('v') {
                            if let Ok(id) = id_str.parse::<u64>() {
                                versions.push(VersionId(id));
                            }
                        }
                    }
                }
            }
        }

        versions.sort_by_key(|v| v.0);
        Ok(versions)
    }

    fn delete(&self, version_id: VersionId) -> Result<()> {
        let path = self.version_path(version_id);
        if path.exists() {
            fs::remove_file(path).map_err(|e| {
                Error::Internal(format!("Failed to delete version: {}", e))
            })?;
        }
        Ok(())
    }

    fn latest(&self) -> Result<Option<ChonkerTree>> {
        let metadata_path = self.metadata_path();
        if !metadata_path.exists() {
            return Ok(None);
        }

        let metadata_json = fs::read_to_string(&metadata_path).map_err(|e| {
            Error::Internal(format!("Failed to read metadata: {}", e))
        })?;
        let metadata: StoreMetadata = serde_json::from_str(&metadata_json).map_err(|e| {
            Error::Internal(format!("Failed to parse metadata: {}", e))
        })?;

        if let Some(version_id) = metadata.latest_version {
            self.load(version_id)
        } else {
            Ok(None)
        }
    }
}

/// Store metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoreMetadata {
    latest_version: Option<VersionId>,
}

/// In-memory tree store for testing
#[derive(Default)]
pub struct MemoryTreeStore {
    trees: parking_lot::RwLock<HashMap<VersionId, TreeSnapshot>>,
    latest: parking_lot::RwLock<Option<VersionId>>,
}

impl MemoryTreeStore {
    /// Create a new in-memory store
    pub fn new() -> Self {
        Self::default()
    }
}

impl TreeStore for MemoryTreeStore {
    fn store(&self, tree: &ChonkerTree) -> Result<()> {
        let snapshot = TreeSnapshot::from_tree(tree);
        self.trees.write().insert(tree.version_id, snapshot);
        *self.latest.write() = Some(tree.version_id);
        Ok(())
    }

    fn load(&self, version_id: VersionId) -> Result<Option<ChonkerTree>> {
        Ok(self.trees.read().get(&version_id).map(|s| s.to_tree()))
    }

    fn list_versions(&self) -> Result<Vec<VersionId>> {
        let mut versions: Vec<_> = self.trees.read().keys().copied().collect();
        versions.sort_by_key(|v| v.0);
        Ok(versions)
    }

    fn delete(&self, version_id: VersionId) -> Result<()> {
        self.trees.write().remove(&version_id);
        Ok(())
    }

    fn latest(&self) -> Result<Option<ChonkerTree>> {
        if let Some(version_id) = *self.latest.read() {
            self.load(version_id)
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_snapshot_roundtrip() {
        let config = ChonkersConfig::default();
        let data = b"test data for snapshot";

        let tree = ChonkerTree::from_data(data, config).unwrap();
        let snapshot = TreeSnapshot::from_tree(&tree);

        let bytes = snapshot.to_bytes().unwrap();
        let restored_snapshot = TreeSnapshot::from_bytes(&bytes).unwrap();
        let restored_tree = restored_snapshot.to_tree();

        assert_eq!(tree.version_id, restored_tree.version_id);
        assert_eq!(tree.data_size(), restored_tree.data_size());
        assert_eq!(tree.node_count(), restored_tree.node_count());
    }

    #[test]
    fn test_file_store() {
        let dir = tempdir().unwrap();
        let store = FileTreeStore::new(dir.path()).unwrap();

        let config = ChonkersConfig::default();
        let data = b"test data for file store";

        let tree = ChonkerTree::from_data(data, config).unwrap();
        let version_id = tree.version_id;

        store.store(&tree).unwrap();

        let loaded = store.load(version_id).unwrap().unwrap();
        assert_eq!(loaded.version_id, version_id);
        assert_eq!(loaded.data_size(), tree.data_size());

        let versions = store.list_versions().unwrap();
        assert!(versions.contains(&version_id));

        let latest = store.latest().unwrap().unwrap();
        assert_eq!(latest.version_id, version_id);
    }

    #[test]
    fn test_memory_store() {
        let store = MemoryTreeStore::new();

        let config = ChonkersConfig::default();
        let data = b"test data for memory store";

        let tree = ChonkerTree::from_data(data, config).unwrap();
        let version_id = tree.version_id;

        store.store(&tree).unwrap();

        let loaded = store.load(version_id).unwrap().unwrap();
        assert_eq!(loaded.version_id, version_id);

        store.delete(version_id).unwrap();
        assert!(store.load(version_id).unwrap().is_none());
    }
}
