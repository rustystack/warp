//! Model versioning and metadata

use std::collections::HashMap;
use std::time::SystemTime;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use crate::config::TensorConfig;
use crate::error::{TensorError, TensorResult};

/// Model metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelMetadata {
    /// Model name
    pub name: String,
    /// Model description
    pub description: String,
    /// Model architecture (e.g., "transformer", "cnn")
    pub architecture: String,
    /// Framework (e.g., "pytorch", "tensorflow")
    pub framework: String,
    /// Framework version
    pub framework_version: String,
    /// Creation time
    pub created_at: SystemTime,
    /// Last modified time
    pub modified_at: SystemTime,
    /// Custom metadata
    pub custom: HashMap<String, String>,
    /// Tags for organization
    pub tags: Vec<String>,
    /// License
    pub license: Option<String>,
    /// Author
    pub author: Option<String>,
}

impl ModelMetadata {
    /// Create new model metadata
    pub fn new(name: impl Into<String>) -> Self {
        let now = SystemTime::now();
        Self {
            name: name.into(),
            description: String::new(),
            architecture: String::new(),
            framework: String::new(),
            framework_version: String::new(),
            created_at: now,
            modified_at: now,
            custom: HashMap::new(),
            tags: Vec::new(),
            license: None,
            author: None,
        }
    }

    /// Create a builder
    pub fn builder(name: impl Into<String>) -> ModelMetadataBuilder {
        ModelMetadataBuilder::new(name)
    }
}

/// Builder for model metadata
pub struct ModelMetadataBuilder {
    meta: ModelMetadata,
}

impl ModelMetadataBuilder {
    /// Create a new builder
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            meta: ModelMetadata::new(name),
        }
    }

    /// Set description
    #[must_use]
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.meta.description = desc.into();
        self
    }

    /// Set architecture
    #[must_use]
    pub fn architecture(mut self, arch: impl Into<String>) -> Self {
        self.meta.architecture = arch.into();
        self
    }

    /// Set framework
    #[must_use]
    pub fn framework(mut self, framework: impl Into<String>, version: impl Into<String>) -> Self {
        self.meta.framework = framework.into();
        self.meta.framework_version = version.into();
        self
    }

    /// Add a tag
    #[must_use]
    pub fn tag(mut self, tag: impl Into<String>) -> Self {
        self.meta.tags.push(tag.into());
        self
    }

    /// Set author
    #[must_use]
    pub fn author(mut self, author: impl Into<String>) -> Self {
        self.meta.author = Some(author.into());
        self
    }

    /// Set license
    #[must_use]
    pub fn license(mut self, license: impl Into<String>) -> Self {
        self.meta.license = Some(license.into());
        self
    }

    /// Add custom metadata
    #[must_use]
    pub fn custom(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.meta.custom.insert(key.into(), value.into());
        self
    }

    /// Build the metadata
    #[must_use]
    pub fn build(self) -> ModelMetadata {
        self.meta
    }
}

/// A model version
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelVersion {
    /// Version string (e.g., "v1.0.0", "`epoch_100`")
    pub version: String,
    /// Associated checkpoint name
    pub checkpoint: String,
    /// Creation time
    pub created_at: SystemTime,
    /// Parent version (for version history)
    pub parent: Option<String>,
    /// Version description
    pub description: String,
    /// Metrics at this version
    pub metrics: HashMap<String, f64>,
    /// Custom metadata
    pub metadata: HashMap<String, String>,
}

impl ModelVersion {
    /// Create a new version
    pub fn new(version: impl Into<String>, checkpoint: impl Into<String>) -> Self {
        Self {
            version: version.into(),
            checkpoint: checkpoint.into(),
            created_at: SystemTime::now(),
            parent: None,
            description: String::new(),
            metrics: HashMap::new(),
            metadata: HashMap::new(),
        }
    }

    /// Set parent version
    #[must_use]
    pub fn with_parent(mut self, parent: impl Into<String>) -> Self {
        self.parent = Some(parent.into());
        self
    }

    /// Set description
    #[must_use]
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Add a metric
    #[must_use]
    pub fn with_metric(mut self, name: impl Into<String>, value: f64) -> Self {
        self.metrics.insert(name.into(), value);
        self
    }

    /// Add metadata
    #[must_use]
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// Model store for managing multiple models and versions
pub struct ModelStore {
    /// Configuration
    config: TensorConfig,
    /// Models by name
    models: DashMap<String, ModelMetadata>,
    /// Versions by model name
    versions: DashMap<String, Vec<ModelVersion>>,
    /// Current version by model name
    current_versions: DashMap<String, String>,
}

impl ModelStore {
    /// Create a new model store
    #[must_use]
    pub fn new(config: TensorConfig) -> Self {
        Self {
            config,
            models: DashMap::new(),
            versions: DashMap::new(),
            current_versions: DashMap::new(),
        }
    }

    /// Register a model
    pub fn register_model(&self, metadata: ModelMetadata) {
        let name = metadata.name.clone();
        self.models.insert(name.clone(), metadata);
        self.versions.insert(name, Vec::new());
    }

    /// Get model metadata
    #[must_use]
    pub fn get_model(&self, name: &str) -> Option<ModelMetadata> {
        self.models.get(name).map(|m| m.clone())
    }

    /// Check if model exists
    #[must_use]
    pub fn model_exists(&self, name: &str) -> bool {
        self.models.contains_key(name)
    }

    /// List all models
    #[must_use]
    pub fn list_models(&self) -> Vec<String> {
        self.models.iter().map(|m| m.key().clone()).collect()
    }

    /// Add a version to a model
    ///
    /// # Errors
    ///
    /// Returns an error if the model does not exist.
    pub fn add_version(&self, model_name: &str, version: ModelVersion) -> TensorResult<()> {
        if !self.model_exists(model_name) {
            return Err(TensorError::ModelNotFound(model_name.to_string()));
        }

        let version_name = version.version.clone();

        if let Some(mut v) = self.versions.get_mut(model_name) {
            v.push(version)
        }

        // Set as current if first version
        if !self.current_versions.contains_key(model_name) {
            self.current_versions
                .insert(model_name.to_string(), version_name);
        }

        Ok(())
    }

    /// Get all versions for a model
    ///
    /// # Errors
    ///
    /// Returns an error if the model does not exist.
    pub fn get_versions(&self, model_name: &str) -> TensorResult<Vec<ModelVersion>> {
        self.versions
            .get(model_name)
            .map(|v| v.clone())
            .ok_or_else(|| TensorError::ModelNotFound(model_name.to_string()))
    }

    /// Get a specific version
    ///
    /// # Errors
    ///
    /// Returns an error if the model does not exist or the version is not found.
    pub fn get_version(&self, model_name: &str, version: &str) -> TensorResult<ModelVersion> {
        let versions = self.get_versions(model_name)?;
        versions
            .into_iter()
            .find(|v| v.version == version)
            .ok_or_else(|| TensorError::CheckpointNotFound(format!("{model_name}:{version}")))
    }

    /// Get current version
    ///
    /// # Errors
    ///
    /// Returns an error if the model does not exist or has no current version set.
    pub fn get_current_version(&self, model_name: &str) -> TensorResult<ModelVersion> {
        let current = self
            .current_versions
            .get(model_name)
            .map(|v| v.clone())
            .ok_or_else(|| TensorError::ModelNotFound(model_name.to_string()))?;

        self.get_version(model_name, &current)
    }

    /// Set current version
    ///
    /// # Errors
    ///
    /// Returns an error if the model or version does not exist.
    pub fn set_current_version(&self, model_name: &str, version: &str) -> TensorResult<()> {
        if !self.model_exists(model_name) {
            return Err(TensorError::ModelNotFound(model_name.to_string()));
        }

        // Verify version exists
        let _ = self.get_version(model_name, version)?;

        self.current_versions
            .insert(model_name.to_string(), version.to_string());
        Ok(())
    }

    /// Remove a model and all versions
    #[must_use]
    pub fn remove_model(&self, name: &str) -> Option<ModelMetadata> {
        self.versions.remove(name);
        self.current_versions.remove(name);
        self.models.remove(name).map(|(_, v)| v)
    }

    /// Find models by tag
    #[must_use]
    pub fn find_by_tag(&self, tag: &str) -> Vec<String> {
        self.models
            .iter()
            .filter(|m| m.tags.contains(&tag.to_string()))
            .map(|m| m.key().clone())
            .collect()
    }

    /// Get model count
    #[must_use]
    pub fn model_count(&self) -> usize {
        self.models.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_metadata_builder() {
        let meta = ModelMetadata::builder("gpt-2")
            .description("A transformer language model")
            .architecture("transformer")
            .framework("pytorch", "2.0")
            .tag("nlp")
            .tag("generation")
            .author("Test Author")
            .license("MIT")
            .custom("num_params", "124M")
            .build();

        assert_eq!(meta.name, "gpt-2");
        assert_eq!(meta.architecture, "transformer");
        assert_eq!(meta.framework, "pytorch");
        assert_eq!(meta.tags, vec!["nlp", "generation"]);
        assert_eq!(meta.custom.get("num_params"), Some(&"124M".to_string()));
    }

    #[test]
    fn test_model_version() {
        let version = ModelVersion::new("v1.0.0", "checkpoint_v1")
            .with_parent("v0.9.0")
            .with_description("First stable release")
            .with_metric("accuracy", 0.95)
            .with_metric("loss", 0.05);

        assert_eq!(version.version, "v1.0.0");
        assert_eq!(version.parent, Some("v0.9.0".to_string()));
        assert_eq!(version.metrics.get("accuracy"), Some(&0.95));
    }

    #[test]
    fn test_model_store() {
        let config = TensorConfig::default();
        let store = ModelStore::new(config);

        // Register a model
        let meta = ModelMetadata::builder("my_model")
            .architecture("mlp")
            .tag("classification")
            .build();
        store.register_model(meta);

        assert!(store.model_exists("my_model"));
        assert!(!store.model_exists("other_model"));

        // Add versions
        store
            .add_version(
                "my_model",
                ModelVersion::new("v1", "checkpoint_1").with_metric("accuracy", 0.8),
            )
            .unwrap();

        store
            .add_version(
                "my_model",
                ModelVersion::new("v2", "checkpoint_2")
                    .with_parent("v1")
                    .with_metric("accuracy", 0.9),
            )
            .unwrap();

        // Get versions
        let versions = store.get_versions("my_model").unwrap();
        assert_eq!(versions.len(), 2);

        // Get current version (should be v1 - first added)
        let current = store.get_current_version("my_model").unwrap();
        assert_eq!(current.version, "v1");

        // Set current to v2
        store.set_current_version("my_model", "v2").unwrap();
        let current = store.get_current_version("my_model").unwrap();
        assert_eq!(current.version, "v2");
    }

    #[test]
    fn test_find_by_tag() {
        let config = TensorConfig::default();
        let store = ModelStore::new(config);

        store.register_model(
            ModelMetadata::builder("model1")
                .tag("nlp")
                .tag("transformer")
                .build(),
        );
        store.register_model(
            ModelMetadata::builder("model2")
                .tag("vision")
                .tag("transformer")
                .build(),
        );
        store.register_model(ModelMetadata::builder("model3").tag("nlp").build());

        let nlp_models = store.find_by_tag("nlp");
        assert_eq!(nlp_models.len(), 2);

        let transformer_models = store.find_by_tag("transformer");
        assert_eq!(transformer_models.len(), 2);

        let vision_models = store.find_by_tag("vision");
        assert_eq!(vision_models.len(), 1);
    }
}
