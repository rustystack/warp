//! ONNX Runtime session management
//!
//! Provides thread-safe session caching and model loading for neural inference.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use once_cell::sync::Lazy;
use ort::session::Session;
use parking_lot::RwLock;
use tracing::{debug, info, warn};

use crate::error::{Error, Result};
use crate::model::presets::{ModelConfig, ModelPreset};

/// Global ONNX Runtime environment initialization flag
static ORT_INITIALIZED: Lazy<Result<()>> = Lazy::new(|| {
    match ort::init().with_name("warp-neural").commit() {
        Ok(_) => Ok(()),
        Err(e) => Err(Error::ModelLoad(format!("Failed to initialize ONNX Runtime: {}", e))),
    }
});

/// Thread-safe model session cache
///
/// Caches loaded ONNX sessions to avoid repeated model loading.
/// Sessions are keyed by model path and GPU flag.
pub struct SessionCache {
    /// Cached sessions: (path, use_gpu) -> session
    sessions: RwLock<HashMap<String, Arc<Session>>>,
}

impl SessionCache {
    /// Get the global session cache
    pub fn global() -> &'static Self {
        static CACHE: Lazy<SessionCache> = Lazy::new(|| SessionCache {
            sessions: RwLock::new(HashMap::new()),
        });
        &CACHE
    }

    /// Create a new empty session cache
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }

    /// Get or load a session for the given model path
    ///
    /// If the session is already cached, returns the cached version.
    /// Otherwise, loads the model and caches it.
    pub fn get_or_load(&self, model_path: &Path, use_cuda: bool) -> Result<Arc<Session>> {
        // Ensure ORT is initialized
        ORT_INITIALIZED.as_ref().map_err(|e| Error::ModelLoad(e.to_string()))?;

        let cache_key = format!("{}:{}", model_path.display(), use_cuda);

        // Check cache first (read lock)
        {
            let sessions = self.sessions.read();
            if let Some(session) = sessions.get(&cache_key) {
                debug!(path = %model_path.display(), "Using cached ONNX session");
                return Ok(Arc::clone(session));
            }
        }

        // Load model (write lock)
        let session = self.load_model(model_path, use_cuda)?;
        let session = Arc::new(session);

        // Cache the session
        {
            let mut sessions = self.sessions.write();
            sessions.insert(cache_key, Arc::clone(&session));
        }

        Ok(session)
    }

    /// Load a model from file
    fn load_model(&self, model_path: &Path, use_cuda: bool) -> Result<Session> {
        if !model_path.exists() {
            return Err(Error::ModelNotFound {
                path: model_path.to_path_buf(),
            });
        }

        info!(path = %model_path.display(), cuda = use_cuda, "Loading ONNX model");

        if use_cuda && !Self::is_cuda_available() {
            warn!("CUDA requested but not available, falling back to CPU");
        }

        // Load model from file
        // Note: For CUDA support, the ort crate needs to be compiled with CUDA feature
        // and appropriate execution providers configured
        let session = Session::builder()
            .map_err(|e| Error::ModelLoad(format!("Failed to create session builder: {}", e)))?
            .commit_from_file(model_path)
            .map_err(|e| Error::ModelLoad(format!("Failed to load model: {}", e)))?;

        info!(
            path = %model_path.display(),
            inputs = session.inputs.len(),
            outputs = session.outputs.len(),
            "Model loaded successfully"
        );

        Ok(session)
    }

    /// Check if CUDA is available
    #[cfg(feature = "cuda")]
    pub fn is_cuda_available() -> bool {
        use ort::execution_providers::{cuda::CUDAExecutionProvider, ExecutionProvider};
        CUDAExecutionProvider::default()
            .is_available()
            .unwrap_or(false)
    }

    /// Check if CUDA is available (CPU-only build)
    #[cfg(not(feature = "cuda"))]
    pub fn is_cuda_available() -> bool {
        false
    }

    /// Clear all cached sessions
    pub fn clear(&self) {
        let mut sessions = self.sessions.write();
        sessions.clear();
        debug!("Cleared session cache");
    }

    /// Get the number of cached sessions
    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.read().len()
    }

    /// Check if cache is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sessions.read().is_empty()
    }
}

impl Default for SessionCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolve model paths for a given configuration
pub struct ModelResolver;

impl ModelResolver {
    /// Standard model directory locations
    const MODEL_DIRS: &'static [&'static str] = &[
        "./models",
        "../models",
        "~/.warp/models",
        "/usr/share/warp/models",
        "/usr/local/share/warp/models",
    ];

    /// Resolve encoder and decoder paths for a model configuration
    pub fn resolve(config: &ModelConfig) -> Result<(PathBuf, PathBuf)> {
        match config.preset {
            ModelPreset::Custom => {
                let encoder = config
                    .custom_encoder_path
                    .clone()
                    .ok_or_else(|| Error::ModelNotFound {
                        path: PathBuf::from("custom encoder path not specified"),
                    })?;
                let decoder = config
                    .custom_decoder_path
                    .clone()
                    .ok_or_else(|| Error::ModelNotFound {
                        path: PathBuf::from("custom decoder path not specified"),
                    })?;
                Ok((encoder, decoder))
            }
            _ => {
                let model_dir = Self::find_model_dir()?;
                let encoder = model_dir.join(config.preset.encoder_filename());
                let decoder = model_dir.join(config.preset.decoder_filename());
                Ok((encoder, decoder))
            }
        }
    }

    /// Find the model directory
    fn find_model_dir() -> Result<PathBuf> {
        for dir in Self::MODEL_DIRS {
            let expanded = shellexpand::tilde(dir);
            let path = PathBuf::from(expanded.as_ref());
            if path.exists() && path.is_dir() {
                debug!(path = %path.display(), "Found model directory");
                return Ok(path);
            }
        }

        Err(Error::ModelNotFound {
            path: PathBuf::from("No model directory found in standard locations"),
        })
    }

    /// Check if models are available for a preset
    pub fn is_available(preset: ModelPreset) -> bool {
        if let Ok(dir) = Self::find_model_dir() {
            let encoder = dir.join(preset.encoder_filename());
            let decoder = dir.join(preset.decoder_filename());
            encoder.exists() && decoder.exists()
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_cache_new() {
        let cache = SessionCache::new();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_cache_key_format() {
        let path = Path::new("/models/test.onnx");
        let key_gpu = format!("{}:{}", path.display(), true);
        let key_cpu = format!("{}:{}", path.display(), false);

        assert!(key_gpu.contains("true"));
        assert!(key_cpu.contains("false"));
        assert_ne!(key_gpu, key_cpu);
    }

    #[test]
    fn test_model_resolver_custom() {
        let config = ModelConfig::custom(
            PathBuf::from("/custom/encoder.onnx"),
            PathBuf::from("/custom/decoder.onnx"),
        );

        let (encoder, decoder) = ModelResolver::resolve(&config).unwrap();
        assert_eq!(encoder, PathBuf::from("/custom/encoder.onnx"));
        assert_eq!(decoder, PathBuf::from("/custom/decoder.onnx"));
    }
}
