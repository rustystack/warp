//! Configuration for the Chonkers algorithm
//!
//! The algorithm processes data through multiple layers, each with its own
//! target chunk size. Higher layers have larger target sizes.

use crate::{Error, Result};
use serde::{Deserialize, Serialize};

/// Configuration for the Chonkers algorithm
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChonkersConfig {
    /// Number of layers to process
    pub num_layers: usize,

    /// Base target chunk size (layer 0)
    pub base_target_size: usize,

    /// Size multiplier between layers (typically 2-4)
    pub layer_multiplier: usize,

    /// Minimum chunk size as fraction of target (0.0-1.0)
    pub min_size_ratio: f64,

    /// Maximum chunk size as fraction of target (1.0+)
    pub max_size_ratio: f64,

    /// Caterpillar phase: minimum period length to detect
    pub min_period_length: usize,

    /// Caterpillar phase: minimum repetitions to collapse
    pub min_repetitions: usize,
}

impl Default for ChonkersConfig {
    fn default() -> Self {
        Self {
            num_layers: 3,
            base_target_size: 4096,       // 4 KB base
            layer_multiplier: 4,           // 4x per layer: 4KB, 16KB, 64KB
            min_size_ratio: 0.25,          // min = 25% of target
            max_size_ratio: 4.0,           // max = 400% of target
            min_period_length: 64,         // minimum period to detect
            min_repetitions: 3,            // need at least 3 repetitions
        }
    }
}

impl ChonkersConfig {
    /// Create a new configuration with custom parameters
    pub fn new(
        num_layers: usize,
        base_target_size: usize,
        layer_multiplier: usize,
    ) -> Result<Self> {
        if num_layers == 0 {
            return Err(Error::InvalidConfig("num_layers must be > 0".into()));
        }
        if base_target_size < 64 {
            return Err(Error::InvalidConfig(
                "base_target_size must be >= 64".into(),
            ));
        }
        if layer_multiplier < 2 {
            return Err(Error::InvalidConfig("layer_multiplier must be >= 2".into()));
        }

        Ok(Self {
            num_layers,
            base_target_size,
            layer_multiplier,
            ..Default::default()
        })
    }

    /// Preset for small files (1-10 MB)
    pub fn small_files() -> Self {
        Self {
            num_layers: 2,
            base_target_size: 2048,        // 2 KB
            layer_multiplier: 4,
            ..Default::default()
        }
    }

    /// Preset for medium files (10-100 MB)
    pub fn medium_files() -> Self {
        Self::default()
    }

    /// Preset for large files (100 MB+)
    pub fn large_files() -> Self {
        Self {
            num_layers: 4,
            base_target_size: 8192,        // 8 KB
            layer_multiplier: 4,           // 8KB, 32KB, 128KB, 512KB
            ..Default::default()
        }
    }

    /// Preset optimized for backup workloads
    pub fn backup() -> Self {
        Self {
            num_layers: 3,
            base_target_size: 16384,       // 16 KB
            layer_multiplier: 4,
            min_period_length: 128,        // larger periods for backup
            ..Default::default()
        }
    }

    /// Get configuration for a specific layer
    pub fn layer(&self, layer_idx: usize) -> LayerConfig {
        let target_size = self.base_target_size * self.layer_multiplier.pow(layer_idx as u32);
        let min_size = (target_size as f64 * self.min_size_ratio) as usize;
        let max_size = (target_size as f64 * self.max_size_ratio) as usize;

        LayerConfig {
            index: layer_idx,
            target_size,
            min_size: min_size.max(1),
            max_size,
            min_period_length: self.min_period_length,
            min_repetitions: self.min_repetitions,
        }
    }

    /// Get all layer configurations
    pub fn layers(&self) -> Vec<LayerConfig> {
        (0..self.num_layers).map(|i| self.layer(i)).collect()
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        if self.num_layers == 0 {
            return Err(Error::InvalidConfig("num_layers must be > 0".into()));
        }
        if self.base_target_size < 64 {
            return Err(Error::InvalidConfig(
                "base_target_size must be >= 64".into(),
            ));
        }
        if self.layer_multiplier < 2 {
            return Err(Error::InvalidConfig("layer_multiplier must be >= 2".into()));
        }
        if self.min_size_ratio <= 0.0 || self.min_size_ratio >= 1.0 {
            return Err(Error::InvalidConfig(
                "min_size_ratio must be in (0, 1)".into(),
            ));
        }
        if self.max_size_ratio <= 1.0 {
            return Err(Error::InvalidConfig("max_size_ratio must be > 1".into()));
        }
        Ok(())
    }
}

/// Configuration for a single layer
#[derive(Debug, Clone, Copy)]
pub struct LayerConfig {
    /// Layer index (0 = base layer)
    pub index: usize,

    /// Target chunk size for this layer
    pub target_size: usize,

    /// Minimum allowed chunk size
    pub min_size: usize,

    /// Maximum allowed chunk size
    pub max_size: usize,

    /// Minimum period length for caterpillar phase
    pub min_period_length: usize,

    /// Minimum repetitions for caterpillar phase
    pub min_repetitions: usize,
}

impl LayerConfig {
    /// Check if a chunk size is within bounds
    pub fn is_valid_size(&self, size: usize) -> bool {
        size >= self.min_size && size <= self.max_size
    }

    /// Check if a chunk is a "kitten" (undersized)
    pub fn is_kitten(&self, size: usize) -> bool {
        size < self.min_size
    }

    /// Check if a chunk is oversized
    pub fn is_oversized(&self, size: usize) -> bool {
        size > self.max_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ChonkersConfig::default();
        assert_eq!(config.num_layers, 3);
        assert_eq!(config.base_target_size, 4096);
        assert_eq!(config.layer_multiplier, 4);
    }

    #[test]
    fn test_layer_config() {
        let config = ChonkersConfig::default();

        let layer0 = config.layer(0);
        assert_eq!(layer0.target_size, 4096);

        let layer1 = config.layer(1);
        assert_eq!(layer1.target_size, 16384); // 4096 * 4

        let layer2 = config.layer(2);
        assert_eq!(layer2.target_size, 65536); // 4096 * 16
    }

    #[test]
    fn test_layer_size_bounds() {
        let config = ChonkersConfig::default();
        let layer = config.layer(0);

        // Target is 4096, min is 25% = 1024, max is 400% = 16384
        assert_eq!(layer.min_size, 1024);
        assert_eq!(layer.max_size, 16384);

        assert!(!layer.is_valid_size(500));   // too small
        assert!(layer.is_valid_size(2000));   // valid
        assert!(!layer.is_valid_size(20000)); // too large

        assert!(layer.is_kitten(500));
        assert!(!layer.is_kitten(2000));

        assert!(layer.is_oversized(20000));
        assert!(!layer.is_oversized(2000));
    }

    #[test]
    fn test_presets() {
        let small = ChonkersConfig::small_files();
        assert_eq!(small.num_layers, 2);
        assert_eq!(small.base_target_size, 2048);

        let large = ChonkersConfig::large_files();
        assert_eq!(large.num_layers, 4);
        assert_eq!(large.base_target_size, 8192);

        let backup = ChonkersConfig::backup();
        assert_eq!(backup.base_target_size, 16384);
    }

    #[test]
    fn test_validation() {
        let mut config = ChonkersConfig::default();
        assert!(config.validate().is_ok());

        config.num_layers = 0;
        assert!(config.validate().is_err());

        config = ChonkersConfig::default();
        config.base_target_size = 10;
        assert!(config.validate().is_err());

        config = ChonkersConfig::default();
        config.layer_multiplier = 1;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_new_config() {
        let config = ChonkersConfig::new(5, 8192, 2).unwrap();
        assert_eq!(config.num_layers, 5);
        assert_eq!(config.base_target_size, 8192);
        assert_eq!(config.layer_multiplier, 2);

        // Should fail with invalid params
        assert!(ChonkersConfig::new(0, 4096, 4).is_err());
        assert!(ChonkersConfig::new(3, 32, 4).is_err());
        assert!(ChonkersConfig::new(3, 4096, 1).is_err());
    }
}
