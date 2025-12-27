//! Pre-trained model presets and configuration

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Pre-trained model presets from WaLLoC
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ModelPreset {
    /// RGB image compression at 16x ratio
    /// Best for image-like data, photographs, renders
    #[default]
    Rgb16x,

    /// Stereo audio at 5x ratio
    /// Best for audio waveforms, time-series signals
    Stereo5x,

    /// Generic data compression
    /// Works on arbitrary byte streams with reasonable results
    Generic,

    /// Custom model loaded from user path
    Custom,
}

impl ModelPreset {
    /// Get the compression ratio for this preset
    #[must_use]
    pub fn compression_ratio(&self) -> f32 {
        match self {
            Self::Rgb16x => 16.0,
            Self::Stereo5x => 5.0,
            Self::Generic => 8.0,
            Self::Custom => 1.0, // Unknown, needs config
        }
    }

    /// Get the recommended block size for this preset
    #[must_use]
    pub fn block_size(&self) -> usize {
        match self {
            Self::Rgb16x => 64 * 1024,    // 64KB blocks for images
            Self::Stereo5x => 32 * 1024,  // 32KB blocks for audio
            Self::Generic => 64 * 1024,   // 64KB default
            Self::Custom => 64 * 1024,
        }
    }

    /// Get encoder model filename
    #[must_use]
    pub fn encoder_filename(&self) -> &'static str {
        match self {
            Self::Rgb16x => "rgb_16x_encoder.onnx",
            Self::Stereo5x => "stereo_5x_encoder.onnx",
            Self::Generic => "generic_encoder.onnx",
            Self::Custom => "",
        }
    }

    /// Get decoder model filename
    #[must_use]
    pub fn decoder_filename(&self) -> &'static str {
        match self {
            Self::Rgb16x => "rgb_16x_decoder.onnx",
            Self::Stereo5x => "stereo_5x_decoder.onnx",
            Self::Generic => "generic_decoder.onnx",
            Self::Custom => "",
        }
    }
}

/// Model configuration for WaLLoC compression
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelConfig {
    /// Model preset to use
    pub preset: ModelPreset,

    /// Custom encoder model path (for Custom preset)
    pub custom_encoder_path: Option<PathBuf>,

    /// Custom decoder model path (for Custom preset)
    pub custom_decoder_path: Option<PathBuf>,

    /// Target compression ratio (0 = use preset default)
    pub target_ratio: f32,

    /// Latent dimensions from autoencoder
    pub latent_dims: usize,

    /// Wavelet decomposition levels
    pub wavelet_levels: usize,

    /// Input block size for processing
    pub block_size: usize,

    /// Minimum input size to use neural compression
    pub min_input_size: usize,

    /// Allow lossy compression
    pub allow_lossy: bool,

    /// Target quality (PSNR in dB, 0 = no constraint)
    pub target_psnr: f32,
}

impl Default for ModelConfig {
    fn default() -> Self {
        Self {
            preset: ModelPreset::default(),
            custom_encoder_path: None,
            custom_decoder_path: None,
            target_ratio: 0.0, // Use preset default
            latent_dims: 64,
            wavelet_levels: 3,
            block_size: 64 * 1024, // 64KB
            min_input_size: 4096,  // 4KB minimum
            allow_lossy: true,
            target_psnr: 30.0, // Good quality
        }
    }
}

impl ModelConfig {
    /// Create config for RGB image compression
    #[must_use]
    pub fn rgb() -> Self {
        Self {
            preset: ModelPreset::Rgb16x,
            block_size: 64 * 1024,
            ..Default::default()
        }
    }

    /// Create config for audio compression
    #[must_use]
    pub fn audio() -> Self {
        Self {
            preset: ModelPreset::Stereo5x,
            block_size: 32 * 1024,
            target_ratio: 5.0,
            ..Default::default()
        }
    }

    /// Create config for generic data
    #[must_use]
    pub fn generic() -> Self {
        Self {
            preset: ModelPreset::Generic,
            block_size: 64 * 1024,
            target_ratio: 8.0,
            ..Default::default()
        }
    }

    /// Create config with custom model paths
    #[must_use]
    pub fn custom(encoder: PathBuf, decoder: PathBuf) -> Self {
        Self {
            preset: ModelPreset::Custom,
            custom_encoder_path: Some(encoder),
            custom_decoder_path: Some(decoder),
            ..Default::default()
        }
    }

    /// Set block size
    #[must_use]
    pub fn with_block_size(mut self, size: usize) -> Self {
        self.block_size = size;
        self
    }

    /// Set target compression ratio
    #[must_use]
    pub fn with_target_ratio(mut self, ratio: f32) -> Self {
        self.target_ratio = ratio;
        self
    }

    /// Set target PSNR quality
    #[must_use]
    pub fn with_target_psnr(mut self, psnr: f32) -> Self {
        self.target_psnr = psnr;
        self
    }

    /// Disable lossy compression (always fall back to lossless)
    #[must_use]
    pub fn lossless_only(mut self) -> Self {
        self.allow_lossy = false;
        self
    }

    /// Get the effective compression ratio
    #[must_use]
    pub fn effective_ratio(&self) -> f32 {
        if self.target_ratio > 0.0 {
            self.target_ratio
        } else {
            self.preset.compression_ratio()
        }
    }

    /// Get the effective block size
    #[must_use]
    pub fn effective_block_size(&self) -> usize {
        if self.block_size > 0 {
            self.block_size
        } else {
            self.preset.block_size()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preset_defaults() {
        assert_eq!(ModelPreset::Rgb16x.compression_ratio(), 16.0);
        assert_eq!(ModelPreset::Stereo5x.compression_ratio(), 5.0);
    }

    #[test]
    fn test_config_builders() {
        let rgb = ModelConfig::rgb();
        assert_eq!(rgb.preset, ModelPreset::Rgb16x);

        let audio = ModelConfig::audio();
        assert_eq!(audio.preset, ModelPreset::Stereo5x);

        let custom = ModelConfig::default()
            .with_target_ratio(12.0)
            .with_block_size(128 * 1024);
        assert_eq!(custom.target_ratio, 12.0);
        assert_eq!(custom.block_size, 128 * 1024);
    }

    #[test]
    fn test_effective_values() {
        let config = ModelConfig::default();
        assert_eq!(config.effective_ratio(), 16.0); // Preset default

        let config = ModelConfig::default().with_target_ratio(20.0);
        assert_eq!(config.effective_ratio(), 20.0); // Explicit override
    }
}
