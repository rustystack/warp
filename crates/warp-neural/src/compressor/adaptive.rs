//! Adaptive neural compressor
//!
//! Automatically selects between neural and lossless compression
//! based on content analysis.

use tracing::debug;
use warp_compress::Compressor;

use crate::detection::ContentClassifier;
use crate::error::Result;
use crate::model::ModelConfig;

use super::walloc::{QualityConfig, WallocCompressor};

/// Adaptive neural compressor
///
/// Analyzes content and automatically chooses the best compression strategy:
/// - Neural (WaLLoC) for image-like, audio-like data
/// - Zstd for text and unknown data
/// - LZ4 for high-entropy data that still benefits from compression
/// - Pass-through for already-compressed data
pub struct AdaptiveNeuralCompressor {
    /// Neural compressor for suitable data
    neural: WallocCompressor,

    /// Fast lossless compressor
    lz4: warp_compress::Lz4Compressor,

    /// Balanced lossless compressor
    zstd: warp_compress::ZstdCompressor,

    /// Content classifier
    classifier: ContentClassifier,

    /// Minimum suitability score for neural compression
    neural_threshold: f32,
}

impl AdaptiveNeuralCompressor {
    /// Create a new adaptive compressor with default settings
    pub fn new() -> Result<Self> {
        Self::with_config(ModelConfig::default(), QualityConfig::default())
    }

    /// Create with custom configuration
    pub fn with_config(model_config: ModelConfig, quality_config: QualityConfig) -> Result<Self> {
        Ok(Self {
            neural: WallocCompressor::with_config(model_config, quality_config)?,
            lz4: warp_compress::Lz4Compressor::new(),
            zstd: warp_compress::ZstdCompressor::new(3)?,
            classifier: ContentClassifier::new(),
            neural_threshold: 0.6,
        })
    }

    /// Set the neural compression threshold
    ///
    /// Higher threshold = less likely to use neural compression
    #[must_use]
    pub fn with_threshold(mut self, threshold: f32) -> Self {
        self.neural_threshold = threshold.clamp(0.0, 1.0);
        self
    }

    /// Analyze and compress with the best strategy
    pub fn compress_adaptive(&self, input: &[u8]) -> warp_compress::Result<Vec<u8>> {
        if input.is_empty() {
            return Ok(vec![]);
        }

        let analysis = self.classifier.analyze(input);

        // Skip compression for already-compressed data
        if analysis.skip_compression {
            debug!(
                entropy = analysis.entropy,
                "Skipping compression for incompressible data"
            );
            return Ok(input.to_vec());
        }

        // Choose strategy based on analysis
        let (strategy, compressed) =
            if analysis.score >= self.neural_threshold && !analysis.use_lossless {
                // Use neural compression
                debug!(
                    score = analysis.score,
                    content_type = ?analysis.content_type,
                    "Using neural compression"
                );
                ("neural", self.neural.compress(input)?)
            } else if analysis.entropy > 0.7 {
                // High entropy but still compressible - use fast LZ4
                debug!(entropy = analysis.entropy, "Using LZ4 for high-entropy data");
                ("lz4", self.lz4.compress(input)?)
            } else {
                // Default to balanced zstd
                debug!(entropy = analysis.entropy, "Using zstd compression");
                ("zstd", self.zstd.compress(input)?)
            };

        debug!(
            strategy = strategy,
            original = input.len(),
            compressed = compressed.len(),
            ratio = input.len() as f64 / compressed.len().max(1) as f64,
            "Adaptive compression complete"
        );

        Ok(compressed)
    }

    /// Decompress data (auto-detects format)
    pub fn decompress_adaptive(&self, input: &[u8]) -> warp_compress::Result<Vec<u8>> {
        if input.is_empty() {
            return Ok(vec![]);
        }

        // Try neural first (check for WLOC magic)
        if crate::header::WlocHeader::is_wloc(input) {
            return self.neural.decompress(input);
        }

        // Try zstd (check for zstd magic)
        if input.len() >= 4 && &input[0..4] == &[0x28, 0xB5, 0x2F, 0xFD] {
            return self.zstd.decompress(input);
        }

        // Try LZ4 (no magic, just try it)
        // LZ4 format starts with the original size as a 4-byte little-endian integer
        if let Ok(decompressed) = self.lz4.decompress(input) {
            return Ok(decompressed);
        }

        // Last resort: try zstd
        self.zstd.decompress(input)
    }

    /// Check if neural compression is available
    #[must_use]
    pub fn is_neural_available(&self) -> bool {
        self.neural.is_neural_available()
    }

    /// Get the current neural threshold
    #[must_use]
    pub fn neural_threshold(&self) -> f32 {
        self.neural_threshold
    }
}

impl Compressor for AdaptiveNeuralCompressor {
    fn compress(&self, input: &[u8]) -> warp_compress::Result<Vec<u8>> {
        self.compress_adaptive(input)
    }

    fn decompress(&self, input: &[u8]) -> warp_compress::Result<Vec<u8>> {
        self.decompress_adaptive(input)
    }

    fn name(&self) -> &'static str {
        "adaptive-neural"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adaptive_compressor_creation() {
        let compressor = AdaptiveNeuralCompressor::new().unwrap();
        assert!(compressor.neural_threshold > 0.0);
    }

    #[test]
    fn test_adaptive_threshold() {
        let compressor = AdaptiveNeuralCompressor::new()
            .unwrap()
            .with_threshold(0.8);
        assert_eq!(compressor.neural_threshold(), 0.8);
    }

    #[test]
    fn test_adaptive_text_compression() {
        let compressor = AdaptiveNeuralCompressor::new().unwrap();

        let text = b"This is some text data that should use lossless compression.";
        let compressed = compressor.compress(text).unwrap();
        let decompressed = compressor.decompress(&compressed).unwrap();

        assert_eq!(decompressed, text);
    }

    #[test]
    fn test_adaptive_empty_input() {
        let compressor = AdaptiveNeuralCompressor::new().unwrap();

        let empty: &[u8] = &[];
        let compressed = compressor.compress(empty).unwrap();
        assert!(compressed.is_empty());
    }

    #[test]
    fn test_compressor_trait() {
        let compressor: Box<dyn Compressor> =
            Box::new(AdaptiveNeuralCompressor::new().unwrap());

        let data = b"Test data for trait implementation";
        let compressed = compressor.compress(data).unwrap();
        let decompressed = compressor.decompress(&compressed).unwrap();

        assert_eq!(decompressed, data);
        assert_eq!(compressor.name(), "adaptive-neural");
    }
}
