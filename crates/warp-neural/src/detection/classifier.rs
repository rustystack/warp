//! Content type classification for neural compression

use serde::{Deserialize, Serialize};

use crate::model::ModelPreset;

/// Content type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContentType {
    /// Image-like data (RGB, grayscale, photos)
    /// Best suited for Rgb16x model
    ImageLike,

    /// Audio-like data (waveforms, stereo signals)
    /// Best suited for Stereo5x model
    AudioLike,

    /// Scientific/HPC data (floating point arrays, simulation output)
    /// Can use generic neural compression
    Scientific,

    /// Text or structured data
    /// Should use lossless compression
    Text,

    /// Already compressed or encrypted data
    /// Skip compression entirely
    Incompressible,

    /// Unknown binary data
    /// Conservative approach - use lossless
    Unknown,
}

impl ContentType {
    /// Get recommended model preset for this content type
    #[must_use]
    pub fn recommended_model(&self) -> Option<ModelPreset> {
        match self {
            Self::ImageLike => Some(ModelPreset::Rgb16x),
            Self::AudioLike => Some(ModelPreset::Stereo5x),
            Self::Scientific => Some(ModelPreset::Generic),
            Self::Text | Self::Unknown => None, // Use lossless
            Self::Incompressible => None,
        }
    }

    /// Should use lossless compression instead of neural
    #[must_use]
    pub fn prefers_lossless(&self) -> bool {
        matches!(self, Self::Text | Self::Unknown)
    }

    /// Should skip compression entirely
    #[must_use]
    pub fn skip_compression(&self) -> bool {
        matches!(self, Self::Incompressible)
    }
}

/// Suitability score for neural compression
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuitabilityScore {
    /// Overall suitability for neural compression (0.0-1.0)
    /// Higher = more suitable for neural compression
    pub score: f32,

    /// Detected content type
    pub content_type: ContentType,

    /// Recommended model preset (if neural compression is suitable)
    pub recommended_model: Option<ModelPreset>,

    /// Should use lossless fallback instead?
    pub use_lossless: bool,

    /// Skip compression entirely (already compressed/encrypted)
    pub skip_compression: bool,

    /// Entropy of input data (0.0-1.0)
    pub entropy: f64,

    /// Confidence in content type detection (0.0-1.0)
    pub confidence: f32,
}

impl SuitabilityScore {
    /// Create a score indicating neural compression is not suitable
    fn not_suitable(entropy: f64) -> Self {
        Self {
            score: 0.0,
            content_type: ContentType::Incompressible,
            recommended_model: None,
            use_lossless: false,
            skip_compression: true,
            entropy,
            confidence: 0.9,
        }
    }

    /// Create a score for lossless-preferred content
    fn lossless_preferred(content_type: ContentType, entropy: f64, confidence: f32) -> Self {
        Self {
            score: 0.2,
            content_type,
            recommended_model: None,
            use_lossless: true,
            skip_compression: false,
            entropy,
            confidence,
        }
    }

    /// Create a score for neural-suitable content
    fn neural_suitable(
        content_type: ContentType,
        score: f32,
        entropy: f64,
        confidence: f32,
    ) -> Self {
        Self {
            score,
            content_type,
            recommended_model: content_type.recommended_model(),
            use_lossless: false,
            skip_compression: false,
            entropy,
            confidence,
        }
    }
}

/// Content classifier for neural compression suitability
pub struct ContentClassifier {
    /// Entropy threshold above which data is considered incompressible
    entropy_threshold_high: f64,

    /// Entropy threshold below which data is highly compressible
    entropy_threshold_low: f64,

    /// Minimum size for reliable analysis
    min_analysis_size: usize,

    /// Sample size for heuristic analysis
    sample_size: usize,
}

impl ContentClassifier {
    /// Create a new content classifier with default settings
    #[must_use]
    pub fn new() -> Self {
        Self {
            entropy_threshold_high: 0.95,
            entropy_threshold_low: 0.3,
            min_analysis_size: 256,
            sample_size: 4096,
        }
    }

    /// Configure entropy thresholds
    #[must_use]
    pub fn with_entropy_thresholds(mut self, low: f64, high: f64) -> Self {
        self.entropy_threshold_low = low;
        self.entropy_threshold_high = high;
        self
    }

    /// Analyze data and determine neural compression suitability
    pub fn analyze(&self, data: &[u8]) -> SuitabilityScore {
        // Check magic bytes first - this works even for small data
        if data.len() >= 8 {
            if let Some((content_type, confidence)) = self.check_magic_bytes(data) {
                let entropy = Self::calculate_entropy(data);
                return match content_type {
                    ContentType::Incompressible => SuitabilityScore::not_suitable(entropy),
                    ContentType::ImageLike => {
                        let score = Self::score_for_neural(entropy, 0.9, confidence);
                        SuitabilityScore::neural_suitable(content_type, score, entropy, confidence)
                    }
                    ContentType::AudioLike => {
                        let score = Self::score_for_neural(entropy, 0.85, confidence);
                        SuitabilityScore::neural_suitable(content_type, score, entropy, confidence)
                    }
                    _ => SuitabilityScore::lossless_preferred(content_type, entropy, confidence),
                };
            }
        }

        // For small data without magic bytes, return unknown
        if data.len() < self.min_analysis_size {
            return SuitabilityScore::lossless_preferred(ContentType::Unknown, 0.5, 0.5);
        }

        // Calculate entropy
        let entropy = Self::calculate_entropy(data);

        // High entropy = likely already compressed or random
        if entropy > self.entropy_threshold_high {
            return SuitabilityScore::not_suitable(entropy);
        }

        // Detect content type based on patterns (magic bytes already checked above)
        let (content_type, confidence) = self.detect_content_type_statistical(data);

        // Score based on content type and entropy
        match content_type {
            ContentType::ImageLike => {
                let score = Self::score_for_neural(entropy, 0.9, confidence);
                SuitabilityScore::neural_suitable(content_type, score, entropy, confidence)
            }
            ContentType::AudioLike => {
                let score = Self::score_for_neural(entropy, 0.85, confidence);
                SuitabilityScore::neural_suitable(content_type, score, entropy, confidence)
            }
            ContentType::Scientific => {
                let score = Self::score_for_neural(entropy, 0.7, confidence);
                SuitabilityScore::neural_suitable(content_type, score, entropy, confidence)
            }
            ContentType::Text => SuitabilityScore::lossless_preferred(content_type, entropy, confidence),
            ContentType::Unknown => {
                // Conservative - prefer lossless for unknown data
                SuitabilityScore::lossless_preferred(content_type, entropy, confidence)
            }
            ContentType::Incompressible => SuitabilityScore::not_suitable(entropy),
        }
    }

    /// Calculate Shannon entropy of data (0.0 = uniform, 1.0 = random)
    fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        // Build histogram
        let mut counts = [0u64; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }

        // Calculate entropy
        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &counts {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        // Normalize to 0-1 range (max entropy is 8 bits)
        entropy / 8.0
    }

    /// Detect content type based on patterns and heuristics
    fn detect_content_type(&self, data: &[u8]) -> (ContentType, f32) {
        // Check for common file signatures
        if let Some((content_type, confidence)) = self.check_magic_bytes(data) {
            return (content_type, confidence);
        }

        self.detect_content_type_statistical(data)
    }

    /// Detect content type based on statistical analysis (no magic byte check)
    fn detect_content_type_statistical(&self, data: &[u8]) -> (ContentType, f32) {
        // Statistical analysis
        let sample = if data.len() > self.sample_size {
            &data[..self.sample_size]
        } else {
            data
        };

        // Check for text characteristics
        let (ascii_ratio, printable_ratio) = Self::calculate_text_ratios(sample);
        if printable_ratio > 0.9 && ascii_ratio > 0.85 {
            return (ContentType::Text, 0.8);
        }

        // Check for floating point patterns
        if self.looks_like_float_array(sample) {
            return (ContentType::Scientific, 0.7);
        }

        // Check for image-like patterns (high byte correlation)
        if self.has_spatial_correlation(sample) {
            return (ContentType::ImageLike, 0.6);
        }

        // Check for audio-like patterns (oscillating values)
        if self.has_temporal_correlation(sample) {
            return (ContentType::AudioLike, 0.5);
        }

        (ContentType::Unknown, 0.3)
    }

    /// Check for known file format magic bytes
    fn check_magic_bytes(&self, data: &[u8]) -> Option<(ContentType, f32)> {
        if data.len() < 8 {
            return None;
        }

        // Image formats
        if &data[0..4] == b"\x89PNG" {
            return Some((ContentType::Incompressible, 0.95)); // Already compressed
        }
        if &data[0..2] == b"\xFF\xD8" {
            return Some((ContentType::Incompressible, 0.95)); // JPEG
        }
        if &data[0..4] == b"GIF8" {
            return Some((ContentType::Incompressible, 0.95));
        }
        if &data[0..4] == b"RIFF" && data.len() > 11 && &data[8..12] == b"WEBP" {
            return Some((ContentType::Incompressible, 0.95));
        }

        // Raw image formats (uncompressed)
        if &data[0..2] == b"BM" {
            return Some((ContentType::ImageLike, 0.9)); // BMP
        }
        if &data[0..4] == b"II\x2A\x00" || &data[0..4] == b"MM\x00\x2A" {
            return Some((ContentType::ImageLike, 0.85)); // TIFF
        }

        // Audio formats
        if &data[0..4] == b"RIFF" && data.len() > 11 && &data[8..12] == b"WAVE" {
            return Some((ContentType::AudioLike, 0.9)); // WAV
        }
        if &data[0..4] == b"fLaC" {
            return Some((ContentType::Incompressible, 0.95)); // FLAC
        }
        if &data[0..4] == b"OggS" {
            return Some((ContentType::Incompressible, 0.95)); // Ogg
        }

        // Compressed formats
        if &data[0..4] == b"\x28\xB5\x2F\xFD" {
            return Some((ContentType::Incompressible, 0.99)); // Zstd
        }
        if &data[0..2] == b"\x1F\x8B" {
            return Some((ContentType::Incompressible, 0.99)); // Gzip
        }
        if &data[0..4] == b"PK\x03\x04" {
            return Some((ContentType::Incompressible, 0.99)); // Zip
        }

        None
    }

    /// Calculate ASCII and printable character ratios
    fn calculate_text_ratios(data: &[u8]) -> (f64, f64) {
        let mut ascii_count = 0;
        let mut printable_count = 0;

        for &byte in data {
            if byte.is_ascii() {
                ascii_count += 1;
            }
            if byte.is_ascii_graphic() || byte.is_ascii_whitespace() {
                printable_count += 1;
            }
        }

        let len = data.len() as f64;
        (ascii_count as f64 / len, printable_count as f64 / len)
    }

    /// Check if data looks like a floating point array
    fn looks_like_float_array(&self, data: &[u8]) -> bool {
        if data.len() % 4 != 0 || data.len() < 32 {
            return false;
        }

        let mut valid_floats = 0;
        let samples = data.len().min(64) / 4;

        for chunk in data.chunks_exact(4).take(samples) {
            let f = f32::from_le_bytes(chunk.try_into().unwrap());
            if f.is_finite() && f.abs() < 1e10 {
                valid_floats += 1;
            }
        }

        // At least 75% should be valid floats
        valid_floats * 4 >= samples * 3
    }

    /// Check for spatial correlation (image-like data)
    fn has_spatial_correlation(&self, data: &[u8]) -> bool {
        if data.len() < 256 {
            return false;
        }

        // Check if adjacent bytes are similar (common in images)
        let mut similar_count = 0;
        for window in data.windows(2) {
            let diff = (window[0] as i16 - window[1] as i16).abs();
            if diff <= 16 {
                similar_count += 1;
            }
        }

        // More than 60% similar = likely spatial data
        similar_count * 5 > (data.len() - 1) * 3
    }

    /// Check for temporal correlation (audio-like data)
    fn has_temporal_correlation(&self, data: &[u8]) -> bool {
        if data.len() < 256 {
            return false;
        }

        // Check for oscillating patterns (common in audio)
        let mut sign_changes = 0;
        let center = 128i16;

        for window in data.windows(2) {
            let a = window[0] as i16 - center;
            let b = window[1] as i16 - center;
            if (a > 0 && b < 0) || (a < 0 && b > 0) {
                sign_changes += 1;
            }
        }

        // Audio typically has many zero crossings
        let change_ratio = sign_changes as f64 / (data.len() - 1) as f64;
        (0.1..0.5).contains(&change_ratio)
    }

    /// Calculate score for neural compression suitability
    fn score_for_neural(entropy: f64, base_score: f32, confidence: f32) -> f32 {
        // Lower entropy = better for neural compression
        let entropy_factor = 1.0 - (entropy as f32 * 0.5);
        base_score * entropy_factor * confidence
    }
}

impl Default for ContentClassifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_calculation() {
        // Uniform data = low entropy
        let uniform = vec![42u8; 1024];
        let entropy = ContentClassifier::calculate_entropy(&uniform);
        assert!(entropy < 0.01, "Uniform data should have near-zero entropy");

        // Random data = high entropy
        let random: Vec<u8> = (0..1024).map(|i| (i * 17 + 13) as u8).collect();
        let entropy = ContentClassifier::calculate_entropy(&random);
        assert!(entropy > 0.9, "Random-ish data should have high entropy");
    }

    #[test]
    fn test_content_type_recommended_model() {
        assert_eq!(
            ContentType::ImageLike.recommended_model(),
            Some(ModelPreset::Rgb16x)
        );
        assert_eq!(
            ContentType::AudioLike.recommended_model(),
            Some(ModelPreset::Stereo5x)
        );
        assert_eq!(ContentType::Text.recommended_model(), None);
    }

    #[test]
    fn test_classifier_text_detection() {
        let classifier = ContentClassifier::new();

        // Use text longer than min_analysis_size (256 bytes)
        let text = b"Hello, this is some text data for testing purposes. \
            This text needs to be long enough to trigger proper content type detection. \
            The classifier requires at least 256 bytes of data to perform statistical analysis. \
            Adding more content here to ensure we meet the minimum threshold for accurate detection. \
            Text content should be detected based on high ASCII and printable character ratios.";
        let score = classifier.analyze(text);

        assert!(score.use_lossless, "Text should prefer lossless");
        assert_eq!(score.content_type, ContentType::Text);
    }

    #[test]
    fn test_classifier_high_entropy() {
        let classifier = ContentClassifier::new();

        // Simulate already-compressed data (high entropy)
        let compressed: Vec<u8> = (0..1024).map(|_| rand::random()).collect();
        let score = classifier.analyze(&compressed);

        assert!(
            score.skip_compression || score.entropy > 0.9,
            "High entropy should skip or score low"
        );
    }

    #[test]
    fn test_magic_bytes_detection() {
        let classifier = ContentClassifier::new();

        // PNG magic bytes
        let png_data = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00];
        let score = classifier.analyze(&png_data);
        assert!(score.skip_compression, "PNG should skip compression");

        // Zstd magic bytes
        let zstd_data = [0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00, 0x00, 0x00];
        let score = classifier.analyze(&zstd_data);
        assert!(score.skip_compression, "Zstd should skip compression");
    }

    #[test]
    fn test_float_array_detection() {
        let classifier = ContentClassifier::new();

        // Create array of floats
        let floats: Vec<u8> = (0..256)
            .flat_map(|i| (i as f32 * 0.1).to_le_bytes())
            .collect();

        let score = classifier.analyze(&floats);
        assert!(
            score.content_type == ContentType::Scientific
                || score.content_type == ContentType::Unknown
        );
    }
}
