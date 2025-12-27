//! warp-neural: Neural compression for warp
//!
//! This crate provides neural compression capabilities using the WaLLoC
//! (Wavelet Learned Lossy Compression) algorithm. It integrates with
//! ONNX Runtime for efficient inference and supports both CPU and CUDA
//! GPU acceleration.
//!
//! # Features
//!
//! - **WaLLoC Compression**: Lossy neural compression achieving 12-28x ratios
//! - **Content Detection**: Automatic content type classification
//! - **Adaptive Mode**: Smart selection between neural and lossless compression
//! - **GPU Acceleration**: CUDA support via ONNX Runtime
//! - **Batch Processing**: Parallel compression of multiple chunks
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use warp_neural::{WallocCompressor, AdaptiveNeuralCompressor};
//! use warp_compress::Compressor;
//!
//! // Basic neural compression (with fallback if models not available)
//! let compressor = WallocCompressor::new()?;
//! let compressed = compressor.compress(&data)?;
//! let restored = compressor.decompress(&compressed)?;
//!
//! // Adaptive mode - automatically selects best algorithm
//! let adaptive = AdaptiveNeuralCompressor::new()?;
//! let compressed = adaptive.compress(&data)?;
//! ```
//!
//! # Architecture
//!
//! WaLLoC uses a three-stage pipeline:
//!
//! 1. **Wavelet Transform**: Haar wavelet packet transform to expose redundancies
//! 2. **Autoencoder**: Shallow neural network (<100k params) for dimensionality reduction
//! 3. **Entropy Coding**: Zstd compression on quantized latent space
//!
//! The algorithm achieves ~5% of the computational cost of typical neural codecs
//! while maintaining competitive compression ratios.
//!
//! # Content Detection
//!
//! The classifier analyzes input data to determine suitability:
//!
//! - **Image-like data**: High spatial correlation → use Rgb16x model
//! - **Audio-like data**: Temporal patterns → use Stereo5x model
//! - **Text/structured**: Low neural suitability → use lossless
//! - **Already compressed**: Skip compression entirely
//!
//! # Feature Flags
//!
//! - `cpu` (default): CPU-only inference
//! - `cuda`: Enable CUDA GPU acceleration
//! - `tensorrt`: Enable TensorRT optimization (requires `cuda`)

#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod compressor;
pub mod detection;
pub mod error;
pub mod header;
pub mod model;

// Re-export main types at crate root
pub use compressor::{AdaptiveNeuralCompressor, BatchNeuralCompressor, QualityConfig, WallocCompressor};
pub use detection::{ContentClassifier, ContentType, SuitabilityScore};
pub use error::{Error, Result};
pub use header::{HeaderFlags, WlocHeader, HEADER_SIZE, MAGIC, VERSION};
pub use model::{ModelConfig, ModelPreset, SessionCache};

/// Check if ONNX Runtime CUDA is available
#[must_use]
pub fn is_cuda_available() -> bool {
    model::SessionCache::is_cuda_available()
}

/// Get the crate version
#[must_use]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;
    use warp_compress::Compressor;

    #[test]
    fn test_version() {
        assert!(!version().is_empty());
    }

    #[test]
    fn test_fallback_compression_roundtrip() {
        // This test works even without ONNX models
        let compressor = WallocCompressor::fallback_only().unwrap();

        let data = b"Hello, World! This is a test of the neural compression system.";
        let compressed = compressor.compress(data).unwrap();
        let decompressed = compressor.decompress(&compressed).unwrap();

        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_adaptive_compression() {
        let compressor = AdaptiveNeuralCompressor::new().unwrap();

        // Text data
        let text = b"This is some text that should be compressed with lossless algorithms.";
        let compressed = compressor.compress(text).unwrap();
        let decompressed = compressor.decompress(&compressed).unwrap();
        assert_eq!(decompressed, text);
    }

    #[test]
    fn test_content_classification() {
        let classifier = ContentClassifier::new();

        // High entropy data
        let random: Vec<u8> = (0..1024).map(|i| (i * 17 + 13) as u8).collect();
        let score = classifier.analyze(&random);
        assert!(score.entropy > 0.8);

        // Uniform data
        let uniform = vec![42u8; 1024];
        let score = classifier.analyze(&uniform);
        assert!(score.entropy < 0.1);
    }

    #[test]
    fn test_header_format() {
        let flags = HeaderFlags::new(true, true);
        let header = WlocHeader::new(1000, 100, flags);

        assert_eq!(header.version, VERSION);
        assert_eq!(header.original_size, 1000);
        assert_eq!(header.compressed_size, 100);
        assert!(header.flags.gpu_compressed);
        assert!(header.flags.lossy);
    }

    #[test]
    fn test_model_config() {
        let config = ModelConfig::rgb();
        assert_eq!(config.preset, ModelPreset::Rgb16x);

        let config = ModelConfig::audio();
        assert_eq!(config.preset, ModelPreset::Stereo5x);
    }

    #[test]
    fn test_quality_config() {
        let quality = QualityConfig::high_quality();
        assert_eq!(quality.min_psnr, 40.0);

        let quality = QualityConfig::lossless();
        assert!(!quality.allow_lossy);
    }

    #[test]
    fn test_batch_compression() {
        let compressor = BatchNeuralCompressor::new().unwrap();

        let chunks: Vec<Vec<u8>> = (0..3).map(|i| vec![i as u8; 256]).collect();
        let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();

        let compressed = compressor.compress_batch(&chunk_refs).unwrap();
        assert_eq!(compressed.len(), 3);

        let compressed_refs: Vec<&[u8]> = compressed.iter().map(|c| c.as_slice()).collect();
        let decompressed = compressor.decompress_batch(&compressed_refs).unwrap();

        for (orig, dec) in chunks.iter().zip(decompressed.iter()) {
            assert_eq!(orig, dec);
        }
    }
}
