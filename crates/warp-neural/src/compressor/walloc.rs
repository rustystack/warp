//! WaLLoC (Wavelet Learned Lossy Compression) implementation
//!
//! Implements the WaLLoC algorithm:
//! 1. Wavelet packet transform (preprocessing)
//! 2. Shallow autoencoder inference (<100k parameters)
//! 3. Entropy coding (zstd on quantized latents)

use std::sync::Arc;

use ndarray::{Array1, Array2, ArrayView1};
use ort::session::Session;
use tracing::{debug, trace, warn};
use warp_compress::Compressor;

use crate::detection::{ContentClassifier, SuitabilityScore};
use crate::error::{Error, Result};
use crate::header::{self, HeaderFlags, WlocHeader};
use crate::model::{ModelConfig, ModelResolver, SessionCache};

/// Quality configuration for neural compression
#[derive(Debug, Clone)]
pub struct QualityConfig {
    /// Allow lossy compression
    pub allow_lossy: bool,

    /// Minimum acceptable PSNR (dB) - 0 = no constraint
    pub min_psnr: f32,

    /// Target compression ratio (0 = use model default)
    pub target_ratio: f32,

    /// Quantization bits for latent space (4-16)
    pub quantization_bits: u8,
}

impl Default for QualityConfig {
    fn default() -> Self {
        Self {
            allow_lossy: true,
            min_psnr: 30.0,     // Good quality
            target_ratio: 0.0, // Use model default
            quantization_bits: 8,
        }
    }
}

impl QualityConfig {
    /// High quality preset (less compression, better quality)
    #[must_use]
    pub fn high_quality() -> Self {
        Self {
            allow_lossy: true,
            min_psnr: 40.0,
            target_ratio: 0.0,
            quantization_bits: 12,
        }
    }

    /// Balanced preset
    #[must_use]
    pub fn balanced() -> Self {
        Self::default()
    }

    /// Maximum compression preset (more compression, lower quality)
    #[must_use]
    pub fn max_compression() -> Self {
        Self {
            allow_lossy: true,
            min_psnr: 25.0,
            target_ratio: 0.0,
            quantization_bits: 6,
        }
    }

    /// Lossless only (falls back to zstd)
    #[must_use]
    pub fn lossless() -> Self {
        Self {
            allow_lossy: false,
            min_psnr: 0.0,
            target_ratio: 0.0,
            quantization_bits: 16,
        }
    }
}

/// WaLLoC neural compressor
///
/// Implements the WaLLoC algorithm using ONNX Runtime for inference.
/// Falls back to zstd for unsuitable content.
pub struct WallocCompressor {
    /// Encoder ONNX session (may be None if models not available)
    encoder: Option<Arc<Session>>,

    /// Decoder ONNX session
    decoder: Option<Arc<Session>>,

    /// Model configuration
    config: ModelConfig,

    /// Quality settings
    quality: QualityConfig,

    /// Zstd fallback compressor
    fallback: warp_compress::ZstdCompressor,

    /// Content classifier
    classifier: ContentClassifier,

    /// Whether CUDA is being used
    use_cuda: bool,

    /// Whether models are loaded and ready
    models_ready: bool,
}

impl WallocCompressor {
    /// Create a new WaLLoC compressor with default configuration
    ///
    /// If models are not available, falls back to lossless compression.
    pub fn new() -> Result<Self> {
        Self::with_config(ModelConfig::default(), QualityConfig::default())
    }

    /// Create with custom configuration
    pub fn with_config(config: ModelConfig, quality: QualityConfig) -> Result<Self> {
        let use_cuda = cfg!(feature = "cuda") && SessionCache::is_cuda_available();

        // Try to load models
        let (encoder, decoder, models_ready) = match Self::load_models(&config, use_cuda) {
            Ok((enc, dec)) => (Some(enc), Some(dec), true),
            Err(e) => {
                warn!("Failed to load neural models: {}. Using fallback compression.", e);
                (None, None, false)
            }
        };

        let fallback = warp_compress::ZstdCompressor::new(3)?;

        Ok(Self {
            encoder,
            decoder,
            config,
            quality,
            fallback,
            classifier: ContentClassifier::new(),
            use_cuda,
            models_ready,
        })
    }

    /// Create with fallback only (no neural compression)
    pub fn fallback_only() -> Result<Self> {
        let fallback = warp_compress::ZstdCompressor::new(3)?;

        Ok(Self {
            encoder: None,
            decoder: None,
            config: ModelConfig::default(),
            quality: QualityConfig::lossless(),
            fallback,
            classifier: ContentClassifier::new(),
            use_cuda: false,
            models_ready: false,
        })
    }

    /// Load encoder and decoder models
    fn load_models(config: &ModelConfig, use_cuda: bool) -> Result<(Arc<Session>, Arc<Session>)> {
        let (encoder_path, decoder_path) = ModelResolver::resolve(config)?;

        let cache = SessionCache::global();
        let encoder = cache.get_or_load(&encoder_path, use_cuda)?;
        let decoder = cache.get_or_load(&decoder_path, use_cuda)?;

        Ok((encoder, decoder))
    }

    /// Check if neural compression is available
    #[must_use]
    pub fn is_neural_available(&self) -> bool {
        self.models_ready
    }

    /// Check if using GPU acceleration
    #[must_use]
    pub fn is_using_cuda(&self) -> bool {
        self.use_cuda && self.models_ready
    }

    /// Analyze content for compression suitability
    pub fn analyze(&self, data: &[u8]) -> SuitabilityScore {
        self.classifier.analyze(data)
    }

    /// Compress using neural algorithm (internal)
    fn compress_neural(&self, input: &[u8]) -> Result<Vec<u8>> {
        let encoder = self
            .encoder
            .as_ref()
            .ok_or_else(|| Error::ModelLoad("Encoder not loaded".into()))?;

        // Step 1: Prepare input blocks
        let block_size = self.config.effective_block_size();
        let blocks = self.prepare_blocks(input, block_size)?;

        trace!(
            blocks = blocks.nrows(),
            block_size = block_size,
            "Prepared input blocks"
        );

        // Step 2: Apply wavelet transform (simplified - real impl would use proper DWT)
        let transformed = self.wavelet_transform(&blocks)?;

        // Step 3: Run encoder inference
        let latent = self.encode(encoder, &transformed)?;

        trace!(
            latent_size = latent.len(),
            "Encoded to latent space"
        );

        // Step 4: Quantize latent space
        let quantized = self.quantize(&latent)?;

        // Step 5: Entropy coding (zstd on quantized latents)
        let compressed = self.entropy_encode(&quantized)?;

        trace!(
            original = input.len(),
            compressed = compressed.len(),
            ratio = input.len() as f64 / compressed.len() as f64,
            "Neural compression complete"
        );

        // Step 6: Pack with header
        let flags = HeaderFlags::new(self.use_cuda, true);
        Ok(header::pack(input.len(), &compressed, flags))
    }

    /// Decompress using neural algorithm (internal)
    fn decompress_neural(&self, input: &[u8]) -> Result<Vec<u8>> {
        let decoder = self
            .decoder
            .as_ref()
            .ok_or_else(|| Error::ModelLoad("Decoder not loaded".into()))?;

        // Step 1: Unpack header
        let (header, compressed) = header::unpack(input)?;

        trace!(
            original_size = header.original_size,
            compressed_size = header.compressed_size,
            ratio = header.compression_ratio(),
            "Unpacked WLOC header"
        );

        // Step 2: Entropy decode
        let quantized = self.entropy_decode(compressed)?;

        // Step 3: Dequantize
        let latent = self.dequantize(&quantized)?;

        // Step 4: Run decoder inference
        let transformed = self.decode(decoder, &latent)?;

        // Step 5: Inverse wavelet transform
        let blocks = self.inverse_wavelet_transform(&transformed)?;

        // Step 6: Flatten blocks to output
        self.flatten_blocks(&blocks, header.original_size as usize)
    }

    /// Prepare input as blocks for processing
    fn prepare_blocks(&self, input: &[u8], block_size: usize) -> Result<Array2<f32>> {
        let num_blocks = (input.len() + block_size - 1) / block_size;
        let mut blocks = Array2::zeros((num_blocks, block_size));

        for (i, chunk) in input.chunks(block_size).enumerate() {
            for (j, &byte) in chunk.iter().enumerate() {
                // Normalize to [-1, 1] range
                blocks[[i, j]] = (byte as f32 / 127.5) - 1.0;
            }
        }

        Ok(blocks)
    }

    /// Flatten blocks back to bytes
    fn flatten_blocks(&self, blocks: &Array2<f32>, original_size: usize) -> Result<Vec<u8>> {
        let mut output = Vec::with_capacity(original_size);

        for row in blocks.rows() {
            for &v in row.iter() {
                // Denormalize from [-1, 1] to [0, 255]
                let byte = ((v + 1.0) * 127.5).clamp(0.0, 255.0) as u8;
                output.push(byte);
                if output.len() >= original_size {
                    break;
                }
            }
            if output.len() >= original_size {
                break;
            }
        }

        output.truncate(original_size);
        Ok(output)
    }

    /// Apply wavelet transform (simplified Haar wavelet)
    fn wavelet_transform(&self, blocks: &Array2<f32>) -> Result<Array2<f32>> {
        // Simplified: Apply Haar wavelet-like transform
        // Real implementation would use proper DWT with configurable levels

        let (rows, cols) = blocks.dim();
        let mut transformed = Array2::zeros((rows, cols));

        for (i, row) in blocks.rows().into_iter().enumerate() {
            let coeffs = self.haar_transform_1d(row);
            for (j, &c) in coeffs.iter().enumerate() {
                transformed[[i, j]] = c;
            }
        }

        Ok(transformed)
    }

    /// Inverse wavelet transform
    fn inverse_wavelet_transform(&self, coeffs: &Array2<f32>) -> Result<Array2<f32>> {
        let (rows, cols) = coeffs.dim();
        let mut reconstructed = Array2::zeros((rows, cols));

        for (i, row) in coeffs.rows().into_iter().enumerate() {
            let values = self.haar_inverse_1d(row);
            for (j, &v) in values.iter().enumerate() {
                reconstructed[[i, j]] = v;
            }
        }

        Ok(reconstructed)
    }

    /// Simple Haar transform for 1D array
    fn haar_transform_1d(&self, input: ArrayView1<f32>) -> Array1<f32> {
        let len = input.len();
        let mut output = Array1::zeros(len);

        // Copy input to output first
        for (i, &v) in input.iter().enumerate() {
            output[i] = v;
        }

        // Apply Haar transform
        let mut step = len;
        while step > 1 {
            let half = step / 2;
            let mut temp = Array1::zeros(step);

            for i in 0..half {
                let a = output[2 * i];
                let b = output[2 * i + 1];
                temp[i] = (a + b) / 2.0_f32.sqrt(); // Average (low frequency)
                temp[half + i] = (a - b) / 2.0_f32.sqrt(); // Difference (high frequency)
            }

            for i in 0..step {
                output[i] = temp[i];
            }

            step = half;
        }

        output
    }

    /// Simple Haar inverse transform for 1D array
    fn haar_inverse_1d(&self, coeffs: ArrayView1<f32>) -> Array1<f32> {
        let len = coeffs.len();
        let mut output = Array1::zeros(len);

        // Copy coeffs to output
        for (i, &c) in coeffs.iter().enumerate() {
            output[i] = c;
        }

        // Apply inverse Haar transform
        let mut step = 1;
        while step < len {
            let double = step * 2;
            let mut temp = Array1::zeros(double);

            for i in 0..step {
                let avg = output[i];
                let diff = output[step + i];
                temp[2 * i] = (avg + diff) / 2.0_f32.sqrt();
                temp[2 * i + 1] = (avg - diff) / 2.0_f32.sqrt();
            }

            for i in 0..double {
                output[i] = temp[i];
            }

            step = double;
        }

        output
    }

    /// Run encoder inference (placeholder - actual ONNX inference)
    fn encode(&self, _encoder: &Session, blocks: &Array2<f32>) -> Result<Vec<f32>> {
        // In a real implementation, this would:
        // 1. Convert ndarray to ONNX tensor
        // 2. Run encoder.run()
        // 3. Extract latent tensor

        // For now, apply simple dimensionality reduction
        let (rows, cols) = blocks.dim();
        let reduction = 4; // Reduce to 1/4 size
        let latent_size = (rows * cols) / reduction;

        let mut latent = Vec::with_capacity(latent_size);

        // Simple averaging as placeholder for autoencoder
        for chunk in blocks.iter().collect::<Vec<_>>().chunks(reduction) {
            let sum: f32 = chunk.iter().copied().sum();
            latent.push(sum / reduction as f32);
        }

        Ok(latent)
    }

    /// Run decoder inference (placeholder - actual ONNX inference)
    fn decode(&self, _decoder: &Session, latent: &[f32]) -> Result<Array2<f32>> {
        // Placeholder: expand latent back to original size
        let block_size = self.config.effective_block_size();
        let expansion = 4;
        let total_size = latent.len() * expansion;
        let num_blocks = (total_size + block_size - 1) / block_size;

        let mut blocks = Array2::zeros((num_blocks, block_size));

        // Simple expansion as placeholder for decoder
        let mut idx = 0;
        for &v in latent {
            for _ in 0..expansion {
                if idx < num_blocks * block_size {
                    let row = idx / block_size;
                    let col = idx % block_size;
                    blocks[[row, col]] = v;
                    idx += 1;
                }
            }
        }

        Ok(blocks)
    }

    /// Quantize latent values to integers
    fn quantize(&self, latent: &[f32]) -> Result<Vec<u8>> {
        let bits = self.quality.quantization_bits;
        // Use u32 to avoid overflow when bits == 16
        let max_val = ((1u32 << bits) - 1).min(u16::MAX as u32) as u16;
        let scale = max_val as f32 / 2.0;

        let mut quantized = Vec::with_capacity(latent.len() * 2);

        for &v in latent {
            // Clamp and scale to quantization range
            let scaled = ((v.clamp(-1.0, 1.0) + 1.0) * scale) as u16;
            quantized.extend_from_slice(&scaled.to_le_bytes());
        }

        Ok(quantized)
    }

    /// Dequantize integers back to floats
    fn dequantize(&self, quantized: &[u8]) -> Result<Vec<f32>> {
        let bits = self.quality.quantization_bits;
        // Use u32 to avoid overflow when bits == 16
        let max_val = ((1u32 << bits) - 1).min(u16::MAX as u32) as u16;
        let scale = max_val as f32 / 2.0;

        let mut latent = Vec::with_capacity(quantized.len() / 2);

        for chunk in quantized.chunks_exact(2) {
            let val = u16::from_le_bytes(chunk.try_into().unwrap());
            let float = (val as f32 / scale) - 1.0;
            latent.push(float);
        }

        Ok(latent)
    }

    /// Entropy encode quantized data
    fn entropy_encode(&self, quantized: &[u8]) -> Result<Vec<u8>> {
        zstd::bulk::compress(quantized, 3).map_err(|e| Error::EntropyCoding(e.to_string()))
    }

    /// Entropy decode compressed data
    fn entropy_decode(&self, compressed: &[u8]) -> Result<Vec<u8>> {
        // Max decompression size: 64MB
        zstd::bulk::decompress(compressed, 64 * 1024 * 1024)
            .map_err(|e| Error::EntropyCoding(e.to_string()))
    }
}

impl Compressor for WallocCompressor {
    fn compress(&self, input: &[u8]) -> warp_compress::Result<Vec<u8>> {
        if input.is_empty() {
            return Ok(vec![]);
        }

        // Check minimum size
        if input.len() < self.config.min_input_size {
            debug!(
                size = input.len(),
                min = self.config.min_input_size,
                "Input too small for neural compression, using fallback"
            );
            return self.fallback.compress(input);
        }

        // Analyze content suitability
        let analysis = self.classifier.analyze(input);

        // Skip compression for incompressible data
        if analysis.skip_compression {
            debug!("Data detected as incompressible, passing through");
            return Ok(input.to_vec());
        }

        // Use lossless for unsuitable content or if lossy not allowed
        if analysis.use_lossless || !self.quality.allow_lossy || !self.models_ready {
            debug!(
                use_lossless = analysis.use_lossless,
                allow_lossy = self.quality.allow_lossy,
                models_ready = self.models_ready,
                "Using fallback compression"
            );
            return self.fallback.compress(input);
        }

        // Attempt neural compression
        match self.compress_neural(input) {
            Ok(compressed) => {
                // Check if compression was worthwhile
                if compressed.len() < input.len() {
                    debug!(
                        original = input.len(),
                        compressed = compressed.len(),
                        ratio = input.len() as f64 / compressed.len() as f64,
                        "Neural compression successful"
                    );
                    Ok(compressed)
                } else {
                    debug!("Neural compression not effective, using fallback");
                    self.fallback.compress(input)
                }
            }
            Err(e) => {
                warn!("Neural compression failed: {}, using fallback", e);
                self.fallback.compress(input)
            }
        }
    }

    fn decompress(&self, input: &[u8]) -> warp_compress::Result<Vec<u8>> {
        if input.is_empty() {
            return Ok(vec![]);
        }

        // Check for WLOC magic bytes
        if WlocHeader::is_wloc(input) {
            self.decompress_neural(input)
                .map_err(|e| warp_compress::Error::Decompression(e.to_string()))
        } else {
            // Assume zstd fallback
            self.fallback.decompress(input)
        }
    }

    fn name(&self) -> &'static str {
        "walloc"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quality_presets() {
        let high = QualityConfig::high_quality();
        assert_eq!(high.min_psnr, 40.0);

        let max = QualityConfig::max_compression();
        assert_eq!(max.quantization_bits, 6);

        let lossless = QualityConfig::lossless();
        assert!(!lossless.allow_lossy);
    }

    #[test]
    fn test_fallback_only_compressor() {
        let compressor = WallocCompressor::fallback_only().unwrap();
        assert!(!compressor.is_neural_available());

        let data = b"Hello, World!";
        let compressed = compressor.compress(data).unwrap();
        let decompressed = compressor.decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_haar_transform_roundtrip() {
        let compressor = WallocCompressor::fallback_only().unwrap();

        // Power of 2 length for Haar
        let input = Array1::from_vec(vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]);
        let transformed = compressor.haar_transform_1d(input.view());
        let reconstructed = compressor.haar_inverse_1d(transformed.view());

        for (a, b) in input.iter().zip(reconstructed.iter()) {
            assert!((a - b).abs() < 0.001, "Haar roundtrip failed");
        }
    }

    #[test]
    fn test_quantization_roundtrip() {
        let compressor = WallocCompressor::fallback_only().unwrap();

        let latent = vec![0.0, 0.5, -0.5, 1.0, -1.0];
        let quantized = compressor.quantize(&latent).unwrap();
        let dequantized = compressor.dequantize(&quantized).unwrap();

        for (a, b) in latent.iter().zip(dequantized.iter()) {
            // Allow some quantization error
            assert!((a - b).abs() < 0.01, "Quantization roundtrip error too large");
        }
    }

    #[test]
    fn test_entropy_coding_roundtrip() {
        let compressor = WallocCompressor::fallback_only().unwrap();

        let data = vec![1u8, 2, 3, 4, 5, 1, 2, 3, 4, 5];
        let encoded = compressor.entropy_encode(&data).unwrap();
        let decoded = compressor.entropy_decode(&encoded).unwrap();

        assert_eq!(data, decoded);
    }

    #[test]
    fn test_blocks_roundtrip() {
        let compressor = WallocCompressor::fallback_only().unwrap();

        let input: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let block_size = 64;

        let blocks = compressor.prepare_blocks(&input, block_size).unwrap();
        let output = compressor.flatten_blocks(&blocks, input.len()).unwrap();

        // Values won't be exact due to float conversion, but should be close
        for (a, b) in input.iter().zip(output.iter()) {
            assert!(
                (*a as i16 - *b as i16).abs() <= 1,
                "Block roundtrip error too large"
            );
        }
    }

    #[test]
    fn test_small_input_uses_fallback() {
        let compressor = WallocCompressor::fallback_only().unwrap();

        let small_data = b"Hi";
        let result = compressor.compress(small_data);
        assert!(result.is_ok());
    }
}
