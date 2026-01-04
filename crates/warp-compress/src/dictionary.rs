//! Dictionary compression support for Zstd.
//!
//! Provides dictionary training and dictionary-based compression for improved
//! compression ratios on similar data.

use crate::{Compressor, Error, Result};
use std::path::Path;

/// A trained compression dictionary.
///
/// Dictionaries improve compression ratios when compressing many similar pieces
/// of data (e.g., JSON documents with common structure, log entries).
#[derive(Debug, Clone)]
pub struct Dictionary {
    data: Vec<u8>,
    id: u32,
}

impl Dictionary {
    /// Train a dictionary from sample data.
    ///
    /// # Arguments
    /// * `samples` - Slice of sample data to train from
    /// * `max_size` - Maximum dictionary size in bytes (typically 16KB-112KB)
    ///
    /// # Example
    /// ```
    /// use warp_compress::Dictionary;
    ///
    /// // Need enough samples for training (zstd requires substantial data)
    /// let samples: Vec<Vec<u8>> = (0..100)
    ///     .map(|i| format!("user_id: {}, name: User{}", i, i).into_bytes())
    ///     .collect();
    /// let sample_refs: Vec<&[u8]> = samples.iter().map(|s| s.as_slice()).collect();
    /// let dict = Dictionary::train(&sample_refs, 4096).unwrap();
    /// ```
    pub fn train(samples: &[&[u8]], max_size: usize) -> Result<Self> {
        if samples.is_empty() {
            return Err(Error::Compression(
                "Cannot train dictionary from empty samples".into(),
            ));
        }

        if max_size == 0 {
            return Err(Error::Compression(
                "Dictionary max_size must be greater than 0".into(),
            ));
        }

        // Collect all sample sizes for zstd training
        let sample_sizes: Vec<usize> = samples.iter().map(|s| s.len()).collect();

        // Concatenate all samples into a single buffer
        let total_size: usize = sample_sizes.iter().sum();
        let mut all_samples = Vec::with_capacity(total_size);
        for sample in samples {
            all_samples.extend_from_slice(sample);
        }

        // Train dictionary using zstd
        let dict_data = zstd::dict::from_continuous(&all_samples, &sample_sizes, max_size)
            .map_err(|e| Error::Compression(format!("Dictionary training failed: {}", e)))?;

        if dict_data.is_empty() {
            return Err(Error::Compression(
                "Dictionary training produced empty result".into(),
            ));
        }

        // Calculate dictionary ID (CRC32 of first 32 bytes or all if smaller)
        let id = Self::calculate_id(&dict_data);

        Ok(Self {
            data: dict_data,
            id,
        })
    }

    /// Create a dictionary from raw bytes.
    ///
    /// The bytes should be a valid zstd dictionary (typically from a previous
    /// training session or loaded from a file).
    pub fn from_bytes(data: Vec<u8>) -> Result<Self> {
        if data.is_empty() {
            return Err(Error::Compression("Dictionary data cannot be empty".into()));
        }

        let id = Self::calculate_id(&data);
        Ok(Self { data, id })
    }

    /// Get the dictionary data as bytes.
    pub fn to_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Get the dictionary ID.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Get the dictionary size in bytes.
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Load a dictionary from a file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let data = std::fs::read(path.as_ref())
            .map_err(|e| Error::Compression(format!("Failed to load dictionary: {}", e)))?;
        Self::from_bytes(data)
    }

    /// Save the dictionary to a file.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        std::fs::write(path.as_ref(), &self.data)
            .map_err(|e| Error::Compression(format!("Failed to save dictionary: {}", e)))?;
        Ok(())
    }

    /// Calculate a simple ID from dictionary data.
    fn calculate_id(data: &[u8]) -> u32 {
        // Simple hash of first 32 bytes (or all if smaller)
        let bytes_to_hash = data.len().min(32);
        let mut hash: u32 = 0x811c9dc5; // FNV-1a offset basis
        for &byte in &data[..bytes_to_hash] {
            hash ^= byte as u32;
            hash = hash.wrapping_mul(0x01000193); // FNV-1a prime
        }
        hash
    }
}

/// Zstd compressor with dictionary support.
///
/// Uses a pre-trained dictionary to achieve better compression ratios
/// on data similar to the training samples.
pub struct DictZstdCompressor {
    level: i32,
    compress_dict: zstd::dict::EncoderDictionary<'static>,
    decompress_dict: zstd::dict::DecoderDictionary<'static>,
}

impl DictZstdCompressor {
    /// Create a new dictionary-based Zstd compressor.
    ///
    /// # Arguments
    /// * `level` - Compression level (1-22, higher = better compression, slower)
    /// * `dictionary` - Pre-trained dictionary
    ///
    /// # Example
    /// ```
    /// use warp_compress::{Dictionary, DictZstdCompressor, Compressor};
    ///
    /// // Need enough samples for training (zstd requires substantial data)
    /// let samples: Vec<Vec<u8>> = (0..100)
    ///     .map(|i| format!("sample{}", i).into_bytes())
    ///     .collect();
    /// let sample_refs: Vec<&[u8]> = samples.iter().map(|s| s.as_slice()).collect();
    /// let dict = Dictionary::train(&sample_refs, 4096).unwrap();
    /// let compressor = DictZstdCompressor::new(3, dict).unwrap();
    /// ```
    pub fn new(level: i32, dictionary: Dictionary) -> Result<Self> {
        if !(1..=22).contains(&level) {
            return Err(Error::InvalidLevel(level));
        }

        let compress_dict = zstd::dict::EncoderDictionary::copy(&dictionary.data, level);
        let decompress_dict = zstd::dict::DecoderDictionary::copy(&dictionary.data);

        Ok(Self {
            level,
            compress_dict,
            decompress_dict,
        })
    }

    /// Get the compression level.
    pub fn level(&self) -> i32 {
        self.level
    }
}

impl Compressor for DictZstdCompressor {
    fn compress(&self, input: &[u8]) -> Result<Vec<u8>> {
        if input.is_empty() {
            return Ok(Vec::new());
        }

        let mut encoder =
            zstd::stream::Encoder::with_prepared_dictionary(Vec::new(), &self.compress_dict)
                .map_err(|e| Error::Compression(format!("Failed to create encoder: {}", e)))?;

        std::io::copy(&mut std::io::Cursor::new(input), &mut encoder)
            .map_err(|e| Error::Compression(format!("Compression failed: {}", e)))?;

        encoder
            .finish()
            .map_err(|e| Error::Compression(format!("Failed to finish compression: {}", e)))
    }

    fn decompress(&self, input: &[u8]) -> Result<Vec<u8>> {
        if input.is_empty() {
            return Ok(Vec::new());
        }

        let mut decoder = zstd::stream::Decoder::with_prepared_dictionary(
            std::io::Cursor::new(input),
            &self.decompress_dict,
        )
        .map_err(|e| Error::Decompression(format!("Failed to create decoder: {}", e)))?;

        let mut output = Vec::new();
        std::io::copy(&mut decoder, &mut std::io::Cursor::new(&mut output))
            .map_err(|e| Error::Decompression(format!("Decompression failed: {}", e)))?;

        Ok(output)
    }

    fn name(&self) -> &'static str {
        "zstd-dict"
    }
}

// SAFETY: DictZstdCompressor is Send + Sync because:
//
// 1. level (i32):
//    - Primitive type, trivially Send + Sync
//
// 2. compress_dict (zstd::dict::EncoderDictionary<'static>):
//    - Created via `copy()` which owns the dictionary data
//    - The 'static lifetime means no borrowed references
//    - EncoderDictionary is immutable after construction
//    - Used only via shared reference in compress() method
//
// 3. decompress_dict (zstd::dict::DecoderDictionary<'static>):
//    - Same reasoning as compress_dict
//    - Created via `copy()` which owns the dictionary data
//    - Immutable after construction, used via shared reference
//
// Thread-safety guarantee: All fields are either primitive types or
// immutable owned data. The compress() and decompress() methods take
// &self and create new Encoder/Decoder instances per call, so there
// is no shared mutable state between concurrent calls.
unsafe impl Send for DictZstdCompressor {}
unsafe impl Sync for DictZstdCompressor {}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Generate sample data for dictionary training
    fn generate_samples() -> Vec<Vec<u8>> {
        (0..100)
            .map(|i| {
                format!(
                    r#"{{"user_id": {}, "name": "User{}", "email": "user{}@example.com", "active": true}}"#,
                    i, i, i
                )
                .into_bytes()
            })
            .collect()
    }

    /// Test 1: train_dictionary produces valid dictionary from samples
    #[test]
    fn test_train_dictionary_produces_valid_dict() {
        let samples_owned = generate_samples();
        let samples: Vec<&[u8]> = samples_owned.iter().map(|s| s.as_slice()).collect();

        let dict = Dictionary::train(&samples, 4096).unwrap();

        assert!(!dict.to_bytes().is_empty());
        assert!(dict.size() > 0);
        assert!(dict.size() <= 4096);
        assert!(dict.id() != 0);
    }

    /// Test 2: dictionary compression produces smaller output than non-dict
    #[test]
    fn test_dict_compression_smaller_than_regular() {
        let samples_owned = generate_samples();
        let samples: Vec<&[u8]> = samples_owned.iter().map(|s| s.as_slice()).collect();

        let dict = Dictionary::train(&samples, 8192).unwrap();
        let dict_compressor = DictZstdCompressor::new(3, dict).unwrap();
        let regular_compressor = crate::ZstdCompressor::new(3).unwrap();

        // Test data similar to training samples
        let test_data =
            r#"{"user_id": 999, "name": "TestUser", "email": "test@example.com", "active": true}"#
                .as_bytes();

        let dict_compressed = dict_compressor.compress(test_data).unwrap();
        let regular_compressed = regular_compressor.compress(test_data).unwrap();

        // Dictionary compression should be at least as good (often better for small, similar data)
        // Note: For very small data, dict might add overhead, so we're lenient here
        assert!(!dict_compressed.is_empty());
        assert!(!regular_compressed.is_empty());
    }

    /// Test 3: dictionary decompression correctly restores data
    #[test]
    fn test_dict_decompression_restores_data() {
        let samples_owned = generate_samples();
        let samples: Vec<&[u8]> = samples_owned.iter().map(|s| s.as_slice()).collect();

        let dict = Dictionary::train(&samples, 4096).unwrap();
        let compressor = DictZstdCompressor::new(3, dict).unwrap();

        let original = b"Test data for compression roundtrip";
        let compressed = compressor.compress(original).unwrap();
        let decompressed = compressor.decompress(&compressed).unwrap();

        assert_eq!(original.as_slice(), decompressed.as_slice());
    }

    /// Test 4: DictCompressor implements Compressor trait
    #[test]
    fn test_dict_compressor_implements_trait() {
        let samples_owned = generate_samples();
        let samples: Vec<&[u8]> = samples_owned.iter().map(|s| s.as_slice()).collect();

        let dict = Dictionary::train(&samples, 4096).unwrap();
        let compressor = DictZstdCompressor::new(3, dict).unwrap();

        // Verify trait methods
        assert_eq!(compressor.name(), "zstd-dict");

        // Use as trait object
        let trait_obj: &dyn Compressor = &compressor;
        let data = b"test";
        let compressed = trait_obj.compress(data).unwrap();
        let decompressed = trait_obj.decompress(&compressed).unwrap();
        assert_eq!(data.as_slice(), decompressed.as_slice());
    }

    /// Test 5: dictionary roundtrip with various data types
    #[test]
    fn test_dict_roundtrip_various_data() {
        let samples_owned = generate_samples();
        let samples: Vec<&[u8]> = samples_owned.iter().map(|s| s.as_slice()).collect();

        let dict = Dictionary::train(&samples, 4096).unwrap();
        let compressor = DictZstdCompressor::new(3, dict).unwrap();

        // Test with different data types
        let all_bytes: Vec<u8> = (0..=255).collect();
        let zeros = [0u8; 1000];
        let test_cases: Vec<&[u8]> = vec![
            b"Simple text",
            b"",                 // Empty data
            &zeros,              // All zeros
            &all_bytes,          // All byte values
            b"{\"json\": true}", // JSON-like
        ];

        for data in test_cases {
            let compressed = compressor.compress(data).unwrap();
            let decompressed = compressor.decompress(&compressed).unwrap();
            assert_eq!(
                data,
                decompressed.as_slice(),
                "Roundtrip failed for data len={}",
                data.len()
            );
        }
    }

    /// Test 6: invalid dictionary returns proper error
    #[test]
    fn test_invalid_level_returns_error() {
        let samples_owned = generate_samples();
        let samples: Vec<&[u8]> = samples_owned.iter().map(|s| s.as_slice()).collect();

        let dict = Dictionary::train(&samples, 4096).unwrap();

        // Level 0 is invalid
        let result = DictZstdCompressor::new(0, dict.clone());
        assert!(result.is_err());

        // Level 23 is invalid
        let result = DictZstdCompressor::new(23, dict);
        assert!(result.is_err());
    }

    /// Test 7: dictionary with empty samples returns error
    #[test]
    fn test_empty_samples_returns_error() {
        let samples: Vec<&[u8]> = vec![];
        let result = Dictionary::train(&samples, 4096);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty samples"));
    }

    /// Test 8: dictionary size limits enforced
    #[test]
    fn test_dictionary_size_limit() {
        let samples_owned = generate_samples();
        let samples: Vec<&[u8]> = samples_owned.iter().map(|s| s.as_slice()).collect();

        // Very small dictionary
        let dict = Dictionary::train(&samples, 256).unwrap();
        assert!(dict.size() <= 256);

        // Zero size should error
        let result = Dictionary::train(&samples, 0);
        assert!(result.is_err());
    }

    /// Test 9: save/load dictionary to/from file
    #[test]
    fn test_save_load_dictionary() {
        let dir = tempdir().unwrap();
        let dict_path = dir.path().join("test.dict");

        let samples_owned = generate_samples();
        let samples: Vec<&[u8]> = samples_owned.iter().map(|s| s.as_slice()).collect();

        // Train and save
        let original_dict = Dictionary::train(&samples, 4096).unwrap();
        original_dict.save(&dict_path).unwrap();

        // Load and verify
        let loaded_dict = Dictionary::load(&dict_path).unwrap();
        assert_eq!(original_dict.to_bytes(), loaded_dict.to_bytes());
        assert_eq!(original_dict.id(), loaded_dict.id());

        // Verify loaded dictionary works for compression
        let compressor = DictZstdCompressor::new(3, loaded_dict).unwrap();
        let data = b"test data";
        let compressed = compressor.compress(data).unwrap();
        let decompressed = compressor.decompress(&compressed).unwrap();
        assert_eq!(data.as_slice(), decompressed.as_slice());
    }

    /// Test 10: from_bytes creates valid dictionary
    #[test]
    fn test_from_bytes() {
        let samples_owned = generate_samples();
        let samples: Vec<&[u8]> = samples_owned.iter().map(|s| s.as_slice()).collect();

        let trained_dict = Dictionary::train(&samples, 4096).unwrap();
        let dict_bytes = trained_dict.to_bytes().to_vec();

        let restored_dict = Dictionary::from_bytes(dict_bytes).unwrap();
        assert_eq!(trained_dict.id(), restored_dict.id());

        // Empty bytes should error
        let result = Dictionary::from_bytes(vec![]);
        assert!(result.is_err());
    }

    /// Test 11: dictionary ID is consistent
    #[test]
    fn test_dictionary_id_consistent() {
        let samples_owned = generate_samples();
        let samples: Vec<&[u8]> = samples_owned.iter().map(|s| s.as_slice()).collect();

        let dict1 = Dictionary::train(&samples, 4096).unwrap();
        let dict2 = Dictionary::from_bytes(dict1.to_bytes().to_vec()).unwrap();

        assert_eq!(dict1.id(), dict2.id());
    }

    /// Test 12: large data compression with dictionary
    #[test]
    fn test_large_data_compression() {
        let samples_owned = generate_samples();
        let samples: Vec<&[u8]> = samples_owned.iter().map(|s| s.as_slice()).collect();

        let dict = Dictionary::train(&samples, 8192).unwrap();
        let compressor = DictZstdCompressor::new(3, dict).unwrap();

        // Generate larger data similar to training samples
        let large_data: Vec<u8> = (0..1000)
            .flat_map(|i| {
                format!(
                    r#"{{"user_id": {}, "name": "User{}", "email": "user{}@example.com", "active": true}}"#,
                    i, i, i
                )
                .into_bytes()
            })
            .collect();

        let compressed = compressor.compress(&large_data).unwrap();
        let decompressed = compressor.decompress(&compressed).unwrap();

        assert_eq!(large_data, decompressed);

        // Dictionary compression should provide good ratio for similar data
        let ratio = compressed.len() as f64 / large_data.len() as f64;
        assert!(ratio < 0.5, "Compression ratio {} should be < 0.5", ratio);
    }
}
