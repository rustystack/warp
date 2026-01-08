//! Tensor format readers and writers

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::{TensorError, TensorResult};
use crate::tensor::{TensorData, TensorDtype, TensorMeta};

/// Supported tensor formats
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TensorFormat {
    /// WARP native format (efficient for storage)
    WarpNative,
    /// Safetensors format (`HuggingFace`)
    Safetensors,
    /// `NumPy` .npy format
    Numpy,
    /// GGUF format (llama.cpp)
    Gguf,
    /// `PyTorch` .pt format (pickle-based, limited support)
    PyTorch,
    /// Raw binary format
    Raw,
}

impl TensorFormat {
    /// Get file extension for format
    #[must_use]
    pub fn extension(&self) -> &'static str {
        match self {
            Self::WarpNative => ".warp",
            Self::Safetensors => ".safetensors",
            Self::Numpy => ".npy",
            Self::Gguf => ".gguf",
            Self::PyTorch => ".pt",
            Self::Raw => ".bin",
        }
    }

    /// Detect format from file extension
    #[must_use]
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext.to_lowercase().as_str() {
            ".warp" | "warp" => Some(Self::WarpNative),
            ".safetensors" | "safetensors" => Some(Self::Safetensors),
            ".npy" | "npy" => Some(Self::Numpy),
            ".gguf" | "gguf" => Some(Self::Gguf),
            ".pt" | "pt" | ".pth" | "pth" => Some(Self::PyTorch),
            ".bin" | "bin" => Some(Self::Raw),
            _ => None,
        }
    }
}

/// Format reader trait
pub trait FormatReader: Send + Sync {
    /// Read tensor metadata without loading data
    ///
    /// # Errors
    ///
    /// Returns an error if the data format is invalid or corrupted.
    fn read_metadata(&self, data: &[u8]) -> TensorResult<Vec<TensorMeta>>;

    /// Read a specific tensor's data
    ///
    /// # Errors
    ///
    /// Returns an error if the tensor is not found or the data format is invalid.
    fn read_tensor(&self, data: &[u8], name: &str) -> TensorResult<TensorData>;

    /// Read all tensors
    ///
    /// # Errors
    ///
    /// Returns an error if the data format is invalid or corrupted.
    fn read_all(&self, data: &[u8]) -> TensorResult<Vec<TensorData>>;
}

/// Format writer trait
pub trait FormatWriter: Send + Sync {
    /// Write tensors to bytes
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    fn write(&self, tensors: &[TensorData]) -> TensorResult<Bytes>;

    /// Get the format
    fn format(&self) -> TensorFormat;
}

/// WARP native format header
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WarpNativeHeader {
    /// Magic bytes
    magic: [u8; 4],
    /// Version
    version: u32,
    /// Number of tensors
    num_tensors: u32,
    /// Header size (for seeking to data)
    header_size: u64,
    /// Tensor metadata
    tensors: Vec<WarpTensorEntry>,
}

/// Entry in WARP native format
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WarpTensorEntry {
    /// Tensor name
    name: String,
    /// Dtype
    dtype: TensorDtype,
    /// Shape
    shape: Vec<usize>,
    /// Offset in data section
    offset: u64,
    /// Size in bytes
    size: u64,
    /// Checksum
    checksum: String,
}

/// WARP native format reader
pub struct WarpNativeReader;

impl WarpNativeReader {
    /// Create a new reader
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for WarpNativeReader {
    fn default() -> Self {
        Self::new()
    }
}

impl FormatReader for WarpNativeReader {
    fn read_metadata(&self, data: &[u8]) -> TensorResult<Vec<TensorMeta>> {
        // Parse header
        let header = parse_warp_header(data)?;

        Ok(header
            .tensors
            .into_iter()
            .map(|entry| {
                let mut meta = TensorMeta::new(entry.name, entry.shape, entry.dtype);
                meta.checksum = Some(entry.checksum);
                meta
            })
            .collect())
    }

    fn read_tensor(&self, data: &[u8], name: &str) -> TensorResult<TensorData> {
        let header = parse_warp_header(data)?;

        let entry = header
            .tensors
            .iter()
            .find(|e| e.name == name)
            .ok_or_else(|| TensorError::TensorNotFound(name.to_string()))?;

        #[allow(clippy::cast_possible_truncation)]
        let start = header.header_size as usize + entry.offset as usize;
        #[allow(clippy::cast_possible_truncation)]
        let end = start + entry.size as usize;

        if end > data.len() {
            return Err(TensorError::DataCorrupted(
                "tensor data extends beyond file".to_string(),
            ));
        }

        let mut meta = TensorMeta::new(entry.name.clone(), entry.shape.clone(), entry.dtype);
        meta.checksum = Some(entry.checksum.clone());

        Ok(TensorData::new(
            meta,
            Bytes::copy_from_slice(&data[start..end]),
        ))
    }

    fn read_all(&self, data: &[u8]) -> TensorResult<Vec<TensorData>> {
        let header = parse_warp_header(data)?;

        let mut tensors = Vec::with_capacity(header.tensors.len());
        for entry in header.tensors {
            #[allow(clippy::cast_possible_truncation)]
            let start = header.header_size as usize + entry.offset as usize;
            #[allow(clippy::cast_possible_truncation)]
            let end = start + entry.size as usize;

            if end > data.len() {
                return Err(TensorError::DataCorrupted(
                    "tensor data extends beyond file".to_string(),
                ));
            }

            let mut meta = TensorMeta::new(entry.name, entry.shape, entry.dtype);
            meta.checksum = Some(entry.checksum);

            tensors.push(TensorData::new(
                meta,
                Bytes::copy_from_slice(&data[start..end]),
            ));
        }

        Ok(tensors)
    }
}

/// WARP native format writer
pub struct WarpNativeWriter;

impl WarpNativeWriter {
    /// Create a new writer
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for WarpNativeWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl FormatWriter for WarpNativeWriter {
    fn write(&self, tensors: &[TensorData]) -> TensorResult<Bytes> {
        let mut entries = Vec::with_capacity(tensors.len());
        let mut offset = 0u64;

        for tensor in tensors {
            let checksum = compute_checksum(&tensor.data);
            entries.push(WarpTensorEntry {
                name: tensor.meta.name.clone(),
                dtype: tensor.meta.dtype,
                shape: tensor.meta.shape.clone(),
                offset,
                size: tensor.data.len() as u64,
                checksum,
            });
            offset += tensor.data.len() as u64;
        }

        #[allow(clippy::cast_possible_truncation)]
        let header = WarpNativeHeader {
            magic: *b"WARP",
            version: 1,
            num_tensors: tensors.len() as u32,
            header_size: 0, // Will be updated after serialization
            tensors: entries,
        };

        let header_bytes =
            rmp_serde::to_vec(&header).map_err(|e| TensorError::Serialization(e.to_string()))?;

        // Create final buffer
        #[allow(clippy::cast_possible_truncation)]
        let mut buffer = Vec::with_capacity(header_bytes.len() + offset as usize);

        // Write header length (8 bytes) + header + data
        buffer.extend_from_slice(&(header_bytes.len() as u64).to_le_bytes());
        buffer.extend_from_slice(&header_bytes);

        for tensor in tensors {
            buffer.extend_from_slice(&tensor.data);
        }

        Ok(Bytes::from(buffer))
    }

    fn format(&self) -> TensorFormat {
        TensorFormat::WarpNative
    }
}

/// Parse WARP native format header
fn parse_warp_header(data: &[u8]) -> TensorResult<WarpNativeHeader> {
    if data.len() < 8 {
        return Err(TensorError::InvalidFormat(
            "file too small for header".to_string(),
        ));
    }

    #[allow(clippy::cast_possible_truncation)]
    let header_len = u64::from_le_bytes(data[0..8].try_into().unwrap()) as usize;

    if data.len() < 8 + header_len {
        return Err(TensorError::InvalidFormat(
            "file truncated before header end".to_string(),
        ));
    }

    let mut header: WarpNativeHeader = rmp_serde::from_slice(&data[8..8 + header_len])
        .map_err(|e| TensorError::Serialization(e.to_string()))?;

    header.header_size = (8 + header_len) as u64;

    if &header.magic != b"WARP" {
        return Err(TensorError::InvalidFormat(
            "invalid magic bytes".to_string(),
        ));
    }

    Ok(header)
}

/// Compute checksum for data
fn compute_checksum(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

/// Create a reader for a specific format
///
/// # Errors
///
/// Returns an error if the format is not supported or not yet implemented.
pub fn create_reader(format: TensorFormat) -> TensorResult<Box<dyn FormatReader>> {
    match format {
        TensorFormat::WarpNative => Ok(Box::new(WarpNativeReader::new())),
        TensorFormat::Safetensors => Err(TensorError::UnsupportedFormat(
            "safetensors support requires feature".to_string(),
        )),
        TensorFormat::Numpy => Err(TensorError::UnsupportedFormat(
            "numpy support not yet implemented".to_string(),
        )),
        TensorFormat::Gguf => Err(TensorError::UnsupportedFormat(
            "gguf support requires feature".to_string(),
        )),
        TensorFormat::PyTorch => Err(TensorError::UnsupportedFormat(
            "pytorch format not supported (pickle-based)".to_string(),
        )),
        TensorFormat::Raw => Err(TensorError::UnsupportedFormat(
            "raw format requires explicit metadata".to_string(),
        )),
    }
}

/// Create a writer for a specific format
///
/// # Errors
///
/// Returns an error if the format is not supported for writing.
pub fn create_writer(format: TensorFormat) -> TensorResult<Box<dyn FormatWriter>> {
    match format {
        TensorFormat::WarpNative => Ok(Box::new(WarpNativeWriter::new())),
        _ => Err(TensorError::UnsupportedFormat(format!(
            "writing {} format not supported",
            format.extension()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_extension() {
        assert_eq!(TensorFormat::WarpNative.extension(), ".warp");
        assert_eq!(TensorFormat::Safetensors.extension(), ".safetensors");
        assert_eq!(TensorFormat::Numpy.extension(), ".npy");
    }

    #[test]
    fn test_format_from_extension() {
        assert_eq!(
            TensorFormat::from_extension(".warp"),
            Some(TensorFormat::WarpNative)
        );
        assert_eq!(
            TensorFormat::from_extension("safetensors"),
            Some(TensorFormat::Safetensors)
        );
        assert_eq!(TensorFormat::from_extension(".unknown"), None);
    }

    #[test]
    fn test_warp_native_roundtrip() {
        let data1 = TensorData::from_f32("weight", vec![2, 3], &[1.0, 2.0, 3.0, 4.0, 5.0, 6.0]);
        let data2 = TensorData::from_f32("bias", vec![3], &[0.1, 0.2, 0.3]);

        let writer = WarpNativeWriter::new();
        let bytes = writer.write(&[data1.clone(), data2.clone()]).unwrap();

        let reader = WarpNativeReader::new();
        let loaded = reader.read_all(&bytes).unwrap();

        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].name(), "weight");
        assert_eq!(loaded[1].name(), "bias");

        let weight = loaded[0].as_f32().unwrap();
        assert_eq!(weight, vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0]);
    }

    #[test]
    fn test_read_single_tensor() {
        let data1 = TensorData::from_f32("weight", vec![2, 2], &[1.0, 2.0, 3.0, 4.0]);
        let data2 = TensorData::from_f32("bias", vec![2], &[0.1, 0.2]);

        let writer = WarpNativeWriter::new();
        let bytes = writer.write(&[data1, data2]).unwrap();

        let reader = WarpNativeReader::new();
        let bias = reader.read_tensor(&bytes, "bias").unwrap();

        assert_eq!(bias.name(), "bias");
        assert_eq!(bias.as_f32().unwrap(), vec![0.1, 0.2]);
    }

    #[test]
    fn test_read_metadata_only() {
        let data1 = TensorData::from_f32("layer1", vec![100, 200], &vec![0.0; 20000]);
        let data2 = TensorData::from_f64("layer2", vec![50], &vec![0.0; 50]);

        let writer = WarpNativeWriter::new();
        let bytes = writer.write(&[data1, data2]).unwrap();

        let reader = WarpNativeReader::new();
        let metadata = reader.read_metadata(&bytes).unwrap();

        assert_eq!(metadata.len(), 2);
        assert_eq!(metadata[0].name, "layer1");
        assert_eq!(metadata[0].shape, vec![100, 200]);
        assert_eq!(metadata[0].dtype, TensorDtype::Float32);
        assert_eq!(metadata[1].name, "layer2");
        assert_eq!(metadata[1].dtype, TensorDtype::Float64);
    }
}
