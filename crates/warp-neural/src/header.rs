//! WLOC header format for neural compressed data
//!
//! Header structure (22 bytes):
//! ```text
//! ┌──────────┬─────────┬───────┬────────────┬───────────┐
//! │ Magic    │ Version │ Flags │ Orig Size  │ Comp Size │
//! │ 4 bytes  │ 1 byte  │ 1 byte│ 8 bytes    │ 8 bytes   │
//! │ "WLOC"   │ 0x01    │ bits  │ u64 LE     │ u64 LE    │
//! └──────────┴─────────┴───────┴────────────┴───────────┘
//! ```

use crate::error::{Error, Result};

/// WLOC magic bytes
pub const MAGIC: [u8; 4] = *b"WLOC";

/// Current format version
pub const VERSION: u8 = 1;

/// Header size in bytes
pub const HEADER_SIZE: usize = 22;

/// Header flags
#[derive(Debug, Clone, Copy, Default)]
pub struct HeaderFlags {
    /// Data was compressed using GPU
    pub gpu_compressed: bool,
    /// Lossy compression was used
    pub lossy: bool,
    /// Reserved for future use
    _reserved: u8,
}

impl HeaderFlags {
    /// Create new flags
    #[must_use]
    pub fn new(gpu_compressed: bool, lossy: bool) -> Self {
        Self {
            gpu_compressed,
            lossy,
            _reserved: 0,
        }
    }

    /// Encode flags to a byte
    #[must_use]
    pub fn to_byte(&self) -> u8 {
        let mut flags = 0u8;
        if self.gpu_compressed {
            flags |= 0x01;
        }
        if self.lossy {
            flags |= 0x02;
        }
        flags
    }

    /// Decode flags from a byte
    #[must_use]
    pub fn from_byte(byte: u8) -> Self {
        Self {
            gpu_compressed: byte & 0x01 != 0,
            lossy: byte & 0x02 != 0,
            _reserved: byte & 0xFC,
        }
    }
}

/// WLOC header for neural compressed data
#[derive(Debug, Clone)]
pub struct WlocHeader {
    /// Format version
    pub version: u8,
    /// Header flags
    pub flags: HeaderFlags,
    /// Original uncompressed size
    pub original_size: u64,
    /// Compressed data size (excluding header)
    pub compressed_size: u64,
}

impl WlocHeader {
    /// Create a new header
    #[must_use]
    pub fn new(original_size: u64, compressed_size: u64, flags: HeaderFlags) -> Self {
        Self {
            version: VERSION,
            flags,
            original_size,
            compressed_size,
        }
    }

    /// Serialize header to bytes
    #[must_use]
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut header = [0u8; HEADER_SIZE];

        // Magic bytes
        header[0..4].copy_from_slice(&MAGIC);

        // Version
        header[4] = self.version;

        // Flags
        header[5] = self.flags.to_byte();

        // Original size (little endian)
        header[6..14].copy_from_slice(&self.original_size.to_le_bytes());

        // Compressed size (little endian)
        header[14..22].copy_from_slice(&self.compressed_size.to_le_bytes());

        header
    }

    /// Parse header from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < HEADER_SIZE {
            return Err(Error::InvalidHeader(format!(
                "Data too short: {} bytes (need {})",
                data.len(),
                HEADER_SIZE
            )));
        }

        // Check magic
        if &data[0..4] != &MAGIC {
            return Err(Error::InvalidHeader(format!(
                "Invalid magic bytes: {:02X?}",
                &data[0..4]
            )));
        }

        // Version
        let version = data[4];
        if version > VERSION {
            return Err(Error::InvalidHeader(format!(
                "Unsupported version: {} (max: {})",
                version, VERSION
            )));
        }

        // Flags
        let flags = HeaderFlags::from_byte(data[5]);

        // Original size
        let original_size = u64::from_le_bytes(data[6..14].try_into().unwrap());

        // Compressed size
        let compressed_size = u64::from_le_bytes(data[14..22].try_into().unwrap());

        Ok(Self {
            version,
            flags,
            original_size,
            compressed_size,
        })
    }

    /// Check if data starts with WLOC magic bytes
    #[must_use]
    pub fn is_wloc(data: &[u8]) -> bool {
        data.len() >= 4 && &data[0..4] == &MAGIC
    }

    /// Get the compression ratio
    #[must_use]
    pub fn compression_ratio(&self) -> f64 {
        if self.compressed_size == 0 {
            0.0
        } else {
            self.original_size as f64 / self.compressed_size as f64
        }
    }
}

/// Pack data with WLOC header
pub fn pack(original_size: usize, compressed: &[u8], flags: HeaderFlags) -> Vec<u8> {
    let header = WlocHeader::new(original_size as u64, compressed.len() as u64, flags);
    let header_bytes = header.to_bytes();

    let mut output = Vec::with_capacity(HEADER_SIZE + compressed.len());
    output.extend_from_slice(&header_bytes);
    output.extend_from_slice(compressed);
    output
}

/// Unpack WLOC data, returns (header, compressed_data)
pub fn unpack(data: &[u8]) -> Result<(WlocHeader, &[u8])> {
    let header = WlocHeader::from_bytes(data)?;

    let data_start = HEADER_SIZE;
    let data_end = data_start + header.compressed_size as usize;

    if data.len() < data_end {
        return Err(Error::InvalidHeader(format!(
            "Data truncated: have {} bytes, need {}",
            data.len(),
            data_end
        )));
    }

    Ok((header, &data[data_start..data_end]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_roundtrip() {
        let flags = HeaderFlags::new(true, true);
        let header = WlocHeader::new(1000, 500, flags);

        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), HEADER_SIZE);

        let parsed = WlocHeader::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.version, VERSION);
        assert_eq!(parsed.original_size, 1000);
        assert_eq!(parsed.compressed_size, 500);
        assert!(parsed.flags.gpu_compressed);
        assert!(parsed.flags.lossy);
    }

    #[test]
    fn test_magic_detection() {
        let data = [b'W', b'L', b'O', b'C', 0, 0, 0, 0];
        assert!(WlocHeader::is_wloc(&data));

        let other = [0u8; 8];
        assert!(!WlocHeader::is_wloc(&other));
    }

    #[test]
    fn test_flags() {
        let flags = HeaderFlags::new(true, false);
        let byte = flags.to_byte();
        assert_eq!(byte, 0x01);

        let parsed = HeaderFlags::from_byte(byte);
        assert!(parsed.gpu_compressed);
        assert!(!parsed.lossy);
    }

    #[test]
    fn test_pack_unpack() {
        let original_size = 1024;
        let compressed = vec![1u8, 2, 3, 4, 5];
        let flags = HeaderFlags::new(false, true);

        let packed = pack(original_size, &compressed, flags);
        assert_eq!(packed.len(), HEADER_SIZE + compressed.len());

        let (header, data) = unpack(&packed).unwrap();
        assert_eq!(header.original_size, original_size as u64);
        assert_eq!(data, &compressed[..]);
    }

    #[test]
    fn test_compression_ratio() {
        let header = WlocHeader::new(1000, 100, HeaderFlags::default());
        assert!((header.compression_ratio() - 10.0).abs() < 0.01);
    }

    #[test]
    fn test_invalid_magic() {
        let data = [0u8; 22];
        let result = WlocHeader::from_bytes(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_truncated_data() {
        let data = [b'W', b'L', b'O', b'C'];
        let result = WlocHeader::from_bytes(&data);
        assert!(result.is_err());
    }
}
