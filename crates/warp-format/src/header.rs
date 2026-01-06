//! Warp file header (256 bytes, fixed)

use crate::{Error, Result};

/// Magic bytes: "WARP"
pub const MAGIC: [u8; 4] = *b"WARP";

/// Current format version
pub const VERSION: u32 = 1;

/// Header size in bytes
pub const HEADER_SIZE: usize = 256;

/// Header flags
pub mod flags {
    /// Content is encrypted
    pub const ENCRYPTED: u64 = 1 << 0;
    /// Archive is signed
    pub const SIGNED: u64 = 1 << 1;
    /// Created in streaming mode
    pub const STREAMING: u64 = 1 << 2;
}

/// Compression algorithm identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Compression {
    /// No compression
    None = 0,
    /// Zstandard
    Zstd = 1,
    /// LZ4
    Lz4 = 2,
}

/// Encryption algorithm identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Encryption {
    /// No encryption
    None = 0,
    /// ChaCha20-Poly1305
    ChaCha20Poly1305 = 1,
}

/// Warp file header
#[derive(Debug, Clone)]
pub struct Header {
    /// Magic bytes (must be "WARP")
    pub magic: [u8; 4],
    /// Format version
    pub version: u32,
    /// Header flags
    pub flags: u64,
    /// Hint for chunk size used
    pub chunk_size_hint: u32,
    /// Compression algorithm
    pub compression: Compression,
    /// Encryption algorithm
    pub encryption: Encryption,
    /// Offset to metadata block
    pub metadata_offset: u64,
    /// Size of metadata block
    pub metadata_size: u64,
    /// Offset to chunk index
    pub index_offset: u64,
    /// Size of chunk index
    pub index_size: u64,
    /// Offset to file table
    pub file_table_offset: u64,
    /// Size of file table
    pub file_table_size: u64,
    /// Offset to data blocks
    pub data_offset: u64,
    /// Merkle root hash (32 bytes)
    pub merkle_root: [u8; 32],
    /// Total number of chunks
    pub total_chunks: u64,
    /// Total number of files
    pub total_files: u64,
    /// Original (uncompressed) size
    pub original_size: u64,
    /// Compressed size
    pub compressed_size: u64,
    /// Salt for key derivation (16 bytes)
    pub salt: [u8; 16],
}

impl Header {
    /// Create a new header with defaults
    pub fn new() -> Self {
        Self {
            magic: MAGIC,
            version: VERSION,
            flags: 0,
            chunk_size_hint: 4 * 1024 * 1024, // 4MB
            compression: Compression::Zstd,
            encryption: Encryption::None,
            metadata_offset: 0,
            metadata_size: 0,
            index_offset: 0,
            index_size: 0,
            file_table_offset: 0,
            file_table_size: 0,
            data_offset: 0,
            merkle_root: [0u8; 32],
            total_chunks: 0,
            total_files: 0,
            original_size: 0,
            compressed_size: 0,
            salt: [0u8; 16],
        }
    }

    /// Validate header
    pub fn validate(&self) -> Result<()> {
        if self.magic != MAGIC {
            return Err(Error::InvalidMagic);
        }
        if self.version > VERSION {
            return Err(Error::UnsupportedVersion(self.version));
        }
        Ok(())
    }

    /// Serialize header to bytes
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];

        buf[0..4].copy_from_slice(&self.magic);
        buf[4..8].copy_from_slice(&self.version.to_le_bytes());
        buf[8..16].copy_from_slice(&self.flags.to_le_bytes());
        buf[16..20].copy_from_slice(&self.chunk_size_hint.to_le_bytes());
        buf[20] = self.compression as u8;
        buf[21] = self.encryption as u8;
        // bytes 22-23 reserved
        buf[24..32].copy_from_slice(&self.metadata_offset.to_le_bytes());
        buf[32..40].copy_from_slice(&self.metadata_size.to_le_bytes());
        buf[40..48].copy_from_slice(&self.index_offset.to_le_bytes());
        buf[48..56].copy_from_slice(&self.index_size.to_le_bytes());
        buf[56..64].copy_from_slice(&self.file_table_offset.to_le_bytes());
        buf[64..72].copy_from_slice(&self.file_table_size.to_le_bytes());
        buf[72..80].copy_from_slice(&self.data_offset.to_le_bytes());
        buf[80..112].copy_from_slice(&self.merkle_root);
        buf[112..120].copy_from_slice(&self.total_chunks.to_le_bytes());
        buf[120..128].copy_from_slice(&self.total_files.to_le_bytes());
        buf[128..136].copy_from_slice(&self.original_size.to_le_bytes());
        buf[136..144].copy_from_slice(&self.compressed_size.to_le_bytes());
        buf[144..160].copy_from_slice(&self.salt);
        // bytes 160-255 reserved for future use

        buf
    }

    /// Deserialize header from bytes
    pub fn from_bytes(buf: &[u8; HEADER_SIZE]) -> Result<Self> {
        let header = Self {
            magic: buf[0..4].try_into().unwrap(),
            version: u32::from_le_bytes(buf[4..8].try_into().unwrap()),
            flags: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
            chunk_size_hint: u32::from_le_bytes(buf[16..20].try_into().unwrap()),
            compression: match buf[20] {
                0 => Compression::None,
                1 => Compression::Zstd,
                2 => Compression::Lz4,
                _ => return Err(Error::Corrupted("Invalid compression".into())),
            },
            encryption: match buf[21] {
                0 => Encryption::None,
                1 => Encryption::ChaCha20Poly1305,
                _ => return Err(Error::Corrupted("Invalid encryption".into())),
            },
            metadata_offset: u64::from_le_bytes(buf[24..32].try_into().unwrap()),
            metadata_size: u64::from_le_bytes(buf[32..40].try_into().unwrap()),
            index_offset: u64::from_le_bytes(buf[40..48].try_into().unwrap()),
            index_size: u64::from_le_bytes(buf[48..56].try_into().unwrap()),
            file_table_offset: u64::from_le_bytes(buf[56..64].try_into().unwrap()),
            file_table_size: u64::from_le_bytes(buf[64..72].try_into().unwrap()),
            data_offset: u64::from_le_bytes(buf[72..80].try_into().unwrap()),
            merkle_root: buf[80..112].try_into().unwrap(),
            total_chunks: u64::from_le_bytes(buf[112..120].try_into().unwrap()),
            total_files: u64::from_le_bytes(buf[120..128].try_into().unwrap()),
            original_size: u64::from_le_bytes(buf[128..136].try_into().unwrap()),
            compressed_size: u64::from_le_bytes(buf[136..144].try_into().unwrap()),
            salt: buf[144..160].try_into().unwrap(),
        };

        header.validate()?;
        Ok(header)
    }
}

impl Default for Header {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_roundtrip() {
        let header = Header::new();
        let bytes = header.to_bytes();
        let parsed = Header::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.magic, MAGIC);
        assert_eq!(parsed.version, VERSION);
    }
}

#[cfg(test)]
mod proptest_tests {
    use super::*;
    use proptest::prelude::*;

    fn arb_compression() -> impl Strategy<Value = Compression> {
        prop_oneof![
            Just(Compression::None),
            Just(Compression::Zstd),
            Just(Compression::Lz4),
        ]
    }

    fn arb_encryption() -> impl Strategy<Value = Encryption> {
        prop_oneof![Just(Encryption::None), Just(Encryption::ChaCha20Poly1305),]
    }

    fn arb_header() -> impl Strategy<Value = Header> {
        // Split into two tuples to stay under proptest's 12-element tuple limit
        let part1 = (
            any::<u64>(), // flags
            any::<u32>(), // chunk_size_hint
            arb_compression(),
            arb_encryption(),
            any::<u64>(), // metadata_offset
            any::<u64>(), // metadata_size
            any::<u64>(), // index_offset
            any::<u64>(), // index_size
            any::<u64>(), // file_table_offset
            any::<u64>(), // file_table_size
        );
        let part2 = (
            any::<u64>(),                        // data_offset
            prop::array::uniform32(any::<u8>()), // merkle_root
            any::<u64>(),                        // total_chunks
            any::<u64>(),                        // total_files
            any::<u64>(),                        // original_size
            any::<u64>(),                        // compressed_size
            prop::array::uniform16(any::<u8>()), // salt
        );

        (part1, part2).prop_map(
            |(
                (
                    flags,
                    chunk_size_hint,
                    compression,
                    encryption,
                    metadata_offset,
                    metadata_size,
                    index_offset,
                    index_size,
                    file_table_offset,
                    file_table_size,
                ),
                (
                    data_offset,
                    merkle_root,
                    total_chunks,
                    total_files,
                    original_size,
                    compressed_size,
                    salt,
                ),
            )| {
                Header {
                    magic: MAGIC,
                    version: VERSION,
                    flags,
                    chunk_size_hint,
                    compression,
                    encryption,
                    metadata_offset,
                    metadata_size,
                    index_offset,
                    index_size,
                    file_table_offset,
                    file_table_size,
                    data_offset,
                    merkle_root,
                    total_chunks,
                    total_files,
                    original_size,
                    compressed_size,
                    salt,
                }
            },
        )
    }

    proptest! {
        /// Property: encode then decode recovers original header
        #[test]
        fn header_roundtrip(header in arb_header()) {
            let bytes = header.to_bytes();
            let decoded = Header::from_bytes(&bytes).unwrap();

            prop_assert_eq!(decoded.magic, header.magic);
            prop_assert_eq!(decoded.version, header.version);
            prop_assert_eq!(decoded.flags, header.flags);
            prop_assert_eq!(decoded.chunk_size_hint, header.chunk_size_hint);
            prop_assert_eq!(decoded.compression, header.compression);
            prop_assert_eq!(decoded.encryption, header.encryption);
            prop_assert_eq!(decoded.merkle_root, header.merkle_root);
            prop_assert_eq!(decoded.salt, header.salt);
        }
    }
}
