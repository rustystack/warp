//! Index implementation

use crate::{Error, Result};

/// Chunk entry in the index (56 bytes)
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ChunkEntry {
    /// Offset in data section
    pub offset: u64,
    /// Compressed size
    pub compressed_size: u32,
    /// Original size
    pub original_size: u32,
    /// BLAKE3 hash
    pub hash: [u8; 32],
    /// Flags (compressed, encrypted, etc.)
    pub flags: u8,
    /// Reserved for alignment
    pub _reserved: [u8; 7],
}

impl ChunkEntry {
    /// Size of a chunk entry in bytes
    pub const SIZE: usize = 56;

    /// Check if chunk is compressed
    pub fn is_compressed(&self) -> bool {
        self.flags & 0x01 != 0
    }

    /// Check if chunk is encrypted
    pub fn is_encrypted(&self) -> bool {
        self.flags & 0x02 != 0
    }

    /// Serialize to bytes (little-endian)
    pub fn to_bytes(&self) -> [u8; 56] {
        let mut bytes = [0u8; 56];
        bytes[0..8].copy_from_slice(&self.offset.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.compressed_size.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.original_size.to_le_bytes());
        bytes[16..48].copy_from_slice(&self.hash);
        bytes[48] = self.flags;
        bytes[49..56].copy_from_slice(&self._reserved);
        bytes
    }

    /// Deserialize from bytes (little-endian)
    pub fn from_bytes(bytes: &[u8; 56]) -> Result<Self> {
        let offset = u64::from_le_bytes(
            bytes[0..8]
                .try_into()
                .map_err(|_| Error::Corrupted("Invalid offset".to_string()))?,
        );
        let compressed_size = u32::from_le_bytes(
            bytes[8..12]
                .try_into()
                .map_err(|_| Error::Corrupted("Invalid compressed_size".to_string()))?,
        );
        let original_size = u32::from_le_bytes(
            bytes[12..16]
                .try_into()
                .map_err(|_| Error::Corrupted("Invalid original_size".to_string()))?,
        );
        let hash: [u8; 32] = bytes[16..48]
            .try_into()
            .map_err(|_| Error::Corrupted("Invalid hash".to_string()))?;
        let flags = bytes[48];
        let _reserved: [u8; 7] = bytes[49..56]
            .try_into()
            .map_err(|_| Error::Corrupted("Invalid reserved".to_string()))?;

        Ok(Self {
            offset,
            compressed_size,
            original_size,
            hash,
            flags,
            _reserved,
        })
    }
}

/// Chunk index for fast lookup
pub struct ChunkIndex {
    entries: Vec<ChunkEntry>,
}

impl ChunkIndex {
    /// Create a new empty index
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add a chunk entry
    pub fn push(&mut self, entry: ChunkEntry) {
        self.entries.push(entry);
    }

    /// Get chunk by index
    pub fn get(&self, index: usize) -> Option<&ChunkEntry> {
        self.entries.get(index)
    }

    /// Number of chunks
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.entries.len() * ChunkEntry::SIZE);
        for entry in &self.entries {
            bytes.extend_from_slice(&entry.to_bytes());
        }
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if !bytes.len().is_multiple_of(ChunkEntry::SIZE) {
            return Err(Error::Corrupted(format!(
                "Invalid chunk index size: {} (not a multiple of {})",
                bytes.len(),
                ChunkEntry::SIZE
            )));
        }

        let num_entries = bytes.len() / ChunkEntry::SIZE;
        let mut entries = Vec::with_capacity(num_entries);

        for i in 0..num_entries {
            let start = i * ChunkEntry::SIZE;
            let end = start + ChunkEntry::SIZE;
            let entry_bytes: [u8; 56] = bytes[start..end]
                .try_into()
                .map_err(|_| Error::Corrupted(format!("Invalid entry at index {}", i)))?;
            entries.push(ChunkEntry::from_bytes(&entry_bytes)?);
        }

        debug_assert_eq!(
            entries.len(),
            num_entries,
            "parsed entry count {} does not match expected count {}",
            entries.len(),
            num_entries
        );

        Ok(Self { entries })
    }
}

impl Default for ChunkIndex {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_entry_flags() {
        let mut entry = ChunkEntry {
            offset: 0,
            compressed_size: 0,
            original_size: 0,
            hash: [0u8; 32],
            flags: 0x01,
            _reserved: [0u8; 7],
        };

        assert!(entry.is_compressed());
        assert!(!entry.is_encrypted());

        entry.flags = 0x02;
        assert!(!entry.is_compressed());
        assert!(entry.is_encrypted());

        entry.flags = 0x03;
        assert!(entry.is_compressed());
        assert!(entry.is_encrypted());
    }

    #[test]
    fn test_chunk_entry_roundtrip() {
        let entry = ChunkEntry {
            offset: 0x1234567890ABCDEF,
            compressed_size: 0x12345678,
            original_size: 0x87654321,
            hash: [42u8; 32],
            flags: 0x03,
            _reserved: [0u8; 7],
        };

        let bytes = entry.to_bytes();
        assert_eq!(bytes.len(), ChunkEntry::SIZE);

        let decoded = ChunkEntry::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.offset, entry.offset);
        assert_eq!(decoded.compressed_size, entry.compressed_size);
        assert_eq!(decoded.original_size, entry.original_size);
        assert_eq!(decoded.hash, entry.hash);
        assert_eq!(decoded.flags, entry.flags);
    }

    #[test]
    fn test_chunk_entry_size() {
        // Verify compile-time size guarantee
        assert_eq!(std::mem::size_of::<ChunkEntry>(), ChunkEntry::SIZE);
    }

    #[test]
    fn test_chunk_index_empty() {
        let index = ChunkIndex::new();
        assert!(index.is_empty());
        assert_eq!(index.len(), 0);
        assert!(index.get(0).is_none());
    }

    #[test]
    fn test_chunk_index_push_get() {
        let mut index = ChunkIndex::new();

        let entry1 = ChunkEntry {
            offset: 100,
            compressed_size: 50,
            original_size: 100,
            hash: [1u8; 32],
            flags: 0x01,
            _reserved: [0u8; 7],
        };

        let entry2 = ChunkEntry {
            offset: 200,
            compressed_size: 60,
            original_size: 120,
            hash: [2u8; 32],
            flags: 0x00,
            _reserved: [0u8; 7],
        };

        index.push(entry1);
        index.push(entry2);

        assert_eq!(index.len(), 2);
        assert!(!index.is_empty());

        let retrieved1 = index.get(0).unwrap();
        assert_eq!(retrieved1.offset, 100);
        assert_eq!(retrieved1.hash, [1u8; 32]);

        let retrieved2 = index.get(1).unwrap();
        assert_eq!(retrieved2.offset, 200);
        assert_eq!(retrieved2.hash, [2u8; 32]);

        assert!(index.get(2).is_none());
    }

    #[test]
    fn test_chunk_index_roundtrip_empty() {
        let index = ChunkIndex::new();
        let bytes = index.to_bytes();
        assert_eq!(bytes.len(), 0);

        let decoded = ChunkIndex::from_bytes(&bytes).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_chunk_index_roundtrip_single() {
        let mut index = ChunkIndex::new();
        index.push(ChunkEntry {
            offset: 1000,
            compressed_size: 256,
            original_size: 512,
            hash: [77u8; 32],
            flags: 0x01,
            _reserved: [0u8; 7],
        });

        let bytes = index.to_bytes();
        assert_eq!(bytes.len(), ChunkEntry::SIZE);

        let decoded = ChunkIndex::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded.get(0).unwrap().offset, 1000);
        assert_eq!(decoded.get(0).unwrap().compressed_size, 256);
    }

    #[test]
    fn test_chunk_index_roundtrip_multiple() {
        let mut index = ChunkIndex::new();

        for i in 0u64..10 {
            index.push(ChunkEntry {
                offset: i * 100,
                compressed_size: (i * 10) as u32,
                original_size: (i * 20) as u32,
                hash: [i as u8; 32],
                flags: i as u8 & 0x03,
                _reserved: [0u8; 7],
            });
        }

        let bytes = index.to_bytes();
        assert_eq!(bytes.len(), 10 * ChunkEntry::SIZE);

        let decoded = ChunkIndex::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.len(), 10);

        for i in 0u64..10 {
            let entry = decoded.get(i as usize).unwrap();
            assert_eq!(entry.offset, i * 100);
            assert_eq!(entry.compressed_size, (i * 10) as u32);
            assert_eq!(entry.original_size, (i * 20) as u32);
            assert_eq!(entry.hash, [i as u8; 32]);
        }
    }

    #[test]
    fn test_chunk_index_invalid_size() {
        // Not a multiple of ChunkEntry::SIZE
        let bytes = vec![0u8; 100];
        let result = ChunkIndex::from_bytes(&bytes);
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod proptest_tests {
    use super::*;
    use proptest::prelude::*;

    fn arb_chunk_entry() -> impl Strategy<Value = ChunkEntry> {
        (
            any::<u64>(),                        // offset
            any::<u32>(),                        // compressed_size
            any::<u32>(),                        // original_size
            prop::array::uniform32(any::<u8>()), // hash
            any::<u8>(),                         // flags
        )
            .prop_map(
                |(offset, compressed_size, original_size, hash, flags)| ChunkEntry {
                    offset,
                    compressed_size,
                    original_size,
                    hash,
                    flags,
                    _reserved: [0u8; 7],
                },
            )
    }

    proptest! {
        /// Property: ChunkEntry encode/decode roundtrip
        #[test]
        fn chunk_entry_roundtrip(entry in arb_chunk_entry()) {
            let bytes = entry.to_bytes();
            let decoded = ChunkEntry::from_bytes(&bytes).unwrap();

            prop_assert_eq!(decoded.offset, entry.offset);
            prop_assert_eq!(decoded.compressed_size, entry.compressed_size);
            prop_assert_eq!(decoded.original_size, entry.original_size);
            prop_assert_eq!(decoded.hash, entry.hash);
            prop_assert_eq!(decoded.flags, entry.flags);
        }

        /// Property: ChunkIndex encode/decode roundtrip
        #[test]
        fn chunk_index_roundtrip(
            entries in prop::collection::vec(arb_chunk_entry(), 0..100)
        ) {
            let mut index = ChunkIndex::new();
            for entry in &entries {
                index.push(*entry);
            }

            let bytes = index.to_bytes();
            let decoded = ChunkIndex::from_bytes(&bytes).unwrap();

            prop_assert_eq!(decoded.len(), entries.len());
            for (i, entry) in entries.iter().enumerate() {
                let dec = decoded.get(i).unwrap();
                prop_assert_eq!(dec.offset, entry.offset);
                prop_assert_eq!(dec.hash, entry.hash);
            }
        }
    }
}
