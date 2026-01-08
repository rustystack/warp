//! Core chunk types for the Chonkers algorithm
//!
//! This module defines the fundamental types used throughout the algorithm:
//! - `ChunkId`: Content-addressed identifier (BLAKE3 hash)
//! - `ChunkWeight`: Priority weight derived from hash
//! - `Chunk`: Complete chunk with metadata

use serde::{Deserialize, Serialize};
use std::fmt;

/// Content-addressed chunk identifier
///
/// The ID is a 32-byte BLAKE3 hash of the chunk content.
/// Identical content always produces identical IDs.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct ChunkId(pub [u8; 32]);

impl ChunkId {
    /// Create a ChunkId from raw bytes
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Compute ChunkId from data using BLAKE3
    pub fn from_data(data: &[u8]) -> Self {
        let hash = warp_hash::hash(data);
        Self(hash)
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Get the weight derived from this ID
    ///
    /// Weight is the first 8 bytes interpreted as little-endian u64.
    pub fn weight(&self) -> ChunkWeight {
        ChunkWeight::from_hash(&self.0)
    }

    /// Convert to hex string (first 16 chars)
    pub fn short_hex(&self) -> String {
        hex::encode(&self.0[..8])
    }
}

impl fmt::Debug for ChunkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChunkId({})", self.short_hex())
    }
}

impl fmt::Display for ChunkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

/// Priority weight for chunk boundary decisions
///
/// Weight is derived from the first 8 bytes of a BLAKE3 hash.
/// Higher weights have higher priority in the Chonkers algorithm.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
pub struct ChunkWeight(pub u64);

impl ChunkWeight {
    /// Create weight from raw value
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Compute weight from hash bytes
    pub fn from_hash(hash: &[u8; 32]) -> Self {
        let bytes: [u8; 8] = hash[..8].try_into().unwrap();
        Self(u64::from_le_bytes(bytes))
    }

    /// Compute weight from arbitrary data
    pub fn from_data(data: &[u8]) -> Self {
        let hash = warp_hash::hash(data);
        Self::from_hash(&hash)
    }

    /// Get the raw value
    pub fn value(&self) -> u64 {
        self.0
    }

    /// Check if this weight is lighter (lower) than another
    pub fn is_lighter_than(&self, other: &Self) -> bool {
        self.0 < other.0
    }

    /// Check if this weight is heavier (higher) than another
    pub fn is_heavier_than(&self, other: &Self) -> bool {
        self.0 > other.0
    }

    /// Get the number of trailing zeros (used for layer assignment)
    pub fn trailing_zeros(&self) -> u32 {
        self.0.trailing_zeros()
    }
}

impl fmt::Debug for ChunkWeight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Weight({})", self.0)
    }
}

impl fmt::Display for ChunkWeight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Flags for chunk metadata
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkFlags(u8);

impl ChunkFlags {
    /// No flags set
    pub const NONE: Self = Self(0);

    /// Chunk was created by merging kittens
    pub const MERGED: Self = Self(1 << 0);

    /// Chunk contains periodic repetitions
    pub const PERIODIC: Self = Self(1 << 1);

    /// Chunk is at a layer boundary
    pub const LAYER_BOUNDARY: Self = Self(1 << 2);

    /// Create new flags
    pub const fn new() -> Self {
        Self(0)
    }

    /// Set a flag
    pub fn set(&mut self, flag: ChunkFlags) {
        self.0 |= flag.0;
    }

    /// Clear a flag
    pub fn clear(&mut self, flag: ChunkFlags) {
        self.0 &= !flag.0;
    }

    /// Check if a flag is set
    pub fn has(&self, flag: ChunkFlags) -> bool {
        (self.0 & flag.0) != 0
    }
}

/// A chunk produced by the Chonkers algorithm
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Chunk {
    /// Content-addressed identifier
    pub id: ChunkId,

    /// Priority weight (from hash)
    pub weight: ChunkWeight,

    /// Chunk index in sequence
    pub index: u64,

    /// Byte offset in original data
    pub offset: usize,

    /// Length in bytes
    pub length: usize,

    /// Layer this chunk belongs to
    pub layer: u8,

    /// Chunk flags
    pub flags: ChunkFlags,
}

impl Chunk {
    /// Create a new chunk from data slice
    pub fn new(index: u64, offset: usize, data: &[u8]) -> Self {
        let id = ChunkId::from_data(data);
        let weight = id.weight();

        Self {
            id,
            weight,
            index,
            offset,
            length: data.len(),
            layer: 0,
            flags: ChunkFlags::NONE,
        }
    }

    /// Create a chunk with explicit ID (for testing)
    pub fn with_id(index: u64, offset: usize, length: usize, id: ChunkId) -> Self {
        let weight = id.weight();
        Self {
            id,
            weight,
            index,
            offset,
            length,
            layer: 0,
            flags: ChunkFlags::NONE,
        }
    }

    /// Set the layer
    pub fn with_layer(mut self, layer: u8) -> Self {
        self.layer = layer;
        self
    }

    /// Set flags
    pub fn with_flags(mut self, flags: ChunkFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Get end offset (exclusive)
    pub fn end(&self) -> usize {
        self.offset + self.length
    }

    /// Check if this chunk contains a byte offset
    pub fn contains(&self, byte_offset: usize) -> bool {
        byte_offset >= self.offset && byte_offset < self.end()
    }
}

impl PartialEq for Chunk {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Chunk {}

impl std::hash::Hash for Chunk {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.0.hash(state);
    }
}

/// Intermediate chunk boundary used during algorithm processing
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub struct Boundary {
    /// Byte offset of this boundary
    pub offset: usize,

    /// Weight at this boundary
    pub weight: ChunkWeight,

    /// Whether this boundary is active
    pub active: bool,
}

#[allow(dead_code)]
impl Boundary {
    /// Create a new boundary
    pub fn new(offset: usize, weight: ChunkWeight) -> Self {
        Self {
            offset,
            weight,
            active: true,
        }
    }

    /// Create boundary with weight computed from data at offset
    pub fn from_data(offset: usize, data: &[u8]) -> Self {
        // Use a small window around the boundary for weight
        let start = offset.saturating_sub(4);
        let end = (offset + 4).min(data.len());
        let weight = if start < end {
            ChunkWeight::from_data(&data[start..end])
        } else {
            ChunkWeight::new(0)
        };

        Self::new(offset, weight)
    }

    /// Deactivate this boundary
    pub fn deactivate(&mut self) {
        self.active = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_id_from_data() {
        let data = b"hello world";
        let id1 = ChunkId::from_data(data);
        let id2 = ChunkId::from_data(data);

        // Same data = same ID
        assert_eq!(id1, id2);

        // Different data = different ID
        let id3 = ChunkId::from_data(b"different");
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_chunk_weight() {
        let data = b"test data";
        let weight = ChunkWeight::from_data(data);

        // Weight should be non-zero for non-empty data
        assert!(weight.value() > 0);

        // Consistent weight
        let weight2 = ChunkWeight::from_data(data);
        assert_eq!(weight, weight2);
    }

    #[test]
    fn test_weight_comparison() {
        let w1 = ChunkWeight::new(100);
        let w2 = ChunkWeight::new(200);

        assert!(w1.is_lighter_than(&w2));
        assert!(w2.is_heavier_than(&w1));
        assert!(!w1.is_heavier_than(&w2));
    }

    #[test]
    fn test_chunk_flags() {
        let mut flags = ChunkFlags::new();
        assert!(!flags.has(ChunkFlags::MERGED));

        flags.set(ChunkFlags::MERGED);
        assert!(flags.has(ChunkFlags::MERGED));
        assert!(!flags.has(ChunkFlags::PERIODIC));

        flags.set(ChunkFlags::PERIODIC);
        assert!(flags.has(ChunkFlags::MERGED));
        assert!(flags.has(ChunkFlags::PERIODIC));

        flags.clear(ChunkFlags::MERGED);
        assert!(!flags.has(ChunkFlags::MERGED));
        assert!(flags.has(ChunkFlags::PERIODIC));
    }

    #[test]
    fn test_chunk_new() {
        let data = b"chunk data";
        let chunk = Chunk::new(0, 100, data);

        assert_eq!(chunk.index, 0);
        assert_eq!(chunk.offset, 100);
        assert_eq!(chunk.length, data.len());
        assert_eq!(chunk.end(), 100 + data.len());
    }

    #[test]
    fn test_chunk_contains() {
        let chunk = Chunk::new(0, 100, b"0123456789");

        assert!(!chunk.contains(99));
        assert!(chunk.contains(100));
        assert!(chunk.contains(105));
        assert!(chunk.contains(109));
        assert!(!chunk.contains(110));
    }

    #[test]
    fn test_chunk_id_weight() {
        let id = ChunkId::from_data(b"test");
        let weight = id.weight();

        // Weight should match ChunkWeight::from_hash
        assert_eq!(weight, ChunkWeight::from_hash(id.as_bytes()));
    }

    #[test]
    fn test_boundary() {
        let data = b"some test data";
        let boundary = Boundary::from_data(5, data);

        assert_eq!(boundary.offset, 5);
        assert!(boundary.active);

        let mut boundary = boundary;
        boundary.deactivate();
        assert!(!boundary.active);
    }
}

// Hex encoding helper (avoiding external dependency for small usage)
mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
