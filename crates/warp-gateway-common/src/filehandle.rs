//! Opaque filehandle generation for protocol gateways
//!
//! Provides stable, opaque filehandles for NFS and SMB protocols.
//! Filehandles encode inode number, generation, and bucket hash for validation.

use std::fmt;

use blake3::Hasher;

use crate::error::{GatewayError, GatewayResult};

/// Filehandle version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FileHandleVersion {
    /// Version 1: Basic handle
    V1 = 1,
}

impl TryFrom<u8> for FileHandleVersion {
    type Error = GatewayError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(FileHandleVersion::V1),
            _ => Err(GatewayError::InvalidHandle(format!(
                "unknown version: {}",
                value
            ))),
        }
    }
}

/// Opaque filehandle for protocols
///
/// Format (25 bytes):
/// - version: 1 byte
/// - inode: 8 bytes (little-endian)
/// - generation: 8 bytes (little-endian)
/// - bucket_hash: 4 bytes
/// - checksum: 4 bytes
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct FileHandle {
    data: [u8; 25],
}

impl FileHandle {
    /// Handle size in bytes
    pub const SIZE: usize = 25;

    /// Create a new filehandle
    pub fn new(ino: u64, generation: u64, bucket: &str) -> Self {
        let mut data = [0u8; 25];

        // Version
        data[0] = FileHandleVersion::V1 as u8;

        // Inode (little-endian)
        data[1..9].copy_from_slice(&ino.to_le_bytes());

        // Generation (little-endian)
        data[9..17].copy_from_slice(&generation.to_le_bytes());

        // Bucket hash (first 4 bytes of BLAKE3)
        let bucket_hash = blake3::hash(bucket.as_bytes());
        data[17..21].copy_from_slice(&bucket_hash.as_bytes()[0..4]);

        // Checksum (BLAKE3 of first 21 bytes, take 4 bytes)
        let checksum = blake3::hash(&data[0..21]);
        data[21..25].copy_from_slice(&checksum.as_bytes()[0..4]);

        Self { data }
    }

    /// Create filehandle for NFS (includes export_id in hash)
    pub fn for_nfs(ino: u64, generation: u64, bucket: &str, export_id: u32) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(bucket.as_bytes());
        hasher.update(&export_id.to_le_bytes());
        let combined = hasher.finalize();

        let mut data = [0u8; 25];
        data[0] = FileHandleVersion::V1 as u8;
        data[1..9].copy_from_slice(&ino.to_le_bytes());
        data[9..17].copy_from_slice(&generation.to_le_bytes());
        data[17..21].copy_from_slice(&combined.as_bytes()[0..4]);

        let checksum = blake3::hash(&data[0..21]);
        data[21..25].copy_from_slice(&checksum.as_bytes()[0..4]);

        Self { data }
    }

    /// Create filehandle for SMB (includes tree_id in hash)
    pub fn for_smb(ino: u64, generation: u64, bucket: &str, tree_id: u32) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(bucket.as_bytes());
        hasher.update(b"smb");
        hasher.update(&tree_id.to_le_bytes());
        let combined = hasher.finalize();

        let mut data = [0u8; 25];
        data[0] = FileHandleVersion::V1 as u8;
        data[1..9].copy_from_slice(&ino.to_le_bytes());
        data[9..17].copy_from_slice(&generation.to_le_bytes());
        data[17..21].copy_from_slice(&combined.as_bytes()[0..4]);

        let checksum = blake3::hash(&data[0..21]);
        data[21..25].copy_from_slice(&checksum.as_bytes()[0..4]);

        Self { data }
    }

    /// Parse and validate a filehandle from bytes
    pub fn from_bytes(bytes: &[u8]) -> GatewayResult<Self> {
        if bytes.len() != Self::SIZE {
            return Err(GatewayError::InvalidHandle(format!(
                "invalid size: expected {}, got {}",
                Self::SIZE,
                bytes.len()
            )));
        }

        let mut data = [0u8; 25];
        data.copy_from_slice(bytes);

        // Validate version
        let _ = FileHandleVersion::try_from(data[0])?;

        // Validate checksum
        let expected_checksum = &data[21..25];
        let actual_checksum = blake3::hash(&data[0..21]);

        if expected_checksum != &actual_checksum.as_bytes()[0..4] {
            return Err(GatewayError::InvalidHandle("checksum mismatch".to_string()));
        }

        Ok(Self { data })
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Get the version
    pub fn version(&self) -> FileHandleVersion {
        // Safe: validated on creation/parsing
        FileHandleVersion::try_from(self.data[0]).unwrap()
    }

    /// Get the inode number
    pub fn ino(&self) -> u64 {
        u64::from_le_bytes(self.data[1..9].try_into().unwrap())
    }

    /// Get the generation number
    pub fn generation(&self) -> u64 {
        u64::from_le_bytes(self.data[9..17].try_into().unwrap())
    }

    /// Get the bucket hash
    pub fn bucket_hash(&self) -> [u8; 4] {
        self.data[17..21].try_into().unwrap()
    }

    /// Validate handle against expected bucket
    pub fn validate_bucket(&self, bucket: &str) -> bool {
        let expected_hash = blake3::hash(bucket.as_bytes());
        self.bucket_hash() == expected_hash.as_bytes()[0..4]
    }

    /// Validate handle generation against current inode generation
    pub fn validate_generation(&self, current_generation: u64) -> GatewayResult<()> {
        if self.generation() != current_generation {
            return Err(GatewayError::StaleHandle {
                expected: current_generation,
                actual: self.generation(),
            });
        }
        Ok(())
    }
}

impl fmt::Debug for FileHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileHandle")
            .field("version", &self.version())
            .field("ino", &self.ino())
            .field("generation", &self.generation())
            .field("bucket_hash", &hex::encode(self.bucket_hash()))
            .finish()
    }
}

impl fmt::Display for FileHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "fh:{}:{}:{}",
            self.ino(),
            self.generation(),
            hex::encode(self.bucket_hash())
        )
    }
}

/// Helper for hex encoding (inline to avoid dependency)
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_parse() {
        let handle = FileHandle::new(12345, 1, "test-bucket");

        assert_eq!(handle.ino(), 12345);
        assert_eq!(handle.generation(), 1);

        // Parse back
        let parsed = FileHandle::from_bytes(handle.as_bytes()).unwrap();
        assert_eq!(parsed.ino(), 12345);
        assert_eq!(parsed.generation(), 1);
    }

    #[test]
    fn test_checksum_validation() {
        let handle = FileHandle::new(12345, 1, "test-bucket");
        let mut corrupted = handle.data;
        corrupted[5] ^= 0xFF; // Corrupt a byte

        assert!(FileHandle::from_bytes(&corrupted).is_err());
    }

    #[test]
    fn test_bucket_validation() {
        let handle = FileHandle::new(12345, 1, "test-bucket");

        assert!(handle.validate_bucket("test-bucket"));
        assert!(!handle.validate_bucket("other-bucket"));
    }

    #[test]
    fn test_generation_validation() {
        let handle = FileHandle::new(12345, 1, "test-bucket");

        assert!(handle.validate_generation(1).is_ok());
        assert!(matches!(
            handle.validate_generation(2),
            Err(GatewayError::StaleHandle { expected: 2, actual: 1 })
        ));
    }

    #[test]
    fn test_nfs_handle() {
        let handle = FileHandle::for_nfs(12345, 1, "bucket", 1);
        assert_eq!(handle.ino(), 12345);

        // Different export_id produces different bucket_hash
        let handle2 = FileHandle::for_nfs(12345, 1, "bucket", 2);
        assert_ne!(handle.bucket_hash(), handle2.bucket_hash());
    }

    #[test]
    fn test_smb_handle() {
        let handle = FileHandle::for_smb(12345, 1, "bucket", 1);
        assert_eq!(handle.ino(), 12345);

        // Different tree_id produces different bucket_hash
        let handle2 = FileHandle::for_smb(12345, 1, "bucket", 2);
        assert_ne!(handle.bucket_hash(), handle2.bucket_hash());
    }
}
