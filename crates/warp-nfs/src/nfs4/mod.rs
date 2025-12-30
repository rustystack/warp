//! NFSv4.1 protocol implementation
//!
//! This module implements the NFSv4.1 protocol as defined in RFC 8881.

pub mod compound;
pub mod ops;
pub mod session;
pub mod state;

use bytes::Bytes;

use crate::error::{NfsResult, NfsStatus};
use crate::rpc::xdr::{XdrDecoder, XdrEncoder};

/// NFSv4.1 minor version
pub const NFS4_MINOR_VERSION: u32 = 1;

/// Maximum COMPOUND operations per request
pub const MAX_COMPOUND_OPS: usize = 16;

/// NFSv4 file handle (opaque, max 128 bytes)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Nfs4FileHandle(pub Bytes);

impl Nfs4FileHandle {
    /// Create a new filehandle from bytes
    pub fn new(data: impl Into<Bytes>) -> Self {
        Self(data.into())
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Check if this is a root filehandle
    pub fn is_root(&self) -> bool {
        self.0.len() == 1 && self.0[0] == 0
    }

    /// Create a root filehandle
    pub fn root() -> Self {
        Self(Bytes::from_static(&[0]))
    }
}

/// NFSv4.1 stateid (identifies state at server)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StateId {
    /// Sequence number
    pub seqid: u32,
    /// Other (12 bytes, opaque)
    pub other: [u8; 12],
}

impl StateId {
    /// Anonymous stateid (all zeros)
    pub const ANONYMOUS: Self = Self {
        seqid: 0,
        other: [0; 12],
    };

    /// Read bypass stateid (all ones)
    pub const READ_BYPASS: Self = Self {
        seqid: 0xFFFFFFFF,
        other: [0xFF; 12],
    };

    /// Current stateid (seqid=1, other=0)
    pub const CURRENT: Self = Self {
        seqid: 1,
        other: [0; 12],
    };

    /// Create a new stateid
    pub fn new(seqid: u32, other: [u8; 12]) -> Self {
        Self { seqid, other }
    }

    /// Check if this is the anonymous stateid
    pub fn is_anonymous(&self) -> bool {
        self.seqid == 0 && self.other == [0; 12]
    }

    /// Encode to XDR
    pub fn encode(&self, enc: &mut XdrEncoder) {
        enc.encode_u32(self.seqid);
        enc.encode_opaque_fixed(&self.other);
    }

    /// Decode from XDR
    pub fn decode(dec: &mut XdrDecoder) -> std::io::Result<Self> {
        let seqid = dec.decode_u32()?;
        let other_vec = dec.decode_opaque_fixed(12)?;
        let mut other = [0u8; 12];
        other.copy_from_slice(&other_vec);
        Ok(Self { seqid, other })
    }
}

/// NFSv4.1 change attribute (for cache validation)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChangeInfo {
    /// Atomic operation
    pub atomic: bool,
    /// Change value before operation
    pub before: u64,
    /// Change value after operation
    pub after: u64,
}

impl ChangeInfo {
    /// Create new change info
    pub fn new(before: u64, after: u64, atomic: bool) -> Self {
        Self {
            atomic,
            before,
            after,
        }
    }

    /// Encode to XDR
    pub fn encode(&self, enc: &mut XdrEncoder) {
        enc.encode_bool(self.atomic);
        enc.encode_u64(self.before);
        enc.encode_u64(self.after);
    }
}

/// File type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Nfs4FileType {
    /// Regular file
    Regular = 1,
    /// Directory
    Directory = 2,
    /// Block device
    BlockDevice = 3,
    /// Character device
    CharDevice = 4,
    /// Symbolic link
    SymLink = 5,
    /// Socket
    Socket = 6,
    /// FIFO (named pipe)
    Fifo = 7,
    /// Attribute directory
    AttrDir = 8,
    /// Named attribute
    NamedAttr = 9,
}

impl TryFrom<u32> for Nfs4FileType {
    type Error = NfsStatus;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Regular),
            2 => Ok(Self::Directory),
            3 => Ok(Self::BlockDevice),
            4 => Ok(Self::CharDevice),
            5 => Ok(Self::SymLink),
            6 => Ok(Self::Socket),
            7 => Ok(Self::Fifo),
            8 => Ok(Self::AttrDir),
            9 => Ok(Self::NamedAttr),
            _ => Err(NfsStatus::BadType),
        }
    }
}

/// Access permission bits
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessBits(pub u32);

impl AccessBits {
    /// Read data
    pub const READ: u32 = 0x00000001;
    /// Lookup in directory
    pub const LOOKUP: u32 = 0x00000002;
    /// Modify file
    pub const MODIFY: u32 = 0x00000004;
    /// Extend file
    pub const EXTEND: u32 = 0x00000008;
    /// Delete entry
    pub const DELETE: u32 = 0x00000010;
    /// Execute file
    pub const EXECUTE: u32 = 0x00000020;

    /// Check if read access is set
    pub fn can_read(&self) -> bool {
        self.0 & Self::READ != 0
    }

    /// Check if lookup access is set
    pub fn can_lookup(&self) -> bool {
        self.0 & Self::LOOKUP != 0
    }

    /// Check if modify access is set
    pub fn can_modify(&self) -> bool {
        self.0 & Self::MODIFY != 0
    }

    /// Check if extend access is set
    pub fn can_extend(&self) -> bool {
        self.0 & Self::EXTEND != 0
    }

    /// Check if delete access is set
    pub fn can_delete(&self) -> bool {
        self.0 & Self::DELETE != 0
    }

    /// Check if execute access is set
    pub fn can_execute(&self) -> bool {
        self.0 & Self::EXECUTE != 0
    }
}

/// State manager for NFSv4.1 stateids
pub struct StateManager {
    /// Next stateid counter
    counter: std::sync::atomic::AtomicU64,
}

impl StateManager {
    /// Create a new state manager
    pub fn new() -> Self {
        Self {
            counter: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Generate a new stateid
    pub fn generate_stateid(&self) -> StateId {
        let counter = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut other = [0u8; 12];
        other[..8].copy_from_slice(&counter.to_be_bytes());
        StateId::new(1, other)
    }
}

impl Default for StateManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stateid_special_values() {
        assert!(StateId::ANONYMOUS.is_anonymous());
        assert!(!StateId::READ_BYPASS.is_anonymous());
        assert!(!StateId::CURRENT.is_anonymous());
    }

    #[test]
    fn test_filehandle_root() {
        let root = Nfs4FileHandle::root();
        assert!(root.is_root());

        let non_root = Nfs4FileHandle::new(vec![1, 2, 3]);
        assert!(!non_root.is_root());
    }

    #[test]
    fn test_state_manager() {
        let mgr = StateManager::new();
        let id1 = mgr.generate_stateid();
        let id2 = mgr.generate_stateid();
        assert_ne!(id1.other, id2.other);
    }

    #[test]
    fn test_access_bits() {
        let bits = AccessBits(AccessBits::READ | AccessBits::LOOKUP);
        assert!(bits.can_read());
        assert!(bits.can_lookup());
        assert!(!bits.can_modify());
    }
}
