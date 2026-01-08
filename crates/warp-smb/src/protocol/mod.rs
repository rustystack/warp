//! SMB3 protocol implementation
//!
//! Implements SMB2/3 message parsing and encoding.

use bytes::{Buf, BufMut, BytesMut};

use crate::error::{NtStatus, SmbError, SmbResult};

/// SMB2 protocol ID
pub const SMB2_PROTOCOL_ID: &[u8; 4] = b"\xFESMB";

/// SMB1 protocol ID (for negotiation)
pub const SMB1_PROTOCOL_ID: &[u8; 4] = b"\xFFSMB";

/// SMB2 header size
pub const SMB2_HEADER_SIZE: usize = 64;

/// SMB2 command codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SmbCommand {
    /// Negotiate protocol version
    Negotiate = 0x0000,
    /// Session setup
    SessionSetup = 0x0001,
    /// Session logoff
    Logoff = 0x0002,
    /// Tree connect (mount share)
    TreeConnect = 0x0003,
    /// Tree disconnect
    TreeDisconnect = 0x0004,
    /// Create/Open file
    Create = 0x0005,
    /// Close file
    Close = 0x0006,
    /// Flush buffers
    Flush = 0x0007,
    /// Read data
    Read = 0x0008,
    /// Write data
    Write = 0x0009,
    /// Lock/Unlock byte ranges
    Lock = 0x000A,
    /// IOCTL
    Ioctl = 0x000B,
    /// Cancel request
    Cancel = 0x000C,
    /// Echo (keepalive)
    Echo = 0x000D,
    /// Query directory
    QueryDirectory = 0x000E,
    /// Change notify
    ChangeNotify = 0x000F,
    /// Query info
    QueryInfo = 0x0010,
    /// Set info
    SetInfo = 0x0011,
    /// Oplock break
    OplockBreak = 0x0012,
}

impl TryFrom<u16> for SmbCommand {
    type Error = NtStatus;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0000 => Ok(Self::Negotiate),
            0x0001 => Ok(Self::SessionSetup),
            0x0002 => Ok(Self::Logoff),
            0x0003 => Ok(Self::TreeConnect),
            0x0004 => Ok(Self::TreeDisconnect),
            0x0005 => Ok(Self::Create),
            0x0006 => Ok(Self::Close),
            0x0007 => Ok(Self::Flush),
            0x0008 => Ok(Self::Read),
            0x0009 => Ok(Self::Write),
            0x000A => Ok(Self::Lock),
            0x000B => Ok(Self::Ioctl),
            0x000C => Ok(Self::Cancel),
            0x000D => Ok(Self::Echo),
            0x000E => Ok(Self::QueryDirectory),
            0x000F => Ok(Self::ChangeNotify),
            0x0010 => Ok(Self::QueryInfo),
            0x0011 => Ok(Self::SetInfo),
            0x0012 => Ok(Self::OplockBreak),
            _ => Err(NtStatus::SmbBadCommand),
        }
    }
}

/// SMB2 header flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Smb2Flags(u32);

impl Smb2Flags {
    /// Response flag (server to client)
    pub const RESPONSE: u32 = 0x00000001;
    /// Async command
    pub const ASYNC_COMMAND: u32 = 0x00000002;
    /// Related operations
    pub const RELATED_OPERATIONS: u32 = 0x00000004;
    /// Signed message
    pub const SIGNED: u32 = 0x00000008;
    /// Priority mask
    pub const PRIORITY_MASK: u32 = 0x00000070;
    /// DFS operation
    pub const DFS_OPERATIONS: u32 = 0x10000000;
    /// Replay operation
    pub const REPLAY_OPERATION: u32 = 0x20000000;

    /// Create new flags
    pub fn new(flags: u32) -> Self {
        Self(flags)
    }

    /// Get raw value
    pub fn bits(&self) -> u32 {
        self.0
    }

    /// Check if response
    pub fn is_response(&self) -> bool {
        self.0 & Self::RESPONSE != 0
    }

    /// Check if async
    pub fn is_async(&self) -> bool {
        self.0 & Self::ASYNC_COMMAND != 0
    }

    /// Check if signed
    pub fn is_signed(&self) -> bool {
        self.0 & Self::SIGNED != 0
    }

    /// Set response flag
    pub fn set_response(&mut self) {
        self.0 |= Self::RESPONSE;
    }
}

/// SMB2 header
#[derive(Debug, Clone)]
pub struct Smb2Header {
    /// Structure size (always 64)
    pub structure_size: u16,
    /// Credit charge
    pub credit_charge: u16,
    /// Status (response only)
    pub status: NtStatus,
    /// Command
    pub command: SmbCommand,
    /// Credit request/response
    pub credit: u16,
    /// Flags
    pub flags: Smb2Flags,
    /// Next command offset
    pub next_command: u32,
    /// Message ID
    pub message_id: u64,
    /// Async ID (if async)
    pub async_id: u64,
    /// Session ID
    pub session_id: u64,
    /// Signature
    pub signature: [u8; 16],
    /// Tree ID (sync only)
    pub tree_id: u32,
}

impl Smb2Header {
    /// Create a new request header
    pub fn new_request(
        command: SmbCommand,
        message_id: u64,
        session_id: u64,
        tree_id: u32,
    ) -> Self {
        Self {
            structure_size: 64,
            credit_charge: 1,
            status: NtStatus::Success,
            command,
            credit: 1,
            flags: Smb2Flags::default(),
            next_command: 0,
            message_id,
            async_id: 0,
            session_id,
            signature: [0; 16],
            tree_id,
        }
    }

    /// Create a response header from a request
    pub fn response_from(request: &Self, status: NtStatus) -> Self {
        let mut response = Self {
            structure_size: 64,
            credit_charge: request.credit_charge,
            status,
            command: request.command,
            credit: 1,
            flags: Smb2Flags::new(Smb2Flags::RESPONSE),
            next_command: 0,
            message_id: request.message_id,
            async_id: request.async_id,
            session_id: request.session_id,
            signature: [0; 16],
            tree_id: request.tree_id,
        };

        if request.flags.is_async() {
            response.flags = Smb2Flags::new(response.flags.bits() | Smb2Flags::ASYNC_COMMAND);
        }

        response
    }

    /// Parse header from bytes
    pub fn parse(data: &[u8]) -> SmbResult<Self> {
        if data.len() < SMB2_HEADER_SIZE {
            return Err(SmbError::Protocol("Header too short".to_string()));
        }

        let protocol_id = &data[0..4];
        if protocol_id != SMB2_PROTOCOL_ID {
            return Err(SmbError::Protocol("Invalid SMB2 protocol ID".to_string()));
        }

        let mut buf = &data[4..];

        let structure_size = buf.get_u16_le();
        let credit_charge = buf.get_u16_le();
        let status = NtStatus::from_u32(buf.get_u32_le());
        let command_val = buf.get_u16_le();
        let command = SmbCommand::try_from(command_val)?;
        let credit = buf.get_u16_le();
        let flags = Smb2Flags::new(buf.get_u32_le());
        let next_command = buf.get_u32_le();
        let message_id = buf.get_u64_le();

        let (async_id, tree_id) = if flags.is_async() {
            (buf.get_u64_le(), 0)
        } else {
            let _reserved = buf.get_u32_le();
            let tree_id = buf.get_u32_le();
            (0, tree_id)
        };

        let session_id = buf.get_u64_le();

        let mut signature = [0u8; 16];
        signature.copy_from_slice(&buf[..16]);

        Ok(Self {
            structure_size,
            credit_charge,
            status,
            command,
            credit,
            flags,
            next_command,
            message_id,
            async_id,
            session_id,
            signature,
            tree_id,
        })
    }

    /// Encode header to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_slice(SMB2_PROTOCOL_ID);
        buf.put_u16_le(self.structure_size);
        buf.put_u16_le(self.credit_charge);
        buf.put_u32_le(self.status.as_u32());
        buf.put_u16_le(self.command as u16);
        buf.put_u16_le(self.credit);
        buf.put_u32_le(self.flags.bits());
        buf.put_u32_le(self.next_command);
        buf.put_u64_le(self.message_id);

        if self.flags.is_async() {
            buf.put_u64_le(self.async_id);
        } else {
            buf.put_u32_le(0); // Reserved
            buf.put_u32_le(self.tree_id);
        }

        buf.put_u64_le(self.session_id);
        buf.put_slice(&self.signature);
    }
}

/// File ID (SMB2 persistent + volatile)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileId {
    /// Persistent portion
    pub persistent: u64,
    /// Volatile portion
    pub volatile: u64,
}

impl FileId {
    /// Create a new file ID
    pub fn new(persistent: u64, volatile: u64) -> Self {
        Self {
            persistent,
            volatile,
        }
    }

    /// Invalid file ID
    pub const INVALID: Self = Self {
        persistent: u64::MAX,
        volatile: u64::MAX,
    };

    /// Parse from bytes
    pub fn parse(buf: &mut &[u8]) -> Self {
        let persistent = buf.get_u64_le();
        let volatile = buf.get_u64_le();
        Self {
            persistent,
            volatile,
        }
    }

    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u64_le(self.persistent);
        buf.put_u64_le(self.volatile);
    }
}

/// Create disposition (how to handle existing file)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CreateDisposition {
    /// If exists, fail. If not exists, create.
    Supersede = 0,
    /// If exists, open. If not exists, fail.
    Open = 1,
    /// If exists, fail. If not exists, create.
    Create = 2,
    /// If exists, open. If not exists, create.
    OpenIf = 3,
    /// If exists, overwrite. If not exists, fail.
    Overwrite = 4,
    /// If exists, overwrite. If not exists, create.
    OverwriteIf = 5,
}

impl TryFrom<u32> for CreateDisposition {
    type Error = NtStatus;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Supersede),
            1 => Ok(Self::Open),
            2 => Ok(Self::Create),
            3 => Ok(Self::OpenIf),
            4 => Ok(Self::Overwrite),
            5 => Ok(Self::OverwriteIf),
            _ => Err(NtStatus::InvalidParameter),
        }
    }
}

/// Desired access flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DesiredAccess(u32);

impl DesiredAccess {
    /// Read data
    pub const FILE_READ_DATA: u32 = 0x00000001;
    /// Write data
    pub const FILE_WRITE_DATA: u32 = 0x00000002;
    /// Append data
    pub const FILE_APPEND_DATA: u32 = 0x00000004;
    /// Read extended attributes
    pub const FILE_READ_EA: u32 = 0x00000008;
    /// Write extended attributes
    pub const FILE_WRITE_EA: u32 = 0x00000010;
    /// Execute
    pub const FILE_EXECUTE: u32 = 0x00000020;
    /// Delete child
    pub const FILE_DELETE_CHILD: u32 = 0x00000040;
    /// Read attributes
    pub const FILE_READ_ATTRIBUTES: u32 = 0x00000080;
    /// Write attributes
    pub const FILE_WRITE_ATTRIBUTES: u32 = 0x00000100;
    /// Delete
    pub const DELETE: u32 = 0x00010000;
    /// Read control
    pub const READ_CONTROL: u32 = 0x00020000;
    /// Write DAC
    pub const WRITE_DAC: u32 = 0x00040000;
    /// Write owner
    pub const WRITE_OWNER: u32 = 0x00080000;
    /// Synchronize
    pub const SYNCHRONIZE: u32 = 0x00100000;
    /// Generic read
    pub const GENERIC_READ: u32 = 0x80000000;
    /// Generic write
    pub const GENERIC_WRITE: u32 = 0x40000000;
    /// Generic execute
    pub const GENERIC_EXECUTE: u32 = 0x20000000;
    /// Generic all
    pub const GENERIC_ALL: u32 = 0x10000000;
    /// Maximum allowed
    pub const MAXIMUM_ALLOWED: u32 = 0x02000000;

    /// Create new access flags
    pub fn new(flags: u32) -> Self {
        Self(flags)
    }

    /// Get raw value
    pub fn bits(&self) -> u32 {
        self.0
    }

    /// Check if has access
    pub fn has(&self, flag: u32) -> bool {
        self.0 & flag != 0
    }
}

/// Share access flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShareAccess(u32);

impl ShareAccess {
    /// Share read
    pub const READ: u32 = 0x00000001;
    /// Share write
    pub const WRITE: u32 = 0x00000002;
    /// Share delete
    pub const DELETE: u32 = 0x00000004;

    /// Create new share access
    pub fn new(flags: u32) -> Self {
        Self(flags)
    }

    /// Get raw value
    pub fn bits(&self) -> u32 {
        self.0
    }

    /// Allow all sharing
    pub fn all() -> Self {
        Self(Self::READ | Self::WRITE | Self::DELETE)
    }
}

/// File attributes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileAttributes(u32);

impl FileAttributes {
    /// Read-only
    pub const READONLY: u32 = 0x00000001;
    /// Hidden
    pub const HIDDEN: u32 = 0x00000002;
    /// System
    pub const SYSTEM: u32 = 0x00000004;
    /// Directory
    pub const DIRECTORY: u32 = 0x00000010;
    /// Archive
    pub const ARCHIVE: u32 = 0x00000020;
    /// Normal
    pub const NORMAL: u32 = 0x00000080;
    /// Temporary
    pub const TEMPORARY: u32 = 0x00000100;
    /// Sparse file
    pub const SPARSE_FILE: u32 = 0x00000200;
    /// Reparse point
    pub const REPARSE_POINT: u32 = 0x00000400;
    /// Compressed
    pub const COMPRESSED: u32 = 0x00000800;
    /// Offline
    pub const OFFLINE: u32 = 0x00001000;
    /// Not indexed
    pub const NOT_CONTENT_INDEXED: u32 = 0x00002000;
    /// Encrypted
    pub const ENCRYPTED: u32 = 0x00004000;

    /// Create new attributes
    pub fn new(attrs: u32) -> Self {
        Self(attrs)
    }

    /// Get raw value
    pub fn bits(&self) -> u32 {
        self.0
    }

    /// Check if directory
    pub fn is_directory(&self) -> bool {
        self.0 & Self::DIRECTORY != 0
    }

    /// Check if readonly
    pub fn is_readonly(&self) -> bool {
        self.0 & Self::READONLY != 0
    }
}

impl Default for FileAttributes {
    fn default() -> Self {
        Self(Self::NORMAL)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_encode_decode() {
        let header = Smb2Header::new_request(SmbCommand::Create, 1, 100, 1);

        let mut buf = BytesMut::new();
        header.encode(&mut buf);

        let parsed = Smb2Header::parse(&buf).unwrap();
        assert_eq!(parsed.command, SmbCommand::Create);
        assert_eq!(parsed.message_id, 1);
        assert_eq!(parsed.session_id, 100);
        assert_eq!(parsed.tree_id, 1);
    }

    #[test]
    fn test_response_header() {
        let request = Smb2Header::new_request(SmbCommand::Read, 5, 200, 2);
        let response = Smb2Header::response_from(&request, NtStatus::Success);

        assert!(response.flags.is_response());
        assert_eq!(response.message_id, 5);
        assert_eq!(response.session_id, 200);
    }

    #[test]
    fn test_file_id() {
        let id = FileId::new(12345, 67890);
        assert_ne!(id, FileId::INVALID);

        let mut buf = BytesMut::new();
        id.encode(&mut buf);
        let parsed = FileId::parse(&mut buf.as_ref());
        assert_eq!(parsed, id);
    }

    #[test]
    fn test_file_attributes() {
        let attrs = FileAttributes::new(FileAttributes::DIRECTORY | FileAttributes::HIDDEN);
        assert!(attrs.is_directory());
        assert!(!attrs.is_readonly());
    }
}
