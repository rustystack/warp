//! NBD (Network Block Device) protocol implementation
//!
//! Implements the NBD protocol as specified in:
//! https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::error::{BlockError, BlockResult, NbdError};

/// NBD magic numbers
pub const NBD_INIT_MAGIC: u64 = 0x4e42444d41474943; // "NBDMAGIC"
pub const NBD_CLISERV_MAGIC: u64 = 0x00420281861253; // Old-style
pub const NBD_OPTS_MAGIC: u64 = 0x49484156454F5054; // "IHAVEOPT"
pub const NBD_REP_MAGIC: u64 = 0x0003e889045565a9;
pub const NBD_REQUEST_MAGIC: u32 = 0x25609513;
pub const NBD_REPLY_MAGIC: u32 = 0x67446698;
pub const NBD_STRUCTURED_REPLY_MAGIC: u32 = 0x668e33ef;

/// NBD protocol flags (global)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GlobalFlags(u16);

impl GlobalFlags {
    /// Fixed newstyle negotiation
    pub const FIXED_NEWSTYLE: u16 = 1 << 0;
    /// No zeroes padding
    pub const NO_ZEROES: u16 = 1 << 1;

    /// Create new flags
    pub fn new(flags: u16) -> Self {
        Self(flags)
    }

    /// Get raw value
    pub fn bits(&self) -> u16 {
        self.0
    }

    /// Default flags for server
    pub fn server_default() -> Self {
        Self(Self::FIXED_NEWSTYLE | Self::NO_ZEROES)
    }
}

/// NBD client flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientFlags(u32);

impl ClientFlags {
    /// Fixed newstyle
    pub const FIXED_NEWSTYLE: u32 = 1 << 0;
    /// No zeroes
    pub const NO_ZEROES: u32 = 1 << 1;

    /// Create new flags
    pub fn new(flags: u32) -> Self {
        Self(flags)
    }

    /// Get raw value
    pub fn bits(&self) -> u32 {
        self.0
    }
}

/// NBD transmission flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransmissionFlags(u16);

impl TransmissionFlags {
    /// Has flags (always set)
    pub const HAS_FLAGS: u16 = 1 << 0;
    /// Read-only export
    pub const READ_ONLY: u16 = 1 << 1;
    /// Send FLUSH command
    pub const SEND_FLUSH: u16 = 1 << 2;
    /// Send FUA (Force Unit Access)
    pub const SEND_FUA: u16 = 1 << 3;
    /// Rotational media (not SSD)
    pub const ROTATIONAL: u16 = 1 << 4;
    /// Send TRIM command
    pub const SEND_TRIM: u16 = 1 << 5;
    /// Send WRITE_ZEROES command
    pub const SEND_WRITE_ZEROES: u16 = 1 << 6;
    /// Send DF (Don't Fragment)
    pub const SEND_DF: u16 = 1 << 7;
    /// Can multi-conn
    pub const CAN_MULTI_CONN: u16 = 1 << 8;
    /// Send resize
    pub const SEND_RESIZE: u16 = 1 << 9;
    /// Send cache
    pub const SEND_CACHE: u16 = 1 << 10;
    /// Send fast zero
    pub const SEND_FAST_ZERO: u16 = 1 << 11;

    /// Create new flags
    pub fn new(flags: u16) -> Self {
        Self(flags)
    }

    /// Get raw value
    pub fn bits(&self) -> u16 {
        self.0
    }

    /// Default flags for writable volume
    pub fn default_rw() -> Self {
        Self(
            Self::HAS_FLAGS
                | Self::SEND_FLUSH
                | Self::SEND_FUA
                | Self::SEND_TRIM
                | Self::SEND_WRITE_ZEROES
                | Self::CAN_MULTI_CONN
                | Self::SEND_FAST_ZERO,
        )
    }

    /// Default flags for read-only volume
    pub fn default_ro() -> Self {
        Self(Self::HAS_FLAGS | Self::READ_ONLY | Self::CAN_MULTI_CONN)
    }
}

/// NBD option codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NbdOption {
    /// Export name
    ExportName = 1,
    /// Abort
    Abort = 2,
    /// List exports
    List = 3,
    /// Peek export (deprecated)
    PeekExport = 4,
    /// Starttls
    StartTls = 5,
    /// Info
    Info = 6,
    /// Go (finish negotiation)
    Go = 7,
    /// Structured reply
    StructuredReply = 8,
    /// List meta context
    ListMetaContext = 9,
    /// Set meta context
    SetMetaContext = 10,
}

impl TryFrom<u32> for NbdOption {
    type Error = BlockError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::ExportName),
            2 => Ok(Self::Abort),
            3 => Ok(Self::List),
            4 => Ok(Self::PeekExport),
            5 => Ok(Self::StartTls),
            6 => Ok(Self::Info),
            7 => Ok(Self::Go),
            8 => Ok(Self::StructuredReply),
            9 => Ok(Self::ListMetaContext),
            10 => Ok(Self::SetMetaContext),
            _ => Err(BlockError::Protocol(format!("Unknown option: {}", value))),
        }
    }
}

/// NBD reply types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NbdReplyType {
    /// Acknowledge
    Ack = 1,
    /// Server info
    Server = 2,
    /// Info (export info)
    Info = 3,
    /// Error with message
    ErrUnsup = (1 << 31) | 1,
    /// Error: policy
    ErrPolicy = (1 << 31) | 2,
    /// Error: invalid
    ErrInvalid = (1 << 31) | 3,
    /// Error: platform
    ErrPlatform = (1 << 31) | 4,
    /// Error: TLS required
    ErrTlsReqd = (1 << 31) | 5,
    /// Error: unknown export
    ErrUnknown = (1 << 31) | 6,
    /// Error: shutdown
    ErrShutdown = (1 << 31) | 7,
    /// Error: block size required
    ErrBlockSizeReqd = (1 << 31) | 8,
    /// Error: too big
    ErrTooBig = (1 << 31) | 9,
}

/// NBD command types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum NbdCommand {
    /// Read
    Read = 0,
    /// Write
    Write = 1,
    /// Disconnect
    Disc = 2,
    /// Flush
    Flush = 3,
    /// Trim
    Trim = 4,
    /// Cache (advisory)
    Cache = 5,
    /// Write zeroes
    WriteZeroes = 6,
    /// Block status
    BlockStatus = 7,
    /// Resize
    Resize = 8,
}

impl TryFrom<u16> for NbdCommand {
    type Error = BlockError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Read),
            1 => Ok(Self::Write),
            2 => Ok(Self::Disc),
            3 => Ok(Self::Flush),
            4 => Ok(Self::Trim),
            5 => Ok(Self::Cache),
            6 => Ok(Self::WriteZeroes),
            7 => Ok(Self::BlockStatus),
            8 => Ok(Self::Resize),
            _ => Err(BlockError::Protocol(format!("Unknown command: {}", value))),
        }
    }
}

/// NBD command flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandFlags(u16);

impl CommandFlags {
    /// Force unit access (write-through)
    pub const FUA: u16 = 1 << 0;
    /// Don't fragment (for structured reply)
    pub const DF: u16 = 1 << 2;
    /// Request one (for block status)
    pub const REQ_ONE: u16 = 1 << 3;
    /// Fast zero (for write zeroes)
    pub const FAST_ZERO: u16 = 1 << 4;

    /// Create new flags
    pub fn new(flags: u16) -> Self {
        Self(flags)
    }

    /// Get raw value
    pub fn bits(&self) -> u16 {
        self.0
    }

    /// Check FUA flag
    pub fn has_fua(&self) -> bool {
        self.0 & Self::FUA != 0
    }

    /// Check DF flag
    pub fn has_df(&self) -> bool {
        self.0 & Self::DF != 0
    }

    /// Check fast zero flag
    pub fn has_fast_zero(&self) -> bool {
        self.0 & Self::FAST_ZERO != 0
    }
}

/// NBD request
#[derive(Debug, Clone)]
pub struct NbdRequest {
    /// Command flags
    pub flags: CommandFlags,
    /// Command type
    pub command: NbdCommand,
    /// Handle (cookie for matching reply)
    pub handle: u64,
    /// Offset
    pub offset: u64,
    /// Length
    pub length: u32,
}

impl NbdRequest {
    /// Parse from bytes
    pub fn parse(data: &[u8]) -> BlockResult<Self> {
        if data.len() < 28 {
            return Err(BlockError::Protocol("Request too short".to_string()));
        }

        let mut buf = data;
        let magic = buf.get_u32();
        if magic != NBD_REQUEST_MAGIC {
            return Err(BlockError::Protocol(format!(
                "Invalid request magic: {:08x}",
                magic
            )));
        }

        let flags = CommandFlags::new(buf.get_u16());
        let cmd_type = buf.get_u16();
        let command = NbdCommand::try_from(cmd_type)?;
        let handle = buf.get_u64();
        let offset = buf.get_u64();
        let length = buf.get_u32();

        Ok(Self {
            flags,
            command,
            handle,
            offset,
            length,
        })
    }

    /// Request size (always 28 bytes)
    pub const SIZE: usize = 28;
}

/// NBD simple reply
#[derive(Debug, Clone)]
pub struct NbdReply {
    /// Error code
    pub error: NbdError,
    /// Handle (matches request)
    pub handle: u64,
}

impl NbdReply {
    /// Create a new reply
    pub fn new(handle: u64, error: NbdError) -> Self {
        Self { error, handle }
    }

    /// Create a success reply
    pub fn ok(handle: u64) -> Self {
        Self {
            error: NbdError::Ok,
            handle,
        }
    }

    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(NBD_REPLY_MAGIC);
        buf.put_u32(self.error.code());
        buf.put_u64(self.handle);
    }

    /// Reply size (always 16 bytes)
    pub const SIZE: usize = 16;
}

/// Export information
#[derive(Debug, Clone)]
pub struct ExportInfo {
    /// Export name
    pub name: String,
    /// Size in bytes
    pub size: u64,
    /// Transmission flags
    pub flags: TransmissionFlags,
    /// Minimum block size
    pub min_block_size: u32,
    /// Preferred block size
    pub preferred_block_size: u32,
    /// Maximum block size
    pub max_block_size: u32,
}

impl ExportInfo {
    /// Create new export info
    pub fn new(name: impl Into<String>, size: u64) -> Self {
        Self {
            name: name.into(),
            size,
            flags: TransmissionFlags::default_rw(),
            min_block_size: 1,
            preferred_block_size: 4096,
            max_block_size: 32 * 1024 * 1024, // 32 MB
        }
    }

    /// Set read-only
    pub fn read_only(mut self) -> Self {
        self.flags = TransmissionFlags::default_ro();
        self
    }

    /// Set block sizes
    pub fn block_sizes(
        mut self,
        min: u32,
        preferred: u32,
        max: u32,
    ) -> Self {
        self.min_block_size = min;
        self.preferred_block_size = preferred;
        self.max_block_size = max;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_global_flags() {
        let flags = GlobalFlags::server_default();
        assert_ne!(flags.bits() & GlobalFlags::FIXED_NEWSTYLE, 0);
        assert_ne!(flags.bits() & GlobalFlags::NO_ZEROES, 0);
    }

    #[test]
    fn test_transmission_flags() {
        let rw = TransmissionFlags::default_rw();
        assert_ne!(rw.bits() & TransmissionFlags::HAS_FLAGS, 0);
        assert_eq!(rw.bits() & TransmissionFlags::READ_ONLY, 0);

        let ro = TransmissionFlags::default_ro();
        assert_ne!(ro.bits() & TransmissionFlags::READ_ONLY, 0);
    }

    #[test]
    fn test_command_flags() {
        let flags = CommandFlags::new(CommandFlags::FUA | CommandFlags::FAST_ZERO);
        assert!(flags.has_fua());
        assert!(flags.has_fast_zero());
        assert!(!flags.has_df());
    }

    #[test]
    fn test_nbd_reply() {
        let reply = NbdReply::ok(12345);
        let mut buf = BytesMut::new();
        reply.encode(&mut buf);

        assert_eq!(buf.len(), NbdReply::SIZE);
        assert_eq!(&buf[0..4], &NBD_REPLY_MAGIC.to_be_bytes());
    }

    #[test]
    fn test_export_info() {
        let info = ExportInfo::new("test", 1024 * 1024 * 1024)
            .block_sizes(512, 4096, 1024 * 1024);

        assert_eq!(info.name, "test");
        assert_eq!(info.size, 1024 * 1024 * 1024);
        assert_eq!(info.preferred_block_size, 4096);
    }
}
