//! NFSv4.1 operation handlers
//!
//! Individual handlers for each NFSv4.1 COMPOUND operation.

use bytes::Bytes;

use super::compound::{CompoundContext, Nfs4Op, Nfs4OpRes};
use super::{Nfs4FileHandle, StateId};
use crate::error::NfsStatus;
use crate::rpc::xdr::{XdrDecoder, XdrEncoder};

/// Result of an operation
pub type OpResult = Result<Nfs4OpRes, NfsStatus>;

// ============================================================================
// PUTFH - Set current filehandle
// ============================================================================

/// PUTFH arguments
#[derive(Debug, Clone)]
pub struct PutFhArgs {
    /// Filehandle to set as current
    pub object: Nfs4FileHandle,
}

impl PutFhArgs {
    /// Decode from XDR
    pub fn decode(dec: &mut XdrDecoder) -> std::io::Result<Self> {
        let data = dec.decode_opaque()?;
        Ok(Self {
            object: Nfs4FileHandle::new(data),
        })
    }
}

/// Process PUTFH operation
pub fn process_putfh(ctx: &mut CompoundContext, args: &PutFhArgs) -> OpResult {
    ctx.current_fh = Some(args.object.clone());
    Ok(Nfs4OpRes::ok(Nfs4Op::PutFh, Bytes::new()))
}

// ============================================================================
// PUTROOTFH - Set current filehandle to root
// ============================================================================

/// Process PUTROOTFH operation
pub fn process_putrootfh(ctx: &mut CompoundContext) -> OpResult {
    ctx.current_fh = Some(Nfs4FileHandle::root());
    Ok(Nfs4OpRes::ok(Nfs4Op::PutRootFh, Bytes::new()))
}

// ============================================================================
// GETFH - Get current filehandle
// ============================================================================

/// GETFH result
#[derive(Debug, Clone)]
pub struct GetFhRes {
    /// Current filehandle
    pub object: Nfs4FileHandle,
}

impl GetFhRes {
    /// Encode to XDR
    pub fn encode(&self, enc: &mut XdrEncoder) {
        enc.encode_opaque(self.object.as_bytes());
    }
}

/// Process GETFH operation
pub fn process_getfh(ctx: &CompoundContext) -> OpResult {
    let fh = ctx.require_current_fh()?;
    let mut enc = XdrEncoder::new();
    enc.encode_opaque(fh.as_bytes());
    Ok(Nfs4OpRes::ok(Nfs4Op::GetFh, enc.finish()))
}

// ============================================================================
// SAVEFH - Save current filehandle
// ============================================================================

/// Process SAVEFH operation
pub fn process_savefh(ctx: &mut CompoundContext) -> OpResult {
    let fh = ctx.require_current_fh()?.clone();
    ctx.saved_fh = Some(fh);
    Ok(Nfs4OpRes::ok(Nfs4Op::SaveFh, Bytes::new()))
}

// ============================================================================
// RESTOREFH - Restore saved filehandle
// ============================================================================

/// Process RESTOREFH operation
pub fn process_restorefh(ctx: &mut CompoundContext) -> OpResult {
    let fh = ctx
        .saved_fh
        .clone()
        .ok_or(NfsStatus::RestoreFh)?;
    ctx.current_fh = Some(fh);
    Ok(Nfs4OpRes::ok(Nfs4Op::RestoreFh, Bytes::new()))
}

// ============================================================================
// LOOKUP - Look up filename
// ============================================================================

/// LOOKUP arguments
#[derive(Debug, Clone)]
pub struct LookupArgs {
    /// Name to look up
    pub name: String,
}

impl LookupArgs {
    /// Decode from XDR
    pub fn decode(dec: &mut XdrDecoder) -> std::io::Result<Self> {
        let name = dec.decode_string()?;
        Ok(Self { name })
    }
}

// ============================================================================
// ACCESS - Check access permission
// ============================================================================

/// ACCESS arguments
#[derive(Debug, Clone)]
pub struct AccessArgs {
    /// Access bits to check
    pub access: u32,
}

impl AccessArgs {
    /// Decode from XDR
    pub fn decode(dec: &mut XdrDecoder) -> std::io::Result<Self> {
        let access = dec.decode_u32()?;
        Ok(Self { access })
    }
}

/// ACCESS result
#[derive(Debug, Clone)]
pub struct AccessRes {
    /// Supported access bits
    pub supported: u32,
    /// Granted access bits
    pub access: u32,
}

impl AccessRes {
    /// Encode to XDR
    pub fn encode(&self, enc: &mut XdrEncoder) {
        enc.encode_u32(self.supported);
        enc.encode_u32(self.access);
    }
}

// ============================================================================
// GETATTR - Get file attributes
// ============================================================================

/// GETATTR arguments
#[derive(Debug, Clone)]
pub struct GetAttrArgs {
    /// Attribute bitmap request
    pub attr_request: Vec<u32>,
}

impl GetAttrArgs {
    /// Decode from XDR
    pub fn decode(dec: &mut XdrDecoder) -> std::io::Result<Self> {
        let count = dec.decode_u32()? as usize;
        let mut attr_request = Vec::with_capacity(count);
        for _ in 0..count {
            attr_request.push(dec.decode_u32()?);
        }
        Ok(Self { attr_request })
    }
}

// ============================================================================
// SETATTR - Set file attributes
// ============================================================================

/// SETATTR arguments
#[derive(Debug, Clone)]
pub struct SetAttrArgs {
    /// Stateid
    pub stateid: StateId,
    /// Attribute values to set
    pub attrs: Bytes,
}

impl SetAttrArgs {
    /// Decode from XDR
    pub fn decode(dec: &mut XdrDecoder) -> std::io::Result<Self> {
        let stateid = StateId::decode(dec)?;
        // Read attrs as raw bytes (bitmap + values)
        Ok(Self {
            stateid,
            attrs: Bytes::new(),
        })
    }
}

// ============================================================================
// READ - Read from file
// ============================================================================

/// READ arguments
#[derive(Debug, Clone)]
pub struct ReadArgs {
    /// Stateid
    pub stateid: StateId,
    /// Offset
    pub offset: u64,
    /// Count
    pub count: u32,
}

impl ReadArgs {
    /// Decode from XDR
    pub fn decode(dec: &mut XdrDecoder) -> std::io::Result<Self> {
        let stateid = StateId::decode(dec)?;
        let offset = dec.decode_u64()?;
        let count = dec.decode_u32()?;
        Ok(Self {
            stateid,
            offset,
            count,
        })
    }
}

/// READ result
#[derive(Debug, Clone)]
pub struct ReadRes {
    /// End of file
    pub eof: bool,
    /// Data
    pub data: Bytes,
}

impl ReadRes {
    /// Encode to XDR
    pub fn encode(&self, enc: &mut XdrEncoder) {
        enc.encode_bool(self.eof);
        enc.encode_opaque(&self.data);
    }
}

// ============================================================================
// WRITE - Write to file
// ============================================================================

/// WRITE arguments
#[derive(Debug, Clone)]
pub struct WriteArgs {
    /// Stateid
    pub stateid: StateId,
    /// Offset
    pub offset: u64,
    /// Stable how
    pub stable: StableHow,
    /// Data
    pub data: Bytes,
}

/// Stability for writes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum StableHow {
    /// Unstable (cached)
    Unstable = 0,
    /// Data sync (data written)
    DataSync = 1,
    /// File sync (data + metadata)
    FileSync = 2,
}

impl TryFrom<u32> for StableHow {
    type Error = NfsStatus;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Unstable),
            1 => Ok(Self::DataSync),
            2 => Ok(Self::FileSync),
            _ => Err(NfsStatus::Inval),
        }
    }
}

impl WriteArgs {
    /// Decode from XDR
    pub fn decode(dec: &mut XdrDecoder) -> std::io::Result<Self> {
        let stateid = StateId::decode(dec)?;
        let offset = dec.decode_u64()?;
        let stable_val = dec.decode_u32()?;
        let stable = StableHow::try_from(stable_val)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid stable"))?;
        let data = Bytes::from(dec.decode_opaque()?);
        Ok(Self {
            stateid,
            offset,
            stable,
            data,
        })
    }
}

/// WRITE result
#[derive(Debug, Clone)]
pub struct WriteRes {
    /// Count written
    pub count: u32,
    /// Committed stability
    pub committed: StableHow,
    /// Write verifier
    pub verifier: [u8; 8],
}

impl WriteRes {
    /// Encode to XDR
    pub fn encode(&self, enc: &mut XdrEncoder) {
        enc.encode_u32(self.count);
        enc.encode_u32(self.committed as u32);
        enc.encode_opaque_fixed(&self.verifier);
    }
}

// ============================================================================
// COMMIT - Commit cached data
// ============================================================================

/// COMMIT arguments
#[derive(Debug, Clone)]
pub struct CommitArgs {
    /// Offset
    pub offset: u64,
    /// Count (0 = all)
    pub count: u32,
}

impl CommitArgs {
    /// Decode from XDR
    pub fn decode(dec: &mut XdrDecoder) -> std::io::Result<Self> {
        let offset = dec.decode_u64()?;
        let count = dec.decode_u32()?;
        Ok(Self { offset, count })
    }
}

/// COMMIT result
#[derive(Debug, Clone)]
pub struct CommitRes {
    /// Write verifier
    pub verifier: [u8; 8],
}

impl CommitRes {
    /// Encode to XDR
    pub fn encode(&self, enc: &mut XdrEncoder) {
        enc.encode_opaque_fixed(&self.verifier);
    }
}

// ============================================================================
// READDIR - Read directory
// ============================================================================

/// READDIR arguments
#[derive(Debug, Clone)]
pub struct ReadDirArgs {
    /// Cookie
    pub cookie: u64,
    /// Cookie verifier
    pub cookieverf: [u8; 8],
    /// Directory count (hint)
    pub dircount: u32,
    /// Max count
    pub maxcount: u32,
    /// Attribute request
    pub attr_request: Vec<u32>,
}

impl ReadDirArgs {
    /// Decode from XDR
    pub fn decode(dec: &mut XdrDecoder) -> std::io::Result<Self> {
        let cookie = dec.decode_u64()?;
        let cookieverf_vec = dec.decode_opaque_fixed(8)?;
        let mut cookieverf = [0u8; 8];
        cookieverf.copy_from_slice(&cookieverf_vec);
        let dircount = dec.decode_u32()?;
        let maxcount = dec.decode_u32()?;

        let count = dec.decode_u32()? as usize;
        let mut attr_request = Vec::with_capacity(count);
        for _ in 0..count {
            attr_request.push(dec.decode_u32()?);
        }

        Ok(Self {
            cookie,
            cookieverf,
            dircount,
            maxcount,
            attr_request,
        })
    }
}

// ============================================================================
// CREATE - Create a non-regular file
// ============================================================================

/// CREATE arguments
#[derive(Debug, Clone)]
pub struct CreateArgs {
    /// Object type
    pub objtype: CreateType,
    /// Object name
    pub name: String,
    /// Create attributes
    pub attrs: Bytes,
}

/// Object type for CREATE
#[derive(Debug, Clone)]
pub enum CreateType {
    /// Symbolic link
    Link(String),
    /// Block device
    BlockDev { specdata: (u32, u32) },
    /// Character device
    CharDev { specdata: (u32, u32) },
    /// Socket
    Sock,
    /// FIFO
    Fifo,
    /// Directory
    Dir,
}

// ============================================================================
// REMOVE - Remove filesystem object
// ============================================================================

/// REMOVE arguments
#[derive(Debug, Clone)]
pub struct RemoveArgs {
    /// Name to remove
    pub target: String,
}

impl RemoveArgs {
    /// Decode from XDR
    pub fn decode(dec: &mut XdrDecoder) -> std::io::Result<Self> {
        let target = dec.decode_string()?;
        Ok(Self { target })
    }
}

// ============================================================================
// RENAME - Rename filesystem object
// ============================================================================

/// RENAME arguments
#[derive(Debug, Clone)]
pub struct RenameArgs {
    /// Old name
    pub oldname: String,
    /// New name
    pub newname: String,
}

impl RenameArgs {
    /// Decode from XDR
    pub fn decode(dec: &mut XdrDecoder) -> std::io::Result<Self> {
        let oldname = dec.decode_string()?;
        let newname = dec.decode_string()?;
        Ok(Self { oldname, newname })
    }
}

// ============================================================================
// SEQUENCE - Session slot sequencing
// ============================================================================

/// SEQUENCE arguments
#[derive(Debug, Clone)]
pub struct SequenceArgs {
    /// Session ID
    pub session_id: [u8; 16],
    /// Sequence ID
    pub sequence_id: u32,
    /// Slot ID
    pub slot_id: u32,
    /// Highest slot ID
    pub highest_slot_id: u32,
    /// Cache this
    pub cache_this: bool,
}

impl SequenceArgs {
    /// Decode from XDR
    pub fn decode(dec: &mut XdrDecoder) -> std::io::Result<Self> {
        let session_vec = dec.decode_opaque_fixed(16)?;
        let mut session_id = [0u8; 16];
        session_id.copy_from_slice(&session_vec);
        let sequence_id = dec.decode_u32()?;
        let slot_id = dec.decode_u32()?;
        let highest_slot_id = dec.decode_u32()?;
        let cache_this = dec.decode_bool()?;

        Ok(Self {
            session_id,
            sequence_id,
            slot_id,
            highest_slot_id,
            cache_this,
        })
    }
}

/// SEQUENCE result
#[derive(Debug, Clone)]
pub struct SequenceRes {
    /// Session ID
    pub session_id: [u8; 16],
    /// Sequence ID
    pub sequence_id: u32,
    /// Slot ID
    pub slot_id: u32,
    /// Highest slot ID
    pub highest_slot_id: u32,
    /// Target highest slot ID
    pub target_highest_slot_id: u32,
    /// Status flags
    pub status_flags: u32,
}

impl SequenceRes {
    /// Encode to XDR
    pub fn encode(&self, enc: &mut XdrEncoder) {
        enc.encode_opaque_fixed(&self.session_id);
        enc.encode_u32(self.sequence_id);
        enc.encode_u32(self.slot_id);
        enc.encode_u32(self.highest_slot_id);
        enc.encode_u32(self.target_highest_slot_id);
        enc.encode_u32(self.status_flags);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_putfh() {
        let mut ctx = CompoundContext::new();
        let args = PutFhArgs {
            object: Nfs4FileHandle::new(vec![1, 2, 3]),
        };

        let result = process_putfh(&mut ctx, &args).unwrap();
        assert_eq!(result.status, NfsStatus::Ok);
        assert!(ctx.current_fh.is_some());
    }

    #[test]
    fn test_putrootfh() {
        let mut ctx = CompoundContext::new();
        let result = process_putrootfh(&mut ctx).unwrap();
        assert_eq!(result.status, NfsStatus::Ok);
        assert!(ctx.current_fh.unwrap().is_root());
    }

    #[test]
    fn test_savefh_restorefh() {
        let mut ctx = CompoundContext::new();
        ctx.current_fh = Some(Nfs4FileHandle::new(vec![1, 2, 3]));

        process_savefh(&mut ctx).unwrap();
        ctx.current_fh = Some(Nfs4FileHandle::new(vec![4, 5, 6]));
        process_restorefh(&mut ctx).unwrap();

        assert_eq!(ctx.current_fh.unwrap().as_bytes(), &[1, 2, 3]);
    }

    #[test]
    fn test_stable_how() {
        assert_eq!(StableHow::try_from(0).unwrap(), StableHow::Unstable);
        assert_eq!(StableHow::try_from(1).unwrap(), StableHow::DataSync);
        assert_eq!(StableHow::try_from(2).unwrap(), StableHow::FileSync);
        assert!(StableHow::try_from(3).is_err());
    }
}
