//! NFS error types

use thiserror::Error;
use warp_gateway_common::GatewayError;

/// NFS error types
#[derive(Debug, Error)]
pub enum NfsError {
    /// RPC error
    #[error("RPC error: {0}")]
    Rpc(String),

    /// XDR encoding/decoding error
    #[error("XDR error: {0}")]
    Xdr(String),

    /// NFS protocol error
    #[error("NFS error: {0}")]
    Protocol(NfsStatus),

    /// Session error
    #[error("session error: {0}")]
    Session(String),

    /// State error (stateids, locks)
    #[error("state error: {0}")]
    State(String),

    /// Export not found
    #[error("export not found: {0}")]
    ExportNotFound(String),

    /// Access denied
    #[error("access denied: {0}")]
    AccessDenied(String),

    /// Gateway error
    #[error("gateway error: {0}")]
    Gateway(#[from] GatewayError),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Storage error
    #[error("storage error: {0}")]
    Storage(String),
}

/// NFS status codes (RFC 8881)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NfsStatus {
    /// Success
    Ok = 0,
    /// Permission denied
    Perm = 1,
    /// No such file or directory
    Noent = 2,
    /// I/O error
    Io = 5,
    /// No such device or address
    Nxio = 6,
    /// File exists
    Exist = 17,
    /// Cross-device link
    Xdev = 18,
    /// Not a directory
    Notdir = 20,
    /// Is a directory
    Isdir = 21,
    /// Invalid argument
    Inval = 22,
    /// File too large
    Fbig = 27,
    /// No space left on device
    Nospc = 28,
    /// Read-only file system
    Rofs = 30,
    /// Too many links
    Mlink = 31,
    /// File name too long
    Nametoolong = 63,
    /// Directory not empty
    Notempty = 66,
    /// Disk quota exceeded
    Dquot = 69,
    /// Stale file handle
    Stale = 70,
    /// Bad file handle
    Badhandle = 10001,
    /// Not sync
    NotSync = 10002,
    /// Bad cookie
    BadCookie = 10003,
    /// Not supported
    Notsupp = 10004,
    /// Too small
    Toosmall = 10005,
    /// Server fault
    Serverfault = 10006,
    /// Grace period in effect
    Grace = 10013,
    /// Lock range conflict
    Denied = 10010,
    /// Expired
    Expired = 10011,
    /// Locked
    Locked = 10012,
    /// Bad stateid
    BadStateid = 10025,
    /// Bad sequence ID
    BadSeqid = 10026,
    /// Not same session
    NotSame = 10027,
    /// Lock owner conflict
    LockOwnerConflict = 10028,
    /// Moved
    Moved = 10019,
    /// No matching layout
    NoMatchingLayout = 10058,
    /// Recall conflict
    RecallConflict = 10061,
    /// Layout unavailable
    LayoutUnavailable = 10063,
    /// Illegal operation
    OpIllegal = 10044,
    /// No filehandle
    NoFileHandle = 10020,
    /// Bad session
    BadSession = 10052,
    /// Restore filehandle error
    RestoreFh = 10030,
    /// Bad type
    BadType = 10007,
    /// Access denied
    Access = 13,
}

impl std::fmt::Display for NfsStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            NfsStatus::Ok => "NFS4_OK",
            NfsStatus::Perm => "NFS4ERR_PERM",
            NfsStatus::Noent => "NFS4ERR_NOENT",
            NfsStatus::Io => "NFS4ERR_IO",
            NfsStatus::Nxio => "NFS4ERR_NXIO",
            NfsStatus::Exist => "NFS4ERR_EXIST",
            NfsStatus::Xdev => "NFS4ERR_XDEV",
            NfsStatus::Notdir => "NFS4ERR_NOTDIR",
            NfsStatus::Isdir => "NFS4ERR_ISDIR",
            NfsStatus::Inval => "NFS4ERR_INVAL",
            NfsStatus::Fbig => "NFS4ERR_FBIG",
            NfsStatus::Nospc => "NFS4ERR_NOSPC",
            NfsStatus::Rofs => "NFS4ERR_ROFS",
            NfsStatus::Mlink => "NFS4ERR_MLINK",
            NfsStatus::Nametoolong => "NFS4ERR_NAMETOOLONG",
            NfsStatus::Notempty => "NFS4ERR_NOTEMPTY",
            NfsStatus::Dquot => "NFS4ERR_DQUOT",
            NfsStatus::Stale => "NFS4ERR_STALE",
            NfsStatus::Badhandle => "NFS4ERR_BADHANDLE",
            NfsStatus::NotSync => "NFS4ERR_NOT_SYNC",
            NfsStatus::BadCookie => "NFS4ERR_BAD_COOKIE",
            NfsStatus::Notsupp => "NFS4ERR_NOTSUPP",
            NfsStatus::Toosmall => "NFS4ERR_TOOSMALL",
            NfsStatus::Serverfault => "NFS4ERR_SERVERFAULT",
            NfsStatus::Grace => "NFS4ERR_GRACE",
            NfsStatus::Denied => "NFS4ERR_DENIED",
            NfsStatus::Expired => "NFS4ERR_EXPIRED",
            NfsStatus::Locked => "NFS4ERR_LOCKED",
            NfsStatus::BadStateid => "NFS4ERR_BAD_STATEID",
            NfsStatus::BadSeqid => "NFS4ERR_BAD_SEQID",
            NfsStatus::NotSame => "NFS4ERR_NOT_SAME",
            NfsStatus::LockOwnerConflict => "NFS4ERR_LOCK_NOTSUPP",
            NfsStatus::Moved => "NFS4ERR_MOVED",
            NfsStatus::NoMatchingLayout => "NFS4ERR_NO_MATCHING_LAYOUT",
            NfsStatus::RecallConflict => "NFS4ERR_RECALLCONFLICT",
            NfsStatus::LayoutUnavailable => "NFS4ERR_LAYOUTUNAVAILABLE",
            NfsStatus::OpIllegal => "NFS4ERR_OP_ILLEGAL",
            NfsStatus::NoFileHandle => "NFS4ERR_NOFILEHANDLE",
            NfsStatus::BadSession => "NFS4ERR_BADSESSION",
            NfsStatus::RestoreFh => "NFS4ERR_RESTOREFH",
            NfsStatus::BadType => "NFS4ERR_BADTYPE",
            NfsStatus::Access => "NFS4ERR_ACCESS",
        };
        write!(f, "{}", name)
    }
}

/// Result type for NFS operations
pub type NfsResult<T> = Result<T, NfsError>;
