//! SMB error types
//!
//! Defines error types and NTSTATUS codes for SMB protocol.

use std::io;

use thiserror::Error;

/// SMB-specific result type
pub type SmbResult<T> = Result<T, SmbError>;

/// SMB error types
#[derive(Debug, Error)]
pub enum SmbError {
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Protocol error
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// NTSTATUS error
    #[error("NTSTATUS: {0:?}")]
    NtStatus(NtStatus),

    /// Authentication error
    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    /// Access denied
    #[error("Access denied")]
    AccessDenied,

    /// Share not found
    #[error("Share not found: {0}")]
    ShareNotFound(String),

    /// File not found
    #[error("File not found: {0}")]
    FileNotFound(String),

    /// Invalid parameter
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    /// Not supported
    #[error("Not supported: {0}")]
    NotSupported(String),
}

impl From<NtStatus> for SmbError {
    fn from(status: NtStatus) -> Self {
        SmbError::NtStatus(status)
    }
}

/// NT Status codes (subset commonly used in SMB)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NtStatus {
    /// Success
    Success = 0x00000000,
    /// Pending
    Pending = 0x00000103,
    /// Buffer overflow (warning, not error)
    BufferOverflow = 0x80000005,
    /// No more files
    NoMoreFiles = 0x80000006,
    /// Invalid handle
    InvalidHandle = 0xC0000008,
    /// Invalid parameter
    InvalidParameter = 0xC000000D,
    /// No such file
    NoSuchFile = 0xC000000F,
    /// End of file
    EndOfFile = 0xC0000011,
    /// More processing required
    MoreProcessingRequired = 0xC0000016,
    /// Access denied
    AccessDenied = 0xC0000022,
    /// Buffer too small
    BufferTooSmall = 0xC0000023,
    /// Object name invalid
    ObjectNameInvalid = 0xC0000033,
    /// Object name not found
    ObjectNameNotFound = 0xC0000034,
    /// Object name collision
    ObjectNameCollision = 0xC0000035,
    /// Object path invalid
    ObjectPathInvalid = 0xC0000039,
    /// Object path not found
    ObjectPathNotFound = 0xC000003A,
    /// Sharing violation
    SharingViolation = 0xC0000043,
    /// File lock conflict
    FileLockConflict = 0xC0000054,
    /// Lock not granted
    LockNotGranted = 0xC0000055,
    /// Delete pending
    DeletePending = 0xC0000056,
    /// Privilege not held
    PrivilegeNotHeld = 0xC0000061,
    /// File is a directory
    FileIsDirectory = 0xC00000BA,
    /// Not supported
    NotSupported = 0xC00000BB,
    /// Bad network name (share not found)
    BadNetworkName = 0xC00000CC,
    /// Network access denied
    NetworkAccessDenied = 0xC00000CA,
    /// User session deleted
    UserSessionDeleted = 0xC0000203,
    /// Network session expired
    NetworkSessionExpired = 0xC000035C,
    /// Not a directory
    NotADirectory = 0xC0000103,
    /// File closed
    FileClosed = 0xC0000128,
    /// Directory not empty
    DirectoryNotEmpty = 0xC0000101,
    /// Cancelled
    Cancelled = 0xC0000120,
    /// Oplock not granted
    OplockNotGranted = 0xC00000E2,
    /// Invalid oplock protocol
    InvalidOplockProtocol = 0xC00000E3,
    /// Request not accepted
    RequestNotAccepted = 0xC00000D0,
    /// Invalid SMB
    InvalidSmb = 0x00010002,
    /// SMB bad TID
    SmbBadTid = 0x00050002,
    /// SMB bad command
    SmbBadCommand = 0x00160002,
    /// SMB bad UID
    SmbBadUid = 0x005B0002,
    /// Logon failure
    LogonFailure = 0xC000006D,
    /// Logon type not granted
    LogonTypeNotGranted = 0xC000015B,
    /// Insufficient resources
    InsufficientResources = 0xC000009A,
    /// Pipe disconnected
    PipeDisconnected = 0xC00000B0,
    /// Pipe closing
    PipeClosing = 0xC00000B1,
    /// Pipe empty
    PipeEmpty = 0xC00000D9,
    /// IO timeout
    IoTimeout = 0xC00000B5,
}

impl NtStatus {
    /// Check if this is a success status
    pub fn is_success(&self) -> bool {
        (*self as u32) < 0x40000000
    }

    /// Check if this is a warning (informational)
    pub fn is_warning(&self) -> bool {
        let val = *self as u32;
        val >= 0x40000000 && val < 0x80000000
    }

    /// Check if this is an error
    pub fn is_error(&self) -> bool {
        (*self as u32) >= 0x80000000
    }

    /// Get the raw value
    pub fn as_u32(&self) -> u32 {
        *self as u32
    }

    /// Create from raw value
    pub fn from_u32(val: u32) -> Self {
        match val {
            0x00000000 => Self::Success,
            0x00000103 => Self::Pending,
            0x80000005 => Self::BufferOverflow,
            0x80000006 => Self::NoMoreFiles,
            0xC0000008 => Self::InvalidHandle,
            0xC000000D => Self::InvalidParameter,
            0xC000000F => Self::NoSuchFile,
            0xC0000011 => Self::EndOfFile,
            0xC0000016 => Self::MoreProcessingRequired,
            0xC0000022 => Self::AccessDenied,
            0xC0000023 => Self::BufferTooSmall,
            0xC0000033 => Self::ObjectNameInvalid,
            0xC0000034 => Self::ObjectNameNotFound,
            0xC0000035 => Self::ObjectNameCollision,
            0xC0000039 => Self::ObjectPathInvalid,
            0xC000003A => Self::ObjectPathNotFound,
            0xC0000043 => Self::SharingViolation,
            0xC0000054 => Self::FileLockConflict,
            0xC0000055 => Self::LockNotGranted,
            0xC0000056 => Self::DeletePending,
            0xC0000061 => Self::PrivilegeNotHeld,
            0xC00000BA => Self::FileIsDirectory,
            0xC00000BB => Self::NotSupported,
            0xC00000CC => Self::BadNetworkName,
            0xC00000CA => Self::NetworkAccessDenied,
            0xC0000203 => Self::UserSessionDeleted,
            0xC000035C => Self::NetworkSessionExpired,
            0xC0000103 => Self::NotADirectory,
            0xC0000128 => Self::FileClosed,
            0xC0000101 => Self::DirectoryNotEmpty,
            0xC0000120 => Self::Cancelled,
            0xC00000E2 => Self::OplockNotGranted,
            0xC00000E3 => Self::InvalidOplockProtocol,
            0xC00000D0 => Self::RequestNotAccepted,
            0x00010002 => Self::InvalidSmb,
            0x00050002 => Self::SmbBadTid,
            0x00160002 => Self::SmbBadCommand,
            0x005B0002 => Self::SmbBadUid,
            0xC000006D => Self::LogonFailure,
            0xC000015B => Self::LogonTypeNotGranted,
            0xC000009A => Self::InsufficientResources,
            0xC00000B0 => Self::PipeDisconnected,
            0xC00000B1 => Self::PipeClosing,
            0xC00000D9 => Self::PipeEmpty,
            0xC00000B5 => Self::IoTimeout,
            _ => Self::InvalidParameter,
        }
    }
}

impl std::fmt::Display for NtStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} (0x{:08X})", self, *self as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntstatus_success() {
        assert!(NtStatus::Success.is_success());
        assert!(!NtStatus::Success.is_error());
    }

    #[test]
    fn test_ntstatus_error() {
        assert!(NtStatus::AccessDenied.is_error());
        assert!(!NtStatus::AccessDenied.is_success());
    }

    #[test]
    fn test_ntstatus_from_u32() {
        assert_eq!(NtStatus::from_u32(0xC0000022), NtStatus::AccessDenied);
        assert_eq!(NtStatus::from_u32(0x00000000), NtStatus::Success);
    }
}
