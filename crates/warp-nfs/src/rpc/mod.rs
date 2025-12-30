//! Sun RPC implementation for NFS
//!
//! This module provides the RPC layer for NFSv4.1.

pub mod xdr;

use bytes::{Bytes, BytesMut};

/// RPC message type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RpcMsgType {
    /// Request (call)
    Call = 0,
    /// Response (reply)
    Reply = 1,
}

/// RPC reply status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RpcReplyStatus {
    /// Message accepted
    Accepted = 0,
    /// Message denied
    Denied = 1,
}

/// RPC accept status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RpcAcceptStatus {
    /// Success
    Success = 0,
    /// Program unavailable
    ProgUnavail = 1,
    /// Program version mismatch
    ProgMismatch = 2,
    /// Procedure unavailable
    ProcUnavail = 3,
    /// Garbage arguments
    GarbageArgs = 4,
    /// System error
    SystemErr = 5,
}

/// NFS program number
pub const NFS_PROGRAM: u32 = 100003;

/// NFS version 4.1
pub const NFS_V41: u32 = 4;

/// RPC call header
#[derive(Debug, Clone)]
pub struct RpcCallHeader {
    /// Transaction ID
    pub xid: u32,
    /// RPC version (always 2)
    pub rpc_version: u32,
    /// Program number
    pub program: u32,
    /// Program version
    pub version: u32,
    /// Procedure number
    pub procedure: u32,
    /// Credentials flavor
    pub cred_flavor: u32,
    /// Credentials data
    pub cred_data: Bytes,
    /// Verifier flavor
    pub verf_flavor: u32,
    /// Verifier data
    pub verf_data: Bytes,
}

impl RpcCallHeader {
    /// Parse an RPC call header from bytes
    pub fn parse(_data: &[u8]) -> Result<(Self, usize), RpcError> {
        // TODO: Implement XDR parsing
        Err(RpcError::ParseError("not implemented".to_string()))
    }
}

/// RPC reply header
#[derive(Debug, Clone)]
pub struct RpcReplyHeader {
    /// Transaction ID (matches request)
    pub xid: u32,
    /// Reply status
    pub status: RpcReplyStatus,
}

impl RpcReplyHeader {
    /// Encode reply header to bytes
    pub fn encode(&self, _buf: &mut BytesMut) {
        // TODO: Implement XDR encoding
    }
}

/// RPC error
#[derive(Debug, Clone)]
pub enum RpcError {
    /// Parse error
    ParseError(String),
    /// Invalid message
    InvalidMessage(String),
    /// Program unavailable
    ProgUnavail,
    /// Version mismatch
    VersionMismatch { low: u32, high: u32 },
    /// Procedure unavailable
    ProcUnavail,
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcError::ParseError(msg) => write!(f, "parse error: {}", msg),
            RpcError::InvalidMessage(msg) => write!(f, "invalid message: {}", msg),
            RpcError::ProgUnavail => write!(f, "program unavailable"),
            RpcError::VersionMismatch { low, high } => {
                write!(f, "version mismatch: supported {}-{}", low, high)
            }
            RpcError::ProcUnavail => write!(f, "procedure unavailable"),
        }
    }
}

impl std::error::Error for RpcError {}
