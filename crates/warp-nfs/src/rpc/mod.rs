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
    pub fn parse(data: &[u8]) -> Result<(Self, usize), RpcError> {
        use xdr::XdrDecoder;

        let mut decoder = XdrDecoder::new(data);

        // Parse XID
        let xid = decoder
            .decode_u32()
            .map_err(|e| RpcError::ParseError(format!("failed to decode xid: {}", e)))?;

        // Parse message type
        let msg_type = decoder
            .decode_u32()
            .map_err(|e| RpcError::ParseError(format!("failed to decode msg_type: {}", e)))?;

        if msg_type != RpcMsgType::Call as u32 {
            return Err(RpcError::InvalidMessage(format!(
                "expected CALL (0), got {}",
                msg_type
            )));
        }

        // Parse RPC version
        let rpc_version = decoder
            .decode_u32()
            .map_err(|e| RpcError::ParseError(format!("failed to decode rpc_version: {}", e)))?;

        if rpc_version != 2 {
            return Err(RpcError::VersionMismatch { low: 2, high: 2 });
        }

        // Parse program, version, procedure
        let program = decoder
            .decode_u32()
            .map_err(|e| RpcError::ParseError(format!("failed to decode program: {}", e)))?;
        let version = decoder
            .decode_u32()
            .map_err(|e| RpcError::ParseError(format!("failed to decode version: {}", e)))?;
        let procedure = decoder
            .decode_u32()
            .map_err(|e| RpcError::ParseError(format!("failed to decode procedure: {}", e)))?;

        // Parse credentials
        let cred_flavor = decoder
            .decode_u32()
            .map_err(|e| RpcError::ParseError(format!("failed to decode cred_flavor: {}", e)))?;
        let cred_data = Bytes::from(
            decoder
                .decode_opaque()
                .map_err(|e| RpcError::ParseError(format!("failed to decode cred_data: {}", e)))?,
        );

        // Parse verifier
        let verf_flavor = decoder
            .decode_u32()
            .map_err(|e| RpcError::ParseError(format!("failed to decode verf_flavor: {}", e)))?;
        let verf_data = Bytes::from(
            decoder
                .decode_opaque()
                .map_err(|e| RpcError::ParseError(format!("failed to decode verf_data: {}", e)))?,
        );

        // Calculate bytes consumed
        let bytes_consumed = data.len() - decoder.remaining();

        Ok((
            Self {
                xid,
                rpc_version,
                program,
                version,
                procedure,
                cred_flavor,
                cred_data,
                verf_flavor,
                verf_data,
            },
            bytes_consumed,
        ))
    }

    /// Create a new RPC call header
    pub fn new(program: u32, version: u32, procedure: u32) -> Self {
        Self {
            xid: rand::random(),
            rpc_version: 2,
            program,
            version,
            procedure,
            cred_flavor: 0, // AUTH_NONE
            cred_data: Bytes::new(),
            verf_flavor: 0, // AUTH_NONE
            verf_data: Bytes::new(),
        }
    }

    /// Encode RPC call header to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        use xdr::XdrEncoder;

        let mut encoder = XdrEncoder::new();
        encoder.encode_u32(self.xid);
        encoder.encode_u32(RpcMsgType::Call as u32);
        encoder.encode_u32(self.rpc_version);
        encoder.encode_u32(self.program);
        encoder.encode_u32(self.version);
        encoder.encode_u32(self.procedure);
        encoder.encode_u32(self.cred_flavor);
        encoder.encode_opaque(&self.cred_data);
        encoder.encode_u32(self.verf_flavor);
        encoder.encode_opaque(&self.verf_data);

        buf.extend_from_slice(&encoder.finish());
    }
}

/// RPC reply header
#[derive(Debug, Clone)]
pub struct RpcReplyHeader {
    /// Transaction ID (matches request)
    pub xid: u32,
    /// Reply status
    pub status: RpcReplyStatus,
    /// Accept status (if accepted)
    pub accept_status: Option<RpcAcceptStatus>,
    /// Reject reason (if denied)
    pub reject_reason: Option<RpcRejectReason>,
    /// Verifier flavor
    pub verf_flavor: u32,
    /// Verifier data
    pub verf_data: Bytes,
}

/// RPC reject reason
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RpcRejectReason {
    /// RPC version mismatch
    RpcMismatch = 0,
    /// Authentication error
    AuthError = 1,
}

impl RpcReplyHeader {
    /// Create a new successful reply header
    pub fn success(xid: u32) -> Self {
        Self {
            xid,
            status: RpcReplyStatus::Accepted,
            accept_status: Some(RpcAcceptStatus::Success),
            reject_reason: None,
            verf_flavor: 0, // AUTH_NONE
            verf_data: Bytes::new(),
        }
    }

    /// Create an error reply header
    pub fn error(xid: u32, status: RpcAcceptStatus) -> Self {
        Self {
            xid,
            status: RpcReplyStatus::Accepted,
            accept_status: Some(status),
            reject_reason: None,
            verf_flavor: 0,
            verf_data: Bytes::new(),
        }
    }

    /// Create a denied reply header
    pub fn denied(xid: u32, reason: RpcRejectReason) -> Self {
        Self {
            xid,
            status: RpcReplyStatus::Denied,
            accept_status: None,
            reject_reason: Some(reason),
            verf_flavor: 0,
            verf_data: Bytes::new(),
        }
    }

    /// Encode reply header to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        use xdr::XdrEncoder;

        let mut encoder = XdrEncoder::new();
        encoder.encode_u32(self.xid);
        encoder.encode_u32(RpcMsgType::Reply as u32);
        encoder.encode_u32(self.status as u32);

        match self.status {
            RpcReplyStatus::Accepted => {
                // Encode verifier
                encoder.encode_u32(self.verf_flavor);
                encoder.encode_opaque(&self.verf_data);

                // Encode accept status
                if let Some(accept_status) = self.accept_status {
                    encoder.encode_u32(accept_status as u32);
                }
            }
            RpcReplyStatus::Denied => {
                if let Some(reject_reason) = self.reject_reason {
                    encoder.encode_u32(reject_reason as u32);
                    if reject_reason == RpcRejectReason::RpcMismatch {
                        // Encode supported RPC versions
                        encoder.encode_u32(2); // low
                        encoder.encode_u32(2); // high
                    }
                }
            }
        }

        buf.extend_from_slice(&encoder.finish());
    }

    /// Parse an RPC reply header from bytes
    pub fn parse(data: &[u8]) -> Result<(Self, usize), RpcError> {
        use xdr::XdrDecoder;

        let mut decoder = XdrDecoder::new(data);

        let xid = decoder
            .decode_u32()
            .map_err(|e| RpcError::ParseError(format!("failed to decode xid: {}", e)))?;

        let msg_type = decoder
            .decode_u32()
            .map_err(|e| RpcError::ParseError(format!("failed to decode msg_type: {}", e)))?;

        if msg_type != RpcMsgType::Reply as u32 {
            return Err(RpcError::InvalidMessage(format!(
                "expected REPLY (1), got {}",
                msg_type
            )));
        }

        let reply_status = decoder
            .decode_u32()
            .map_err(|e| RpcError::ParseError(format!("failed to decode reply_status: {}", e)))?;

        let (status, accept_status, reject_reason, verf_flavor, verf_data) = match reply_status {
            0 => {
                // MSG_ACCEPTED
                let verf_flavor = decoder.decode_u32().map_err(|e| {
                    RpcError::ParseError(format!("failed to decode verf_flavor: {}", e))
                })?;
                let verf_data = Bytes::from(decoder.decode_opaque().map_err(|e| {
                    RpcError::ParseError(format!("failed to decode verf_data: {}", e))
                })?);
                let accept_status = decoder.decode_u32().map_err(|e| {
                    RpcError::ParseError(format!("failed to decode accept_status: {}", e))
                })?;
                let accept = match accept_status {
                    0 => RpcAcceptStatus::Success,
                    1 => RpcAcceptStatus::ProgUnavail,
                    2 => RpcAcceptStatus::ProgMismatch,
                    3 => RpcAcceptStatus::ProcUnavail,
                    4 => RpcAcceptStatus::GarbageArgs,
                    5 => RpcAcceptStatus::SystemErr,
                    _ => RpcAcceptStatus::SystemErr,
                };
                (
                    RpcReplyStatus::Accepted,
                    Some(accept),
                    None,
                    verf_flavor,
                    verf_data,
                )
            }
            1 => {
                // MSG_DENIED
                let reject = decoder.decode_u32().map_err(|e| {
                    RpcError::ParseError(format!("failed to decode reject_reason: {}", e))
                })?;
                let reason = match reject {
                    0 => RpcRejectReason::RpcMismatch,
                    1 => RpcRejectReason::AuthError,
                    _ => RpcRejectReason::AuthError,
                };
                (
                    RpcReplyStatus::Denied,
                    None,
                    Some(reason),
                    0,
                    Bytes::new(),
                )
            }
            _ => {
                return Err(RpcError::InvalidMessage(format!(
                    "invalid reply status: {}",
                    reply_status
                )));
            }
        };

        let bytes_consumed = data.len() - decoder.remaining();

        Ok((
            Self {
                xid,
                status,
                accept_status,
                reject_reason,
                verf_flavor,
                verf_data,
            },
            bytes_consumed,
        ))
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
    VersionMismatch {
        /// Lowest supported version
        low: u32,
        /// Highest supported version
        high: u32,
    },
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rpc_call_header_parse() {
        // Build a simple RPC CALL message
        let mut encoder = xdr::XdrEncoder::new();
        encoder.encode_u32(0x12345678); // XID
        encoder.encode_u32(0); // CALL
        encoder.encode_u32(2); // RPC version
        encoder.encode_u32(NFS_PROGRAM); // Program
        encoder.encode_u32(NFS_V41); // Version
        encoder.encode_u32(1); // Procedure
        encoder.encode_u32(0); // Cred flavor (AUTH_NONE)
        encoder.encode_opaque(&[]); // Cred data
        encoder.encode_u32(0); // Verf flavor (AUTH_NONE)
        encoder.encode_opaque(&[]); // Verf data

        let data = encoder.finish();
        let (header, consumed) = RpcCallHeader::parse(&data).unwrap();

        assert_eq!(header.xid, 0x12345678);
        assert_eq!(header.rpc_version, 2);
        assert_eq!(header.program, NFS_PROGRAM);
        assert_eq!(header.version, NFS_V41);
        assert_eq!(header.procedure, 1);
        assert!(consumed > 0);
    }

    #[test]
    fn test_rpc_call_header_encode() {
        let header = RpcCallHeader {
            xid: 0xABCD1234,
            rpc_version: 2,
            program: NFS_PROGRAM,
            version: NFS_V41,
            procedure: 1,
            cred_flavor: 0,
            cred_data: Bytes::new(),
            verf_flavor: 0,
            verf_data: Bytes::new(),
        };

        let mut buf = BytesMut::new();
        header.encode(&mut buf);

        // Parse it back
        let (parsed, _) = RpcCallHeader::parse(&buf).unwrap();
        assert_eq!(parsed.xid, header.xid);
        assert_eq!(parsed.program, header.program);
        assert_eq!(parsed.version, header.version);
    }

    #[test]
    fn test_rpc_reply_header_success() {
        let reply = RpcReplyHeader::success(0x12345678);

        let mut buf = BytesMut::new();
        reply.encode(&mut buf);

        let (parsed, _) = RpcReplyHeader::parse(&buf).unwrap();
        assert_eq!(parsed.xid, 0x12345678);
        assert_eq!(parsed.status, RpcReplyStatus::Accepted);
        assert_eq!(parsed.accept_status, Some(RpcAcceptStatus::Success));
    }

    #[test]
    fn test_rpc_reply_header_error() {
        let reply = RpcReplyHeader::error(0xABCD, RpcAcceptStatus::ProgUnavail);

        let mut buf = BytesMut::new();
        reply.encode(&mut buf);

        let (parsed, _) = RpcReplyHeader::parse(&buf).unwrap();
        assert_eq!(parsed.xid, 0xABCD);
        assert_eq!(parsed.status, RpcReplyStatus::Accepted);
        assert_eq!(parsed.accept_status, Some(RpcAcceptStatus::ProgUnavail));
    }

    #[test]
    fn test_rpc_call_header_invalid_version() {
        let mut encoder = xdr::XdrEncoder::new();
        encoder.encode_u32(1); // XID
        encoder.encode_u32(0); // CALL
        encoder.encode_u32(3); // Invalid RPC version

        let data = encoder.finish();
        let result = RpcCallHeader::parse(&data);
        assert!(matches!(result, Err(RpcError::VersionMismatch { .. })));
    }

    #[test]
    fn test_rpc_call_header_wrong_msg_type() {
        let mut encoder = xdr::XdrEncoder::new();
        encoder.encode_u32(1); // XID
        encoder.encode_u32(1); // REPLY (wrong type for RpcCallHeader)

        let data = encoder.finish();
        let result = RpcCallHeader::parse(&data);
        assert!(matches!(result, Err(RpcError::InvalidMessage(_))));
    }

    #[test]
    fn test_rpc_call_header_new() {
        let header = RpcCallHeader::new(NFS_PROGRAM, NFS_V41, 1);
        assert_eq!(header.rpc_version, 2);
        assert_eq!(header.program, NFS_PROGRAM);
        assert_eq!(header.version, NFS_V41);
        assert_eq!(header.procedure, 1);
    }
}
