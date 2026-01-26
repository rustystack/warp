//! WireGuard error types

use thiserror::Error;

/// Errors that can occur during WireGuard operations
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum WireGuardError {
    /// The destination buffer is too small for the output
    #[error("destination buffer too small")]
    DestinationBufferTooSmall,

    /// The packet is malformed or invalid
    #[error("invalid packet")]
    InvalidPacket,

    /// No active session exists
    #[error("no active session")]
    NoSession,

    /// Session has expired and needs rekey
    #[error("session expired")]
    SessionExpired,

    /// Decryption failed (authentication failed)
    #[error("decryption failed")]
    DecryptionFailed,

    /// Encryption failed
    #[error("encryption failed")]
    EncryptionFailed,

    /// Handshake failed
    #[error("handshake failed")]
    HandshakeFailed,

    /// Counter replay detected
    #[error("replay attack detected")]
    ReplayAttack,

    /// Invalid public key
    #[error("invalid public key")]
    InvalidPublicKey,

    /// Wrong message type received
    #[error("wrong message type")]
    WrongMessageType,

    /// Handshake already in progress
    #[error("handshake in progress")]
    HandshakeInProgress,

    /// Rate limit exceeded (cookie required)
    #[error("rate limited")]
    RateLimited,
}
