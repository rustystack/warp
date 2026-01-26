//! Noise protocol implementation for WireGuard
//!
//! This module implements the Noise_IKpsk2 protocol as specified by WireGuard.

#![allow(clippy::collapsible_if)]
#![allow(clippy::unnecessary_map_or)]

mod crypto;
mod errors;
mod handshake;
mod session;

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tracing::{debug, trace, warn};
use x25519_dalek::{PublicKey, StaticSecret};

pub use errors::WireGuardError;
use handshake::Handshake;
use session::Session;

/// Result of processing a WireGuard packet
#[derive(Debug)]
pub enum TunnResult<'a> {
    /// No action needed
    Done,

    /// Error occurred during processing
    Err(WireGuardError),

    /// Data should be written to the network (handshake response, keepalive)
    WriteToNetwork(&'a mut [u8]),

    /// IPv4 data should be written to the tunnel interface
    WriteToTunnelV4(&'a mut [u8], IpAddr),

    /// IPv6 data should be written to the tunnel interface
    WriteToTunnelV6(&'a mut [u8], IpAddr),
}

/// WireGuard message types
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// Handshake initiation
    HandshakeInit = 1,
    /// Handshake response
    HandshakeResponse = 2,
    /// Cookie reply
    CookieReply = 3,
    /// Encrypted transport data
    TransportData = 4,
}

impl TryFrom<u8> for MessageType {
    type Error = WireGuardError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::HandshakeInit),
            2 => Ok(Self::HandshakeResponse),
            3 => Ok(Self::CookieReply),
            4 => Ok(Self::TransportData),
            _ => Err(WireGuardError::InvalidPacket),
        }
    }
}

/// WireGuard tunnel state
pub struct Tunn {
    /// Our static private key
    static_private: StaticSecret,

    /// Peer's static public key
    peer_static_public: PublicKey,

    /// Optional preshared key (for post-quantum resistance)
    preshared_key: Option<[u8; 32]>,

    /// Current handshake state
    handshake: Mutex<Handshake>,

    /// Current active session for encryption
    current_session: Mutex<Option<Session>>,

    /// Previous session (kept for rekey transitions)
    previous_session: Mutex<Option<Session>>,

    /// Next session (being established)
    next_session: Mutex<Option<Session>>,

    /// Tunnel index (for sender identification)
    tunnel_index: u32,

    /// Counter for outgoing packets
    tx_counter: AtomicU64,

    /// Persistent keepalive interval
    keepalive_interval: Option<Duration>,

    /// Time of last handshake
    last_handshake: Mutex<Option<Instant>>,

    /// Time of last received data
    last_received: Mutex<Option<Instant>>,

    /// Scratch buffer for packet processing
    scratch: Mutex<Vec<u8>>,
}

impl Tunn {
    /// Create a new WireGuard tunnel
    ///
    /// # Arguments
    ///
    /// * `static_private` - Our static private key
    /// * `peer_static_public` - Peer's static public key
    /// * `preshared_key` - Optional preshared key for additional security
    /// * `keepalive` - Optional persistent keepalive interval in seconds
    /// * `tunnel_index` - Index for this tunnel (used in sender field)
    pub fn new(
        static_private: StaticSecret,
        peer_static_public: PublicKey,
        preshared_key: Option<[u8; 32]>,
        keepalive: Option<u16>,
        tunnel_index: u32,
    ) -> Result<Self, WireGuardError> {
        let our_public = PublicKey::from(&static_private);

        Ok(Self {
            handshake: Mutex::new(Handshake::new(
                static_private.clone(),
                our_public,
                peer_static_public,
                preshared_key,
            )),
            static_private,
            peer_static_public,
            preshared_key,
            current_session: Mutex::new(None),
            previous_session: Mutex::new(None),
            next_session: Mutex::new(None),
            tunnel_index,
            tx_counter: AtomicU64::new(0),
            keepalive_interval: keepalive.map(|k| Duration::from_secs(k as u64)),
            last_handshake: Mutex::new(None),
            last_received: Mutex::new(None),
            scratch: Mutex::new(vec![0u8; 65536]),
        })
    }

    /// Get our static public key
    pub fn static_public(&self) -> PublicKey {
        PublicKey::from(&self.static_private)
    }

    /// Get peer's static public key
    pub fn peer_static_public(&self) -> &PublicKey {
        &self.peer_static_public
    }

    /// Check if a handshake is needed
    pub fn needs_handshake(&self) -> bool {
        let session = self.current_session.lock();
        session.is_none() || session.as_ref().map_or(true, |s| s.is_expired())
    }

    /// Initiate a handshake
    ///
    /// Returns bytes to send to the peer to initiate a handshake.
    pub fn format_handshake_initiation<'a>(
        &self,
        dst: &'a mut [u8],
        _include_jitter: bool,
    ) -> TunnResult<'a> {
        if dst.len() < 148 {
            return TunnResult::Err(WireGuardError::DestinationBufferTooSmall);
        }

        let mut handshake = self.handshake.lock();

        match handshake.create_initiation(self.tunnel_index, dst) {
            Ok(len) => {
                debug!(
                    tunnel_index = self.tunnel_index,
                    "Created handshake initiation"
                );
                TunnResult::WriteToNetwork(&mut dst[..len])
            }
            Err(e) => {
                warn!(error = ?e, "Failed to create handshake initiation");
                TunnResult::Err(e)
            }
        }
    }

    /// Process an incoming WireGuard packet
    ///
    /// # Arguments
    ///
    /// * `src` - Optional source IP address
    /// * `packet` - The incoming packet data
    /// * `dst` - Buffer for any response data
    ///
    /// # Returns
    ///
    /// The result of processing the packet
    pub fn decapsulate<'a>(
        &self,
        src: Option<IpAddr>,
        packet: &[u8],
        dst: &'a mut [u8],
    ) -> TunnResult<'a> {
        if packet.len() < 4 {
            return TunnResult::Err(WireGuardError::InvalidPacket);
        }

        let msg_type = match MessageType::try_from(packet[0]) {
            Ok(t) => t,
            Err(e) => return TunnResult::Err(e),
        };

        trace!(msg_type = ?msg_type, len = packet.len(), "Processing incoming packet");

        match msg_type {
            MessageType::HandshakeInit => self.handle_handshake_init(packet, dst),
            MessageType::HandshakeResponse => self.handle_handshake_response(packet, dst),
            MessageType::CookieReply => self.handle_cookie_reply(packet),
            MessageType::TransportData => self.handle_transport_data(src, packet, dst),
        }
    }

    /// Encrypt and encapsulate data for sending
    ///
    /// # Arguments
    ///
    /// * `src` - The plaintext data to send
    /// * `dst` - Buffer for the encrypted packet
    ///
    /// # Returns
    ///
    /// The result of encapsulation
    pub fn encapsulate<'a>(&self, src: &[u8], dst: &'a mut [u8]) -> TunnResult<'a> {
        let session = self.current_session.lock();

        let session = match session.as_ref() {
            Some(s) if !s.is_expired() => s,
            _ => {
                drop(session);
                // Need handshake first
                return self.format_handshake_initiation(dst, false);
            }
        };

        // WireGuard transport data format:
        // - Type (1 byte): 4
        // - Reserved (3 bytes): 0
        // - Receiver index (4 bytes)
        // - Counter (8 bytes)
        // - Encrypted data (variable + 16 byte tag)

        let required_len = 16 + src.len() + 16; // header + data + AEAD tag
        if dst.len() < required_len {
            return TunnResult::Err(WireGuardError::DestinationBufferTooSmall);
        }

        let counter = self.tx_counter.fetch_add(1, Ordering::SeqCst);

        // Build header
        dst[0] = MessageType::TransportData as u8;
        dst[1..4].copy_from_slice(&[0, 0, 0]); // reserved
        dst[4..8].copy_from_slice(&session.peer_index().to_le_bytes());
        dst[8..16].copy_from_slice(&counter.to_le_bytes());

        // Encrypt data
        match session.encrypt(counter, src, &mut dst[16..]) {
            Ok(len) => {
                trace!(len = 16 + len, counter, "Encapsulated data");
                TunnResult::WriteToNetwork(&mut dst[..16 + len])
            }
            Err(e) => TunnResult::Err(e),
        }
    }

    /// Update the timers and return any required action
    pub fn update_timers<'a>(&self, dst: &'a mut [u8]) -> TunnResult<'a> {
        // Check if we need to send a keepalive
        if let Some(interval) = self.keepalive_interval {
            let last_received = *self.last_received.lock();
            if let Some(last) = last_received {
                if last.elapsed() > interval {
                    // Send empty keepalive
                    return self.encapsulate(&[], dst);
                }
            }
        }

        // Check if handshake is needed
        if self.needs_handshake() {
            return self.format_handshake_initiation(dst, false);
        }

        TunnResult::Done
    }

    /// Get time since last handshake
    pub fn time_since_last_handshake(&self) -> Option<Duration> {
        self.last_handshake.lock().map(|t| t.elapsed())
    }

    /// Get persistent keepalive interval
    pub fn persistent_keepalive(&self) -> Option<Duration> {
        self.keepalive_interval
    }

    fn handle_handshake_init<'a>(&self, packet: &[u8], dst: &'a mut [u8]) -> TunnResult<'a> {
        if packet.len() < 148 {
            return TunnResult::Err(WireGuardError::InvalidPacket);
        }

        if dst.len() < 92 {
            return TunnResult::Err(WireGuardError::DestinationBufferTooSmall);
        }

        let mut handshake = self.handshake.lock();

        match handshake.consume_initiation(packet) {
            Ok(()) => {
                // Create response
                match handshake.create_response(self.tunnel_index, dst) {
                    Ok(len) => {
                        // Derive session keys
                        if let Some(session) = handshake.derive_session(false) {
                            *self.previous_session.lock() = self.current_session.lock().take();
                            *self.current_session.lock() = Some(session);
                            *self.last_handshake.lock() = Some(Instant::now());
                            debug!("Handshake completed (responder)");
                        }
                        TunnResult::WriteToNetwork(&mut dst[..len])
                    }
                    Err(e) => TunnResult::Err(e),
                }
            }
            Err(e) => TunnResult::Err(e),
        }
    }

    fn handle_handshake_response<'a>(&self, packet: &[u8], dst: &'a mut [u8]) -> TunnResult<'a> {
        if packet.len() < 92 {
            return TunnResult::Err(WireGuardError::InvalidPacket);
        }

        let mut handshake = self.handshake.lock();

        match handshake.consume_response(packet) {
            Ok(()) => {
                // Derive session keys
                if let Some(session) = handshake.derive_session(true) {
                    *self.previous_session.lock() = self.current_session.lock().take();
                    *self.current_session.lock() = Some(session);
                    *self.last_handshake.lock() = Some(Instant::now());
                    debug!("Handshake completed (initiator)");

                    // Send empty packet to confirm
                    return self.encapsulate(&[], dst);
                }
                TunnResult::Done
            }
            Err(e) => TunnResult::Err(e),
        }
    }

    fn handle_cookie_reply(&self, packet: &[u8]) -> TunnResult<'static> {
        if packet.len() < 64 {
            return TunnResult::Err(WireGuardError::InvalidPacket);
        }

        // Cookie handling would go here
        debug!("Received cookie reply");
        TunnResult::Done
    }

    fn handle_transport_data<'a>(
        &self,
        src: Option<IpAddr>,
        packet: &[u8],
        dst: &'a mut [u8],
    ) -> TunnResult<'a> {
        if packet.len() < 32 {
            // Minimum: 16 byte header + 16 byte tag
            return TunnResult::Err(WireGuardError::InvalidPacket);
        }

        // Parse header
        let receiver_index = u32::from_le_bytes([packet[4], packet[5], packet[6], packet[7]]);
        let counter = u64::from_le_bytes([
            packet[8], packet[9], packet[10], packet[11], packet[12], packet[13], packet[14],
            packet[15],
        ]);

        let encrypted = &packet[16..];

        // Try current session
        {
            let session = self.current_session.lock();
            if let Some(ref s) = *session {
                if s.our_index() == receiver_index {
                    return self.decrypt_transport(s, counter, encrypted, dst, src);
                }
            }
        }

        // Try previous session
        {
            let session = self.previous_session.lock();
            if let Some(ref s) = *session {
                if s.our_index() == receiver_index {
                    return self.decrypt_transport(s, counter, encrypted, dst, src);
                }
            }
        }

        // Try next session
        {
            let session = self.next_session.lock();
            if let Some(ref s) = *session {
                if s.our_index() == receiver_index {
                    return self.decrypt_transport(s, counter, encrypted, dst, src);
                }
            }
        }

        TunnResult::Err(WireGuardError::NoSession)
    }

    fn decrypt_transport<'a>(
        &self,
        session: &Session,
        counter: u64,
        encrypted: &[u8],
        dst: &'a mut [u8],
        src: Option<IpAddr>,
    ) -> TunnResult<'a> {
        let plaintext_len = encrypted.len().saturating_sub(16);
        if dst.len() < plaintext_len {
            return TunnResult::Err(WireGuardError::DestinationBufferTooSmall);
        }

        match session.decrypt(counter, encrypted, &mut dst[..plaintext_len]) {
            Ok(len) => {
                *self.last_received.lock() = Some(Instant::now());

                if len == 0 {
                    // Keepalive
                    trace!("Received keepalive");
                    return TunnResult::Done;
                }

                // Determine IP version from first nibble
                let ip_version = dst[0] >> 4;
                let src_addr = src.unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));

                match ip_version {
                    4 => TunnResult::WriteToTunnelV4(&mut dst[..len], src_addr),
                    6 => TunnResult::WriteToTunnelV6(&mut dst[..len], src_addr),
                    _ => TunnResult::Err(WireGuardError::InvalidPacket),
                }
            }
            Err(e) => TunnResult::Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_tunnel_creation() {
        let secret = StaticSecret::random_from_rng(OsRng);
        let peer_secret = StaticSecret::random_from_rng(OsRng);
        let peer_public = PublicKey::from(&peer_secret);

        let tunnel = Tunn::new(secret, peer_public, None, None, 1).unwrap();
        assert!(tunnel.needs_handshake());
    }

    #[test]
    fn test_message_type_parsing() {
        assert_eq!(
            MessageType::try_from(1).unwrap(),
            MessageType::HandshakeInit
        );
        assert_eq!(
            MessageType::try_from(2).unwrap(),
            MessageType::HandshakeResponse
        );
        assert_eq!(MessageType::try_from(3).unwrap(), MessageType::CookieReply);
        assert_eq!(
            MessageType::try_from(4).unwrap(),
            MessageType::TransportData
        );
        assert!(MessageType::try_from(5).is_err());
    }

    #[test]
    fn test_handshake_initiation_buffer_too_small() {
        let secret = StaticSecret::random_from_rng(OsRng);
        let peer_secret = StaticSecret::random_from_rng(OsRng);
        let peer_public = PublicKey::from(&peer_secret);

        let tunnel = Tunn::new(secret, peer_public, None, None, 1).unwrap();
        let mut buf = [0u8; 10]; // Too small

        match tunnel.format_handshake_initiation(&mut buf, false) {
            TunnResult::Err(WireGuardError::DestinationBufferTooSmall) => {}
            _ => panic!("Expected DestinationBufferTooSmall error"),
        }
    }
}
