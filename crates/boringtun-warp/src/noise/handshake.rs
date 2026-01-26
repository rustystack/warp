//! WireGuard Noise handshake implementation
//!
//! Implements the Noise_IKpsk2 pattern used by WireGuard.

use std::time::Instant;

use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use super::crypto::{
    aead_decrypt, aead_encrypt, hash, hash_many, hkdf2, hkdf3, hmac, HASH_LEN, KEY_LEN,
    NOISE_PROTOCOL_NAME, TAG_LEN, WG_IDENTIFIER,
};
use super::session::Session;
use super::WireGuardError;

/// Size of handshake initiation message
pub const HANDSHAKE_INIT_SIZE: usize = 148;

/// Size of handshake response message
pub const HANDSHAKE_RESPONSE_SIZE: usize = 92;

/// TAI64N timestamp size
const TIMESTAMP_LEN: usize = 12;

/// MAC size
const MAC_LEN: usize = 16;

/// State of the handshake
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    /// No handshake in progress
    None,
    /// We initiated and are waiting for response
    InitiationSent,
    /// We received initiation and sent response
    ResponseSent,
    /// Handshake complete
    Complete,
}

/// Handshake state machine
pub struct Handshake {
    /// Current state
    state: HandshakeState,

    /// Our static private key
    static_private: StaticSecret,

    /// Our static public key
    static_public: PublicKey,

    /// Peer's static public key
    peer_static_public: PublicKey,

    /// Optional preshared key
    preshared_key: Option<[u8; 32]>,

    /// Ephemeral private key (generated per handshake)
    ephemeral_private: Option<StaticSecret>,

    /// Ephemeral public key
    ephemeral_public: Option<PublicKey>,

    /// Peer's ephemeral public key
    peer_ephemeral_public: Option<PublicKey>,

    /// Chaining key (Noise protocol state)
    chaining_key: [u8; HASH_LEN],

    /// Hash state (Noise protocol state)
    hash: [u8; HASH_LEN],

    /// Our sender index
    our_index: u32,

    /// Peer's sender index
    peer_index: u32,

    /// Timestamp of last initiation we sent
    last_initiation: Option<Instant>,

    /// Derived transport keys (after handshake)
    transport_keys: Option<TransportKeys>,
}

/// Transport encryption keys derived from handshake
#[derive(Clone)]
pub struct TransportKeys {
    /// Key for sending
    pub send_key: [u8; KEY_LEN],
    /// Key for receiving
    pub recv_key: [u8; KEY_LEN],
    /// Our sender index
    pub our_index: u32,
    /// Peer's sender index
    pub peer_index: u32,
}

impl Handshake {
    /// Create a new handshake state
    pub fn new(
        static_private: StaticSecret,
        static_public: PublicKey,
        peer_static_public: PublicKey,
        preshared_key: Option<[u8; 32]>,
    ) -> Self {
        // Initialize chaining key
        let chaining_key = hash(NOISE_PROTOCOL_NAME);

        // Initialize hash: H(C || prologue)
        let hash = hash_many(&[&chaining_key, WG_IDENTIFIER]);

        // Mix in peer's static public key: H(H || S_peer)
        let hash = hash_many(&[&hash, peer_static_public.as_bytes()]);

        Self {
            state: HandshakeState::None,
            static_private,
            static_public,
            peer_static_public,
            preshared_key,
            ephemeral_private: None,
            ephemeral_public: None,
            peer_ephemeral_public: None,
            chaining_key,
            hash,
            our_index: 0,
            peer_index: 0,
            last_initiation: None,
            transport_keys: None,
        }
    }

    /// Get current handshake state
    pub fn state(&self) -> HandshakeState {
        self.state
    }

    /// Create handshake initiation message
    pub fn create_initiation(
        &mut self,
        sender_index: u32,
        dst: &mut [u8],
    ) -> Result<usize, WireGuardError> {
        if dst.len() < HANDSHAKE_INIT_SIZE {
            return Err(WireGuardError::DestinationBufferTooSmall);
        }

        // Reset state for new handshake
        let chaining_key = hash(NOISE_PROTOCOL_NAME);
        let hash = hash_many(&[&chaining_key, WG_IDENTIFIER]);
        let hash = hash_many(&[&hash, self.peer_static_public.as_bytes()]);

        self.chaining_key = chaining_key;
        self.hash = hash;
        self.our_index = sender_index;

        // Generate ephemeral keypair
        let ephemeral_private = StaticSecret::random_from_rng(OsRng);
        let ephemeral_public = PublicKey::from(&ephemeral_private);

        self.ephemeral_private = Some(ephemeral_private.clone());
        self.ephemeral_public = Some(ephemeral_public);

        // Message type (1)
        dst[0] = 1;
        dst[1..4].copy_from_slice(&[0, 0, 0]); // reserved

        // Sender index (4 bytes)
        dst[4..8].copy_from_slice(&sender_index.to_le_bytes());

        // Ephemeral public key (32 bytes)
        dst[8..40].copy_from_slice(ephemeral_public.as_bytes());

        // Update chaining key and hash with ephemeral
        let (ck, _) = hkdf2(&self.chaining_key, ephemeral_public.as_bytes());
        self.chaining_key = ck;
        self.hash = hash_many(&[&self.hash, ephemeral_public.as_bytes()]);

        // DH: ephemeral-static
        let dh_result = ephemeral_private.diffie_hellman(&self.peer_static_public);
        let (ck, key) = hkdf2(&self.chaining_key, dh_result.as_bytes());
        self.chaining_key = ck;

        // Encrypt static public key: AEAD(K, 0, S_i, H)
        let encrypted_static = &mut dst[40..88]; // 32 + 16 tag
        aead_encrypt(
            &key,
            0,
            self.static_public.as_bytes(),
            &self.hash,
            encrypted_static,
        )?;
        self.hash = hash_many(&[&self.hash, encrypted_static]);

        // DH: static-static
        let dh_result = self.static_private.diffie_hellman(&self.peer_static_public);
        let (ck, key) = hkdf2(&self.chaining_key, dh_result.as_bytes());
        self.chaining_key = ck;

        // Generate and encrypt timestamp
        let timestamp = self.generate_timestamp();
        let encrypted_timestamp = &mut dst[88..116]; // 12 + 16 tag
        aead_encrypt(&key, 0, &timestamp, &self.hash, encrypted_timestamp)?;
        self.hash = hash_many(&[&self.hash, encrypted_timestamp]);

        // MAC1: HMAC(H(label-mac1 || S_r), msg[0:116])
        let mac1_key = hash_many(&[b"mac1----", self.peer_static_public.as_bytes()]);
        let mac1 = hmac(&mac1_key, &dst[0..116]);
        dst[116..132].copy_from_slice(&mac1[..16]);

        // MAC2: All zeros (no cookie)
        dst[132..148].copy_from_slice(&[0u8; 16]);

        self.state = HandshakeState::InitiationSent;
        self.last_initiation = Some(Instant::now());

        Ok(HANDSHAKE_INIT_SIZE)
    }

    /// Process incoming handshake initiation
    pub fn consume_initiation(&mut self, packet: &[u8]) -> Result<(), WireGuardError> {
        if packet.len() < HANDSHAKE_INIT_SIZE {
            return Err(WireGuardError::InvalidPacket);
        }

        if packet[0] != 1 {
            return Err(WireGuardError::WrongMessageType);
        }

        // Reset state
        let chaining_key = hash(NOISE_PROTOCOL_NAME);
        let hash = hash_many(&[&chaining_key, WG_IDENTIFIER]);
        // Mix in OUR static public key (we are the responder)
        let hash = hash_many(&[&hash, self.static_public.as_bytes()]);

        self.chaining_key = chaining_key;
        self.hash = hash;

        // Parse sender index
        self.peer_index = u32::from_le_bytes([packet[4], packet[5], packet[6], packet[7]]);

        // Parse peer's ephemeral public key
        let mut peer_ephemeral_bytes = [0u8; 32];
        peer_ephemeral_bytes.copy_from_slice(&packet[8..40]);
        let peer_ephemeral = PublicKey::from(peer_ephemeral_bytes);
        self.peer_ephemeral_public = Some(peer_ephemeral);

        // Update chaining key and hash with ephemeral
        let (ck, _) = hkdf2(&self.chaining_key, peer_ephemeral.as_bytes());
        self.chaining_key = ck;
        self.hash = hash_many(&[&self.hash, peer_ephemeral.as_bytes()]);

        // DH: static-ephemeral
        let dh_result = self.static_private.diffie_hellman(&peer_ephemeral);
        let (ck, key) = hkdf2(&self.chaining_key, dh_result.as_bytes());
        self.chaining_key = ck;

        // Decrypt peer's static public key
        let encrypted_static = &packet[40..88];
        let mut peer_static_bytes = [0u8; 32];
        aead_decrypt(&key, 0, encrypted_static, &self.hash, &mut peer_static_bytes)?;

        // Verify it matches expected peer
        if peer_static_bytes != *self.peer_static_public.as_bytes() {
            return Err(WireGuardError::InvalidPublicKey);
        }
        self.hash = hash_many(&[&self.hash, encrypted_static]);

        // DH: static-static
        let dh_result = self.static_private.diffie_hellman(&self.peer_static_public);
        let (ck, key) = hkdf2(&self.chaining_key, dh_result.as_bytes());
        self.chaining_key = ck;

        // Decrypt timestamp
        let encrypted_timestamp = &packet[88..116];
        let mut timestamp = [0u8; TIMESTAMP_LEN];
        aead_decrypt(&key, 0, encrypted_timestamp, &self.hash, &mut timestamp)?;
        self.hash = hash_many(&[&self.hash, encrypted_timestamp]);

        // TODO: Verify timestamp is newer than last seen

        self.state = HandshakeState::InitiationSent;
        Ok(())
    }

    /// Create handshake response message
    pub fn create_response(
        &mut self,
        sender_index: u32,
        dst: &mut [u8],
    ) -> Result<usize, WireGuardError> {
        if dst.len() < HANDSHAKE_RESPONSE_SIZE {
            return Err(WireGuardError::DestinationBufferTooSmall);
        }

        self.our_index = sender_index;

        // Generate ephemeral keypair
        let ephemeral_private = StaticSecret::random_from_rng(OsRng);
        let ephemeral_public = PublicKey::from(&ephemeral_private);

        self.ephemeral_private = Some(ephemeral_private.clone());
        self.ephemeral_public = Some(ephemeral_public);

        // Message type (2)
        dst[0] = 2;
        dst[1..4].copy_from_slice(&[0, 0, 0]); // reserved

        // Sender index
        dst[4..8].copy_from_slice(&sender_index.to_le_bytes());

        // Receiver index (peer's sender index)
        dst[8..12].copy_from_slice(&self.peer_index.to_le_bytes());

        // Ephemeral public key
        dst[12..44].copy_from_slice(ephemeral_public.as_bytes());

        // Update chaining key and hash
        let (ck, _) = hkdf2(&self.chaining_key, ephemeral_public.as_bytes());
        self.chaining_key = ck;
        self.hash = hash_many(&[&self.hash, ephemeral_public.as_bytes()]);

        // DH: ephemeral-ephemeral
        let peer_ephemeral = self
            .peer_ephemeral_public
            .ok_or(WireGuardError::HandshakeFailed)?;
        let dh_result = ephemeral_private.diffie_hellman(&peer_ephemeral);
        let (ck, _) = hkdf2(&self.chaining_key, dh_result.as_bytes());
        self.chaining_key = ck;

        // DH: ephemeral-static
        let dh_result = ephemeral_private.diffie_hellman(&self.peer_static_public);
        let (ck, _) = hkdf2(&self.chaining_key, dh_result.as_bytes());
        self.chaining_key = ck;

        // Mix in preshared key
        let psk = self.preshared_key.unwrap_or([0u8; 32]);
        let (ck, temp, key) = hkdf3(&self.chaining_key, &psk);
        self.chaining_key = ck;
        self.hash = hash_many(&[&self.hash, &temp]);

        // Encrypt empty payload
        let encrypted_nothing = &mut dst[44..60]; // 0 + 16 tag
        aead_encrypt(&key, 0, &[], &self.hash, encrypted_nothing)?;
        self.hash = hash_many(&[&self.hash, encrypted_nothing]);

        // MAC1
        let mac1_key = hash_many(&[b"mac1----", self.peer_static_public.as_bytes()]);
        let mac1 = hmac(&mac1_key, &dst[0..60]);
        dst[60..76].copy_from_slice(&mac1[..16]);

        // MAC2: All zeros
        dst[76..92].copy_from_slice(&[0u8; 16]);

        self.state = HandshakeState::ResponseSent;
        Ok(HANDSHAKE_RESPONSE_SIZE)
    }

    /// Process incoming handshake response
    pub fn consume_response(&mut self, packet: &[u8]) -> Result<(), WireGuardError> {
        if packet.len() < HANDSHAKE_RESPONSE_SIZE {
            return Err(WireGuardError::InvalidPacket);
        }

        if packet[0] != 2 {
            return Err(WireGuardError::WrongMessageType);
        }

        if self.state != HandshakeState::InitiationSent {
            return Err(WireGuardError::HandshakeFailed);
        }

        // Parse sender index (peer's)
        self.peer_index = u32::from_le_bytes([packet[4], packet[5], packet[6], packet[7]]);

        // Parse receiver index (should be our sender index)
        let receiver_index = u32::from_le_bytes([packet[8], packet[9], packet[10], packet[11]]);
        if receiver_index != self.our_index {
            return Err(WireGuardError::InvalidPacket);
        }

        // Parse peer's ephemeral public key
        let mut peer_ephemeral_bytes = [0u8; 32];
        peer_ephemeral_bytes.copy_from_slice(&packet[12..44]);
        let peer_ephemeral = PublicKey::from(peer_ephemeral_bytes);
        self.peer_ephemeral_public = Some(peer_ephemeral);

        // Update chaining key and hash
        let (ck, _) = hkdf2(&self.chaining_key, peer_ephemeral.as_bytes());
        self.chaining_key = ck;
        self.hash = hash_many(&[&self.hash, peer_ephemeral.as_bytes()]);

        // DH: ephemeral-ephemeral
        let ephemeral_private = self
            .ephemeral_private
            .as_ref()
            .ok_or(WireGuardError::HandshakeFailed)?;
        let dh_result = ephemeral_private.diffie_hellman(&peer_ephemeral);
        let (ck, _) = hkdf2(&self.chaining_key, dh_result.as_bytes());
        self.chaining_key = ck;

        // DH: static-ephemeral
        let dh_result = self.static_private.diffie_hellman(&peer_ephemeral);
        let (ck, _) = hkdf2(&self.chaining_key, dh_result.as_bytes());
        self.chaining_key = ck;

        // Mix in preshared key
        let psk = self.preshared_key.unwrap_or([0u8; 32]);
        let (ck, temp, key) = hkdf3(&self.chaining_key, &psk);
        self.chaining_key = ck;
        self.hash = hash_many(&[&self.hash, &temp]);

        // Decrypt empty payload
        let encrypted_nothing = &packet[44..60];
        let mut nothing = [0u8; 0];
        aead_decrypt(&key, 0, encrypted_nothing, &self.hash, &mut nothing)?;
        self.hash = hash_many(&[&self.hash, encrypted_nothing]);

        self.state = HandshakeState::Complete;
        Ok(())
    }

    /// Derive transport session keys after handshake completion
    pub fn derive_session(&mut self, is_initiator: bool) -> Option<Session> {
        if self.state != HandshakeState::ResponseSent && self.state != HandshakeState::Complete {
            return None;
        }

        // Derive transport keys
        let (t1, t2) = hkdf2(&self.chaining_key, &[]);

        let (send_key, recv_key) = if is_initiator {
            (t1, t2)
        } else {
            (t2, t1)
        };

        self.transport_keys = Some(TransportKeys {
            send_key,
            recv_key,
            our_index: self.our_index,
            peer_index: self.peer_index,
        });

        // Clear sensitive ephemeral data
        self.ephemeral_private = None;
        self.state = HandshakeState::Complete;

        Some(Session::new(send_key, recv_key, self.our_index, self.peer_index))
    }

    /// Generate TAI64N timestamp
    fn generate_timestamp(&self) -> [u8; TIMESTAMP_LEN] {
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();

        let secs = now.as_secs() + 0x400000000000000a; // TAI64 offset
        let nanos = now.subsec_nanos();

        let mut timestamp = [0u8; TIMESTAMP_LEN];
        timestamp[0..8].copy_from_slice(&secs.to_be_bytes());
        timestamp[8..12].copy_from_slice(&nanos.to_be_bytes());

        timestamp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_state_machine() {
        // Generate keys for both parties
        let initiator_private = StaticSecret::random_from_rng(OsRng);
        let initiator_public = PublicKey::from(&initiator_private);

        let responder_private = StaticSecret::random_from_rng(OsRng);
        let responder_public = PublicKey::from(&responder_private);

        // Create handshake states
        let mut initiator = Handshake::new(
            initiator_private,
            initiator_public,
            responder_public,
            None,
        );

        let mut responder = Handshake::new(
            responder_private,
            responder_public,
            initiator_public,
            None,
        );

        // Step 1: Initiator creates initiation
        let mut init_msg = vec![0u8; HANDSHAKE_INIT_SIZE];
        let len = initiator.create_initiation(1, &mut init_msg).unwrap();
        assert_eq!(len, HANDSHAKE_INIT_SIZE);
        assert_eq!(initiator.state(), HandshakeState::InitiationSent);

        // Step 2: Responder processes initiation
        responder.consume_initiation(&init_msg).unwrap();

        // Step 3: Responder creates response
        let mut resp_msg = vec![0u8; HANDSHAKE_RESPONSE_SIZE];
        let len = responder.create_response(2, &mut resp_msg).unwrap();
        assert_eq!(len, HANDSHAKE_RESPONSE_SIZE);
        assert_eq!(responder.state(), HandshakeState::ResponseSent);

        // Step 4: Initiator processes response
        initiator.consume_response(&resp_msg).unwrap();
        assert_eq!(initiator.state(), HandshakeState::Complete);

        // Step 5: Both derive session keys
        let initiator_session = initiator.derive_session(true).unwrap();
        let responder_session = responder.derive_session(false).unwrap();

        // Verify sessions can encrypt/decrypt
        let plaintext = b"Hello, WireGuard!";
        let mut ciphertext = vec![0u8; plaintext.len() + TAG_LEN];
        let ct_len = initiator_session.encrypt(0, plaintext, &mut ciphertext).unwrap();

        let mut decrypted = vec![0u8; plaintext.len()];
        let pt_len = responder_session.decrypt(0, &ciphertext[..ct_len], &mut decrypted).unwrap();

        assert_eq!(&decrypted[..pt_len], plaintext);
    }

    #[test]
    fn test_handshake_with_psk() {
        let psk = [42u8; 32];

        let initiator_private = StaticSecret::random_from_rng(OsRng);
        let initiator_public = PublicKey::from(&initiator_private);

        let responder_private = StaticSecret::random_from_rng(OsRng);
        let responder_public = PublicKey::from(&responder_private);

        let mut initiator = Handshake::new(
            initiator_private,
            initiator_public,
            responder_public,
            Some(psk),
        );

        let mut responder = Handshake::new(
            responder_private,
            responder_public,
            initiator_public,
            Some(psk),
        );

        // Complete handshake
        let mut init_msg = vec![0u8; HANDSHAKE_INIT_SIZE];
        initiator.create_initiation(1, &mut init_msg).unwrap();
        responder.consume_initiation(&init_msg).unwrap();

        let mut resp_msg = vec![0u8; HANDSHAKE_RESPONSE_SIZE];
        responder.create_response(2, &mut resp_msg).unwrap();
        initiator.consume_response(&resp_msg).unwrap();

        // Derive sessions
        let i_session = initiator.derive_session(true).unwrap();
        let r_session = responder.derive_session(false).unwrap();

        // Verify encryption works
        let plaintext = b"PSK protected!";
        let mut ciphertext = vec![0u8; plaintext.len() + TAG_LEN];
        i_session.encrypt(0, plaintext, &mut ciphertext).unwrap();

        let mut decrypted = vec![0u8; plaintext.len()];
        r_session.decrypt(0, &ciphertext, &mut decrypted).unwrap();
        assert_eq!(&decrypted[..], plaintext);
    }
}
