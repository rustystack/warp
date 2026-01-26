//! WireGuard transport session
//!
//! Handles encryption/decryption of transport data after handshake completion.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use super::crypto::{aead_decrypt, aead_encrypt, KEY_LEN, TAG_LEN};
use super::WireGuardError;

/// Session lifetime before rekey is required (2 minutes for testing, normally 3 minutes)
const SESSION_LIFETIME: Duration = Duration::from_secs(180);

/// Maximum number of messages before rekey
const MAX_MESSAGES: u64 = u64::MAX - (1 << 16);

/// Maximum counter value for replay protection window
const REPLAY_WINDOW_SIZE: u64 = 8192;

/// Active transport session for WireGuard
pub struct Session {
    /// Key for sending data
    send_key: [u8; KEY_LEN],

    /// Key for receiving data
    recv_key: [u8; KEY_LEN],

    /// Our sender index
    our_index: u32,

    /// Peer's sender index
    peer_index: u32,

    /// Creation time
    created_at: Instant,

    /// Counter for sending
    send_counter: AtomicU64,

    /// Counter for replay protection (highest received)
    recv_counter: AtomicU64,

    /// Bitmap for replay protection
    recv_bitmap: parking_lot::Mutex<u128>,
}

impl Session {
    /// Create a new transport session
    pub fn new(
        send_key: [u8; KEY_LEN],
        recv_key: [u8; KEY_LEN],
        our_index: u32,
        peer_index: u32,
    ) -> Self {
        Self {
            send_key,
            recv_key,
            our_index,
            peer_index,
            created_at: Instant::now(),
            send_counter: AtomicU64::new(0),
            recv_counter: AtomicU64::new(0),
            recv_bitmap: parking_lot::Mutex::new(0),
        }
    }

    /// Get our sender index
    pub fn our_index(&self) -> u32 {
        self.our_index
    }

    /// Get peer's sender index
    pub fn peer_index(&self) -> u32 {
        self.peer_index
    }

    /// Check if session has expired
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > SESSION_LIFETIME
            || self.send_counter.load(Ordering::SeqCst) >= MAX_MESSAGES
    }

    /// Get session age
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Encrypt data for sending
    ///
    /// Returns the length of the ciphertext (plaintext.len() + 16)
    pub fn encrypt(
        &self,
        counter: u64,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, WireGuardError> {
        aead_encrypt(&self.send_key, counter, plaintext, &[], ciphertext)
    }

    /// Encrypt data and advance counter
    pub fn encrypt_and_advance(
        &self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(u64, usize), WireGuardError> {
        let counter = self.send_counter.fetch_add(1, Ordering::SeqCst);
        let len = self.encrypt(counter, plaintext, ciphertext)?;
        Ok((counter, len))
    }

    /// Decrypt received data
    ///
    /// Returns the length of the plaintext
    pub fn decrypt(
        &self,
        counter: u64,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, WireGuardError> {
        // Check replay protection
        if !self.check_and_update_replay(counter) {
            return Err(WireGuardError::ReplayAttack);
        }

        aead_decrypt(&self.recv_key, counter, ciphertext, &[], plaintext)
    }

    /// Check and update replay protection state
    ///
    /// Returns true if the counter is acceptable (not a replay)
    fn check_and_update_replay(&self, counter: u64) -> bool {
        let highest = self.recv_counter.load(Ordering::SeqCst);

        if counter > highest {
            // New highest counter
            let diff = counter - highest;

            let mut bitmap = self.recv_bitmap.lock();

            if diff >= 128 {
                // Counter jumped too far, reset bitmap
                *bitmap = 1; // Mark position 0 as seen
            } else {
                // Shift bitmap and set new position
                *bitmap = (*bitmap << diff) | 1;
            }

            self.recv_counter.store(counter, Ordering::SeqCst);
            true
        } else if highest - counter >= 128 {
            // Too old, definitely a replay
            false
        } else {
            // Check bitmap for this position
            let pos = highest - counter;
            let mut bitmap = self.recv_bitmap.lock();

            if (*bitmap >> pos) & 1 == 1 {
                // Already seen, replay
                false
            } else {
                // Mark as seen
                *bitmap |= 1 << pos;
                true
            }
        }
    }

    /// Get current send counter value
    pub fn send_counter(&self) -> u64 {
        self.send_counter.load(Ordering::SeqCst)
    }

    /// Get current receive counter value
    pub fn recv_counter(&self) -> u64 {
        self.recv_counter.load(Ordering::SeqCst)
    }
}

impl Clone for Session {
    fn clone(&self) -> Self {
        Self {
            send_key: self.send_key,
            recv_key: self.recv_key,
            our_index: self.our_index,
            peer_index: self.peer_index,
            created_at: self.created_at,
            send_counter: AtomicU64::new(self.send_counter.load(Ordering::SeqCst)),
            recv_counter: AtomicU64::new(self.recv_counter.load(Ordering::SeqCst)),
            recv_bitmap: parking_lot::Mutex::new(*self.recv_bitmap.lock()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_session_pair() -> (Session, Session) {
        let send_key = [1u8; KEY_LEN];
        let recv_key = [2u8; KEY_LEN];

        let session1 = Session::new(send_key, recv_key, 1, 2);
        let session2 = Session::new(recv_key, send_key, 2, 1);

        (session1, session2)
    }

    #[test]
    fn test_session_creation() {
        let (session1, session2) = create_test_session_pair();

        assert_eq!(session1.our_index(), 1);
        assert_eq!(session1.peer_index(), 2);
        assert_eq!(session2.our_index(), 2);
        assert_eq!(session2.peer_index(), 1);
        assert!(!session1.is_expired());
    }

    #[test]
    fn test_encrypt_decrypt() {
        let (session1, session2) = create_test_session_pair();

        let plaintext = b"Hello, WireGuard!";
        let mut ciphertext = vec![0u8; plaintext.len() + TAG_LEN];
        let mut decrypted = vec![0u8; plaintext.len()];

        // Encrypt with session1
        let ct_len = session1.encrypt(0, plaintext, &mut ciphertext).unwrap();
        assert_eq!(ct_len, plaintext.len() + TAG_LEN);

        // Decrypt with session2
        let pt_len = session2
            .decrypt(0, &ciphertext[..ct_len], &mut decrypted)
            .unwrap();
        assert_eq!(pt_len, plaintext.len());
        assert_eq!(&decrypted[..pt_len], plaintext);
    }

    #[test]
    fn test_encrypt_and_advance() {
        let (session1, session2) = create_test_session_pair();

        let plaintext = b"Message";
        let mut ciphertext = vec![0u8; plaintext.len() + TAG_LEN];
        let mut decrypted = vec![0u8; plaintext.len()];

        // First message
        let (counter1, _) = session1.encrypt_and_advance(plaintext, &mut ciphertext).unwrap();
        assert_eq!(counter1, 0);
        session2.decrypt(counter1, &ciphertext, &mut decrypted).unwrap();

        // Second message
        let (counter2, _) = session1.encrypt_and_advance(plaintext, &mut ciphertext).unwrap();
        assert_eq!(counter2, 1);
        session2.decrypt(counter2, &ciphertext, &mut decrypted).unwrap();

        // Counter should have advanced
        assert_eq!(session1.send_counter(), 2);
    }

    #[test]
    fn test_replay_protection() {
        let (session1, session2) = create_test_session_pair();

        let plaintext = b"Test";
        let mut ciphertext = vec![0u8; plaintext.len() + TAG_LEN];
        let mut decrypted = vec![0u8; plaintext.len()];

        // Send and receive a message
        session1.encrypt(0, plaintext, &mut ciphertext).unwrap();
        session2.decrypt(0, &ciphertext, &mut decrypted).unwrap();

        // Try to replay the same message
        let result = session2.decrypt(0, &ciphertext, &mut decrypted);
        assert!(matches!(result, Err(WireGuardError::ReplayAttack)));
    }

    #[test]
    fn test_replay_protection_out_of_order() {
        let (session1, session2) = create_test_session_pair();

        let plaintext = b"Test";
        let mut ciphertext0 = vec![0u8; plaintext.len() + TAG_LEN];
        let mut ciphertext1 = vec![0u8; plaintext.len() + TAG_LEN];
        let mut decrypted = vec![0u8; plaintext.len()];

        // Send two messages
        session1.encrypt(0, plaintext, &mut ciphertext0).unwrap();
        session1.encrypt(1, plaintext, &mut ciphertext1).unwrap();

        // Receive out of order (1 first, then 0)
        session2.decrypt(1, &ciphertext1, &mut decrypted).unwrap();
        session2.decrypt(0, &ciphertext0, &mut decrypted).unwrap();

        // Try to replay either
        assert!(matches!(
            session2.decrypt(0, &ciphertext0, &mut decrypted),
            Err(WireGuardError::ReplayAttack)
        ));
        assert!(matches!(
            session2.decrypt(1, &ciphertext1, &mut decrypted),
            Err(WireGuardError::ReplayAttack)
        ));
    }

    #[test]
    fn test_replay_window() {
        let (_, session2) = create_test_session_pair();

        // Simulate receiving counter 1000
        assert!(session2.check_and_update_replay(1000));

        // Counter 999 should still be valid (within window)
        assert!(session2.check_and_update_replay(999));

        // Counter 999 again should be rejected (replay)
        assert!(!session2.check_and_update_replay(999));

        // Counter 900 should still be valid (within 128 window)
        assert!(session2.check_and_update_replay(900));

        // Counter 800 is too old (outside 128 window)
        assert!(!session2.check_and_update_replay(800));
    }

    #[test]
    fn test_session_clone() {
        let (session1, _) = create_test_session_pair();

        // Advance counter
        session1.send_counter.fetch_add(10, Ordering::SeqCst);

        let cloned = session1.clone();

        assert_eq!(cloned.our_index(), session1.our_index());
        assert_eq!(cloned.peer_index(), session1.peer_index());
        assert_eq!(cloned.send_counter(), session1.send_counter());
    }
}
