//! OPRF Client implementation
//!
//! Uses a simplified OPRF construction based on Diffie-Hellman:
//! 1. Client: generate random scalar r, send H(input)^r to server
//! 2. Server: compute (H(input)^r)^k = H(input)^(rk), return it
//! 3. Client: compute (H(input)^(rk))^(1/r) = H(input)^k
//! 4. Hash the result to get the final output
//!
//! The output is deterministic for the same input + server key.

use super::{BlindedInput, ClientState, Evaluation, OprfClientTrait, OprfOutput};
use crate::error::{OprfError, Result};
use crate::suite::{CipherSuite, OprfMode};

#[cfg(feature = "ristretto255")]
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
#[cfg(feature = "ristretto255")]
use rand::rngs::OsRng;

/// OPRF client using Ristretto255 curve
#[cfg(feature = "ristretto255")]
pub struct Ristretto255Client {
    /// Server's public key for verification
    #[allow(dead_code)]
    server_public_key: Vec<u8>,
    /// Mode of operation
    mode: OprfMode,
}

#[cfg(feature = "ristretto255")]
impl Ristretto255Client {
    /// Create a new client with the server's public key
    pub fn new(server_public_key: &[u8]) -> Result<Self> {
        if server_public_key.len() != 32 {
            return Err(OprfError::InvalidInput(format!(
                "server public key must be 32 bytes, got {}",
                server_public_key.len()
            )));
        }

        Ok(Self {
            server_public_key: server_public_key.to_vec(),
            mode: OprfMode::Verifiable,
        })
    }

    /// Create a client for base (non-verifiable) mode
    pub fn new_base() -> Self {
        Self {
            server_public_key: Vec::new(),
            mode: OprfMode::Base,
        }
    }

    /// Set the mode of operation
    pub fn with_mode(mut self, mode: OprfMode) -> Self {
        self.mode = mode;
        self
    }

    /// Hash to curve - map input to a Ristretto point
    fn hash_to_point(input: &[u8]) -> RistrettoPoint {
        use sha2::{Digest, Sha512};
        let hash = Sha512::digest(input);
        let hash_bytes: [u8; 64] = hash.into();
        RistrettoPoint::from_uniform_bytes(&hash_bytes)
    }
}

#[cfg(feature = "ristretto255")]
impl OprfClientTrait for Ristretto255Client {
    fn blind(&self, input: &[u8]) -> Result<(BlindedInput, ClientState)> {
        use rand::RngCore;

        // Generate random blinding scalar
        let mut scalar_bytes = [0u8; 64];
        OsRng.fill_bytes(&mut scalar_bytes);
        let r = Scalar::from_bytes_mod_order_wide(&scalar_bytes);

        // Compute H(input)^r
        let input_point = Self::hash_to_point(input);
        let blinded_point = input_point * r;

        // Serialize the blinded point
        let element_bytes = blinded_point.compress().to_bytes().to_vec();

        // Store the blinding scalar for unblinding later
        let r_bytes = r.to_bytes();

        let blinded = BlindedInput::new(element_bytes, CipherSuite::Ristretto255Sha512, self.mode);

        let state = ClientState {
            state: r_bytes.to_vec(),
            input: input.to_vec(),
            suite: CipherSuite::Ristretto255Sha512,
            mode: self.mode,
        };

        Ok((blinded, state))
    }

    fn finalize(&self, state: ClientState, evaluation: &Evaluation) -> Result<OprfOutput> {
        // Deserialize the blinding scalar
        let r_bytes: [u8; 32] = state
            .state
            .as_slice()
            .try_into()
            .map_err(|_| OprfError::FinalizationFailed("invalid state length".to_string()))?;

        let r = Scalar::from_canonical_bytes(r_bytes);
        if r.is_none().into() {
            return Err(OprfError::FinalizationFailed("invalid scalar".to_string()));
        }
        let r = r.unwrap();

        // Compute r^(-1)
        let r_inv = r.invert();

        // Deserialize the evaluated point (H(input)^(rk))
        let eval_bytes: [u8; 32] = evaluation
            .element
            .as_slice()
            .try_into()
            .map_err(|_| OprfError::InvalidEvaluation)?;

        let eval_point = curve25519_dalek::ristretto::CompressedRistretto(eval_bytes)
            .decompress()
            .ok_or(OprfError::InvalidEvaluation)?;

        // Unblind: (H(input)^(rk))^(1/r) = H(input)^k
        let output_point = eval_point * r_inv;

        // Hash the output point to get the final output (64 bytes)
        let output_bytes = output_point.compress().to_bytes();
        let hash1: [u8; 32] = warp_hash::hash(&output_bytes);
        let hash2: [u8; 32] = warp_hash::hash(&hash1);
        let output = [hash1.as_slice(), hash2.as_slice()].concat();

        Ok(OprfOutput::new(output))
    }

    fn suite(&self) -> CipherSuite {
        CipherSuite::Ristretto255Sha512
    }

    fn mode(&self) -> OprfMode {
        self.mode
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "ristretto255")]
    #[test]
    fn test_client_creation() {
        let fake_pk = [0u8; 32];
        let client = Ristretto255Client::new(&fake_pk);
        assert!(client.is_ok());
    }

    #[cfg(feature = "ristretto255")]
    #[test]
    fn test_client_invalid_pk() {
        let fake_pk = [0u8; 16]; // Too short
        let client = Ristretto255Client::new(&fake_pk);
        assert!(client.is_err());
    }

    #[cfg(feature = "ristretto255")]
    #[test]
    fn test_base_mode_client() {
        let client = Ristretto255Client::new_base();
        assert_eq!(client.mode(), OprfMode::Base);
    }
}
