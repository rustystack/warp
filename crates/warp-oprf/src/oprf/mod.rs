//! Core OPRF (Oblivious Pseudorandom Function) implementation
//!
//! This module provides the core OPRF protocol as defined in RFC 9497.
//! The protocol allows a client to evaluate a PRF on their input with
//! the help of a server, without revealing the input to the server.
//!
//! # Protocol Overview
//!
//! 1. **Blind**: Client blinds their input with a random scalar
//! 2. **Evaluate**: Server evaluates the blinded input with their secret key
//! 3. **Finalize**: Client unblinds the result to get the PRF output
//!
//! # Example
//!
//! ```ignore
//! use warp_oprf::oprf::{OprfClient, OprfServer, Ristretto255Client, Ristretto255Server};
//!
//! // Server setup
//! let server = Ristretto255Server::new()?;
//! let public_key = server.public_key();
//!
//! // Client blinds input
//! let client = Ristretto255Client::new(&public_key)?;
//! let (blinded, state) = client.blind(b"my secret input")?;
//!
//! // Server evaluates (verifiable mode)
//! let evaluation = server.evaluate(&blinded)?;
//!
//! // Client finalizes
//! let output = client.finalize(state, &evaluation)?;
//! ```

mod client;
mod server;

pub use client::*;
pub use server::*;

use crate::error::Result;
use crate::suite::{CipherSuite, OprfMode};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Blinded input sent from client to server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindedInput {
    /// The blinded group element
    #[serde(with = "serde_bytes")]
    pub element: Vec<u8>,
    /// The cipher suite used
    pub suite: CipherSuite,
    /// The mode of operation
    pub mode: OprfMode,
}

impl BlindedInput {
    /// Create a new blinded input
    pub fn new(element: Vec<u8>, suite: CipherSuite, mode: OprfMode) -> Self {
        Self { element, suite, mode }
    }
}

/// Server evaluation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evaluation {
    /// The evaluated group element
    #[serde(with = "serde_bytes")]
    pub element: Vec<u8>,
    /// Optional DLEQ proof for verifiable mode
    #[serde(with = "serde_bytes")]
    pub proof: Vec<u8>,
}

impl Evaluation {
    /// Create a new evaluation without proof (base mode)
    pub fn new(element: Vec<u8>) -> Self {
        Self {
            element,
            proof: Vec::new(),
        }
    }

    /// Create a new evaluation with proof (verifiable mode)
    pub fn with_proof(element: Vec<u8>, proof: Vec<u8>) -> Self {
        Self { element, proof }
    }

    /// Check if this evaluation includes a proof
    pub fn has_proof(&self) -> bool {
        !self.proof.is_empty()
    }
}

/// Client state that must be preserved between blind and finalize
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ClientState {
    /// The blinding factor (secret scalar)
    #[zeroize(skip)]
    pub(crate) state: Vec<u8>,
    /// The original input
    #[zeroize(skip)]
    pub(crate) input: Vec<u8>,
    /// The cipher suite used
    #[zeroize(skip)]
    pub(crate) suite: CipherSuite,
    /// The mode used
    #[zeroize(skip)]
    pub(crate) mode: OprfMode,
}

/// Final OPRF output (PRF value)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct OprfOutput(Vec<u8>);

impl OprfOutput {
    /// Create a new OPRF output
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    /// Get the output as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Get the output length
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Convert to fixed-size array (for key derivation)
    pub fn to_array<const N: usize>(&self) -> Option<[u8; N]> {
        if self.0.len() >= N {
            let mut arr = [0u8; N];
            arr.copy_from_slice(&self.0[..N]);
            Some(arr)
        } else {
            None
        }
    }

    /// Derive a 32-byte key from the output
    pub fn derive_key(&self) -> [u8; 32] {
        // Use BLAKE3 to derive a fixed-size key
        warp_hash::hash(self.as_bytes())
    }
}

impl AsRef<[u8]> for OprfOutput {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for OprfOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OprfOutput([REDACTED {} bytes])", self.0.len())
    }
}

/// Trait for OPRF client operations
pub trait OprfClientTrait: Send + Sync {
    /// Blind an input value
    ///
    /// Returns the blinded input to send to the server and state to preserve
    fn blind(&self, input: &[u8]) -> Result<(BlindedInput, ClientState)>;

    /// Finalize the OPRF output after receiving server evaluation
    ///
    /// Verifies the proof if in verifiable mode, then unblinds the result
    fn finalize(&self, state: ClientState, evaluation: &Evaluation) -> Result<OprfOutput>;

    /// Get the cipher suite in use
    fn suite(&self) -> CipherSuite;

    /// Get the mode of operation
    fn mode(&self) -> OprfMode;
}

/// Trait for OPRF server operations
pub trait OprfServerTrait: Send + Sync {
    /// Get the server's public key
    fn public_key(&self) -> Vec<u8>;

    /// Evaluate a blinded input
    ///
    /// In verifiable mode, also generates a DLEQ proof
    fn evaluate(&self, blinded: &BlindedInput) -> Result<Evaluation>;

    /// Get the key identifier for this server
    fn key_id(&self) -> &str;

    /// Get the cipher suite in use
    fn suite(&self) -> CipherSuite;

    /// Get the mode of operation
    fn mode(&self) -> OprfMode;
}

/// Batch OPRF operations for efficiency
pub trait BatchOprfClient: OprfClientTrait {
    /// Blind multiple inputs at once
    fn blind_batch(&self, inputs: &[&[u8]]) -> Result<(Vec<BlindedInput>, Vec<ClientState>)>;

    /// Finalize multiple evaluations at once
    fn finalize_batch(
        &self,
        states: Vec<ClientState>,
        evaluations: &[Evaluation],
    ) -> Result<Vec<OprfOutput>>;
}

/// Batch server evaluation
pub trait BatchOprfServer: OprfServerTrait {
    /// Evaluate multiple blinded inputs at once
    fn evaluate_batch(&self, blinded: &[BlindedInput]) -> Result<Vec<Evaluation>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oprf_output() {
        let output = OprfOutput::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(output.len(), 8);
        assert!(!output.is_empty());
        assert_eq!(output.as_bytes(), &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_oprf_output_derive_key() {
        let output = OprfOutput::new(vec![0u8; 64]);
        let key = output.derive_key();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_blinded_input() {
        let blinded = BlindedInput::new(
            vec![1, 2, 3],
            CipherSuite::default(),
            OprfMode::Verifiable,
        );
        assert_eq!(blinded.element, vec![1, 2, 3]);
        assert_eq!(blinded.mode, OprfMode::Verifiable);
    }

    #[test]
    fn test_evaluation() {
        let eval = Evaluation::new(vec![1, 2, 3]);
        assert!(!eval.has_proof());

        let eval_with_proof = Evaluation::with_proof(vec![1, 2, 3], vec![4, 5, 6]);
        assert!(eval_with_proof.has_proof());
    }
}
