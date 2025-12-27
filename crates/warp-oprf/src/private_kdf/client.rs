//! Private KDF Client

use super::{DerivedKey, KdfRequest, KdfResponse, KdfState};
use crate::error::Result;
use crate::oprf::OprfClientTrait;

#[cfg(feature = "ristretto255")]
use crate::oprf::Ristretto255Client;

/// Client for private key derivation
#[cfg(feature = "ristretto255")]
pub struct PrivateKdfClient {
    oprf_client: Ristretto255Client,
}

#[cfg(feature = "ristretto255")]
impl PrivateKdfClient {
    /// Create a new KDF client with server's public key
    pub fn new(server_public_key: &[u8]) -> Result<Self> {
        Ok(Self {
            oprf_client: Ristretto255Client::new(server_public_key)?,
        })
    }

    /// Start a key derivation request
    ///
    /// # Arguments
    /// * `input` - The secret input (e.g., password, master secret)
    /// * `context` - Purpose of the derived key (e.g., "encryption", "signing")
    /// * `info` - Optional additional context data
    pub fn derive_request(
        &self,
        input: &[u8],
        context: impl Into<String>,
        info: Option<&[u8]>,
    ) -> Result<(KdfRequest, KdfState)> {
        let context = context.into();
        let info = info.map(|i| i.to_vec()).unwrap_or_default();

        // Combine input with context for domain separation
        let combined = [input, context.as_bytes(), &info].concat();

        // Blind the combined input
        let (blinded, oprf_state) = self.oprf_client.blind(&combined)?;

        let request = KdfRequest {
            blinded: blinded.element,
            context: context.clone(),
            info: info.clone(),
        };

        let state = KdfState {
            oprf_state,
            context,
            info,
        };

        Ok((request, state))
    }

    /// Finalize key derivation after receiving server response
    pub fn derive_key(&self, state: KdfState, response: &KdfResponse) -> Result<DerivedKey> {
        // Reconstruct evaluation
        let evaluation = crate::oprf::Evaluation::with_proof(
            response.evaluated.clone(),
            response.proof.clone(),
        );

        // Finalize OPRF
        let output = self.oprf_client.finalize(state.oprf_state, &evaluation)?;

        // Derive final key with context binding
        let key = output.derive_key();

        Ok(DerivedKey::new(key, &response.key_id, &state.context))
    }

    /// Derive a key in one call (for testing/simple cases)
    #[cfg(feature = "ristretto255")]
    pub fn derive_with_server(
        &self,
        input: &[u8],
        context: &str,
        server: &super::PrivateKdfServer,
    ) -> Result<DerivedKey> {
        let (request, state) = self.derive_request(input, context, None)?;
        let response = server.evaluate(&request)?;
        self.derive_key(state, &response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::private_kdf::PrivateKdfServer;

    #[cfg(feature = "ristretto255")]
    #[test]
    fn test_derive_request() {
        let server = PrivateKdfServer::new("test-key").unwrap();
        let client = PrivateKdfClient::new(&server.public_key()).unwrap();

        let (request, _state) = client.derive_request(b"password", "encryption", None).unwrap();
        assert!(!request.blinded.is_empty());
        assert_eq!(request.context, "encryption");
    }

    #[cfg(feature = "ristretto255")]
    #[test]
    fn test_full_kdf_flow() {
        let server = PrivateKdfServer::new("kdf-key").unwrap();
        let client = PrivateKdfClient::new(&server.public_key()).unwrap();

        let key1 = client.derive_with_server(b"password", "encryption", &server).unwrap();
        let key2 = client.derive_with_server(b"password", "encryption", &server).unwrap();

        // Same input produces same key
        assert_eq!(key1.as_bytes(), key2.as_bytes());

        // Different context produces different key
        let key3 = client.derive_with_server(b"password", "signing", &server).unwrap();
        assert_ne!(key1.as_bytes(), key3.as_bytes());
    }

    #[cfg(feature = "ristretto255")]
    #[test]
    fn test_different_inputs() {
        let server = PrivateKdfServer::new("kdf-key").unwrap();
        let client = PrivateKdfClient::new(&server.public_key()).unwrap();

        let key1 = client.derive_with_server(b"password1", "encryption", &server).unwrap();
        let key2 = client.derive_with_server(b"password2", "encryption", &server).unwrap();

        // Different inputs produce different keys
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }
}
