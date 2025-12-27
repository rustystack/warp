//! Blind deduplication client

use super::DedupToken;
use crate::error::Result;
use crate::oprf::{BlindedInput, ClientState, Evaluation, OprfClientTrait};

#[cfg(feature = "ristretto255")]
use crate::oprf::Ristretto255Client;

/// Client for content-blind deduplication
#[cfg(feature = "ristretto255")]
pub struct BlindDedupClient {
    client: Ristretto255Client,
}

#[cfg(feature = "ristretto255")]
impl BlindDedupClient {
    /// Create a new dedup client with server's public key
    pub fn new(server_public_key: &[u8]) -> Result<Self> {
        Ok(Self {
            client: Ristretto255Client::new(server_public_key)?,
        })
    }

    /// Blind a content hash for deduplication
    ///
    /// Takes the BLAKE3 hash of the content and returns a blinded
    /// request to send to the server.
    pub fn blind_hash(&self, content_hash: &[u8]) -> Result<(BlindedInput, ClientState)> {
        self.client.blind(content_hash)
    }

    /// Blind raw content data
    ///
    /// First hashes the content with BLAKE3, then blinds the hash.
    /// Use `blind_hash` if you already have the hash.
    pub fn blind_content(&self, content: &[u8]) -> Result<(BlindedInput, ClientState)> {
        let hash: [u8; 32] = warp_hash::hash(content);
        self.blind_hash(&hash)
    }

    /// Finalize the OPRF to get a dedup token
    pub fn finalize(&self, state: ClientState, evaluation: &Evaluation) -> Result<DedupToken> {
        let output = self.client.finalize(state, evaluation)?;

        // Derive the dedup token from OPRF output
        let key = output.derive_key();
        Ok(DedupToken::from_bytes(key))
    }

    /// Complete dedup flow in one call (for testing/simple cases)
    ///
    /// This is a convenience method that combines blind + server evaluate + finalize.
    /// In production, the evaluate step happens on the server.
    #[cfg(feature = "ristretto255")]
    pub fn compute_token_with_server(
        &self,
        content: &[u8],
        server: &super::BlindDedupServer,
    ) -> Result<DedupToken> {
        let (blinded, state) = self.blind_content(content)?;
        let evaluation = server.evaluate(&blinded)?;
        self.finalize(state, &evaluation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dedup::BlindDedupServer;

    #[cfg(feature = "ristretto255")]
    #[test]
    fn test_blind_hash() {
        let server = BlindDedupServer::new("test-key").unwrap();
        let client = BlindDedupClient::new(&server.public_key()).unwrap();

        let hash = [0x42u8; 32];
        let (blinded, _state) = client.blind_hash(&hash).unwrap();

        assert_eq!(blinded.element.len(), 32);
    }

    #[cfg(feature = "ristretto255")]
    #[test]
    fn test_full_dedup_flow() {
        let server = BlindDedupServer::new("test-key").unwrap();
        let client = BlindDedupClient::new(&server.public_key()).unwrap();

        let content = b"some content to deduplicate";
        let token = client.compute_token_with_server(content, &server).unwrap();

        // Same content should produce same token
        let token2 = client.compute_token_with_server(content, &server).unwrap();
        assert_eq!(token, token2);

        // Different content should produce different token
        let token3 = client
            .compute_token_with_server(b"different content", &server)
            .unwrap();
        assert_ne!(token, token3);
    }

    #[cfg(feature = "ristretto255")]
    #[test]
    fn test_different_servers_different_tokens() {
        let server1 = BlindDedupServer::new("key-1").unwrap();
        let server2 = BlindDedupServer::new("key-2").unwrap();

        let client1 = BlindDedupClient::new(&server1.public_key()).unwrap();
        let client2 = BlindDedupClient::new(&server2.public_key()).unwrap();

        let content = b"same content";

        let token1 = client1.compute_token_with_server(content, &server1).unwrap();
        let token2 = client2.compute_token_with_server(content, &server2).unwrap();

        // Different server keys produce different tokens
        assert_ne!(token1, token2);
    }
}
