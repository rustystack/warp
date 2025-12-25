//! Ephemeral URL generation with Ed25519 signed tokens
//!
//! Ephemeral tokens provide time-limited, scoped access to objects without
//! requiring full authentication. They can be embedded in URLs for sharing.

use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

use crate::key::ObjectKey;
use crate::{Error, Result};

/// Access scope for an ephemeral token
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AccessScope {
    /// Access to a single object
    Object(ObjectKey),

    /// Access to all objects with a prefix
    Prefix {
        /// Bucket name
        bucket: String,
        /// Key prefix
        prefix: String,
    },

    /// Access to an entire bucket
    Bucket(String),
}

impl AccessScope {
    /// Check if this scope allows access to the given key
    pub fn allows(&self, key: &ObjectKey) -> bool {
        match self {
            AccessScope::Object(allowed) => allowed == key,
            AccessScope::Prefix { bucket, prefix } => {
                key.bucket() == bucket && key.key().starts_with(prefix)
            }
            AccessScope::Bucket(bucket) => key.bucket() == bucket,
        }
    }
}

/// Permissions granted by a token
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Permissions {
    /// Can read objects
    pub read: bool,

    /// Can write objects
    pub write: bool,

    /// Can delete objects
    pub delete: bool,

    /// Can list objects
    pub list: bool,
}

impl Permissions {
    /// Read-only permission
    pub const READ: Self = Self {
        read: true,
        write: false,
        delete: false,
        list: false,
    };

    /// Read and list permission
    pub const READ_LIST: Self = Self {
        read: true,
        write: false,
        delete: false,
        list: true,
    };

    /// Write-only permission (for uploads)
    pub const WRITE: Self = Self {
        read: false,
        write: true,
        delete: false,
        list: false,
    };

    /// Read and write permission
    pub const READ_WRITE: Self = Self {
        read: true,
        write: true,
        delete: false,
        list: true,
    };

    /// Full permission
    pub const FULL: Self = Self {
        read: true,
        write: true,
        delete: true,
        list: true,
    };

    /// Check if read is allowed
    pub fn can_read(&self) -> bool {
        self.read
    }

    /// Check if write is allowed
    pub fn can_write(&self) -> bool {
        self.write
    }

    /// Check if delete is allowed
    pub fn can_delete(&self) -> bool {
        self.delete
    }

    /// Check if list is allowed
    pub fn can_list(&self) -> bool {
        self.list
    }
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimit {
    /// Maximum requests per second
    pub requests_per_second: u32,

    /// Maximum bytes per second
    pub bytes_per_second: Option<u64>,

    /// Maximum total requests
    pub max_requests: Option<u64>,

    /// Maximum total bytes
    pub max_bytes: Option<u64>,
}

impl RateLimit {
    /// Create a new rate limit
    pub fn new(requests_per_second: u32) -> Self {
        Self {
            requests_per_second,
            bytes_per_second: None,
            max_requests: None,
            max_bytes: None,
        }
    }

    /// Set bytes per second limit
    pub fn with_bytes_per_second(mut self, bps: u64) -> Self {
        self.bytes_per_second = Some(bps);
        self
    }

    /// Set maximum total requests
    pub fn with_max_requests(mut self, max: u64) -> Self {
        self.max_requests = Some(max);
        self
    }

    /// Set maximum total bytes
    pub fn with_max_bytes(mut self, max: u64) -> Self {
        self.max_bytes = Some(max);
        self
    }
}

/// The payload that gets signed
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenPayload {
    /// Access scope
    scope: AccessScope,

    /// Permissions
    permissions: Permissions,

    /// Expiration timestamp (Unix timestamp)
    expires_at: i64,

    /// IP restrictions
    ip_restrictions: Option<Vec<IpNet>>,

    /// Rate limiting
    rate_limit: Option<RateLimit>,

    /// Nonce for uniqueness
    nonce: u64,
}

/// An ephemeral access token
///
/// Tokens are signed with Ed25519 and can be serialized to base64 for embedding in URLs.
#[derive(Debug, Clone)]
pub struct EphemeralToken {
    /// The token payload
    payload: TokenPayload,

    /// Ed25519 signature over the payload
    signature: Signature,
}

impl EphemeralToken {
    /// Generate a new ephemeral token
    ///
    /// # Arguments
    /// * `signing_key` - The Ed25519 signing key
    /// * `scope` - What the token grants access to
    /// * `permissions` - What operations are allowed
    /// * `ttl` - How long the token is valid
    /// * `ip_restrictions` - Optional IP allowlist
    /// * `rate_limit` - Optional rate limiting
    pub fn generate(
        signing_key: &SigningKey,
        scope: AccessScope,
        permissions: Permissions,
        ttl: std::time::Duration,
        ip_restrictions: Option<Vec<IpNet>>,
        rate_limit: Option<RateLimit>,
    ) -> Result<Self> {
        let expires_at = Utc::now() + Duration::from_std(ttl).map_err(|_| {
            Error::TokenEncoding("invalid TTL duration".to_string())
        })?;

        let payload = TokenPayload {
            scope,
            permissions,
            expires_at: expires_at.timestamp(),
            ip_restrictions,
            rate_limit,
            nonce: rand::random(),
        };

        // Serialize payload for signing
        let payload_bytes = rmp_serde::to_vec(&payload)?;

        // Sign the payload
        let signature = signing_key.sign(&payload_bytes);

        Ok(Self { payload, signature })
    }

    /// Verify the token
    ///
    /// # Arguments
    /// * `verifying_key` - The Ed25519 verifying key
    /// * `request_ip` - Optional IP address of the requester
    pub fn verify(
        &self,
        verifying_key: &VerifyingKey,
        request_ip: Option<IpAddr>,
    ) -> Result<()> {
        // Check expiration
        let now = Utc::now().timestamp();
        if now > self.payload.expires_at {
            return Err(Error::TokenExpired);
        }

        // Check IP restrictions
        if let (Some(restrictions), Some(ip)) = (&self.payload.ip_restrictions, request_ip) {
            let allowed = restrictions.iter().any(|net| net.contains(&ip));
            if !allowed {
                return Err(Error::IpNotAllowed(ip));
            }
        }

        // Verify signature
        let payload_bytes = rmp_serde::to_vec(&self.payload)?;
        verifying_key
            .verify(&payload_bytes, &self.signature)
            .map_err(|_| Error::InvalidSignature)?;

        Ok(())
    }

    /// Get the access scope
    pub fn scope(&self) -> &AccessScope {
        &self.payload.scope
    }

    /// Get the permissions
    pub fn permissions(&self) -> &Permissions {
        &self.payload.permissions
    }

    /// Get the expiration time
    pub fn expires_at(&self) -> DateTime<Utc> {
        DateTime::from_timestamp(self.payload.expires_at, 0)
            .unwrap_or_else(Utc::now)
    }

    /// Get IP restrictions
    pub fn ip_restrictions(&self) -> Option<&[IpNet]> {
        self.payload.ip_restrictions.as_deref()
    }

    /// Get rate limit
    pub fn rate_limit(&self) -> Option<&RateLimit> {
        self.payload.rate_limit.as_ref()
    }

    /// Check if this token allows access to a key
    pub fn allows(&self, key: &ObjectKey) -> bool {
        self.payload.scope.allows(key)
    }

    /// Encode the token to a base64 string
    pub fn encode(&self) -> String {
        use base64::Engine;

        #[derive(Serialize)]
        struct EncodedToken<'a> {
            payload: &'a TokenPayload,
            #[serde(with = "serde_bytes")]
            signature: Vec<u8>,
        }

        let encoded = EncodedToken {
            payload: &self.payload,
            signature: self.signature.to_bytes().to_vec(),
        };

        let bytes = rmp_serde::to_vec(&encoded).unwrap_or_default();
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes)
    }

    /// Decode a token from a base64 string
    pub fn decode(s: &str) -> Result<Self> {
        use base64::Engine;

        #[derive(Deserialize)]
        struct EncodedToken {
            payload: TokenPayload,
            #[serde(with = "serde_bytes")]
            signature: Vec<u8>,
        }

        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)?;
        let encoded: EncodedToken = rmp_serde::from_slice(&bytes)?;

        let sig_bytes: [u8; 64] = encoded.signature.try_into()
            .map_err(|_| Error::TokenEncoding("invalid signature length".to_string()))?;
        let signature = Signature::from_bytes(&sig_bytes);

        Ok(Self {
            payload: encoded.payload,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keys() -> (SigningKey, VerifyingKey) {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    #[test]
    fn test_token_generation_and_verification() {
        let (signing_key, verifying_key) = test_keys();
        let key = ObjectKey::new("bucket", "path/to/file.txt").unwrap();

        let token = EphemeralToken::generate(
            &signing_key,
            AccessScope::Object(key.clone()),
            Permissions::READ,
            std::time::Duration::from_secs(3600),
            None,
            None,
        )
        .unwrap();

        // Should verify successfully
        assert!(token.verify(&verifying_key, None).is_ok());

        // Should allow access to the key
        assert!(token.allows(&key));

        // Should not allow access to a different key
        let other_key = ObjectKey::new("bucket", "other/file.txt").unwrap();
        assert!(!token.allows(&other_key));
    }

    #[test]
    fn test_token_expiration() {
        let (signing_key, verifying_key) = test_keys();
        let key = ObjectKey::new("bucket", "file.txt").unwrap();

        // Create a token with very short TTL
        let token = EphemeralToken::generate(
            &signing_key,
            AccessScope::Object(key),
            Permissions::READ,
            std::time::Duration::from_millis(1),
            None,
            None,
        )
        .unwrap();

        // Wait for the token to expire (1 second is enough to guarantee expiration)
        std::thread::sleep(std::time::Duration::from_secs(1));
        assert!(matches!(token.verify(&verifying_key, None), Err(Error::TokenExpired)));
    }

    #[test]
    fn test_ip_restrictions() {
        let (signing_key, verifying_key) = test_keys();
        let key = ObjectKey::new("bucket", "file.txt").unwrap();

        let allowed_net: IpNet = "192.168.1.0/24".parse().unwrap();

        let token = EphemeralToken::generate(
            &signing_key,
            AccessScope::Object(key),
            Permissions::READ,
            std::time::Duration::from_secs(3600),
            Some(vec![allowed_net]),
            None,
        )
        .unwrap();

        // Allowed IP
        let allowed_ip: IpAddr = "192.168.1.100".parse().unwrap();
        assert!(token.verify(&verifying_key, Some(allowed_ip)).is_ok());

        // Blocked IP
        let blocked_ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(matches!(
            token.verify(&verifying_key, Some(blocked_ip)),
            Err(Error::IpNotAllowed(_))
        ));
    }

    #[test]
    fn test_prefix_scope() {
        let (signing_key, _) = test_keys();

        let token = EphemeralToken::generate(
            &signing_key,
            AccessScope::Prefix {
                bucket: "bucket".to_string(),
                prefix: "data/2024/".to_string(),
            },
            Permissions::READ_LIST,
            std::time::Duration::from_secs(3600),
            None,
            None,
        )
        .unwrap();

        // Should allow files in prefix
        let key1 = ObjectKey::new("bucket", "data/2024/01/file.csv").unwrap();
        assert!(token.allows(&key1));

        // Should not allow files outside prefix
        let key2 = ObjectKey::new("bucket", "data/2023/12/file.csv").unwrap();
        assert!(!token.allows(&key2));

        // Should not allow different bucket
        let key3 = ObjectKey::new("other-bucket", "data/2024/01/file.csv").unwrap();
        assert!(!token.allows(&key3));
    }

    #[test]
    fn test_token_encode_decode() {
        let (signing_key, verifying_key) = test_keys();
        let key = ObjectKey::new("bucket", "file.txt").unwrap();

        let token = EphemeralToken::generate(
            &signing_key,
            AccessScope::Object(key.clone()),
            Permissions::READ,
            std::time::Duration::from_secs(3600),
            None,
            None,
        )
        .unwrap();

        // Encode
        let encoded = token.encode();
        assert!(!encoded.is_empty());

        // Decode
        let decoded = EphemeralToken::decode(&encoded).unwrap();

        // Should still verify
        assert!(decoded.verify(&verifying_key, None).is_ok());
        assert!(decoded.allows(&key));
    }

    #[test]
    fn test_permissions() {
        assert!(Permissions::READ.can_read());
        assert!(!Permissions::READ.can_write());

        assert!(!Permissions::WRITE.can_read());
        assert!(Permissions::WRITE.can_write());

        assert!(Permissions::FULL.can_read());
        assert!(Permissions::FULL.can_write());
        assert!(Permissions::FULL.can_delete());
        assert!(Permissions::FULL.can_list());
    }
}
