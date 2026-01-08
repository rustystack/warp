//! Ephemeral relay authentication for Portal Hub
//!
//! This module extends the base authentication system to support ephemeral access:
//! - Time-limited relay tokens for external collaborators
//! - Scoped relay permissions (which peers/channels can be relayed)
//! - Session-based authorization with sponsor attribution
//! - Rate limiting per ephemeral identity
//!
//! # Authentication Flow for Ephemeral Access
//!
//! 1. Sponsor creates ephemeral identity with allowed relay targets
//! 2. Ephemeral user receives relay token with scoped permissions
//! 3. Hub validates ephemeral token on each relay request
//! 4. Access denied if token expired, revoked, or target not allowed
//!
//! # Security
//!
//! - Ephemeral tokens have shorter expiration (configurable)
//! - Tokens are tied to specific session IDs
//! - Sponsor ID tracked for cost attribution
//! - Revocation list for immediate access termination

use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{Error, Result};

/// Default ephemeral token expiration (15 minutes - shorter than regular tokens)
const EPHEMERAL_TOKEN_EXPIRATION_MINUTES: i64 = 15;

/// Maximum relay targets per ephemeral identity
const MAX_RELAY_TARGETS: usize = 100;

/// Ephemeral relay token for time-limited access
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EphemeralRelayToken {
    /// Ephemeral identity ID (from hpc-ephemeral-identity)
    pub ephemeral_identity_id: Uuid,

    /// Session ID this token belongs to
    pub session_id: String,

    /// Sponsor ID (who created the ephemeral identity)
    pub sponsor_id: Uuid,

    /// Token expiration timestamp
    pub expires_at: DateTime<Utc>,

    /// Ed25519 signature over the canonical message
    #[serde(with = "signature_serde")]
    pub signature: Signature,
}

impl EphemeralRelayToken {
    /// Create a new ephemeral relay token
    #[must_use]
    pub fn new(
        ephemeral_identity_id: Uuid,
        session_id: String,
        sponsor_id: Uuid,
        signing_key: &SigningKey,
        ttl_minutes: Option<i64>,
    ) -> Self {
        let expires_at = Utc::now()
            + Duration::minutes(ttl_minutes.unwrap_or(EPHEMERAL_TOKEN_EXPIRATION_MINUTES));
        let message =
            Self::canonical_message(ephemeral_identity_id, &session_id, sponsor_id, expires_at);
        let signature = signing_key.sign(&message);

        Self {
            ephemeral_identity_id,
            session_id,
            sponsor_id,
            expires_at,
            signature,
        }
    }

    /// Verify the token signature and expiration
    ///
    /// # Errors
    ///
    /// Returns an error if the token has expired or the signature verification fails
    pub fn verify(&self, public_key: &VerifyingKey) -> Result<()> {
        // Check expiration
        if Utc::now() >= self.expires_at {
            tracing::debug!(
                ephemeral_id = %self.ephemeral_identity_id,
                expires_at = %self.expires_at,
                "Ephemeral relay token expired"
            );
            return Err(Error::AuthFailed);
        }

        // Verify signature
        let message = Self::canonical_message(
            self.ephemeral_identity_id,
            &self.session_id,
            self.sponsor_id,
            self.expires_at,
        );
        public_key.verify(&message, &self.signature).map_err(|e| {
            tracing::debug!(
                ephemeral_id = %self.ephemeral_identity_id,
                error = %e,
                "Ephemeral signature verification failed"
            );
            Error::InvalidSignature
        })?;

        Ok(())
    }

    /// Check if token is expired
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    /// Time remaining until expiry
    #[must_use]
    pub fn time_remaining(&self) -> std::time::Duration {
        let now = Utc::now();
        if now >= self.expires_at {
            std::time::Duration::ZERO
        } else {
            (self.expires_at - now)
                .to_std()
                .unwrap_or(std::time::Duration::ZERO)
        }
    }

    /// Generate canonical message for signing
    fn canonical_message(
        ephemeral_identity_id: Uuid,
        session_id: &str,
        sponsor_id: Uuid,
        expires_at: DateTime<Utc>,
    ) -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(b"ephemeral_relay:");
        message.extend_from_slice(ephemeral_identity_id.as_bytes());
        message.extend_from_slice(session_id.as_bytes());
        message.extend_from_slice(sponsor_id.as_bytes());
        message.extend_from_slice(&expires_at.timestamp().to_le_bytes());
        message
    }
}

/// Ephemeral relay permissions - what an ephemeral identity can access
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EphemeralRelayPermissions {
    /// Allowed relay targets (public keys as hex)
    pub allowed_targets: HashSet<String>,

    /// Allowed channel labels (glob patterns supported)
    pub allowed_channels: HashSet<String>,

    /// Maximum payload size in bytes
    pub max_payload_size: usize,

    /// Rate limit (relays per minute)
    pub rate_limit_per_minute: u32,

    /// Priority level for relay scheduling
    pub priority: RelayPriority,
}

impl Default for EphemeralRelayPermissions {
    fn default() -> Self {
        Self {
            allowed_targets: HashSet::new(),
            allowed_channels: HashSet::new(),
            max_payload_size: 64 * 1024, // 64KB
            rate_limit_per_minute: 60,
            priority: RelayPriority::Low,
        }
    }
}

impl EphemeralRelayPermissions {
    /// Create permissions with specific targets
    #[must_use]
    pub fn with_targets(targets: Vec<String>) -> Self {
        Self {
            allowed_targets: targets.into_iter().collect(),
            ..Default::default()
        }
    }

    /// Add a target
    ///
    /// # Errors
    ///
    /// Returns an error if the maximum number of relay targets has been exceeded
    pub fn add_target(&mut self, target: String) -> Result<()> {
        if self.allowed_targets.len() >= MAX_RELAY_TARGETS {
            return Err(Error::Configuration("max relay targets exceeded".into()));
        }
        self.allowed_targets.insert(target);
        Ok(())
    }

    /// Add a channel pattern
    pub fn add_channel(&mut self, channel: String) {
        self.allowed_channels.insert(channel);
    }

    /// Check if target is allowed
    #[must_use]
    pub fn can_relay_to(&self, target: &str) -> bool {
        // Empty allowed_targets means no restrictions
        self.allowed_targets.is_empty() || self.allowed_targets.contains(target)
    }

    /// Check if channel is allowed
    #[must_use]
    pub fn can_access_channel(&self, channel: &str) -> bool {
        if self.allowed_channels.is_empty() {
            return true;
        }

        for pattern in &self.allowed_channels {
            if matches_pattern(pattern, channel) {
                return true;
            }
        }
        false
    }
}

/// Relay priority for ephemeral access
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum RelayPriority {
    /// Lowest priority (background)
    VeryLow,
    /// Low priority (default for ephemeral)
    #[default]
    Low,
    /// Normal priority (for verified ephemeral)
    Normal,
    /// High priority (for premium ephemeral)
    High,
}

/// Rate limiter for ephemeral relay requests
struct RelayRateLimiter {
    /// Number of requests in current window
    requests: AtomicU64,
    /// Start time of current rate limit window
    window_start: RwLock<Instant>,
    /// Maximum requests allowed per minute
    limit_per_minute: u32,
}

impl RelayRateLimiter {
    /// Creates a new rate limiter with specified limit
    fn new(limit_per_minute: u32) -> Self {
        Self {
            requests: AtomicU64::new(0),
            window_start: RwLock::new(Instant::now()),
            limit_per_minute,
        }
    }

    /// Checks and enforces the rate limit
    async fn check_rate_limit(&self) -> Result<()> {
        let elapsed = {
            let window_start = self.window_start.read().await;
            window_start.elapsed()
        };

        // Reset window if past 1 minute
        if elapsed.as_secs() >= 60 {
            let mut window_start = self.window_start.write().await;
            self.requests.store(0, Ordering::Relaxed);
            *window_start = Instant::now();
        }

        // Check limit
        let current = self.requests.fetch_add(1, Ordering::Relaxed);
        if current >= u64::from(self.limit_per_minute) {
            return Err(Error::RateLimited);
        }

        Ok(())
    }
}

/// Registered ephemeral identity in the relay system
struct EphemeralRelayIdentity {
    /// Ephemeral identity ID
    #[allow(dead_code)]
    identity_id: Uuid,
    /// Session ID this identity belongs to
    session_id: String,
    /// Sponsor ID who created this ephemeral identity
    sponsor_id: Uuid,
    /// Relay permissions for this identity
    permissions: EphemeralRelayPermissions,
    /// Public key for signature verification
    #[allow(dead_code)]
    public_key: VerifyingKey,
    /// Rate limiter for relay requests
    rate_limiter: RelayRateLimiter,
    /// When this identity was created
    created_at: DateTime<Utc>,
    /// When this identity expires
    expires_at: DateTime<Utc>,
    /// Total number of relays performed
    total_relays: AtomicU64,
    /// Total bytes relayed
    total_bytes: AtomicU64,
}

/// Ephemeral relay authorization service
pub struct EphemeralRelayAuth {
    /// Registered ephemeral identities
    identities: DashMap<Uuid, EphemeralRelayIdentity>,

    /// Session to identity mapping
    session_index: DashMap<String, Vec<Uuid>>,

    /// Revocation list
    revoked: DashMap<Uuid, DateTime<Utc>>,

    /// Signing key for token generation
    signing_key: SigningKey,

    /// Statistics
    total_registered: AtomicU64,
    total_revoked: AtomicU64,
    total_relays: AtomicU64,
}

impl EphemeralRelayAuth {
    /// Create a new ephemeral relay auth service
    #[must_use]
    pub fn new(signing_key: SigningKey) -> Self {
        Self {
            identities: DashMap::new(),
            session_index: DashMap::new(),
            revoked: DashMap::new(),
            signing_key,
            total_registered: AtomicU64::new(0),
            total_revoked: AtomicU64::new(0),
            total_relays: AtomicU64::new(0),
        }
    }

    /// Create with random key (for testing)
    #[cfg(test)]
    pub fn new_random() -> Self {
        use rand::rngs::OsRng;
        Self::new(SigningKey::generate(&mut OsRng))
    }

    /// Get the verifying key
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Register an ephemeral identity for relay access
    ///
    /// # Errors
    ///
    /// Returns an error if the ephemeral identity is already registered
    pub fn register(
        &self,
        ephemeral_identity_id: Uuid,
        session_id: String,
        sponsor_id: Uuid,
        public_key: VerifyingKey,
        permissions: EphemeralRelayPermissions,
        ttl_minutes: i64,
    ) -> Result<EphemeralRelayToken> {
        // Check if already registered
        if self.identities.contains_key(&ephemeral_identity_id) {
            return Err(Error::AlreadyExists(format!(
                "ephemeral identity {ephemeral_identity_id} already registered"
            )));
        }

        let now = Utc::now();
        let expires_at = now + Duration::minutes(ttl_minutes);

        // Create rate limiter
        let rate_limiter = RelayRateLimiter::new(permissions.rate_limit_per_minute);

        // Store identity
        let identity = EphemeralRelayIdentity {
            identity_id: ephemeral_identity_id,
            session_id: session_id.clone(),
            sponsor_id,
            permissions,
            public_key,
            rate_limiter,
            created_at: now,
            expires_at,
            total_relays: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
        };

        self.identities.insert(ephemeral_identity_id, identity);

        // Update session index
        self.session_index
            .entry(session_id.clone())
            .or_default()
            .push(ephemeral_identity_id);

        self.total_registered.fetch_add(1, Ordering::Relaxed);

        // Generate token
        let token = EphemeralRelayToken::new(
            ephemeral_identity_id,
            session_id,
            sponsor_id,
            &self.signing_key,
            Some(ttl_minutes),
        );

        tracing::info!(
            ephemeral_id = %ephemeral_identity_id,
            session = %token.session_id,
            expires_at = %expires_at,
            "Ephemeral identity registered for relay"
        );

        Ok(token)
    }

    /// Authorize a relay request
    ///
    /// # Errors
    ///
    /// Returns an error if the token verification fails, the identity is revoked or expired,
    /// the target is not allowed, the payload is too large, or the rate limit is exceeded
    pub async fn authorize_relay(
        &self,
        token: &EphemeralRelayToken,
        target: &str,
        payload_size: usize,
    ) -> Result<RelayAuthorization> {
        // Verify token signature
        token.verify(&self.verifying_key())?;

        // Check revocation
        if self.revoked.contains_key(&token.ephemeral_identity_id) {
            tracing::debug!(
                ephemeral_id = %token.ephemeral_identity_id,
                "Ephemeral identity revoked"
            );
            return Err(Error::AuthFailed);
        }

        // Get identity
        let identity = self
            .identities
            .get(&token.ephemeral_identity_id)
            .ok_or_else(|| {
                tracing::debug!(
                    ephemeral_id = %token.ephemeral_identity_id,
                    "Ephemeral identity not found"
                );
                Error::NotFound(token.ephemeral_identity_id.to_string())
            })?;

        // Check identity expiration
        if Utc::now() >= identity.expires_at {
            tracing::debug!(
                ephemeral_id = %token.ephemeral_identity_id,
                "Ephemeral identity expired"
            );
            return Err(Error::AuthFailed);
        }

        // Check target permission
        if !identity.permissions.can_relay_to(target) {
            tracing::debug!(
                ephemeral_id = %token.ephemeral_identity_id,
                target = %target,
                "Relay target not allowed"
            );
            return Err(Error::AccessDenied(format!(
                "relay to {target} not allowed"
            )));
        }

        // Check payload size
        if payload_size > identity.permissions.max_payload_size {
            tracing::debug!(
                ephemeral_id = %token.ephemeral_identity_id,
                payload_size = payload_size,
                max = identity.permissions.max_payload_size,
                "Payload too large"
            );
            return Err(Error::Configuration(format!(
                "payload size {} exceeds limit {}",
                payload_size, identity.permissions.max_payload_size
            )));
        }

        // Check rate limit
        identity.rate_limiter.check_rate_limit().await?;

        // Update statistics
        identity.total_relays.fetch_add(1, Ordering::Relaxed);
        identity
            .total_bytes
            .fetch_add(payload_size as u64, Ordering::Relaxed);
        self.total_relays.fetch_add(1, Ordering::Relaxed);

        Ok(RelayAuthorization {
            ephemeral_identity_id: token.ephemeral_identity_id,
            sponsor_id: token.sponsor_id,
            priority: identity.permissions.priority,
        })
    }

    /// Revoke an ephemeral identity
    ///
    /// # Errors
    ///
    /// Returns an error if the ephemeral identity is not found
    pub fn revoke(&self, ephemeral_identity_id: Uuid) -> Result<()> {
        if !self.identities.contains_key(&ephemeral_identity_id) {
            return Err(Error::NotFound(ephemeral_identity_id.to_string()));
        }

        // Remove from identities
        if let Some((_, identity)) = self.identities.remove(&ephemeral_identity_id) {
            // Remove from session index
            if let Some(mut ids) = self.session_index.get_mut(&identity.session_id) {
                ids.retain(|id| *id != ephemeral_identity_id);
            }

            // Add to revocation list
            self.revoked.insert(ephemeral_identity_id, Utc::now());
            self.total_revoked.fetch_add(1, Ordering::Relaxed);

            tracing::info!(
                ephemeral_id = %ephemeral_identity_id,
                "Ephemeral identity revoked"
            );
        }

        Ok(())
    }

    /// Revoke all identities in a session
    pub fn revoke_session(&self, session_id: &str) -> Vec<Uuid> {
        let identity_ids: Vec<Uuid> = self
            .session_index
            .get(session_id)
            .map(|ids| ids.clone())
            .unwrap_or_default();

        for id in &identity_ids {
            let _ = self.revoke(*id);
        }

        self.session_index.remove(session_id);
        identity_ids
    }

    /// Cleanup expired identities
    pub fn cleanup_expired(&self) -> Vec<Uuid> {
        let now = Utc::now();
        let expired: Vec<Uuid> = self
            .identities
            .iter()
            .filter(|entry| entry.value().expires_at <= now)
            .map(|entry| *entry.key())
            .collect();

        for id in &expired {
            let _ = self.revoke(*id);
        }

        expired
    }

    /// Get statistics for an ephemeral identity
    pub fn get_stats(&self, ephemeral_identity_id: Uuid) -> Option<EphemeralRelayStats> {
        self.identities
            .get(&ephemeral_identity_id)
            .map(|identity| EphemeralRelayStats {
                ephemeral_identity_id,
                session_id: identity.session_id.clone(),
                sponsor_id: identity.sponsor_id,
                total_relays: identity.total_relays.load(Ordering::Relaxed),
                total_bytes: identity.total_bytes.load(Ordering::Relaxed),
                created_at: identity.created_at,
                expires_at: identity.expires_at,
            })
    }

    /// Get all identities in a session
    pub fn get_session_identities(&self, session_id: &str) -> Vec<Uuid> {
        self.session_index
            .get(session_id)
            .map(|ids| ids.clone())
            .unwrap_or_default()
    }

    /// Get service statistics
    pub fn service_stats(&self) -> EphemeralRelayServiceStats {
        EphemeralRelayServiceStats {
            total_registered: self.total_registered.load(Ordering::Relaxed),
            total_revoked: self.total_revoked.load(Ordering::Relaxed),
            total_relays: self.total_relays.load(Ordering::Relaxed),
            active_identities: self.identities.len() as u64,
            active_sessions: self.session_index.len() as u64,
        }
    }
}

/// Result of successful relay authorization
#[derive(Debug, Clone)]
pub struct RelayAuthorization {
    /// Ephemeral identity ID that was authorized
    pub ephemeral_identity_id: Uuid,
    /// Sponsor ID for cost attribution
    pub sponsor_id: Uuid,
    /// Relay priority level
    pub priority: RelayPriority,
}

/// Statistics for an ephemeral relay identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EphemeralRelayStats {
    /// Ephemeral identity ID
    pub ephemeral_identity_id: Uuid,
    /// Session ID this identity belongs to
    pub session_id: String,
    /// Sponsor ID who created this identity
    pub sponsor_id: Uuid,
    /// Total number of relays performed
    pub total_relays: u64,
    /// Total bytes relayed
    pub total_bytes: u64,
    /// When this identity was created
    pub created_at: DateTime<Utc>,
    /// When this identity expires
    pub expires_at: DateTime<Utc>,
}

/// Service-level statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EphemeralRelayServiceStats {
    /// Total number of ephemeral identities ever registered
    pub total_registered: u64,
    /// Total number of ephemeral identities ever revoked
    pub total_revoked: u64,
    /// Total number of relays performed across all identities
    pub total_relays: u64,
    /// Number of currently active ephemeral identities
    pub active_identities: u64,
    /// Number of active sessions with ephemeral identities
    pub active_sessions: u64,
}

/// Simple glob pattern matching
fn matches_pattern(pattern: &str, value: &str) -> bool {
    if pattern == "*" || pattern == "**" {
        return true;
    }

    if let Some(prefix) = pattern.strip_suffix("/*") {
        return value.starts_with(prefix);
    }

    if let Some(prefix) = pattern.strip_suffix("/**") {
        return value.starts_with(prefix);
    }

    pattern == value
}

/// Signature serialization helpers for Ed25519 signatures
mod signature_serde {
    use ed25519_dalek::Signature;
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serializes an Ed25519 signature to bytes
    pub fn serialize<S>(signature: &Signature, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&signature.to_bytes())
    }

    /// Deserializes an Ed25519 signature from bytes
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Signature, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        let array: [u8; 64] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid signature length"))?;
        Ok(Signature::from_bytes(&array))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn create_test_auth() -> EphemeralRelayAuth {
        EphemeralRelayAuth::new_random()
    }

    fn create_test_key() -> (SigningKey, VerifyingKey) {
        let signing = SigningKey::generate(&mut OsRng);
        let verifying = signing.verifying_key();
        (signing, verifying)
    }

    #[test]
    fn test_token_creation() {
        let (signing_key, verifying_key) = create_test_key();
        let identity_id = Uuid::new_v4();
        let session_id = "test-session".to_string();
        let sponsor_id = Uuid::new_v4();

        let token = EphemeralRelayToken::new(
            identity_id,
            session_id.clone(),
            sponsor_id,
            &signing_key,
            Some(30),
        );

        assert_eq!(token.ephemeral_identity_id, identity_id);
        assert_eq!(token.session_id, session_id);
        assert_eq!(token.sponsor_id, sponsor_id);
        assert!(token.verify(&verifying_key).is_ok());
    }

    #[test]
    fn test_token_expiration() {
        let (signing_key, verifying_key) = create_test_key();
        let identity_id = Uuid::new_v4();

        // Create expired token
        let expires_at = Utc::now() - Duration::minutes(1);
        let message =
            EphemeralRelayToken::canonical_message(identity_id, "test", Uuid::new_v4(), expires_at);
        let signature = signing_key.sign(&message);

        let token = EphemeralRelayToken {
            ephemeral_identity_id: identity_id,
            session_id: "test".to_string(),
            sponsor_id: Uuid::new_v4(),
            expires_at,
            signature,
        };

        assert!(token.is_expired());
        assert!(token.verify(&verifying_key).is_err());
    }

    #[test]
    fn test_permissions_default() {
        let perms = EphemeralRelayPermissions::default();
        assert!(perms.allowed_targets.is_empty());
        assert!(perms.allowed_channels.is_empty());
        assert_eq!(perms.max_payload_size, 64 * 1024);
        assert_eq!(perms.rate_limit_per_minute, 60);
    }

    #[test]
    fn test_permissions_target_check() {
        let mut perms = EphemeralRelayPermissions::default();

        // Empty targets allows all
        assert!(perms.can_relay_to("any-target"));

        // Add specific target
        perms.add_target("allowed-target".to_string()).unwrap();
        assert!(perms.can_relay_to("allowed-target"));
        assert!(!perms.can_relay_to("blocked-target"));
    }

    #[test]
    fn test_permissions_channel_check() {
        let mut perms = EphemeralRelayPermissions::default();

        // Empty channels allows all
        assert!(perms.can_access_channel("any-channel"));

        // Add specific channel
        perms.add_channel("collaboration/*".to_string());
        assert!(perms.can_access_channel("collaboration/notebook"));
        assert!(!perms.can_access_channel("admin/settings"));
    }

    #[tokio::test]
    async fn test_register_and_authorize() {
        let auth = create_test_auth();
        let (_, verifying_key) = create_test_key();
        let identity_id = Uuid::new_v4();
        let session_id = "test-session".to_string();
        let sponsor_id = Uuid::new_v4();

        let token = auth
            .register(
                identity_id,
                session_id,
                sponsor_id,
                verifying_key,
                EphemeralRelayPermissions::default(),
                30,
            )
            .unwrap();

        assert_eq!(token.ephemeral_identity_id, identity_id);

        // Authorize relay
        let result = auth.authorize_relay(&token, "any-target", 1000).await;
        assert!(result.is_ok());

        let authz = result.unwrap();
        assert_eq!(authz.ephemeral_identity_id, identity_id);
        assert_eq!(authz.sponsor_id, sponsor_id);
    }

    #[tokio::test]
    async fn test_authorize_target_denied() {
        let auth = create_test_auth();
        let (_, verifying_key) = create_test_key();

        let mut perms = EphemeralRelayPermissions::default();
        perms.add_target("allowed-target".to_string()).unwrap();

        let token = auth
            .register(
                Uuid::new_v4(),
                "session".to_string(),
                Uuid::new_v4(),
                verifying_key,
                perms,
                30,
            )
            .unwrap();

        // Allowed target
        let result = auth.authorize_relay(&token, "allowed-target", 100).await;
        assert!(result.is_ok());

        // Blocked target
        let result = auth.authorize_relay(&token, "blocked-target", 100).await;
        assert!(matches!(result, Err(Error::AccessDenied(_))));
    }

    #[tokio::test]
    async fn test_authorize_payload_too_large() {
        let auth = create_test_auth();
        let (_, verifying_key) = create_test_key();

        let mut perms = EphemeralRelayPermissions::default();
        perms.max_payload_size = 100;

        let token = auth
            .register(
                Uuid::new_v4(),
                "session".to_string(),
                Uuid::new_v4(),
                verifying_key,
                perms,
                30,
            )
            .unwrap();

        // Too large
        let result = auth.authorize_relay(&token, "target", 200).await;
        assert!(matches!(result, Err(Error::Configuration(_))));
    }

    #[test]
    fn test_revoke() {
        let auth = create_test_auth();
        let (_, verifying_key) = create_test_key();
        let identity_id = Uuid::new_v4();

        auth.register(
            identity_id,
            "session".to_string(),
            Uuid::new_v4(),
            verifying_key,
            EphemeralRelayPermissions::default(),
            30,
        )
        .unwrap();

        assert!(auth.revoke(identity_id).is_ok());
        assert!(auth.get_stats(identity_id).is_none());
    }

    #[test]
    fn test_revoke_session() {
        let auth = create_test_auth();
        let session_id = "shared-session".to_string();

        // Register multiple identities in same session
        for _ in 0..3 {
            let (_, verifying_key) = create_test_key();
            auth.register(
                Uuid::new_v4(),
                session_id.clone(),
                Uuid::new_v4(),
                verifying_key,
                EphemeralRelayPermissions::default(),
                30,
            )
            .unwrap();
        }

        let revoked = auth.revoke_session(&session_id);
        assert_eq!(revoked.len(), 3);
        assert!(auth.get_session_identities(&session_id).is_empty());
    }

    #[test]
    fn test_service_stats() {
        let auth = create_test_auth();
        let (_, verifying_key) = create_test_key();

        auth.register(
            Uuid::new_v4(),
            "session".to_string(),
            Uuid::new_v4(),
            verifying_key,
            EphemeralRelayPermissions::default(),
            30,
        )
        .unwrap();

        let stats = auth.service_stats();
        assert_eq!(stats.total_registered, 1);
        assert_eq!(stats.active_identities, 1);
        assert_eq!(stats.active_sessions, 1);
    }

    #[test]
    fn test_pattern_matching() {
        assert!(matches_pattern("*", "anything"));
        assert!(matches_pattern("**", "anything"));
        assert!(matches_pattern("foo/*", "foo/bar"));
        assert!(matches_pattern("foo/**", "foo/bar/baz"));
        assert!(matches_pattern("exact", "exact"));
        assert!(!matches_pattern("foo/*", "bar/baz"));
    }

    #[tokio::test]
    async fn test_revoked_identity_denied() {
        let auth = create_test_auth();
        let (_, verifying_key) = create_test_key();
        let identity_id = Uuid::new_v4();

        let token = auth
            .register(
                identity_id,
                "session".to_string(),
                Uuid::new_v4(),
                verifying_key,
                EphemeralRelayPermissions::default(),
                30,
            )
            .unwrap();

        // Revoke
        auth.revoke(identity_id).unwrap();

        // Try to authorize
        let result = auth.authorize_relay(&token, "target", 100).await;
        assert!(matches!(result, Err(Error::AuthFailed)));
    }
}
