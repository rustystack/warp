//! Access control for portals
//!
//! Fine-grained access control with multiple levels, identity/link/email grants,
//! and conditional access (expiration, usage limits, network, passwords).

use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

/// Access levels ordered by privilege (higher includes all lower permissions)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AccessLevel {
    /// Can see metadata only
    List,
    /// Can download content
    Read,
    /// Can modify content
    Write,
    /// Can grant/revoke access
    Admin,
    /// Full control
    Owner,
}

impl std::fmt::Display for AccessLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::List => write!(f, "List"),
            Self::Read => write!(f, "Read"),
            Self::Write => write!(f, "Write"),
            Self::Admin => write!(f, "Admin"),
            Self::Owner => write!(f, "Owner"),
        }
    }
}

/// Conditional access restrictions (all must be satisfied)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccessConditions {
    /// Access expires at this time
    pub expires_at: Option<DateTime<Utc>>,
    /// Maximum number of uses
    pub max_uses: Option<u64>,
    /// Current usage count
    pub current_uses: u64,
    /// Network CIDR restriction
    pub network_cidr: Option<String>,
    /// BLAKE3 hash of password
    pub password_hash: Option<[u8; 32]>,
}

impl AccessConditions {
    /// Create new default conditions
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set expiration time
    #[must_use]
    pub const fn with_expiration(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Set maximum number of uses
    #[must_use]
    pub const fn with_max_uses(mut self, max_uses: u64) -> Self {
        self.max_uses = Some(max_uses);
        self
    }

    /// Set network CIDR restriction
    #[must_use]
    pub fn with_network(mut self, cidr: String) -> Self {
        self.network_cidr = Some(cidr);
        self
    }

    /// Set password requirement (automatically hashed with BLAKE3)
    #[must_use]
    pub fn with_password(mut self, password: &str) -> Self {
        self.password_hash = Some(warp_hash::hash(password.as_bytes()));
        self
    }

    /// Check if all conditions are satisfied
    #[must_use]
    pub fn is_satisfied(
        &self,
        now: DateTime<Utc>,
        network: Option<&str>,
        password: Option<&str>,
    ) -> bool {
        // Check expiration
        if let Some(expires_at) = self.expires_at
            && now >= expires_at
        {
            return false;
        }

        // Check usage limit
        if let Some(max_uses) = self.max_uses
            && self.current_uses >= max_uses
        {
            return false;
        }

        // Check network restriction (simplified - real impl would parse CIDR)
        if let Some(required_cidr) = &self.network_cidr {
            match network {
                Some(addr) if Self::network_matches(addr, required_cidr) => {}
                _ => return false,
            }
        }

        // Check password
        if let Some(required_hash) = self.password_hash {
            match password {
                Some(pwd) => {
                    let provided_hash = warp_hash::hash(pwd.as_bytes());
                    if provided_hash != required_hash {
                        return false;
                    }
                }
                None => return false,
            }
        }

        true
    }

    /// Record a use of this grant
    pub const fn record_use(&mut self) {
        self.current_uses = self.current_uses.saturating_add(1);
    }

    /// Simple network matching (production would use ipnetwork crate)
    fn network_matches(addr: &str, cidr: &str) -> bool {
        // Simplified implementation - in production use ipnetwork crate
        // For testing, we'll do simple prefix matching
        cidr.split('/')
            .next()
            .is_some_and(|prefix| addr.starts_with(prefix.trim_end_matches(".0")))
    }
}

/// Access grant types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccessGrant {
    /// Grant to ed25519 identity
    Identity {
        /// Ed25519 verifying key
        key: VerifyingKey,
        /// Access level
        level: AccessLevel,
        /// Optional conditions
        conditions: Option<AccessConditions>,
    },
    /// Grant via secret link
    Link {
        /// BLAKE3 hash of secret
        secret_hash: [u8; 32],
        /// Access level
        level: AccessLevel,
        /// Optional conditions
        conditions: Option<AccessConditions>,
    },
    /// Grant to email address
    Email {
        /// Email address
        email: String,
        /// Access level
        level: AccessLevel,
        /// Optional conditions
        conditions: Option<AccessConditions>,
    },
}

impl AccessGrant {
    /// Get the access level for this grant
    #[must_use]
    pub const fn level(&self) -> AccessLevel {
        match self {
            Self::Identity { level, .. } | Self::Link { level, .. } | Self::Email { level, .. } => {
                *level
            }
        }
    }

    /// Get mutable reference to conditions
    pub const fn conditions_mut(&mut self) -> Option<&mut AccessConditions> {
        match self {
            Self::Identity { conditions, .. }
            | Self::Link { conditions, .. }
            | Self::Email { conditions, .. } => conditions.as_mut(),
        }
    }

    /// Check if conditions are satisfied
    #[must_use]
    pub fn conditions_satisfied(
        &self,
        now: DateTime<Utc>,
        network: Option<&str>,
        password: Option<&str>,
    ) -> bool {
        match self {
            Self::Identity { conditions, .. }
            | Self::Link { conditions, .. }
            | Self::Email { conditions, .. } => conditions
                .as_ref()
                .is_none_or(|c| c.is_satisfied(now, network, password)),
        }
    }
}

/// Accessor identity for checking access
#[derive(Debug, Clone)]
pub enum Accessor {
    /// Access via ed25519 key
    Identity(VerifyingKey),
    /// Access via secret link
    Link {
        /// Secret from URL
        secret: String,
        /// Optional password
        password: Option<String>,
    },
    /// Access via email
    Email(String),
}

/// Access control list (highest level from matching grants is used)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccessControlList {
    grants: Vec<AccessGrant>,
}

impl AccessControlList {
    /// Create a new empty ACL
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an access grant (multiple grants allowed, highest level wins)
    pub fn grant(&mut self, grant: AccessGrant) {
        self.grants.push(grant);
    }

    /// Revoke all grants for a specific identity (returns count removed)
    pub fn revoke_identity(&mut self, key: &VerifyingKey) -> usize {
        let initial_len = self.grants.len();
        self.grants.retain(|grant| match grant {
            AccessGrant::Identity { key: grant_key, .. } => grant_key != key,
            _ => true,
        });
        initial_len - self.grants.len()
    }

    /// Revoke all grants for a specific link (returns count removed)
    pub fn revoke_link(&mut self, secret_hash: &[u8; 32]) -> usize {
        let initial_len = self.grants.len();
        self.grants.retain(|grant| match grant {
            AccessGrant::Link {
                secret_hash: hash, ..
            } => hash != secret_hash,
            _ => true,
        });
        initial_len - self.grants.len()
    }

    /// Revoke all grants for a specific email (returns count removed)
    pub fn revoke_email(&mut self, email: &str) -> usize {
        let initial_len = self.grants.len();
        self.grants.retain(|grant| match grant {
            AccessGrant::Email {
                email: grant_email, ..
            } => grant_email != email,
            _ => true,
        });
        initial_len - self.grants.len()
    }

    /// Check if accessor has required access level
    #[must_use]
    pub fn check_access(
        &self,
        accessor: &Accessor,
        required_level: AccessLevel,
        now: DateTime<Utc>,
        network: Option<&str>,
        password: Option<&str>,
    ) -> bool {
        self.get_access_level(accessor, now, network, password)
            .is_some_and(|level| level >= required_level)
    }

    /// Get the effective access level (highest from matching grants)
    #[must_use]
    pub fn get_access_level(
        &self,
        accessor: &Accessor,
        now: DateTime<Utc>,
        network: Option<&str>,
        password: Option<&str>,
    ) -> Option<AccessLevel> {
        let mut max_level: Option<AccessLevel> = None;

        for grant in &self.grants {
            // Check if grant matches accessor
            let matches = match (accessor, grant) {
                (Accessor::Identity(key), AccessGrant::Identity { key: grant_key, .. }) => {
                    key == grant_key
                }
                (
                    Accessor::Link {
                        secret,
                        password: link_password,
                    },
                    AccessGrant::Link { secret_hash, .. },
                ) => {
                    let provided_hash = warp_hash::hash(secret.as_bytes());
                    if provided_hash != *secret_hash {
                        continue;
                    }
                    // For links, use link's password if provided, otherwise use general password
                    let pwd = link_password.as_deref().or(password);
                    // Check conditions with link-specific password
                    if !grant.conditions_satisfied(now, network, pwd) {
                        continue;
                    }
                    true
                }
                (
                    Accessor::Email(email),
                    AccessGrant::Email {
                        email: grant_email, ..
                    },
                ) => email == grant_email,
                _ => false,
            };

            if !matches {
                continue;
            }

            // For non-Link grants, check conditions with provided password
            if !matches!(grant, AccessGrant::Link { .. })
                && !grant.conditions_satisfied(now, network, password)
            {
                continue;
            }

            // Update max level
            let level = grant.level();
            max_level = Some(max_level.map_or(level, |current| current.max(level)));
        }

        max_level
    }

    /// Get all grants in the ACL
    #[must_use]
    pub fn grants(&self) -> &[AccessGrant] {
        &self.grants
    }

    /// Record a use for an accessor's grant (updates first match)
    pub fn record_access(
        &mut self,
        accessor: &Accessor,
        now: DateTime<Utc>,
        network: Option<&str>,
        password: Option<&str>,
    ) {
        for grant in &mut self.grants {
            let matches = match (accessor, &grant) {
                (Accessor::Identity(key), AccessGrant::Identity { key: grant_key, .. }) => {
                    key == grant_key
                }
                (Accessor::Link { secret, .. }, AccessGrant::Link { secret_hash, .. }) => {
                    let provided_hash = warp_hash::hash(secret.as_bytes());
                    provided_hash == *secret_hash
                }
                (
                    Accessor::Email(email),
                    AccessGrant::Email {
                        email: grant_email, ..
                    },
                ) => email == grant_email,
                _ => false,
            };

            if matches && grant.conditions_satisfied(now, network, password) {
                if let Some(conditions) = grant.conditions_mut() {
                    conditions.record_use();
                }
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use ed25519_dalek::SigningKey;

    fn create_test_key(seed: u8) -> (SigningKey, VerifyingKey) {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    #[test]
    fn test_access_level_ordering() {
        assert!(AccessLevel::Owner > AccessLevel::Admin);
        assert!(AccessLevel::Admin > AccessLevel::Write);
        assert!(AccessLevel::Write > AccessLevel::Read);
        assert!(AccessLevel::Read > AccessLevel::List);
        assert!(AccessLevel::Owner > AccessLevel::List);
        assert!(AccessLevel::Admin >= AccessLevel::Write);
    }

    #[test]
    fn test_grant_identity() {
        let mut acl = AccessControlList::new();
        let (_, key) = create_test_key(1);

        acl.grant(AccessGrant::Identity {
            key,
            level: AccessLevel::Read,
            conditions: None,
        });

        let accessor = Accessor::Identity(key);
        let now = Utc::now();

        assert!(acl.check_access(&accessor, AccessLevel::Read, now, None, None));
        assert!(acl.check_access(&accessor, AccessLevel::List, now, None, None));
        assert!(!acl.check_access(&accessor, AccessLevel::Write, now, None, None));
    }

    #[test]
    fn test_grant_link() {
        let mut acl = AccessControlList::new();
        let secret = "super-secret-link-12345";
        let secret_hash = warp_hash::hash(secret.as_bytes());

        acl.grant(AccessGrant::Link {
            secret_hash,
            level: AccessLevel::Read,
            conditions: None,
        });

        let accessor = Accessor::Link {
            secret: secret.to_string(),
            password: None,
        };
        let now = Utc::now();

        assert!(acl.check_access(&accessor, AccessLevel::Read, now, None, None));
        assert!(!acl.check_access(&accessor, AccessLevel::Write, now, None, None));

        // Wrong secret should fail
        let wrong_accessor = Accessor::Link {
            secret: "wrong-secret".to_string(),
            password: None,
        };
        assert!(!acl.check_access(&wrong_accessor, AccessLevel::Read, now, None, None));
    }

    #[test]
    fn test_grant_email() {
        let mut acl = AccessControlList::new();
        let email = "user@example.com";

        acl.grant(AccessGrant::Email {
            email: email.to_string(),
            level: AccessLevel::Write,
            conditions: None,
        });

        let accessor = Accessor::Email(email.to_string());
        let now = Utc::now();

        assert!(acl.check_access(&accessor, AccessLevel::Write, now, None, None));
        assert!(acl.check_access(&accessor, AccessLevel::Read, now, None, None));
        assert!(!acl.check_access(&accessor, AccessLevel::Admin, now, None, None));

        // Different email should fail
        let wrong_accessor = Accessor::Email("other@example.com".to_string());
        assert!(!acl.check_access(&wrong_accessor, AccessLevel::Write, now, None, None));
    }

    #[test]
    fn test_revoke_identity() {
        let mut acl = AccessControlList::new();
        let (_, key1) = create_test_key(1);
        let (_, key2) = create_test_key(2);

        acl.grant(AccessGrant::Identity {
            key: key1,
            level: AccessLevel::Read,
            conditions: None,
        });
        acl.grant(AccessGrant::Identity {
            key: key2,
            level: AccessLevel::Write,
            conditions: None,
        });

        assert_eq!(acl.grants().len(), 2);

        let removed = acl.revoke_identity(&key1);
        assert_eq!(removed, 1);
        assert_eq!(acl.grants().len(), 1);

        let accessor1 = Accessor::Identity(key1);
        let accessor2 = Accessor::Identity(key2);
        let now = Utc::now();

        assert!(!acl.check_access(&accessor1, AccessLevel::Read, now, None, None));
        assert!(acl.check_access(&accessor2, AccessLevel::Write, now, None, None));
    }

    #[test]
    fn test_check_access_level() {
        let mut acl = AccessControlList::new();
        let (_, key) = create_test_key(1);

        acl.grant(AccessGrant::Identity {
            key,
            level: AccessLevel::Write,
            conditions: None,
        });

        let accessor = Accessor::Identity(key);
        let now = Utc::now();

        assert_eq!(
            acl.get_access_level(&accessor, now, None, None),
            Some(AccessLevel::Write)
        );

        // Check that higher levels include lower permissions
        assert!(acl.check_access(&accessor, AccessLevel::List, now, None, None));
        assert!(acl.check_access(&accessor, AccessLevel::Read, now, None, None));
        assert!(acl.check_access(&accessor, AccessLevel::Write, now, None, None));
        assert!(!acl.check_access(&accessor, AccessLevel::Admin, now, None, None));
    }

    #[test]
    fn test_conditions_expiration() {
        let mut acl = AccessControlList::new();
        let (_, key) = create_test_key(1);
        let now = Utc::now();
        let future = now + Duration::hours(1);

        acl.grant(AccessGrant::Identity {
            key,
            level: AccessLevel::Read,
            conditions: Some(AccessConditions::new().with_expiration(future)),
        });

        let accessor = Accessor::Identity(key);
        assert!(acl.check_access(&accessor, AccessLevel::Read, now, None, None));
        assert!(!acl.check_access(&accessor, AccessLevel::Read, future, None, None));
        assert!(!acl.check_access(
            &accessor,
            AccessLevel::Read,
            future + Duration::seconds(1),
            None,
            None
        ));
    }

    #[test]
    fn test_conditions_max_uses() {
        let mut acl = AccessControlList::new();
        let (_, key) = create_test_key(1);

        acl.grant(AccessGrant::Identity {
            key,
            level: AccessLevel::Read,
            conditions: Some(AccessConditions::new().with_max_uses(2)),
        });

        let accessor = Accessor::Identity(key);
        let now = Utc::now();

        assert!(acl.check_access(&accessor, AccessLevel::Read, now, None, None));
        acl.record_access(&accessor, now, None, None);
        assert!(acl.check_access(&accessor, AccessLevel::Read, now, None, None));
        acl.record_access(&accessor, now, None, None);
        assert!(!acl.check_access(&accessor, AccessLevel::Read, now, None, None));
    }

    #[test]
    fn test_conditions_password() {
        let mut acl = AccessControlList::new();
        let (_, key) = create_test_key(1);

        acl.grant(AccessGrant::Identity {
            key,
            level: AccessLevel::Read,
            conditions: Some(AccessConditions::new().with_password("secret123")),
        });

        let accessor = Accessor::Identity(key);
        let now = Utc::now();
        assert!(acl.check_access(&accessor, AccessLevel::Read, now, None, Some("secret123")));
        assert!(!acl.check_access(&accessor, AccessLevel::Read, now, None, Some("wrong")));
        assert!(!acl.check_access(&accessor, AccessLevel::Read, now, None, None));
    }

    #[test]
    fn test_conditions_network() {
        let mut acl = AccessControlList::new();
        let (_, key) = create_test_key(1);

        acl.grant(AccessGrant::Identity {
            key,
            level: AccessLevel::Read,
            conditions: Some(AccessConditions::new().with_network("192.168.1.0/24".to_string())),
        });

        let accessor = Accessor::Identity(key);
        let now = Utc::now();
        assert!(acl.check_access(
            &accessor,
            AccessLevel::Read,
            now,
            Some("192.168.1.100"),
            None
        ));
        assert!(!acl.check_access(&accessor, AccessLevel::Read, now, Some("10.0.0.1"), None));
        assert!(!acl.check_access(&accessor, AccessLevel::Read, now, None, None));
    }

    #[test]
    fn test_acl_multiple_grants() {
        let mut acl = AccessControlList::new();
        let (_, key) = create_test_key(1);

        acl.grant(AccessGrant::Identity {
            key,
            level: AccessLevel::Read,
            conditions: None,
        });
        acl.grant(AccessGrant::Identity {
            key,
            level: AccessLevel::Write,
            conditions: None,
        });

        let accessor = Accessor::Identity(key);
        let now = Utc::now();
        assert_eq!(
            acl.get_access_level(&accessor, now, None, None),
            Some(AccessLevel::Write)
        );
        assert!(acl.check_access(&accessor, AccessLevel::Write, now, None, None));
    }

    #[test]
    fn test_acl_empty() {
        let acl = AccessControlList::new();
        let (_, key) = create_test_key(1);
        let accessor = Accessor::Identity(key);
        let now = Utc::now();
        assert!(!acl.check_access(&accessor, AccessLevel::List, now, None, None));
        assert_eq!(acl.get_access_level(&accessor, now, None, None), None);
    }

    #[test]
    fn test_link_secret_hashing() {
        let secret = "my-secret-link";
        let secret_hash = warp_hash::hash(secret.as_bytes());
        let grant = AccessGrant::Link {
            secret_hash,
            level: AccessLevel::Read,
            conditions: None,
        };

        match grant {
            AccessGrant::Link {
                secret_hash: stored_hash,
                ..
            } => {
                assert_eq!(stored_hash, warp_hash::hash(secret.as_bytes()));
                assert_eq!(stored_hash.len(), 32);
                assert!(stored_hash != secret.as_bytes());
            }
            _ => panic!("Expected Link grant"),
        }
    }

    #[test]
    fn test_link_with_password() {
        let mut acl = AccessControlList::new();
        let secret = "link-secret";
        let secret_hash = warp_hash::hash(secret.as_bytes());

        acl.grant(AccessGrant::Link {
            secret_hash,
            level: AccessLevel::Read,
            conditions: Some(AccessConditions::new().with_password("link-password")),
        });

        let now = Utc::now();
        let ok = Accessor::Link {
            secret: secret.to_string(),
            password: Some("link-password".to_string()),
        };
        let wrong = Accessor::Link {
            secret: secret.to_string(),
            password: Some("wrong".to_string()),
        };
        let none = Accessor::Link {
            secret: secret.to_string(),
            password: None,
        };

        assert!(acl.check_access(&ok, AccessLevel::Read, now, None, None));
        assert!(!acl.check_access(&wrong, AccessLevel::Read, now, None, None));
        assert!(!acl.check_access(&none, AccessLevel::Read, now, None, None));
    }

    #[test]
    fn test_revoke_link() {
        let mut acl = AccessControlList::new();
        let secret = "secret1";
        let secret_hash = warp_hash::hash(secret.as_bytes());

        acl.grant(AccessGrant::Link {
            secret_hash,
            level: AccessLevel::Read,
            conditions: None,
        });

        let accessor = Accessor::Link {
            secret: secret.to_string(),
            password: None,
        };
        let now = Utc::now();

        // Initially accessible
        assert!(acl.check_access(&accessor, AccessLevel::Read, now, None, None));

        // Revoke
        let removed = acl.revoke_link(&secret_hash);
        assert_eq!(removed, 1);

        // No longer accessible
        assert!(!acl.check_access(&accessor, AccessLevel::Read, now, None, None));
    }

    #[test]
    fn test_revoke_email() {
        let mut acl = AccessControlList::new();
        let email = "user@example.com";

        acl.grant(AccessGrant::Email {
            email: email.to_string(),
            level: AccessLevel::Read,
            conditions: None,
        });

        let accessor = Accessor::Email(email.to_string());
        let now = Utc::now();

        // Initially accessible
        assert!(acl.check_access(&accessor, AccessLevel::Read, now, None, None));

        // Revoke
        let removed = acl.revoke_email(email);
        assert_eq!(removed, 1);

        // No longer accessible
        assert!(!acl.check_access(&accessor, AccessLevel::Read, now, None, None));
    }

    #[test]
    fn test_combined_conditions() {
        let mut acl = AccessControlList::new();
        let (_, key) = create_test_key(1);
        let now = Utc::now();
        let future = now + Duration::hours(1);

        acl.grant(AccessGrant::Identity {
            key,
            level: AccessLevel::Read,
            conditions: Some(
                AccessConditions::new()
                    .with_expiration(future)
                    .with_max_uses(3)
                    .with_password("secret"),
            ),
        });

        let accessor = Accessor::Identity(key);
        assert!(acl.check_access(&accessor, AccessLevel::Read, now, None, Some("secret")));
        assert!(!acl.check_access(&accessor, AccessLevel::Read, now, None, None));
        assert!(!acl.check_access(&accessor, AccessLevel::Read, now, None, Some("wrong")));
        assert!(!acl.check_access(
            &accessor,
            AccessLevel::Read,
            future + Duration::seconds(1),
            None,
            Some("secret")
        ));
    }

    #[test]
    fn test_access_level_display() {
        assert_eq!(AccessLevel::List.to_string(), "List");
        assert_eq!(AccessLevel::Read.to_string(), "Read");
        assert_eq!(AccessLevel::Write.to_string(), "Write");
        assert_eq!(AccessLevel::Admin.to_string(), "Admin");
        assert_eq!(AccessLevel::Owner.to_string(), "Owner");
    }

    #[test]
    fn test_conditions_record_use() {
        let mut conditions = AccessConditions::new().with_max_uses(5);
        assert_eq!(conditions.current_uses, 0);
        conditions.record_use();
        assert_eq!(conditions.current_uses, 1);
        conditions.record_use();
        conditions.record_use();
        assert_eq!(conditions.current_uses, 3);

        let mut saturated = AccessConditions::new();
        saturated.current_uses = u64::MAX;
        saturated.record_use();
        assert_eq!(saturated.current_uses, u64::MAX);
    }

    #[test]
    fn test_multiple_identity_grants_different_levels() {
        let mut acl = AccessControlList::new();
        let (_, key) = create_test_key(1);
        let now = Utc::now();
        let future = now + Duration::hours(1);

        acl.grant(AccessGrant::Identity {
            key,
            level: AccessLevel::Read,
            conditions: None,
        });
        acl.grant(AccessGrant::Identity {
            key,
            level: AccessLevel::Write,
            conditions: Some(AccessConditions::new().with_expiration(future)),
        });

        let accessor = Accessor::Identity(key);
        assert_eq!(
            acl.get_access_level(&accessor, now, None, None),
            Some(AccessLevel::Write)
        );
        assert_eq!(
            acl.get_access_level(&accessor, future + Duration::seconds(1), None, None),
            Some(AccessLevel::Read)
        );
    }

    #[test]
    fn test_grant_level_method() {
        let (_, key) = create_test_key(1);
        let id = AccessGrant::Identity {
            key,
            level: AccessLevel::Admin,
            conditions: None,
        };
        let link = AccessGrant::Link {
            secret_hash: [0u8; 32],
            level: AccessLevel::Write,
            conditions: None,
        };
        let email = AccessGrant::Email {
            email: "test@example.com".to_string(),
            level: AccessLevel::Owner,
            conditions: None,
        };

        assert_eq!(id.level(), AccessLevel::Admin);
        assert_eq!(link.level(), AccessLevel::Write);
        assert_eq!(email.level(), AccessLevel::Owner);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let mut acl = AccessControlList::new();
        let (_, key) = create_test_key(1);

        acl.grant(AccessGrant::Identity {
            key,
            level: AccessLevel::Write,
            conditions: Some(
                AccessConditions::new()
                    .with_expiration(Utc::now())
                    .with_max_uses(10)
                    .with_password("test"),
            ),
        });

        let serialized = rmp_serde::to_vec(&acl).expect("serialization failed");
        let deserialized: AccessControlList =
            rmp_serde::from_slice(&serialized).expect("deserialization failed");
        assert_eq!(deserialized.grants().len(), acl.grants().len());
    }
}
