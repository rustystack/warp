//! Identity types and provider trait
//!
//! Defines the core identity model used across all providers.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::Credentials;
use crate::error::Result;
use crate::policy::PolicyDocument;

/// A principal represents who is making a request
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Principal {
    /// Anonymous/unauthenticated
    Anonymous,

    /// Authenticated user
    User(String),

    /// Service account
    Service(String),

    /// Group of users
    Group(String),

    /// Role (assumed identity)
    Role(String),

    /// AWS-style principal (for S3 compatibility)
    Aws(String),

    /// Federated identity (from OIDC/SAML)
    Federated {
        /// The identity provider (e.g., "google.com", "okta.com")
        provider: String,
        /// The subject identifier from the IdP
        subject: String,
    },

    /// Wildcard - matches everyone
    Wildcard,
}

impl Principal {
    /// Parse a principal from string
    pub fn parse(s: &str) -> Self {
        if s == "*" {
            return Principal::Wildcard;
        }

        if let Some(rest) = s.strip_prefix("user:") {
            return Principal::User(rest.to_string());
        }

        if let Some(rest) = s.strip_prefix("service:") {
            return Principal::Service(rest.to_string());
        }

        if let Some(rest) = s.strip_prefix("group:") {
            return Principal::Group(rest.to_string());
        }

        if let Some(rest) = s.strip_prefix("role:") {
            return Principal::Role(rest.to_string());
        }

        if s.starts_with("arn:aws:") {
            return Principal::Aws(s.to_string());
        }

        // Default to user
        Principal::User(s.to_string())
    }

    /// Check if this principal matches another
    pub fn matches(&self, other: &Principal) -> bool {
        match (self, other) {
            (Principal::Wildcard, _) | (_, Principal::Wildcard) => true,
            (Principal::User(a), Principal::User(b)) => a == b,
            (Principal::Service(a), Principal::Service(b)) => a == b,
            (Principal::Group(a), Principal::Group(b)) => a == b,
            (Principal::Role(a), Principal::Role(b)) => a == b,
            (Principal::Aws(a), Principal::Aws(b)) => a == b,
            (
                Principal::Federated {
                    provider: p1,
                    subject: s1,
                },
                Principal::Federated {
                    provider: p2,
                    subject: s2,
                },
            ) => p1 == p2 && s1 == s2,
            (Principal::Anonymous, Principal::Anonymous) => true,
            _ => false,
        }
    }

    /// Convert to string representation
    pub fn to_string_repr(&self) -> String {
        match self {
            Principal::Anonymous => "anonymous".to_string(),
            Principal::User(u) => format!("user:{}", u),
            Principal::Service(s) => format!("service:{}", s),
            Principal::Group(g) => format!("group:{}", g),
            Principal::Role(r) => format!("role:{}", r),
            Principal::Aws(a) => a.clone(),
            Principal::Federated { provider, subject } => {
                format!("federated:{}:{}", provider, subject)
            }
            Principal::Wildcard => "*".to_string(),
        }
    }
}

/// A group of users
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    /// Group ID
    pub id: String,

    /// Group name
    pub name: String,

    /// Group description
    pub description: Option<String>,

    /// Member user IDs
    pub members: Vec<String>,

    /// Policies attached to this group
    pub policies: Vec<PolicyDocument>,

    /// Custom attributes
    pub attributes: HashMap<String, String>,
}

impl Group {
    /// Create a new group
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: None,
            members: Vec::new(),
            policies: Vec::new(),
            attributes: HashMap::new(),
        }
    }

    /// Check if a user is a member
    pub fn has_member(&self, user_id: &str) -> bool {
        self.members.contains(&user_id.to_string())
    }

    /// Add a member
    pub fn add_member(&mut self, user_id: impl Into<String>) {
        let id = user_id.into();
        if !self.members.contains(&id) {
            self.members.push(id);
        }
    }

    /// Remove a member
    pub fn remove_member(&mut self, user_id: &str) {
        self.members.retain(|m| m != user_id);
    }
}

/// An authenticated identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    /// Unique identifier
    pub id: String,

    /// Principal type
    pub principal: Principal,

    /// Display name
    pub name: String,

    /// Email (if available)
    pub email: Option<String>,

    /// Groups this identity belongs to
    pub groups: Vec<String>,

    /// Roles assigned to this identity
    pub roles: Vec<String>,

    /// Policies directly attached to this identity
    pub policies: Vec<PolicyDocument>,

    /// Claims from the identity provider
    pub claims: HashMap<String, serde_json::Value>,

    /// Provider that authenticated this identity
    pub provider_id: String,

    /// When the identity was authenticated
    pub authenticated_at: DateTime<Utc>,

    /// Custom attributes
    pub attributes: HashMap<String, String>,
}

impl Identity {
    /// Create a new identity
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        provider_id: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            principal: Principal::Anonymous,
            name: name.into(),
            email: None,
            groups: Vec::new(),
            roles: Vec::new(),
            policies: Vec::new(),
            claims: HashMap::new(),
            provider_id: provider_id.into(),
            authenticated_at: Utc::now(),
            attributes: HashMap::new(),
        }
    }

    /// Create a user identity
    pub fn user(
        id: impl Into<String>,
        name: impl Into<String>,
        provider_id: impl Into<String>,
    ) -> Self {
        let id_str: String = id.into();
        let mut identity = Self::new(id_str.clone(), name, provider_id);
        identity.principal = Principal::User(id_str);
        identity
    }

    /// Create a service identity
    pub fn service(
        id: impl Into<String>,
        name: impl Into<String>,
        provider_id: impl Into<String>,
    ) -> Self {
        let id_str: String = id.into();
        let mut identity = Self::new(id_str.clone(), name, provider_id);
        identity.principal = Principal::Service(id_str);
        identity
    }

    /// Check if this identity matches a principal
    pub fn matches_principal(&self, principal: &Principal) -> bool {
        // Direct match
        if self.principal.matches(principal) {
            return true;
        }

        // Check group membership
        if let Principal::Group(group_id) = principal {
            if self.groups.contains(group_id) {
                return true;
            }
        }

        // Check role assignment
        if let Principal::Role(role_id) = principal {
            if self.roles.contains(role_id) {
                return true;
            }
        }

        false
    }

    /// Get a claim value
    pub fn get_claim(&self, key: &str) -> Option<&serde_json::Value> {
        self.claims.get(key)
    }

    /// Get a string claim
    pub fn get_string_claim(&self, key: &str) -> Option<&str> {
        self.claims.get(key).and_then(|v| v.as_str())
    }

    /// Check if identity has a specific role
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.contains(&role.to_string())
    }

    /// Check if identity is in a specific group
    pub fn in_group(&self, group: &str) -> bool {
        self.groups.contains(&group.to_string())
    }
}

/// Identity provider trait
#[async_trait]
pub trait IdentityProvider: Send + Sync {
    /// Provider ID
    fn id(&self) -> &str;

    /// Provider name (for display)
    fn name(&self) -> &str;

    /// Authenticate with credentials
    async fn authenticate(&self, credentials: &Credentials) -> Result<Identity>;

    /// Validate an existing token/session
    async fn validate_token(&self, token: &str) -> Result<Identity>;

    /// Refresh a token
    async fn refresh_token(&self, refresh_token: &str) -> Result<(String, Option<String>)>;

    /// Get user info by ID
    async fn get_user(&self, user_id: &str) -> Result<Option<Identity>>;

    /// List groups a user belongs to
    async fn get_user_groups(&self, user_id: &str) -> Result<Vec<Group>>;

    /// Get group by ID
    async fn get_group(&self, group_id: &str) -> Result<Option<Group>>;
}

/// Local identity provider for testing and simple setups
pub struct LocalIdentityProvider {
    id: String,
    name: String,
    users: dashmap::DashMap<String, LocalUser>,
    groups: dashmap::DashMap<String, Group>,
}

/// Local user record
#[derive(Debug, Clone)]
struct LocalUser {
    id: String,
    username: String,
    password_hash: [u8; 32],
    email: Option<String>,
    groups: Vec<String>,
    roles: Vec<String>,
    policies: Vec<PolicyDocument>,
    attributes: HashMap<String, String>,
}

impl LocalIdentityProvider {
    /// Create a new local provider
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            users: dashmap::DashMap::new(),
            groups: dashmap::DashMap::new(),
        }
    }

    /// Add a user
    pub fn add_user(
        &self,
        id: impl Into<String>,
        username: impl Into<String>,
        password: impl AsRef<[u8]>,
    ) -> &Self {
        let id = id.into();
        let password_hash = *blake3::hash(password.as_ref()).as_bytes();

        self.users.insert(
            id.clone(),
            LocalUser {
                id: id.clone(),
                username: username.into(),
                password_hash,
                email: None,
                groups: Vec::new(),
                roles: Vec::new(),
                policies: Vec::new(),
                attributes: HashMap::new(),
            },
        );

        self
    }

    /// Add a user to a group
    pub fn add_user_to_group(&self, user_id: &str, group_id: &str) -> &Self {
        if let Some(mut user) = self.users.get_mut(user_id) {
            if !user.groups.contains(&group_id.to_string()) {
                user.groups.push(group_id.to_string());
            }
        }

        if let Some(mut group) = self.groups.get_mut(group_id) {
            if !group.members.contains(&user_id.to_string()) {
                group.members.push(user_id.to_string());
            }
        }

        self
    }

    /// Add a group
    pub fn add_group(&self, group: Group) -> &Self {
        self.groups.insert(group.id.clone(), group);
        self
    }

    /// Assign a role to a user
    pub fn assign_role(&self, user_id: &str, role: &str) -> &Self {
        if let Some(mut user) = self.users.get_mut(user_id) {
            if !user.roles.contains(&role.to_string()) {
                user.roles.push(role.to_string());
            }
        }
        self
    }

    /// Attach a policy to a user
    pub fn attach_user_policy(&self, user_id: &str, policy: PolicyDocument) -> &Self {
        if let Some(mut user) = self.users.get_mut(user_id) {
            user.policies.push(policy);
        }
        self
    }
}

#[async_trait]
impl IdentityProvider for LocalIdentityProvider {
    fn id(&self) -> &str {
        &self.id
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn authenticate(&self, credentials: &Credentials) -> Result<Identity> {
        match credentials {
            Credentials::Password { username, password } => {
                let password_hash = *blake3::hash(password.as_bytes()).as_bytes();

                let user = self
                    .users
                    .iter()
                    .find(|u| u.username == *username && u.password_hash == password_hash)
                    .map(|u| u.clone())
                    .ok_or_else(|| {
                        crate::Error::AuthenticationFailed(
                            "Invalid username or password".to_string(),
                        )
                    })?;

                let mut identity = Identity::user(&user.id, &user.username, &self.id);
                identity.email = user.email.clone();
                identity.groups = user.groups.clone();
                identity.roles = user.roles.clone();
                identity.policies = user.policies.clone();
                identity.attributes = user.attributes.clone();

                Ok(identity)
            }
            _ => Err(crate::Error::AuthenticationFailed(
                "Unsupported credential type".to_string(),
            )),
        }
    }

    async fn validate_token(&self, _token: &str) -> Result<Identity> {
        Err(crate::Error::InvalidToken(
            "Local provider does not support tokens".to_string(),
        ))
    }

    async fn refresh_token(&self, _refresh_token: &str) -> Result<(String, Option<String>)> {
        Err(crate::Error::InvalidToken(
            "Local provider does not support token refresh".to_string(),
        ))
    }

    async fn get_user(&self, user_id: &str) -> Result<Option<Identity>> {
        if let Some(user) = self.users.get(user_id) {
            let mut identity = Identity::user(&user.id, &user.username, &self.id);
            identity.email = user.email.clone();
            identity.groups = user.groups.clone();
            identity.roles = user.roles.clone();
            identity.policies = user.policies.clone();
            Ok(Some(identity))
        } else {
            Ok(None)
        }
    }

    async fn get_user_groups(&self, user_id: &str) -> Result<Vec<Group>> {
        if let Some(user) = self.users.get(user_id) {
            let groups: Vec<Group> = user
                .groups
                .iter()
                .filter_map(|gid| self.groups.get(gid).map(|g| g.clone()))
                .collect();
            Ok(groups)
        } else {
            Ok(Vec::new())
        }
    }

    async fn get_group(&self, group_id: &str) -> Result<Option<Group>> {
        Ok(self.groups.get(group_id).map(|g| g.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_principal_parse() {
        assert_eq!(Principal::parse("*"), Principal::Wildcard);
        assert_eq!(
            Principal::parse("user:alice"),
            Principal::User("alice".to_string())
        );
        assert_eq!(
            Principal::parse("group:admins"),
            Principal::Group("admins".to_string())
        );
        assert_eq!(
            Principal::parse("role:reader"),
            Principal::Role("reader".to_string())
        );
    }

    #[test]
    fn test_principal_matches() {
        let alice = Principal::User("alice".to_string());
        let wildcard = Principal::Wildcard;

        assert!(alice.matches(&Principal::User("alice".to_string())));
        assert!(!alice.matches(&Principal::User("bob".to_string())));
        assert!(alice.matches(&wildcard));
        assert!(wildcard.matches(&alice));
    }

    #[test]
    fn test_identity_matches_principal() {
        let mut identity = Identity::user("alice", "Alice", "local");
        identity.groups.push("admins".to_string());
        identity.roles.push("reader".to_string());

        assert!(identity.matches_principal(&Principal::User("alice".to_string())));
        assert!(identity.matches_principal(&Principal::Group("admins".to_string())));
        assert!(identity.matches_principal(&Principal::Role("reader".to_string())));
        assert!(identity.matches_principal(&Principal::Wildcard));
        assert!(!identity.matches_principal(&Principal::User("bob".to_string())));
    }

    #[tokio::test]
    async fn test_local_provider_auth() {
        let provider = LocalIdentityProvider::new("local", "Local Provider");
        provider.add_user("alice", "alice", "password123");

        let result = provider
            .authenticate(&Credentials::Password {
                username: "alice".to_string(),
                password: "password123".to_string(),
            })
            .await;

        assert!(result.is_ok());
        let identity = result.unwrap();
        assert_eq!(identity.id, "alice");
    }

    #[tokio::test]
    async fn test_local_provider_wrong_password() {
        let provider = LocalIdentityProvider::new("local", "Local Provider");
        provider.add_user("alice", "alice", "password123");

        let result = provider
            .authenticate(&Credentials::Password {
                username: "alice".to_string(),
                password: "wrong".to_string(),
            })
            .await;

        assert!(result.is_err());
    }
}
