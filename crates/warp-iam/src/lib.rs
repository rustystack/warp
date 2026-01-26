#![allow(clippy::collapsible_if)]
#![allow(clippy::field_reassign_with_default)]

//! Identity and Access Management for WARP Storage
//!
//! This crate provides enterprise-grade IAM capabilities:
//! - **OIDC Integration**: Connect to Keycloak, Auth0, Okta, and other providers
//! - **S3 Bucket Policies**: AWS-compatible policy documents
//! - **Role-Based Access Control**: Map OIDC claims to storage permissions
//! - **Session Management**: OAuth token handling with refresh
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                         WARP IAM                                 │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
//! │  │    OIDC     │  │    LDAP     │  │   Local     │  Providers   │
//! │  │  Provider   │  │  Provider   │  │  Provider   │              │
//! │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘              │
//! │         │                │                │                     │
//! │         └────────────────┼────────────────┘                     │
//! │                          ▼                                      │
//! │  ┌───────────────────────────────────────────────────────────┐ │
//! │  │                   Identity Manager                        │ │
//! │  │  - User/Group resolution                                  │ │
//! │  │  - Claim mapping                                          │ │
//! │  │  - Session caching                                        │ │
//! │  └───────────────────────────────────────────────────────────┘ │
//! │                          │                                      │
//! │                          ▼                                      │
//! │  ┌───────────────────────────────────────────────────────────┐ │
//! │  │                   Policy Engine                           │ │
//! │  │  - S3-compatible bucket policies                          │ │
//! │  │  - RBAC role evaluation                                   │ │
//! │  │  - Action/Resource matching                               │ │
//! │  └───────────────────────────────────────────────────────────┘ │
//! │                          │                                      │
//! │                          ▼                                      │
//! │  ┌───────────────────────────────────────────────────────────┐ │
//! │  │                Authorization Decision                     │ │
//! │  │  Allow / Deny / NotApplicable                             │ │
//! │  └───────────────────────────────────────────────────────────┘ │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```ignore
//! use warp_iam::{IamManager, PolicyDocument, OidcConfig};
//!
//! // Configure OIDC provider
//! let oidc_config = OidcConfig::new(
//!     "https://keycloak.example.com/realms/warp",
//!     "warp-storage",
//!     "secret",
//! );
//!
//! // Create IAM manager
//! let iam = IamManager::new()
//!     .with_oidc_provider(oidc_config)
//!     .build()?;
//!
//! // Attach bucket policy
//! let policy = PolicyDocument::parse(r#"{
//!     "Version": "2012-10-17",
//!     "Statement": [{
//!         "Effect": "Allow",
//!         "Principal": {"AWS": "user:alice"},
//!         "Action": ["s3:GetObject", "s3:PutObject"],
//!         "Resource": "arn:aws:s3:::my-bucket/*"
//!     }]
//! }"#)?;
//! iam.set_bucket_policy("my-bucket", policy)?;
//!
//! // Check authorization
//! let decision = iam.authorize(
//!     &identity,
//!     "s3:GetObject",
//!     "arn:aws:s3:::my-bucket/data.json"
//! ).await?;
//! ```

pub mod error;
pub mod identity;
pub mod policy;
pub mod session;

#[cfg(feature = "oidc")]
pub mod oidc;

pub mod ldap;

pub use error::{Error, Result};
pub use identity::{Group, Identity, IdentityProvider, Principal};
pub use policy::{
    Action, AuthorizationDecision, Effect, PolicyDocument, PolicyEngine, PrincipalSpec, Resource,
    Statement,
};
pub use session::{Session, SessionManager, SessionToken};

use dashmap::DashMap;

/// IAM Manager - main entry point for identity and access management
pub struct IamManager {
    /// Identity providers
    providers: Vec<Box<dyn IdentityProvider>>,

    /// Policy engine
    policy_engine: PolicyEngine,

    /// Session manager
    session_manager: SessionManager,

    /// Bucket policies (bucket_name -> policy)
    bucket_policies: DashMap<String, PolicyDocument>,
}

impl IamManager {
    /// Create a new IAM manager builder
    pub fn builder() -> IamManagerBuilder {
        IamManagerBuilder::new()
    }

    /// Authenticate a user and create a session
    pub async fn authenticate(
        &self,
        provider_id: &str,
        credentials: &Credentials,
    ) -> Result<Session> {
        // Find provider
        let provider = self
            .providers
            .iter()
            .find(|p| p.id() == provider_id)
            .ok_or_else(|| Error::ProviderNotFound(provider_id.to_string()))?;

        // Authenticate with provider
        let identity = provider.authenticate(credentials).await?;

        // Create session
        let session = self.session_manager.create_session(identity)?;

        Ok(session)
    }

    /// Authorize an action on a resource
    pub async fn authorize(
        &self,
        session: &Session,
        action: &str,
        resource: &str,
    ) -> Result<AuthorizationDecision> {
        // Validate session
        if !self.session_manager.is_valid(&session.id) {
            return Ok(AuthorizationDecision::Deny {
                reason: "Session expired or invalid".to_string(),
            });
        }

        // Get identity from session
        let identity = &session.identity;

        // Check bucket policy if resource is a bucket/object
        if let Some(bucket) = extract_bucket_from_resource(resource) {
            if let Some(policy) = self.bucket_policies.get(&bucket) {
                let decision = self
                    .policy_engine
                    .evaluate(&policy, identity, action, resource)?;

                if !matches!(decision, AuthorizationDecision::NotApplicable) {
                    return Ok(decision);
                }
            }
        }

        // Default: check identity's attached policies
        for policy in &identity.policies {
            let decision = self
                .policy_engine
                .evaluate(policy, identity, action, resource)?;

            match &decision {
                AuthorizationDecision::Deny { .. } => return Ok(decision),
                AuthorizationDecision::Allow => return Ok(decision),
                AuthorizationDecision::NotApplicable => continue,
            }
        }

        // No applicable policy found - implicit deny
        Ok(AuthorizationDecision::Deny {
            reason: "No applicable policy".to_string(),
        })
    }

    /// Set a bucket policy
    pub fn set_bucket_policy(&self, bucket: &str, policy: PolicyDocument) -> Result<()> {
        policy.validate()?;
        self.bucket_policies.insert(bucket.to_string(), policy);
        Ok(())
    }

    /// Get a bucket policy
    pub fn get_bucket_policy(&self, bucket: &str) -> Option<PolicyDocument> {
        self.bucket_policies.get(bucket).map(|p| p.clone())
    }

    /// Delete a bucket policy
    pub fn delete_bucket_policy(&self, bucket: &str) -> Option<PolicyDocument> {
        self.bucket_policies.remove(bucket).map(|(_, p)| p)
    }

    /// Validate a session token and return the session
    pub fn validate_session(&self, token: &str) -> Result<Session> {
        self.session_manager.get_session(token)
    }

    /// Invalidate a session
    pub fn invalidate_session(&self, session_id: &str) -> Result<()> {
        self.session_manager.invalidate(session_id)
    }
}

/// Builder for IamManager
pub struct IamManagerBuilder {
    providers: Vec<Box<dyn IdentityProvider>>,
    session_ttl_seconds: u64,
}

impl IamManagerBuilder {
    fn new() -> Self {
        Self {
            providers: Vec::new(),
            session_ttl_seconds: 3600, // 1 hour default
        }
    }

    /// Add an identity provider
    pub fn with_provider(mut self, provider: Box<dyn IdentityProvider>) -> Self {
        self.providers.push(provider);
        self
    }

    /// Set session TTL in seconds
    pub fn with_session_ttl(mut self, ttl_seconds: u64) -> Self {
        self.session_ttl_seconds = ttl_seconds;
        self
    }

    /// Build the IAM manager
    pub fn build(self) -> Result<IamManager> {
        Ok(IamManager {
            providers: self.providers,
            policy_engine: PolicyEngine::new(),
            session_manager: SessionManager::new(self.session_ttl_seconds),
            bucket_policies: DashMap::new(),
        })
    }
}

/// Credentials for authentication
#[derive(Debug, Clone)]
pub enum Credentials {
    /// Username and password
    Password {
        /// The username
        username: String,
        /// The password
        password: String,
    },
    /// OAuth authorization code
    AuthorizationCode {
        /// The authorization code
        code: String,
        /// The redirect URI used in the OAuth flow
        redirect_uri: String,
    },
    /// OAuth access token
    AccessToken(String),
    /// API key
    ApiKey(String),
}

/// Extract bucket name from S3 ARN or path
fn extract_bucket_from_resource(resource: &str) -> Option<String> {
    // Handle ARN format: arn:aws:s3:::bucket-name/key
    if let Some(path) = resource.strip_prefix("arn:aws:s3:::") {
        // Skip "arn:aws:s3:::"
        let bucket = path.split('/').next()?;
        return Some(bucket.to_string());
    }

    // Handle path format: /bucket-name/key or bucket-name/key
    let path = resource.trim_start_matches('/');
    let bucket = path.split('/').next()?;
    if !bucket.is_empty() {
        return Some(bucket.to_string());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_bucket_from_arn() {
        assert_eq!(
            extract_bucket_from_resource("arn:aws:s3:::my-bucket/path/to/object"),
            Some("my-bucket".to_string())
        );
        assert_eq!(
            extract_bucket_from_resource("arn:aws:s3:::my-bucket"),
            Some("my-bucket".to_string())
        );
    }

    #[test]
    fn test_extract_bucket_from_path() {
        assert_eq!(
            extract_bucket_from_resource("/my-bucket/path/to/object"),
            Some("my-bucket".to_string())
        );
        assert_eq!(
            extract_bucket_from_resource("my-bucket/path/to/object"),
            Some("my-bucket".to_string())
        );
    }
}
