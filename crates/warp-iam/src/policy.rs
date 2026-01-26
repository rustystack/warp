//! S3-compatible policy engine
//!
//! Implements AWS IAM-style policy documents for bucket and object access control.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::error::{Error, Result};
use crate::identity::{Identity, Principal};

/// Policy document version
pub const POLICY_VERSION: &str = "2012-10-17";

/// Policy effect - Allow or Deny
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Effect {
    /// Allow the action
    #[serde(rename = "Allow")]
    Allow,
    /// Deny the action
    #[serde(rename = "Deny")]
    Deny,
}

/// An action in a policy (e.g., "s3:GetObject")
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Action {
    /// Single action
    Single(String),
    /// Multiple actions
    Multiple(Vec<String>),
}

impl Action {
    /// Check if this action matches the given action string
    pub fn matches(&self, action: &str) -> bool {
        match self {
            Action::Single(pattern) => action_matches(pattern, action),
            Action::Multiple(patterns) => patterns.iter().any(|p| action_matches(p, action)),
        }
    }

    /// Get all action strings
    pub fn actions(&self) -> Vec<&str> {
        match self {
            Action::Single(a) => vec![a.as_str()],
            Action::Multiple(a) => a.iter().map(|s| s.as_str()).collect(),
        }
    }
}

/// A resource in a policy (e.g., "arn:aws:s3:::bucket/*")
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Resource {
    /// Single resource
    Single(String),
    /// Multiple resources
    Multiple(Vec<String>),
}

impl Resource {
    /// Check if this resource matches the given resource string
    pub fn matches(&self, resource: &str) -> bool {
        match self {
            Resource::Single(pattern) => resource_matches(pattern, resource),
            Resource::Multiple(patterns) => patterns.iter().any(|p| resource_matches(p, resource)),
        }
    }

    /// Get all resource strings
    pub fn resources(&self) -> Vec<&str> {
        match self {
            Resource::Single(r) => vec![r.as_str()],
            Resource::Multiple(r) => r.iter().map(|s| s.as_str()).collect(),
        }
    }
}

/// Principal specification in a policy
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PrincipalSpec {
    /// Wildcard - all principals
    Wildcard(String),
    /// AWS-style principal map
    Aws {
        /// AWS principal identifier(s)
        #[serde(rename = "AWS")]
        aws: PrincipalList,
    },
    /// Federated principal
    Federated {
        /// Federated identity provider identifier(s)
        #[serde(rename = "Federated")]
        federated: PrincipalList,
    },
    /// Service principal
    Service {
        /// Service principal identifier(s)
        #[serde(rename = "Service")]
        service: PrincipalList,
    },
}

/// List of principals (single or multiple)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PrincipalList {
    /// Single principal identifier
    Single(String),
    /// Multiple principal identifiers
    Multiple(Vec<String>),
}

impl PrincipalSpec {
    /// Check if this principal spec matches the given identity
    pub fn matches(&self, identity: &Identity) -> bool {
        match self {
            PrincipalSpec::Wildcard(s) if s == "*" => true,
            PrincipalSpec::Aws { aws } => {
                let principals = match aws {
                    PrincipalList::Single(p) => vec![p.as_str()],
                    PrincipalList::Multiple(ps) => ps.iter().map(|s| s.as_str()).collect(),
                };
                principals.iter().any(|p| {
                    let parsed = Principal::parse(p);
                    identity.matches_principal(&parsed)
                })
            }
            PrincipalSpec::Federated { federated } => {
                if let Principal::Federated { provider, subject } = &identity.principal {
                    let expected = match federated {
                        PrincipalList::Single(p) => vec![p.as_str()],
                        PrincipalList::Multiple(ps) => ps.iter().map(|s| s.as_str()).collect(),
                    };
                    expected
                        .iter()
                        .any(|e| e == provider || e == &format!("{}:{}", provider, subject))
                } else {
                    false
                }
            }
            PrincipalSpec::Service { service } => {
                if let Principal::Service(svc) = &identity.principal {
                    let expected = match service {
                        PrincipalList::Single(p) => vec![p.as_str()],
                        PrincipalList::Multiple(ps) => ps.iter().map(|s| s.as_str()).collect(),
                    };
                    expected.iter().any(|e| e == svc)
                } else {
                    false
                }
            }
            _ => false,
        }
    }
}

/// Condition operator for policy evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConditionOperator {
    /// Exact string match
    StringEquals,
    /// String does not match
    StringNotEquals,
    /// Case-insensitive string match
    StringEqualsIgnoreCase,
    /// Glob-style string pattern match
    StringLike,
    /// String does not match glob pattern
    StringNotLike,
    /// Numeric equality
    NumericEquals,
    /// Numeric inequality
    NumericNotEquals,
    /// Numeric less than
    NumericLessThan,
    /// Numeric less than or equal
    NumericLessThanEquals,
    /// Numeric greater than
    NumericGreaterThan,
    /// Numeric greater than or equal
    NumericGreaterThanEquals,
    /// Date equality
    DateEquals,
    /// Date inequality
    DateNotEquals,
    /// Date before
    DateLessThan,
    /// Date before or equal
    DateLessThanEquals,
    /// Date after
    DateGreaterThan,
    /// Date after or equal
    DateGreaterThanEquals,
    /// Boolean condition
    Bool,
    /// IP address in CIDR range
    IpAddress,
    /// IP address not in CIDR range
    NotIpAddress,
    /// Exact ARN match
    ArnEquals,
    /// ARN pattern match
    ArnLike,
    /// Key is null/missing
    Null,
}

/// A policy statement
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Statement {
    /// Optional statement ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,

    /// Effect (Allow or Deny)
    pub effect: Effect,

    /// Principal (who the statement applies to)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal: Option<PrincipalSpec>,

    /// NotPrincipal (who the statement does NOT apply to)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_principal: Option<PrincipalSpec>,

    /// Actions allowed or denied
    pub action: Action,

    /// NotAction (actions NOT covered by this statement)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_action: Option<Action>,

    /// Resources this statement applies to
    pub resource: Resource,

    /// NotResource (resources NOT covered by this statement)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_resource: Option<Resource>,

    /// Conditions for the statement
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<serde_json::Value>,
}

impl Statement {
    /// Create a new allow statement
    pub fn allow(action: impl Into<String>, resource: impl Into<String>) -> Self {
        Self {
            sid: None,
            effect: Effect::Allow,
            principal: Some(PrincipalSpec::Wildcard("*".to_string())),
            not_principal: None,
            action: Action::Single(action.into()),
            not_action: None,
            resource: Resource::Single(resource.into()),
            not_resource: None,
            condition: None,
        }
    }

    /// Create a new deny statement
    pub fn deny(action: impl Into<String>, resource: impl Into<String>) -> Self {
        Self {
            sid: None,
            effect: Effect::Deny,
            principal: Some(PrincipalSpec::Wildcard("*".to_string())),
            not_principal: None,
            action: Action::Single(action.into()),
            not_action: None,
            resource: Resource::Single(resource.into()),
            not_resource: None,
            condition: None,
        }
    }

    /// Set the statement ID
    pub fn with_sid(mut self, sid: impl Into<String>) -> Self {
        self.sid = Some(sid.into());
        self
    }

    /// Set the principal
    pub fn with_principal(mut self, principal: PrincipalSpec) -> Self {
        self.principal = Some(principal);
        self
    }

    /// Check if this statement applies to the given identity, action, and resource
    pub fn applies(&self, identity: &Identity, action: &str, resource: &str) -> bool {
        // Check principal
        let principal_matches = match (&self.principal, &self.not_principal) {
            (Some(p), None) => p.matches(identity),
            (None, Some(np)) => !np.matches(identity),
            (Some(p), Some(np)) => p.matches(identity) && !np.matches(identity),
            (None, None) => true, // No principal restriction
        };

        if !principal_matches {
            return false;
        }

        // Check action
        let action_matches = match (&self.not_action, &self.action) {
            (Some(na), _) => !na.matches(action),
            (None, a) => a.matches(action),
        };

        if !action_matches {
            return false;
        }

        // Check resource

        match (&self.not_resource, &self.resource) {
            (Some(nr), _) => !nr.matches(resource),
            (None, r) => r.matches(resource),
        }
    }
}

/// A complete policy document
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PolicyDocument {
    /// Policy version (should be "2012-10-17")
    #[serde(default = "default_version")]
    pub version: String,

    /// Optional policy ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Policy statements
    pub statement: Vec<Statement>,
}

fn default_version() -> String {
    POLICY_VERSION.to_string()
}

impl PolicyDocument {
    /// Create a new empty policy
    pub fn new() -> Self {
        Self {
            version: POLICY_VERSION.to_string(),
            id: None,
            statement: Vec::new(),
        }
    }

    /// Parse a policy from JSON
    pub fn parse(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| Error::InvalidPolicy(e.to_string()))
    }

    /// Add a statement
    pub fn add_statement(mut self, statement: Statement) -> Self {
        self.statement.push(statement);
        self
    }

    /// Validate the policy document
    pub fn validate(&self) -> Result<()> {
        if self.version != POLICY_VERSION {
            return Err(Error::InvalidPolicy(format!(
                "Unsupported policy version: {}. Expected: {}",
                self.version, POLICY_VERSION
            )));
        }

        if self.statement.is_empty() {
            return Err(Error::InvalidPolicy(
                "Policy must have at least one statement".to_string(),
            ));
        }

        for (i, stmt) in self.statement.iter().enumerate() {
            // Validate actions
            for action in stmt.action.actions() {
                if !is_valid_action(action) {
                    return Err(Error::InvalidPolicy(format!(
                        "Invalid action in statement {}: {}",
                        i, action
                    )));
                }
            }

            // Validate resources
            for resource in stmt.resource.resources() {
                if !is_valid_resource(resource) {
                    return Err(Error::InvalidPolicy(format!(
                        "Invalid resource in statement {}: {}",
                        i, resource
                    )));
                }
            }
        }

        Ok(())
    }

    /// Convert to JSON string
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(Error::Json)
    }
}

impl Default for PolicyDocument {
    fn default() -> Self {
        Self::new()
    }
}

/// Authorization decision
#[derive(Debug, Clone)]
pub enum AuthorizationDecision {
    /// Access is allowed
    Allow,
    /// Access is denied with reason
    Deny {
        /// The reason for denial (statement ID or description)
        reason: String,
    },
    /// No applicable policy found
    NotApplicable,
}

/// Policy evaluation engine
pub struct PolicyEngine {
    /// Known S3 actions (for future validation)
    _known_actions: HashSet<&'static str>,
}

impl PolicyEngine {
    /// Create a new policy engine
    pub fn new() -> Self {
        let mut known_actions = HashSet::new();

        // S3 object actions
        known_actions.insert("s3:GetObject");
        known_actions.insert("s3:GetObjectVersion");
        known_actions.insert("s3:GetObjectAcl");
        known_actions.insert("s3:GetObjectVersionAcl");
        known_actions.insert("s3:GetObjectTagging");
        known_actions.insert("s3:GetObjectVersionTagging");
        known_actions.insert("s3:PutObject");
        known_actions.insert("s3:PutObjectAcl");
        known_actions.insert("s3:PutObjectTagging");
        known_actions.insert("s3:DeleteObject");
        known_actions.insert("s3:DeleteObjectVersion");
        known_actions.insert("s3:DeleteObjectTagging");
        known_actions.insert("s3:DeleteObjectVersionTagging");
        known_actions.insert("s3:ListMultipartUploadParts");
        known_actions.insert("s3:AbortMultipartUpload");

        // S3 bucket actions
        known_actions.insert("s3:ListBucket");
        known_actions.insert("s3:ListBucketVersions");
        known_actions.insert("s3:ListBucketMultipartUploads");
        known_actions.insert("s3:GetBucketLocation");
        known_actions.insert("s3:GetBucketPolicy");
        known_actions.insert("s3:GetBucketAcl");
        known_actions.insert("s3:GetBucketVersioning");
        known_actions.insert("s3:GetBucketNotification");
        known_actions.insert("s3:GetLifecycleConfiguration");
        known_actions.insert("s3:PutBucketPolicy");
        known_actions.insert("s3:PutBucketAcl");
        known_actions.insert("s3:PutBucketVersioning");
        known_actions.insert("s3:PutBucketNotification");
        known_actions.insert("s3:PutLifecycleConfiguration");
        known_actions.insert("s3:DeleteBucket");
        known_actions.insert("s3:DeleteBucketPolicy");
        known_actions.insert("s3:CreateBucket");

        // Wildcard actions
        known_actions.insert("s3:*");
        known_actions.insert("*");

        Self {
            _known_actions: known_actions,
        }
    }

    /// Evaluate a policy for an identity, action, and resource
    pub fn evaluate(
        &self,
        policy: &PolicyDocument,
        identity: &Identity,
        action: &str,
        resource: &str,
    ) -> Result<AuthorizationDecision> {
        let mut explicit_deny = false;
        let mut explicit_allow = false;
        let mut deny_reason = String::new();

        // Evaluate each statement
        for stmt in &policy.statement {
            if stmt.applies(identity, action, resource) {
                match stmt.effect {
                    Effect::Deny => {
                        explicit_deny = true;
                        deny_reason = stmt
                            .sid
                            .clone()
                            .unwrap_or_else(|| "Explicit deny".to_string());
                    }
                    Effect::Allow => {
                        explicit_allow = true;
                    }
                }
            }
        }

        // Deny takes precedence
        if explicit_deny {
            return Ok(AuthorizationDecision::Deny {
                reason: deny_reason,
            });
        }

        if explicit_allow {
            return Ok(AuthorizationDecision::Allow);
        }

        Ok(AuthorizationDecision::NotApplicable)
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if an action pattern matches an action
fn action_matches(pattern: &str, action: &str) -> bool {
    if pattern == "*" || pattern == "s3:*" {
        return true;
    }

    if pattern.contains('*') {
        // Convert glob pattern to regex
        let regex_pattern = pattern.replace('.', "\\.").replace('*', ".*");
        if let Ok(re) = Regex::new(&format!("^{}$", regex_pattern)) {
            return re.is_match(action);
        }
    }

    pattern == action
}

/// Check if a resource pattern matches a resource
fn resource_matches(pattern: &str, resource: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    if pattern.contains('*') || pattern.contains('?') {
        // Convert glob pattern to regex
        let regex_pattern = pattern
            .replace('.', "\\.")
            .replace('*', ".*")
            .replace('?', ".");
        if let Ok(re) = Regex::new(&format!("^{}$", regex_pattern)) {
            return re.is_match(resource);
        }
    }

    pattern == resource
}

/// Validate action format
fn is_valid_action(action: &str) -> bool {
    if action == "*" {
        return true;
    }

    // Must be in format "service:action" or "service:*"
    if let Some((service, _action)) = action.split_once(':') {
        !service.is_empty()
    } else {
        false
    }
}

/// Validate resource format
fn is_valid_resource(resource: &str) -> bool {
    if resource == "*" {
        return true;
    }

    // Accept ARN format or path format
    resource.starts_with("arn:") || resource.starts_with("/") || !resource.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_matches() {
        assert!(action_matches("*", "s3:GetObject"));
        assert!(action_matches("s3:*", "s3:GetObject"));
        assert!(action_matches("s3:Get*", "s3:GetObject"));
        assert!(action_matches("s3:GetObject", "s3:GetObject"));
        assert!(!action_matches("s3:PutObject", "s3:GetObject"));
    }

    #[test]
    fn test_resource_matches() {
        assert!(resource_matches("*", "arn:aws:s3:::bucket/key"));
        assert!(resource_matches(
            "arn:aws:s3:::bucket/*",
            "arn:aws:s3:::bucket/key"
        ));
        assert!(resource_matches(
            "arn:aws:s3:::bucket/prefix/*",
            "arn:aws:s3:::bucket/prefix/key"
        ));
        assert!(!resource_matches(
            "arn:aws:s3:::other/*",
            "arn:aws:s3:::bucket/key"
        ));
    }

    #[test]
    fn test_parse_policy() {
        let json = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "user:alice"},
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*"
            }]
        }"#;

        let policy = PolicyDocument::parse(json).unwrap();
        assert_eq!(policy.version, "2012-10-17");
        assert_eq!(policy.statement.len(), 1);
        assert_eq!(policy.statement[0].effect, Effect::Allow);
    }

    #[test]
    fn test_statement_applies() {
        let stmt = Statement::allow("s3:GetObject", "arn:aws:s3:::bucket/*").with_principal(
            PrincipalSpec::Aws {
                aws: PrincipalList::Single("user:alice".to_string()),
            },
        );

        let alice = Identity::user("alice", "Alice", "local");
        let bob = Identity::user("bob", "Bob", "local");

        assert!(stmt.applies(&alice, "s3:GetObject", "arn:aws:s3:::bucket/key"));
        assert!(!stmt.applies(&bob, "s3:GetObject", "arn:aws:s3:::bucket/key"));
        assert!(!stmt.applies(&alice, "s3:PutObject", "arn:aws:s3:::bucket/key"));
        assert!(!stmt.applies(&alice, "s3:GetObject", "arn:aws:s3:::other/key"));
    }

    #[test]
    fn test_policy_evaluation() {
        let policy = PolicyDocument::new()
            .add_statement(
                Statement::allow("s3:GetObject", "arn:aws:s3:::bucket/*")
                    .with_principal(PrincipalSpec::Wildcard("*".to_string())),
            )
            .add_statement(
                Statement::deny("s3:*", "arn:aws:s3:::bucket/secret/*")
                    .with_principal(PrincipalSpec::Wildcard("*".to_string())),
            );

        let engine = PolicyEngine::new();
        let alice = Identity::user("alice", "Alice", "local");

        // Allowed: regular object
        let decision = engine
            .evaluate(
                &policy,
                &alice,
                "s3:GetObject",
                "arn:aws:s3:::bucket/public/file",
            )
            .unwrap();
        assert!(matches!(decision, AuthorizationDecision::Allow));

        // Denied: secret path
        let decision = engine
            .evaluate(
                &policy,
                &alice,
                "s3:GetObject",
                "arn:aws:s3:::bucket/secret/file",
            )
            .unwrap();
        assert!(matches!(decision, AuthorizationDecision::Deny { .. }));

        // Not applicable: different action
        let decision = engine
            .evaluate(&policy, &alice, "s3:PutObject", "arn:aws:s3:::bucket/file")
            .unwrap();
        assert!(matches!(decision, AuthorizationDecision::NotApplicable));
    }

    #[test]
    fn test_policy_validation() {
        let valid = PolicyDocument::new()
            .add_statement(Statement::allow("s3:GetObject", "arn:aws:s3:::bucket/*"));
        assert!(valid.validate().is_ok());

        let empty = PolicyDocument::new();
        assert!(empty.validate().is_err());

        // Invalid action format
        let json = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "invalid",
                "Resource": "*"
            }]
        }"#;
        let invalid = PolicyDocument::parse(json).unwrap();
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_multiple_actions_resources() {
        let stmt = Statement {
            sid: None,
            effect: Effect::Allow,
            principal: Some(PrincipalSpec::Wildcard("*".to_string())),
            not_principal: None,
            action: Action::Multiple(vec!["s3:GetObject".to_string(), "s3:PutObject".to_string()]),
            not_action: None,
            resource: Resource::Multiple(vec![
                "arn:aws:s3:::bucket1/*".to_string(),
                "arn:aws:s3:::bucket2/*".to_string(),
            ]),
            not_resource: None,
            condition: None,
        };

        let identity = Identity::user("alice", "Alice", "local");

        assert!(stmt.applies(&identity, "s3:GetObject", "arn:aws:s3:::bucket1/key"));
        assert!(stmt.applies(&identity, "s3:PutObject", "arn:aws:s3:::bucket2/key"));
        assert!(!stmt.applies(&identity, "s3:DeleteObject", "arn:aws:s3:::bucket1/key"));
        assert!(!stmt.applies(&identity, "s3:GetObject", "arn:aws:s3:::bucket3/key"));
    }
}
