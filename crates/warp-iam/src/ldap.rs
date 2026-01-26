//! LDAP/Active Directory identity provider
//!
//! Provides enterprise LDAP authentication and user/group lookup.
//! Supports standard LDAP v3 and Active Directory.

use crate::identity::{Group, Identity};
use crate::{Credentials, Error, IdentityProvider, Result};
use async_trait::async_trait;

#[cfg(feature = "ldap")]
use std::sync::Arc;
#[cfg(feature = "ldap")]
use tokio::sync::RwLock;
#[cfg(feature = "ldap")]
use tracing::{debug, error, instrument, warn};

/// LDAP identity provider configuration
#[derive(Debug, Clone)]
pub struct LdapConfig {
    /// Provider ID
    pub id: String,
    /// Provider name (for display)
    pub name: String,
    /// LDAP server URL (e.g., "ldap://localhost:389" or "ldaps://localhost:636")
    pub url: String,
    /// Base DN for user searches (e.g., "ou=users,dc=example,dc=com")
    pub base_dn: String,
    /// Bind DN for service account (e.g., "cn=admin,dc=example,dc=com")
    pub bind_dn: Option<String>,
    /// Bind password for service account
    pub bind_password: Option<String>,
    /// User search filter with {username} placeholder (e.g., "(uid={username})")
    pub user_filter: String,
    /// User ID attribute (e.g., "uid" for OpenLDAP, "sAMAccountName" for AD)
    pub user_id_attr: String,
    /// User name attribute (e.g., "cn" or "displayName")
    pub user_name_attr: String,
    /// User email attribute (e.g., "mail")
    pub user_email_attr: String,
    /// Group search base DN (e.g., "ou=groups,dc=example,dc=com")
    pub group_base_dn: String,
    /// Group search filter (e.g., "(objectClass=groupOfNames)")
    pub group_filter: String,
    /// Group ID attribute (e.g., "cn")
    pub group_id_attr: String,
    /// Group name attribute (e.g., "cn" or "description")
    pub group_name_attr: String,
    /// Group member attribute (e.g., "member" or "memberUid")
    pub group_member_attr: String,
    /// User's group membership attribute (e.g., "memberOf")
    pub user_groups_attr: String,
    /// Connection timeout in seconds
    pub timeout_seconds: u64,
    /// Use STARTTLS for encryption
    pub starttls: bool,
    /// Skip TLS certificate verification (not recommended for production)
    pub skip_tls_verify: bool,
}

impl Default for LdapConfig {
    fn default() -> Self {
        Self {
            id: "ldap".to_string(),
            name: "LDAP".to_string(),
            url: "ldap://localhost:389".to_string(),
            base_dn: "dc=example,dc=com".to_string(),
            bind_dn: None,
            bind_password: None,
            user_filter: "(uid={username})".to_string(),
            user_id_attr: "uid".to_string(),
            user_name_attr: "cn".to_string(),
            user_email_attr: "mail".to_string(),
            group_base_dn: "ou=groups,dc=example,dc=com".to_string(),
            group_filter: "(objectClass=groupOfNames)".to_string(),
            group_id_attr: "cn".to_string(),
            group_name_attr: "cn".to_string(),
            group_member_attr: "member".to_string(),
            user_groups_attr: "memberOf".to_string(),
            timeout_seconds: 10,
            starttls: false,
            skip_tls_verify: false,
        }
    }
}

impl LdapConfig {
    /// Create config for Active Directory
    pub fn active_directory(url: &str, base_dn: &str) -> Self {
        Self {
            id: "ad".to_string(),
            name: "Active Directory".to_string(),
            url: url.to_string(),
            base_dn: base_dn.to_string(),
            bind_dn: None,
            bind_password: None,
            user_filter: "(sAMAccountName={username})".to_string(),
            user_id_attr: "sAMAccountName".to_string(),
            user_name_attr: "displayName".to_string(),
            user_email_attr: "mail".to_string(),
            group_base_dn: base_dn.to_string(),
            group_filter: "(objectClass=group)".to_string(),
            group_id_attr: "cn".to_string(),
            group_name_attr: "cn".to_string(),
            group_member_attr: "member".to_string(),
            user_groups_attr: "memberOf".to_string(),
            timeout_seconds: 10,
            starttls: false,
            skip_tls_verify: false,
        }
    }

    /// Create config for OpenLDAP
    pub fn openldap(url: &str, base_dn: &str) -> Self {
        Self {
            id: "openldap".to_string(),
            name: "OpenLDAP".to_string(),
            url: url.to_string(),
            base_dn: base_dn.to_string(),
            bind_dn: None,
            bind_password: None,
            user_filter: "(uid={username})".to_string(),
            user_id_attr: "uid".to_string(),
            user_name_attr: "cn".to_string(),
            user_email_attr: "mail".to_string(),
            group_base_dn: format!("ou=groups,{}", base_dn),
            group_filter: "(objectClass=groupOfNames)".to_string(),
            group_id_attr: "cn".to_string(),
            group_name_attr: "cn".to_string(),
            group_member_attr: "member".to_string(),
            user_groups_attr: "memberOf".to_string(),
            timeout_seconds: 10,
            starttls: false,
            skip_tls_verify: false,
        }
    }

    /// Set service account credentials for binding
    pub fn with_bind_credentials(mut self, bind_dn: &str, password: &str) -> Self {
        self.bind_dn = Some(bind_dn.to_string());
        self.bind_password = Some(password.to_string());
        self
    }

    /// Enable STARTTLS
    pub fn with_starttls(mut self) -> Self {
        self.starttls = true;
        self
    }
}

/// LDAP identity provider
#[cfg(feature = "ldap")]
pub struct LdapProvider {
    config: LdapConfig,
    connection: Arc<RwLock<Option<ldap3::Ldap>>>,
}

#[cfg(feature = "ldap")]
impl LdapProvider {
    /// Create a new LDAP provider
    pub async fn new(config: LdapConfig) -> Result<Self> {
        let provider = Self {
            config,
            connection: Arc::new(RwLock::new(None)),
        };

        // Test connection
        provider.ensure_connection().await?;

        Ok(provider)
    }

    /// Ensure we have a valid connection
    async fn ensure_connection(&self) -> Result<()> {
        let mut conn = self.connection.write().await;

        // Check if existing connection is alive
        if conn.is_some() {
            return Ok(());
        }

        // Create new connection
        let settings = ldap3::LdapConnSettings::new()
            .set_conn_timeout(std::time::Duration::from_secs(self.config.timeout_seconds));

        let (ldap_conn, mut ldap) = ldap3::LdapConnAsync::with_settings(settings, &self.config.url)
            .await
            .map_err(|e| Error::Ldap(format!("Connection failed: {}", e)))?;

        ldap3::drive!(ldap_conn);

        // STARTTLS if configured
        if self.config.starttls {
            ldap.start_tls(self.config.skip_tls_verify)
                .await
                .map_err(|e| Error::Ldap(format!("STARTTLS failed: {}", e)))?;
        }

        // Bind with service account if configured
        if let (Some(bind_dn), Some(bind_pw)) = (&self.config.bind_dn, &self.config.bind_password) {
            ldap.simple_bind(bind_dn, bind_pw)
                .await
                .map_err(|e| Error::Ldap(format!("Service bind failed: {}", e)))?
                .success()
                .map_err(|e| Error::Ldap(format!("Service bind rejected: {}", e)))?;

            debug!(bind_dn = %bind_dn, "LDAP service account bound");
        }

        *conn = Some(ldap);
        Ok(())
    }

    /// Get a connection for operations
    async fn get_connection(
        &self,
    ) -> Result<tokio::sync::RwLockWriteGuard<'_, Option<ldap3::Ldap>>> {
        self.ensure_connection().await?;
        Ok(self.connection.write().await)
    }

    /// Create a fresh connection for user authentication (avoids session mixing)
    async fn create_auth_connection(&self) -> Result<ldap3::Ldap> {
        let settings = ldap3::LdapConnSettings::new()
            .set_conn_timeout(std::time::Duration::from_secs(self.config.timeout_seconds));

        let (ldap_conn, mut ldap) = ldap3::LdapConnAsync::with_settings(settings, &self.config.url)
            .await
            .map_err(|e| Error::Ldap(format!("Connection failed: {}", e)))?;

        ldap3::drive!(ldap_conn);

        if self.config.starttls {
            ldap.start_tls(self.config.skip_tls_verify)
                .await
                .map_err(|e| Error::Ldap(format!("STARTTLS failed: {}", e)))?;
        }

        Ok(ldap)
    }

    /// Search for a user by username and return their DN and entry
    #[instrument(skip(self))]
    async fn search_user(&self, username: &str) -> Result<Option<(String, LdapUserEntry)>> {
        let mut conn_guard = self.get_connection().await?;
        let ldap = conn_guard
            .as_mut()
            .ok_or_else(|| Error::Ldap("No connection".to_string()))?;

        // Build search filter
        let filter = self
            .config
            .user_filter
            .replace("{username}", &ldap3::ldap_escape(username));

        let attrs = vec![
            &self.config.user_id_attr,
            &self.config.user_name_attr,
            &self.config.user_email_attr,
            &self.config.user_groups_attr,
            "dn",
        ];

        debug!(base = %self.config.base_dn, filter = %filter, "Searching for user");

        let (entries, _result) = ldap
            .search(&self.config.base_dn, ldap3::Scope::Subtree, &filter, attrs)
            .await
            .map_err(|e| Error::Ldap(format!("User search failed: {}", e)))?
            .success()
            .map_err(|e| Error::Ldap(format!("User search rejected: {}", e)))?;

        if entries.is_empty() {
            debug!(username = %username, "User not found");
            return Ok(None);
        }

        let entry = ldap3::SearchEntry::construct(entries.into_iter().next().unwrap());

        let user_entry = LdapUserEntry {
            dn: entry.dn.clone(),
            id: get_first_attr(&entry, &self.config.user_id_attr).unwrap_or_default(),
            name: get_first_attr(&entry, &self.config.user_name_attr).unwrap_or_default(),
            email: get_first_attr(&entry, &self.config.user_email_attr),
            groups: entry
                .attrs
                .get(&self.config.user_groups_attr)
                .cloned()
                .unwrap_or_default(),
        };

        debug!(dn = %entry.dn, user_id = %user_entry.id, "Found user");

        Ok(Some((entry.dn, user_entry)))
    }

    /// Search for a group by ID
    #[instrument(skip(self))]
    async fn search_group(&self, group_id: &str) -> Result<Option<LdapGroupEntry>> {
        let mut conn_guard = self.get_connection().await?;
        let ldap = conn_guard
            .as_mut()
            .ok_or_else(|| Error::Ldap("No connection".to_string()))?;

        let filter = format!(
            "(&{}({}={}))",
            self.config.group_filter,
            self.config.group_id_attr,
            ldap3::ldap_escape(group_id)
        );

        let attrs = vec![
            &self.config.group_id_attr,
            &self.config.group_name_attr,
            &self.config.group_member_attr,
            "description",
        ];

        let (entries, _result) = ldap
            .search(
                &self.config.group_base_dn,
                ldap3::Scope::Subtree,
                &filter,
                attrs,
            )
            .await
            .map_err(|e| Error::Ldap(format!("Group search failed: {}", e)))?
            .success()
            .map_err(|e| Error::Ldap(format!("Group search rejected: {}", e)))?;

        if entries.is_empty() {
            return Ok(None);
        }

        let entry = ldap3::SearchEntry::construct(entries.into_iter().next().unwrap());

        Ok(Some(LdapGroupEntry {
            dn: entry.dn,
            id: get_first_attr(&entry, &self.config.group_id_attr).unwrap_or_default(),
            name: get_first_attr(&entry, &self.config.group_name_attr).unwrap_or_default(),
            description: get_first_attr(&entry, "description"),
            members: entry
                .attrs
                .get(&self.config.group_member_attr)
                .cloned()
                .unwrap_or_default(),
        }))
    }

    /// Get all groups containing a user DN
    #[instrument(skip(self))]
    async fn get_groups_for_user_dn(&self, user_dn: &str) -> Result<Vec<LdapGroupEntry>> {
        let mut conn_guard = self.get_connection().await?;
        let ldap = conn_guard
            .as_mut()
            .ok_or_else(|| Error::Ldap("No connection".to_string()))?;

        let filter = format!(
            "(&{}({}={}))",
            self.config.group_filter,
            self.config.group_member_attr,
            ldap3::ldap_escape(user_dn)
        );

        let attrs = vec![
            &self.config.group_id_attr,
            &self.config.group_name_attr,
            &self.config.group_member_attr,
            "description",
        ];

        let (entries, _result) = ldap
            .search(
                &self.config.group_base_dn,
                ldap3::Scope::Subtree,
                &filter,
                attrs,
            )
            .await
            .map_err(|e| Error::Ldap(format!("Group search failed: {}", e)))?
            .success()
            .map_err(|e| Error::Ldap(format!("Group search rejected: {}", e)))?;

        let groups = entries
            .into_iter()
            .map(|e| {
                let entry = ldap3::SearchEntry::construct(e);
                LdapGroupEntry {
                    dn: entry.dn,
                    id: get_first_attr(&entry, &self.config.group_id_attr).unwrap_or_default(),
                    name: get_first_attr(&entry, &self.config.group_name_attr).unwrap_or_default(),
                    description: get_first_attr(&entry, "description"),
                    members: entry
                        .attrs
                        .get(&self.config.group_member_attr)
                        .cloned()
                        .unwrap_or_default(),
                }
            })
            .collect();

        Ok(groups)
    }

    /// Convert LDAP user entry to Identity
    fn entry_to_identity(&self, entry: LdapUserEntry, groups: Vec<String>) -> Identity {
        let mut identity = Identity::user(&entry.id, &entry.name, &self.config.id);
        identity.email = entry.email;
        identity.groups = groups;

        // Add DN as attribute
        identity.attributes.insert("dn".to_string(), entry.dn);

        identity
    }

    /// Health check - verify LDAP server is reachable
    pub async fn health_check(&self) -> Result<bool> {
        self.ensure_connection().await?;
        Ok(true)
    }
}

/// Internal LDAP user entry
#[cfg(feature = "ldap")]
#[derive(Debug, Clone)]
struct LdapUserEntry {
    dn: String,
    id: String,
    name: String,
    email: Option<String>,
    groups: Vec<String>,
}

/// Internal LDAP group entry
#[cfg(feature = "ldap")]
#[derive(Debug, Clone)]
struct LdapGroupEntry {
    dn: String,
    id: String,
    name: String,
    description: Option<String>,
    members: Vec<String>,
}

/// Get first attribute value from a search entry
#[cfg(feature = "ldap")]
fn get_first_attr(entry: &ldap3::SearchEntry, attr: &str) -> Option<String> {
    entry.attrs.get(attr).and_then(|v| v.first()).cloned()
}

/// Extract CN from a DN (e.g., "cn=admins,ou=groups,dc=example,dc=com" -> "admins")
#[cfg(any(feature = "ldap", test))]
fn extract_cn_from_dn(dn: &str) -> Option<String> {
    for part in dn.split(',') {
        let part = part.trim();
        if let Some(cn) = part
            .strip_prefix("cn=")
            .or_else(|| part.strip_prefix("CN="))
        {
            return Some(cn.to_string());
        }
    }
    None
}

#[cfg(feature = "ldap")]
#[async_trait]
impl IdentityProvider for LdapProvider {
    fn id(&self) -> &str {
        &self.config.id
    }

    fn name(&self) -> &str {
        &self.config.name
    }

    #[instrument(skip(self, credentials))]
    async fn authenticate(&self, credentials: &Credentials) -> Result<Identity> {
        match credentials {
            Credentials::Password { username, password } => {
                // First, search for the user to get their DN
                let (user_dn, user_entry) = self.search_user(username).await?.ok_or_else(|| {
                    warn!(username = %username, "User not found in LDAP");
                    Error::AuthenticationFailed("Invalid username or password".to_string())
                })?;

                // Create a fresh connection for authentication
                let mut auth_ldap = self.create_auth_connection().await?;

                // Attempt to bind as the user
                let bind_result = auth_ldap
                    .simple_bind(&user_dn, password)
                    .await
                    .map_err(|e| {
                        error!(username = %username, error = %e, "LDAP bind failed");
                        Error::AuthenticationFailed("Invalid username or password".to_string())
                    })?;

                if bind_result.rc != 0 {
                    warn!(username = %username, rc = bind_result.rc, "LDAP bind rejected");
                    return Err(Error::AuthenticationFailed(
                        "Invalid username or password".to_string(),
                    ));
                }

                // Successfully authenticated - unbind the auth connection
                let _ = auth_ldap.unbind().await;

                debug!(username = %username, dn = %user_dn, "User authenticated via LDAP");

                // Get groups from memberOf attribute or by searching
                let groups = if !user_entry.groups.is_empty() {
                    // Extract group names from memberOf DNs
                    user_entry
                        .groups
                        .iter()
                        .filter_map(|dn| extract_cn_from_dn(dn))
                        .collect()
                } else {
                    // Search for groups containing this user
                    let group_entries = self.get_groups_for_user_dn(&user_dn).await?;
                    group_entries.iter().map(|g| g.id.clone()).collect()
                };

                Ok(self.entry_to_identity(user_entry, groups))
            }
            _ => Err(Error::AuthenticationFailed(
                "LDAP only supports password authentication".to_string(),
            )),
        }
    }

    async fn validate_token(&self, _token: &str) -> Result<Identity> {
        Err(Error::InvalidToken(
            "LDAP does not support token validation".to_string(),
        ))
    }

    async fn refresh_token(&self, _refresh_token: &str) -> Result<(String, Option<String>)> {
        Err(Error::InvalidToken(
            "LDAP does not support token refresh".to_string(),
        ))
    }

    #[instrument(skip(self))]
    async fn get_user(&self, user_id: &str) -> Result<Option<Identity>> {
        let result = self.search_user(user_id).await?;

        if let Some((user_dn, user_entry)) = result {
            // Get groups
            let groups = if !user_entry.groups.is_empty() {
                user_entry
                    .groups
                    .iter()
                    .filter_map(|dn| extract_cn_from_dn(dn))
                    .collect()
            } else {
                let group_entries = self.get_groups_for_user_dn(&user_dn).await?;
                group_entries.iter().map(|g| g.id.clone()).collect()
            };

            Ok(Some(self.entry_to_identity(user_entry, groups)))
        } else {
            Ok(None)
        }
    }

    #[instrument(skip(self))]
    async fn get_user_groups(&self, user_id: &str) -> Result<Vec<Group>> {
        let result = self.search_user(user_id).await?;

        if let Some((user_dn, user_entry)) = result {
            // Get groups from memberOf or by searching
            let group_entries = if !user_entry.groups.is_empty() {
                // Load full group info for each memberOf DN
                let mut groups = Vec::new();
                for group_dn in &user_entry.groups {
                    if let Some(cn) = extract_cn_from_dn(group_dn) {
                        if let Some(g) = self.search_group(&cn).await? {
                            groups.push(g);
                        }
                    }
                }
                groups
            } else {
                self.get_groups_for_user_dn(&user_dn).await?
            };

            // Convert to Group type
            let groups = group_entries
                .into_iter()
                .map(|g| {
                    let mut group = Group::new(&g.id, &g.name);
                    group.description = g.description;

                    // Convert member DNs to user IDs
                    for member_dn in &g.members {
                        if let Some(cn) = extract_cn_from_dn(member_dn) {
                            group.members.push(cn);
                        }
                    }

                    group.attributes.insert("dn".to_string(), g.dn);
                    group
                })
                .collect();

            Ok(groups)
        } else {
            Ok(Vec::new())
        }
    }

    #[instrument(skip(self))]
    async fn get_group(&self, group_id: &str) -> Result<Option<Group>> {
        let result = self.search_group(group_id).await?;

        if let Some(g) = result {
            let mut group = Group::new(&g.id, &g.name);
            group.description = g.description;

            // Convert member DNs to user IDs
            for member_dn in &g.members {
                if let Some(cn) = extract_cn_from_dn(member_dn) {
                    group.members.push(cn);
                }
            }

            group.attributes.insert("dn".to_string(), g.dn);
            Ok(Some(group))
        } else {
            Ok(None)
        }
    }
}

/// Stub LDAP provider when the ldap feature is not enabled
#[cfg(not(feature = "ldap"))]
pub struct LdapProvider {
    config: LdapConfig,
}

#[cfg(not(feature = "ldap"))]
impl LdapProvider {
    /// Create a new LDAP provider (stub)
    pub async fn new(config: LdapConfig) -> Result<Self> {
        Ok(Self { config })
    }

    /// Health check
    pub async fn health_check(&self) -> Result<bool> {
        Err(Error::Ldap("LDAP requires the 'ldap' feature".to_string()))
    }
}

#[cfg(not(feature = "ldap"))]
#[async_trait]
impl IdentityProvider for LdapProvider {
    fn id(&self) -> &str {
        &self.config.id
    }

    fn name(&self) -> &str {
        &self.config.name
    }

    async fn authenticate(&self, _credentials: &Credentials) -> Result<Identity> {
        Err(Error::Ldap("LDAP requires the 'ldap' feature".to_string()))
    }

    async fn validate_token(&self, _token: &str) -> Result<Identity> {
        Err(Error::InvalidToken(
            "LDAP does not support token validation".to_string(),
        ))
    }

    async fn refresh_token(&self, _refresh_token: &str) -> Result<(String, Option<String>)> {
        Err(Error::InvalidToken(
            "LDAP does not support token refresh".to_string(),
        ))
    }

    async fn get_user(&self, _user_id: &str) -> Result<Option<Identity>> {
        Err(Error::Ldap("LDAP requires the 'ldap' feature".to_string()))
    }

    async fn get_user_groups(&self, _user_id: &str) -> Result<Vec<Group>> {
        Err(Error::Ldap("LDAP requires the 'ldap' feature".to_string()))
    }

    async fn get_group(&self, _group_id: &str) -> Result<Option<Group>> {
        Err(Error::Ldap("LDAP requires the 'ldap' feature".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ldap_config_default() {
        let config = LdapConfig::default();
        assert_eq!(config.id, "ldap");
        assert_eq!(config.url, "ldap://localhost:389");
        assert_eq!(config.user_filter, "(uid={username})");
        assert_eq!(config.user_id_attr, "uid");
    }

    #[test]
    fn test_ldap_config_active_directory() {
        let config =
            LdapConfig::active_directory("ldaps://ad.example.com:636", "dc=example,dc=com");
        assert_eq!(config.id, "ad");
        assert_eq!(config.user_filter, "(sAMAccountName={username})");
        assert_eq!(config.user_id_attr, "sAMAccountName");
    }

    #[test]
    fn test_ldap_config_openldap() {
        let config = LdapConfig::openldap("ldap://ldap.example.com:389", "dc=example,dc=com");
        assert_eq!(config.id, "openldap");
        assert_eq!(config.user_filter, "(uid={username})");
        assert_eq!(config.group_base_dn, "ou=groups,dc=example,dc=com");
    }

    #[test]
    fn test_ldap_config_with_bind() {
        let config =
            LdapConfig::default().with_bind_credentials("cn=admin,dc=example,dc=com", "secret");
        assert_eq!(
            config.bind_dn,
            Some("cn=admin,dc=example,dc=com".to_string())
        );
        assert_eq!(config.bind_password, Some("secret".to_string()));
    }

    #[test]
    fn test_ldap_config_with_starttls() {
        let config = LdapConfig::default().with_starttls();
        assert!(config.starttls);
    }

    #[test]
    fn test_extract_cn_from_dn() {
        assert_eq!(
            extract_cn_from_dn("cn=admins,ou=groups,dc=example,dc=com"),
            Some("admins".to_string())
        );
        assert_eq!(
            extract_cn_from_dn("CN=Domain Admins,OU=Groups,DC=example,DC=com"),
            Some("Domain Admins".to_string())
        );
        assert_eq!(
            extract_cn_from_dn("uid=alice,ou=users,dc=example,dc=com"),
            None
        );
        assert_eq!(extract_cn_from_dn("invalid"), None);
    }

    #[test]
    fn test_extract_cn_preserves_spaces() {
        assert_eq!(
            extract_cn_from_dn("cn=Domain Users,ou=groups,dc=example,dc=com"),
            Some("Domain Users".to_string())
        );
    }

    #[tokio::test]
    #[cfg(not(feature = "ldap"))]
    async fn test_ldap_stub_returns_error() {
        let config = LdapConfig::default();
        let provider = LdapProvider::new(config).await.unwrap();

        let result = provider
            .authenticate(&Credentials::Password {
                username: "test".to_string(),
                password: "test".to_string(),
            })
            .await;
        assert!(matches!(result, Err(Error::Ldap(_))));

        let result = provider.get_user("test").await;
        assert!(matches!(result, Err(Error::Ldap(_))));

        let result = provider.get_group("admins").await;
        assert!(matches!(result, Err(Error::Ldap(_))));

        let result = provider.health_check().await;
        assert!(matches!(result, Err(Error::Ldap(_))));
    }

    #[tokio::test]
    #[cfg(not(feature = "ldap"))]
    async fn test_ldap_stub_token_errors() {
        let config = LdapConfig::default();
        let provider = LdapProvider::new(config).await.unwrap();

        let result = provider.validate_token("token").await;
        assert!(matches!(result, Err(Error::InvalidToken(_))));

        let result = provider.refresh_token("refresh").await;
        assert!(matches!(result, Err(Error::InvalidToken(_))));
    }

    #[test]
    fn test_ldap_provider_id_and_name() {
        let config = LdapConfig {
            id: "corp-ldap".to_string(),
            name: "Corporate LDAP".to_string(),
            ..Default::default()
        };

        // Just verify config fields are accessible
        assert_eq!(config.id, "corp-ldap");
        assert_eq!(config.name, "Corporate LDAP");
    }
}
