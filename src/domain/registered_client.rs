//! Registered client domain type.
//!
//! Maps the `registered_clients` table: a known client application allowed to
//! sign users in through the device authorization flow or the authorization
//! code flow. Requests naming an unregistered client are refused.

use time::OffsetDateTime;

use super::client_quota::UserClientQuota;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RegisteredClient {
    pub client_id: String,
    pub display_name: String,
    /// The application this instance owns; used when a device flow names no client.
    pub is_primary: bool,
    pub created_at: OffsetDateTime,
    /// Permissions a token issued for this client may carry, by `resource:action`
    /// name. Empty means unrestricted.
    pub scopes: Vec<String>,
    /// Exact redirect URIs accepted for the authorization code flow.
    pub redirect_uris: Vec<String>,
    /// Whether a loopback redirect on any port is accepted for a registered path.
    pub allows_loopback_redirect: bool,
    /// Concurrent device sessions per user when no quota row overrides it.
    pub default_max_sessions: i16,
    /// SHA-256 of the client secret of a confidential client; `None` for a
    /// public client.
    pub client_secret_hash: Option<Vec<u8>>,
    /// May obtain tokens for itself with the client credentials grant.
    pub allows_client_credentials: bool,
}

impl RegisteredClient {
    /// Whether the client authenticates with a secret at the token endpoint.
    pub fn is_confidential(&self) -> bool {
        self.client_secret_hash.is_some()
    }

    /// Concurrent device sessions a user may hold for this client.
    ///
    /// A per-user quota row always applies. Without one, a non-primary client is
    /// capped by its default, while the primary client (the application this
    /// instance owns) is unlimited.
    pub fn session_limit(&self, quota: Option<&UserClientQuota>) -> Option<i64> {
        match quota {
            Some(quota) => Some(i64::from(quota.max_sessions)),
            None if self.is_primary => None,
            None => Some(i64::from(self.default_max_sessions)),
        }
    }

    /// Permissions a token for this client carries, given the user's own: the
    /// intersection with the client's scopes, or everything the user holds when
    /// the client is unrestricted.
    pub fn granted(&self, user_permissions: &[String]) -> Vec<String> {
        if self.scopes.is_empty() {
            return user_permissions.to_vec();
        }
        user_permissions
            .iter()
            .filter(|permission| self.scopes.contains(permission))
            .cloned()
            .collect()
    }

    /// The scopes an approval freezes: what the user holds among the client's
    /// scopes, or `None` for an unrestricted client. `Some` of an empty list is
    /// a real answer, a token carrying no permission, never "unrestricted".
    pub fn consented_scopes(&self, user_permissions: &[String]) -> Option<Vec<String>> {
        (!self.scopes.is_empty()).then(|| self.granted(user_permissions))
    }
}

/// The claims of a token: the user's roles and permissions, restricted to
/// `consent` when its session was issued to a client. Roles are dropped then:
/// a resource server authorizing by role would grant more than the consent
/// covered. `Some(&[])` consents to nothing.
pub fn restrict_to_consent(
    roles: Vec<String>,
    mut permissions: Vec<String>,
    consent: Option<&[String]>,
) -> (Vec<String>, Vec<String>) {
    match consent {
        None => (roles, permissions),
        Some(consent) => {
            permissions.retain(|permission| consent.contains(permission));
            (Vec::new(), permissions)
        }
    }
}

/// Whether `client_id` has the shape the `registered_clients` table accepts.
pub fn is_valid_client_id(client_id: &str) -> bool {
    (1..=100).contains(&client_id.len())
        && client_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

/// Check client settings before they are stored, with a message for the caller.
pub fn check_settings(
    client_id: &str,
    display_name: &str,
    redirect_uris: &[String],
    default_max_sessions: i16,
) -> Result<(), String> {
    if !is_valid_client_id(client_id) {
        return Err("client id must be 1 to 100 of [A-Za-z0-9._-]".into());
    }
    if display_name.trim().is_empty() || display_name.chars().count() > 200 {
        return Err("name must be 1 to 200 characters".into());
    }
    for uri in redirect_uris {
        reqwest::Url::parse(uri).map_err(|e| format!("invalid redirect uri {uri}: {e}"))?;
    }
    if default_max_sessions <= 0 {
        return Err("max sessions must be a positive number".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(is_primary: bool, scopes: &[&str]) -> RegisteredClient {
        RegisteredClient {
            client_id: "app".into(),
            display_name: "App".into(),
            is_primary,
            created_at: OffsetDateTime::now_utc(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            redirect_uris: vec![],
            allows_loopback_redirect: false,
            default_max_sessions: 2,
            client_secret_hash: None,
            allows_client_credentials: false,
        }
    }

    #[test]
    fn session_limit_prefers_quota_then_default_and_leaves_primary_unlimited() {
        let quota = UserClientQuota {
            id: uuid::Uuid::new_v4(),
            user_id: uuid::Uuid::new_v4(),
            client_id: "app".into(),
            max_sessions: 7,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        };
        assert_eq!(client(false, &[]).session_limit(Some(&quota)), Some(7));
        assert_eq!(client(false, &[]).session_limit(None), Some(2));
        assert_eq!(client(true, &[]).session_limit(None), None);
        assert_eq!(client(true, &[]).session_limit(Some(&quota)), Some(7));
    }

    #[test]
    fn granted_is_an_intersection_unless_unrestricted() {
        let user = vec!["users:read".to_string(), "users:manage".to_string()];
        assert_eq!(
            client(false, &["users:read", "other:x"]).granted(&user),
            vec!["users:read"]
        );
        assert_eq!(client(false, &[]).granted(&user), user);
    }

    #[test]
    fn only_a_restricted_client_freezes_scopes() {
        let user = vec!["users:read".to_string(), "users:manage".to_string()];
        assert_eq!(client(false, &[]).consented_scopes(&user), None);
        assert_eq!(
            client(false, &["users:read"]).consented_scopes(&user),
            Some(vec!["users:read".to_string()])
        );
        assert_eq!(
            client(false, &["other:x"]).consented_scopes(&user),
            Some(vec![]),
            "consenting to scopes the user lacks grants nothing, not everything"
        );
    }

    #[test]
    fn a_consent_keeps_its_permissions_and_drops_every_role() {
        let roles = vec!["admin".to_string()];
        let permissions = vec!["users:read".to_string(), "users:manage".to_string()];

        assert_eq!(
            restrict_to_consent(roles.clone(), permissions.clone(), None),
            (roles.clone(), permissions.clone())
        );
        assert_eq!(
            restrict_to_consent(
                roles.clone(),
                permissions.clone(),
                Some(&["users:read".to_string()])
            ),
            (vec![], vec!["users:read".to_string()])
        );
        assert_eq!(
            restrict_to_consent(roles, permissions, Some(&[])),
            (vec![], vec![])
        );
    }
}
