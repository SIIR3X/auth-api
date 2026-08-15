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
}

impl RegisteredClient {
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
}
