//! OpenID Connect: the scopes that are about identity rather than permissions,
//! and the claims an ID token and the UserInfo endpoint carry.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::user::User;

pub const SCOPE_OPENID: &str = "openid";
pub const SCOPE_PROFILE: &str = "profile";
pub const SCOPE_EMAIL: &str = "email";

/// Scopes defined by OpenID Connect. They are not permissions: any client may
/// ask for them, and they never grant access to a resource.
pub const SCOPES: [&str; 3] = [SCOPE_OPENID, SCOPE_PROFILE, SCOPE_EMAIL];

pub fn is_oidc_scope(scope: &str) -> bool {
    SCOPES.contains(&scope)
}

/// Whether a session's scopes make it an OpenID Connect session.
pub fn requests_identity(scopes: Option<&[String]>) -> bool {
    scopes.is_some_and(|scopes| scopes.iter().any(|s| s == SCOPE_OPENID))
}

/// OIDC Core 3.1.3.6: the base64url of the left half of the SHA-256 of the
/// access token.
pub fn at_hash(access_token: &str) -> String {
    let digest = Sha256::digest(access_token.as_bytes());
    B64URL.encode(&digest[..16])
}

/// Claims of an ID token.
#[derive(Debug, Serialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: Uuid,
    pub aud: String,
    pub azp: String,
    pub exp: i64,
    pub iat: i64,
    pub auth_time: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    pub at_hash: String,
    #[serde(flatten)]
    pub profile: UserClaims,
}

/// The claims the granted scopes release about the user.
#[derive(Debug, Default, Serialize, PartialEq)]
pub struct UserClaims {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
}

pub fn user_claims(user: &User, scopes: &[String]) -> UserClaims {
    let has = |scope: &str| scopes.iter().any(|s| s == scope);
    let mut claims = UserClaims::default();
    if has(SCOPE_PROFILE) {
        claims.preferred_username = Some(user.username.clone());
        claims.locale = Some(user.preferred_locale.clone());
        claims.updated_at = Some(user.updated_at.unix_timestamp());
    }
    if has(SCOPE_EMAIL) {
        claims.email = Some(user.email.clone());
        claims.email_verified = Some(user.email_verified_at.is_some());
    }
    claims
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::user::UserStatus;
    use time::OffsetDateTime;

    fn user() -> User {
        User {
            id: Uuid::nil(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(10),
            email_verified_at: Some(OffsetDateTime::UNIX_EPOCH),
            last_login_at: None,
            locked_until: None,
            status: UserStatus::Active,
            preferred_locale: "fr".into(),
            username: "jane".into(),
            email: "jane@example.com".into(),
            password_hash: String::new(),
        }
    }

    #[test]
    fn scopes_release_their_claims_only() {
        let scopes = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            user_claims(&user(), &scopes(&["openid"])),
            UserClaims::default()
        );
        let profile = user_claims(&user(), &scopes(&["openid", "profile"]));
        assert_eq!(profile.preferred_username.as_deref(), Some("jane"));
        assert_eq!(profile.updated_at, Some(10));
        assert!(profile.email.is_none());
        let email = user_claims(&user(), &scopes(&["email"]));
        assert_eq!(email.email.as_deref(), Some("jane@example.com"));
        assert_eq!(email.email_verified, Some(true));
        assert!(email.preferred_username.is_none());
    }

    #[test]
    fn at_hash_is_the_left_half_of_the_sha256() {
        // OIDC Core example, recomputed: 16 bytes, base64url without padding.
        let hash = at_hash("jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y");
        assert_eq!(hash.len(), 22);
        assert!(!hash.contains('='));
        assert!(requests_identity(Some(&["openid".to_owned()])));
        assert!(!requests_identity(Some(&["docs:read".to_owned()])));
        assert!(!requests_identity(None));
        assert!(is_oidc_scope("email") && !is_oidc_scope("users:read"));
    }
}
