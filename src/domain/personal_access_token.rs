//! Personal access tokens: what a token looks like, and what an account may put
//! in one.

use time::OffsetDateTime;
use uuid::Uuid;

/// Marks the secret as this service's personal access token, so secret
/// scanners and people recognize it in a leaked file.
pub const PREFIX: &str = "aapat_";

/// Longest lifetime an account may give a token.
pub const MAX_LIFETIME_DAYS: i64 = 365;

/// Lifetime when the request names none.
pub const DEFAULT_LIFETIME_DAYS: i64 = 90;

/// Active tokens per account.
pub const MAX_ACTIVE_PER_ACCOUNT: i64 = 20;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PersonalAccessToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub name: String,
    pub scopes: Vec<String>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub last_used_at: Option<OffsetDateTime>,
}

/// The secret handed to the account: the prefix and 32 random bytes.
pub fn format_token(random: &str) -> String {
    format!("{PREFIX}{random}")
}

/// The random part of a presented token, when it has the shape of one: the
/// prefix, then 43 URL-safe base64 characters.
pub fn random_part(presented: &str) -> Option<&str> {
    let random = presented.strip_prefix(PREFIX)?;
    (random.len() == 43
        && random
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
    .then_some(random)
}

/// The requested scopes, sorted and deduplicated, when the account holds every
/// one of them; otherwise the ones it does not hold.
pub fn grantable_scopes(requested: &[String], held: &[String]) -> Result<Vec<String>, Vec<String>> {
    let mut scopes = requested.to_vec();
    scopes.sort();
    scopes.dedup();
    let missing: Vec<String> = scopes
        .iter()
        .filter(|scope| !held.contains(scope))
        .cloned()
        .collect();
    if missing.is_empty() {
        Ok(scopes)
    } else {
        Err(missing)
    }
}

/// A token name: 1 to 100 characters once trimmed, no control character.
pub fn valid_name(name: &str) -> Option<&str> {
    let name = name.trim();
    ((1..=100).contains(&name.chars().count()) && !name.chars().any(char::is_control))
        .then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_is_the_prefix_and_its_random_part() {
        let random = "a".repeat(43);
        let token = format_token(&random);
        assert_eq!(random_part(&token), Some(random.as_str()));
        assert_eq!(random_part(&random), None);
        assert_eq!(random_part(&format!("{PREFIX}{}", "a".repeat(42))), None);
        assert_eq!(random_part(&format!("{PREFIX}{}!", "a".repeat(42))), None);
    }

    #[test]
    fn scopes_are_limited_to_the_permissions_held() {
        let held = vec!["profile:read".to_owned(), "users:read".to_owned()];
        assert_eq!(
            grantable_scopes(&["users:read".into(), "users:read".into()], &held),
            Ok(vec!["users:read".to_owned()])
        );
        assert_eq!(
            grantable_scopes(&["users:manage".into()], &held),
            Err(vec!["users:manage".to_owned()])
        );
        assert_eq!(grantable_scopes(&[], &held), Ok(vec![]));
    }

    #[test]
    fn names_are_trimmed_and_bounded() {
        assert_eq!(valid_name("  deploy script "), Some("deploy script"));
        assert_eq!(valid_name("   "), None);
        assert_eq!(valid_name(&"n".repeat(101)), None);
        assert_eq!(valid_name("tab\there"), None);
    }
}
