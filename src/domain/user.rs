//! User domain type.
//!
//! Maps the `users` table. The password_hash field is intentionally kept
//! here and must never be forwarded to a DTO or HTTP response.

use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, sqlx::Type)]
#[sqlx(type_name = "user_status", rename_all = "snake_case")]
pub enum UserStatus {
    Active,
    Inactive,
    Suspended,
    PendingVerification,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub email_verified_at: Option<OffsetDateTime>,
    pub last_login_at: Option<OffsetDateTime>,
    pub locked_until: Option<OffsetDateTime>,
    pub status: UserStatus,
    pub preferred_locale: String,
    pub username: String,
    pub email: String,
    pub password_hash: String,
}

impl User {
    pub fn is_locked(&self, now: OffsetDateTime) -> bool {
        self.locked_until.is_some_and(|t| t > now)
    }
}

impl User {
    pub fn is_active(&self) -> bool {
        self.status == UserStatus::Active
    }

    pub fn is_email_verified(&self) -> bool {
        self.email_verified_at.is_some()
    }
}

/// Usernames as the `users_username_format` constraint accepts them: ASCII
/// letters, digits and underscores only. Length is checked by the caller.
pub fn is_valid_username(username: &str) -> bool {
    !username.is_empty()
        && username
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Addresses the `users` table can store: ASCII, at most 254 bytes, in the
/// shape of the `users_email_format` constraint (`local@host.tld`). Stricter
/// than RFC 5322 on purpose: whatever passes here must also pass the database
/// CHECK, or the request fails with a 500 instead of a 422.
pub fn is_storable_email(email: &str) -> bool {
    if email.len() > 254 || !email.is_ascii() {
        return false;
    }
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    let Some((host, tld)) = domain.rsplit_once('.') else {
        return false;
    };
    !local.is_empty()
        && local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._%+-".contains(&b))
        && !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
        && tld.len() >= 2
        && tld.bytes().all(|b| b.is_ascii_alphabetic())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH + time::Duration::days(20_000)
    }

    fn make_user(status: UserStatus, locked_secs: Option<i64>, verified: bool) -> User {
        let now = now();
        User {
            id: uuid::Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            email_verified_at: if verified { Some(now) } else { None },
            last_login_at: None,
            locked_until: locked_secs.map(|s| now + time::Duration::seconds(s)),
            status,
            preferred_locale: "en".into(),
            username: "test".into(),
            email: "test@example.com".into(),
            password_hash: "hash".into(),
        }
    }

    #[test]
    fn is_locked_true_when_locked_until_is_in_future() {
        assert!(make_user(UserStatus::Active, Some(3600), false).is_locked(now()));
    }

    #[test]
    fn is_locked_false_when_locked_until_is_in_past() {
        assert!(!make_user(UserStatus::Active, Some(-1), false).is_locked(now()));
    }

    #[test]
    fn is_locked_false_when_no_lockout() {
        assert!(!make_user(UserStatus::Active, None, false).is_locked(now()));
    }

    #[test]
    fn lockout_ends_at_locked_until() {
        let user = make_user(UserStatus::Active, Some(1800), false);
        let until = user.locked_until.unwrap();
        assert!(user.is_locked(until - time::Duration::nanoseconds(1)));
        assert!(!user.is_locked(until));
    }

    #[test]
    fn is_active_true_for_active_status() {
        assert!(make_user(UserStatus::Active, None, false).is_active());
    }

    #[test]
    fn is_active_false_for_suspended() {
        assert!(!make_user(UserStatus::Suspended, None, false).is_active());
    }

    #[test]
    fn is_email_verified_true_when_timestamp_set() {
        assert!(make_user(UserStatus::Active, None, true).is_email_verified());
    }

    #[test]
    fn is_email_verified_false_when_timestamp_missing() {
        assert!(!make_user(UserStatus::Active, None, false).is_email_verified());
    }

    #[test]
    fn usernames_must_match_the_database_constraint() {
        assert!(is_valid_username("alice_42"));
        assert!(!is_valid_username("José_1"));
        assert!(!is_valid_username("bad-name"));
        assert!(!is_valid_username(""));
    }

    #[test]
    fn storable_emails_match_the_database_constraint() {
        assert!(is_storable_email("first.last+tag@mail.example.org"));
        assert!(!is_storable_email("user@localhost"));
        assert!(!is_storable_email("usér@example.com"));
        assert!(!is_storable_email("a@b@example.com"));
        assert!(!is_storable_email("user@example.c0m"));
        assert!(!is_storable_email(&format!(
            "{}@example.com",
            "a".repeat(250)
        )));
    }
}
