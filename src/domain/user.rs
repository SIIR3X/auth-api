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
    pub fn is_locked(&self) -> bool {
        self.locked_until
            .is_some_and(|t| t > OffsetDateTime::now_utc())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_user(status: UserStatus, locked_secs: Option<i64>, verified: bool) -> User {
        let now = time::OffsetDateTime::now_utc();
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
        assert!(make_user(UserStatus::Active, Some(3600), false).is_locked());
    }

    #[test]
    fn is_locked_false_when_locked_until_is_in_past() {
        assert!(!make_user(UserStatus::Active, Some(-1), false).is_locked());
    }

    #[test]
    fn is_locked_false_when_no_lockout() {
        assert!(!make_user(UserStatus::Active, None, false).is_locked());
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
}
