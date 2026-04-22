//! One-time token domain types.
//!
//! Maps `email_verification_tokens` and `password_reset_tokens` tables.
//! token_hash is a 32-byte SHA-256 digest; the plaintext token is never stored.

use ipnetwork::IpNetwork;

use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct EmailVerificationToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: Vec<u8>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub used_at: Option<OffsetDateTime>,
    pub request_ip: Option<IpNetwork>,
    pub request_user_agent: Option<String>,
    pub target_email: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PasswordResetToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: Vec<u8>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub used_at: Option<OffsetDateTime>,
    pub request_ip: Option<IpNetwork>,
    pub request_user_agent: Option<String>,
}

// Shared helpers for both token types

pub trait OneTimeToken {
    fn used_at(&self) -> Option<OffsetDateTime>;
    fn expires_at(&self) -> OffsetDateTime;

    fn is_used(&self) -> bool {
        self.used_at().is_some()
    }

    fn is_expired(&self) -> bool {
        self.expires_at() < OffsetDateTime::now_utc()
    }

    fn is_valid(&self) -> bool {
        !self.is_used() && !self.is_expired()
    }
}

impl OneTimeToken for EmailVerificationToken {
    fn used_at(&self) -> Option<OffsetDateTime> {
        self.used_at
    }

    fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }
}

impl OneTimeToken for PasswordResetToken {
    fn used_at(&self) -> Option<OffsetDateTime> {
        self.used_at
    }

    fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_reset_token(used: bool, expires_in_secs: i64) -> PasswordResetToken {
        let now = OffsetDateTime::now_utc();
        PasswordResetToken {
            id: uuid::Uuid::new_v4(),
            user_id: uuid::Uuid::new_v4(),
            token_hash: vec![0u8; 32],
            created_at: now,
            expires_at: now + time::Duration::seconds(expires_in_secs),
            used_at: if used { Some(now) } else { None },
            request_ip: None,
            request_user_agent: None,
        }
    }

    #[test]
    fn is_used_true_when_used_at_set() {
        assert!(make_reset_token(true, 3600).is_used());
    }

    #[test]
    fn is_used_false_when_not_used() {
        assert!(!make_reset_token(false, 3600).is_used());
    }

    #[test]
    fn is_expired_true_when_past() {
        assert!(make_reset_token(false, -1).is_expired());
    }

    #[test]
    fn is_expired_false_when_future() {
        assert!(!make_reset_token(false, 3600).is_expired());
    }

    #[test]
    fn is_valid_true_when_unused_and_not_expired() {
        assert!(make_reset_token(false, 3600).is_valid());
    }

    #[test]
    fn is_valid_false_when_used() {
        assert!(!make_reset_token(true, 3600).is_valid());
    }

    #[test]
    fn is_valid_false_when_expired() {
        assert!(!make_reset_token(false, -1).is_valid());
    }
}
