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
