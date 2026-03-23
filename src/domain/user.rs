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
