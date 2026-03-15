//! Login attempt domain type.
//!
//! Maps the `login_attempts` table used for brute-force detection,
//! lockout logic, and security investigations.

use ipnetwork::IpNetwork;

use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, sqlx::Type)]
#[sqlx(type_name = "login_failure_reason", rename_all = "snake_case")]
pub enum LoginFailureReason {
    UnknownIdentifier,
    InvalidPassword,
    EmailNotVerified,
    AccountInactive,
    AccountSuspended,
    AccountDisabled,
    TwoFactorRequired,
    TwoFactorFailed,
    RateLimited,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LoginAttempt {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub attempted_at: OffsetDateTime,
    pub attempted_identifier: String,
    pub was_successful: bool,
    pub failure_reason: Option<LoginFailureReason>,
    pub request_ip: Option<IpNetwork>,
    pub request_user_agent: Option<String>,
}
