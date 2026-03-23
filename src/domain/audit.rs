//! Audit log domain type.
//!
//! Maps the `audit_log` partitioned table. This table is append-only;
//! the database enforces it via a trigger. Never attempt updates or deletes.

use ipnetwork::IpNetwork;

use serde_json::Value as JsonValue;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, sqlx::Type)]
#[sqlx(type_name = "audit_action", rename_all = "snake_case")]
pub enum AuditAction {
    Login,
    LoginFailed,
    Logout,
    Register,
    EmailVerificationSent,
    EmailVerified,
    PasswordChanged,
    PasswordResetRequested,
    PasswordResetCompleted,
    TwoFactorEnabled,
    TwoFactorDisabled,
    TwoFactorVerified,
    TwoFactorFailed,
    RoleAssigned,
    RoleRevoked,
    SessionRevoked,
    SessionReplayDetected,
    SessionFamilyRevoked,
    AccountSuspended,
    AccountReactivated,
    RateLimitExceeded,
    SuspiciousLogin,
    NewDeviceLogin,
    AccountDeleted,
    Reauthenticated,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuditLog {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub request_id: Option<Uuid>,
    pub created_at: OffsetDateTime,
    pub action: AuditAction,
    pub ip_address: Option<IpNetwork>,
    pub metadata: JsonValue,
}
