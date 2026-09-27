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
    UsernameChanged,
    RecoveryCodeUsed,
    EmailChanged,
    EncryptionKeyRotated,
    AccountUnlocked,
    PasswordResetForced,
    AccessFactorsRemoved,
    /// The user approved a client application's authorization request.
    ClientAuthorized,
    /// The user approved a device authorization request.
    DeviceApproved,
    /// The user refused a device authorization request.
    DeviceDenied,
    /// An administrator read accounts or the audit log (in their own history).
    AdminDataRead,
    RoleCreated,
    RoleDeleted,
    RolePermissionsChanged,
    ClientRegistered,
    ClientUpdated,
    ClientDeleted,
    DataExported,
    MagicLinkSent,
    PersonalAccessTokenCreated,
    PersonalAccessTokenRevoked,
    WebhookCreated,
    WebhookUpdated,
    WebhookDeleted,
    WebhookSecretRotated,
    ClientSecretRotated,
    PasskeyRegistered,
    PasskeyRemoved,
    ExternalIdentityLinked,
    ExternalIdentityUnlinked,
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

/// An entry as the account's owner sees it: a change made by an administrator
/// or from the command line keeps what was done, not who did it nor from
/// where (no administrator id or address, no operator account or host).
pub fn owner_view(
    mut metadata: serde_json::Value,
    ip_address: Option<ipnetwork::IpNetwork>,
) -> (serde_json::Value, Option<ipnetwork::IpNetwork>) {
    let by = metadata.get("by").and_then(|by| by.as_str());
    if !matches!(by, Some("administrator" | "command_line")) {
        return (metadata, ip_address);
    }
    if let Some(fields) = metadata.as_object_mut() {
        for field in OPERATOR_FIELDS {
            fields.remove(*field);
        }
    }
    (metadata, None)
}

/// Metadata naming who made a change on someone else's account.
pub const OPERATOR_FIELDS: &[&str] = &["administrator_id", "operator", "host"];
