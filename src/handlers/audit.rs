//! The caller's own security history.
//!
//! Every sign-in, password change and replayed session is written to the audit
//! log; showing people their own entries is how they notice one that is not
//! theirs. Scoped to the caller by the query: there is no id to pass, and none
//! to guess.

use axum::{
    Json,
    extract::{Query, State},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    domain::audit::AuditAction, error::AppError, repositories::audit as audit_repo, state::AppState,
};

use super::extractors::AuthUser;

const DEFAULT_LIMIT: i64 = 50;
/// Most entries one page may hold; larger requests are clamped, not refused.
const MAX_LIMIT: i64 = 200;

#[derive(Deserialize, utoipa::ToSchema)]
pub struct ListParams {
    pub limit: Option<i64>,
    /// `next_cursor` of the previous page.
    pub cursor: Option<String>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct AuditEntryResponse {
    pub id: Uuid,
    /// Unix timestamp (seconds), like every other timestamp of this API.
    pub created_at: i64,
    /// Stable snake_case name: `login`, `password_changed`, ...
    pub action: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<Uuid>,
    #[schema(value_type = Object)]
    pub metadata: serde_json::Value,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct AuditPageResponse {
    pub entries: Vec<AuditEntryResponse>,
    /// Pass back as `cursor` to read the next page; absent on the last one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// GET /users/me/audit - newest first.
#[utoipa::path(
    get,
    path = "/users/me/audit",
    tag = "account",
    params(("limit" = Option<i64>, Query, description = "Entries per page, 1-200 (default 50)"), ("cursor" = Option<String>, Query, description = "next_cursor of the previous page")),
    responses(
        (status = 200, description = "The caller's security history, newest first", body = AuditPageResponse),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 422, description = "Invalid cursor", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn list(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<ListParams>,
) -> Result<Json<AuditPageResponse>, AppError> {
    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let before = params.cursor.as_deref().map(decode_cursor).transpose()?;

    // One row beyond the page tells whether another page follows.
    let mut rows = audit_repo::find_page_by_user(&state.db, auth.user_id, before, limit + 1)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    let next_cursor = if rows.len() > limit as usize {
        rows.truncate(limit as usize);
        rows.last()
            .map(|last| encode_cursor(last.created_at, last.id))
    } else {
        None
    };

    Ok(Json(AuditPageResponse {
        entries: rows
            .into_iter()
            .map(|entry| AuditEntryResponse {
                id: entry.id,
                created_at: entry.created_at.unix_timestamp(),
                action: action_name(&entry.action),
                // The address, not the network: every row is written from one
                // address and a `/32` on each line says nothing.
                ip_address: entry.ip_address.map(|net| net.ip().to_string()),
                request_id: entry.request_id,
                metadata: entry.metadata,
            })
            .collect(),
        next_cursor,
    }))
}

/// Opaque to clients: the position of the last entry of a page.
pub(crate) fn encode_cursor(created_at: OffsetDateTime, id: Uuid) -> String {
    B64URL.encode(format!("{}:{id}", created_at.unix_timestamp_nanos()))
}

pub(crate) fn decode_cursor(cursor: &str) -> Result<(OffsetDateTime, Uuid), AppError> {
    let invalid = || AppError::Validation("invalid cursor".into());
    let raw = B64URL.decode(cursor).map_err(|_| invalid())?;
    let raw = std::str::from_utf8(&raw).map_err(|_| invalid())?;
    let (nanos, id) = raw.split_once(':').ok_or_else(invalid)?;
    let nanos: i128 = nanos.parse().map_err(|_| invalid())?;
    let created_at = OffsetDateTime::from_unix_timestamp_nanos(nanos).map_err(|_| invalid())?;
    let id = id.parse().map_err(|_| invalid())?;
    Ok((created_at, id))
}

/// Wire name of an action. Written out rather than derived: these strings are
/// an API, and renaming a Rust variant must not rename them silently.
fn action_name(action: &AuditAction) -> &'static str {
    use AuditAction as A;
    match action {
        A::Login => "login",
        A::LoginFailed => "login_failed",
        A::Logout => "logout",
        A::Register => "register",
        A::EmailVerificationSent => "email_verification_sent",
        A::EmailVerified => "email_verified",
        A::PasswordChanged => "password_changed",
        A::PasswordResetRequested => "password_reset_requested",
        A::PasswordResetCompleted => "password_reset_completed",
        A::TwoFactorEnabled => "two_factor_enabled",
        A::TwoFactorDisabled => "two_factor_disabled",
        A::TwoFactorVerified => "two_factor_verified",
        A::TwoFactorFailed => "two_factor_failed",
        A::RoleAssigned => "role_assigned",
        A::RoleRevoked => "role_revoked",
        A::SessionRevoked => "session_revoked",
        A::SessionReplayDetected => "session_replay_detected",
        A::SessionFamilyRevoked => "session_family_revoked",
        A::AccountSuspended => "account_suspended",
        A::AccountReactivated => "account_reactivated",
        A::RateLimitExceeded => "rate_limit_exceeded",
        A::SuspiciousLogin => "suspicious_login",
        A::NewDeviceLogin => "new_device_login",
        A::AccountDeleted => "account_deleted",
        A::Reauthenticated => "reauthenticated",
        A::UsernameChanged => "username_changed",
        A::RecoveryCodeUsed => "recovery_code_used",
        A::EmailChanged => "email_changed",
        A::EncryptionKeyRotated => "encryption_key_rotated",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cursor_round_trips_to_the_microsecond() {
        let at = OffsetDateTime::from_unix_timestamp_nanos(1_789_000_000_123_456_000).unwrap();
        let id = Uuid::new_v4();
        assert_eq!(decode_cursor(&encode_cursor(at, id)).unwrap(), (at, id));
    }

    #[test]
    fn a_malformed_cursor_is_a_validation_error() {
        for cursor in [
            "",
            "not base64!",
            &B64URL.encode("123"),
            &B64URL.encode("x:y"),
        ] {
            assert!(matches!(
                decode_cursor(cursor),
                Err(AppError::Validation(_))
            ));
        }
    }

    #[test]
    fn wire_names_are_stable() {
        assert_eq!(action_name(&AuditAction::Login), "login");
        assert_eq!(
            action_name(&AuditAction::SessionReplayDetected),
            "session_replay_detected"
        );
    }
    mod properties {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(512))]

            #[test]
            fn cursors_round_trip_across_the_whole_timestamp_range(
                nanos in -377_705_116_800_000_000_000i128..=253_402_300_799_999_999_999i128,
                id in any::<[u8; 16]>(),
            ) {
                let at = OffsetDateTime::from_unix_timestamp_nanos(nanos).unwrap();
                let id = Uuid::from_bytes(id);
                prop_assert_eq!(decode_cursor(&encode_cursor(at, id)).unwrap(), (at, id));
            }
        }
    }
}
