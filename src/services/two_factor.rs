//! TOTP setup, verification, and recovery code management.
//!
//! Flow for enabling TOTP:
//!   1. setup_totp      -- generates a secret and stores it unverified in the DB
//!   2. verify_setup    -- user submits the first code and receives recovery codes after verification
//!
//! The TOTP secret is encrypted with AES-256-GCM before storage.
//! Recovery codes are hashed with SHA-256; the plaintext is returned once and never stored.

use ipnetwork::IpNetwork;
use serde_json::json;
use uuid::Uuid;

use deadpool_redis::redis::AsyncCommands;

use crate::{
    domain::{
        audit::AuditAction,
        two_factor::{TwoFactorMethod, TwoFactorType},
    },
    error::AppError,
    repositories::{
        audit::{self, NewAuditEntry},
        recovery_code,
        two_factor::{self as tf_repo, NewTwoFactorMethod},
        user as user_repo,
    },
    state::AppState,
    utils::{
        crypto,
        redis_counter::{self, Budget},
        time, totp,
    },
};

/// Max failed recovery code attempts per authenticated user within the window.
const MAX_RC_FAILURES_BY_USER: i64 = 5;
/// Sliding window for recovery code failure tracking (15 minutes).
const RC_FAILURE_WINDOW_SECS: u64 = 900;
/// Minimum delay between two recovery code regenerations (24 hours).
const RC_REGEN_COOLDOWN_SECS: u64 = 86_400;
/// Redis key prefix for consumed TOTP codes during setup (prevents code reuse within the window).
const TOTP_SETUP_USED_PREFIX: &str = "totp_setup_used:";

use super::reauth as reauth_svc;

/// Notify the account owner that a second factor was enabled or disabled.
/// Best-effort: the change itself has already been committed.
pub(crate) fn notify_two_factor_change(
    state: &AppState,
    user: &crate::domain::user::User,
    method: &'static str,
    enabled: bool,
) {
    let mailer = state.mailer.clone();
    let templates = state.templates.clone();
    let mail_cfg = state.config.mail.clone();
    let email_to = user.email.clone();
    let username = user.username.clone();
    let locale = user.preferred_locale.clone();
    let label = if enabled {
        "two_factor_enabled_email"
    } else {
        "two_factor_disabled_email"
    };
    super::email::dispatch_best_effort(label, async move {
        if enabled {
            super::email::send_two_factor_enabled(
                &mailer,
                templates.as_ref(),
                &mail_cfg,
                &email_to,
                &username,
                &locale,
                method,
            )
            .await
        } else {
            super::email::send_two_factor_disabled(
                &mailer,
                templates.as_ref(),
                &mail_cfg,
                &email_to,
                &username,
                &locale,
                method,
            )
            .await
        }
    });
}

/// Create a method, or restart the user's abandoned enrolment of that type.
/// A second enrolment of an already verified method answers 409.
pub(crate) async fn create_or_restart_method(
    state: &AppState,
    input: &NewTwoFactorMethod<'_>,
) -> Result<crate::domain::two_factor::TwoFactorMethod, AppError> {
    if let Some(resumed) = tf_repo::replace_pending(&state.db, input)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
    {
        return Ok(resumed);
    }
    tf_repo::create(&state.db, input).await.map_err(|e| {
        AppError::from_unique_violation(
            e,
            &[
                ("idx_2fa_user_totp", "two_factor_already_enabled"),
                ("idx_2fa_user_email", "two_factor_already_enabled"),
            ],
        )
    })
}

pub struct TotpSetupResult {
    pub method_id: Uuid,
    pub base32_secret: String,
    pub qr_uri: String,
}

/// Creates (or restarts) an unverified TOTP method and returns setup data.
/// Requires a recent re-authentication or the current password: with a stolen
/// access token alone, an attacker could otherwise enrol their own
/// authenticator and lock the owner out.
pub async fn setup_totp(
    state: &AppState,
    user_id: Uuid,
    current_session_id: Uuid,
    current_password: Option<&str>,
    ip: Option<IpNetwork>,
    request_id: Option<Uuid>,
) -> Result<TotpSetupResult, AppError> {
    reauth_svc::require_recent_reauth_or_password(
        state,
        user_id,
        current_session_id,
        current_password,
        ip,
        request_id,
        "setup_totp",
    )
    .await?;

    let user = user_repo::find_by_id(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::NotFound)?;

    let base32_secret = totp::generate_secret();
    let qr_uri = totp::qr_uri(
        &base32_secret,
        &user.email,
        &state.config.crypto.totp_issuer,
    );
    let encrypted = state
        .keyring
        .encrypt(&base32_secret)
        .map_err(|e| AppError::Internal(e.into()))?;

    let method = create_or_restart_method(
        state,
        &NewTwoFactorMethod {
            user_id,
            method_type: TwoFactorType::Totp,
            totp_secret: Some(&encrypted),
        },
    )
    .await?;

    Ok(TotpSetupResult {
        method_id: method.id,
        base32_secret,
        qr_uri,
    })
}

/// Verifies the first TOTP code to confirm the user scanned the QR correctly.
/// On success: marks the method verified, sets it as primary if it is the first,
/// generates recovery codes, and returns their plaintext (shown once).
pub async fn verify_setup(
    state: &AppState,
    user_id: Uuid,
    method_id: Uuid,
    code: &str,
    request_id: Option<Uuid>,
) -> Result<Vec<String>, AppError> {
    let method = tf_repo::find_by_id_and_user(&state.db, method_id, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::NotFound)?;

    if method.is_verified {
        return Err(AppError::Conflict("already_verified"));
    }

    let encrypted_secret = method.totp_secret.as_deref().ok_or(AppError::NotFound)?;
    let valid = totp::verify_code(
        encrypted_secret,
        code,
        &state.keyring,
        state.config.crypto.totp_skew,
    )
    .map_err(|e| AppError::Internal(e.into()))?;

    if !valid {
        return Err(AppError::TwoFactorFailed);
    }

    // Reject if this exact code was already consumed in the current TOTP window.
    // Prevents replay attacks during the setup verification step.
    let used_key = format!("{}{}:{}", TOTP_SETUP_USED_PREFIX, user_id, code);
    if let Ok(mut conn) = state.redis.get().await {
        let already_used: bool = conn.exists(&used_key).await.unwrap_or(false);
        if already_used {
            return Err(AppError::TwoFactorFailed);
        }
        let _: Result<(), _> = conn.set_ex(&used_key, 1u8, 60u64).await;
    }

    tf_repo::mark_verified(&state.db, method_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    // Make it primary if the user has no other primary method yet
    let has_primary = tf_repo::find_primary_by_user(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .is_some();

    if !has_primary {
        tf_repo::set_primary(&state.db, method_id, user_id)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
    }

    let plaintext_codes = create_recovery_codes(state, user_id).await?;

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user_id),
            request_id,
            action: AuditAction::TwoFactorEnabled,
            ip_address: None,
            metadata: json!({"method": "totp"}),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    if let Ok(Some(user)) = user_repo::find_by_id(&state.db, user_id).await {
        notify_two_factor_change(state, &user, "totp", true);
    }

    Ok(plaintext_codes)
}

/// Generates a fresh set of recovery codes, replacing any existing ones.
/// Requires the user's current password as confirmation.
/// Enforces a 24-hour cooldown between regenerations to prevent invalidating
/// the legitimate user's codes.
pub async fn generate_recovery_codes(
    state: &AppState,
    user_id: Uuid,
    current_session_id: Uuid,
    current_password: Option<&str>,
    ip: Option<IpNetwork>,
    request_id: Option<Uuid>,
) -> Result<Vec<String>, AppError> {
    reauth_svc::require_recent_reauth_or_password(
        state,
        user_id,
        current_session_id,
        current_password,
        ip,
        request_id,
        "regenerate_recovery_codes",
    )
    .await?;

    let cooldown_key = format!("rc_regen:{}", user_id);
    if let Ok(mut conn) = state.redis.get().await {
        let locked: bool = conn.exists(&cooldown_key).await.unwrap_or(false);
        if locked {
            return Err(AppError::RateLimitExceeded);
        }
    }

    let codes = create_recovery_codes(state, user_id).await?;

    // Set cooldown after successful regeneration.
    if let Ok(mut conn) = state.redis.get().await {
        let _: Result<(), _> = conn
            .set_ex(&cooldown_key, 1u8, RC_REGEN_COOLDOWN_SECS)
            .await;
    }

    Ok(codes)
}

// Internal version used by verify_setup; no password check needed at that point.
// Also called from email_2fa service on first Email 2FA activation.
pub async fn create_recovery_codes_internal(
    state: &AppState,
    user_id: Uuid,
) -> Result<Vec<String>, AppError> {
    create_recovery_codes(state, user_id).await
}

async fn create_recovery_codes(state: &AppState, user_id: Uuid) -> Result<Vec<String>, AppError> {
    let plaintext = crypto::generate_recovery_codes(10);

    // Hash each code before storage; position is 1-based
    let hashed: Vec<(i16, Vec<u8>)> = plaintext
        .iter()
        .enumerate()
        .map(|(i, code)| {
            let hash = crypto::sha256(code.as_bytes()).to_vec();
            ((i + 1) as i16, hash)
        })
        .collect();

    let refs: Vec<(i16, &[u8])> = hashed.iter().map(|(pos, h)| (*pos, h.as_slice())).collect();

    let expires_at = match state.config.crypto.recovery_code_expiry_days {
        0 => None,
        days => Some(time::in_secs(days as u64 * 86400)),
    };

    recovery_code::replace_all_by_user(&state.db, user_id, &refs, expires_at)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    Ok(plaintext)
}

/// Validates and consumes a recovery code submitted by an already-authenticated user.
/// Records the event in the audit log; returns an error if the code is invalid, already
/// used, expired, or if the failure budget has been exhausted.
pub async fn use_recovery_code(
    state: &AppState,
    user_id: Uuid,
    code: &str,
    request_id: Option<Uuid>,
) -> Result<(), AppError> {
    let fail_key = format!("rc_fail_user:{}", user_id);

    let attempt = redis_counter::consume(
        &state.redis,
        &[Budget {
            key: &fail_key,
            limit: MAX_RC_FAILURES_BY_USER,
            window_secs: RC_FAILURE_WINDOW_SECS,
        }],
    )
    .await?;
    if attempt.exceeded {
        return Err(AppError::RateLimitExceeded);
    }

    // `find_by_hash` refuses used and expired codes; `consume` re-checks both.
    let hash = crypto::sha256(code.as_bytes());
    let record = recovery_code::find_by_hash(&state.db, &hash)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .filter(|r| r.user_id == user_id);

    let consumed = match record {
        Some(record) => recovery_code::consume(&state.db, record.id)
            .await
            .map_err(|e| AppError::Internal(e.into()))?,
        None => false,
    };
    if !consumed {
        return Err(AppError::TwoFactorFailed);
    }

    redis_counter::reset(&state.redis, &[&fail_key]).await;

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user_id),
            request_id,
            action: AuditAction::RecoveryCodeUsed,
            ip_address: None,
            metadata: json!({}),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    Ok(())
}

/// Disables the TOTP method. Requires a recent re-authentication or the current
/// password. The remaining verified method, if any, becomes primary; recovery
/// codes are removed only with the last method.
pub async fn disable_totp(
    state: &AppState,
    user_id: Uuid,
    current_session_id: Uuid,
    method_id: Uuid,
    current_password: Option<&str>,
    ip: Option<IpNetwork>,
    request_id: Option<Uuid>,
) -> Result<(), AppError> {
    disable_method(
        state,
        user_id,
        current_session_id,
        method_id,
        TwoFactorType::Totp,
        current_password,
        ip,
        request_id,
    )
    .await
}

/// Shared removal path for every second-factor type.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn disable_method(
    state: &AppState,
    user_id: Uuid,
    current_session_id: Uuid,
    method_id: Uuid,
    method_type: TwoFactorType,
    current_password: Option<&str>,
    ip: Option<IpNetwork>,
    request_id: Option<Uuid>,
) -> Result<(), AppError> {
    let label = match method_type {
        TwoFactorType::Totp => "totp",
        TwoFactorType::Email => "email",
    };

    reauth_svc::require_recent_reauth_or_password(
        state,
        user_id,
        current_session_id,
        current_password,
        ip,
        request_id,
        if method_type == TwoFactorType::Totp {
            "disable_totp"
        } else {
            "disable_email_2fa"
        },
    )
    .await?;

    let user = user_repo::find_by_id(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::NotFound)?;

    let removed = tf_repo::remove_method(&state.db, method_id, user_id, method_type)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::NotFound)?;

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user_id),
            request_id,
            action: AuditAction::TwoFactorDisabled,
            ip_address: ip,
            metadata: json!({
                "method": label,
                "was_primary": removed.was_primary,
                "remaining_verified": removed.remaining_verified,
            }),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    notify_two_factor_change(state, &user, label, false);
    Ok(())
}

/// The account's second factors, and how many recovery codes remain spendable.
pub async fn list_methods(
    state: &AppState,
    user_id: Uuid,
) -> Result<(Vec<TwoFactorMethod>, i64), AppError> {
    tokio::try_join!(
        tf_repo::find_by_user(&state.db, user_id),
        recovery_code::count_usable_by_user(&state.db, user_id),
    )
    .map_err(|e| AppError::Internal(e.into()))
}
