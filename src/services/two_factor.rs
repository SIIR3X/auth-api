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
    domain::{audit::AuditAction, two_factor::TwoFactorType},
    error::AppError,
    repositories::{
        audit::{self, NewAuditEntry},
        recovery_code,
        two_factor::{self as tf_repo, NewTwoFactorMethod},
        user as user_repo,
    },
    state::AppState,
    utils::{crypto, time, totp},
};

/// Max failed recovery code attempts per authenticated user within the window.
const MAX_RC_FAILURES_BY_USER: i64 = 5;
/// Sliding window for recovery code failure tracking (15 minutes).
const RC_FAILURE_WINDOW_SECS: u64 = 900;
/// Minimum delay between two recovery code regenerations (24 hours).
const RC_REGEN_COOLDOWN_SECS: u64 = 86_400;

use super::reauth as reauth_svc;

pub struct TotpSetupResult {
    pub method_id: Uuid,
    pub base32_secret: String,
    pub qr_uri: String,
}

/// Creates an unverified TOTP method for the user and returns setup data.
/// The user must call `verify_setup` with a valid code to activate it.
pub async fn setup_totp(state: &AppState, user_id: Uuid) -> Result<TotpSetupResult, AppError> {
    let enc_key = crypto::decode_encryption_key(&state.config.crypto.encryption_key)
        .map_err(|e| AppError::Internal(e.into()))?;

    let base32_secret = totp::generate_secret();
    let qr_uri = totp::qr_uri(&base32_secret, "", &state.config.crypto.totp_issuer);
    let encrypted =
        crypto::encrypt(&base32_secret, &enc_key).map_err(|e| AppError::Internal(e.into()))?;

    let method = tf_repo::create(
        &state.db,
        &NewTwoFactorMethod {
            user_id,
            method_type: TwoFactorType::Totp,
            totp_secret: Some(&encrypted),
            webauthn_credential_id: None,
            webauthn_public_key: None,
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

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
    let method = tf_repo::find_by_user(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .into_iter()
        .find(|m| m.id == method_id)
        .ok_or(AppError::NotFound)?;

    if method.is_verified {
        return Err(AppError::Conflict("already_verified"));
    }

    let enc_key = crypto::decode_encryption_key(&state.config.crypto.encryption_key)
        .map_err(|e| AppError::Internal(e.into()))?;

    let encrypted_secret = method.totp_secret.as_deref().ok_or(AppError::NotFound)?;
    let valid = totp::verify_code(
        encrypted_secret,
        code,
        &enc_key,
        state.config.crypto.totp_skew,
    )
    .map_err(|e| AppError::Internal(e.into()))?;

    if !valid {
        return Err(AppError::TwoFactorFailed);
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

/// Validates and consumes a recovery code in lieu of a TOTP code.
pub async fn use_recovery_code(
    state: &AppState,
    user_id: Uuid,
    code: &str,
) -> Result<(), AppError> {
    let fail_key = format!("rc_fail_user:{}", user_id);

    // Check failure budget before doing any DB work.
    if let Ok(mut conn) = state.redis.get().await {
        let failures: i64 = conn.get(&fail_key).await.unwrap_or(0);
        if failures >= MAX_RC_FAILURES_BY_USER {
            return Err(AppError::RateLimitExceeded);
        }
    }

    let hash = crypto::sha256(code.as_bytes());

    let record = recovery_code::find_by_hash(&state.db, &hash)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    let record = match record {
        Some(r) if r.user_id == user_id => r,
        _ => {
            if let Ok(mut conn) = state.redis.get().await {
                let _: Result<(), _> = conn.incr(&fail_key, 1i64).await;
                let _: Result<(), _> = conn.expire(&fail_key, RC_FAILURE_WINDOW_SECS as i64).await;
            }
            return Err(AppError::TwoFactorFailed);
        }
    };

    // Reject expired codes
    if let Some(exp) = record.expires_at
        && exp < time::now()
    {
        return Err(AppError::TokenExpired);
    }

    let consumed = recovery_code::consume(&state.db, record.id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    if !consumed {
        if let Ok(mut conn) = state.redis.get().await {
            let _: Result<(), _> = conn.incr(&fail_key, 1i64).await;
            let _: Result<(), _> = conn.expire(&fail_key, RC_FAILURE_WINDOW_SECS as i64).await;
        }
        return Err(AppError::TwoFactorFailed);
    }

    // Reset failure counter on success.
    if let Ok(mut conn) = state.redis.get().await {
        let _: Result<(), _> = conn.del(&fail_key).await;
    }

    Ok(())
}

/// Disables TOTP and removes recovery codes. Requires the user's current password.
pub async fn disable_totp(
    state: &AppState,
    user_id: Uuid,
    current_session_id: Uuid,
    method_id: Uuid,
    current_password: Option<&str>,
    ip: Option<IpNetwork>,
    request_id: Option<Uuid>,
) -> Result<(), AppError> {
    reauth_svc::require_recent_reauth_or_password(
        state,
        user_id,
        current_session_id,
        current_password,
        ip,
        request_id,
        "disable_totp",
    )
    .await?;

    let user = user_repo::find_by_id(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::NotFound)?;

    tf_repo::delete(&state.db, method_id, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    // Remove recovery codes since they are tied to TOTP
    recovery_code::delete_all_by_user(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user_id),
            request_id,
            action: AuditAction::TwoFactorDisabled,
            ip_address: ip,
            metadata: json!({"method": "totp"}),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    let mailer = state.mailer.clone();
    let templates = state.templates.clone();
    let mail_cfg = state.config.mail.clone();
    let email_to = user.email.clone();
    let username = user.username.clone();
    let locale = user.preferred_locale.clone();
    super::email::dispatch_best_effort("totp_disabled_email", async move {
        super::email::send_two_factor_disabled(
            &mailer,
            templates.as_ref(),
            &mail_cfg,
            &email_to,
            &username,
            &locale,
            "totp",
        )
        .await
    });

    Ok(())
}
