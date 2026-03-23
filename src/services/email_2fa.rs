//! Email-based 2FA service.
//!
//! Flow (2FA challenge during login, primary method = Email):
//!   1. send_code    -- generates a 6-digit OTP, stores its hash, sends it by email
//!   2. verify_code  -- hashes the submitted code, validates against DB, consumes it
//!
//! Flow (setup, authenticated user):
//!   1. setup        -- creates an unverified Email 2FA method for the user
//!   2. send_code    -- sends the first code so the user can confirm their email
//!   3. verify_setup -- validates the code, marks the method verified, primary if first

use deadpool_redis::redis::AsyncCommands;
use ipnetwork::IpNetwork;
use rand::RngExt;
use serde_json::json;
use uuid::Uuid;

use crate::{
    domain::{audit::AuditAction, two_factor::TwoFactorType},
    error::AppError,
    repositories::{
        audit::{self, NewAuditEntry},
        email_2fa,
        two_factor::{self as tf_repo, NewTwoFactorMethod},
        user as user_repo,
    },
    state::AppState,
    utils::{crypto, time},
};

use super::{email as email_svc, reauth as reauth_svc};

// OTP lifetime: 10 minutes
const OTP_EXPIRY_SECS: u64 = 600;
// Minimum delay between two sends per user (60 seconds anti-spam)
const SEND_COOLDOWN_SECS: u64 = 60;
// Max failed verification attempts per pre_auth_token
const MAX_FAILURES: i64 = 5;

// Setup (authenticated flow)

/// Creates an unverified Email 2FA method for the user.
/// The user must call send_code + verify_setup to activate it.
pub async fn setup(state: &AppState, user_id: Uuid) -> Result<Uuid, AppError> {
    let method = tf_repo::create(
        &state.db,
        &NewTwoFactorMethod {
            user_id,
            method_type: TwoFactorType::Email,
            totp_secret: None,
            webauthn_credential_id: None,
            webauthn_public_key: None,
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    Ok(method.id)
}

/// Verifies the OTP submitted during setup, marks the method verified.
/// Returns recovery codes on first activation.
pub async fn verify_setup(
    state: &AppState,
    user_id: Uuid,
    method_id: Uuid,
    submitted_code: &str,
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

    verify_otp(
        state,
        user_id,
        submitted_code,
        &format!("email2fa_setup_fail:{}", method_id),
    )
    .await?;

    tf_repo::mark_verified(&state.db, method_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    let has_primary = tf_repo::find_primary_by_user(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .is_some();

    if !has_primary {
        tf_repo::set_primary(&state.db, method_id, user_id)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
    }

    let codes = super::two_factor::create_recovery_codes_internal(state, user_id).await?;

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user_id),
            request_id,
            action: AuditAction::TwoFactorEnabled,
            ip_address: None,
            metadata: json!({"method": "email"}),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    Ok(codes)
}

/// Disables the Email 2FA method. Requires the user's current password.
pub async fn disable(
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
        "disable_email_2fa",
    )
    .await?;

    let user = user_repo::find_by_id(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::NotFound)?;

    tf_repo::delete(&state.db, method_id, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    crate::repositories::recovery_code::delete_all_by_user(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user_id),
            request_id,
            action: AuditAction::TwoFactorDisabled,
            ip_address: ip,
            metadata: json!({"method": "email"}),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    if let Err(e) = email_svc::send_two_factor_disabled(
        &state.mailer,
        &state.templates,
        &state.config.mail,
        &user.email,
        &user.username,
        &user.preferred_locale,
        "email",
    )
    .await
    {
        tracing::warn!(error = ?e, user_id = %user_id, "failed to send two_factor_disabled email");
    }

    Ok(())
}

// Code dispatch (used both during setup and during login challenge)

/// Generates and sends a 6-digit OTP to the user's email.
/// Enforces a 60-second cooldown between sends.
pub async fn send_code(state: &AppState, user_id: Uuid) -> Result<(), AppError> {
    // Anti-spam cooldown
    let cooldown_key = format!("email2fa_cd:{}", user_id);
    if let Ok(mut conn) = state.redis.get().await {
        let active: bool = conn.exists(&cooldown_key).await.unwrap_or(false);
        if active {
            return Err(AppError::RateLimitExceeded);
        }
    }

    let user = user_repo::find_by_id(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::Unauthorized)?;

    let code = generate_otp();
    let hash = crypto::sha256(code.as_bytes());

    email_2fa::create(
        &state.db,
        &email_2fa::NewEmail2faCode {
            user_id,
            code_hash: &hash,
            expires_at: time::in_secs(OTP_EXPIRY_SECS),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    // Set cooldown after successful DB write
    if let Ok(mut conn) = state.redis.get().await {
        let _: Result<(), _> = conn.set_ex(&cooldown_key, 1u8, SEND_COOLDOWN_SECS).await;
    }

    if let Err(e) = email_svc::send_email_otp(
        &state.mailer,
        &state.templates,
        &state.config.mail,
        &user.email,
        &user.username,
        &user.preferred_locale,
        &code,
    )
    .await
    {
        tracing::warn!(error = ?e, user_id = %user_id, "failed to send email 2FA code");
    }

    Ok(())
}

// Authentication (login 2FA challenge)

/// Verifies the OTP submitted during the login 2FA challenge.
/// The fail_key is scoped to the pre_auth_token to isolate attempts.
pub async fn verify_login_code(
    state: &AppState,
    user_id: Uuid,
    pre_auth_token: &str,
    submitted_code: &str,
) -> Result<(), AppError> {
    let fail_key = format!("email2fa_fail:{}", pre_auth_token);
    verify_otp(state, user_id, submitted_code, &fail_key).await
}

// Shared OTP verification logic

// Backoff constants (mirror those in auth.rs)
const BACKOFF_BASE_SECS: u64 = 1;
const BACKOFF_MAX_SECS: u64 = 16;

async fn verify_otp(
    state: &AppState,
    user_id: Uuid,
    submitted_code: &str,
    fail_key: &str,
) -> Result<(), AppError> {
    // Check failure budget
    let failures: i64 = if let Ok(mut conn) = state.redis.get().await {
        conn.get(fail_key).await.unwrap_or(0)
    } else {
        0
    };
    if failures >= MAX_FAILURES {
        return Err(AppError::RateLimitExceeded);
    }

    let hash = crypto::sha256(submitted_code.as_bytes());

    let record = email_2fa::find_by_hash(&state.db, &hash)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    let record = match record {
        Some(r) if r.user_id == user_id => r,
        _ => {
            let n = increment_fail(state, fail_key, OTP_EXPIRY_SECS).await;
            apply_backoff(n).await;
            return Err(AppError::TwoFactorFailed);
        }
    };

    if record.is_used() || record.is_expired() {
        let n = increment_fail(state, fail_key, OTP_EXPIRY_SECS).await;
        apply_backoff(n).await;
        return Err(AppError::TwoFactorFailed);
    }

    let consumed = email_2fa::consume(&state.db, record.id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    if !consumed {
        let n = increment_fail(state, fail_key, OTP_EXPIRY_SECS).await;
        apply_backoff(n).await;
        return Err(AppError::TwoFactorFailed);
    }

    // Reset failure counter on success
    if let Ok(mut conn) = state.redis.get().await {
        let _: Result<(), _> = conn.del(fail_key).await;
    }

    Ok(())
}

/// Increment the failure counter and return the new count.
async fn increment_fail(state: &AppState, key: &str, window_secs: u64) -> i64 {
    if let Ok(mut conn) = state.redis.get().await {
        let n: i64 = conn.incr(key, 1i64).await.unwrap_or(1);
        let _: Result<(), _> = conn.expire(key, window_secs as i64).await;
        n
    } else {
        1
    }
}

async fn apply_backoff(failures: i64) {
    if failures <= 0 {
        return;
    }
    let exp = (failures - 1).min(4) as u32;
    let secs = BACKOFF_BASE_SECS
        .saturating_mul(2u64.pow(exp))
        .min(BACKOFF_MAX_SECS);
    tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
}

// OTP generation

fn generate_otp() -> String {
    let code: u32 = rand::rng().random_range(0..1_000_000);
    format!("{:06}", code)
}
