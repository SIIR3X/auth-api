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

use ipnetwork::IpNetwork;
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
    utils::{
        backoff, crypto,
        redis_counter::{self, Budget},
    },
};

use super::{email as email_svc, reauth as reauth_svc};

// OTP lifetime: 10 minutes
const OTP_EXPIRY_SECS: u64 = 600;
// Minimum delay between two sends per user (60 seconds anti-spam)
const SEND_COOLDOWN_SECS: u64 = 60;
// Max failed verification attempts per pre_auth_token (or per setup method).
// Kept low (3) because a 6-digit OTP has only ~20 bits of entropy.
const MAX_FAILURES: i64 = 3;
// Max failed verification attempts per account per window, across every token.
const MAX_FAILURES_BY_USER: i64 = 10;
// Window of the per-account budget (1 hour).
const USER_FAILURE_WINDOW_SECS: u64 = 3600;

// Setup (authenticated flow)

/// Creates (or restarts) an unverified Email 2FA method for the user.
/// Requires a recent re-authentication or the current password.
pub async fn setup(
    state: &AppState,
    user_id: Uuid,
    current_session_id: Uuid,
    current_password: Option<&str>,
    ip: Option<IpNetwork>,
    request_id: Option<Uuid>,
) -> Result<Uuid, AppError> {
    reauth_svc::require_recent_reauth_or_password(
        state,
        user_id,
        current_session_id,
        current_password,
        ip,
        request_id,
        "setup_email_2fa",
    )
    .await?;

    let method = super::two_factor::create_or_restart_method(
        state,
        &NewTwoFactorMethod {
            user_id,
            method_type: TwoFactorType::Email,
            totp_secret: None,
        },
    )
    .await?;

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
    let method = tf_repo::find_by_id_and_user(&state.db, method_id, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::NotFound)?;

    if method.is_verified {
        return Err(AppError::Conflict("already_verified"));
    }

    verify_otp(
        state,
        user_id,
        submitted_code,
        &format!("email2fa_setup_fail:{}", method_id),
        None,
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

    if let Ok(Some(user)) = user_repo::find_by_id(&state.db, user_id).await {
        super::two_factor::notify_two_factor_change(state, &user, "email", true);
    }

    Ok(codes)
}

/// Disables the Email 2FA method. Requires a recent re-authentication or the
/// current password; see `two_factor::disable_method`.
pub async fn disable(
    state: &AppState,
    user_id: Uuid,
    current_session_id: Uuid,
    method_id: Uuid,
    current_password: Option<&str>,
    ip: Option<IpNetwork>,
    request_id: Option<Uuid>,
) -> Result<(), AppError> {
    super::two_factor::disable_method(
        state,
        user_id,
        current_session_id,
        method_id,
        TwoFactorType::Email,
        current_password,
        ip,
        request_id,
    )
    .await
}

// Code dispatch (used both during setup and during login challenge)

/// Generates and sends a 6-digit OTP to the user's email.
/// Enforces a 60-second cooldown between sends.
pub async fn send_code(state: &AppState, user_id: Uuid) -> Result<(), AppError> {
    // Anti-spam cooldown, claimed before the send: concurrent requests cannot
    // all find it free and all send.
    let cooldown_key = format!("email2fa_cd:{}", user_id);
    if !redis_counter::claim_cooldown(&state.redis, &cooldown_key, SEND_COOLDOWN_SECS).await {
        return Err(AppError::RateLimitExceeded);
    }

    let user = user_repo::find_by_id(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::Unauthorized)?;

    let code = crypto::generate_otp();
    // A keyed digest: a copy of the table does not give live codes away.
    let hash = state
        .keyring
        .otp_digest(OTP_PURPOSE, user_id.as_bytes(), &code);

    email_2fa::create(
        &state.db,
        &email_2fa::NewEmail2faCode {
            user_id,
            code_hash: &hash,
            expires_at: state.clock.in_secs(OTP_EXPIRY_SECS),
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
    email_svc::dispatch_best_effort("email_2fa_code", async move {
        email_svc::send_email_otp(
            &mailer,
            templates.as_ref(),
            &mail_cfg,
            &email_to,
            &username,
            &locale,
            &code,
        )
        .await
    });

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
    ip: Option<IpNetwork>,
) -> Result<(), AppError> {
    let fail_key = format!("{}{pre_auth_token}", super::auth::EMAIL_2FA_FAIL_PREFIX);
    verify_otp(state, user_id, submitted_code, &fail_key, ip).await
}

/// Separates the digests of these codes from any other flow's.
const OTP_PURPOSE: &str = "email_2fa";

// Shared OTP verification logic

async fn verify_otp(
    state: &AppState,
    user_id: Uuid,
    submitted_code: &str,
    fail_key: &str,
    ip: Option<IpNetwork>,
) -> Result<(), AppError> {
    let account_keys = crate::services::auth::second_factor_budget_keys(
        crate::services::auth::EMAIL_2FA_USER_FAIL_PREFIX,
        user_id,
        ip,
        MAX_FAILURES_BY_USER,
    );

    // Reserve the attempt atomically before looking the code up.
    let mut budgets = vec![Budget {
        key: fail_key,
        limit: MAX_FAILURES,
        window_secs: OTP_EXPIRY_SECS,
    }];
    budgets.extend(account_keys.iter().map(|(key, limit)| Budget {
        key,
        limit: *limit,
        window_secs: USER_FAILURE_WINDOW_SECS,
    }));
    let attempt = redis_counter::consume(&state.redis, &budgets).await?;
    if attempt.exceeded {
        if crate::services::auth::account_budget_exceeded(&attempt.counts, account_keys[0].1) {
            crate::services::auth::notify_second_factor_pressure(state, user_id).await;
        }
        return Err(AppError::RateLimitExceeded);
    }

    let digests: Vec<Vec<u8>> = state
        .keyring
        .otp_digests(OTP_PURPOSE, user_id.as_bytes(), submitted_code)
        .iter()
        .map(|digest| digest.to_vec())
        .collect();
    let record = email_2fa::find_active_by_user_and_hash(&state.db, user_id, &digests)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    let consumed = match record {
        Some(record) => email_2fa::consume(&state.db, record.id)
            .await
            .map_err(|e| AppError::Internal(e.into()))?,
        None => false,
    };

    if !consumed {
        apply_backoff(attempt.counts[0]).await;
        return Err(AppError::TwoFactorFailed);
    }

    let mut reset: Vec<&str> = account_keys.iter().map(|(key, _)| key.as_str()).collect();
    reset.push(fail_key);
    redis_counter::reset(&state.redis, &reset).await;
    Ok(())
}

async fn apply_backoff(failures: i64) {
    backoff::apply(failures).await;
}

// OTP generation
