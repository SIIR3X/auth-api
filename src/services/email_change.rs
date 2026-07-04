//! Email change flow: two-step OTP verification (current email then new email).
//!
//! State machine stored in Redis, keyed by a short-lived flow_token.
//!
//! Steps:
//!   1. start          - sends OTP to the current email, returns a flow_token
//!   2. verify_current - verifies the OTP for the current email
//!   3. submit_new     - accepts the new address, sends OTP to it
//!   4. confirm_new    - verifies the OTP for the new email and commits the change
//!
//! The account remains active and its email is marked verified immediately after
//! confirm_new succeeds - no separate verification link is required because
//! ownership of the new address was already proven via OTP.

use base64::Engine;
use deadpool_redis::redis::AsyncCommands;
use ipnetwork::IpNetwork;
use rand::RngExt;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::{
    domain::audit::AuditAction,
    error::AppError,
    repositories::{
        audit::{self, NewAuditEntry},
        session as session_repo, user as user_repo,
    },
    state::AppState,
    utils::crypto,
};

use super::{auth as auth_svc, email as email_svc, events};

const FLOW_TTL_SECS: u64 = 60 * 15; // 15-minute window for the entire flow
const MAX_OTP_FAILURES: i64 = 5;
const BACKOFF_BASE_SECS: u64 = 1;
const BACKOFF_MAX_SECS: u64 = 16;

/// Per-user cooldown between two completed email changes (prevents mailbox spam).
const CHANGE_COOLDOWN_SECS: u64 = 300;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum FlowStep {
    /// OTP sent to the current email; waiting for the user to confirm it.
    CurrentVerify,
    /// Current email confirmed; waiting for the user to submit a new address.
    NewSubmit,
    /// OTP sent to the new email; waiting for the user to confirm it.
    NewVerify,
}

#[derive(Debug, Serialize, Deserialize)]
struct FlowState {
    user_id: Uuid,
    step: FlowStep,
    /// Base64url-encoded SHA-256 of the OTP (present in CurrentVerify / NewVerify).
    otp_hash: Option<String>,
    /// New address chosen by the user (present only in NewVerify).
    new_email: Option<String>,
}

// Public API

/// Starts the email-change flow. Sends a 6-digit OTP to the user's current email
/// and returns a flow_token that must be passed to each subsequent step.
///
/// Requires the current email to already be verified.
/// Cancels any in-progress flow for the same user to prevent accumulation.
pub async fn start(
    state: &AppState,
    user_id: Uuid,
    ip: Option<IpNetwork>,
    request_id: Option<Uuid>,
) -> Result<String, AppError> {
    // Block if a change was completed recently.
    let cooldown_key = format!("email_change_cd:{}", user_id);
    {
        let mut conn = state
            .redis
            .get()
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        let active: bool = conn.exists(&cooldown_key).await.unwrap_or(false);
        if active {
            return Err(AppError::RateLimitExceeded);
        }
    }

    // Cancel any existing in-progress flow for this user.
    let active_key = format!("email_change_active:{}", user_id);
    if let Ok(mut conn) = state.redis.get().await {
        let old: Option<String> = conn.get(&active_key).await.unwrap_or(None);
        if let Some(old_token) = old {
            let _: Result<(), _> = conn.del(format!("email_change_flow:{}", old_token)).await;
            let _: Result<(), _> = conn.del(format!("email_change_fail:{}", old_token)).await;
        }
    }

    let user = user_repo::find_by_id(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::NotFound)?;

    if user.email_verified_at.is_none() {
        return Err(AppError::EmailNotVerified);
    }

    let flow_token = crypto::generate_token();
    let otp = generate_otp();
    let otp_hash = hash_otp(&otp);

    let flow = FlowState {
        user_id,
        step: FlowStep::CurrentVerify,
        otp_hash: Some(otp_hash),
        new_email: None,
    };
    save_flow(state, &flow_token, &flow).await?;

    // Record the active flow token so a second call can cancel the first.
    if let Ok(mut conn) = state.redis.get().await {
        let _: Result<(), _> = conn.set_ex(&active_key, &flow_token, FLOW_TTL_SECS).await;
    }

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user_id),
            request_id,
            action: AuditAction::EmailVerificationSent,
            ip_address: ip,
            metadata: json!({"reason": "email_change_start"}),
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
    email_svc::dispatch_best_effort("email_change_otp_current", async move {
        email_svc::send_email_change_otp(
            &mailer,
            templates.as_ref(),
            &mail_cfg,
            &email_to,
            &username,
            &locale,
            &otp,
        )
        .await
    });

    Ok(flow_token)
}

/// Verifies the OTP sent to the user's current email.
/// On success, transitions the flow to the NewSubmit step.
pub async fn verify_current(
    state: &AppState,
    user_id: Uuid,
    flow_token: &str,
    submitted_code: &str,
) -> Result<(), AppError> {
    let mut flow = load_flow(state, flow_token, user_id).await?;

    if flow.step != FlowStep::CurrentVerify {
        return Err(AppError::Unauthorized);
    }

    let fail_key = format!("email_change_fail:{}", flow_token);
    verify_otp(state, submitted_code, flow.otp_hash.as_deref(), &fail_key).await?;

    flow.step = FlowStep::NewSubmit;
    flow.otp_hash = None;
    save_flow(state, flow_token, &flow).await?;

    Ok(())
}

/// Records the new email address and sends an OTP to it.
/// Validates uniqueness before sending to give a clear error without wasting an OTP.
pub async fn submit_new(
    state: &AppState,
    user_id: Uuid,
    flow_token: &str,
    new_email: &str,
    ip: Option<IpNetwork>,
    request_id: Option<Uuid>,
) -> Result<(), AppError> {
    let mut flow = load_flow(state, flow_token, user_id).await?;

    if flow.step != FlowStep::NewSubmit {
        return Err(AppError::Unauthorized);
    }

    let taken: Option<(i32,)> =
        sqlx::query_as("SELECT 1 FROM users WHERE email = $1 AND id <> $2 LIMIT 1")
            .bind(new_email)
            .bind(user_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;

    if taken.is_some() {
        return Err(AppError::Conflict("email_taken"));
    }

    let otp = generate_otp();
    let otp_hash = hash_otp(&otp);

    flow.step = FlowStep::NewVerify;
    flow.otp_hash = Some(otp_hash);
    flow.new_email = Some(new_email.to_string());
    save_flow(state, flow_token, &flow).await?;

    let user = user_repo::find_by_id(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::NotFound)?;

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user_id),
            request_id,
            action: AuditAction::EmailVerificationSent,
            ip_address: ip,
            metadata: json!({"reason": "email_change_new", "target_email": new_email}),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    let mailer = state.mailer.clone();
    let templates = state.templates.clone();
    let mail_cfg = state.config.mail.clone();
    let email_to = new_email.to_string();
    let username = user.username.clone();
    let locale = user.preferred_locale.clone();
    email_svc::dispatch_best_effort("email_change_otp_new", async move {
        email_svc::send_email_change_otp(
            &mailer,
            templates.as_ref(),
            &mail_cfg,
            &email_to,
            &username,
            &locale,
            &otp,
        )
        .await
    });

    Ok(())
}

/// Verifies the OTP sent to the new email and commits the change.
///
/// After this call:
/// - the user's email is updated to the new address
/// - email_verified_at is set (ownership proven via OTP - no extra link needed)
/// - all other sessions are revoked
/// - the flow token is consumed and a cooldown is armed
pub async fn confirm_new(
    state: &AppState,
    user_id: Uuid,
    current_session_id: Uuid,
    flow_token: &str,
    submitted_code: &str,
    ip: Option<IpNetwork>,
    request_id: Option<Uuid>,
) -> Result<(), AppError> {
    let flow = load_flow(state, flow_token, user_id).await?;

    if flow.step != FlowStep::NewVerify {
        return Err(AppError::Unauthorized);
    }

    let new_email = flow.new_email.as_deref().ok_or(AppError::Unauthorized)?;

    let fail_key = format!("email_change_fail:{}", flow_token);
    verify_otp(state, submitted_code, flow.otp_hash.as_deref(), &fail_key).await?;

    let old_email = user_repo::find_by_id(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .map(|u| u.email)
        .unwrap_or_default();

    let other_session_ids = session_repo::find_active_by_user(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .into_iter()
        .filter(|s| s.id != current_session_id)
        .map(|s| s.id)
        .collect::<Vec<_>>();

    {
        let mut tx = state
            .db
            .begin()
            .await
            .map_err(|e| AppError::Internal(e.into()))?;

        // Re-check uniqueness inside the transaction.
        let taken: Option<(i32,)> =
            sqlx::query_as("SELECT 1 FROM users WHERE email = $1 AND id <> $2 LIMIT 1")
                .bind(new_email)
                .bind(user_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| AppError::Internal(e.into()))?;

        if taken.is_some() {
            return Err(AppError::Conflict("email_taken"));
        }

        sqlx::query(
            "UPDATE email_verification_tokens
             SET used_at = NOW()
             WHERE user_id = $1 AND used_at IS NULL",
        )
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

        // Ownership of the new address is proven via OTP, so the account stays
        // active and email_verified_at is set immediately.
        sqlx::query(
            "UPDATE users
             SET email = $2,
                 email_verified_at = NOW(),
                 status = 'active'::user_status
             WHERE id = $1",
        )
        .bind(user_id)
        .bind(new_email)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

        sqlx::query(
            "UPDATE sessions
             SET revoked_at = NOW()
             WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL",
        )
        .bind(user_id)
        .bind(current_session_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

        sqlx::query(
            "INSERT INTO audit_log (user_id, request_id, action, ip_address, metadata)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(Some(user_id))
        .bind(request_id)
        .bind(AuditAction::EmailChanged)
        .bind(ip)
        .bind(json!({"new_email": new_email}))
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

        tx.commit()
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
    }

    auth_svc::invalidate_session_caches(state, &other_session_ids).await;

    events::publish(
        state,
        "user.email_changed",
        &events::UserEmailChanged {
            user_id,
            old_email: old_email.clone(),
            new_email: new_email.to_string(),
        },
    )
    .await;

    // Clean up all Redis keys for this flow and arm the cooldown.
    if let Ok(mut conn) = state.redis.get().await {
        let _: Result<(), _> = conn
            .del(vec![
                format!("email_change_flow:{flow_token}"),
                format!("email_change_fail:{flow_token}"),
                format!("email_change_active:{user_id}"),
            ])
            .await;
        let _: Result<(), _> = conn
            .set_ex(
                format!("email_change_cd:{user_id}"),
                1u8,
                CHANGE_COOLDOWN_SECS,
            )
            .await;
    }

    Ok(())
}

// Internal helpers

async fn save_flow(state: &AppState, flow_token: &str, flow: &FlowState) -> Result<(), AppError> {
    let key = format!("email_change_flow:{}", flow_token);
    let val = serde_json::to_string(flow).map_err(|e| AppError::Internal(e.into()))?;

    let mut conn = state
        .redis
        .get()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    conn.set_ex::<_, _, ()>(&key, val, FLOW_TTL_SECS)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    Ok(())
}

async fn load_flow(
    state: &AppState,
    flow_token: &str,
    user_id: Uuid,
) -> Result<FlowState, AppError> {
    let key = format!("email_change_flow:{}", flow_token);

    let mut conn = state
        .redis
        .get()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    let raw: Option<String> = conn.get(&key).await.unwrap_or(None);
    let raw = raw.ok_or(AppError::Unauthorized)?;

    let flow: FlowState = serde_json::from_str(&raw).map_err(|e| AppError::Internal(e.into()))?;

    // Bind the flow to the authenticated user to prevent token substitution.
    if flow.user_id != user_id {
        return Err(AppError::Unauthorized);
    }

    Ok(flow)
}

async fn verify_otp(
    state: &AppState,
    submitted_code: &str,
    expected_hash: Option<&str>,
    fail_key: &str,
) -> Result<(), AppError> {
    let failures: i64 = if let Ok(mut conn) = state.redis.get().await {
        conn.get(fail_key).await.unwrap_or(0)
    } else {
        0
    };
    if failures >= MAX_OTP_FAILURES {
        return Err(AppError::RateLimitExceeded);
    }

    let expected = expected_hash.ok_or(AppError::Unauthorized)?;
    let actual = hash_otp(submitted_code);

    if actual != expected {
        let n = increment_fail(state, fail_key, FLOW_TTL_SECS).await;
        apply_backoff(n).await;
        return Err(AppError::TwoFactorFailed);
    }

    if let Ok(mut conn) = state.redis.get().await {
        let _: Result<(), _> = conn.del(fail_key).await;
    }

    Ok(())
}

/// Returns the base64url-encoded SHA-256 of an OTP plaintext.
fn hash_otp(code: &str) -> String {
    let hash = crypto::sha256(code.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
}

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

/// Generates a 6-digit numeric OTP (000000..999999).
/// Security relies on the 5-attempt budget, exponential backoff, and 15-minute TTL
/// rather than on entropy alone - matching the Email 2FA approach.
fn generate_otp() -> String {
    let code: u32 = rand::rng().random_range(0..1_000_000);
    format!("{:06}", code)
}
