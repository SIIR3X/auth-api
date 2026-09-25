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
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::{
    domain::{
        audit::AuditAction,
        email_change::{FlowEvent, FlowStep, Transition},
    },
    error::AppError,
    repositories::{
        audit::{self, NewAuditEntry},
        session as session_repo, token as token_repo, user as user_repo,
    },
    state::AppState,
    utils::{
        backoff, crypto,
        redis_counter::{self, Budget},
    },
};

use super::{auth as auth_svc, email as email_svc, events};

const FLOW_TTL_SECS: u64 = 60 * 15; // 15-minute window for the entire flow
const MAX_OTP_FAILURES: i64 = 5;
/// Wrong codes one account may submit per hour across its flows: starting a
/// new flow opens a fresh budget of `MAX_OTP_FAILURES`, not a fresh search.
const MAX_OTP_FAILURES_PER_ACCOUNT: i64 = MAX_OTP_FAILURES * 3;
const OTP_ACCOUNT_WINDOW_SECS: u64 = 3600;
/// A flow starts at most once a minute: each start mails the current address.
const START_COOLDOWN_SECS: u64 = 60;

/// Per-user cooldown between two completed email changes (prevents mailbox spam).
const CHANGE_COOLDOWN_SECS: u64 = 300;

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
    current_session_id: Uuid,
    current_password: Option<&str>,
    ip: Option<IpNetwork>,
    request_id: Option<Uuid>,
) -> Result<String, AppError> {
    super::reauth::require_recent_reauth_or_password(
        state,
        user_id,
        current_session_id,
        current_password,
        ip,
        request_id,
        "email_change_start",
    )
    .await?;

    // Each start mails a code: at most one a minute, refused when Redis
    // cannot tell.
    if !redis_counter::claim_cooldown_strict(
        &state.redis,
        &format!("email_change_start_cd:{user_id}"),
        START_COOLDOWN_SECS,
    )
    .await?
    {
        return Err(AppError::RateLimitExceeded);
    }

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
    let otp = crypto::generate_otp();
    let otp_hash = hash_otp(state, user_id, &otp);

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

    let Some(Transition::To(next)) = flow.step.after(FlowEvent::CurrentConfirmed) else {
        return Err(AppError::Unauthorized);
    };

    let fail_key = format!("email_change_fail:{}", flow_token);
    verify_otp(
        state,
        user_id,
        submitted_code,
        flow.otp_hash.as_deref(),
        &fail_key,
    )
    .await?;

    flow.step = next;
    flow.otp_hash = None;
    save_flow(state, flow_token, &flow).await?;

    Ok(())
}

/// Records the new email address and sends an OTP to it.
///
/// A taken address answers exactly like a free one, and the flow moves on the
/// same way, but no code is sent: the caller cannot read that mailbox, so the
/// answer reveals nothing, and its owner is not bothered. Submissions are
/// budgeted per account and per target address, so the route sends codes to
/// nobody in bulk.
pub async fn submit_new(
    state: &AppState,
    user_id: Uuid,
    flow_token: &str,
    new_email: &str,
    ip: Option<IpNetwork>,
    request_id: Option<Uuid>,
) -> Result<(), AppError> {
    let mut flow = load_flow(state, flow_token, user_id).await?;

    let Some(Transition::To(next)) = flow.step.after(FlowEvent::NewAddressSubmitted) else {
        return Err(AppError::Unauthorized);
    };

    let account_key = format!("ec_submit_account:{user_id}");
    let target_key = format!(
        "ec_submit_target:{}",
        crypto::sha256(new_email.to_ascii_lowercase().as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    match redis_counter::consume(
        &state.redis,
        &[
            Budget {
                key: &account_key,
                limit: MAX_SUBMISSIONS_PER_WINDOW,
                window_secs: SUBMISSION_WINDOW_SECS,
            },
            Budget {
                key: &target_key,
                limit: MAX_SUBMISSIONS_PER_WINDOW,
                window_secs: SUBMISSION_WINDOW_SECS,
            },
        ],
    )
    .await
    {
        Ok(attempt) if attempt.exceeded => return Err(AppError::RateLimitExceeded),
        Ok(_) => {}
        // The budget keeps codes from being mailed to anyone in bulk: without
        // it, nothing is sent.
        Err(error) => return Err(error),
    }

    let taken = user_repo::email_taken(&state.db, new_email, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    let otp = crypto::generate_otp();
    let otp_hash = hash_otp(state, user_id, &otp);

    flow.step = next;
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
            metadata: json!({"reason": "email_change_new"}),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    // Written whether a code leaves or not: the requester reads their own
    // history, and a missing entry would tell them the address has an account.
    if taken {
        return Ok(());
    }

    let mailer = state.mailer.clone();
    let templates = state.templates.clone();
    let mail_cfg = state.config.mail.clone();
    let email_to = new_email.to_string();
    let locale = user.preferred_locale.clone();
    email_svc::dispatch_best_effort("email_change_otp_new", async move {
        email_svc::send_email_change_new_otp(
            &mailer,
            templates.as_ref(),
            &mail_cfg,
            &email_to,
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

    if flow.step.after(FlowEvent::NewConfirmed) != Some(Transition::Done) {
        return Err(AppError::Unauthorized);
    }

    let new_email = flow.new_email.as_deref().ok_or(AppError::Unauthorized)?;

    let fail_key = format!("email_change_fail:{}", flow_token);
    verify_otp(
        state,
        user_id,
        submitted_code,
        flow.otp_hash.as_deref(),
        &fail_key,
    )
    .await?;

    let previous = user_repo::find_by_id(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::NotFound)?;

    let other_session_ids = session_repo::find_active_by_user(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .into_iter()
        .filter(|s| s.id != current_session_id)
        .map(|s| s.id)
        .collect::<Vec<_>>();

    {
        let mut tx = state.db.begin().await?;

        // Re-check uniqueness inside the transaction.
        if user_repo::email_taken(&mut *tx, new_email, user_id)
            .await
            .map_err(|e| AppError::Internal(e.into()))?
        {
            return Err(AppError::Conflict("email_taken"));
        }

        token_repo::revoke_active_verification_by_user(&mut *tx, user_id).await?;
        // Links already mailed to the previous address, possibly compromised,
        // stop opening the account.
        token_repo::revoke_mailbox_links(&mut tx, user_id).await?;

        // Ownership of the new address is proven via OTP, so it is verified at once.
        // Two accounts confirming the same address at once: the constraint
        // decides, and the loser hears the address is taken.
        user_repo::change_email(&mut *tx, user_id, new_email)
            .await
            .map_err(|e| {
                AppError::from_unique_violation(e, &[("users_email_key", "email_taken")])
            })?;

        session_repo::revoke_others(&mut *tx, user_id, current_session_id).await?;

        audit::append(
            &mut *tx,
            &NewAuditEntry {
                user_id: Some(user_id),
                request_id,
                action: AuditAction::EmailChanged,
                ip_address: ip,
                metadata: json!({}),
            },
        )
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

        events::enqueue(
            &mut *tx,
            "user.sessions_revoked",
            &events::UserSessionsRevoked { user_id },
        )
        .await?;
        events::enqueue(
            &mut *tx,
            "user.email_changed",
            &events::UserEmailChanged { user_id },
        )
        .await?;

        tx.commit().await?;
    }
    events::wake();

    auth_svc::invalidate_session_caches(state, &other_session_ids).await;

    // Challenges and flows opened before the change belong to the old identity.
    auth_svc::purge_user_pre_auth_and_email_change(state, user_id).await;
    notify_previous_address(state, &previous, new_email);

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

/// Warn the previous address that the account moved away from it: if the change
/// was not wanted, this message is the owner's only chance to notice.
fn notify_previous_address(
    state: &AppState,
    previous: &crate::domain::user::User,
    new_email: &str,
) {
    let mailer = state.mailer.clone();
    let templates = state.templates.clone();
    let mail_cfg = state.config.mail.clone();
    let email_to = previous.email.clone();
    let username = previous.username.clone();
    let locale = previous.preferred_locale.clone();
    let masked = email_svc::mask_email(new_email);
    email_svc::dispatch_best_effort("email_changed_notice", async move {
        email_svc::send_email_changed(
            &mailer,
            templates.as_ref(),
            &mail_cfg,
            &email_to,
            &username,
            &locale,
            &masked,
        )
        .await
    });
}

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
    user_id: Uuid,
    submitted_code: &str,
    expected_hash: Option<&str>,
    fail_key: &str,
) -> Result<(), AppError> {
    let expected = expected_hash.ok_or(AppError::Unauthorized)?;

    let account_key = format!("email_change_fail_user:{user_id}");
    let attempt = redis_counter::consume(
        &state.redis,
        &[
            Budget {
                key: fail_key,
                limit: MAX_OTP_FAILURES,
                window_secs: FLOW_TTL_SECS,
            },
            Budget {
                key: &account_key,
                limit: MAX_OTP_FAILURES_PER_ACCOUNT,
                window_secs: OTP_ACCOUNT_WINDOW_SECS,
            },
        ],
    )
    .await?;
    if attempt.exceeded {
        return Err(AppError::RateLimitExceeded);
    }

    // Compared in constant time, under every key the keyring holds: a code
    // issued just before a key rotation still verifies.
    let matches = state
        .keyring
        .otp_digests(OTP_PURPOSE, user_id.as_bytes(), submitted_code)
        .iter()
        .any(|digest| {
            crypto::constant_time_eq(encode_digest(digest).as_bytes(), expected.as_bytes())
        });
    if !matches {
        backoff::apply(attempt.counts[0]).await;
        return Err(AppError::TwoFactorFailed);
    }

    redis_counter::reset(&state.redis, &[fail_key, &account_key]).await;
    Ok(())
}

/// New addresses one account may submit per window, and submissions one address
/// may receive: codes are not sent to anyone in bulk.
const MAX_SUBMISSIONS_PER_WINDOW: i64 = 3;
const SUBMISSION_WINDOW_SECS: u64 = 3600;

/// Separates the digests of this flow's codes from any other flow's.
const OTP_PURPOSE: &str = "email_change";

/// The keyed digest of a code of `user_id`'s flow, base64url-encoded as the
/// flow stores it: the Redis entry alone does not give the code away.
fn hash_otp(state: &AppState, user_id: Uuid, code: &str) -> String {
    encode_digest(
        &state
            .keyring
            .otp_digest(OTP_PURPOSE, user_id.as_bytes(), code),
    )
}

fn encode_digest(digest: &[u8; 32]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}
