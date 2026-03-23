//! Authentication service: register, login, logout, token refresh, email verification,
//! password reset, and 2FA challenge completion.
//!
//! Security notes:
//! - Password verification always runs even when the user does not exist (timing safety).
//! - Brute-force limits are checked before any credential lookup.
//! - Refresh token replay is detected via session family revocation.
//! - Pre-auth tokens (2FA challenge) are stored in Redis with a 5-minute TTL.

use deadpool_redis::redis::AsyncCommands;
use ipnetwork::IpNetwork;
use serde_json::json;
use uuid::Uuid;

use crate::{
    domain::{
        audit::AuditAction,
        login_attempt::LoginFailureReason,
        session::Session,
        user::{User, UserStatus},
    },
    error::AppError,
    repositories::{
        audit::{self, NewAuditEntry},
        login_attempt::{self, NewLoginAttempt},
        recovery_code, role,
        session::{self as session_repo, NewSession},
        token::{self, NewEmailVerificationToken, NewPasswordResetToken},
        two_factor as tf_repo,
        user::{self as user_repo, NewUser},
    },
    state::AppState,
    utils::{crypto, jwt::Claims, password, time, totp},
};

use ::time::Duration as TimeDuration;

use super::{email, email_2fa, reauth, risk_score};

// Constants

/// Redis key prefix for the JTI blocklist.
const JTI_BLOCKLIST_PREFIX: &str = "jti_block:";

/// Max failed attempts per identifier within the window before lockout.
const MAX_FAILURES_BY_IDENTIFIER: i64 = 10;
/// Max failed attempts per IP within the window before lockout.
const MAX_FAILURES_BY_IP: i64 = 30;
/// Lookback window for brute-force counting (15 minutes).
const BRUTE_FORCE_WINDOW_SECS: i64 = 900;
/// Redis key prefix for the credential-stuffing HyperLogLog counter (per IP).
const CS_HLL_PREFIX: &str = "cs_hll:";
/// Sliding window for the credential-stuffing counter (5 minutes).
const CS_WINDOW_SECS: u64 = 300;
/// Max distinct identifiers attempted from a single IP within CS_WINDOW_SECS before blocking.
const CS_MAX_DISTINCT_IDENTIFIERS: i64 = 50;
/// Max invalid refresh token attempts per IP within the window.
const MAX_REFRESH_FAILURES_BY_IP: i64 = 20;
/// TTL for the refresh failure counter in Redis (seconds).
const REFRESH_FAILURE_WINDOW_SECS: u64 = 900;
/// Pre-auth (2FA challenge) token TTL in Redis.
const PRE_AUTH_TTL_SECS: u64 = 300;
/// Max TOTP code failures per pre-auth token before the challenge is permanently rejected.
const MAX_TOTP_FAILURES: i64 = 5;
/// Redis key prefix for consumed TOTP codes (prevents code reuse within the 30-second window).
const TOTP_USED_PREFIX: &str = "totp_used:";
/// Max recovery code failures per pre-auth token (same limit as TOTP).
const MAX_RECOVERY_FAILURES: i64 = 5;
/// Max recovery code failures per user in a rolling window (cross-session protection).
const MAX_RECOVERY_FAILURES_BY_USER: i64 = 10;
/// Rolling window for the per-user recovery code failure counter (1 hour).
const RECOVERY_FAILURE_USER_WINDOW_SECS: u64 = 3600;
/// Redis key prefix for the per-user recovery code failure counter.
const RC_USER_FAIL_PREFIX: &str = "rc_user_fail:";
/// Initial backoff delay after the first 2FA failure (seconds).
const BACKOFF_BASE_SECS: u64 = 1;
/// Maximum backoff delay cap (seconds). Doubles each attempt: 1, 2, 4, 8, 16, capped.
const BACKOFF_MAX_SECS: u64 = 16;
/// Max verify-email or reset-password token submission attempts per IP within the window.
const MAX_TOKEN_SUBMIT_BY_IP: i64 = 10;
/// Sliding window for token submission rate limiting (1 hour).
const TOKEN_SUBMIT_WINDOW_SECS: u64 = 3600;
/// Email verification token lifetime.
const EMAIL_TOKEN_EXPIRY_SECS: u64 = 60 * 60 * 24; // 24h
/// Password reset token lifetime.
const RESET_TOKEN_EXPIRY_SECS: u64 = 60 * 30; // 30 min

// A valid argon2id PHC string that will always fail verification.
// Running it ensures the response time is the same whether the user exists or not.
const DUMMY_HASH: &str =
    "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHRzb21lc2FsdA$RdescudvJCsgt3ub+b+dWRWJTmaaJObG";

// Output types

pub struct AuthTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub session: Session,
}

#[allow(clippy::large_enum_variant)]
pub enum LoginResult {
    Complete(AuthTokens),
    /// 2FA is required; submit this token with the code to complete login.
    /// method: "totp" or "webauthn"
    TwoFactorRequired {
        pre_auth_token: String,
        method: String,
    },
}

// Register

#[allow(clippy::too_many_arguments)]
pub async fn register(
    state: &AppState,
    username: &str,
    email: &str,
    password_plaintext: &str,
    locale: &str,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    request_id: Option<Uuid>,
) -> Result<User, AppError> {
    // Uniqueness checks
    if user_repo::find_by_email(&state.db, email).await?.is_some() {
        return Err(AppError::Conflict("email_taken"));
    }
    if user_repo::find_by_username(&state.db, username)
        .await?
        .is_some()
    {
        return Err(AppError::Conflict("username_taken"));
    }

    let hash = password::hash(password_plaintext, &state.config.crypto)
        .map_err(|e| AppError::Internal(e.into()))?;

    let user = user_repo::create(
        &state.db,
        &NewUser {
            username,
            email,
            password_hash: &hash,
            preferred_locale: locale,
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    // Assign default role if one exists
    if let Some(role) = role::find_default(&state.db)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
    {
        let _ = role::assign_to_user(&state.db, user.id, role.id, None).await;
    }

    // Email verification token
    let raw_token = crypto::generate_token();
    let hash_bytes = crypto::sha256(raw_token.as_bytes());

    token::create_verification(
        &state.db,
        &NewEmailVerificationToken {
            user_id: user.id,
            token_hash: &hash_bytes,
            expires_at: time::in_secs(EMAIL_TOKEN_EXPIRY_SECS),
            request_ip: ip,
            request_user_agent: user_agent,
            target_email: email,
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    if let Err(e) = email::send_verification_email(
        &state.mailer,
        &state.templates,
        &state.config.mail,
        email,
        username,
        locale,
        &raw_token,
        &state.config.server.public_url,
    )
    .await
    {
        tracing::warn!(error = ?e, user_id = %user.id, "failed to send verification email");
    }

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user.id),
            request_id,
            action: AuditAction::Register,
            ip_address: ip,
            metadata: json!({}),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    Ok(user)
}

// Login

pub async fn login(
    state: &AppState,
    identifier: &str,
    password_plaintext: &str,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    device_name: Option<&str>,
    request_id: Option<Uuid>,
) -> Result<LoginResult, AppError> {
    // Brute-force guard
    if let Some(ip_val) = ip {
        let failures =
            login_attempt::count_recent_failures_by_ip(&state.db, ip_val, BRUTE_FORCE_WINDOW_SECS)
                .await
                .map_err(|e| AppError::Internal(e.into()))?;
        if failures >= MAX_FAILURES_BY_IP {
            return Err(AppError::RateLimitExceeded);
        }

        // Credential-stuffing guard: block IPs that attempt too many distinct identifiers.
        if let Ok(mut conn) = state.redis.get().await {
            let hll_key = format!("{}{}", CS_HLL_PREFIX, ip_val.ip());
            let distinct: i64 = conn.pfcount(&hll_key).await.unwrap_or(0);
            if distinct >= CS_MAX_DISTINCT_IDENTIFIERS {
                return Err(AppError::RateLimitExceeded);
            }
        }
    }

    let failures = login_attempt::count_recent_failures_by_identifier(
        &state.db,
        identifier,
        BRUTE_FORCE_WINDOW_SECS,
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;
    if failures >= MAX_FAILURES_BY_IDENTIFIER {
        return Err(AppError::RateLimitExceeded);
    }

    // User lookup (email first, then username)
    let user_opt = match user_repo::find_by_email(&state.db, identifier).await? {
        Some(u) => Some(u),
        None => user_repo::find_by_username(&state.db, identifier).await?,
    };

    // Always verify a password hash to prevent timing-based enumeration.
    let (user, password_ok) = match user_opt {
        Some(u) => {
            let ok = password::verify(password_plaintext, &u.password_hash)
                .map_err(|e| AppError::Internal(e.into()))?;
            (Some(u), ok)
        }
        None => {
            let _ = password::verify(password_plaintext, DUMMY_HASH);
            (None, false)
        }
    };

    // Record failure and return on bad credentials
    let user = match (user, password_ok) {
        (None, _) => {
            record_failure(
                &state.db,
                None,
                identifier,
                LoginFailureReason::UnknownIdentifier,
                ip,
                user_agent,
            )
            .await;
            track_credential_stuffing(state, ip, identifier).await;
            apply_backoff(failures + 1).await;
            return Err(AppError::InvalidCredentials);
        }
        (Some(u), false) => {
            record_failure(
                &state.db,
                Some(u.id),
                identifier,
                LoginFailureReason::InvalidPassword,
                ip,
                user_agent,
            )
            .await;
            track_credential_stuffing(state, ip, identifier).await;

            // After recording the failure, check if the lockout threshold is reached.
            let consecutive = login_attempt::count_consecutive_failures_by_user(&state.db, u.id)
                .await
                .unwrap_or(0);
            let threshold = state.config.security.lockout_threshold as i64;
            if consecutive >= threshold {
                let locked_until = time::now()
                    + TimeDuration::seconds(state.config.security.lockout_duration_secs as i64);
                let _ = user_repo::set_locked_until(&state.db, u.id, locked_until).await;

                let _ = audit::append(
                    &state.db,
                    &NewAuditEntry {
                        user_id: Some(u.id),
                        request_id,
                        action: AuditAction::AccountSuspended,
                        ip_address: ip,
                        metadata: json!({"reason": "lockout", "locked_until": locked_until.unix_timestamp()}),
                    },
                )
                .await;
            }

            apply_backoff(failures + 1).await;
            return Err(AppError::InvalidCredentials);
        }
        (Some(u), true) => u,
    };

    // Account lockout check (before status checks; locked accounts return early).
    if user.is_locked() {
        return Err(AppError::AccountLocked);
    }

    // Account status checks
    match user.status {
        UserStatus::Suspended => return Err(AppError::AccountSuspended),
        UserStatus::Inactive => return Err(AppError::AccountInactive),
        UserStatus::PendingVerification => return Err(AppError::EmailNotVerified),
        UserStatus::Active => {}
    }

    // Risk scoring: evaluate before issuing tokens or 2FA challenge.
    let risk_ctx = build_risk_context(state, user.id, ip, user_agent);
    let risk = risk_score::evaluate(state, &risk_ctx).await;
    match &risk {
        Ok(r) if r.decision == risk_score::RiskDecision::Block => {
            if let Ok(r) = &risk {
                let _ = risk_score::audit_suspicious(state, &risk_ctx, r, request_id).await;
            }
            return Err(AppError::LoginBlocked);
        }
        Ok(r)
            if r.decision == risk_score::RiskDecision::Alert
                || r.decision == risk_score::RiskDecision::Challenge =>
        {
            if let Ok(r) = &risk {
                let _ = risk_score::audit_suspicious(state, &risk_ctx, r, request_id).await;
                let _ = email::send_suspicious_login_alert(
                    &state.mailer,
                    &state.templates,
                    &state.config.mail,
                    &user.email,
                    &user.username,
                    &user.preferred_locale,
                    ip,
                    r,
                )
                .await;
            }
        }
        _ => {}
    }

    // 2FA: issue a short-lived pre-auth token and pause login.
    let primary_method = tf_repo::find_primary_by_user(&state.db, user.id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    let has_2fa = primary_method.is_some();

    // Also force 2FA challenge when risk decision is Challenge and user has no TOTP configured.
    let force_challenge = risk
        .as_ref()
        .map(|r| r.decision == risk_score::RiskDecision::Challenge)
        .unwrap_or(false);

    if has_2fa || force_challenge {
        let method = match primary_method.as_ref().map(|m| &m.method_type) {
            Some(crate::domain::two_factor::TwoFactorType::Webauthn) => "webauthn",
            Some(crate::domain::two_factor::TwoFactorType::Email) => "email",
            None if force_challenge => "email",
            _ => "totp",
        }
        .to_string();

        let pre_auth_token = Uuid::new_v4().to_string();
        let redis_key = format!("pre_auth:{}", pre_auth_token);

        let mut conn = state
            .redis
            .get()
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        conn.set_ex::<_, _, ()>(&redis_key, user.id.to_string(), PRE_AUTH_TTL_SECS)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;

        // For Email 2FA, dispatch the code as soon as the challenge is issued.
        if method == "email" {
            let _ = email_2fa::send_code(state, user.id).await;
        }

        return Ok(LoginResult::TwoFactorRequired {
            pre_auth_token,
            method,
        });
    }

    let tokens = issue_tokens(state, &user, ip, user_agent, device_name).await?;

    user_repo::update_last_login(&state.db, user.id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    // Clear any previous lockout on successful login.
    if user.locked_until.is_some() {
        let _ = user_repo::clear_lockout(&state.db, user.id).await;
    }

    login_attempt::record(
        &state.db,
        &NewLoginAttempt {
            user_id: Some(user.id),
            attempted_identifier: identifier,
            was_successful: true,
            failure_reason: None,
            request_ip: ip,
            request_user_agent: user_agent,
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user.id),
            request_id,
            action: AuditAction::Login,
            ip_address: ip,
            metadata: json!({}),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    let _ = risk_score::record_login(state, &risk_ctx).await;

    // Send new-device notification when the user-agent hasn't been seen before
    // and risk decision did not already trigger a suspicious-login alert.
    if let Ok(r) = &risk {
        let is_new_device = r.signals.contains(&"new_device".to_string());
        let already_alerted = r.decision == risk_score::RiskDecision::Alert
            || r.decision == risk_score::RiskDecision::Challenge;
        if is_new_device && !already_alerted {
            let country = r
                .signals
                .iter()
                .find_map(|s| s.strip_prefix("new_country:"))
                .unwrap_or("");
            let city = r
                .signals
                .iter()
                .find_map(|s| s.strip_prefix("new_city:"))
                .unwrap_or("");
            let _ = email::send_new_device_login(
                &state.mailer,
                &state.templates,
                &state.config.mail,
                &user.email,
                &user.username,
                &user.preferred_locale,
                ip,
                user_agent.unwrap_or(""),
                country,
                city,
            )
            .await;
        }
    }

    Ok(LoginResult::Complete(tokens))
}

// 2FA challenge completion

pub async fn complete_two_factor_login(
    state: &AppState,
    pre_auth_token: &str,
    code: &str,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    device_name: Option<&str>,
    request_id: Option<Uuid>,
) -> Result<AuthTokens, AppError> {
    let redis_key = format!("pre_auth:{}", pre_auth_token);
    let fail_key = format!("totp_fail:{}", pre_auth_token);

    let mut conn = state
        .redis
        .get()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    // Reject if this pre-auth token already exceeded the failure limit.
    let failures: i64 = conn.get(&fail_key).await.unwrap_or(0);
    if failures >= MAX_TOTP_FAILURES {
        return Err(AppError::RateLimitExceeded);
    }

    let user_id_str: Option<String> = conn
        .get(&redis_key)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    let user_id_str = user_id_str.ok_or(AppError::TokenInvalid)?;

    // Do NOT consume yet; only consume on success so failures can be retried
    // within the attempt budget (token stays valid until TTL or budget exhausted).

    let user_id: Uuid = user_id_str.parse().map_err(|_| AppError::TokenInvalid)?;

    let user = user_repo::find_by_id(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::Unauthorized)?;

    if !user.is_active() {
        return Err(AppError::AccountSuspended);
    }

    let method = tf_repo::find_primary_by_user(&state.db, user.id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::Unauthorized)?;

    let enc_key = crypto::decode_encryption_key(&state.config.crypto.encryption_key)
        .map_err(|e| AppError::Internal(e.into()))?;

    let encrypted_secret = method
        .totp_secret
        .as_deref()
        .ok_or(AppError::Unauthorized)?;

    let valid = totp::verify_code(
        encrypted_secret,
        code,
        &enc_key,
        state.config.crypto.totp_skew,
    )
    .map_err(|e| AppError::Internal(e.into()))?;

    // Reject if this exact code was already consumed in the current TOTP window.
    // Key: totp_used:{user_id}:{code}, TTL = 2 * 30s = one full window on either side.
    if valid {
        let used_key = format!("{}{}:{}", TOTP_USED_PREFIX, user_id, code);
        let already_used: bool = if let Ok(mut c) = state.redis.get().await {
            let used: bool = c.exists(&used_key).await.unwrap_or(false);
            if !used {
                let _: Result<(), _> = c.set_ex(&used_key, 1u8, 60u64).await;
            }
            used
        } else {
            false
        };

        if already_used {
            let new_failures = if let Ok(mut c) = state.redis.get().await {
                let n: i64 = c.incr(&fail_key, 1i64).await.unwrap_or(failures + 1);
                let _: Result<(), _> = c.expire(&fail_key, PRE_AUTH_TTL_SECS as i64).await;
                n
            } else {
                failures + 1
            };
            apply_backoff(new_failures).await;
            return Err(AppError::TwoFactorFailed);
        }
    }

    if !valid {
        // Increment failure counter; lock the token out after MAX_TOTP_FAILURES attempts.
        let new_failures = if let Ok(mut c) = state.redis.get().await {
            let n: i64 = c.incr(&fail_key, 1i64).await.unwrap_or(failures + 1);
            let _: Result<(), _> = c.expire(&fail_key, PRE_AUTH_TTL_SECS as i64).await;
            n
        } else {
            failures + 1
        };

        audit::append(
            &state.db,
            &NewAuditEntry {
                user_id: Some(user.id),
                request_id,
                action: AuditAction::TwoFactorFailed,
                ip_address: ip,
                metadata: json!({}),
            },
        )
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

        apply_backoff(new_failures).await;
        return Err(AppError::TwoFactorFailed);
    }

    // Consume the pre-auth token now that verification succeeded.
    if let Ok(mut c) = state.redis.get().await {
        let _: Result<(), _> = c.del(&redis_key).await;
        let _: Result<(), _> = c.del(&fail_key).await;
    }

    let tokens = issue_tokens(state, &user, ip, user_agent, device_name).await?;

    user_repo::update_last_login(&state.db, user.id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    maybe_notify_new_device(state, &user, ip, user_agent, request_id).await;

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user.id),
            request_id,
            action: AuditAction::Login,
            ip_address: ip,
            metadata: json!({"two_factor": true}),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    Ok(tokens)
}

// Token refresh

pub async fn refresh_token(
    state: &AppState,
    raw_token: &str,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    request_id: Option<Uuid>,
) -> Result<AuthTokens, AppError> {
    // Brute-force guard on refresh attempts per IP.
    if let Some(ip_val) = ip {
        let key = format!("refresh_fail:{}", ip_val.ip());
        let mut conn = state
            .redis
            .get()
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        let failures: i64 = conn.get(&key).await.unwrap_or(0);
        if failures >= MAX_REFRESH_FAILURES_BY_IP {
            return Err(AppError::RateLimitExceeded);
        }
    }

    let token_hash = crypto::sha256(raw_token.as_bytes());

    // Fast-path: check Redis blocklist before hitting the DB.
    if is_refresh_token_blocked(state, &token_hash).await {
        return Err(AppError::TokenInvalid);
    }

    let session = match session_repo::find_by_token_hash(&state.db, &token_hash)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
    {
        Some(s) => s,
        None => {
            // Increment failure counter on unknown token.
            if let Some(ip_val) = ip {
                let key = format!("refresh_fail:{}", ip_val.ip());
                if let Ok(mut conn) = state.redis.get().await {
                    let _: Result<(), _> = conn.incr(&key, 1i64).await;
                    let _: Result<(), _> =
                        conn.expire(&key, REFRESH_FAILURE_WINDOW_SECS as i64).await;
                }
            }
            return Err(AppError::TokenInvalid);
        }
    };

    // Revoked session that is presented again = replay attack
    if session.revoked_at.is_some() {
        session_repo::revoke_family(&state.db, session.id)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;

        audit::append(
            &state.db,
            &NewAuditEntry {
                user_id: Some(session.user_id),
                request_id,
                action: AuditAction::SessionReplayDetected,
                ip_address: ip,
                metadata: json!({"session_id": session.id}),
            },
        )
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

        return Err(AppError::TokenInvalid);
    }

    if !session.is_active() {
        return Err(AppError::TokenExpired);
    }

    // Absolute session lifetime guard
    let max_lifetime = state.config.jwt.max_session_lifetime_secs as i64;
    let session_age = (time::now() - session.created_at).whole_seconds();
    if session_age >= max_lifetime {
        return Err(AppError::TokenExpired);
    }

    // Optional IP binding: reject if the request IP differs from the session's recorded IP.
    if state.config.jwt.strict_session_binding {
        let session_ip = session.ip_address.map(|n| n.ip());
        let request_ip = ip.map(|n| n.ip());
        if session_ip != request_ip {
            audit::append(
                &state.db,
                &NewAuditEntry {
                    user_id: Some(session.user_id),
                    request_id,
                    action: AuditAction::SessionReplayDetected,
                    ip_address: ip,
                    metadata: json!({
                        "reason": "ip_mismatch",
                        "session_id": session.id,
                        "expected_ip": session_ip.map(|i| i.to_string()),
                        "actual_ip": request_ip.map(|i| i.to_string()),
                    }),
                },
            )
            .await
            .map_err(|e| AppError::Internal(e.into()))?;

            return Err(AppError::Unauthorized);
        }
    }

    let user = user_repo::find_by_id(&state.db, session.user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::Unauthorized)?;

    if !user.is_active() {
        return Err(AppError::AccountSuspended);
    }

    let new_raw_token = crypto::generate_token();
    let new_hash = crypto::sha256(new_raw_token.as_bytes());

    let new_session = session_repo::rotate(
        &state.db,
        session.id,
        &NewSession {
            user_id: user.id,
            session_family_id: session.session_family_id,
            expires_at: time::in_secs(state.config.jwt.refresh_expiry_secs),
            ip_address: ip,
            device_name: session.device_name.as_deref(),
            token_hash: &new_hash,
            user_agent,
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    let access_token = build_access_token(&user, new_session.id, state)?;

    Ok(AuthTokens {
        access_token,
        refresh_token: new_raw_token,
        session: new_session,
    })
}

// Logout

pub async fn logout(
    state: &AppState,
    session_id: Uuid,
    user_id: Uuid,
    jti: Uuid,
    token_exp: i64,
    ip: Option<IpNetwork>,
    request_id: Option<Uuid>,
) -> Result<(), AppError> {
    // Load session before revoking to get token_hash for RT blacklist.
    let session = session_repo::find_by_id(&state.db, session_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    session_repo::revoke(&state.db, session_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    blocklist_jti(state, jti, token_exp).await;

    if let Some(s) = session {
        blocklist_refresh_token(state, &s.token_hash, s.expires_at).await;
        reauth::clear_recent_reauth(state, s.id).await;
    }

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user_id),
            request_id,
            action: AuditAction::Logout,
            ip_address: ip,
            metadata: json!({"session_id": session_id}),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    Ok(())
}

// Email verification

pub async fn verify_email(
    state: &AppState,
    raw_token: &str,
    ip: Option<IpNetwork>,
    request_id: Option<Uuid>,
) -> Result<(), AppError> {
    use crate::domain::token::OneTimeToken;

    // Rate limit token submission attempts per IP to prevent brute-force on 24h tokens.
    if let Some(ip_val) = ip {
        let key = format!("vf_fail:{}", ip_val.ip());
        if let Ok(mut conn) = state.redis.get().await {
            let count: i64 = conn.get(&key).await.unwrap_or(0);
            if count >= MAX_TOKEN_SUBMIT_BY_IP {
                return Err(AppError::RateLimitExceeded);
            }
            let _: Result<(), _> = conn.incr(&key, 1i64).await;
            let _: Result<(), _> = conn.expire(&key, TOKEN_SUBMIT_WINDOW_SECS as i64).await;
        }
    }

    let hash = crypto::sha256(raw_token.as_bytes());

    let record = token::find_verification_by_hash(&state.db, &hash)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::TokenInvalid)?;

    if record.is_expired() {
        return Err(AppError::TokenExpired);
    }
    if record.is_used() {
        return Err(AppError::TokenInvalid);
    }

    token::consume_verification(&state.db, record.id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    user_repo::mark_email_verified(&state.db, record.user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(record.user_id),
            request_id,
            action: AuditAction::EmailVerified,
            ip_address: ip,
            metadata: json!({}),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    Ok(())
}

// Forgot password

/// Always returns Ok to prevent email enumeration.
pub async fn forgot_password(
    state: &AppState,
    email: &str,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    request_id: Option<Uuid>,
) -> Result<(), AppError> {
    // Rate limit forgot-password requests per IP (prevents email spam campaigns).
    if let Some(ip_val) = ip {
        let key = format!("fp_req:{}", ip_val.ip());
        if let Ok(mut conn) = state.redis.get().await {
            let count: i64 = conn.get(&key).await.unwrap_or(0);
            if count >= 5 {
                return Err(AppError::RateLimitExceeded);
            }
            let _: Result<(), _> = conn.incr(&key, 1i64).await;
            let _: Result<(), _> = conn.expire(&key, 900i64).await; // 15-min window
        }
    }

    let user = match user_repo::find_by_email(&state.db, email).await? {
        Some(u) => u,
        None => return Ok(()),
    };

    // Revoke any previous pending reset before issuing a new one
    token::revoke_active_password_reset_by_user(&state.db, user.id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    let raw_token = crypto::generate_token();
    let hash = crypto::sha256(raw_token.as_bytes());

    token::create_password_reset(
        &state.db,
        &NewPasswordResetToken {
            user_id: user.id,
            token_hash: &hash,
            expires_at: time::in_secs(RESET_TOKEN_EXPIRY_SECS),
            request_ip: ip,
            request_user_agent: user_agent,
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    if let Err(e) = email::send_password_reset_email(
        &state.mailer,
        &state.templates,
        &state.config.mail,
        email,
        &user.username,
        &user.preferred_locale,
        &raw_token,
        &state.config.server.public_url,
    )
    .await
    {
        tracing::warn!(error = ?e, user_id = %user.id, "failed to send password reset email");
    }

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user.id),
            request_id,
            action: AuditAction::PasswordResetRequested,
            ip_address: ip,
            metadata: json!({}),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    Ok(())
}

// Reset password

pub async fn reset_password(
    state: &AppState,
    raw_token: &str,
    new_password: &str,
    ip: Option<IpNetwork>,
    request_id: Option<Uuid>,
) -> Result<(), AppError> {
    use crate::domain::token::OneTimeToken;

    // Rate limit reset attempts per IP.
    if let Some(ip_val) = ip {
        let key = format!("rp_fail:{}", ip_val.ip());
        if let Ok(mut conn) = state.redis.get().await {
            let count: i64 = conn.get(&key).await.unwrap_or(0);
            if count >= MAX_TOKEN_SUBMIT_BY_IP {
                return Err(AppError::RateLimitExceeded);
            }
            let _: Result<(), _> = conn.incr(&key, 1i64).await;
            let _: Result<(), _> = conn.expire(&key, TOKEN_SUBMIT_WINDOW_SECS as i64).await;
        }
    }

    let hash = crypto::sha256(raw_token.as_bytes());

    let record = token::find_password_reset_by_hash(&state.db, &hash)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::TokenInvalid)?;

    if record.is_expired() {
        return Err(AppError::TokenExpired);
    }
    if record.is_used() {
        return Err(AppError::TokenInvalid);
    }

    let new_hash = password::hash(new_password, &state.config.crypto)
        .map_err(|e| AppError::Internal(e.into()))?;

    token::consume_password_reset(&state.db, record.id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    user_repo::update_password_hash(&state.db, record.user_id, &new_hash)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    // Invalidate all active sessions to force re-login with the new password
    session_repo::revoke_all_by_user(&state.db, record.user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    // Also purge pending verification and reset tokens
    token::revoke_active_password_reset_by_user(&state.db, record.user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(record.user_id),
            request_id,
            action: AuditAction::PasswordResetCompleted,
            ip_address: ip,
            metadata: json!({}),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    Ok(())
}

// Internal helpers

/// Record login location and send new-device notification if applicable.
/// Public so WebAuthn and other 2FA handlers can call it after issuing tokens.
pub async fn post_login_hooks(
    state: &AppState,
    user: &User,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    request_id: Option<Uuid>,
) {
    maybe_notify_new_device(state, user, ip, user_agent, request_id).await;
}

/// Public wrapper so WebAuthn and future handlers can issue tokens after 2FA verification.
pub async fn issue_session_tokens(
    state: &AppState,
    user: &crate::domain::user::User,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    device_name: Option<&str>,
) -> Result<AuthTokens, AppError> {
    issue_tokens(state, user, ip, user_agent, device_name).await
}

async fn issue_tokens(
    state: &AppState,
    user: &User,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    device_name: Option<&str>,
) -> Result<AuthTokens, AppError> {
    let raw_token = crypto::generate_token();
    let token_hash = crypto::sha256(raw_token.as_bytes());

    let session = session_repo::create(
        &state.db,
        &NewSession {
            user_id: user.id,
            session_family_id: Uuid::new_v4(),
            expires_at: time::in_secs(state.config.jwt.refresh_expiry_secs),
            ip_address: ip,
            device_name,
            token_hash: &token_hash,
            user_agent,
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    reauth::mark_recent_reauth(state, session.id).await;

    let access_token = build_access_token(user, session.id, state)?;

    Ok(AuthTokens {
        access_token,
        refresh_token: raw_token,
        session,
    })
}

fn build_access_token(
    user: &User,
    session_id: uuid::Uuid,
    state: &AppState,
) -> Result<String, AppError> {
    let exp = time::in_secs(state.config.jwt.access_expiry_secs).unix_timestamp();
    let claims = Claims::new(user.id, session_id, exp);
    crate::utils::jwt::encode_token(&claims, &state.config.jwt.secret)
        .map_err(|e| AppError::Internal(e.into()))
}

/// Add the attempted identifier to the per-IP HyperLogLog for credential-stuffing detection.
/// Fire-and-forget: Redis unavailability does not affect the login flow.
async fn track_credential_stuffing(state: &AppState, ip: Option<IpNetwork>, identifier: &str) {
    let ip_val = match ip {
        Some(i) => i,
        None => return,
    };
    if let Ok(mut conn) = state.redis.get().await {
        let key = format!("{}{}", CS_HLL_PREFIX, ip_val.ip());
        let _: Result<(), _> = conn.pfadd(&key, identifier).await;
        let _: Result<(), _> = conn.expire(&key, CS_WINDOW_SECS as i64).await;
    }
}

async fn record_failure(
    db: &sqlx::PgPool,
    user_id: Option<Uuid>,
    identifier: &str,
    reason: LoginFailureReason,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
) {
    let _ = login_attempt::record(
        db,
        &NewLoginAttempt {
            user_id,
            attempted_identifier: identifier,
            was_successful: false,
            failure_reason: Some(reason),
            request_ip: ip,
            request_user_agent: user_agent,
        },
    )
    .await;
}

// Re-send email verification (called from user service when email changes)
#[allow(clippy::too_many_arguments)]
pub async fn resend_verification_email(
    state: &AppState,
    user_id: Uuid,
    email: &str,
    username: &str,
    locale: &str,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    request_id: Option<Uuid>,
) -> Result<(), AppError> {
    token::revoke_active_verification_by_user(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    let raw_token = crypto::generate_token();
    let hash = crypto::sha256(raw_token.as_bytes());

    token::create_verification(
        &state.db,
        &NewEmailVerificationToken {
            user_id,
            token_hash: &hash,
            expires_at: time::in_secs(EMAIL_TOKEN_EXPIRY_SECS),
            request_ip: ip,
            request_user_agent: user_agent,
            target_email: email,
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    if let Err(e) = email::send_verification_email(
        &state.mailer,
        &state.templates,
        &state.config.mail,
        email,
        username,
        locale,
        &raw_token,
        &state.config.server.public_url,
    )
    .await
    {
        tracing::warn!(error = ?e, user_id = %user_id, "failed to send verification email");
    }

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user_id),
            request_id,
            action: AuditAction::EmailVerificationSent,
            ip_address: ip,
            metadata: json!({}),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    Ok(())
}

// Complete 2FA login with an Email OTP code

pub async fn complete_email_2fa_login(
    state: &AppState,
    pre_auth_token: &str,
    code: &str,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    device_name: Option<&str>,
    request_id: Option<Uuid>,
) -> Result<AuthTokens, AppError> {
    let redis_key = format!("pre_auth:{}", pre_auth_token);

    let mut conn = state
        .redis
        .get()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    let user_id_str: Option<String> = conn
        .get(&redis_key)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    let user_id_str = user_id_str.ok_or(AppError::TokenInvalid)?;
    drop(conn);

    let user_id: Uuid = user_id_str.parse().map_err(|_| AppError::TokenInvalid)?;

    let user = user_repo::find_by_id(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::Unauthorized)?;

    if !user.is_active() {
        return Err(AppError::AccountSuspended);
    }

    email_2fa::verify_login_code(state, user_id, pre_auth_token, code).await?;

    // Consume the pre-auth token on success.
    if let Ok(mut c) = state.redis.get().await {
        let _: Result<(), _> = c.del(&redis_key).await;
    }

    let tokens = issue_tokens(state, &user, ip, user_agent, device_name).await?;

    user_repo::update_last_login(&state.db, user.id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    maybe_notify_new_device(state, &user, ip, user_agent, request_id).await;

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user.id),
            request_id,
            action: AuditAction::Login,
            ip_address: ip,
            metadata: json!({"two_factor": "email"}),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    Ok(tokens)
}

// Complete 2FA login with a recovery code instead of a TOTP code.
pub async fn complete_login_with_recovery(
    state: &AppState,
    pre_auth_token: &str,
    recovery_code_plaintext: &str,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    request_id: Option<Uuid>,
) -> Result<AuthTokens, AppError> {
    let redis_key = format!("pre_auth:{}", pre_auth_token);
    let fail_key = format!("rc_fail:{}", pre_auth_token);

    let mut conn = state
        .redis
        .get()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    // Reject if this pre-auth token already exceeded the recovery code failure limit.
    let failures: i64 = conn.get(&fail_key).await.unwrap_or(0);
    if failures >= MAX_RECOVERY_FAILURES {
        return Err(AppError::RateLimitExceeded);
    }

    let user_id_str: Option<String> = conn
        .get(&redis_key)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    let user_id_str = user_id_str.ok_or(AppError::TokenInvalid)?;

    // Keep the pre-auth token alive until success; consume on success below.
    let user_id: Uuid = user_id_str.parse().map_err(|_| AppError::TokenInvalid)?;

    // Cross-session guard: reject if the user already burned too many recovery attempts
    // within the rolling window, regardless of how many pre-auth tokens they cycled through.
    let user_fail_key = format!("{}{}", RC_USER_FAIL_PREFIX, user_id);
    let user_failures: i64 = conn.get(&user_fail_key).await.unwrap_or(0);
    if user_failures >= MAX_RECOVERY_FAILURES_BY_USER {
        return Err(AppError::RateLimitExceeded);
    }
    drop(conn);

    let user = user_repo::find_by_id(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::Unauthorized)?;

    if !user.is_active() {
        return Err(AppError::AccountSuspended);
    }

    let code_hash = crypto::sha256(recovery_code_plaintext.as_bytes());
    let record = recovery_code::find_by_hash(&state.db, &code_hash)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    // On invalid code: increment both the per-token and per-user failure counters,
    // apply backoff, and return error.
    let record = match record {
        Some(r) if r.user_id == user_id => r,
        _ => {
            let new_failures = if let Ok(mut c) = state.redis.get().await {
                let n: i64 = c.incr(&fail_key, 1i64).await.unwrap_or(failures + 1);
                let _: Result<(), _> = c.expire(&fail_key, PRE_AUTH_TTL_SECS as i64).await;
                let _: i64 = c.incr(&user_fail_key, 1i64).await.unwrap_or(0);
                let _: Result<(), _> = c
                    .expire(&user_fail_key, RECOVERY_FAILURE_USER_WINDOW_SECS as i64)
                    .await;
                n
            } else {
                failures + 1
            };
            apply_backoff(new_failures).await;
            return Err(AppError::TwoFactorFailed);
        }
    };

    let consumed = recovery_code::consume(&state.db, record.id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    if !consumed {
        let new_failures = if let Ok(mut c) = state.redis.get().await {
            let n: i64 = c.incr(&fail_key, 1i64).await.unwrap_or(failures + 1);
            let _: Result<(), _> = c.expire(&fail_key, PRE_AUTH_TTL_SECS as i64).await;
            let _: i64 = c.incr(&user_fail_key, 1i64).await.unwrap_or(0);
            let _: Result<(), _> = c
                .expire(&user_fail_key, RECOVERY_FAILURE_USER_WINDOW_SECS as i64)
                .await;
            n
        } else {
            failures + 1
        };
        apply_backoff(new_failures).await;
        return Err(AppError::TwoFactorFailed);
    }

    // Consume the pre-auth token now that recovery succeeded.
    if let Ok(mut c) = state.redis.get().await {
        let _: Result<(), _> = c.del(&redis_key).await;
        let _: Result<(), _> = c.del(&fail_key).await;
        let _: Result<(), _> = c.del(&user_fail_key).await;
    }

    let tokens = issue_tokens(state, &user, ip, user_agent, None).await?;

    user_repo::update_last_login(&state.db, user.id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user.id),
            request_id,
            action: AuditAction::Login,
            ip_address: ip,
            metadata: json!({"two_factor": "recovery_code"}),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    if let Err(e) = email::send_recovery_code_used(
        &state.mailer,
        &state.templates,
        &state.config.mail,
        &user.email,
        &user.username,
        &user.preferred_locale,
    )
    .await
    {
        tracing::warn!(error = ?e, user_id = %user.id, "failed to send recovery_code_used email");
    }

    Ok(tokens)
}

// -- Helpers

/// Redis key prefix for the refresh token blocklist.
const RT_BLOCKLIST_PREFIX: &str = "rt_block:";

/// Add a refresh token hash to the Redis blocklist.
/// TTL is set to the remaining lifetime of the session so the key auto-expires.
/// Fail-open: if Redis is unavailable the revocation is still recorded in DB.
pub async fn blocklist_refresh_token(
    state: &AppState,
    token_hash: &[u8],
    session_expires_at: ::time::OffsetDateTime,
) {
    let ttl = (session_expires_at - time::now()).whole_seconds();
    if ttl <= 0 {
        return;
    }
    let key = format!("{}{}", RT_BLOCKLIST_PREFIX, rt_hash_key(token_hash));
    if let Ok(mut conn) = state.redis.get().await {
        let _: Result<(), _> = conn.set_ex(&key, 1u8, ttl as u64).await;
    }
}

/// Return true if the refresh token hash is in the Redis blocklist.
/// Fail-open: returns false if Redis is unreachable (DB revoke_at is the safety net).
pub async fn is_refresh_token_blocked(state: &AppState, token_hash: &[u8]) -> bool {
    let key = format!("{}{}", RT_BLOCKLIST_PREFIX, rt_hash_key(token_hash));
    match state.redis.get().await {
        Ok(mut conn) => conn.exists::<_, bool>(&key).await.unwrap_or(false),
        Err(_) => false,
    }
}

fn rt_hash_key(token_hash: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token_hash)
}

/// Apply an exponential backoff delay based on how many failures are recorded.
/// The delay is 2^(failures-1) seconds, capped at BACKOFF_MAX_SECS.
/// Called *before* returning a failure response so attackers can't pipeline requests.
async fn apply_backoff(failures: i64) {
    if failures <= 0 {
        return;
    }
    let exp = (failures - 1).min(4) as u32; // 2^4 = 16 = cap
    let secs = BACKOFF_BASE_SECS
        .saturating_mul(2u64.pow(exp))
        .min(BACKOFF_MAX_SECS);
    tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
}

/// Write a JTI to the Redis blocklist with TTL = remaining token lifetime.
/// Fail-open: if Redis is unavailable the logout still succeeds.
pub async fn blocklist_jti(state: &AppState, jti: Uuid, token_exp: i64) {
    let ttl = token_exp - time::now().unix_timestamp();
    if ttl <= 0 {
        return;
    }
    let key = format!("{}{}", JTI_BLOCKLIST_PREFIX, jti);
    if let Ok(mut conn) = state.redis.get().await {
        let _: Result<(), _> = conn.set_ex(&key, 1u8, ttl as u64).await;
    }
}

/// Return true if the given JTI has been blocklisted.
pub async fn is_jti_blocked(state: &AppState, jti: Uuid) -> bool {
    let key = format!("{}{}", JTI_BLOCKLIST_PREFIX, jti);
    match state.redis.get().await {
        Ok(mut conn) => conn.exists::<_, bool>(&key).await.unwrap_or(false),
        Err(_) => false,
    }
}

/// Record the login location and send a new-device notification if needed.
/// Also writes an audit entry when a new device is detected but risk is below alert threshold.
/// Fire-and-forget; failures are logged and ignored.
async fn maybe_notify_new_device(
    state: &AppState,
    user: &User,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    request_id: Option<Uuid>,
) {
    let ua = match user_agent {
        Some(u) if !u.is_empty() => u,
        _ => {
            let risk_ctx = build_risk_context(state, user.id, ip, None);
            let _ = risk_score::record_login(state, &risk_ctx).await;
            return;
        }
    };

    let risk_ctx = build_risk_context(state, user.id, ip, Some(ua));

    let _ = risk_score::record_login(state, &risk_ctx).await;

    if let Ok(result) = risk_score::evaluate(state, &risk_ctx).await {
        let is_new_device = result.signals.contains(&"new_device".to_string());
        let already_alerted = result.decision == risk_score::RiskDecision::Alert
            || result.decision == risk_score::RiskDecision::Challenge;
        if is_new_device && !already_alerted {
            let country = result
                .signals
                .iter()
                .find_map(|s| s.strip_prefix("new_country:"))
                .unwrap_or("");
            let city = result
                .signals
                .iter()
                .find_map(|s| s.strip_prefix("new_city:"))
                .unwrap_or("");

            let _ = audit::append(
                &state.db,
                &NewAuditEntry {
                    user_id: Some(user.id),
                    request_id,
                    action: AuditAction::NewDeviceLogin,
                    ip_address: ip,
                    metadata: json!({
                        "user_agent": ua,
                        "country": country,
                        "city": city,
                        "score": result.score,
                    }),
                },
            )
            .await;

            let _ = email::send_new_device_login(
                &state.mailer,
                &state.templates,
                &state.config.mail,
                &user.email,
                &user.username,
                &user.preferred_locale,
                ip,
                ua,
                country,
                city,
            )
            .await;
        }
    }
}

fn build_risk_context(
    state: &AppState,
    user_id: Uuid,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
) -> risk_score::LoginContext {
    let geo = ip.and_then(|ip| state.geoip.lookup(&ip));
    risk_score::LoginContext {
        user_id,
        ip: ip.unwrap_or_else(|| "0.0.0.0/0".parse().unwrap()),
        user_agent: user_agent.unwrap_or("").to_string(),
        geo,
        login_time: time::now(),
    }
}
