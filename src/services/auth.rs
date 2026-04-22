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
use serde::{Deserialize, Serialize};
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
    utils::{crypto, geoip::GeoLocation, jwt::Claims, password, time, totp},
};

use ::time::Duration as TimeDuration;

use super::{email, email_2fa, reauth, risk_score};
use crate::utils::backoff;

// Constants

/// Redis key prefix for the JTI blocklist.
const JTI_BLOCKLIST_PREFIX: &str = "jti_block:";
/// Redis key prefix for the session validity cache.
const SESSION_CACHE_PREFIX: &str = "sess_valid:";
/// TTL for cached session validity checks (seconds).
/// Short TTL ensures revocations (admin, bulk) propagate within this window.
/// Explicit logouts always invalidate the cache key immediately.
const SESSION_CACHE_TTL_SECS: u64 = 5;

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
/// Redis key prefix for pre-auth state.
const PRE_AUTH_PREFIX: &str = "pre_auth:";
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
    /// method: "totp" or "email"
    TwoFactorRequired {
        pre_auth_token: String,
        method: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreAuthState {
    pub user_id: Uuid,
    pub risk: Option<CachedRiskEvaluation>,
    /// Propagated from the login request so the correct token TTL is used after 2FA completes.
    #[serde(default)]
    pub remember_me: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedRiskEvaluation {
    pub context: CachedRiskContext,
    pub result: Option<risk_score::RiskResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedRiskContext {
    pub ip: String,
    pub user_agent: String,
    pub country: String,
    pub city: String,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

impl CachedRiskEvaluation {
    fn capture(
        context: &risk_score::LoginContext,
        result: Option<&risk_score::RiskResult>,
    ) -> Self {
        Self {
            context: CachedRiskContext::from_login_context(context),
            result: result.cloned(),
        }
    }
}

impl CachedRiskContext {
    fn from_login_context(context: &risk_score::LoginContext) -> Self {
        let geo = context.geo.as_ref();

        Self {
            ip: context.ip.to_string(),
            user_agent: context.user_agent.clone(),
            country: geo.map(|g| g.country.clone()).unwrap_or_default(),
            city: geo.map(|g| g.city.clone()).unwrap_or_default(),
            latitude: geo.and_then(|g| g.latitude),
            longitude: geo.and_then(|g| g.longitude),
        }
    }

    fn to_login_context(&self, user_id: Uuid) -> Option<risk_score::LoginContext> {
        let ip = self.ip.parse().ok()?;
        let geo = if self.country.is_empty()
            && self.city.is_empty()
            && self.latitude.is_none()
            && self.longitude.is_none()
        {
            None
        } else {
            Some(GeoLocation {
                country: self.country.clone(),
                city: self.city.clone(),
                latitude: self.latitude,
                longitude: self.longitude,
            })
        };

        Some(risk_score::LoginContext {
            user_id,
            ip,
            user_agent: self.user_agent.clone(),
            geo,
            login_time: time::now(),
        })
    }
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

    let hash = password::hash_async(password_plaintext, &state.config.crypto)
        .await
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

    let mailer = state.mailer.clone();
    let templates = state.templates.clone();
    let mail_cfg = state.config.mail.clone();
    let email_to = email.to_string();
    let username = username.to_string();
    let locale = locale.to_string();
    let raw_token = raw_token.clone();
    let public_url = state.config.server.public_url.clone();
    email::dispatch_best_effort("verification_email", async move {
        email::send_verification_email(
            &mailer,
            templates.as_ref(),
            &mail_cfg,
            &email_to,
            &username,
            &locale,
            &raw_token,
            &public_url,
        )
        .await
    });

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

#[allow(clippy::too_many_arguments)]
pub async fn login(
    state: &AppState,
    identifier: &str,
    password_plaintext: &str,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    device_name: Option<&str>,
    remember_me: bool,
    request_id: Option<Uuid>,
) -> Result<LoginResult, AppError> {
    let brute_force_cutoff = time::now() - TimeDuration::seconds(BRUTE_FORCE_WINDOW_SECS);

    let ip_failures_fut = async {
        match ip {
            Some(ip_val) => login_attempt::count_recent_failures_by_ip(
                &state.db,
                ip_val,
                brute_force_cutoff,
                MAX_FAILURES_BY_IP,
            )
            .await
            .map_err(|e| AppError::Internal(e.into())),
            None => Ok(0),
        }
    };
    let ip_distinct_fut = async {
        match ip {
            Some(ip_val) => {
                if let Ok(mut conn) = state.redis.get().await {
                    let hll_key = format!("{}{}", CS_HLL_PREFIX, ip_val.ip());
                    Ok(conn.pfcount(&hll_key).await.unwrap_or(0))
                } else {
                    Ok(0)
                }
            }
            None => Ok(0),
        }
    };
    let identifier_failures_fut = async {
        login_attempt::count_recent_failures_by_identifier(
            &state.db,
            identifier,
            brute_force_cutoff,
            MAX_FAILURES_BY_IDENTIFIER,
        )
        .await
        .map_err(|e| AppError::Internal(e.into()))
    };

    let (ip_failures, distinct_identifiers, failures) =
        tokio::try_join!(ip_failures_fut, ip_distinct_fut, identifier_failures_fut)?;

    if ip_failures >= MAX_FAILURES_BY_IP {
        return Err(AppError::RateLimitExceeded);
    }
    if distinct_identifiers >= CS_MAX_DISTINCT_IDENTIFIERS {
        return Err(AppError::RateLimitExceeded);
    }

    if failures >= MAX_FAILURES_BY_IDENTIFIER {
        return Err(AppError::RateLimitExceeded);
    }

    // User lookup stays index-friendly by branching on email vs username format.
    let user_opt = user_repo::find_by_identifier(&state.db, identifier).await?;

    // Always verify a password hash to prevent timing-based enumeration.
    let (user, password_ok) = match user_opt {
        Some(u) => {
            let ok = password::verify_async(password_plaintext, &u.password_hash)
                .await
                .map_err(|e| AppError::Internal(e.into()))?;
            (Some(u), ok)
        }
        None => {
            let _ = password::verify_async(password_plaintext, DUMMY_HASH).await;
            (None, false)
        }
    };

    // Record failure and return on bad credentials
    let user = match (user, password_ok) {
        (None, _) => {
            tokio::join!(
                record_failure(
                    &state.db,
                    None,
                    identifier,
                    LoginFailureReason::UnknownIdentifier,
                    ip,
                    user_agent,
                ),
                track_credential_stuffing(state, ip, identifier),
            );
            apply_backoff(failures + 1).await;
            return Err(AppError::InvalidCredentials);
        }
        (Some(u), false) => {
            tokio::join!(
                record_failure(
                    &state.db,
                    Some(u.id),
                    identifier,
                    LoginFailureReason::InvalidPassword,
                    ip,
                    user_agent,
                ),
                track_credential_stuffing(state, ip, identifier),
            );

            // After recording the failure, check if the lockout threshold is reached.
            let threshold = state.config.security.lockout_threshold as i64;
            let consecutive =
                login_attempt::count_consecutive_failures_by_user(&state.db, u.id, threshold)
                    .await
                    .unwrap_or(0);
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

    // Risk scoring and 2FA lookup are independent, so run them together on the success path.
    let risk_ctx = build_risk_context(state, user.id, ip, user_agent);
    let (risk, primary_method) = tokio::join!(
        risk_score::evaluate(state, &risk_ctx),
        tf_repo::find_primary_by_user(&state.db, user.id),
    );
    let primary_method = primary_method.map_err(|e| AppError::Internal(e.into()))?;
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
                let mailer = state.mailer.clone();
                let templates = state.templates.clone();
                let mail_cfg = state.config.mail.clone();
                let email_to = user.email.clone();
                let username = user.username.clone();
                let locale = user.preferred_locale.clone();
                let risk = r.clone();
                email::dispatch_best_effort("suspicious_login_alert", async move {
                    email::send_suspicious_login_alert(
                        &mailer,
                        templates.as_ref(),
                        &mail_cfg,
                        &email_to,
                        &username,
                        &locale,
                        ip,
                        &risk,
                    )
                    .await
                });
            }
        }
        _ => {}
    }

    // 2FA: issue a short-lived pre-auth token and pause login.
    let has_2fa = primary_method.is_some();

    // Also force 2FA challenge when risk decision is Challenge and user has no TOTP configured.
    let force_challenge = risk
        .as_ref()
        .map(|r| r.decision == risk_score::RiskDecision::Challenge)
        .unwrap_or(false);

    if has_2fa || force_challenge {
        let method = match primary_method.as_ref().map(|m| &m.method_type) {
            Some(crate::domain::two_factor::TwoFactorType::Email) => "email",
            None if force_challenge => "email",
            _ => "totp",
        }
        .to_string();

        let pre_auth_token = crypto::generate_token();
        let redis_key = pre_auth_key(&pre_auth_token);
        let pre_auth_state = PreAuthState {
            user_id: user.id,
            risk: Some(CachedRiskEvaluation::capture(&risk_ctx, risk.as_ref().ok())),
            remember_me,
        };
        let serialized =
            serde_json::to_string(&pre_auth_state).map_err(|e| AppError::Internal(e.into()))?;

        let mut conn = state
            .redis
            .get()
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        conn.set_ex::<_, _, ()>(&redis_key, serialized, PRE_AUTH_TTL_SECS)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;

        // For Email 2FA, dispatch the code as soon as the challenge is issued.
        if method == "email" {
            email_2fa::send_code(state, user.id).await?;
        }

        return Ok(LoginResult::TwoFactorRequired {
            pre_auth_token,
            method,
        });
    }

    let tokens = issue_tokens(state, user.id, ip, user_agent, device_name, remember_me).await?;
    let cached_risk = CachedRiskEvaluation::capture(&risk_ctx, risk.as_ref().ok());

    tokio::try_join!(
        async {
            user_repo::update_last_login(&state.db, user.id)
                .await
                .map_err(|e| AppError::Internal(e.into()))
        },
        async {
            if user.locked_until.is_some() {
                user_repo::clear_lockout(&state.db, user.id)
                    .await
                    .map_err(|e| AppError::Internal(e.into()))?;
            }
            Ok::<(), AppError>(())
        },
        async {
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
            .map_err(|e| AppError::Internal(e.into()))
        },
        async {
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
            .map_err(|e| AppError::Internal(e.into()))
        },
        async {
            post_login_hooks(state, &user, ip, user_agent, request_id, Some(&cached_risk)).await;
            Ok::<(), AppError>(())
        },
    )?;

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
    let redis_key = pre_auth_key(pre_auth_token);
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

    let pre_auth_state = load_pre_auth_state_from_redis(&mut conn, &redis_key).await?;

    // Do NOT consume yet; only consume on success so failures can be retried
    // within the attempt budget (token stays valid until TTL or budget exhausted).
    let user_id = pre_auth_state.user_id;
    let remember_me = pre_auth_state.remember_me;

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

    let tokens = issue_tokens(state, user.id, ip, user_agent, device_name, remember_me).await?;

    tokio::try_join!(
        async {
            user_repo::update_last_login(&state.db, user.id)
                .await
                .map_err(|e| AppError::Internal(e.into()))
        },
        async {
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
            .map_err(|e| AppError::Internal(e.into()))
        },
        async {
            post_login_hooks(
                state,
                &user,
                ip,
                user_agent,
                request_id,
                pre_auth_state.risk.as_ref(),
            )
            .await;
            Ok::<(), AppError>(())
        },
    )?;

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

    let refresh_expiry = if session.remember_me {
        state.config.jwt.refresh_expiry_secs
    } else {
        state.config.jwt.short_session_expiry_secs
    };

    let new_session = match session_repo::rotate(
        &state.db,
        session.id,
        &NewSession {
            user_id: user.id,
            session_family_id: session.session_family_id,
            expires_at: time::in_secs(refresh_expiry),
            ip_address: ip,
            device_name: session.device_name.as_deref(),
            remember_me: session.remember_me,
            token_hash: &new_hash,
            user_agent,
        },
    )
    .await
    {
        Ok(session) => session,
        Err(sqlx::Error::RowNotFound) => {
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
        Err(e) => return Err(AppError::Internal(e.into())),
    };

    let access_token = build_access_token(user.id, new_session.id, state)?;

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

    // Invalidate the Redis session cache so revocation propagates immediately
    // without waiting for SESSION_CACHE_TTL_SECS to expire.
    invalidate_session_cache(state, session_id);

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

    let consumed = token::consume_verification(&state.db, record.id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    if !consumed {
        return Err(AppError::TokenInvalid);
    }

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
        None => {
            // Normalize timing so callers cannot distinguish "email not found"
            // from "email found" via response latency (2 DB writes normally happen).
            tokio::time::sleep(std::time::Duration::from_millis(80)).await;
            return Ok(());
        }
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

    let mailer = state.mailer.clone();
    let templates = state.templates.clone();
    let mail_cfg = state.config.mail.clone();
    let email_to = email.to_string();
    let username = user.username.clone();
    let locale = user.preferred_locale.clone();
    let raw_token = raw_token.clone();
    let public_url = state.config.server.public_url.clone();
    email::dispatch_best_effort("password_reset_email", async move {
        email::send_password_reset_email(
            &mailer,
            templates.as_ref(),
            &mail_cfg,
            &email_to,
            &username,
            &locale,
            &raw_token,
            &public_url,
        )
        .await
    });

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

    let new_hash = password::hash_async(new_password, &state.config.crypto)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    let consumed = token::consume_password_reset(&state.db, record.id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    if !consumed {
        return Err(AppError::TokenInvalid);
    }

    user_repo::update_password_hash(&state.db, record.user_id, &new_hash)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    let revoked_session_ids = session_repo::find_active_by_user(&state.db, record.user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .into_iter()
        .map(|session| session.id)
        .collect::<Vec<_>>();

    // Invalidate all active sessions to force re-login with the new password
    session_repo::revoke_all_by_user(&state.db, record.user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    invalidate_session_caches(state, &revoked_session_ids).await;

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
/// Record login location and send new-device notification if applicable.
pub async fn post_login_hooks(
    state: &AppState,
    user: &User,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    request_id: Option<Uuid>,
    cached_risk: Option<&CachedRiskEvaluation>,
) {
    maybe_notify_new_device(state, user, ip, user_agent, request_id, cached_risk).await;
}

async fn issue_tokens(
    state: &AppState,
    user_id: Uuid,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    device_name: Option<&str>,
    remember_me: bool,
) -> Result<AuthTokens, AppError> {
    let raw_token = crypto::generate_token();
    let token_hash = crypto::sha256(raw_token.as_bytes());

    let expiry_secs = if remember_me {
        state.config.jwt.refresh_expiry_secs
    } else {
        state.config.jwt.short_session_expiry_secs
    };

    let session = session_repo::create(
        &state.db,
        &NewSession {
            user_id,
            session_family_id: Uuid::new_v4(),
            expires_at: time::in_secs(expiry_secs),
            ip_address: ip,
            device_name,
            remember_me,
            token_hash: &token_hash,
            user_agent,
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    reauth::mark_recent_reauth(state, session.id).await;

    let access_token = build_access_token(user_id, session.id, state)?;

    Ok(AuthTokens {
        access_token,
        refresh_token: raw_token,
        session,
    })
}

fn build_access_token(
    user_id: Uuid,
    session_id: uuid::Uuid,
    state: &AppState,
) -> Result<String, AppError> {
    let exp = time::in_secs(state.config.jwt.access_expiry_secs).unix_timestamp();
    let claims = Claims::new(user_id, session_id, exp);
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
    match state.redis.get().await {
        Ok(mut conn) => {
            let key = format!("{}{}", CS_HLL_PREFIX, ip_val.ip());
            let _: Result<(), _> = conn.pfadd(&key, identifier).await;
            let _: Result<(), _> = conn.expire(&key, CS_WINDOW_SECS as i64).await;
        }
        Err(e) => {
            tracing::warn!(ip = %ip_val.ip(), error = %e, "credential-stuffing tracking skipped: Redis unavailable");
        }
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
    let redis_key = pre_auth_key(pre_auth_token);

    let mut conn = state
        .redis
        .get()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    let pre_auth_state = load_pre_auth_state_from_redis(&mut conn, &redis_key).await?;
    drop(conn);

    let user_id = pre_auth_state.user_id;
    let remember_me = pre_auth_state.remember_me;

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

    let tokens = issue_tokens(state, user.id, ip, user_agent, device_name, remember_me).await?;

    tokio::try_join!(
        async {
            user_repo::update_last_login(&state.db, user.id)
                .await
                .map_err(|e| AppError::Internal(e.into()))
        },
        async {
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
            .map_err(|e| AppError::Internal(e.into()))
        },
        async {
            post_login_hooks(
                state,
                &user,
                ip,
                user_agent,
                request_id,
                pre_auth_state.risk.as_ref(),
            )
            .await;
            Ok::<(), AppError>(())
        },
    )?;

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
    let redis_key = pre_auth_key(pre_auth_token);
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

    let pre_auth_state = load_pre_auth_state_from_redis(&mut conn, &redis_key).await?;

    // Keep the pre-auth token alive until success; consume on success below.
    let user_id = pre_auth_state.user_id;
    let remember_me = pre_auth_state.remember_me;

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

    let tokens = issue_tokens(state, user.id, ip, user_agent, None, remember_me).await?;

    tokio::try_join!(
        async {
            user_repo::update_last_login(&state.db, user.id)
                .await
                .map_err(|e| AppError::Internal(e.into()))
        },
        async {
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
            .map_err(|e| AppError::Internal(e.into()))
        },
    )?;

    let mailer = state.mailer.clone();
    let templates = state.templates.clone();
    let mail_cfg = state.config.mail.clone();
    let email_to = user.email.clone();
    let username = user.username.clone();
    let locale = user.preferred_locale.clone();
    email::dispatch_best_effort("recovery_code_used_email", async move {
        email::send_recovery_code_used(
            &mailer,
            templates.as_ref(),
            &mail_cfg,
            &email_to,
            &username,
            &locale,
        )
        .await
    });

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

async fn apply_backoff(failures: i64) {
    backoff::apply(failures).await;
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

/// Check session validity with a short-lived Redis cache to reduce per-request DB queries.
///
/// On cache hit, returns the cached result immediately.
/// On cache miss, queries the database and caches the result for SESSION_CACHE_TTL_SECS.
/// Both active and inactive results are cached: inactive prevents DB hammering from
/// replayed revoked tokens (JTI blocklist covers the logout case directly).
/// Fails open on Redis errors - falls back to a direct DB query.
pub async fn check_session_validity(state: &AppState, session_id: Uuid) -> Result<bool, AppError> {
    let key = format!("{SESSION_CACHE_PREFIX}{session_id}");

    // Fast path: check Redis cache first.
    if let Ok(mut conn) = state.redis.get().await
        && let Ok(Some(cached)) = conn.get::<_, Option<u8>>(&key).await
    {
        return Ok(cached == 1);
    }

    // Slow path: query the database on cache miss.
    let session = session_repo::find_validation_by_id(&state.db, session_id)
        .await
        .map_err(|_| AppError::Unauthorized)?
        .ok_or(AppError::Unauthorized)?;

    let is_active = session.is_active();

    // Cache the result to skip the DB on subsequent requests within the TTL window.
    if let Ok(mut conn) = state.redis.get().await {
        let value: u8 = if is_active { 1 } else { 0 };
        let _: Result<(), _> = conn.set_ex(&key, value, SESSION_CACHE_TTL_SECS).await;
    }

    Ok(is_active)
}

/// Immediately invalidate the session validity cache entry.
/// Call this on explicit logout to ensure revocation takes effect without waiting for TTL expiry.
/// Best-effort: if Redis is unavailable, the cache expires naturally within SESSION_CACHE_TTL_SECS.
pub fn invalidate_session_cache(state: &AppState, session_id: Uuid) {
    let redis = state.redis.clone();
    let key = format!("{SESSION_CACHE_PREFIX}{session_id}");
    tokio::spawn(async move {
        if let Ok(mut conn) = redis.get().await {
            let _: Result<(), _> = conn.del(&key).await;
        }
    });
}

pub async fn invalidate_session_caches(state: &AppState, session_ids: &[Uuid]) {
    if session_ids.is_empty() {
        return;
    }

    if let Ok(mut conn) = state.redis.get().await {
        let keys: Vec<String> = session_ids
            .iter()
            .map(|id| format!("{SESSION_CACHE_PREFIX}{id}"))
            .collect();
        let _: Result<(), _> = conn.del(keys).await;
    }
}

pub async fn resolve_pre_auth(
    state: &AppState,
    pre_auth_token: &str,
) -> Result<PreAuthState, AppError> {
    let redis_key = pre_auth_key(pre_auth_token);
    let mut conn = state
        .redis
        .get()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    load_pre_auth_state_from_redis(&mut conn, &redis_key).await
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
    cached_risk: Option<&CachedRiskEvaluation>,
) {
    if let Some(cached_risk) = cached_risk
        && let Some(risk_ctx) = cached_risk.context.to_login_context(user.id)
    {
        if let Some(result) = cached_risk.result.as_ref() {
            let (record_result, _) = tokio::join!(
                risk_score::record_login(state, &risk_ctx),
                send_new_device_notification(state, user, &risk_ctx, result, request_id),
            );
            let _ = record_result;
            return;
        }

        let _ = risk_score::record_login(state, &risk_ctx).await;
        return;
    }

    let ua = match user_agent {
        Some(u) if !u.is_empty() => u,
        _ => {
            let risk_ctx = build_risk_context(state, user.id, ip, None);
            let _ = risk_score::record_login(state, &risk_ctx).await;
            return;
        }
    };

    let risk_ctx = build_risk_context(state, user.id, ip, Some(ua));
    let evaluated_risk = risk_score::evaluate(state, &risk_ctx).await;

    if let Ok(result) = evaluated_risk {
        let (record_result, _) = tokio::join!(
            risk_score::record_login(state, &risk_ctx),
            send_new_device_notification(state, user, &risk_ctx, &result, request_id),
        );
        let _ = record_result;
    } else {
        let _ = risk_score::record_login(state, &risk_ctx).await;
    }
}

async fn send_new_device_notification(
    state: &AppState,
    user: &User,
    risk_ctx: &risk_score::LoginContext,
    result: &risk_score::RiskResult,
    request_id: Option<Uuid>,
) {
    let is_new_device = result.signals.contains(&"new_device".to_string());
    let already_alerted = result.decision == risk_score::RiskDecision::Alert
        || result.decision == risk_score::RiskDecision::Challenge;
    if !is_new_device || already_alerted {
        return;
    }

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
            ip_address: Some(risk_ctx.ip),
            metadata: json!({
                "user_agent": &risk_ctx.user_agent,
                "country": country,
                "city": city,
                "score": result.score,
            }),
        },
    )
    .await;

    let mailer = state.mailer.clone();
    let templates = state.templates.clone();
    let mail_cfg = state.config.mail.clone();
    let email_to = user.email.clone();
    let username = user.username.clone();
    let locale = user.preferred_locale.clone();
    let ip = risk_ctx.ip;
    let user_agent = risk_ctx.user_agent.clone();
    let country = country.to_string();
    let city = city.to_string();
    email::dispatch_best_effort("new_device_login", async move {
        email::send_new_device_login(
            &mailer,
            templates.as_ref(),
            &mail_cfg,
            &email_to,
            &username,
            &locale,
            Some(ip),
            &user_agent,
            &country,
            &city,
        )
        .await
    });
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
        ip: ip.unwrap_or_else(|| "0.0.0.0/0".parse().expect("0.0.0.0/0 is a valid CIDR")),
        user_agent: user_agent.unwrap_or("").to_string(),
        geo,
        login_time: time::now(),
    }
}

fn pre_auth_key(pre_auth_token: &str) -> String {
    format!("{}{}", PRE_AUTH_PREFIX, pre_auth_token)
}

async fn load_pre_auth_state_from_redis(
    conn: &mut deadpool_redis::Connection,
    redis_key: &str,
) -> Result<PreAuthState, AppError> {
    let raw: Option<String> = conn
        .get(redis_key)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    let raw = raw.ok_or(AppError::TokenInvalid)?;

    parse_pre_auth_state(&raw)
}

fn parse_pre_auth_state(raw: &str) -> Result<PreAuthState, AppError> {
    if let Ok(user_id) = raw.parse::<Uuid>() {
        return Ok(PreAuthState {
            user_id,
            risk: None,
            remember_me: false,
        });
    }

    serde_json::from_str(raw).map_err(|_| AppError::TokenInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pre_auth_state_accepts_legacy_uuid_payload() {
        let user_id = Uuid::new_v4();

        let state =
            parse_pre_auth_state(&user_id.to_string()).expect("legacy pre-auth should parse");

        assert_eq!(state.user_id, user_id);
        assert!(state.risk.is_none());
    }

    #[test]
    fn parse_pre_auth_state_accepts_cached_risk_payload() {
        let user_id = Uuid::new_v4();
        let payload = serde_json::json!({
            "user_id": user_id,
            "risk": {
                "context": {
                    "ip": "203.0.113.9/32",
                    "user_agent": "perf-test-agent",
                    "country": "FR",
                    "city": "Paris",
                    "latitude": 48.8566,
                    "longitude": 2.3522
                },
                "result": {
                    "score": 35,
                    "decision": "Alert",
                    "signals": ["new_device", "new_country:FR"]
                }
            }
        });

        let state = parse_pre_auth_state(&payload.to_string())
            .expect("cached pre-auth payload should parse");

        let risk = state.risk.expect("cached risk should be preserved");
        assert_eq!(state.user_id, user_id);
        assert_eq!(risk.context.ip, "203.0.113.9/32");
        assert_eq!(risk.context.user_agent, "perf-test-agent");
        assert_eq!(
            risk.result.expect("risk result should be present").score,
            35
        );
    }

    #[test]
    fn cached_risk_context_roundtrip_preserves_security_relevant_fields() {
        let user_id = Uuid::new_v4();
        let ip = "198.51.100.20/32".parse().expect("valid cidr");
        let original = risk_score::LoginContext {
            user_id,
            ip,
            user_agent: "agent/1.0".to_string(),
            geo: Some(GeoLocation {
                country: "FR".to_string(),
                city: "Paris".to_string(),
                latitude: Some(48.8566),
                longitude: Some(2.3522),
            }),
            login_time: time::now(),
        };

        let cached = CachedRiskContext::from_login_context(&original);
        let restored = cached
            .to_login_context(user_id)
            .expect("cached context should restore");

        assert_eq!(restored.user_id, user_id);
        assert_eq!(restored.ip, original.ip);
        assert_eq!(restored.user_agent, original.user_agent);
        assert_eq!(
            restored.geo.as_ref().expect("restored geo").country,
            original.geo.as_ref().expect("original geo").country
        );
        assert_eq!(
            restored.geo.as_ref().expect("restored geo").city,
            original.geo.as_ref().expect("original geo").city
        );
        assert_eq!(
            restored.geo.as_ref().expect("restored geo").latitude,
            original.geo.as_ref().expect("original geo").latitude
        );
        assert_eq!(
            restored.geo.as_ref().expect("restored geo").longitude,
            original.geo.as_ref().expect("original geo").longitude
        );
    }
}
