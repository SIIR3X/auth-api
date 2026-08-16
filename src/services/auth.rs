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
        session::{Session, SessionType},
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

use super::{email, email_2fa, events, reauth};
use crate::middleware::rate_limit::ip_bucket;
use crate::utils::{
    backoff,
    redis_counter::{self, Budget},
};

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
/// A rotated refresh token presented again within this window is treated as a
/// concurrent refresh from the same client (two tabs, a retried request): it is
/// refused without revoking the family. Later, it is a replay and the whole
/// family is revoked. Kept short: inside the window a replay goes undetected.
const REFRESH_REUSE_GRACE: TimeDuration = TimeDuration::seconds(2);
/// Pre-auth (2FA challenge) token TTL in Redis.
const PRE_AUTH_TTL_SECS: u64 = 300;
/// Redis key prefix for pre-auth state.
const PRE_AUTH_PREFIX: &str = "pre_auth:";
/// Redis key prefix for the per-user pre-auth token index (Set of active flow tokens).
/// Used to purge pre-auth tokens belonging to a user on sensitive events
/// (e.g. password reset) without resorting to SCAN.
const USER_PRE_AUTH_PREFIX: &str = "user_pre_auth:";
/// Max TOTP code failures per pre-auth token before the challenge is permanently rejected.
const MAX_TOTP_FAILURES: i64 = 5;
/// Max TOTP code failures per account per window, across every pre-auth token.
/// A new token only costs the password, so the per-token budget alone does not
/// bound a search of the code space.
const MAX_TOTP_FAILURES_BY_USER: i64 = 20;
/// Redis key prefix for the per-account TOTP failure budget.
const TOTP_USER_FAIL_PREFIX: &str = "totp_user_fail:";
/// Rolling window of the per-account second-factor budgets (1 hour).
const SECOND_FACTOR_USER_WINDOW_SECS: u64 = 3600;
/// Redis key prefix for consumed TOTP codes (prevents code reuse within the 30-second window).
const TOTP_USED_PREFIX: &str = "totp_used:";
/// Max recovery code failures per pre-auth token (same limit as TOTP).
const MAX_RECOVERY_FAILURES: i64 = 5;
/// Max recovery code failures per user in a rolling window (cross-session protection).
const MAX_RECOVERY_FAILURES_BY_USER: i64 = 10;
/// Rolling window for the per-user recovery code failure counter (24 hours).
const RECOVERY_FAILURE_USER_WINDOW_SECS: u64 = 86400;
/// Redis key prefix for the per-user recovery code failure counter.
const RC_USER_FAIL_PREFIX: &str = "rc_user_fail:";
/// Max verify-email or reset-password token submission attempts per IP within the window.
/// High enough that users sharing an egress IP (CGNAT, corporate proxies) do not
/// lock each other out; the per-token-hash cap below is what actually stops
/// brute-force against a specific token.
const MAX_TOKEN_SUBMIT_BY_IP: i64 = 10;
/// Max submission attempts per token hash, across every IP. Three rather than
/// one: a double-click or a retried request must not burn a valid link.
const MAX_TOKEN_SUBMIT_BY_HASH: i64 = 3;
/// Sliding window for token submission rate limiting (1 hour).
const TOKEN_SUBMIT_WINDOW_SECS: u64 = 3600;
/// Email verification token lifetime.
const EMAIL_TOKEN_EXPIRY_SECS: u64 = 60 * 60 * 24; // 24h
/// Password reset token lifetime.
const RESET_TOKEN_EXPIRY_SECS: u64 = 60 * 30; // 30 min
/// Forgot-password requests per IP per window.
const MAX_FORGOT_PASSWORD_BY_IP: i64 = 5;
/// Window of the per-IP forgot-password budget (15 minutes).
const FORGOT_PASSWORD_IP_WINDOW_SECS: u64 = 900;
/// Reset emails per account per window, across every IP.
const MAX_FORGOT_PASSWORD_BY_ACCOUNT: i64 = 3;
/// Window of the per-account forgot-password budget (1 hour).
const FORGOT_PASSWORD_ACCOUNT_WINDOW_SECS: u64 = 3600;
/// Every forgot-password response takes at least this long, known address or not.
const FORGOT_PASSWORD_MIN_DURATION: std::time::Duration = std::time::Duration::from_millis(250);

// Fallback for the decoy hash below, used only if the configured Argon2
// parameters are unusable -- in which case real hashing is broken too.
const DUMMY_HASH: &str =
    "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHRzb21lc2FsdA$RdescudvJCsgt3ub+b+dWRWJTmaaJObG";

/// A hash no password can match, verified when the identifier is unknown so a
/// login costs the same either way.
///
/// Built from the configured parameters rather than written down: Argon2 reads
/// its cost from the PHC string, so a hard-coded decoy costs what *it* says,
/// not what real hashes cost, and turns into an enumeration oracle as soon as
/// `ARGON2_*` differs from it. The plaintext is random, drawn once per process.
fn dummy_hash(cfg: &crate::config::CryptoConfig) -> &'static str {
    static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    DUMMY.get_or_init(|| {
        password::hash(&crypto::generate_token(), cfg).unwrap_or_else(|e| {
            tracing::error!(error = ?e, "could not build a decoy hash from the Argon2 parameters");
            DUMMY_HASH.to_owned()
        })
    })
}

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
    /// Propagated from the login request so the correct token TTL is used after 2FA completes.
    #[serde(default)]
    pub remember_me: bool,
    /// Second factor this challenge was issued for. Each completion endpoint
    /// accepts only its own method, so a TOTP challenge cannot be answered with
    /// an email code. `None` only for tokens minted before the field existed,
    /// which are refused (they expire within `PRE_AUTH_TTL_SECS` anyway).
    #[serde(default)]
    pub method: Option<ChallengeMethod>,
}

/// Second factor demanded by a login challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeMethod {
    Totp,
    Email,
}

impl ChallengeMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Totp => "totp",
            Self::Email => "email",
        }
    }
}

impl PreAuthState {
    /// Refuse a completion endpoint that does not match the challenge.
    pub fn expect_method(&self, expected: ChallengeMethod) -> Result<(), AppError> {
        if self.method == Some(expected) {
            Ok(())
        } else {
            Err(AppError::TokenInvalid)
        }
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
) -> Result<Option<User>, AppError> {
    // A taken username is reported: it is a public identifier the user picks
    // and must know to change. A taken email is not: answering differently
    // would let anyone test which addresses have an account. Its owner is told
    // by email instead, and the caller gets the same response as a new signup.
    if user_repo::find_by_username(&state.db, username)
        .await?
        .is_some()
    {
        return Err(AppError::Conflict("username_taken"));
    }

    // Hash on every path so a registered address costs the same as a new one.
    let hash = password::hash_async(password_plaintext, &state.config.crypto)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    if let Some(existing) = user_repo::find_by_email(&state.db, email).await? {
        notify_existing_account(state, &existing);
        return Ok(None);
    }

    let created = user_repo::create(
        &state.db,
        &NewUser {
            username,
            email,
            password_hash: &hash,
            preferred_locale: locale,
        },
    )
    .await;
    let user = match created {
        Ok(user) => user,
        // The pre-checks can race with a concurrent registration; the UNIQUE
        // constraints are authoritative and resolve to the same outcomes.
        Err(e) => {
            return match AppError::from_unique_violation(
                e,
                &[
                    ("users_email_key", "email_taken"),
                    ("users_username_key", "username_taken"),
                ],
            ) {
                AppError::Conflict("email_taken") => Ok(None),
                other => Err(other),
            };
        }
    };

    // Assign default role if one exists
    if let Some(role) = role::find_default(&state.db)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
    {
        // Best-effort: default role assignment must not block registration.
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

    events::publish(
        state,
        "user.created",
        &events::UserCreated {
            user_id: user.id,
            email: user.email.clone(),
            username: user.username.clone(),
        },
    )
    .await;

    Ok(Some(user))
}

// Login

/// Tell the owner of an existing account that someone tried to register with
/// their address. Best-effort, like every notification.
fn notify_existing_account(state: &AppState, user: &User) {
    let mailer = state.mailer.clone();
    let templates = state.templates.clone();
    let mail_cfg = state.config.mail.clone();
    let email_to = user.email.clone();
    let username = user.username.clone();
    let locale = user.preferred_locale.clone();
    email::dispatch_best_effort("account_exists_email", async move {
        email::send_account_exists(
            &mailer,
            templates.as_ref(),
            &mail_cfg,
            &email_to,
            &username,
            &locale,
        )
        .await
    });
}

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
                    let hll_key = format!("{}{}", CS_HLL_PREFIX, ip_bucket(ip_val.ip()));
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
            let ok =
                password::verify_async(password_plaintext, &u.password_hash, &state.config.crypto)
                    .await
                    .map_err(|e| AppError::Internal(e.into()))?;

            // A locked account answers the same whatever the password, after the
            // same Argon2 work. Checking the lock only after a correct password
            // turned the lockout into an oracle confirming the guess.
            if u.is_locked() {
                metrics::counter!("auth_logins_total", "outcome" => "locked").increment(1);
                return Err(AppError::AccountLocked);
            }
            (Some(u), ok)
        }
        None => {
            let _ = password::verify_async(
                password_plaintext,
                dummy_hash(&state.config.crypto),
                &state.config.crypto,
            )
            .await;
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
            metrics::counter!("auth_logins_total", "outcome" => "invalid_credentials").increment(1);
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
                metrics::counter!("auth_lockouts_total").increment(1);
                // Best-effort: lockout and audit must not leak timing information on the login path.
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

            metrics::counter!("auth_logins_total", "outcome" => "invalid_credentials").increment(1);
            apply_backoff(failures + 1).await;
            return Err(AppError::InvalidCredentials);
        }
        (Some(u), true) => u,
    };

    // Account status checks
    match user.status {
        UserStatus::Suspended => return Err(AppError::AccountSuspended),
        UserStatus::Inactive => return Err(AppError::AccountInactive),
        UserStatus::PendingVerification => return Err(AppError::EmailNotVerified),
        UserStatus::Active => {}
    }

    let primary_method = tf_repo::find_primary_by_user(&state.db, user.id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    // 2FA: issue a short-lived pre-auth token and pause login.
    if let Some(primary) = primary_method.as_ref() {
        let method = match primary.method_type {
            crate::domain::two_factor::TwoFactorType::Email => ChallengeMethod::Email,
            crate::domain::two_factor::TwoFactorType::Totp => ChallengeMethod::Totp,
        };

        let pre_auth_token = crypto::generate_token();
        let redis_key = pre_auth_key(&pre_auth_token);
        let pre_auth_state = PreAuthState {
            user_id: user.id,
            remember_me,
            method: Some(method),
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

        // Maintain a per-user index so reset_password (and other revocation
        // hooks) can purge active pre-auth tokens without SCAN. Best-effort:
        // a stale entry is harmless because the token itself expires after
        // PRE_AUTH_TTL_SECS, and DEL on a missing key is a no-op.
        let user_index_key = user_pre_auth_index_key(user.id);
        let _: Result<(), _> = conn
            .sadd::<_, _, ()>(&user_index_key, &pre_auth_token)
            .await;
        let _: Result<(), _> = conn
            .expire::<_, ()>(&user_index_key, PRE_AUTH_TTL_SECS as i64)
            .await;

        // For Email 2FA, dispatch the code as soon as the challenge is issued.
        if method == ChallengeMethod::Email {
            email_2fa::send_code(state, user.id).await?;
        }

        metrics::counter!("auth_logins_total", "outcome" => "two_factor_required").increment(1);
        return Ok(LoginResult::TwoFactorRequired {
            pre_auth_token,
            method: method.as_str().to_string(),
        });
    }

    let tokens = issue_tokens(
        state,
        user.id,
        ip,
        user_agent,
        device_name,
        remember_me,
        SessionType::Web,
        None,
        None,
    )
    .await?;

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
    )?;

    metrics::counter!("auth_logins_total", "outcome" => "success").increment(1);
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
    let pre_auth_state = load_pre_auth_state_from_redis(&mut conn, &redis_key).await?;
    drop(conn);
    pre_auth_state.expect_method(ChallengeMethod::Totp)?;

    // Do NOT consume the token yet; only on success, so failures can be retried
    // within the attempt budget.
    let user_id = pre_auth_state.user_id;
    let remember_me = pre_auth_state.remember_me;
    let user_fail_key = format!("{TOTP_USER_FAIL_PREFIX}{user_id}");

    // Reserve the attempt before checking the code, atomically, against both
    // the token and the account: concurrent guesses cannot all read the same
    // counter and slip under the limit together.
    let attempt = redis_counter::consume(
        &state.redis,
        &[
            Budget {
                key: &fail_key,
                limit: MAX_TOTP_FAILURES,
                window_secs: PRE_AUTH_TTL_SECS,
            },
            Budget {
                key: &user_fail_key,
                limit: MAX_TOTP_FAILURES_BY_USER,
                window_secs: SECOND_FACTOR_USER_WINDOW_SECS,
            },
        ],
    )
    .await?;
    if attempt.exceeded {
        return Err(AppError::RateLimitExceeded);
    }

    let user = user_repo::find_by_id(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::Unauthorized)?;

    if !user.is_active() {
        return Err(AppError::AccountSuspended);
    }
    if user.is_locked() {
        return Err(AppError::AccountLocked);
    }

    // The primary method may have changed since the challenge was issued.
    let method = tf_repo::find_primary_by_user(&state.db, user.id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .filter(|m| m.method_type == crate::domain::two_factor::TwoFactorType::Totp)
        .ok_or(AppError::TokenInvalid)?;

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

    // Replay guard: a code already consumed within its validity window is
    // refused. Redis is only a fast path; `used_totp_codes` is the durable
    // authority, checked with an atomic INSERT .. ON CONFLICT, and a database
    // error is propagated (fail-closed).
    let consumed = if valid {
        let used_key = format!("{}{}:{}", TOTP_USED_PREFIX, user_id, code);
        let cached_replay: bool = if let Ok(mut c) = state.redis.get().await {
            c.exists(&used_key).await.unwrap_or(false)
        } else {
            false
        };

        let consumed = !cached_replay
            && tf_repo::try_consume_totp_code(&state.db, user_id, &crypto::sha256(code.as_bytes()))
                .await
                .map_err(|e| AppError::Internal(e.into()))?;

        if consumed && let Ok(mut c) = state.redis.get().await {
            let _: Result<(), _> = c.set_ex(&used_key, 1u8, 60u64).await;
        }
        consumed
    } else {
        false
    };

    if !consumed {
        record_second_factor_failure(state, &user, ip, user_agent, request_id).await;
        metrics::counter!("auth_2fa_failures_total", "method" => "totp").increment(1);
        apply_backoff(attempt.counts[0]).await;
        return Err(AppError::TwoFactorFailed);
    }

    redis_counter::reset(&state.redis, &[&user_fail_key]).await;

    // Consume the pre-auth token now that verification succeeded.
    if let Ok(mut c) = state.redis.get().await {
        let _: Result<(), _> = c.del(&redis_key).await;
        let _: Result<(), _> = c.del(&fail_key).await;
        let _: Result<(), _> = c
            .srem::<_, _, ()>(user_pre_auth_index_key(user_id), pre_auth_token)
            .await;
    }

    let tokens = issue_tokens(
        state,
        user.id,
        ip,
        user_agent,
        device_name,
        remember_me,
        SessionType::Web,
        None,
        None,
    )
    .await?;

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
    )?;

    metrics::counter!("auth_logins_total", "outcome" => "success").increment(1);
    metrics::counter!("auth_2fa_success_total", "method" => "totp").increment(1);
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
        let key = format!("refresh_fail:{}", ip_bucket(ip_val.ip()));
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
    // If Redis is unavailable we deliberately do NOT abort here: the DB
    // revocation check below (`session.revoked_at`) is the durable source of
    // truth. The Redis miss has already been logged at error! by the helper.
    match is_refresh_token_blocked(state, &token_hash).await {
        Ok(true) => return Err(AppError::TokenInvalid),
        Ok(false) => {}
        Err(AppError::ServiceUnavailable(_)) => {
            tracing::warn!(
                "refresh-token Redis blocklist unavailable; relying on DB session.revoked_at fallback"
            );
        }
        Err(e) => return Err(e),
    }

    let session = match session_repo::find_by_token_hash(&state.db, &token_hash)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
    {
        Some(s) => s,
        None => {
            // Increment failure counter on unknown token.
            if let Some(ip_val) = ip {
                let key = format!("refresh_fail:{}", ip_bucket(ip_val.ip()));
                if let Ok(mut conn) = state.redis.get().await {
                    let _: Result<(), _> = conn.incr(&key, 1i64).await;
                    let _: Result<(), _> =
                        conn.expire(&key, REFRESH_FAILURE_WINDOW_SECS as i64).await;
                }
            }
            return Err(AppError::TokenInvalid);
        }
    };

    // Revoked session presented again: a concurrent refresh when it was rotated
    // moments ago, a replay attack otherwise.
    if session.revoked_at.is_some() {
        if session.rotated_within(REFRESH_REUSE_GRACE) {
            return Err(AppError::TokenInvalid);
        }
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
    // Measured from the family's first sign-in: every rotation creates a new
    // row, so the current row's created_at would restart the clock each time.
    let session_age = (time::now() - session.family_created_at).whole_seconds();
    if session_age >= max_lifetime {
        return Err(AppError::TokenExpired);
    }

    // Optional IP binding: reject if the request IP differs from the session's recorded IP.
    if state.config.jwt.strict_session_binding {
        let session_ip = session.ip_address.map(|n| n.ip());
        let request_ip = ip.map(|n| n.ip());
        if session_ip != request_ip {
            metrics::counter!("auth_session_replays_total").increment(1);
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
            session_type: session.session_type,
            client_id: session.client_id.as_deref(),
            family_created_at: Some(session.family_created_at),
            scopes: None,
        },
    )
    .await
    {
        Ok(session) => session,
        Err(sqlx::Error::RowNotFound) => {
            // Another request rotated this session between our read and the
            // lock. Moments ago: the same client refreshing twice.
            if let Ok(Some(current)) = session_repo::find_by_id(&state.db, session.id).await
                && current.rotated_within(REFRESH_REUSE_GRACE)
            {
                return Err(AppError::TokenInvalid);
            }
            session_repo::revoke_family(&state.db, session.id)
                .await
                .map_err(|e| AppError::Internal(e.into()))?;

            metrics::counter!("auth_session_replays_total").increment(1);

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

    let access_token = build_access_token(
        user.id,
        new_session.id,
        new_session.scopes.as_deref(),
        state,
    )
    .await?;

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

    let hash = crypto::sha256(raw_token.as_bytes());
    guard_token_submission(state, "vf", ip, &hash).await?;

    // Constant-time token validation: always perform a DB lookup and apply a
    // minimum delay so that the response time does not reveal whether a token
    // exists. This prevents timing-based enumeration of valid tokens.
    let start = std::time::Instant::now();
    let min_duration = std::time::Duration::from_millis(100);

    let result = async {
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

        Ok(record)
    }
    .await;

    let elapsed = start.elapsed();
    if elapsed < min_duration {
        tokio::time::sleep(min_duration - elapsed).await;
    }

    let record = result?;

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

    events::publish(
        state,
        "user.email_verified",
        &events::UserEmailVerified {
            user_id: record.user_id,
            email: record.target_email.clone(),
        },
    )
    .await;

    Ok(())
}

// Forgot password

/// Always returns Ok (or 429 for an abusive IP) so the response never reveals
/// whether an account exists.
///
/// Both outcomes take the same time: the work for a known address runs, and the
/// response is padded to `FORGOT_PASSWORD_MIN_DURATION` either way. Padding only
/// the unknown path, as before, made the unknown address the slow one.
pub async fn forgot_password(
    state: &AppState,
    email: &str,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    request_id: Option<Uuid>,
) -> Result<(), AppError> {
    if let Some(ip_val) = ip {
        let key = format!("fp_req:{}", ip_bucket(ip_val.ip()));
        if budget_exhausted(
            state,
            &key,
            MAX_FORGOT_PASSWORD_BY_IP,
            FORGOT_PASSWORD_IP_WINDOW_SECS,
        )
        .await
        {
            return Err(AppError::RateLimitExceeded);
        }
    }

    let started = std::time::Instant::now();
    let result = issue_password_reset(state, email, ip, user_agent, request_id).await;
    let elapsed = started.elapsed();
    if elapsed < FORGOT_PASSWORD_MIN_DURATION {
        tokio::time::sleep(FORGOT_PASSWORD_MIN_DURATION - elapsed).await;
    }
    result
}

async fn issue_password_reset(
    state: &AppState,
    email: &str,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    request_id: Option<Uuid>,
) -> Result<(), AppError> {
    let Some(user) = user_repo::find_by_email(&state.db, email).await? else {
        return Ok(());
    };

    // Cap resets per account across every IP, so nobody can flood a mailbox or
    // keep invalidating its pending link from many addresses.
    let account_key = format!("fp_account:{}", user.id);
    if budget_exhausted(
        state,
        &account_key,
        MAX_FORGOT_PASSWORD_BY_ACCOUNT,
        FORGOT_PASSWORD_ACCOUNT_WINDOW_SECS,
    )
    .await
    {
        return Ok(());
    }

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

    let hash = crypto::sha256(raw_token.as_bytes());
    guard_token_submission(state, "rp", ip, &hash).await?;

    // Constant-time token validation (see verify_email for rationale).
    let start = std::time::Instant::now();
    let min_duration = std::time::Duration::from_millis(100);

    let result = async {
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

        Ok(record)
    }
    .await;

    let elapsed = start.elapsed();
    if elapsed < min_duration {
        tokio::time::sleep(min_duration - elapsed).await;
    }

    let record = result?;

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

    events::publish(
        state,
        "user.password_changed",
        &events::UserPasswordChanged {
            user_id: record.user_id,
        },
    )
    .await;
    events::publish(
        state,
        "user.sessions_revoked",
        &events::UserSessionsRevoked {
            user_id: record.user_id,
        },
    )
    .await;

    // Close the post-reset hijack window: any pre-auth (2FA challenge) token
    // or email-change flow that was already in flight before the reset would
    // otherwise survive and could be used by an attacker who knew them.
    // Best-effort: Redis failures here must not fail the reset.
    purge_user_pre_auth_and_email_change(state, record.user_id).await;

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

/// Consume one attempt of an abuse-control budget.
///
/// Fails open: these budgets bound volume (mail floods, token scanning) rather
/// than guard a secret, so a Redis outage must not take account recovery down
/// with it. Second-factor budgets, which do guard secrets, fail closed instead.
async fn budget_exhausted(state: &AppState, key: &str, limit: i64, window_secs: u64) -> bool {
    match redis_counter::consume(
        &state.redis,
        &[Budget {
            key,
            limit,
            window_secs,
        }],
    )
    .await
    {
        Ok(attempt) => attempt.exceeded,
        Err(error) => {
            tracing::warn!(key, error = %error, "abuse budget unavailable, failing open");
            false
        }
    }
}

/// Throttle submissions of one-time tokens (email verification, password
/// reset): per IP, and per token hash across every IP. Tokens carry 256 bits,
/// so this is volume control, not the security boundary; it fails open.
async fn guard_token_submission(
    state: &AppState,
    kind: &str,
    ip: Option<IpNetwork>,
    token_hash: &[u8; 32],
) -> Result<(), AppError> {
    let hex: String = token_hash.iter().map(|b| format!("{b:02x}")).collect();
    let hash_key = format!("{kind}_tok:{hex}");
    let ip_key = ip.map(|ip| format!("{kind}_fail:{}", ip_bucket(ip.ip())));

    let mut budgets = vec![Budget {
        key: &hash_key,
        limit: MAX_TOKEN_SUBMIT_BY_HASH,
        window_secs: TOKEN_SUBMIT_WINDOW_SECS,
    }];
    if let Some(key) = ip_key.as_deref() {
        budgets.push(Budget {
            key,
            limit: MAX_TOKEN_SUBMIT_BY_IP,
            window_secs: TOKEN_SUBMIT_WINDOW_SECS,
        });
    }

    match redis_counter::consume(&state.redis, &budgets).await {
        Ok(attempt) if attempt.exceeded => Err(AppError::RateLimitExceeded),
        Ok(_) => Ok(()),
        Err(error) => {
            tracing::warn!(error = %error, "token submission budget unavailable, failing open");
            Ok(())
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn issue_tokens(
    state: &AppState,
    user_id: Uuid,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    device_name: Option<&str>,
    remember_me: bool,
    session_type: SessionType,
    client_id: Option<&str>,
    scopes: Option<&[String]>,
) -> Result<AuthTokens, AppError> {
    let raw_token = crypto::generate_token();
    let token_hash = crypto::sha256(raw_token.as_bytes());

    let expiry_secs = if remember_me {
        state.config.jwt.refresh_expiry_secs
    } else {
        state.config.jwt.short_session_expiry_secs
    };

    let device_name = device_name.and_then(crate::domain::session::device_label);

    let session = session_repo::create(
        &state.db,
        &NewSession {
            user_id,
            session_family_id: Uuid::new_v4(),
            expires_at: time::in_secs(expiry_secs),
            ip_address: ip,
            device_name: device_name.as_deref(),
            remember_me,
            token_hash: &token_hash,
            user_agent,
            session_type,
            client_id,
            family_created_at: None,
            scopes,
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    // No re-authentication marker here: a session that was just created (by a
    // password login, an approved device, a 2FA challenge) has not re-proven
    // knowledge of the password for sensitive actions. Only an explicit
    // `POST /users/me/reauth` or a `current_password` in the request does.
    let access_token = build_access_token(user_id, session.id, scopes, state).await?;

    Ok(AuthTokens {
        access_token,
        refresh_token: raw_token,
        session,
    })
}

async fn build_access_token(
    user_id: Uuid,
    session_id: uuid::Uuid,
    scopes: Option<&[String]>,
    state: &AppState,
) -> Result<String, AppError> {
    let exp = time::in_secs(state.config.jwt.access_expiry_secs).unix_timestamp();

    // Roles and permissions are independent lookups; run them concurrently to
    // shave a DB round trip off every token issue/refresh.
    let (user_roles, user_permissions) = tokio::try_join!(
        role::find_by_user(&state.db, user_id),
        role::find_permissions_by_user(&state.db, user_id),
    )
    .map_err(|e| AppError::Internal(e.into()))?;
    let mut role_names: Vec<String> = user_roles.iter().map(|r| r.name.clone()).collect();
    let mut permission_names: Vec<String> =
        user_permissions.iter().map(|p| p.name.clone()).collect();

    // A session issued to a client carries only the permissions consented for
    // that client, re-evaluated against the user's current permissions on every
    // issue and refresh. Roles are dropped: a resource server authorizing by
    // role would otherwise grant more than the consent covered.
    if let Some(scopes) = scopes {
        permission_names.retain(|permission| scopes.contains(permission));
        role_names.clear();
    }

    let mut claims = Claims::new(user_id, session_id, exp).with_rbac(role_names, permission_names);
    // Stamp iss/aud so downstream resource servers can pin
    // the token to this issuer and to themselves. `aud` is emitted as a JSON
    // array so a single token can be accepted by multiple downstream services.
    claims.iss = Some(state.config.server.public_url.clone());
    claims.aud = state.config.jwt.audience.clone();

    crate::utils::jwt::encode_token(&claims, &state.jwt_signing_key, Some(&state.jwt_kid))
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
            let key = format!("{}{}", CS_HLL_PREFIX, ip_bucket(ip_val.ip()));
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

/// Record a failed second factor: it lands in `login_attempts` next to password
/// failures and in the audit log.
///
/// It deliberately does not feed the account lockout: whoever fails a second
/// factor already holds the password, and locking would hand them a way to shut
/// the real owner out. The per-token and per-account budgets bound the search.
async fn record_second_factor_failure(
    state: &AppState,
    user: &User,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    request_id: Option<Uuid>,
) {
    record_failure(
        &state.db,
        Some(user.id),
        &user.email,
        LoginFailureReason::TwoFactorFailed,
        ip,
        user_agent,
    )
    .await;

    let _ = audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user.id),
            request_id,
            action: AuditAction::TwoFactorFailed,
            ip_address: ip,
            metadata: json!({}),
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
    pre_auth_state.expect_method(ChallengeMethod::Email)?;

    let user_id = pre_auth_state.user_id;
    let remember_me = pre_auth_state.remember_me;

    let user = user_repo::find_by_id(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::Unauthorized)?;

    if !user.is_active() {
        return Err(AppError::AccountSuspended);
    }
    if user.is_locked() {
        return Err(AppError::AccountLocked);
    }

    if let Err(e) = email_2fa::verify_login_code(state, user_id, pre_auth_token, code).await {
        if matches!(e, AppError::TwoFactorFailed) {
            record_second_factor_failure(state, &user, ip, user_agent, request_id).await;
        }
        return Err(e);
    }

    // Consume the pre-auth token on success.
    if let Ok(mut c) = state.redis.get().await {
        let _: Result<(), _> = c.del(&redis_key).await;
        let _: Result<(), _> = c
            .srem::<_, _, ()>(user_pre_auth_index_key(user_id), pre_auth_token)
            .await;
    }

    let tokens = issue_tokens(
        state,
        user.id,
        ip,
        user_agent,
        device_name,
        remember_me,
        SessionType::Web,
        None,
        None,
    )
    .await?;

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
    )?;

    metrics::counter!("auth_logins_total", "outcome" => "success").increment(1);
    metrics::counter!("auth_2fa_success_total", "method" => "email").increment(1);
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
    let pre_auth_state = load_pre_auth_state_from_redis(&mut conn, &redis_key).await?;
    drop(conn);

    // Recovery codes stand in for any method, so no method check here. The
    // token stays alive until success.
    let user_id = pre_auth_state.user_id;
    let remember_me = pre_auth_state.remember_me;
    let user_fail_key = format!("{}{}", RC_USER_FAIL_PREFIX, user_id);

    let attempt = redis_counter::consume(
        &state.redis,
        &[
            Budget {
                key: &fail_key,
                limit: MAX_RECOVERY_FAILURES,
                window_secs: PRE_AUTH_TTL_SECS,
            },
            Budget {
                key: &user_fail_key,
                limit: MAX_RECOVERY_FAILURES_BY_USER,
                window_secs: RECOVERY_FAILURE_USER_WINDOW_SECS,
            },
        ],
    )
    .await?;
    if attempt.exceeded {
        return Err(AppError::RateLimitExceeded);
    }

    let user = user_repo::find_by_id(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::Unauthorized)?;

    if !user.is_active() {
        return Err(AppError::AccountSuspended);
    }
    if user.is_locked() {
        return Err(AppError::AccountLocked);
    }

    // The lookup refuses used and expired codes, and the UPDATE re-checks both:
    // a code sitting on its deadline can cross it between the two statements.
    let code_hash = crypto::sha256(recovery_code_plaintext.as_bytes());
    let record = recovery_code::find_by_hash(&state.db, &code_hash)
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
        record_second_factor_failure(state, &user, ip, user_agent, request_id).await;
        metrics::counter!("auth_2fa_failures_total", "method" => "recovery_code").increment(1);
        apply_backoff(attempt.counts[0]).await;
        return Err(AppError::TwoFactorFailed);
    }

    // Consume the pre-auth token now that recovery succeeded.
    if let Ok(mut c) = state.redis.get().await {
        let _: Result<(), _> = c.del(&redis_key).await;
        let _: Result<(), _> = c.del(&fail_key).await;
        let _: Result<(), _> = c.del(&user_fail_key).await;
        let _: Result<(), _> = c
            .srem::<_, _, ()>(user_pre_auth_index_key(user_id), pre_auth_token)
            .await;
    }

    let tokens = issue_tokens(
        state,
        user.id,
        ip,
        user_agent,
        None,
        remember_me,
        SessionType::Web,
        None,
        None,
    )
    .await?;

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

    metrics::counter!("auth_logins_total", "outcome" => "success").increment(1);
    metrics::counter!("auth_2fa_success_total", "method" => "recovery_code").increment(1);
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
///
/// Fail-soft: returns `Err(AppError::ServiceUnavailable)` when Redis is unreachable
/// or the EXISTS query fails. The caller (`refresh_token`) is expected to fall back
/// to the database revocation check (`session.revoked_at`) which is the durable
/// source of truth. Returning `false` silently here would let revoked refresh
/// tokens be accepted during a Redis outage (AUTH-H1).
pub async fn is_refresh_token_blocked(
    state: &AppState,
    token_hash: &[u8],
) -> Result<bool, AppError> {
    let key = format!("{}{}", RT_BLOCKLIST_PREFIX, rt_hash_key(token_hash));
    let mut conn = state.redis.get().await.map_err(|e| {
        tracing::error!(
            error = %e,
            "refresh-token blocklist check failed: Redis pool unavailable; falling back to DB revocation check"
        );
        AppError::ServiceUnavailable("redis_unavailable")
    })?;
    conn.exists::<_, bool>(&key).await.map_err(|e| {
        tracing::error!(
            error = %e,
            "refresh-token blocklist EXISTS query failed; falling back to DB revocation check"
        );
        AppError::ServiceUnavailable("redis_query_failed")
    })
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
///
/// Fail-CLOSED: there is no DB-side fallback for per-JTI revocation (logout
/// only writes to Redis), so any Redis failure is propagated as
/// `AppError::ServiceUnavailable` (HTTP 503) rather than being silently
/// treated as "not blocked". Otherwise, an attacker could bypass an explicit
/// logout simply by triggering a Redis outage (AUTH-H1).
pub async fn is_jti_blocked(state: &AppState, jti: Uuid) -> Result<bool, AppError> {
    let key = format!("{}{}", JTI_BLOCKLIST_PREFIX, jti);
    let mut conn = state.redis.get().await.map_err(|e| {
        tracing::error!(
            jti = %jti,
            error = %e,
            "JTI blocklist check failed: Redis pool unavailable; failing closed (cannot prove token is not revoked)"
        );
        AppError::ServiceUnavailable("redis_unavailable")
    })?;
    conn.exists::<_, bool>(&key).await.map_err(|e| {
        tracing::error!(
            jti = %jti,
            error = %e,
            "JTI blocklist EXISTS query failed; failing closed"
        );
        AppError::ServiceUnavailable("redis_query_failed")
    })
}

/// Check session validity with a short-lived Redis cache to reduce per-request DB queries.
///
/// On cache hit, returns the cached result immediately.
/// On cache miss, queries the database and caches the result for SESSION_CACHE_TTL_SECS.
/// Both active and inactive results are cached: inactive prevents DB hammering from
/// replayed revoked tokens (JTI blocklist covers the logout case directly).
/// Fails open on Redis errors - falls back to a direct DB query.
///
/// **Limitation:** admin/bulk session revocations (outside explicit logout) are not
/// reflected until the cache entry expires (up to SESSION_CACHE_TTL_SECS seconds).
/// Explicit logouts bypass this by calling `invalidate_session_cache` immediately.
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

fn pre_auth_key(pre_auth_token: &str) -> String {
    format!("{}{}", PRE_AUTH_PREFIX, pre_auth_token)
}

fn user_pre_auth_index_key(user_id: Uuid) -> String {
    format!("{}{}", USER_PRE_AUTH_PREFIX, user_id)
}

/// Purge every active pre-auth (2FA challenge) and email-change flow token
/// belonging to `user_id`. Called from sensitive-event handlers such as
/// password reset to close the post-reset hijack window.
///
/// Best-effort: any Redis failure is logged and swallowed -- callers must not
/// abort their primary operation (e.g. the password reset itself) on a
/// transient Redis error during cleanup.
pub async fn purge_user_pre_auth_and_email_change(state: &AppState, user_id: Uuid) {
    let mut conn = match state.redis.get().await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, user_id = %user_id, "failed to acquire redis connection for pre-auth purge");
            return;
        }
    };

    // 1. Purge pre-auth (2FA challenge) tokens via the per-user index.
    let index_key = user_pre_auth_index_key(user_id);
    let tokens: Vec<String> = conn.smembers(&index_key).await.unwrap_or_default();
    for token in &tokens {
        let pre_key = pre_auth_key(token);
        let _: Result<(), _> = conn.del(&pre_key).await;
        let _: Result<(), _> = conn.del(format!("totp_fail:{}", token)).await;
        let _: Result<(), _> = conn.del(format!("rc_fail:{}", token)).await;
    }
    let _: Result<(), _> = conn.del(&index_key).await;

    // 2. Purge any in-progress email-change flow for this user. The flow keeps
    // its current flow_token in `email_change_active:{user_id}`, so we don't
    // need to scan.
    let active_key = format!("email_change_active:{}", user_id);
    let active_token: Option<String> = conn.get(&active_key).await.unwrap_or(None);
    if let Some(flow_token) = active_token {
        let _: Result<(), _> = conn
            .del(vec![
                format!("email_change_flow:{}", flow_token),
                format!("email_change_fail:{}", flow_token),
                active_key,
            ])
            .await;
    }
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
            remember_me: false,
            method: None,
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
    }

    #[test]
    fn parse_pre_auth_state_ignores_fields_from_older_versions() {
        // Tokens minted before risk scoring was retired carry a `risk` field;
        // they must keep parsing until they expire.
        let user_id = Uuid::new_v4();
        let payload = serde_json::json!({
            "user_id": user_id,
            "risk": { "context": { "ip": "203.0.113.9/32" }, "result": null },
            "remember_me": true,
            "method": "totp"
        });

        let state = parse_pre_auth_state(&payload.to_string()).expect("payload should parse");

        assert_eq!(state.user_id, user_id);
        assert!(state.remember_me);
        assert_eq!(state.method, Some(ChallengeMethod::Totp));
    }
}
