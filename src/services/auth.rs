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
        recovery_code,
        role,
        session::{self as session_repo, NewSession},
        token::{self, NewEmailVerificationToken, NewPasswordResetToken},
        two_factor as tf_repo,
        user::{self as user_repo, NewUser},
    },
    state::AppState,
    utils::{crypto, jwt::Claims, password, time, totp},
};

use super::email;

// Constants

/// Max failed attempts per identifier within the window before lockout.
const MAX_FAILURES_BY_IDENTIFIER: i64 = 10;
/// Max failed attempts per IP within the window before lockout.
const MAX_FAILURES_BY_IP: i64 = 30;
/// Lookback window for brute-force counting (15 minutes).
const BRUTE_FORCE_WINDOW_SECS: i64 = 900;
/// Pre-auth (2FA challenge) token TTL in Redis.
const PRE_AUTH_TTL_SECS: u64 = 300;
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

pub enum LoginResult {
    Complete(AuthTokens),
    /// 2FA is required; submit this token with the code to complete login.
    TwoFactorRequired { pre_auth_token: String },
}

// Register

pub async fn register(
    state: &AppState,
    username: &str,
    email: &str,
    password_plaintext: &str,
    locale: &str,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
) -> Result<User, AppError> {
    // Uniqueness checks
    if user_repo::find_by_email(&state.db, email).await?.is_some() {
        return Err(AppError::Conflict("email_taken"));
    }
    if user_repo::find_by_username(&state.db, username).await?.is_some() {
        return Err(AppError::Conflict("username_taken"));
    }

    let hash = password::hash(password_plaintext, &state.config.crypto)
        .map_err(|e| AppError::Internal(e.into()))?;

    let user = user_repo::create(
        &state.db,
        &NewUser { username, email, password_hash: &hash, preferred_locale: locale },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    // Assign default role if one exists
    if let Some(role) = role::find_default(&state.db).await.map_err(|e| AppError::Internal(e.into()))? {
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

    email::send_verification_email(
        &state.mailer,
        &state.templates,
        &state.config.mail,
        email,
        username,
        locale,
        &raw_token,
        &state.config.server.public_url,
    )
    .await?;

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user.id),
            request_id: None,
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
) -> Result<LoginResult, AppError> {
    // Brute-force guard
    if let Some(ip_val) = ip {
        let failures = login_attempt::count_recent_failures_by_ip(&state.db, ip_val, BRUTE_FORCE_WINDOW_SECS)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        if failures >= MAX_FAILURES_BY_IP {
            return Err(AppError::RateLimitExceeded);
        }
    }

    let failures =
        login_attempt::count_recent_failures_by_identifier(&state.db, identifier, BRUTE_FORCE_WINDOW_SECS)
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
            record_failure(&state.db, None, identifier, LoginFailureReason::UnknownIdentifier, ip, user_agent).await;
            return Err(AppError::InvalidCredentials);
        }
        (Some(u), false) => {
            record_failure(&state.db, Some(u.id), identifier, LoginFailureReason::InvalidPassword, ip, user_agent).await;
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

    // 2FA: issue a short-lived pre-auth token and pause login
    let has_2fa = tf_repo::find_primary_by_user(&state.db, user.id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .is_some();

    if has_2fa {
        let pre_auth_token = Uuid::new_v4().to_string();
        let redis_key = format!("pre_auth:{}", pre_auth_token);

        let mut conn = state.redis.get().await.map_err(|e| AppError::Internal(e.into()))?;
        conn.set_ex::<_, _, ()>(&redis_key, user.id.to_string(), PRE_AUTH_TTL_SECS)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;

        return Ok(LoginResult::TwoFactorRequired { pre_auth_token });
    }

    let tokens = issue_tokens(state, &user, ip, user_agent, device_name).await?;

    user_repo::update_last_login(&state.db, user.id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

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
            request_id: None,
            action: AuditAction::Login,
            ip_address: ip,
            metadata: json!({}),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

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
) -> Result<AuthTokens, AppError> {
    let redis_key = format!("pre_auth:{}", pre_auth_token);

    let mut conn = state.redis.get().await.map_err(|e| AppError::Internal(e.into()))?;

    let user_id_str: Option<String> = conn.get(&redis_key).await.map_err(|e| AppError::Internal(e.into()))?;

    let user_id_str = user_id_str.ok_or(AppError::TokenInvalid)?;

    // Consume immediately to prevent reuse
    conn.del::<_, ()>(&redis_key)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

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

    let encrypted_secret = method.totp_secret.as_deref().ok_or(AppError::Unauthorized)?;

    let valid = totp::verify_code(encrypted_secret, code, &enc_key)
        .map_err(|e| AppError::Internal(e.into()))?;

    if !valid {
        audit::append(
            &state.db,
            &NewAuditEntry {
                user_id: Some(user.id),
                request_id: None,
                action: AuditAction::TwoFactorFailed,
                ip_address: ip,
                metadata: json!({}),
            },
        )
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

        return Err(AppError::TwoFactorFailed);
    }

    let tokens = issue_tokens(state, &user, ip, user_agent, device_name).await?;

    user_repo::update_last_login(&state.db, user.id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user.id),
            request_id: None,
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
) -> Result<AuthTokens, AppError> {
    let token_hash = crypto::sha256(raw_token.as_bytes());

    let session = session_repo::find_by_token_hash(&state.db, &token_hash)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::TokenInvalid)?;

    // Revoked session that is presented again = replay attack
    if session.revoked_at.is_some() {
        session_repo::revoke_family(&state.db, session.id)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;

        audit::append(
            &state.db,
            &NewAuditEntry {
                user_id: Some(session.user_id),
                request_id: None,
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
    ip: Option<IpNetwork>,
) -> Result<(), AppError> {
    session_repo::revoke(&state.db, session_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user_id),
            request_id: None,
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

pub async fn verify_email(state: &AppState, raw_token: &str) -> Result<(), AppError> {
    use crate::domain::token::OneTimeToken;

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
            request_id: None,
            action: AuditAction::EmailVerified,
            ip_address: None,
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
) -> Result<(), AppError> {
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

    email::send_password_reset_email(
        &state.mailer,
        &state.templates,
        &state.config.mail,
        email,
        &user.username,
        &user.preferred_locale,
        &raw_token,
        &state.config.server.public_url,
    )
    .await?;

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user.id),
            request_id: None,
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
) -> Result<(), AppError> {
    use crate::domain::token::OneTimeToken;

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
            request_id: None,
            action: AuditAction::PasswordResetCompleted,
            ip_address: None,
            metadata: json!({}),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    Ok(())
}

// Internal helpers

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

    let access_token = build_access_token(user, session.id, state)?;

    Ok(AuthTokens { access_token, refresh_token: raw_token, session })
}

fn build_access_token(user: &User, session_id: uuid::Uuid, state: &AppState) -> Result<String, AppError> {
    let exp = time::in_secs(state.config.jwt.access_expiry_secs).unix_timestamp();
    let claims = Claims::new(user.id, session_id, exp);
    crate::utils::jwt::encode_token(&claims, &state.config.jwt.secret)
        .map_err(|e| AppError::Internal(e.into()))
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
pub async fn resend_verification_email(
    state: &AppState,
    user_id: Uuid,
    email: &str,
    username: &str,
    locale: &str,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
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

    email::send_verification_email(
        &state.mailer,
        &state.templates,
        &state.config.mail,
        email,
        username,
        locale,
        &raw_token,
        &state.config.server.public_url,
    )
    .await?;

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user_id),
            request_id: None,
            action: AuditAction::EmailVerificationSent,
            ip_address: ip,
            metadata: json!({}),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    Ok(())
}

// Complete 2FA login with a recovery code instead of a TOTP code.
pub async fn complete_login_with_recovery(
    state: &AppState,
    pre_auth_token: &str,
    recovery_code_plaintext: &str,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
) -> Result<AuthTokens, AppError> {
    let redis_key = format!("pre_auth:{}", pre_auth_token);
    let mut conn = state.redis.get().await.map_err(|e| AppError::Internal(e.into()))?;

    let user_id_str: Option<String> = conn.get(&redis_key).await.map_err(|e| AppError::Internal(e.into()))?;
    let user_id_str = user_id_str.ok_or(AppError::TokenInvalid)?;

    conn.del::<_, ()>(&redis_key).await.map_err(|e| AppError::Internal(e.into()))?;

    let user_id: Uuid = user_id_str.parse().map_err(|_| AppError::TokenInvalid)?;

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
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::TwoFactorFailed)?;

    if record.user_id != user_id {
        return Err(AppError::TwoFactorFailed);
    }

    let consumed = recovery_code::consume(&state.db, record.id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    if !consumed {
        return Err(AppError::TwoFactorFailed);
    }

    let tokens = issue_tokens(state, &user, ip, user_agent, None).await?;

    user_repo::update_last_login(&state.db, user.id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user.id),
            request_id: None,
            action: AuditAction::Login,
            ip_address: ip,
            metadata: json!({"two_factor": "recovery_code"}),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    Ok(tokens)
}
