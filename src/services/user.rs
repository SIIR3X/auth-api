//! User profile management: read profile, change username/email/password/locale.
//!
//! Email changes reset verification state and trigger a new verification email.
//! Password changes revoke all active sessions to force re-login.

use ipnetwork::IpNetwork;
use serde_json::json;
use uuid::Uuid;

use crate::{
    domain::{audit::AuditAction, user::User},
    error::AppError,
    repositories::{
        audit::{self, NewAuditEntry},
        session as session_repo, user as user_repo,
    },
    state::AppState,
    utils::{crypto, password, time},
};

use super::{auth as auth_svc, reauth as reauth_svc};

const EMAIL_TOKEN_EXPIRY_SECS: u64 = 60 * 60 * 24;

/// Verifies a user's current password. Returns Err(InvalidCredentials) on mismatch.
pub async fn verify_password(
    state: &AppState,
    user_id: Uuid,
    password: &str,
) -> Result<(), AppError> {
    let user = user_repo::find_by_id(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::NotFound)?;

    let valid = password::verify_async(password, &user.password_hash)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    if !valid {
        return Err(AppError::InvalidCredentials);
    }

    Ok(())
}

pub async fn get_profile(state: &AppState, user_id: Uuid) -> Result<User, AppError> {
    user_repo::find_by_id(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::NotFound)
}

pub async fn change_username(
    state: &AppState,
    user_id: Uuid,
    new_username: &str,
    ip: Option<IpNetwork>,
    request_id: Option<Uuid>,
) -> Result<(), AppError> {
    if user_repo::find_by_username(&state.db, new_username)
        .await?
        .is_some()
    {
        return Err(AppError::Conflict("username_taken"));
    }

    user_repo::update_username(&state.db, user_id, new_username)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user_id),
            request_id,
            action: AuditAction::AccountReactivated, // reuse closest action; extend AuditAction if needed
            ip_address: ip,
            metadata: json!({"field": "username"}),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    Ok(())
}

/// Changing email resets verification, revokes all other sessions, and sends a new verification email.
/// Requires the current email to already be verified.
#[allow(clippy::too_many_arguments)]
pub async fn change_email(
    state: &AppState,
    user_id: Uuid,
    current_session_id: Uuid,
    new_email: &str,
    current_password: Option<&str>,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    request_id: Option<Uuid>,
) -> Result<(), AppError> {
    reauth_svc::require_recent_reauth_or_password(
        state,
        user_id,
        current_session_id,
        current_password,
        ip,
        request_id,
        "change_email",
    )
    .await?;

    let raw_token = crypto::generate_token();
    let token_hash = crypto::sha256(raw_token.as_bytes());
    let other_session_ids = session_repo::find_active_by_user(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .into_iter()
        .filter(|session| session.id != current_session_id)
        .map(|session| session.id)
        .collect::<Vec<_>>();

    let (username, preferred_locale) = {
        let mut tx = state
            .db
            .begin()
            .await
            .map_err(|e| AppError::Internal(e.into()))?;

        let email_taken: Option<(i64,)> =
            sqlx::query_as("SELECT 1 FROM users WHERE email = $1 AND id <> $2 LIMIT 1")
                .bind(new_email)
                .bind(user_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| AppError::Internal(e.into()))?;

        if email_taken.is_some() {
            return Err(AppError::Conflict("email_taken"));
        }

        let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1 FOR UPDATE")
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| AppError::Internal(e.into()))?
            .ok_or(AppError::NotFound)?;

        if user.email_verified_at.is_none() {
            return Err(AppError::EmailNotVerified);
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

        sqlx::query(
            "UPDATE users
             SET email = $2,
                 email_verified_at = NULL,
                 status = 'pending_verification'::user_status
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
            "INSERT INTO email_verification_tokens
                 (user_id, token_hash, expires_at, request_ip, request_user_agent, target_email)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(user_id)
        .bind(token_hash.as_slice())
        .bind(time::in_secs(EMAIL_TOKEN_EXPIRY_SECS))
        .bind(ip)
        .bind(user_agent)
        .bind(new_email)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

        sqlx::query(
            "INSERT INTO audit_log (user_id, request_id, action, ip_address, metadata)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(Some(user_id))
        .bind(request_id)
        .bind(AuditAction::EmailVerificationSent)
        .bind(ip)
        .bind(json!({
            "reason": "email_change",
            "target_email": new_email,
        }))
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

        tx.commit()
            .await
            .map_err(|e| AppError::Internal(e.into()))?;

        (user.username, user.preferred_locale)
    };

    auth_svc::invalidate_session_caches(state, &other_session_ids).await;

    let mailer = state.mailer.clone();
    let templates = state.templates.clone();
    let mail_cfg = state.config.mail.clone();
    let email_to = new_email.to_string();
    let username = username.clone();
    let locale = preferred_locale.clone();
    let raw_token = raw_token.clone();
    let public_url = state.config.server.public_url.clone();
    super::email::dispatch_best_effort("email_change_verification", async move {
        super::email::send_verification_email(
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

    Ok(())
}

/// Verifies the current password before applying the new one, then revokes all sessions.
/// Requires a verified email.
pub async fn change_password(
    state: &AppState,
    user_id: Uuid,
    current_session_id: Uuid,
    current_password: Option<&str>,
    new_password: &str,
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
        "change_password",
    )
    .await?;

    let user = user_repo::find_by_id(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::NotFound)?;

    if user.email_verified_at.is_none() {
        return Err(AppError::EmailNotVerified);
    }

    let new_hash = password::hash_async(new_password, &state.config.crypto)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    user_repo::update_password_hash(&state.db, user_id, &new_hash)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    let revoked_session_ids = session_repo::find_active_by_user(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .into_iter()
        .map(|session| session.id)
        .collect::<Vec<_>>();

    // Revoke all sessions so other devices must re-authenticate
    session_repo::revoke_all_by_user(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    auth_svc::invalidate_session_caches(state, &revoked_session_ids).await;

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user_id),
            request_id,
            action: AuditAction::PasswordChanged,
            ip_address: ip,
            metadata: json!({}),
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
    super::email::dispatch_best_effort("password_changed_email", async move {
        super::email::send_password_changed(
            &mailer,
            templates.as_ref(),
            &mail_cfg,
            &email_to,
            &username,
            &locale,
        )
        .await
    });

    Ok(())
}

/// Permanently deletes the user account and all associated data.
/// Requires the current password for confirmation.
/// The audit entry is written before deletion so it can reference the user_id.
pub async fn delete_account(
    state: &AppState,
    user_id: Uuid,
    current_session_id: Uuid,
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
        "delete_account",
    )
    .await?;

    let user = user_repo::find_by_id(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::NotFound)?;

    // Append the audit entry before deletion (audit_log uses SET NULL on user FK).
    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user_id),
            request_id,
            action: AuditAction::AccountDeleted,
            ip_address: ip,
            metadata: serde_json::json!({"username": user.username, "email": user.email}),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    user_repo::delete(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    Ok(())
}

pub async fn change_locale(state: &AppState, user_id: Uuid, locale: &str) -> Result<(), AppError> {
    user_repo::update_locale(&state.db, user_id, locale)
        .await
        .map_err(|e| AppError::Internal(e.into()))
}

pub async fn reauthenticate(
    state: &AppState,
    user_id: Uuid,
    session_id: Uuid,
    current_password: &str,
    ip: Option<IpNetwork>,
    request_id: Option<Uuid>,
) -> Result<(), AppError> {
    reauth_svc::reauthenticate(
        state,
        user_id,
        session_id,
        current_password,
        ip,
        request_id,
        "user_initiated",
    )
    .await
}
