//! User profile management: read profile, change username/password/locale.
//!
//! Email changes are handled by the email_change service (two-step OTP flow).
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
    utils::password,
};

use super::{auth as auth_svc, reauth as reauth_svc};

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
            action: AuditAction::UsernameChanged,
            ip_address: ip,
            metadata: json!({}),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

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

    // Collect active session IDs before deletion so we can invalidate their
    // Redis cache entries - otherwise the session validity cache would stay
    // warm for up to SESSION_CACHE_TTL_SECS after the account is gone.
    let session_ids: Vec<_> = session_repo::find_active_by_user(&state.db, user_id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|s| s.id)
        .collect();

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

    auth_svc::invalidate_session_caches(state, &session_ids).await;

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
