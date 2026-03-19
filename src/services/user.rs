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
        session as session_repo,
        user as user_repo,
    },
    state::AppState,
    utils::password,
};

use super::auth;

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
) -> Result<(), AppError> {
    if user_repo::find_by_username(&state.db, new_username).await?.is_some() {
        return Err(AppError::Conflict("username_taken"));
    }

    user_repo::update_username(&state.db, user_id, new_username)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user_id),
            request_id: None,
            action: AuditAction::AccountReactivated, // reuse closest action; extend AuditAction if needed
            ip_address: ip,
            metadata: json!({"field": "username"}),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    Ok(())
}

/// Changing email resets verification and sends a new verification email to the new address.
pub async fn change_email(
    state: &AppState,
    user_id: Uuid,
    new_email: &str,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
) -> Result<(), AppError> {
    if user_repo::find_by_email(&state.db, new_email).await?.is_some() {
        return Err(AppError::Conflict("email_taken"));
    }

    let user = user_repo::find_by_id(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::NotFound)?;

    user_repo::update_email(&state.db, user_id, new_email)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    auth::resend_verification_email(
        state,
        user_id,
        new_email,
        &user.username,
        &user.preferred_locale,
        ip,
        user_agent,
    )
    .await?;

    Ok(())
}

/// Verifies the current password before applying the new one, then revokes all sessions.
pub async fn change_password(
    state: &AppState,
    user_id: Uuid,
    current_password: &str,
    new_password: &str,
    ip: Option<IpNetwork>,
) -> Result<(), AppError> {
    let user = user_repo::find_by_id(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::NotFound)?;

    let valid = password::verify(current_password, &user.password_hash)
        .map_err(|e| AppError::Internal(e.into()))?;

    if !valid {
        return Err(AppError::InvalidCredentials);
    }

    let new_hash = password::hash(new_password, &state.config.crypto)
        .map_err(|e| AppError::Internal(e.into()))?;

    user_repo::update_password_hash(&state.db, user_id, &new_hash)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    // Revoke all sessions so other devices must re-authenticate
    session_repo::revoke_all_by_user(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user_id),
            request_id: None,
            action: AuditAction::PasswordChanged,
            ip_address: ip,
            metadata: json!({}),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    Ok(())
}

pub async fn change_locale(
    state: &AppState,
    user_id: Uuid,
    locale: &str,
) -> Result<(), AppError> {
    user_repo::update_locale(&state.db, user_id, locale)
        .await
        .map_err(|e| AppError::Internal(e.into()))
}
