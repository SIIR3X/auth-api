//! User profile handlers: read and update the authenticated user's profile.

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{error::AppError, services::user as user_svc, state::AppState};

use super::extractors::{AuthUser, ClientIp, UserAgent};

// Request types

#[derive(Deserialize)]
pub struct ChangeUsernameRequest {
    pub username: String,
}

#[derive(Deserialize)]
pub struct ChangeEmailRequest {
    pub email: String,
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Deserialize)]
pub struct ChangeLocaleRequest {
    pub locale: String,
}

// Response types

#[derive(Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub status: String,
    pub preferred_locale: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_login_at: Option<i64>,
    pub created_at: i64,
}

// Handlers

pub async fn me(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<UserResponse>, AppError> {
    let user = user_svc::get_profile(&state, auth.user_id).await?;

    Ok(Json(UserResponse {
        id: user.id,
        username: user.username,
        email: user.email,
        status: user_status_str(&user.status),
        preferred_locale: user.preferred_locale,
        email_verified_at: user.email_verified_at.map(|t| t.unix_timestamp()),
        last_login_at: user.last_login_at.map(|t| t.unix_timestamp()),
        created_at: user.created_at.unix_timestamp(),
    }))
}

pub async fn change_username(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    auth: AuthUser,
    Json(body): Json<ChangeUsernameRequest>,
) -> Result<StatusCode, AppError> {
    if body.username.len() < 3 || body.username.len() > 30 {
        return Err(AppError::Validation("username must be 3 to 30 characters".into()));
    }

    user_svc::change_username(&state, auth.user_id, &body.username, ip).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn change_email(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    UserAgent(ua): UserAgent,
    auth: AuthUser,
    Json(body): Json<ChangeEmailRequest>,
) -> Result<StatusCode, AppError> {
    user_svc::change_email(&state, auth.user_id, &body.email, ip, ua.as_deref()).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn change_password(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    auth: AuthUser,
    Json(body): Json<ChangePasswordRequest>,
) -> Result<StatusCode, AppError> {
    if body.new_password.len() < 8 {
        return Err(AppError::Validation("password must be at least 8 characters".into()));
    }

    user_svc::change_password(
        &state,
        auth.user_id,
        &body.current_password,
        &body.new_password,
        ip,
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn change_locale(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<ChangeLocaleRequest>,
) -> Result<StatusCode, AppError> {
    user_svc::change_locale(&state, auth.user_id, &body.locale).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn user_status_str(status: &crate::domain::user::UserStatus) -> String {
    use crate::domain::user::UserStatus;
    match status {
        UserStatus::Active => "active",
        UserStatus::Inactive => "inactive",
        UserStatus::Suspended => "suspended",
        UserStatus::PendingVerification => "pending_verification",
    }
    .to_owned()
}
