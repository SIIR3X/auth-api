//! User profile handlers: read and update the authenticated user's profile.

use axum::{Json, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    error::AppError,
    services::{email_change as email_change_svc, reauth as reauth_svc, user as user_svc},
    state::AppState,
};

use super::extractors::{AuthUser, ClientIp};

// Request types

#[derive(Deserialize)]
pub struct ChangeUsernameRequest {
    pub username: String,
    pub current_password: Option<String>,
}

#[derive(Serialize)]
pub struct FlowTokenResponse {
    pub flow_token: String,
}

#[derive(Deserialize)]
pub struct VerifyCurrentEmailRequest {
    pub flow_token: String,
    pub code: String,
}

#[derive(Deserialize)]
pub struct SubmitNewEmailRequest {
    pub flow_token: String,
    pub new_email: String,
}

#[derive(Deserialize)]
pub struct ConfirmNewEmailRequest {
    pub flow_token: String,
    pub code: String,
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: Option<String>,
    pub new_password: String,
}

#[derive(Deserialize)]
pub struct ChangeLocaleRequest {
    pub locale: String,
}

#[derive(Deserialize)]
pub struct DeleteAccountRequest {
    pub current_password: Option<String>,
}

#[derive(Deserialize)]
pub struct ReauthenticateRequest {
    pub current_password: String,
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
        return Err(AppError::Validation(
            "username must be 3 to 30 characters".into(),
        ));
    }
    if !body
        .username
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_')
    {
        return Err(AppError::Validation(
            "username may only contain letters, digits and underscores".into(),
        ));
    }

    reauth_svc::require_recent_reauth_or_password(
        &state,
        auth.user_id,
        auth.session_id,
        body.current_password.as_deref(),
        ip,
        auth.request_id,
        "change_username",
    )
    .await?;

    user_svc::change_username(&state, auth.user_id, &body.username, ip, auth.request_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn start_email_change(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    auth: AuthUser,
) -> Result<Json<FlowTokenResponse>, AppError> {
    let flow_token = email_change_svc::start(&state, auth.user_id, ip, auth.request_id).await?;
    Ok(Json(FlowTokenResponse { flow_token }))
}

pub async fn verify_current_email(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<VerifyCurrentEmailRequest>,
) -> Result<StatusCode, AppError> {
    email_change_svc::verify_current(&state, auth.user_id, &body.flow_token, &body.code).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn submit_new_email(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    auth: AuthUser,
    Json(body): Json<SubmitNewEmailRequest>,
) -> Result<StatusCode, AppError> {
    if !email_address::EmailAddress::is_valid(&body.new_email) {
        return Err(AppError::Validation("invalid email address".into()));
    }
    email_change_svc::submit_new(
        &state,
        auth.user_id,
        &body.flow_token,
        &body.new_email,
        ip,
        auth.request_id,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn confirm_new_email(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    auth: AuthUser,
    Json(body): Json<ConfirmNewEmailRequest>,
) -> Result<StatusCode, AppError> {
    email_change_svc::confirm_new(
        &state,
        auth.user_id,
        auth.session_id,
        &body.flow_token,
        &body.code,
        ip,
        auth.request_id,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn change_password(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    auth: AuthUser,
    Json(body): Json<ChangePasswordRequest>,
) -> Result<StatusCode, AppError> {
    validate_password(&body.new_password)?;

    user_svc::change_password(
        &state,
        auth.user_id,
        auth.session_id,
        body.current_password.as_deref(),
        &body.new_password,
        ip,
        auth.request_id,
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn change_locale(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<ChangeLocaleRequest>,
) -> Result<StatusCode, AppError> {
    validate_locale(&body.locale)?;
    user_svc::change_locale(&state, auth.user_id, &body.locale).await?;
    Ok(StatusCode::NO_CONTENT)
}

const SUPPORTED_LOCALES: &[&str] = &["en", "fr"];

pub fn validate_locale(locale: &str) -> Result<(), AppError> {
    if !SUPPORTED_LOCALES.contains(&locale) {
        return Err(AppError::Validation(format!(
            "unsupported locale; accepted values: {}",
            SUPPORTED_LOCALES.join(", ")
        )));
    }
    Ok(())
}

/// Validates a plaintext password against the application password policy.
///
/// Rules (all must be satisfied):
///   - at least 10 characters
///   - no more than 128 characters (Argon2id DoS guard)
///   - at least one ASCII digit (0-9)
///   - at least one ASCII uppercase letter (A-Z)
///   - at least one ASCII punctuation / symbol character
///
/// Note: NIST SP 800-63B recommends favouring length over composition rules.
/// These constraints are intentionally modest; raising the minimum length is
/// more effective than adding more character-class requirements.
pub fn validate_password(password: &str) -> Result<(), AppError> {
    if password.len() < 10 {
        return Err(AppError::Validation(
            "password must be at least 10 characters".into(),
        ));
    }
    if password.len() > 128 {
        return Err(AppError::Validation(
            "password must not exceed 128 characters".into(),
        ));
    }
    if !password.chars().any(|c| c.is_ascii_digit()) {
        return Err(AppError::Validation(
            "password must contain at least one digit (0-9)".into(),
        ));
    }
    if !password.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(AppError::Validation(
            "password must contain at least one uppercase letter (A-Z)".into(),
        ));
    }
    // is_ascii_punctuation covers: !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
    if !password.chars().any(|c| c.is_ascii_punctuation()) {
        return Err(AppError::Validation(
            "password must contain at least one special character (!@#$... etc.)".into(),
        ));
    }
    Ok(())
}

pub async fn delete_account(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    auth: AuthUser,
    Json(body): Json<DeleteAccountRequest>,
) -> Result<StatusCode, AppError> {
    user_svc::delete_account(
        &state,
        auth.user_id,
        auth.session_id,
        body.current_password.as_deref(),
        ip,
        auth.request_id,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn reauthenticate(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    auth: AuthUser,
    Json(body): Json<ReauthenticateRequest>,
) -> Result<StatusCode, AppError> {
    user_svc::reauthenticate(
        &state,
        auth.user_id,
        auth.session_id,
        &body.current_password,
        ip,
        auth.request_id,
    )
    .await?;
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
