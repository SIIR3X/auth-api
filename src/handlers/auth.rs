//! Authentication handlers: register, login, logout, token refresh,
//! email verification, password reset, and 2FA challenge completion.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    error::AppError,
    services::{auth as auth_svc, two_factor as tf_svc},
    state::AppState,
};

use super::extractors::{AuthUser, ClientIp, UserAgent};

// Request types

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub email: String,
    pub password: String,
    pub locale: Option<String>,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub identifier: String,
    pub password: String,
    pub device_name: Option<String>,
}

#[derive(Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Deserialize)]
pub struct VerifyEmailQuery {
    pub token: String,
}

#[derive(Deserialize)]
pub struct ForgotPasswordRequest {
    pub email: String,
}

#[derive(Deserialize)]
pub struct ResetPasswordRequest {
    pub token: String,
    pub new_password: String,
}

#[derive(Deserialize)]
pub struct CompleteTwoFactorRequest {
    pub pre_auth_token: String,
    pub code: String,
}

#[derive(Deserialize)]
pub struct RecoveryLoginRequest {
    pub pre_auth_token: String,
    pub recovery_code: String,
}

// Response types

#[derive(Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub status: String,
    pub preferred_locale: String,
}

#[derive(Serialize)]
pub struct TokensResponse {
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum LoginResponse {
    Complete {
        access_token: String,
        refresh_token: String,
    },
    TwoFactor {
        two_factor_required: bool,
        pre_auth_token: String,
    },
}

// Handlers

pub async fn register(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    UserAgent(ua): UserAgent,
    Json(body): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<UserResponse>), AppError> {
    validate_email(&body.email)?;
    validate_password(&body.password)?;
    validate_username(&body.username)?;

    let locale = body.locale.as_deref().unwrap_or("en");

    let user = auth_svc::register(
        &state,
        &body.username,
        &body.email,
        &body.password,
        locale,
        ip,
        ua.as_deref(),
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(UserResponse {
            id: user.id,
            username: user.username,
            email: user.email,
            status: format!("{:?}", user.status).to_lowercase(),
            preferred_locale: user.preferred_locale,
        }),
    ))
}

pub async fn login(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    UserAgent(ua): UserAgent,
    Json(body): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    let result = auth_svc::login(
        &state,
        &body.identifier,
        &body.password,
        ip,
        ua.as_deref(),
        body.device_name.as_deref(),
    )
    .await?;

    let response = match result {
        auth_svc::LoginResult::Complete(tokens) => LoginResponse::Complete {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
        },
        auth_svc::LoginResult::TwoFactorRequired { pre_auth_token } => {
            LoginResponse::TwoFactor {
                two_factor_required: true,
                pre_auth_token,
            }
        }
    };

    Ok(Json(response))
}

pub async fn logout(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    auth: AuthUser,
) -> Result<StatusCode, AppError> {
    auth_svc::logout(&state, auth.session_id, auth.user_id, ip).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn refresh(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    UserAgent(ua): UserAgent,
    Json(body): Json<RefreshRequest>,
) -> Result<Json<TokensResponse>, AppError> {
    let tokens = auth_svc::refresh_token(&state, &body.refresh_token, ip, ua.as_deref()).await?;
    Ok(Json(TokensResponse {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
    }))
}

pub async fn verify_email(
    State(state): State<AppState>,
    Query(q): Query<VerifyEmailQuery>,
) -> Result<StatusCode, AppError> {
    auth_svc::verify_email(&state, &q.token).await?;
    Ok(StatusCode::OK)
}

pub async fn forgot_password(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    UserAgent(ua): UserAgent,
    Json(body): Json<ForgotPasswordRequest>,
) -> Result<StatusCode, AppError> {
    auth_svc::forgot_password(&state, &body.email, ip, ua.as_deref()).await?;
    Ok(StatusCode::OK)
}

pub async fn reset_password(
    State(state): State<AppState>,
    Json(body): Json<ResetPasswordRequest>,
) -> Result<StatusCode, AppError> {
    validate_password(&body.new_password)?;
    auth_svc::reset_password(&state, &body.token, &body.new_password).await?;
    Ok(StatusCode::OK)
}

pub async fn complete_two_factor(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    UserAgent(ua): UserAgent,
    Json(body): Json<CompleteTwoFactorRequest>,
) -> Result<Json<TokensResponse>, AppError> {
    let tokens = auth_svc::complete_two_factor_login(
        &state,
        &body.pre_auth_token,
        &body.code,
        ip,
        ua.as_deref(),
        None,
    )
    .await?;

    Ok(Json(TokensResponse {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
    }))
}

pub async fn recovery_login(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    UserAgent(ua): UserAgent,
    Json(body): Json<RecoveryLoginRequest>,
) -> Result<Json<TokensResponse>, AppError> {
    let tokens = auth_svc::complete_login_with_recovery(
        &state,
        &body.pre_auth_token,
        &body.recovery_code,
        ip,
        ua.as_deref(),
    )
    .await?;

    Ok(Json(TokensResponse {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
    }))
}

// Validation helpers

fn validate_email(email: &str) -> Result<(), AppError> {
    let has_at = email.contains('@');
    let parts: Vec<&str> = email.splitn(2, '@').collect();
    let valid = has_at && parts.len() == 2 && !parts[0].is_empty() && parts[1].contains('.');
    if !valid {
        return Err(AppError::Validation("invalid email address".into()));
    }
    Ok(())
}

fn validate_password(password: &str) -> Result<(), AppError> {
    if password.len() < 8 {
        return Err(AppError::Validation("password must be at least 8 characters".into()));
    }
    if password.len() > 128 {
        return Err(AppError::Validation("password must not exceed 128 characters".into()));
    }
    Ok(())
}

fn validate_username(username: &str) -> Result<(), AppError> {
    if username.len() < 3 || username.len() > 30 {
        return Err(AppError::Validation("username must be 3 to 30 characters".into()));
    }
    if !username.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
        return Err(AppError::Validation(
            "username may only contain letters, digits, underscores and hyphens".into(),
        ));
    }
    Ok(())
}
