//! Authentication handlers: register, login, logout, token refresh,
//! email verification, password reset, and 2FA challenge completion.

use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    error::AppError,
    services::{auth as auth_svc, captcha as captcha_svc, email_2fa as email_2fa_svc},
    state::AppState,
};

use super::{
    extractors::{AuthUser, ClientIp, RequestId, UserAgent},
    user::{user_status_str, validate_locale},
};

// Request types

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub email: String,
    pub password: String,
    pub locale: Option<String>,
    /// hCaptcha token from the frontend widget. Required when CAPTCHA_SECRET is configured.
    pub captcha_token: Option<String>,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub identifier: String,
    pub password: String,
    pub device_name: Option<String>,
    pub captcha_token: Option<String>,
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
    pub captcha_token: Option<String>,
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

#[derive(Deserialize)]
pub struct CompleteEmailTwoFactorRequest {
    pub pre_auth_token: String,
    pub code: String,
}

#[derive(Deserialize)]
pub struct ResendEmailTwoFactorRequest {
    pub pre_auth_token: String,
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
        /// "totp" or "webauthn"
        two_factor_method: String,
        pre_auth_token: String,
    },
}

// Handlers

pub async fn register(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    UserAgent(ua): UserAgent,
    RequestId(rid): RequestId,
    Json(body): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<UserResponse>), AppError> {
    validate_email(&body.email)?;
    validate_password(&body.password)?;
    validate_username(&body.username)?;

    let locale = body.locale.as_deref().unwrap_or("en");
    validate_locale(locale)?;

    // Verify CAPTCHA if a secret is configured; skip silently otherwise.
    let captcha_token = body.captcha_token.as_deref().unwrap_or("");
    captcha_svc::verify(&state, captcha_token).await?;

    let user = auth_svc::register(
        &state,
        &body.username,
        &body.email,
        &body.password,
        locale,
        ip,
        ua.as_deref(),
        rid,
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(UserResponse {
            id: user.id,
            username: user.username,
            email: user.email,
            status: user_status_str(&user.status),
            preferred_locale: user.preferred_locale,
        }),
    ))
}

pub async fn login(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    UserAgent(ua): UserAgent,
    RequestId(rid): RequestId,
    Json(body): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    let captcha_token = body.captcha_token.as_deref().unwrap_or("");
    captcha_svc::verify(&state, captcha_token).await?;

    let result = auth_svc::login(
        &state,
        &body.identifier,
        &body.password,
        ip,
        ua.as_deref(),
        body.device_name.as_deref(),
        rid,
    )
    .await?;

    let response = match result {
        auth_svc::LoginResult::Complete(tokens) => LoginResponse::Complete {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
        },
        auth_svc::LoginResult::TwoFactorRequired {
            pre_auth_token,
            method,
        } => LoginResponse::TwoFactor {
            two_factor_required: true,
            two_factor_method: method,
            pre_auth_token,
        },
    };

    Ok(Json(response))
}

pub async fn logout(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    auth: AuthUser,
) -> Result<StatusCode, AppError> {
    auth_svc::logout(
        &state,
        auth.session_id,
        auth.user_id,
        auth.jti,
        auth.token_exp,
        ip,
        auth.request_id,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn refresh(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    UserAgent(ua): UserAgent,
    RequestId(rid): RequestId,
    Json(body): Json<RefreshRequest>,
) -> Result<Json<TokensResponse>, AppError> {
    let tokens =
        auth_svc::refresh_token(&state, &body.refresh_token, ip, ua.as_deref(), rid).await?;
    Ok(Json(TokensResponse {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
    }))
}

pub async fn verify_email(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    RequestId(rid): RequestId,
    Query(q): Query<VerifyEmailQuery>,
) -> Result<StatusCode, AppError> {
    auth_svc::verify_email(&state, &q.token, ip, rid).await?;
    Ok(StatusCode::OK)
}

pub async fn forgot_password(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    UserAgent(ua): UserAgent,
    RequestId(rid): RequestId,
    Json(body): Json<ForgotPasswordRequest>,
) -> Result<StatusCode, AppError> {
    let captcha_token = body.captcha_token.as_deref().unwrap_or("");
    captcha_svc::verify(&state, captcha_token).await?;

    auth_svc::forgot_password(&state, &body.email, ip, ua.as_deref(), rid).await?;
    Ok(StatusCode::OK)
}

pub async fn reset_password(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    RequestId(rid): RequestId,
    Json(body): Json<ResetPasswordRequest>,
) -> Result<StatusCode, AppError> {
    validate_password(&body.new_password)?;
    auth_svc::reset_password(&state, &body.token, &body.new_password, ip, rid).await?;
    Ok(StatusCode::OK)
}

pub async fn complete_two_factor(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    UserAgent(ua): UserAgent,
    RequestId(rid): RequestId,
    Json(body): Json<CompleteTwoFactorRequest>,
) -> Result<Json<TokensResponse>, AppError> {
    let tokens = auth_svc::complete_two_factor_login(
        &state,
        &body.pre_auth_token,
        &body.code,
        ip,
        ua.as_deref(),
        None,
        rid,
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
    RequestId(rid): RequestId,
    Json(body): Json<RecoveryLoginRequest>,
) -> Result<Json<TokensResponse>, AppError> {
    let tokens = auth_svc::complete_login_with_recovery(
        &state,
        &body.pre_auth_token,
        &body.recovery_code,
        ip,
        ua.as_deref(),
        rid,
    )
    .await?;

    Ok(Json(TokensResponse {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
    }))
}

pub async fn complete_email_two_factor(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    UserAgent(ua): UserAgent,
    RequestId(rid): RequestId,
    Json(body): Json<CompleteEmailTwoFactorRequest>,
) -> Result<Json<TokensResponse>, AppError> {
    let tokens = auth_svc::complete_email_2fa_login(
        &state,
        &body.pre_auth_token,
        &body.code,
        ip,
        ua.as_deref(),
        None,
        rid,
    )
    .await?;

    Ok(Json(TokensResponse {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
    }))
}

pub async fn resend_email_two_factor(
    State(state): State<AppState>,
    Json(body): Json<ResendEmailTwoFactorRequest>,
) -> Result<StatusCode, AppError> {
    // Resolve user_id from pre_auth_token without revealing whether it exists.
    let user_id = auth_svc::resolve_pre_auth(&state, &body.pre_auth_token)
        .await?
        .user_id;

    // Fire-and-forget: errors are non-fatal to avoid enumeration via timing.
    let _ = email_2fa_svc::send_code(&state, user_id).await;
    Ok(StatusCode::NO_CONTENT)
}

// Validation helpers

fn validate_email(email: &str) -> Result<(), AppError> {
    if !email_address::EmailAddress::is_valid(email) {
        return Err(AppError::Validation("invalid email address".into()));
    }
    Ok(())
}

fn validate_password(password: &str) -> Result<(), AppError> {
    if password.len() < 8 {
        return Err(AppError::Validation(
            "password must be at least 8 characters".into(),
        ));
    }
    if password.len() > 128 {
        return Err(AppError::Validation(
            "password must not exceed 128 characters".into(),
        ));
    }
    Ok(())
}

fn validate_username(username: &str) -> Result<(), AppError> {
    if username.len() < 3 || username.len() > 30 {
        return Err(AppError::Validation(
            "username must be 3 to 30 characters".into(),
        ));
    }
    if !username.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Err(AppError::Validation(
            "username may only contain letters, digits and underscores".into(),
        ));
    }
    Ok(())
}
