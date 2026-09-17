//! Authentication handlers: register, login, logout, token refresh,
//! email verification, password reset, and 2FA challenge completion.

use axum::{Json, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};

use crate::{
    error::AppError,
    services::{auth as auth_svc, captcha as captcha_svc, email_2fa as email_2fa_svc},
    state::AppState,
};

use super::{
    extractors::{AuthUser, ClientIp, RequestId, UserAgent},
    user::{validate_locale, validate_password},
};

// Request types

#[derive(Deserialize, utoipa::ToSchema)]
pub struct RegisterRequest {
    pub username: String,
    pub email: String,
    pub password: String,
    pub locale: Option<String>,
    /// hCaptcha token from the frontend widget. Required when CAPTCHA_SECRET is configured.
    pub captcha_token: Option<String>,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct LoginRequest {
    pub identifier: String,
    pub password: String,
    pub device_name: Option<String>,
    /// When true, issues a long-lived refresh token (30 days).
    /// When false or omitted, issues a short-lived token (24 h).
    pub remember_me: Option<bool>,
    pub captcha_token: Option<String>,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct VerifyEmailRequest {
    pub token: String,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct ResendVerificationRequest {
    pub email: String,
    pub captcha_token: Option<String>,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct ForgotPasswordRequest {
    pub email: String,
    pub captcha_token: Option<String>,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct MagicLinkRequest {
    pub email: String,
    pub captcha_token: Option<String>,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct CompleteMagicLinkRequest {
    /// The token from the link's fragment.
    pub token: String,
    pub device_name: Option<String>,
    /// When true, issues a long-lived refresh token.
    pub remember_me: Option<bool>,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct ResetPasswordRequest {
    pub token: String,
    pub new_password: String,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct CompleteTwoFactorRequest {
    pub pre_auth_token: String,
    pub code: String,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct RecoveryLoginRequest {
    pub pre_auth_token: String,
    pub recovery_code: String,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct CompleteEmailTwoFactorRequest {
    pub pre_auth_token: String,
    pub code: String,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct ResendEmailTwoFactorRequest {
    pub pre_auth_token: String,
}

// Response types

/// Registration answer. Identical whether the address was free or already had
/// an account, so it cannot be used to enumerate accounts.
#[derive(Serialize, utoipa::ToSchema)]
pub struct RegistrationAccepted {
    pub status: &'static str,
    pub message: &'static str,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct TokensResponse {
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Serialize, utoipa::ToSchema)]
#[serde(untagged)]
pub enum LoginResponse {
    Complete {
        access_token: String,
        refresh_token: String,
    },
    TwoFactor {
        two_factor_required: bool,
        /// "totp" or "email"
        two_factor_method: String,
        pre_auth_token: String,
    },
}

// Handlers

#[utoipa::path(
    post,
    path = "/auth/register",
    tag = "auth",
    request_body = RegisterRequest,
    responses(
        (status = 202, description = "Accepted; identical whether or not the address is taken", body = RegistrationAccepted),
        (status = 409, description = "Username already taken (`username_taken`); a taken address is not revealed", body = crate::error::ErrorBody),
        (status = 422, description = "Invalid input", body = crate::error::ErrorBody),
        (status = 429, description = "Rate limited; see Retry-After"),
    ),
)]
pub async fn register(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    UserAgent(ua): UserAgent,
    RequestId(rid): RequestId,
    Json(body): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegistrationAccepted>), AppError> {
    validate_email(&body.email)?;
    validate_password(&body.password)?;
    validate_username(&body.username)?;

    let locale = body.locale.as_deref().unwrap_or("en");
    validate_locale(locale)?;

    // Verify CAPTCHA if a secret is configured; skip silently otherwise.
    let captcha_token = body.captcha_token.as_deref().unwrap_or("");
    captcha_svc::verify(&state, captcha_token).await?;

    auth_svc::register(
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
        StatusCode::ACCEPTED,
        Json(RegistrationAccepted {
            status: "pending_verification",
            message: "Check your inbox to verify your email address.",
        }),
    ))
}

#[utoipa::path(
    post,
    path = "/auth/login",
    tag = "auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Tokens, or a two-factor challenge", body = LoginResponse),
        (status = 401, description = "Invalid credentials", body = crate::error::ErrorBody),
        (status = 403, description = "Account locked, suspended or not verified", body = crate::error::ErrorBody),
        (status = 422, description = "Invalid input", body = crate::error::ErrorBody),
        (status = 429, description = "Rate limited; see Retry-After"),
    ),
)]
pub async fn login(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    UserAgent(ua): UserAgent,
    RequestId(rid): RequestId,
    Json(body): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    // Bound client input before the database and Argon2 see it.
    if body.identifier.is_empty()
        || body.identifier.len() > MAX_IDENTIFIER_LEN
        || body.password.len() > MAX_LOGIN_PASSWORD_LEN
    {
        return Err(AppError::Validation(
            "identifier or password has an invalid length".into(),
        ));
    }

    let captcha_token = body.captcha_token.as_deref().unwrap_or("");
    captcha_svc::verify(&state, captcha_token).await?;

    let result = auth_svc::login(
        &state,
        &body.identifier,
        &body.password,
        ip,
        ua.as_deref(),
        body.device_name.as_deref(),
        body.remember_me.unwrap_or(false),
        rid,
    )
    .await?;

    Ok(Json(login_response(result)))
}

fn login_response(result: auth_svc::LoginResult) -> LoginResponse {
    match result {
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
    }
}

#[utoipa::path(
    post,
    path = "/auth/logout",
    tag = "auth",
    responses(
        (status = 204, description = "Session ended"),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
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

#[utoipa::path(
    post,
    path = "/auth/refresh",
    tag = "auth",
    request_body = RefreshRequest,
    responses(
        (status = 200, description = "Tokens issued", body = TokensResponse),
        (status = 401, description = "Invalid, expired or replayed refresh token", body = crate::error::ErrorBody),
        (status = 403, description = "Account suspended or inactive", body = crate::error::ErrorBody),
        (status = 429, description = "Rate limited; see Retry-After"),
    ),
)]
pub async fn refresh(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    UserAgent(ua): UserAgent,
    RequestId(rid): RequestId,
    Json(body): Json<RefreshRequest>,
) -> Result<Json<TokensResponse>, AppError> {
    let tokens =
        auth_svc::refresh_token(&state, &body.refresh_token, None, ip, ua.as_deref(), rid).await?;
    Ok(Json(TokensResponse {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
    }))
}

// Accepts the token in the request body rather than in the URL query string so
// that it is not captured in server access logs, browser history, or Referer headers.
#[utoipa::path(
    post,
    path = "/auth/verify-email",
    tag = "auth",
    request_body = VerifyEmailRequest,
    responses(
        (status = 200, description = "Address verified"),
        (status = 401, description = "Invalid or expired token", body = crate::error::ErrorBody),
        (status = 429, description = "Rate limited; see Retry-After"),
    ),
)]
pub async fn verify_email(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    RequestId(rid): RequestId,
    Json(body): Json<VerifyEmailRequest>,
) -> Result<StatusCode, AppError> {
    auth_svc::verify_email(&state, &body.token, ip, rid).await?;
    Ok(StatusCode::OK)
}

#[utoipa::path(
    post,
    path = "/auth/verify-email/resend",
    tag = "auth",
    request_body = ResendVerificationRequest,
    responses(
        (status = 200, description = "Accepted; identical whether the address is unknown, pending or already verified"),
        (status = 429, description = "Rate limited; see Retry-After"),
    ),
)]
pub async fn resend_verification(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    UserAgent(ua): UserAgent,
    RequestId(rid): RequestId,
    Json(body): Json<ResendVerificationRequest>,
) -> Result<StatusCode, AppError> {
    let captcha_token = body.captcha_token.as_deref().unwrap_or("");
    captcha_svc::verify(&state, captcha_token).await?;

    auth_svc::resend_verification(&state, &body.email, ip, ua.as_deref(), rid).await?;
    Ok(StatusCode::OK)
}

#[utoipa::path(
    post,
    path = "/auth/magic-link",
    tag = "auth",
    request_body = MagicLinkRequest,
    responses(
        (status = 200, description = "Accepted; identical whether or not an account can sign in with this address"),
        (status = 404, description = "Sign-in links are not enabled on this deployment", body = crate::error::ErrorBody),
        (status = 429, description = "Rate limited; see Retry-After"),
    ),
)]
pub async fn request_magic_link(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    UserAgent(ua): UserAgent,
    RequestId(rid): RequestId,
    Json(body): Json<MagicLinkRequest>,
) -> Result<StatusCode, AppError> {
    let captcha_token = body.captcha_token.as_deref().unwrap_or("");
    captcha_svc::verify(&state, captcha_token).await?;

    auth_svc::request_magic_link(&state, &body.email, ip, ua.as_deref(), rid).await?;
    Ok(StatusCode::OK)
}

#[utoipa::path(
    post,
    path = "/auth/magic-link/complete",
    tag = "auth",
    request_body = CompleteMagicLinkRequest,
    responses(
        (status = 200, description = "Tokens, or the account's two-factor challenge", body = LoginResponse),
        (status = 401, description = "Invalid, used or expired link", body = crate::error::ErrorBody),
        (status = 403, description = "Account locked, suspended or inactive", body = crate::error::ErrorBody),
        (status = 404, description = "Sign-in links are not enabled on this deployment", body = crate::error::ErrorBody),
        (status = 429, description = "Rate limited; see Retry-After"),
    ),
)]
pub async fn complete_magic_link(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    UserAgent(ua): UserAgent,
    RequestId(rid): RequestId,
    Json(body): Json<CompleteMagicLinkRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    let result = auth_svc::complete_magic_link(
        &state,
        &body.token,
        ip,
        ua.as_deref(),
        body.device_name.as_deref(),
        body.remember_me.unwrap_or(false),
        rid,
    )
    .await?;
    Ok(Json(login_response(result)))
}

#[utoipa::path(
    post,
    path = "/auth/forgot-password",
    tag = "auth",
    request_body = ForgotPasswordRequest,
    responses(
        (status = 200, description = "Accepted; identical whether or not the account exists"),
        (status = 429, description = "Rate limited; see Retry-After"),
    ),
)]
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

#[utoipa::path(
    post,
    path = "/auth/reset-password",
    tag = "auth",
    request_body = ResetPasswordRequest,
    responses(
        (status = 200, description = "Password replaced; every session revoked"),
        (status = 401, description = "Invalid or expired token", body = crate::error::ErrorBody),
        (status = 422, description = "Invalid input", body = crate::error::ErrorBody),
    ),
)]
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

#[utoipa::path(
    post,
    path = "/auth/two-factor/complete",
    tag = "auth",
    request_body = CompleteTwoFactorRequest,
    responses(
        (status = 200, description = "Tokens issued", body = TokensResponse),
        (status = 401, description = "Invalid code or pre-auth token", body = crate::error::ErrorBody),
        (status = 403, description = "Account suspended or locked since the challenge", body = crate::error::ErrorBody),
        (status = 429, description = "Rate limited; see Retry-After"),
    ),
)]
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

#[utoipa::path(
    post,
    path = "/auth/two-factor/recovery",
    tag = "auth",
    request_body = RecoveryLoginRequest,
    responses(
        (status = 200, description = "Tokens issued", body = TokensResponse),
        (status = 401, description = "Invalid recovery code or pre-auth token", body = crate::error::ErrorBody),
        (status = 403, description = "Account suspended or locked since the challenge", body = crate::error::ErrorBody),
        (status = 429, description = "Rate limited; see Retry-After"),
    ),
)]
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

#[utoipa::path(
    post,
    path = "/auth/two-factor/email/complete",
    tag = "auth",
    request_body = CompleteEmailTwoFactorRequest,
    responses(
        (status = 200, description = "Tokens issued", body = TokensResponse),
        (status = 401, description = "Invalid code or pre-auth token", body = crate::error::ErrorBody),
        (status = 403, description = "Account suspended or locked since the challenge", body = crate::error::ErrorBody),
        (status = 429, description = "Rate limited; see Retry-After"),
    ),
)]
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

#[utoipa::path(
    post,
    path = "/auth/two-factor/email/resend",
    tag = "auth",
    request_body = ResendEmailTwoFactorRequest,
    responses(
        (status = 204, description = "Code sent if the challenge is an email challenge"),
        (status = 401, description = "Invalid pre-auth token", body = crate::error::ErrorBody),
    ),
)]
pub async fn resend_email_two_factor(
    State(state): State<AppState>,
    Json(body): Json<ResendEmailTwoFactorRequest>,
) -> Result<StatusCode, AppError> {
    // Resolve user_id from pre_auth_token without revealing whether it exists.
    let pre_auth = auth_svc::resolve_pre_auth(&state, &body.pre_auth_token).await?;
    // Only an email challenge may request an email code: resending one for a
    // TOTP challenge would let a mailbox stand in for the authenticator app.
    pre_auth.expect_method(auth_svc::ChallengeMethod::Email)?;
    let user_id = pre_auth.user_id;

    // Fire-and-forget: errors are non-fatal to avoid enumeration via timing.
    let _ = email_2fa_svc::send_code(&state, user_id).await;
    Ok(StatusCode::NO_CONTENT)
}

// Validation helpers

/// Longest identifier (email or username) accepted at login.
const MAX_IDENTIFIER_LEN: usize = 254;
/// Longest password accepted at login. Above the registration limit (128) so
/// no existing account is refused, but bounded before Argon2 runs.
const MAX_LOGIN_PASSWORD_LEN: usize = 256;

/// Emails accepted for storage: syntactically valid and in the shape the
/// `users_email_format` constraint accepts, so a bad address is a 422 rather
/// than a constraint violation surfacing as a 500.
pub(crate) fn validate_email(email: &str) -> Result<(), AppError> {
    if !email_address::EmailAddress::is_valid(email)
        || !crate::domain::user::is_storable_email(email)
    {
        return Err(AppError::Validation("invalid email address".into()));
    }
    Ok(())
}

/// Usernames as the `users_username_format` constraint accepts them: 3 to 30
/// ASCII letters, digits or underscores.
pub(crate) fn validate_username(username: &str) -> Result<(), AppError> {
    if !(3..=30).contains(&username.len()) {
        return Err(AppError::Validation(
            "username must be 3 to 30 characters".into(),
        ));
    }
    if !crate::domain::user::is_valid_username(username) {
        return Err(AppError::Validation(
            "username may only contain ASCII letters, digits and underscores".into(),
        ));
    }
    Ok(())
}
