//! Two-factor authentication handlers: TOTP, Email OTP, setup, verification, and recovery codes.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    domain::two_factor::TwoFactorType,
    error::AppError,
    services::{email_2fa as email_2fa_svc, two_factor as tf_svc},
    state::AppState,
};

use super::extractors::{AuthUser, ClientIp};

// Request types

/// Body of the setup endpoints. Optional: a recent re-authentication
/// (`POST /users/me/reauth`) makes the password unnecessary.
#[derive(Deserialize, Default, utoipa::ToSchema)]
pub struct SetupTwoFactorRequest {
    pub current_password: Option<String>,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct VerifyTotpSetupRequest {
    pub code: String,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct DisableTotpRequest {
    pub current_password: Option<String>,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct RegenerateRecoveryCodesRequest {
    pub current_password: Option<String>,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct UseRecoveryCodeRequest {
    pub code: String,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct VerifyEmailOtpSetupRequest {
    pub code: String,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct DisableEmailOtpRequest {
    pub current_password: Option<String>,
}

// Response types

#[derive(Serialize, utoipa::ToSchema)]
pub struct TotpSetupResponse {
    pub method_id: Uuid,
    pub qr_uri: String,
    /// Base32 secret shown once so the user can manually enter it in their app.
    pub base32_secret: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct RecoveryCodesResponse {
    /// Plaintext recovery codes shown once. The user must store them securely.
    pub recovery_codes: Vec<String>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct EmailOtpSetupResponse {
    pub method_id: Uuid,
}

// Handlers

#[utoipa::path(
    post,
    path = "/users/me/two-factor/totp/setup",
    tag = "two-factor",
    request_body = Option<SetupTwoFactorRequest>,
    responses(
        (status = 200, description = "Secret provisioned, shown once", body = TotpSetupResponse),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Recent re-authentication required", body = crate::error::ErrorBody),
        (status = 409, description = "Already enabled", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn setup_totp(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    auth: AuthUser,
    body: Option<Json<SetupTwoFactorRequest>>,
) -> Result<Json<TotpSetupResponse>, AppError> {
    let body = body.map(|Json(b)| b).unwrap_or_default();
    let result = tf_svc::setup_totp(
        &state,
        auth.user_id,
        auth.session_id,
        body.current_password.as_deref(),
        ip,
        auth.request_id,
    )
    .await?;

    Ok(Json(TotpSetupResponse {
        method_id: result.method_id,
        qr_uri: result.qr_uri,
        base32_secret: result.base32_secret,
    }))
}

#[utoipa::path(
    post,
    path = "/users/me/two-factor/totp/{id}/verify",
    tag = "two-factor",
    params(("id" = Uuid, Path, description = "Method or session id")),
    request_body = VerifyTotpSetupRequest,
    responses(
        (status = 200, description = "Method enabled; recovery codes shown once", body = RecoveryCodesResponse),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 404, description = "No such method", body = crate::error::ErrorBody),
        (status = 409, description = "Already verified", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn verify_totp_setup(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(method_id): Path<Uuid>,
    Json(body): Json<VerifyTotpSetupRequest>,
) -> Result<Json<RecoveryCodesResponse>, AppError> {
    let codes =
        tf_svc::verify_setup(&state, auth.user_id, method_id, &body.code, auth.request_id).await?;
    Ok(Json(RecoveryCodesResponse {
        recovery_codes: codes,
    }))
}

#[utoipa::path(
    delete,
    path = "/users/me/two-factor/totp/{id}",
    tag = "two-factor",
    params(("id" = Uuid, Path, description = "Method or session id")),
    request_body = Option<DisableTotpRequest>,
    responses(
        (status = 204, description = "Method removed"),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Recent re-authentication required", body = crate::error::ErrorBody),
        (status = 404, description = "No such method", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn disable_totp(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    auth: AuthUser,
    Path(method_id): Path<Uuid>,
    body: Option<Json<DisableTotpRequest>>,
) -> Result<StatusCode, AppError> {
    let current_password = body.and_then(|Json(b)| b.current_password);
    tf_svc::disable_totp(
        &state,
        auth.user_id,
        auth.session_id,
        method_id,
        current_password.as_deref(),
        ip,
        auth.request_id,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/users/me/two-factor/recovery-codes",
    tag = "two-factor",
    request_body = RegenerateRecoveryCodesRequest,
    responses(
        (status = 200, description = "New codes, shown once", body = RecoveryCodesResponse),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Recent re-authentication required", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn regenerate_recovery_codes(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    auth: AuthUser,
    Json(body): Json<RegenerateRecoveryCodesRequest>,
) -> Result<Json<RecoveryCodesResponse>, AppError> {
    let codes = tf_svc::generate_recovery_codes(
        &state,
        auth.user_id,
        auth.session_id,
        body.current_password.as_deref(),
        ip,
        auth.request_id,
    )
    .await?;
    Ok(Json(RecoveryCodesResponse {
        recovery_codes: codes,
    }))
}

#[utoipa::path(
    post,
    path = "/users/me/two-factor/recovery-codes/use",
    tag = "two-factor",
    request_body = UseRecoveryCodeRequest,
    responses(
        (status = 204, description = "Code consumed"),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn use_recovery_code(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<UseRecoveryCodeRequest>,
) -> Result<StatusCode, AppError> {
    tf_svc::use_recovery_code(&state, auth.user_id, &body.code, auth.request_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// Email OTP 2FA

#[utoipa::path(
    post,
    path = "/users/me/two-factor/email/setup",
    tag = "two-factor",
    request_body = Option<SetupTwoFactorRequest>,
    responses(
        (status = 200, description = "Method created; first code sent", body = EmailOtpSetupResponse),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Recent re-authentication required", body = crate::error::ErrorBody),
        (status = 409, description = "Already enabled", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn setup_email_otp(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    auth: AuthUser,
    body: Option<Json<SetupTwoFactorRequest>>,
) -> Result<Json<EmailOtpSetupResponse>, AppError> {
    let body = body.map(|Json(b)| b).unwrap_or_default();
    let method_id = email_2fa_svc::setup(
        &state,
        auth.user_id,
        auth.session_id,
        body.current_password.as_deref(),
        ip,
        auth.request_id,
    )
    .await?;
    // Send the first code immediately so the user can verify right away.
    email_2fa_svc::send_code(&state, auth.user_id).await?;
    Ok(Json(EmailOtpSetupResponse { method_id }))
}

#[utoipa::path(
    post,
    path = "/users/me/two-factor/email/send",
    tag = "two-factor",
    responses(
        (status = 204, description = "Code sent"),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 429, description = "Rate limited; see Retry-After"),
    ),
    security(("bearer" = [])),
)]
pub async fn send_email_otp_code(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<StatusCode, AppError> {
    email_2fa_svc::send_code(&state, auth.user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/users/me/two-factor/email/{id}/verify",
    tag = "two-factor",
    params(("id" = Uuid, Path, description = "Method or session id")),
    request_body = VerifyEmailOtpSetupRequest,
    responses(
        (status = 200, description = "Method enabled; recovery codes shown once", body = RecoveryCodesResponse),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 404, description = "No such method", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn verify_email_otp_setup(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(method_id): Path<Uuid>,
    Json(body): Json<VerifyEmailOtpSetupRequest>,
) -> Result<Json<RecoveryCodesResponse>, AppError> {
    let codes =
        email_2fa_svc::verify_setup(&state, auth.user_id, method_id, &body.code, auth.request_id)
            .await?;
    Ok(Json(RecoveryCodesResponse {
        recovery_codes: codes,
    }))
}

#[utoipa::path(
    delete,
    path = "/users/me/two-factor/email/{id}",
    tag = "two-factor",
    params(("id" = Uuid, Path, description = "Method or session id")),
    request_body = Option<DisableEmailOtpRequest>,
    responses(
        (status = 204, description = "Method removed"),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Recent re-authentication required", body = crate::error::ErrorBody),
        (status = 404, description = "No such method", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn disable_email_otp(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    auth: AuthUser,
    Path(method_id): Path<Uuid>,
    body: Option<Json<DisableEmailOtpRequest>>,
) -> Result<StatusCode, AppError> {
    let current_password = body.and_then(|Json(b)| b.current_password);
    email_2fa_svc::disable(
        &state,
        auth.user_id,
        auth.session_id,
        method_id,
        current_password.as_deref(),
        ip,
        auth.request_id,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

// Overview

#[derive(Serialize, utoipa::ToSchema)]
pub struct TwoFactorMethodResponse {
    pub id: Uuid,
    /// `totp` or `email`.
    pub method_type: &'static str,
    pub is_verified: bool,
    pub is_primary: bool,
    pub created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<i64>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct TwoFactorOverviewResponse {
    pub methods: Vec<TwoFactorMethodResponse>,
    /// Unused and unexpired. Zero next to a verified method is worth showing:
    /// losing the device would then lock the account.
    pub recovery_codes_remaining: i64,
}

/// GET /users/me/two-factor
///
/// What the account has set up. The disable routes need a method id that only
/// the setup call returned: without this, a refreshed page could not turn its
/// own second factor off.
#[utoipa::path(
    get,
    path = "/users/me/two-factor",
    tag = "two-factor",
    responses(
        (status = 200, description = "Configured methods and remaining recovery codes", body = TwoFactorOverviewResponse),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn list(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<TwoFactorOverviewResponse>, AppError> {
    let (methods, recovery_codes_remaining) = tf_svc::list_methods(&state, auth.user_id).await?;

    Ok(Json(TwoFactorOverviewResponse {
        methods: methods
            .into_iter()
            .map(|method| TwoFactorMethodResponse {
                id: method.id,
                method_type: match method.method_type {
                    TwoFactorType::Totp => "totp",
                    TwoFactorType::Email => "email",
                },
                is_verified: method.is_verified,
                is_primary: method.is_primary,
                created_at: method.created_at.unix_timestamp(),
                last_used_at: method.last_used_at.map(|at| at.unix_timestamp()),
            })
            .collect(),
        recovery_codes_remaining,
    }))
}
