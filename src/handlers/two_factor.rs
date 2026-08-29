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
#[derive(Deserialize, Default)]
pub struct SetupTwoFactorRequest {
    pub current_password: Option<String>,
}

#[derive(Deserialize)]
pub struct VerifyTotpSetupRequest {
    pub code: String,
}

#[derive(Deserialize)]
pub struct DisableTotpRequest {
    pub current_password: Option<String>,
}

#[derive(Deserialize)]
pub struct RegenerateRecoveryCodesRequest {
    pub current_password: Option<String>,
}

#[derive(Deserialize)]
pub struct UseRecoveryCodeRequest {
    pub code: String,
}

#[derive(Deserialize)]
pub struct VerifyEmailOtpSetupRequest {
    pub code: String,
}

#[derive(Deserialize)]
pub struct DisableEmailOtpRequest {
    pub current_password: Option<String>,
}

// Response types

#[derive(Serialize)]
pub struct TotpSetupResponse {
    pub method_id: Uuid,
    pub qr_uri: String,
    /// Base32 secret shown once so the user can manually enter it in their app.
    pub base32_secret: String,
}

#[derive(Serialize)]
pub struct RecoveryCodesResponse {
    /// Plaintext recovery codes shown once. The user must store them securely.
    pub recovery_codes: Vec<String>,
}

#[derive(Serialize)]
pub struct EmailOtpSetupResponse {
    pub method_id: Uuid,
}

// Handlers

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

pub async fn use_recovery_code(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<UseRecoveryCodeRequest>,
) -> Result<StatusCode, AppError> {
    tf_svc::use_recovery_code(&state, auth.user_id, &body.code, auth.request_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// Email OTP 2FA

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

pub async fn send_email_otp_code(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<StatusCode, AppError> {
    email_2fa_svc::send_code(&state, auth.user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

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

#[derive(Serialize)]
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

#[derive(Serialize)]
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
