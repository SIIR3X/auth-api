//! Two-factor authentication handlers: TOTP, Email OTP, setup, verification, and recovery codes.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    error::AppError,
    services::{email_2fa as email_2fa_svc, two_factor as tf_svc},
    state::AppState,
};

use super::extractors::{AuthUser, ClientIp};

// Request types

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
    auth: AuthUser,
) -> Result<Json<TotpSetupResponse>, AppError> {
    let result = tf_svc::setup_totp(&state, auth.user_id).await?;

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
    Json(body): Json<DisableTotpRequest>,
) -> Result<StatusCode, AppError> {
    tf_svc::disable_totp(
        &state,
        auth.user_id,
        auth.session_id,
        method_id,
        body.current_password.as_deref(),
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
    auth: AuthUser,
) -> Result<Json<EmailOtpSetupResponse>, AppError> {
    let method_id = email_2fa_svc::setup(&state, auth.user_id).await?;
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
    Json(body): Json<DisableEmailOtpRequest>,
) -> Result<StatusCode, AppError> {
    email_2fa_svc::disable(
        &state,
        auth.user_id,
        auth.session_id,
        method_id,
        body.current_password.as_deref(),
        ip,
        auth.request_id,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}
