//! Two-factor authentication handlers: TOTP setup, verification, and recovery codes.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{error::AppError, services::two_factor as tf_svc, state::AppState};

use super::extractors::AuthUser;

// Request types

#[derive(Deserialize)]
pub struct VerifyTotpSetupRequest {
    pub code: String,
}

#[derive(Deserialize)]
pub struct UseRecoveryCodeRequest {
    pub code: String,
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
    let codes = tf_svc::verify_setup(&state, auth.user_id, method_id, &body.code).await?;
    Ok(Json(RecoveryCodesResponse { recovery_codes: codes }))
}

pub async fn disable_totp(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(method_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    tf_svc::disable_totp(&state, auth.user_id, method_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn regenerate_recovery_codes(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<RecoveryCodesResponse>, AppError> {
    let codes = tf_svc::generate_recovery_codes(&state, auth.user_id).await?;
    Ok(Json(RecoveryCodesResponse { recovery_codes: codes }))
}

pub async fn use_recovery_code(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<UseRecoveryCodeRequest>,
) -> Result<StatusCode, AppError> {
    tf_svc::use_recovery_code(&state, auth.user_id, &body.code).await?;
    Ok(StatusCode::NO_CONTENT)
}
