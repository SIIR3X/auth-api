//! Device Authorization Flow handlers (RFC 8628).
//!
//! Three endpoints manage the device auth lifecycle:
//! - POST /auth/device - initiate (no auth, rate limited)
//! - POST /auth/device/token - poll for tokens (no auth, rate limited)
//! - POST /auth/device/verify - user approves/denies device (JWT required)

use axum::{Json, extract::State, http::StatusCode};
use serde::Deserialize;

use crate::{error::AppError, services::device as device_svc, state::AppState};

use super::extractors::{AuthUser, ClientIp, UserAgent};

// Request types

#[derive(Deserialize)]
pub struct DeviceAuthorizeRequest {
    pub client_id: Option<String>,
}

#[derive(Deserialize)]
pub struct DeviceTokenRequest {
    pub device_code: String,
}

#[derive(Deserialize)]
pub struct DeviceVerifyRequest {
    pub user_code: String,
    #[serde(default = "default_approve")]
    pub approve: bool,
}

fn default_approve() -> bool {
    true
}

// Handlers

/// POST /auth/device
/// Desktop app calls this to start the device authorization flow.
/// No authentication required.
pub async fn authorize(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    UserAgent(ua): UserAgent,
    Json(body): Json<DeviceAuthorizeRequest>,
) -> Result<Json<device_svc::DeviceInitResponse>, AppError> {
    let response =
        device_svc::initiate(&state, ip, ua.as_deref(), body.client_id.as_deref()).await?;
    Ok(Json(response))
}

/// POST /auth/device/token
/// Desktop app polls this with the device_code until tokens are available.
/// No authentication required.
pub async fn token(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    UserAgent(ua): UserAgent,
    Json(body): Json<DeviceTokenRequest>,
) -> Result<Json<device_svc::DevicePollResult>, AppError> {
    if body.device_code.is_empty() {
        return Err(AppError::Validation("device_code is required".into()));
    }

    let result = device_svc::poll(&state, &body.device_code, ip, ua.as_deref(), None).await?;
    Ok(Json(result))
}

/// POST /auth/device/verify
/// Authenticated user approves or denies the device authorization request.
pub async fn verify(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<DeviceVerifyRequest>,
) -> Result<StatusCode, AppError> {
    validate_user_code(&body.user_code)?;

    if body.approve {
        device_svc::verify(&state, auth.user_id, &body.user_code).await?;
    } else {
        device_svc::deny(&state, &body.user_code).await?;
    }

    Ok(StatusCode::OK)
}

// Validation

fn validate_user_code(code: &str) -> Result<(), AppError> {
    let parts: Vec<&str> = code.split('-').collect();
    if parts.len() != 2 || parts[0].len() != 4 || parts[1].len() != 4 {
        return Err(AppError::Validation(
            "user_code must be in XXXX-XXXX format".into(),
        ));
    }
    if !parts[0].chars().all(|c| c.is_ascii_uppercase())
        || !parts[1].chars().all(|c| c.is_ascii_digit())
    {
        return Err(AppError::Validation("invalid user_code format".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_user_code_accepts_valid_format() {
        assert!(validate_user_code("ABCD-2345").is_ok());
        assert!(validate_user_code("WXYZ-6789").is_ok());
    }

    #[test]
    fn validate_user_code_rejects_lowercase() {
        assert!(validate_user_code("abcd-2345").is_err());
    }

    #[test]
    fn validate_user_code_rejects_wrong_length() {
        assert!(validate_user_code("ABC-2345").is_err());
        assert!(validate_user_code("ABCDE-2345").is_err());
        assert!(validate_user_code("ABCD-234").is_err());
    }

    #[test]
    fn validate_user_code_rejects_missing_hyphen() {
        assert!(validate_user_code("ABCD2345").is_err());
    }

    #[test]
    fn validate_user_code_rejects_letters_in_digit_part() {
        assert!(validate_user_code("ABCD-23AB").is_err());
    }

    #[test]
    fn validate_user_code_rejects_digits_in_letter_part() {
        assert!(validate_user_code("AB12-2345").is_err());
    }
}
