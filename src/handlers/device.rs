//! Device Authorization Flow handlers (RFC 8628).
//!
//! - `POST /auth/device`: a device client starts a flow (no authentication)
//! - `POST /auth/device/token`: the device polls for tokens (no authentication)
//! - `GET /auth/device/{user_code}`: what the signed-in user is about to approve
//! - `POST /auth/device/verify`: the signed-in user approves or denies it

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::Deserialize;

use crate::{error::AppError, services::device as device_svc, state::AppState};

use super::extractors::{AuthUser, ClientIp, UserAgent};

/// Longest client identifier accepted (`registered_clients.client_id`).
const MAX_CLIENT_ID_LEN: usize = 100;

#[derive(Deserialize)]
pub struct DeviceAuthorizeRequest {
    /// Registered client starting the flow. Omitted: the primary client.
    pub client_id: Option<String>,
}

#[derive(Deserialize)]
pub struct DeviceTokenRequest {
    pub device_code: String,
    /// Label for the account's session list. Client-supplied, so a label and
    /// never an identity; it is normalized before it is stored.
    pub device_name: Option<String>,
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

/// POST /auth/device
pub async fn authorize(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    UserAgent(ua): UserAgent,
    Json(body): Json<DeviceAuthorizeRequest>,
) -> Result<Json<device_svc::DeviceInitResponse>, AppError> {
    if let Some(client_id) = body.client_id.as_deref()
        && (client_id.is_empty() || client_id.len() > MAX_CLIENT_ID_LEN)
    {
        return Err(AppError::Validation("invalid client_id".into()));
    }

    let response =
        device_svc::initiate(&state, ip, ua.as_deref(), body.client_id.as_deref()).await?;
    Ok(Json(response))
}

/// POST /auth/device/token
pub async fn token(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    UserAgent(ua): UserAgent,
    Json(body): Json<DeviceTokenRequest>,
) -> Result<Json<device_svc::DevicePollResult>, AppError> {
    if body.device_code.is_empty() {
        return Err(AppError::Validation("device_code is required".into()));
    }

    let result = device_svc::poll(
        &state,
        &body.device_code,
        ip,
        ua.as_deref(),
        body.device_name.as_deref(),
    )
    .await?;
    Ok(Json(result))
}

/// GET /auth/device/{user_code}
pub async fn describe(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    _auth: AuthUser,
    Path(user_code): Path<String>,
) -> Result<Json<device_svc::DevicePreview>, AppError> {
    validate_user_code(&user_code)?;
    let preview = device_svc::describe(&state, &user_code, ip).await?;
    Ok(Json(preview))
}

/// POST /auth/device/verify
pub async fn verify(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    auth: AuthUser,
    Json(body): Json<DeviceVerifyRequest>,
) -> Result<StatusCode, AppError> {
    validate_user_code(&body.user_code)?;

    if body.approve {
        device_svc::verify(&state, auth.user_id, &body.user_code, ip).await?;
    } else {
        device_svc::deny(&state, &body.user_code, ip).await?;
    }

    Ok(StatusCode::OK)
}

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
    fn validate_user_code_rejects_malformed_codes() {
        for code in [
            "abcd-2345",
            "ABC-2345",
            "ABCDE-2345",
            "ABCD-234",
            "ABCD2345",
            "ABCD-23AB",
            "AB12-2345",
        ] {
            assert!(validate_user_code(code).is_err(), "{code} must be rejected");
        }
    }
}
