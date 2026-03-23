//! Session management handlers: list active sessions, revoke one or all.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{error::AppError, services::session as session_svc, state::AppState};

use super::extractors::{AuthUser, ClientIp};

// Response types

#[derive(Serialize)]
pub struct SessionResponse {
    pub id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    pub last_used_at: i64,
    pub expires_at: i64,
    pub created_at: i64,
    /// True when this is the session used to make the current request.
    pub is_current: bool,
}

// Request types

#[derive(Deserialize)]
pub struct RevokeAllRequest {
    pub current_password: Option<String>,
}

// Handlers

pub async fn list(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<SessionResponse>>, AppError> {
    let sessions = session_svc::list_active(&state, auth.user_id).await?;

    let response = sessions
        .into_iter()
        .map(|s| {
            let is_current = s.id == auth.session_id;
            SessionResponse {
                id: s.id,
                device_name: s.device_name,
                user_agent: s.user_agent,
                ip_address: s.ip_address.map(|ip| ip.ip().to_string()),
                last_used_at: s.last_used_at.unix_timestamp(),
                expires_at: s.expires_at.unix_timestamp(),
                created_at: s.created_at.unix_timestamp(),
                is_current,
            }
        })
        .collect();

    Ok(Json(response))
}

pub async fn revoke(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    auth: AuthUser,
    Path(session_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    session_svc::revoke(
        &state,
        auth.user_id,
        auth.session_id,
        session_id,
        ip,
        auth.request_id,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn revoke_all(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    auth: AuthUser,
    Json(body): Json<RevokeAllRequest>,
) -> Result<StatusCode, AppError> {
    session_svc::revoke_all(
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
