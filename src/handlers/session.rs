//! Session management handlers: list active sessions, revoke one or all.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    domain::session::SessionType, error::AppError, services::session as session_svc,
    state::AppState,
};

use super::extractors::{AuthUser, ClientIp};

// Response types

#[derive(Serialize, utoipa::ToSchema)]
pub struct SessionResponse {
    pub id: Uuid,
    pub session_type: SessionType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
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

#[derive(Deserialize, utoipa::ToSchema)]
pub struct RevokeAllRequest {
    pub current_password: Option<String>,
}

// Handlers

#[utoipa::path(
    get,
    path = "/users/me/sessions",
    tag = "sessions",
    responses(
        (status = 200, description = "Active sessions", body = [SessionResponse]),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
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
                session_type: s.session_type,
                client_id: s.client_id,
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

#[utoipa::path(
    delete,
    path = "/users/me/sessions/{id}",
    tag = "sessions",
    params(("id" = Uuid, Path, description = "Method or session id")),
    request_body = Option<RevokeAllRequest>,
    responses(
        (status = 204, description = "Session revoked"),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Recent re-authentication required", body = crate::error::ErrorBody),
        (status = 404, description = "No such session", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn revoke(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    auth: AuthUser,
    Path(session_id): Path<Uuid>,
    body: Option<Json<RevokeAllRequest>>,
) -> Result<StatusCode, AppError> {
    let current_password = body.and_then(|Json(b)| b.current_password);
    session_svc::revoke(
        &state,
        auth.user_id,
        auth.session_id,
        session_id,
        current_password.as_deref(),
        ip,
        auth.request_id,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/users/me/sessions",
    tag = "sessions",
    request_body = Option<RevokeAllRequest>,
    responses(
        (status = 204, description = "Every session revoked, the current one included"),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Recent re-authentication required", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn revoke_all(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    auth: AuthUser,
    body: Option<Json<RevokeAllRequest>>,
) -> Result<StatusCode, AppError> {
    let current_password = body.and_then(|Json(b)| b.current_password);
    session_svc::revoke_all(
        &state,
        auth.user_id,
        auth.session_id,
        current_password.as_deref(),
        ip,
        auth.request_id,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}
