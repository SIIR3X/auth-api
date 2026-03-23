//! WebAuthn/passkey HTTP handlers.
//!
//! Registration endpoints (protected, require JWT):
//!   POST /users/me/two-factor/webauthn/register/start  -> CreationChallengeResponse
//!   POST /users/me/two-factor/webauthn/register/finish -> 200 OK
//!
//! Authentication endpoints (public, during login 2FA):
//!   POST /auth/two-factor/webauthn/start  -> RequestChallengeResponse
//!   POST /auth/two-factor/webauthn/finish -> TokensResponse

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};

use crate::{
    error::AppError,
    repositories::user as user_repo,
    services::{auth as auth_svc, webauthn as wa_svc},
    state::AppState,
};

use super::extractors::{AuthUser, ClientIp};

// Request / response types

#[derive(Deserialize)]
pub struct DisableWebAuthnRequest {
    pub current_password: Option<String>,
}

#[derive(Deserialize)]
pub struct WebAuthnAuthStartRequest {
    pub pre_auth_token: String,
}

#[derive(Deserialize)]
pub struct WebAuthnAuthFinishRequest {
    pub pre_auth_token: String,
    pub credential: PublicKeyCredential,
}

#[derive(Serialize)]
pub struct TokensResponse {
    pub access_token: String,
    pub refresh_token: String,
}

// Registration handlers (authenticated)

pub async fn start_registration(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<CreationChallengeResponse>, AppError> {
    let user = user_repo::find_by_id(&state.db, auth.user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::Unauthorized)?;

    let ccr = wa_svc::start_registration(&state, auth.user_id, &user.username).await?;
    Ok(Json(ccr))
}

pub async fn finish_registration(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(response): Json<RegisterPublicKeyCredential>,
) -> Result<StatusCode, AppError> {
    wa_svc::finish_registration(&state, auth.user_id, &response, auth.request_id).await?;
    Ok(StatusCode::OK)
}

pub async fn disable_webauthn(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    auth: AuthUser,
    Path(method_id): Path<Uuid>,
    Json(body): Json<DisableWebAuthnRequest>,
) -> Result<StatusCode, AppError> {
    wa_svc::disable(
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

// Authentication handlers (public, during 2FA)

pub async fn start_authentication(
    State(state): State<AppState>,
    Json(body): Json<WebAuthnAuthStartRequest>,
) -> Result<Json<RequestChallengeResponse>, AppError> {
    // Resolve pre_auth_token -> user_id from Redis (same key as TOTP flow).
    let redis_key = format!("pre_auth:{}", body.pre_auth_token);
    let user_id = resolve_pre_auth_token(&state, &redis_key).await?;

    let rcr = wa_svc::start_authentication(&state, &body.pre_auth_token, user_id).await?;
    Ok(Json(rcr))
}

pub async fn finish_authentication(
    State(state): State<AppState>,
    super::extractors::ClientIp(ip): super::extractors::ClientIp,
    super::extractors::UserAgent(ua): super::extractors::UserAgent,
    super::extractors::RequestId(rid): super::extractors::RequestId,
    Json(body): Json<WebAuthnAuthFinishRequest>,
) -> Result<Json<TokensResponse>, AppError> {
    let redis_key = format!("pre_auth:{}", body.pre_auth_token);
    let user_id = resolve_pre_auth_token(&state, &redis_key).await?;

    let user = user_repo::find_by_id(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::Unauthorized)?;

    if !user.is_active() {
        return Err(AppError::AccountSuspended);
    }

    wa_svc::finish_authentication(&state, &body.pre_auth_token, user_id, &body.credential).await?;

    // Consume the pre-auth token.
    if let Ok(mut conn) = state.redis.get().await {
        let _: Result<(), _> =
            deadpool_redis::redis::AsyncCommands::del(&mut conn, &redis_key).await;
    }

    // Issue session tokens.
    let tokens = auth_svc::issue_session_tokens(&state, &user, ip, ua.as_deref(), None).await?;

    user_repo::update_last_login(&state.db, user.id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    auth_svc::post_login_hooks(&state, &user, ip, ua.as_deref(), rid).await;

    let _ = crate::repositories::audit::append(
        &state.db,
        &crate::repositories::audit::NewAuditEntry {
            user_id: Some(user.id),
            request_id: rid,
            action: crate::domain::audit::AuditAction::Login,
            ip_address: ip,
            metadata: serde_json::json!({"two_factor": "webauthn"}),
        },
    )
    .await;

    Ok(Json(TokensResponse {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
    }))
}

// Helper

async fn resolve_pre_auth_token(state: &AppState, redis_key: &str) -> Result<uuid::Uuid, AppError> {
    use deadpool_redis::redis::AsyncCommands;

    let mut conn = state
        .redis
        .get()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    let val: Option<String> = conn
        .get(redis_key)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("redis: {e}")))?;
    let val = val.ok_or(AppError::TokenInvalid)?;
    val.parse::<uuid::Uuid>()
        .map_err(|_| AppError::TokenInvalid)
}
