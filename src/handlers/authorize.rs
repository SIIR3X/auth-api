//! Authorization Code with PKCE: describe, approve, redeem.
//!
//! Describe and approve act for a signed-in user; redeem is unauthenticated by
//! necessity (the client has no session yet) and relies on the PKCE verifier.

use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};

use crate::{error::AppError, services::authorize as authorize_svc, state::AppState};

use super::extractors::{AuthUser, ClientIp, UserAgent};

/// Longest `state` parameter echoed back to the client.
const MAX_STATE_LEN: usize = 512;

#[derive(Deserialize)]
pub struct DescribeRequest {
    pub client_id: String,
    pub redirect_uri: String,
}

#[derive(Serialize)]
pub struct DescribeResponse {
    pub client_id: String,
    pub client_name: String,
    pub scopes: Vec<String>,
    pub unrestricted: bool,
    pub unavailable_scopes: Vec<String>,
    pub sessions_used: i64,
    pub sessions_allowed: Option<i64>,
}

#[derive(Deserialize)]
pub struct ApproveRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    #[serde(default = "s256")]
    pub code_challenge_method: String,
    /// Opaque client value echoed in the redirect (CSRF protection, RFC 6749).
    pub state: Option<String>,
    /// Required for a non-primary client unless the session re-authenticated recently.
    pub current_password: Option<String>,
}

fn s256() -> String {
    "S256".into()
}

#[derive(Serialize)]
pub struct ApproveResponse {
    /// Where to send the browser: the redirect URI carrying `code` (and `state`).
    pub redirect_to: String,
}

#[derive(Deserialize)]
pub struct RedeemRequest {
    pub code: String,
    pub code_verifier: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub device_name: Option<String>,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
}

/// POST /auth/authorize/describe
pub async fn describe(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<DescribeRequest>,
) -> Result<Json<DescribeResponse>, AppError> {
    let request =
        authorize_svc::describe(&state, auth.user_id, &body.client_id, &body.redirect_uri).await?;

    Ok(Json(DescribeResponse {
        client_id: request.client_id,
        client_name: request.client_name,
        scopes: request.scopes,
        unrestricted: request.unrestricted,
        unavailable_scopes: request.unavailable_scopes,
        sessions_used: request.sessions_used,
        sessions_allowed: request.sessions_allowed,
    }))
}

/// POST /auth/authorize
pub async fn approve(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    auth: AuthUser,
    Json(body): Json<ApproveRequest>,
) -> Result<Json<ApproveResponse>, AppError> {
    if body
        .state
        .as_deref()
        .is_some_and(|s| s.len() > MAX_STATE_LEN)
    {
        return Err(AppError::Validation("state is too long".into()));
    }

    let code = authorize_svc::approve(
        &state,
        &authorize_svc::Approval {
            user_id: auth.user_id,
            session_id: auth.session_id,
            client_id: &body.client_id,
            redirect_uri: &body.redirect_uri,
            code_challenge: &body.code_challenge,
            code_challenge_method: &body.code_challenge_method,
            current_password: body.current_password.as_deref(),
            ip,
            request_id: auth.request_id,
        },
    )
    .await?;

    // The redirect was validated to carry no query, so these are its only
    // parameters; the URL builder percent-encodes them.
    let mut redirect = reqwest::Url::parse(&body.redirect_uri)
        .map_err(|_| AppError::Validation("invalid redirect_uri".into()))?;
    redirect.query_pairs_mut().append_pair("code", &code);
    if let Some(client_state) = body.state.as_deref() {
        redirect
            .query_pairs_mut()
            .append_pair("state", client_state);
    }

    Ok(Json(ApproveResponse {
        redirect_to: redirect.to_string(),
    }))
}

/// POST /auth/authorize/token
pub async fn token(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    UserAgent(ua): UserAgent,
    Json(body): Json<RedeemRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    let tokens = authorize_svc::redeem(
        &state,
        &authorize_svc::Redemption {
            code: &body.code,
            verifier: &body.code_verifier,
            client_id: &body.client_id,
            redirect_uri: &body.redirect_uri,
            ip,
            user_agent: ua.as_deref(),
            device_name: body.device_name.as_deref(),
        },
    )
    .await?;

    Ok(Json(TokenResponse {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
    }))
}
