//! Personal access tokens: `/users/me/tokens`, and their exchange for access
//! tokens.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    domain::personal_access_token::PersonalAccessToken, error::AppError,
    services::personal_access_token as pat_svc, state::AppState,
};

use super::extractors::{AuthUser, ClientIp};

#[derive(Deserialize, utoipa::ToSchema)]
pub struct CreatePersonalAccessTokenRequest {
    pub name: String,
    /// Permissions the token's access tokens carry; each must be held by the
    /// account. Empty: none.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// 1 to 365 (default 90).
    pub expires_in_days: Option<i64>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct PersonalAccessTokenResponse {
    pub id: Uuid,
    pub name: String,
    pub scopes: Vec<String>,
    pub created_at: i64,
    pub expires_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<i64>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct CreatedPersonalAccessTokenResponse {
    #[serde(flatten)]
    pub token: PersonalAccessTokenResponse,
    /// The secret, shown once.
    pub secret: String,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct PersonalAccessTokenExchangeRequest {
    /// A personal access token (`aapat_...`).
    pub token: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct PersonalAccessTokenExchangeResponse {
    pub access_token: String,
    /// Always `Bearer`.
    pub token_type: &'static str,
    /// Seconds.
    pub expires_in: u64,
}

fn token_response(token: PersonalAccessToken) -> PersonalAccessTokenResponse {
    PersonalAccessTokenResponse {
        id: token.id,
        name: token.name,
        scopes: token.scopes,
        created_at: token.created_at.unix_timestamp(),
        expires_at: token.expires_at.unix_timestamp(),
        last_used_at: token.last_used_at.map(|t| t.unix_timestamp()),
    }
}

#[utoipa::path(
    get,
    path = "/users/me/tokens",
    tag = "account",
    responses(
        (status = 200, description = "Personal access tokens that still work, newest first", body = [PersonalAccessTokenResponse]),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn list(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<PersonalAccessTokenResponse>>, AppError> {
    let tokens = pat_svc::list(&state, auth.user_id).await?;
    Ok(Json(tokens.into_iter().map(token_response).collect()))
}

#[utoipa::path(
    post,
    path = "/users/me/tokens",
    tag = "account",
    request_body = CreatePersonalAccessTokenRequest,
    responses(
        (status = 201, description = "Token created; its secret is in this response only", body = CreatedPersonalAccessTokenResponse),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Recent re-authentication required", body = crate::error::ErrorBody),
        (status = 409, description = "`too_many_tokens`", body = crate::error::ErrorBody),
        (status = 422, description = "Invalid name or lifetime, or a scope the account does not hold", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn create(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    auth: AuthUser,
    Json(body): Json<CreatePersonalAccessTokenRequest>,
) -> Result<(StatusCode, Json<CreatedPersonalAccessTokenResponse>), AppError> {
    let created = pat_svc::create(
        &state,
        auth.user_id,
        auth.session_id,
        &body.name,
        &body.scopes,
        body.expires_in_days,
        ip,
        auth.request_id,
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(CreatedPersonalAccessTokenResponse {
            token: token_response(created.token),
            secret: created.secret,
        }),
    ))
}

#[utoipa::path(
    delete,
    path = "/users/me/tokens/{id}",
    tag = "account",
    params(("id" = Uuid, Path, description = "Token id")),
    responses(
        (status = 204, description = "Token revoked"),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 404, description = "No such token for this account", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn revoke(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    pat_svc::revoke(&state, auth.user_id, id, ip, auth.request_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/auth/personal-access-tokens/exchange",
    tag = "auth",
    request_body = PersonalAccessTokenExchangeRequest,
    responses(
        (status = 200, description = "A short-lived access token carrying the token's scopes", body = PersonalAccessTokenExchangeResponse),
        (status = 401, description = "Unknown, revoked or expired token", body = crate::error::ErrorBody),
        (status = 403, description = "Account locked, suspended or inactive", body = crate::error::ErrorBody),
        (status = 429, description = "Rate limited; see Retry-After"),
    ),
)]
pub async fn exchange(
    State(state): State<AppState>,
    Json(body): Json<PersonalAccessTokenExchangeRequest>,
) -> Result<Json<PersonalAccessTokenExchangeResponse>, AppError> {
    let exchanged = pat_svc::exchange(&state, &body.token).await?;
    Ok(Json(PersonalAccessTokenExchangeResponse {
        access_token: exchanged.access_token,
        token_type: "Bearer",
        expires_in: exchanged.expires_in,
    }))
}
