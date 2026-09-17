//! External identity providers: `/auth/external` and
//! `/users/me/external-identities`.

use axum::{
    Json,
    extract::{Path, RawQuery, State},
    http::StatusCode,
    response::{IntoResponse, Redirect},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    domain::oauth,
    error::AppError,
    repositories::external_identity::ExternalIdentity,
    services::external_identity::{self as external_svc, Intent, Started},
    state::AppState,
};

use super::{
    auth::LoginResponse,
    extractors::{AuthUser, ClientIp, RequestId, UserAgent},
    user::CurrentPasswordRequest,
};

#[derive(Serialize, utoipa::ToSchema)]
pub struct IdentityProviderResponse {
    pub name: String,
    pub display_name: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct ExternalStartResponse {
    /// Send the browser there.
    pub authorization_url: String,
    /// Keep in the browser (session storage) and present at completion.
    pub binding: String,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct ExternalCompleteRequest {
    /// `code` given to `EXTERNAL_LOGIN_URI` after the provider.
    pub code: String,
    pub binding: String,
    pub device_name: Option<String>,
    pub remember_me: Option<bool>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct ExternalIdentityResponse {
    pub id: Uuid,
    pub provider: String,
    pub created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<i64>,
}

fn started(started: Started) -> Json<ExternalStartResponse> {
    Json(ExternalStartResponse {
        authorization_url: started.authorization_url,
        binding: started.binding,
    })
}

fn identity_response(identity: ExternalIdentity) -> ExternalIdentityResponse {
    ExternalIdentityResponse {
        id: identity.id,
        provider: identity.provider,
        created_at: identity.created_at.unix_timestamp(),
        last_used_at: identity.last_used_at.map(|t| t.unix_timestamp()),
    }
}

#[utoipa::path(
    get,
    path = "/auth/external/providers",
    tag = "external-identities",
    responses(
        (status = 200, description = "Configured identity providers", body = [IdentityProviderResponse]),
    ),
)]
pub async fn providers(State(state): State<AppState>) -> Json<Vec<IdentityProviderResponse>> {
    Json(
        state
            .config
            .identity_providers
            .iter()
            .map(|p| IdentityProviderResponse {
                name: p.name.clone(),
                display_name: p.display_name.clone(),
            })
            .collect(),
    )
}

#[utoipa::path(
    post,
    path = "/auth/external/{provider}/start",
    tag = "external-identities",
    params(("provider" = String, Path, description = "Provider name")),
    responses(
        (status = 200, description = "Where to send the browser to sign in", body = ExternalStartResponse),
        (status = 404, description = "No such provider", body = crate::error::ErrorBody),
        (status = 503, description = "The provider's metadata is unavailable", body = crate::error::ErrorBody),
    ),
)]
pub async fn start_sign_in(
    State(state): State<AppState>,
    Path(provider): Path<String>,
) -> Result<Json<ExternalStartResponse>, AppError> {
    Ok(started(
        external_svc::start(&state, &provider, Intent::SignIn, None).await?,
    ))
}

#[utoipa::path(
    get,
    path = "/auth/external/{provider}/callback",
    tag = "external-identities",
    params(("provider" = String, Path, description = "Provider name")),
    responses(
        (status = 303, description = "To `EXTERNAL_LOGIN_URI` with `code`, or `error` when the request matches no pending sign-in"),
        (status = 404, description = "No such provider", body = crate::error::ErrorBody),
    ),
)]
pub async fn callback(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    RawQuery(query): RawQuery,
) -> Result<impl IntoResponse, AppError> {
    let parameters = oauth::form_parameters(query.unwrap_or_default().as_bytes())
        .map_err(AppError::Validation)?;
    let location = external_svc::callback(&state, &provider, &parameters).await?;
    Ok(Redirect::to(&location))
}

#[utoipa::path(
    post,
    path = "/auth/external/complete",
    tag = "external-identities",
    request_body = ExternalCompleteRequest,
    responses(
        (status = 200, description = "Tokens, or the account's two-factor challenge", body = LoginResponse),
        (status = 401, description = "Unknown, used or foreign code", body = crate::error::ErrorBody),
        (status = 403, description = "Account locked, suspended or inactive", body = crate::error::ErrorBody),
        (status = 409, description = "`external_identity_not_linked`", body = crate::error::ErrorBody),
        (status = 503, description = "The provider could not identify the person", body = crate::error::ErrorBody),
    ),
)]
pub async fn complete_sign_in(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    UserAgent(ua): UserAgent,
    RequestId(rid): RequestId,
    Json(body): Json<ExternalCompleteRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    let result = external_svc::complete_sign_in(
        &state,
        &body.code,
        &body.binding,
        ip,
        ua.as_deref(),
        body.device_name.as_deref(),
        body.remember_me.unwrap_or(false),
        rid,
    )
    .await?;
    Ok(Json(super::auth::login_response(result)))
}

#[utoipa::path(
    get,
    path = "/users/me/external-identities",
    tag = "external-identities",
    responses(
        (status = 200, description = "Identities linked to the account", body = [ExternalIdentityResponse]),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn list(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<ExternalIdentityResponse>>, AppError> {
    let identities = external_svc::list(&state, auth.user_id).await?;
    Ok(Json(
        identities.into_iter().map(identity_response).collect(),
    ))
}

#[utoipa::path(
    post,
    path = "/users/me/external-identities/{provider}/start",
    tag = "external-identities",
    params(("provider" = String, Path, description = "Provider name")),
    responses(
        (status = 200, description = "Where to send the browser to link the identity", body = ExternalStartResponse),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Recent re-authentication required", body = crate::error::ErrorBody),
        (status = 404, description = "No such provider", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn start_link(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    auth: AuthUser,
    Path(provider): Path<String>,
) -> Result<Json<ExternalStartResponse>, AppError> {
    Ok(started(
        external_svc::start_link(
            &state,
            auth.user_id,
            auth.session_id,
            &provider,
            ip,
            auth.request_id,
        )
        .await?,
    ))
}

#[utoipa::path(
    post,
    path = "/users/me/external-identities/complete",
    tag = "external-identities",
    request_body = ExternalCompleteRequest,
    responses(
        (status = 201, description = "Identity linked", body = ExternalIdentityResponse),
        (status = 401, description = "Missing, invalid or revoked access token, or an unknown, used or foreign code", body = crate::error::ErrorBody),
        (status = 409, description = "`external_identity_already_linked`", body = crate::error::ErrorBody),
        (status = 503, description = "The provider could not identify the person", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn complete_link(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<ExternalCompleteRequest>,
) -> Result<(StatusCode, Json<ExternalIdentityResponse>), AppError> {
    let identity =
        external_svc::complete_link(&state, auth.user_id, &body.code, &body.binding).await?;
    Ok((StatusCode::CREATED, Json(identity_response(identity))))
}

#[utoipa::path(
    delete,
    path = "/users/me/external-identities/{id}",
    tag = "external-identities",
    params(("id" = Uuid, Path, description = "Identity id")),
    request_body = Option<CurrentPasswordRequest>,
    responses(
        (status = 204, description = "Identity unlinked"),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Recent re-authentication required", body = crate::error::ErrorBody),
        (status = 404, description = "No such identity on this account", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn unlink(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    auth: AuthUser,
    Path(id): Path<Uuid>,
    body: Option<Json<CurrentPasswordRequest>>,
) -> Result<StatusCode, AppError> {
    let current_password = body.and_then(|Json(b)| b.current_password);
    external_svc::unlink(
        &state,
        auth.user_id,
        auth.session_id,
        id,
        current_password.as_deref(),
        ip,
        auth.request_id,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}
