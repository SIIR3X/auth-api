//! `/admin/clients`: client applications.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};

use crate::{
    domain::registered_client::RegisteredClient,
    error::AppError,
    handlers::extractors::{AdminUser, ClientIp},
    repositories::registered_client::NewRegisteredClient,
    services::admin::clients as admin_clients,
    state::AppState,
};

use super::actor;

#[derive(Serialize, utoipa::ToSchema)]
pub struct ClientResponse {
    pub client_id: String,
    pub display_name: String,
    pub is_primary: bool,
    /// Permissions its tokens may carry; empty means every permission of the user.
    pub scopes: Vec<String>,
    pub redirect_uris: Vec<String>,
    pub allows_loopback_redirect: bool,
    pub default_max_sessions: i16,
    /// Authenticates with a secret at the token endpoint.
    pub confidential: bool,
    /// May obtain tokens for itself with the client credentials grant.
    pub allows_client_credentials: bool,
    pub created_at: i64,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct ClientSecretResponse {
    /// The client secret (`aacs_...`), shown once.
    pub client_secret: String,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct SaveClientRequest {
    pub display_name: String,
    #[serde(default)]
    pub is_primary: bool,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub allows_loopback_redirect: bool,
    /// Default: 5.
    pub default_max_sessions: Option<i16>,
    /// Allow the client credentials grant; needs a secret and scopes. Omitted:
    /// unchanged (false for a new client).
    pub allows_client_credentials: Option<bool>,
}

fn client_response(client: RegisteredClient) -> ClientResponse {
    ClientResponse {
        confidential: client.is_confidential(),
        allows_client_credentials: client.allows_client_credentials,
        created_at: client.created_at.unix_timestamp(),
        client_id: client.client_id,
        display_name: client.display_name,
        is_primary: client.is_primary,
        scopes: client.scopes,
        redirect_uris: client.redirect_uris,
        allows_loopback_redirect: client.allows_loopback_redirect,
        default_max_sessions: client.default_max_sessions,
    }
}

#[utoipa::path(
    get,
    path = "/admin/clients",
    tag = "admin",
    responses(
        (status = 200, description = "Every registered client", body = [ClientResponse]),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Missing `clients:manage`, or no second factor enrolled", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn list(
    admin: AdminUser,
    State(state): State<AppState>,
) -> Result<Json<Vec<ClientResponse>>, AppError> {
    admin.require(&state, "clients:manage").await?;
    let clients = admin_clients::list(&state).await?;
    Ok(Json(clients.into_iter().map(client_response).collect()))
}

#[utoipa::path(
    put,
    path = "/admin/clients/{client_id}",
    tag = "admin",
    params(("client_id" = String, Path, description = "Client id, 1 to 100 of [A-Za-z0-9._-]")),
    request_body = SaveClientRequest,
    responses(
        (status = 200, description = "Client updated", body = ClientResponse),
        (status = 201, description = "Client registered", body = ClientResponse),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Missing `clients:manage`, no second factor, or re-authentication required", body = crate::error::ErrorBody),
        (status = 409, description = "`primary_client_exists`", body = crate::error::ErrorBody),
        (status = 422, description = "Invalid settings or unknown scope", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn save(
    admin: AdminUser,
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(client_id): Path<String>,
    Json(body): Json<SaveClientRequest>,
) -> Result<(StatusCode, Json<ClientResponse>), AppError> {
    admin.require(&state, "clients:manage").await?;
    let (client, created) = admin_clients::save(
        &state,
        &actor(&admin, ip),
        &NewRegisteredClient {
            client_id: &client_id,
            display_name: &body.display_name,
            is_primary: body.is_primary,
            scopes: &body.scopes,
            redirect_uris: &body.redirect_uris,
            allows_loopback_redirect: body.allows_loopback_redirect,
            default_max_sessions: body.default_max_sessions.unwrap_or(5),
        },
        body.allows_client_credentials,
    )
    .await?;
    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(client_response(client))))
}

#[utoipa::path(
    delete,
    path = "/admin/clients/{client_id}",
    tag = "admin",
    params(("client_id" = String, Path, description = "Client id")),
    responses(
        (status = 204, description = "Client removed and its sessions revoked"),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Missing `clients:manage`, or no second factor enrolled", body = crate::error::ErrorBody),
        (status = 404, description = "No such client", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn delete(
    admin: AdminUser,
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(client_id): Path<String>,
) -> Result<StatusCode, AppError> {
    admin.require(&state, "clients:manage").await?;
    admin_clients::delete(&state, &actor(&admin, ip), &client_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/admin/clients/{client_id}/secret",
    tag = "admin",
    params(("client_id" = String, Path, description = "Client id")),
    responses(
        (status = 200, description = "A new secret; the client is confidential from now on", body = ClientSecretResponse),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Missing `clients:manage`, no second factor, or re-authentication required", body = crate::error::ErrorBody),
        (status = 404, description = "No such client", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn rotate_secret(
    admin: AdminUser,
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(client_id): Path<String>,
) -> Result<Json<ClientSecretResponse>, AppError> {
    admin.require(&state, "clients:manage").await?;
    crate::services::reauth::require_recent_reauth_or_password(
        &state,
        admin.auth.user_id,
        admin.auth.session_id,
        None,
        ip,
        admin.auth.request_id,
        "admin_client_secret",
    )
    .await?;
    let client_secret =
        admin_clients::rotate_secret(&state, &actor(&admin, ip), &client_id).await?;
    Ok(Json(ClientSecretResponse { client_secret }))
}

#[utoipa::path(
    delete,
    path = "/admin/clients/{client_id}/secret",
    tag = "admin",
    params(("client_id" = String, Path, description = "Client id")),
    responses(
        (status = 204, description = "Secret removed; the client is public"),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Missing `clients:manage`, or no second factor enrolled", body = crate::error::ErrorBody),
        (status = 404, description = "No such client", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn remove_secret(
    admin: AdminUser,
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(client_id): Path<String>,
) -> Result<StatusCode, AppError> {
    admin.require(&state, "clients:manage").await?;
    admin_clients::remove_secret(&state, &actor(&admin, ip), &client_id).await?;
    Ok(StatusCode::NO_CONTENT)
}
