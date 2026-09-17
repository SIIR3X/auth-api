//! `/admin/webhooks`: endpoints receiving domain events, and their deliveries.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    error::AppError,
    handlers::extractors::{AdminUser, ClientIp},
    repositories::webhook::{self as webhook_repo, WebhookDelivery, WebhookEndpoint},
    services::webhooks::{self as webhook_svc, EndpointInput},
    state::AppState,
};

use super::actor;

#[derive(Deserialize, utoipa::ToSchema)]
pub struct WebhookRequest {
    /// HTTPS URL receiving the deliveries.
    pub url: String,
    pub description: Option<String>,
    /// Event names (`user.created`, `user.deleted`, ...) or `*`.
    pub events: Vec<String>,
    /// Default: true.
    pub enabled: Option<bool>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct WebhookResponse {
    pub id: Uuid,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub events: Vec<String>,
    pub enabled: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct CreatedWebhookResponse {
    #[serde(flatten)]
    pub webhook: WebhookResponse,
    /// Signing secret (`whsec_...`), shown once.
    pub secret: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct WebhookSecretResponse {
    /// The new signing secret, shown once; the previous one stops signing now.
    pub secret: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct WebhookDeliveryResponse {
    pub id: Uuid,
    pub event_id: Uuid,
    pub event: String,
    pub attempts: i32,
    pub created_at: i64,
    /// Next attempt, while neither delivered nor given up.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivered_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_status: Option<i16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

fn webhook_response(endpoint: WebhookEndpoint) -> WebhookResponse {
    WebhookResponse {
        id: endpoint.id,
        url: endpoint.url,
        description: endpoint.description,
        events: endpoint.events,
        enabled: endpoint.enabled,
        created_at: endpoint.created_at.unix_timestamp(),
        updated_at: endpoint.updated_at.unix_timestamp(),
    }
}

fn delivery_response(delivery: WebhookDelivery) -> WebhookDeliveryResponse {
    let finished = delivery.delivered_at.is_some() || delivery.failed_at.is_some();
    WebhookDeliveryResponse {
        id: delivery.id,
        event_id: delivery.event_id,
        event: delivery.event_name,
        attempts: delivery.attempts,
        created_at: delivery.created_at.unix_timestamp(),
        next_attempt_at: (!finished).then(|| delivery.next_attempt_at.unix_timestamp()),
        delivered_at: delivery.delivered_at.map(|t| t.unix_timestamp()),
        failed_at: delivery.failed_at.map(|t| t.unix_timestamp()),
        last_status: delivery.last_status,
        last_error: delivery.last_error,
    }
}

fn input(body: &WebhookRequest) -> EndpointInput<'_> {
    EndpointInput {
        url: &body.url,
        description: body.description.as_deref(),
        events: &body.events,
        enabled: body.enabled.unwrap_or(true),
    }
}

#[utoipa::path(
    get,
    path = "/admin/webhooks",
    tag = "admin",
    responses(
        (status = 200, description = "Every webhook endpoint", body = [WebhookResponse]),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Missing `webhooks:manage`, or no second factor enrolled", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn list(
    admin: AdminUser,
    State(state): State<AppState>,
) -> Result<Json<Vec<WebhookResponse>>, AppError> {
    admin.require(&state, "webhooks:manage").await?;
    let endpoints = webhook_repo::find_all_endpoints(&state.db).await?;
    Ok(Json(endpoints.into_iter().map(webhook_response).collect()))
}

#[utoipa::path(
    post,
    path = "/admin/webhooks",
    tag = "admin",
    request_body = WebhookRequest,
    responses(
        (status = 201, description = "Endpoint registered; its signing secret is in this response only", body = CreatedWebhookResponse),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Missing `webhooks:manage`, or no second factor enrolled", body = crate::error::ErrorBody),
        (status = 422, description = "Invalid URL or unknown event", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn create(
    admin: AdminUser,
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(body): Json<WebhookRequest>,
) -> Result<(StatusCode, Json<CreatedWebhookResponse>), AppError> {
    admin.require(&state, "webhooks:manage").await?;
    let saved = webhook_svc::create(&state, &actor(&admin, ip), &input(&body)).await?;
    Ok((
        StatusCode::CREATED,
        Json(CreatedWebhookResponse {
            webhook: webhook_response(saved.endpoint),
            secret: saved.secret.unwrap_or_default(),
        }),
    ))
}

#[utoipa::path(
    put,
    path = "/admin/webhooks/{id}",
    tag = "admin",
    params(("id" = Uuid, Path, description = "Webhook id")),
    request_body = WebhookRequest,
    responses(
        (status = 200, description = "Endpoint updated; the secret is unchanged", body = WebhookResponse),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Missing `webhooks:manage`, or no second factor enrolled", body = crate::error::ErrorBody),
        (status = 404, description = "No such webhook", body = crate::error::ErrorBody),
        (status = 422, description = "Invalid URL or unknown event", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn update(
    admin: AdminUser,
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<Uuid>,
    Json(body): Json<WebhookRequest>,
) -> Result<Json<WebhookResponse>, AppError> {
    admin.require(&state, "webhooks:manage").await?;
    let endpoint = webhook_svc::update(&state, &actor(&admin, ip), id, &input(&body)).await?;
    Ok(Json(webhook_response(endpoint)))
}

#[utoipa::path(
    delete,
    path = "/admin/webhooks/{id}",
    tag = "admin",
    params(("id" = Uuid, Path, description = "Webhook id")),
    responses(
        (status = 204, description = "Endpoint and its pending deliveries removed"),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Missing `webhooks:manage`, or no second factor enrolled", body = crate::error::ErrorBody),
        (status = 404, description = "No such webhook", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn delete(
    admin: AdminUser,
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    admin.require(&state, "webhooks:manage").await?;
    webhook_svc::delete(&state, &actor(&admin, ip), id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/admin/webhooks/{id}/secret",
    tag = "admin",
    params(("id" = Uuid, Path, description = "Webhook id")),
    responses(
        (status = 200, description = "A new signing secret", body = WebhookSecretResponse),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Missing `webhooks:manage`, or no second factor enrolled", body = crate::error::ErrorBody),
        (status = 404, description = "No such webhook", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn rotate_secret(
    admin: AdminUser,
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<Uuid>,
) -> Result<Json<WebhookSecretResponse>, AppError> {
    admin.require(&state, "webhooks:manage").await?;
    let secret = webhook_svc::rotate_secret(&state, &actor(&admin, ip), id).await?;
    Ok(Json(WebhookSecretResponse { secret }))
}

#[utoipa::path(
    get,
    path = "/admin/webhooks/{id}/deliveries",
    tag = "admin",
    params(("id" = Uuid, Path, description = "Webhook id")),
    responses(
        (status = 200, description = "The latest 100 deliveries, newest first", body = [WebhookDeliveryResponse]),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Missing `webhooks:manage`, or no second factor enrolled", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn deliveries(
    admin: AdminUser,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<WebhookDeliveryResponse>>, AppError> {
    admin.require(&state, "webhooks:manage").await?;
    let deliveries = webhook_repo::find_recent_deliveries(&state.db, id, 100).await?;
    Ok(Json(
        deliveries.into_iter().map(delivery_response).collect(),
    ))
}

#[utoipa::path(
    post,
    path = "/admin/webhooks/{id}/deliveries/{delivery_id}/retry",
    tag = "admin",
    params(
        ("id" = Uuid, Path, description = "Webhook id"),
        ("delivery_id" = Uuid, Path, description = "Delivery id"),
    ),
    responses(
        (status = 204, description = "Delivery queued again with a fresh attempt budget"),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Missing `webhooks:manage`, or no second factor enrolled", body = crate::error::ErrorBody),
        (status = 404, description = "No such delivery for this webhook", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn retry(
    admin: AdminUser,
    State(state): State<AppState>,
    Path((id, delivery_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    admin.require(&state, "webhooks:manage").await?;
    webhook_svc::redeliver(&state, id, delivery_id).await?;
    Ok(StatusCode::NO_CONTENT)
}
