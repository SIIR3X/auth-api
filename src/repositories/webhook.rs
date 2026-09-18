//! Repository for `webhook_endpoints` and `webhook_deliveries`.

use std::time::Duration;

use serde_json::Value;
use sqlx::{PgExecutor, PgPool};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct WebhookEndpoint {
    pub id: Uuid,
    pub url: String,
    pub description: Option<String>,
    pub events: Vec<String>,
    /// Encrypted with the keyring.
    pub secret: String,
    pub enabled: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

pub struct EndpointSettings<'a> {
    pub url: &'a str,
    pub description: Option<&'a str>,
    pub events: &'a [String],
    pub enabled: bool,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct WebhookDelivery {
    pub id: Uuid,
    pub endpoint_id: Uuid,
    pub event_id: Uuid,
    pub event_name: String,
    pub occurred_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
    pub attempts: i32,
    pub next_attempt_at: OffsetDateTime,
    pub delivered_at: Option<OffsetDateTime>,
    pub failed_at: Option<OffsetDateTime>,
    pub last_status: Option<i16>,
    pub last_error: Option<String>,
}

/// A delivery claimed by a dispatcher, with what it needs to send it.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ClaimedDelivery {
    pub id: Uuid,
    pub event_id: Uuid,
    pub event_name: String,
    pub payload: Value,
    pub occurred_at: OffsetDateTime,
    pub attempts: i32,
    pub url: String,
    pub secret: String,
}

// Endpoints

pub async fn create_endpoint(
    pool: &PgPool,
    settings: &EndpointSettings<'_>,
    encrypted_secret: &str,
) -> Result<WebhookEndpoint, sqlx::Error> {
    sqlx::query_as::<_, WebhookEndpoint>(
        "INSERT INTO webhook_endpoints (url, description, events, enabled, secret)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING *",
    )
    .bind(settings.url)
    .bind(settings.description)
    .bind(settings.events)
    .bind(settings.enabled)
    .bind(encrypted_secret)
    .fetch_one(pool)
    .await
}

pub async fn update_endpoint(
    pool: &PgPool,
    id: Uuid,
    settings: &EndpointSettings<'_>,
) -> Result<Option<WebhookEndpoint>, sqlx::Error> {
    sqlx::query_as::<_, WebhookEndpoint>(
        "UPDATE webhook_endpoints
         SET url = $2, description = $3, events = $4, enabled = $5
         WHERE id = $1
         RETURNING *",
    )
    .bind(id)
    .bind(settings.url)
    .bind(settings.description)
    .bind(settings.events)
    .bind(settings.enabled)
    .fetch_optional(pool)
    .await
}

pub async fn replace_secret(
    pool: &PgPool,
    id: Uuid,
    encrypted_secret: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("UPDATE webhook_endpoints SET secret = $2 WHERE id = $1")
        .bind(id)
        .bind(encrypted_secret)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn delete_endpoint(pool: &PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM webhook_endpoints WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn find_all_endpoints(pool: &PgPool) -> Result<Vec<WebhookEndpoint>, sqlx::Error> {
    sqlx::query_as::<_, WebhookEndpoint>("SELECT * FROM webhook_endpoints ORDER BY created_at")
        .fetch_all(pool)
        .await
}

pub async fn find_endpoint(
    pool: &PgPool,
    id: Uuid,
) -> Result<Option<WebhookEndpoint>, sqlx::Error> {
    sqlx::query_as::<_, WebhookEndpoint>("SELECT * FROM webhook_endpoints WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
}

/// Replace a secret only if it still holds the value that was read (key
/// rotation beside live traffic).
pub async fn rewrap_secret(
    pool: &PgPool,
    id: Uuid,
    expected: &str,
    replacement: &str,
) -> Result<bool, sqlx::Error> {
    let result =
        sqlx::query("UPDATE webhook_endpoints SET secret = $3 WHERE id = $1 AND secret = $2")
            .bind(id)
            .bind(expected)
            .bind(replacement)
            .execute(pool)
            .await?;
    Ok(result.rows_affected() == 1)
}

// Deliveries

/// Record the event in the outbox and a delivery for every enabled endpoint
/// subscribed to it, in one statement of the caller's transaction.
pub async fn record_event<'e>(
    executor: impl PgExecutor<'e>,
    subject: &str,
    event_name: &str,
    payload: &Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "WITH event AS (
             INSERT INTO event_outbox (subject, payload) VALUES ($1, $2)
             RETURNING id, created_at
         )
         INSERT INTO webhook_deliveries (endpoint_id, event_id, event_name, payload, occurred_at)
         SELECT endpoint.id, event.id, $3, $2, event.created_at
         FROM event CROSS JOIN webhook_endpoints endpoint
         WHERE endpoint.enabled AND ($3 = ANY (endpoint.events) OR '*' = ANY (endpoint.events))",
    )
    .bind(subject)
    .bind(payload)
    .bind(event_name)
    .execute(executor)
    .await?;
    Ok(())
}

/// Claim up to `limit` due deliveries for `lease`: another dispatcher skips
/// them until the lease ends, so a crashed one only delays its claims.
pub async fn claim_due(
    pool: &PgPool,
    limit: i64,
    lease: Duration,
) -> Result<Vec<ClaimedDelivery>, sqlx::Error> {
    sqlx::query_as::<_, ClaimedDelivery>(
        "WITH due AS (
             SELECT d.id FROM webhook_deliveries d
             JOIN webhook_endpoints e ON e.id = d.endpoint_id
             WHERE d.delivered_at IS NULL AND d.failed_at IS NULL
               AND d.next_attempt_at <= NOW() AND e.enabled
             ORDER BY d.next_attempt_at
             LIMIT $1
             FOR UPDATE OF d SKIP LOCKED
         ),
         claimed AS (
             UPDATE webhook_deliveries d
             SET next_attempt_at = NOW() + make_interval(secs => $2)
             FROM due WHERE d.id = due.id
             RETURNING d.id, d.endpoint_id, d.event_id, d.event_name, d.payload, d.occurred_at, d.attempts
         )
         SELECT c.id, c.event_id, c.event_name, c.payload, c.occurred_at, c.attempts, e.url, e.secret
         FROM claimed c JOIN webhook_endpoints e ON e.id = c.endpoint_id",
    )
    .bind(limit)
    .bind(lease.as_secs_f64())
    .fetch_all(pool)
    .await
}

pub async fn mark_delivered(pool: &PgPool, id: Uuid, status: u16) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE webhook_deliveries
         SET delivered_at = NOW(), attempts = attempts + 1, last_status = $2, last_error = NULL
         WHERE id = $1",
    )
    .bind(id)
    .bind(i16::try_from(status).unwrap_or(i16::MAX))
    .execute(pool)
    .await?;
    Ok(())
}

/// Record a failed attempt: retried after `retry_in`, or given up when `None`.
pub async fn mark_attempt_failed(
    pool: &PgPool,
    id: Uuid,
    status: Option<u16>,
    error: &str,
    retry_in: Option<Duration>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE webhook_deliveries
         SET attempts = attempts + 1,
             last_status = $2,
             last_error = left($3, 500),
             next_attempt_at = CASE WHEN $4::float8 IS NULL THEN next_attempt_at
                                    ELSE NOW() + make_interval(secs => $4) END,
             failed_at = CASE WHEN $4::float8 IS NULL THEN NOW() ELSE NULL END
         WHERE id = $1",
    )
    .bind(id)
    .bind(status.map(|s| i16::try_from(s).unwrap_or(i16::MAX)))
    .bind(error)
    .bind(retry_in.map(|d| d.as_secs_f64()))
    .execute(pool)
    .await?;
    Ok(())
}

/// The endpoint's latest deliveries, newest first.
pub async fn find_recent_deliveries(
    pool: &PgPool,
    endpoint_id: Uuid,
    limit: i64,
) -> Result<Vec<WebhookDelivery>, sqlx::Error> {
    sqlx::query_as::<_, WebhookDelivery>(
        "SELECT id, endpoint_id, event_id, event_name, occurred_at, created_at, attempts,
                next_attempt_at, delivered_at, failed_at, last_status, last_error
         FROM webhook_deliveries WHERE endpoint_id = $1
         ORDER BY created_at DESC LIMIT $2",
    )
    .bind(endpoint_id)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Queue a delivery again now, with a fresh attempt budget.
pub async fn redeliver(pool: &PgPool, endpoint_id: Uuid, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE webhook_deliveries
         SET attempts = 0, failed_at = NULL, delivered_at = NULL, next_attempt_at = NOW()
         WHERE id = $1 AND endpoint_id = $2",
    )
    .bind(id)
    .bind(endpoint_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Deliveries waiting, for the backlog gauge.
pub async fn pending_count(pool: &PgPool) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM webhook_deliveries WHERE delivered_at IS NULL AND failed_at IS NULL",
    )
    .fetch_one(pool)
    .await
}
