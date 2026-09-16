//! Repository for `event_outbox`, the transactional outbox of domain events.

use std::time::Duration;

use serde_json::Value;
use sqlx::PgExecutor;
use time::OffsetDateTime;
use uuid::Uuid;

/// A pending event at the head of the queue.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PendingEvent {
    pub seq: i64,
    pub id: Uuid,
    pub subject: String,
    pub payload: Value,
    pub created_at: OffsetDateTime,
    pub attempts: i32,
    /// Whether its next attempt is due now.
    pub due: bool,
}

/// Record an event; call it with the transaction of the change it announces.
pub async fn insert<'e>(
    executor: impl PgExecutor<'e>,
    subject: &str,
    payload: &Value,
) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar("INSERT INTO event_outbox (subject, payload) VALUES ($1, $2) RETURNING id")
        .bind(subject)
        .bind(payload)
        .fetch_one(executor)
        .await
}

/// The oldest unpublished events, in the order they were recorded.
pub async fn head<'e>(
    executor: impl PgExecutor<'e>,
    limit: i64,
) -> Result<Vec<PendingEvent>, sqlx::Error> {
    sqlx::query_as::<_, PendingEvent>(
        "SELECT seq, id, subject, payload, created_at, attempts, next_attempt_at <= NOW() AS due
         FROM event_outbox
         WHERE published_at IS NULL
         ORDER BY seq
         LIMIT $1",
    )
    .bind(limit)
    .fetch_all(executor)
    .await
}

pub async fn mark_published<'e>(
    executor: impl PgExecutor<'e>,
    seq: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE event_outbox SET published_at = NOW(), last_error = NULL WHERE seq = $1")
        .bind(seq)
        .execute(executor)
        .await?;
    Ok(())
}

/// Count a failed attempt and schedule the next one `retry_in` from now.
pub async fn mark_failed<'e>(
    executor: impl PgExecutor<'e>,
    seq: i64,
    error: &str,
    retry_in: Duration,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE event_outbox
         SET attempts = attempts + 1,
             last_error = $2,
             next_attempt_at = NOW() + make_interval(secs => $3)
         WHERE seq = $1",
    )
    .bind(seq)
    .bind(error)
    .bind(retry_in.as_secs_f64())
    .execute(executor)
    .await?;
    Ok(())
}

/// Unpublished events: how many, and the age in seconds of the oldest (0 when
/// none).
pub async fn backlog<'e>(executor: impl PgExecutor<'e>) -> Result<(i64, f64), sqlx::Error> {
    sqlx::query_as(
        "SELECT count(*),
                COALESCE(EXTRACT(EPOCH FROM NOW() - min(created_at))::float8, 0)
         FROM event_outbox
         WHERE published_at IS NULL",
    )
    .fetch_one(executor)
    .await
}
