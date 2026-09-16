//! Repository for the `audit_log` partitioned table.
//!
//! This table is append-only; the database enforces it via a trigger.
//! Never attempt UPDATE or DELETE through this repository.

use ipnetwork::IpNetwork;

use serde_json::Value as JsonValue;
use sqlx::{PgExecutor, PgPool};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::audit::{AuditAction, AuditLog};

// Input types

pub struct NewAuditEntry {
    pub user_id: Option<Uuid>,
    pub request_id: Option<Uuid>,
    pub action: AuditAction,
    pub ip_address: Option<IpNetwork>,
    pub metadata: JsonValue,
}

// Write

pub async fn append<'e>(
    executor: impl PgExecutor<'e>,
    entry: &NewAuditEntry,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_log (user_id, request_id, action, ip_address, metadata)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(entry.user_id)
    .bind(entry.request_id)
    .bind(&entry.action)
    .bind(entry.ip_address)
    .bind(&entry.metadata)
    .execute(executor)
    .await?;
    Ok(())
}

// Reads

/// One page of a user's history, newest first: rows strictly older than
/// `before` (`created_at`, `id`) when given. Keyset pagination keeps a page as
/// cheap at the end of a long history as at its start, and a row written while
/// someone pages cannot shift the next page.
///
/// `created_at <= NOW()` lets PostgreSQL skip the empty partitions created in
/// advance for the coming months instead of visiting each of them.
pub async fn find_page_by_user(
    pool: &PgPool,
    user_id: Uuid,
    before: Option<(OffsetDateTime, Uuid)>,
    limit: i64,
) -> Result<Vec<AuditLog>, sqlx::Error> {
    match before {
        None => {
            sqlx::query_as::<_, AuditLog>(
                "SELECT * FROM audit_log
                 WHERE user_id = $1 AND created_at <= NOW()
                 ORDER BY created_at DESC, id DESC
                 LIMIT $2",
            )
            .bind(user_id)
            .bind(limit)
            .fetch_all(pool)
            .await
        }
        Some((created_at, id)) => {
            sqlx::query_as::<_, AuditLog>(
                "SELECT * FROM audit_log
                 WHERE user_id = $1 AND created_at <= NOW() AND (created_at, id) < ($2, $3)
                 ORDER BY created_at DESC, id DESC
                 LIMIT $4",
            )
            .bind(user_id)
            .bind(created_at)
            .bind(id)
            .bind(limit)
            .fetch_all(pool)
            .await
        }
    }
}

/// One page of the whole audit log, newest first, optionally for one account
/// or one action (its snake_case name).
pub async fn find_page(
    pool: &PgPool,
    user_id: Option<Uuid>,
    action: Option<&str>,
    before: Option<(OffsetDateTime, Uuid)>,
    limit: i64,
) -> Result<Vec<AuditLog>, sqlx::Error> {
    let (before_at, before_id) = before.unzip();
    sqlx::query_as::<_, AuditLog>(
        "SELECT * FROM audit_log
         WHERE created_at <= NOW()
           AND ($1::uuid IS NULL OR user_id = $1)
           AND ($2::text IS NULL OR action::text = $2)
           AND ($3::timestamptz IS NULL OR (created_at, id) < ($3, $4))
         ORDER BY created_at DESC, id DESC
         LIMIT $5",
    )
    .bind(user_id)
    .bind(action)
    .bind(before_at)
    .bind(before_id)
    .bind(limit)
    .fetch_all(pool)
    .await
}

pub async fn find_by_user(
    pool: &PgPool,
    user_id: Uuid,
    limit: i64,
    offset: i64,
) -> Result<Vec<AuditLog>, sqlx::Error> {
    sqlx::query_as::<_, AuditLog>(
        "SELECT * FROM audit_log
         WHERE user_id = $1
         ORDER BY created_at DESC
         LIMIT $2 OFFSET $3",
    )
    .bind(user_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
}
