//! Repository for the `audit_log` partitioned table.
//!
//! This table is append-only; the database enforces it via a trigger.
//! Never attempt UPDATE or DELETE through this repository.

use std::net::IpAddr;

use serde_json::Value as JsonValue;
use sqlx::PgPool;
use uuid::Uuid;

use crate::domain::audit::{AuditAction, AuditLog};

// Input types

pub struct NewAuditEntry {
    pub user_id: Option<Uuid>,
    pub request_id: Option<Uuid>,
    pub action: AuditAction,
    pub ip_address: Option<IpAddr>,
    pub metadata: JsonValue,
}

// Write

pub async fn append(pool: &PgPool, entry: &NewAuditEntry) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_log (user_id, request_id, action, ip_address, metadata)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(entry.user_id)
    .bind(entry.request_id)
    .bind(&entry.action)
    .bind(entry.ip_address)
    .bind(&entry.metadata)
    .execute(pool)
    .await?;
    Ok(())
}

// Reads

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

pub async fn find_by_action(
    pool: &PgPool,
    action: AuditAction,
    limit: i64,
    offset: i64,
) -> Result<Vec<AuditLog>, sqlx::Error> {
    sqlx::query_as::<_, AuditLog>(
        "SELECT * FROM audit_log
         WHERE action = $1
         ORDER BY created_at DESC
         LIMIT $2 OFFSET $3",
    )
    .bind(action)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
}

/// Returns all events tied to a single request, useful for incident investigation.
pub async fn find_by_request_id(
    pool: &PgPool,
    request_id: Uuid,
) -> Result<Vec<AuditLog>, sqlx::Error> {
    sqlx::query_as::<_, AuditLog>(
        "SELECT * FROM audit_log
         WHERE request_id = $1
         ORDER BY created_at ASC",
    )
    .bind(request_id)
    .fetch_all(pool)
    .await
}
