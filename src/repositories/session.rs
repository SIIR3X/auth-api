//! Repository for the `sessions` table.
//!
//! Refresh token rotation is handled atomically inside `rotate`: the old session
//! is revoked and the new one is created in a single transaction to prevent
//! any window where both tokens are valid simultaneously.

use ipnetwork::IpNetwork;

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::session::Session;

// Input types

pub struct NewSession<'a> {
    pub user_id: Uuid,
    pub session_family_id: Uuid,
    pub expires_at: OffsetDateTime,
    pub ip_address: Option<IpNetwork>,
    pub device_name: Option<&'a str>,
    pub token_hash: &'a [u8],
    pub user_agent: Option<&'a str>,
}

// Writes

pub async fn create(pool: &PgPool, input: &NewSession<'_>) -> Result<Session, sqlx::Error> {
    sqlx::query_as::<_, Session>(
        "INSERT INTO sessions
             (user_id, session_family_id, expires_at, ip_address, device_name, token_hash, user_agent)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING *",
    )
    .bind(input.user_id)
    .bind(input.session_family_id)
    .bind(input.expires_at)
    .bind(input.ip_address)
    .bind(input.device_name)
    .bind(input.token_hash)
    .bind(input.user_agent)
    .fetch_one(pool)
    .await
}

/// Atomically revokes the old session and creates its replacement.
/// The new session inherits the same session_family_id.
pub async fn rotate(
    pool: &PgPool,
    old_session_id: Uuid,
    input: &NewSession<'_>,
) -> Result<Session, sqlx::Error> {
    let mut tx = pool.begin().await?;

    let new_session = sqlx::query_as::<_, Session>(
        "INSERT INTO sessions
             (user_id, session_family_id, expires_at, ip_address, device_name, token_hash, user_agent)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING *",
    )
    .bind(input.user_id)
    .bind(input.session_family_id)
    .bind(input.expires_at)
    .bind(input.ip_address)
    .bind(input.device_name)
    .bind(input.token_hash)
    .bind(input.user_agent)
    .fetch_one(&mut *tx)
    .await?;

    sqlx::query(
        "UPDATE sessions
         SET revoked_at = NOW(),
             rotated_at = NOW(),
             replaced_by_session_id = $2
         WHERE id = $1",
    )
    .bind(old_session_id)
    .bind(new_session.id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(new_session)
}

pub async fn revoke(pool: &PgPool, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE sessions SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn revoke_all_by_user(pool: &PgPool, user_id: Uuid) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE sessions SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Revokes all active sessions for a user except the given session.
pub async fn revoke_all_except(
    pool: &PgPool,
    user_id: Uuid,
    except_session_id: Uuid,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE sessions SET revoked_at = NOW()
         WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .bind(except_session_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Calls the database function that revokes every session in the same family.
/// Used when a refresh token replay attack is detected.
pub async fn revoke_family(pool: &PgPool, session_id: Uuid) -> Result<u64, sqlx::Error> {
    let row: (i32,) = sqlx::query_as("SELECT revoke_session_family($1)")
        .bind(session_id)
        .fetch_one(pool)
        .await?;
    Ok(row.0 as u64)
}

// Reads

pub async fn find_by_token_hash(
    pool: &PgPool,
    token_hash: &[u8],
) -> Result<Option<Session>, sqlx::Error> {
    sqlx::query_as::<_, Session>("SELECT * FROM sessions WHERE token_hash = $1")
        .bind(token_hash)
        .fetch_optional(pool)
        .await
}

pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Session>, sqlx::Error> {
    sqlx::query_as::<_, Session>("SELECT * FROM sessions WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
}

/// Returns non-revoked sessions ordered by most recently used.
pub async fn find_active_by_user(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Vec<Session>, sqlx::Error> {
    sqlx::query_as::<_, Session>(
        "SELECT * FROM sessions
         WHERE user_id = $1 AND revoked_at IS NULL
         ORDER BY last_used_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}
