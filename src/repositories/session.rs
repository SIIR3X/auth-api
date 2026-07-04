//! Repository for the `sessions` table.
//!
//! Refresh token rotation is handled atomically inside `rotate`: the old session
//! is revoked and the new one is created in a single transaction to prevent
//! any window where both tokens are valid simultaneously.

use ipnetwork::IpNetwork;

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::session::{Session, SessionType};

pub const FIND_BY_TOKEN_HASH_SQL: &str = "SELECT * FROM sessions WHERE token_hash = $1";
pub const FIND_VALIDATION_BY_ID_SQL: &str =
    "SELECT expires_at, revoked_at FROM sessions WHERE id = $1";
pub const FIND_ACTIVE_BY_USER_SQL: &str = "SELECT * FROM sessions
         WHERE user_id = $1 AND revoked_at IS NULL
         ORDER BY last_used_at DESC";
pub const FIND_ACTIVE_SUMMARY_BY_USER_SQL: &str = "SELECT id, last_used_at, expires_at, created_at,
            ip_address, device_name, user_agent, session_type, client_id
         FROM sessions
         WHERE user_id = $1 AND revoked_at IS NULL
         ORDER BY last_used_at DESC";

// Input types

pub struct NewSession<'a> {
    pub user_id: Uuid,
    pub session_family_id: Uuid,
    pub expires_at: OffsetDateTime,
    pub ip_address: Option<IpNetwork>,
    pub device_name: Option<&'a str>,
    pub remember_me: bool,
    pub token_hash: &'a [u8],
    pub user_agent: Option<&'a str>,
    pub session_type: SessionType,
    pub client_id: Option<&'a str>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SessionValidation {
    pub expires_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ActiveSessionSummary {
    pub id: Uuid,
    pub last_used_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
    pub ip_address: Option<IpNetwork>,
    pub device_name: Option<String>,
    pub user_agent: Option<String>,
    pub session_type: SessionType,
    pub client_id: Option<String>,
}

impl SessionValidation {
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none() && self.expires_at > OffsetDateTime::now_utc()
    }
}

// Writes

pub async fn create(pool: &PgPool, input: &NewSession<'_>) -> Result<Session, sqlx::Error> {
    sqlx::query_as::<_, Session>(
        "INSERT INTO sessions
             (user_id, session_family_id, expires_at, ip_address, device_name, remember_me, token_hash, user_agent, session_type, client_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         RETURNING *",
    )
    .bind(input.user_id)
    .bind(input.session_family_id)
    .bind(input.expires_at)
    .bind(input.ip_address)
    .bind(input.device_name)
    .bind(input.remember_me)
    .bind(input.token_hash)
    .bind(input.user_agent)
    .bind(input.session_type)
    .bind(input.client_id)
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

    let old_session =
        sqlx::query_as::<_, Session>("SELECT * FROM sessions WHERE id = $1 FOR UPDATE")
            .bind(old_session_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(sqlx::Error::RowNotFound)?;

    if old_session.revoked_at.is_some() {
        return Err(sqlx::Error::RowNotFound);
    }

    let new_session = sqlx::query_as::<_, Session>(
        "INSERT INTO sessions
             (user_id, session_family_id, expires_at, ip_address, device_name, remember_me, token_hash, user_agent, session_type, client_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         RETURNING *",
    )
    .bind(input.user_id)
    .bind(input.session_family_id)
    .bind(input.expires_at)
    .bind(input.ip_address)
    .bind(input.device_name)
    .bind(input.remember_me)
    .bind(input.token_hash)
    .bind(input.user_agent)
    .bind(input.session_type)
    .bind(input.client_id)
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
    sqlx::query_as::<_, Session>(FIND_BY_TOKEN_HASH_SQL)
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

pub async fn find_validation_by_id(
    pool: &PgPool,
    id: Uuid,
) -> Result<Option<SessionValidation>, sqlx::Error> {
    sqlx::query_as::<_, SessionValidation>(FIND_VALIDATION_BY_ID_SQL)
        .bind(id)
        .fetch_optional(pool)
        .await
}

/// Returns non-revoked sessions ordered by most recently used.
pub async fn find_active_by_user(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Vec<Session>, sqlx::Error> {
    sqlx::query_as::<_, Session>(FIND_ACTIVE_BY_USER_SQL)
        .bind(user_id)
        .fetch_all(pool)
        .await
}

pub async fn count_active_by_type(
    pool: &PgPool,
    user_id: Uuid,
    session_type: SessionType,
) -> Result<i64, sqlx::Error> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM sessions
         WHERE user_id = $1 AND session_type = $2 AND revoked_at IS NULL AND expires_at > NOW()",
    )
    .bind(user_id)
    .bind(session_type)
    .fetch_one(pool)
    .await?;
    Ok(count)
}

pub async fn count_active_by_client(
    pool: &PgPool,
    user_id: Uuid,
    client_id: &str,
) -> Result<i64, sqlx::Error> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM sessions
         WHERE user_id = $1 AND client_id = $2 AND session_type = 'device'
           AND revoked_at IS NULL AND expires_at > NOW()",
    )
    .bind(user_id)
    .bind(client_id)
    .fetch_one(pool)
    .await?;
    Ok(count)
}

pub async fn find_active_summary_by_user(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Vec<ActiveSessionSummary>, sqlx::Error> {
    sqlx::query_as::<_, ActiveSessionSummary>(FIND_ACTIVE_SUMMARY_BY_USER_SQL)
        .bind(user_id)
        .fetch_all(pool)
        .await
}
