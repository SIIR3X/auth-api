//! Repository for the `login_attempts` table.
//!
//! Used by the authentication service to record attempts and by the rate-limit
//! layer to detect brute-force patterns before issuing a lockout.

use ipnetwork::IpNetwork;

use sqlx::PgPool;
use uuid::Uuid;

use crate::domain::login_attempt::{LoginAttempt, LoginFailureReason};

// Input types

pub struct NewLoginAttempt<'a> {
    pub user_id: Option<Uuid>,
    pub attempted_identifier: &'a str,
    pub was_successful: bool,
    pub failure_reason: Option<LoginFailureReason>,
    pub request_ip: Option<IpNetwork>,
    pub request_user_agent: Option<&'a str>,
}

// Writes

pub async fn record(pool: &PgPool, input: &NewLoginAttempt<'_>) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO login_attempts
             (user_id, attempted_identifier, was_successful, failure_reason, request_ip, request_user_agent)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(input.user_id)
    .bind(input.attempted_identifier)
    .bind(input.was_successful)
    .bind(&input.failure_reason)
    .bind(input.request_ip)
    .bind(input.request_user_agent)
    .execute(pool)
    .await?;
    Ok(())
}

// Reads

/// Counts failed attempts for an identifier within the last `window_secs` seconds.
/// Uses the partial index on (attempted_identifier, attempted_at) WHERE was_successful = FALSE.
pub async fn count_recent_failures_by_identifier(
    pool: &PgPool,
    identifier: &str,
    window_secs: i64,
) -> Result<i64, sqlx::Error> {
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*)
         FROM login_attempts
         WHERE attempted_identifier = $1
           AND was_successful = FALSE
           AND attempted_at > NOW() - ($2 * INTERVAL '1 second')",
    )
    .bind(identifier)
    .bind(window_secs)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

/// Counts failed attempts from an IP within the last `window_secs` seconds.
/// Uses the partial index on (request_ip, attempted_at) WHERE was_successful = FALSE.
pub async fn count_recent_failures_by_ip(
    pool: &PgPool,
    ip: IpNetwork,
    window_secs: i64,
) -> Result<i64, sqlx::Error> {
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*)
         FROM login_attempts
         WHERE request_ip = $1
           AND was_successful = FALSE
           AND attempted_at > NOW() - ($2 * INTERVAL '1 second')",
    )
    .bind(ip)
    .bind(window_secs)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

/// Counts consecutive failures for a known user since their last successful login.
/// Returns 0 if the user has never logged in or the last attempt was successful.
pub async fn count_consecutive_failures_by_user(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<i64, sqlx::Error> {
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*)
         FROM login_attempts
         WHERE user_id = $1
           AND was_successful = FALSE
           AND attempted_at > COALESCE(
               (SELECT MAX(attempted_at) FROM login_attempts
                WHERE user_id = $1 AND was_successful = TRUE),
               '1970-01-01'::TIMESTAMPTZ
           )",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

pub async fn find_last_by_user(
    pool: &PgPool,
    user_id: Uuid,
    limit: i64,
) -> Result<Vec<LoginAttempt>, sqlx::Error> {
    sqlx::query_as::<_, LoginAttempt>(
        "SELECT * FROM login_attempts
         WHERE user_id = $1
         ORDER BY attempted_at DESC
         LIMIT $2",
    )
    .bind(user_id)
    .bind(limit)
    .fetch_all(pool)
    .await
}
