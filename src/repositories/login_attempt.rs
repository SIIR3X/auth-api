//! Repository for the `login_attempts` table.
//!
//! Used by the authentication service to record attempts and by the rate-limit
//! layer to detect brute-force patterns before issuing a lockout.

use ipnetwork::IpNetwork;

use sqlx::{PgPool, Row};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::login_attempt::LoginFailureReason;

pub const COUNT_RECENT_FAILURES_BY_IDENTIFIER_SQL: &str = "SELECT COUNT(*) FROM (
         SELECT 1 FROM login_attempts
         WHERE attempted_identifier = $1::citext
           AND was_successful = FALSE
           AND attempted_at > $2
         LIMIT $3
     ) sub";

pub const COUNT_RECENT_FAILURES_BY_IP_SQL: &str = "SELECT COUNT(*) FROM (
         SELECT 1 FROM login_attempts
         WHERE request_ip = $1::cidr
           AND was_successful = FALSE
           AND attempted_at > $2
         LIMIT $3
     ) sub";

pub const COUNT_CONSECUTIVE_FAILURES_BY_USER_SQL: &str = "SELECT COUNT(*) FROM (
         SELECT 1 FROM login_attempts
         WHERE user_id = $1
           AND was_successful = FALSE
           AND attempted_at > COALESCE(
               (SELECT MAX(attempted_at) FROM login_attempts
                WHERE user_id = $1 AND was_successful = TRUE),
               '1970-01-01'::TIMESTAMPTZ
           )
         LIMIT $2
     ) sub";

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

/// Counts recent failed attempts for an identifier after `cutoff`, capped at `max_count`.
/// The cap keeps the brute-force check exact for threshold decisions without scanning
/// more rows than the caller actually needs.
pub async fn count_recent_failures_by_identifier(
    pool: &PgPool,
    identifier: &str,
    cutoff: OffsetDateTime,
    max_count: i64,
) -> Result<i64, sqlx::Error> {
    let row = sqlx::query(COUNT_RECENT_FAILURES_BY_IDENTIFIER_SQL)
        .bind(identifier)
        .bind(cutoff)
        .bind(max_count)
        .fetch_one(pool)
        .await?;
    Ok(row.get::<i64, _>(0))
}

/// Counts recent failed attempts from an IP after `cutoff`, capped at `max_count`.
pub async fn count_recent_failures_by_ip(
    pool: &PgPool,
    ip: IpNetwork,
    cutoff: OffsetDateTime,
    max_count: i64,
) -> Result<i64, sqlx::Error> {
    let row = sqlx::query(COUNT_RECENT_FAILURES_BY_IP_SQL)
        .bind(ip)
        .bind(cutoff)
        .bind(max_count)
        .fetch_one(pool)
        .await?;
    Ok(row.get::<i64, _>(0))
}

/// Counts consecutive failures for a known user since their last successful login,
/// capped at `max_count`. Returns 0 if the user has never logged in or the last
/// attempt was successful.
pub async fn count_consecutive_failures_by_user(
    pool: &PgPool,
    user_id: Uuid,
    max_count: i64,
) -> Result<i64, sqlx::Error> {
    let row = sqlx::query(COUNT_CONSECUTIVE_FAILURES_BY_USER_SQL)
        .bind(user_id)
        .bind(max_count)
        .fetch_one(pool)
        .await?;
    Ok(row.get::<i64, _>(0))
}
