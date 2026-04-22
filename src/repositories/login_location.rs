//! Repository for the `login_locations` table.
//!
//! Used by the risk scoring service to look up recent login history
//! and upsert new observations after a successful login.

use ipnetwork::IpNetwork;
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::login_location::LoginLocation;

pub const FIND_RECENT_FOR_RISK_SQL: &str = r#"
        SELECT
            country, city, user_agent,
            latitude, longitude, last_seen
        FROM login_locations
        WHERE user_id = $1
          AND last_seen >= now() - make_interval(days => $2)
        ORDER BY last_seen DESC
        "#;
pub const UPSERT_LOGIN_LOCATION_SQL: &str = r#"
        INSERT INTO login_locations
            (user_id, country, city, user_agent, ip_address, latitude, longitude, last_seen, first_seen)
        VALUES ($1, $2, $3, $4, $5, $6, $7, now(), now())
        ON CONFLICT (user_id, country, city, user_agent)
        DO UPDATE SET
            last_seen  = now(),
            ip_address = EXCLUDED.ip_address,
            latitude   = EXCLUDED.latitude,
            longitude  = EXCLUDED.longitude
        "#;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RiskHistoryEntry {
    pub country: String,
    pub city: String,
    pub user_agent: String,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub last_seen: OffsetDateTime,
}

/// Fetch only the fields needed by risk scoring to reduce row width on the hot login path.
pub async fn find_recent_for_risk(
    pool: &PgPool,
    user_id: Uuid,
    history_days: u32,
) -> Result<Vec<RiskHistoryEntry>, sqlx::Error> {
    let history_days = i32::try_from(history_days).unwrap_or(i32::MAX);

    sqlx::query_as::<_, RiskHistoryEntry>(FIND_RECENT_FOR_RISK_SQL)
        .bind(user_id)
        .bind(history_days)
        .fetch_all(pool)
        .await
}

/// Upsert: update `last_seen` if the (user, country, city, user_agent) tuple already
/// exists, otherwise insert a new row.
#[allow(clippy::too_many_arguments)]
pub async fn upsert(
    pool: &PgPool,
    user_id: Uuid,
    country: &str,
    city: &str,
    user_agent: &str,
    ip_address: IpNetwork,
    latitude: Option<f64>,
    longitude: Option<f64>,
) -> Result<(), sqlx::Error> {
    sqlx::query(UPSERT_LOGIN_LOCATION_SQL)
        .bind(user_id)
        .bind(country)
        .bind(city)
        .bind(user_agent)
        .bind(ip_address)
        .bind(latitude)
        .bind(longitude)
        .execute(pool)
        .await?;
    Ok(())
}

/// Return the most recent location seen for a user (excluding the current login).
pub async fn find_last(pool: &PgPool, user_id: Uuid) -> Result<Option<LoginLocation>, sqlx::Error> {
    sqlx::query_as::<_, LoginLocation>(
        r#"
        SELECT
            id, user_id, country, city, user_agent,
            ip_address,
            latitude, longitude, last_seen, first_seen
        FROM login_locations
        WHERE user_id = $1
        ORDER BY last_seen DESC
        LIMIT 1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
}
