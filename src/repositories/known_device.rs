//! Repository for `known_devices`.

use sqlx::PgExecutor;
use uuid::Uuid;

/// Record a sign-in from the device `fingerprint`. Returns whether the device
/// is new to an account that already knew other devices: the case to alert on.
pub async fn record_sign_in<'e>(
    executor: impl PgExecutor<'e>,
    user_id: Uuid,
    fingerprint: &[u8],
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "WITH known AS (
             SELECT count(*) AS devices FROM known_devices WHERE user_id = $1
         ),
         seen AS (
             INSERT INTO known_devices (user_id, fingerprint) VALUES ($1, $2)
             ON CONFLICT (user_id, fingerprint) DO UPDATE SET last_seen_at = NOW()
             RETURNING (xmax = 0) AS inserted
         )
         SELECT seen.inserted AND known.devices > 0 FROM seen, known",
    )
    .bind(user_id)
    .bind(fingerprint)
    .fetch_one(executor)
    .await
}
