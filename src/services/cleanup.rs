//! Background cleanup task for expired operational data.
//!
//! Runs periodically to delete rows that are past their retention period from all
//! operational tables (sessions, tokens, login attempts, recovery codes).
//!
//! This complements pg_cron (scheduled via migration 0017): whichever runs first
//! cleans up. When pg_cron is unavailable, this task is the sole cleanup mechanism.

use std::sync::Arc;
use std::time::Duration;

use sqlx::PgPool;
use tokio::time::{self, MissedTickBehavior};

use crate::config::Config;

/// Spawns a background task that periodically deletes expired rows.
/// The first run is delayed by one full interval (no cleanup at startup).
pub fn spawn_cleanup_task(db: PgPool, config: Arc<Config>) {
    tokio::spawn(async move {
        let mut ticker = time::interval(Duration::from_secs(config.cleanup.interval_secs));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        ticker.tick().await; // skip the immediate first tick

        loop {
            ticker.tick().await;
            run_all(&db, &config).await;
        }
    });
}

async fn run_all(db: &PgPool, config: &Config) {
    let c = &config.cleanup;

    run(
        db,
        "cleanup_expired_sessions",
        "SELECT cleanup_expired_sessions($1::interval)",
        &format!("{} days", c.sessions_grace_days),
    )
    .await;

    run(
        db,
        "cleanup_expired_email_2fa_codes",
        "SELECT cleanup_expired_email_2fa_codes($1::interval)",
        &format!("{} days", c.tokens_grace_days),
    )
    .await;

    run(
        db,
        "cleanup_expired_email_verification_tokens",
        "SELECT cleanup_expired_email_verification_tokens($1::interval)",
        &format!("{} days", c.tokens_grace_days),
    )
    .await;

    run(
        db,
        "cleanup_expired_password_reset_tokens",
        "SELECT cleanup_expired_password_reset_tokens($1::interval)",
        &format!("{} days", c.tokens_grace_days),
    )
    .await;

    run(
        db,
        "cleanup_expired_recovery_codes",
        "SELECT cleanup_expired_recovery_codes($1::interval)",
        &format!("{} days", c.recovery_codes_grace_days),
    )
    .await;

    run(
        db,
        "cleanup_old_login_attempts",
        "SELECT cleanup_old_login_attempts($1::interval)",
        &format!("{} days", c.login_attempts_retention_days),
    )
    .await;
}

async fn run(db: &PgPool, name: &str, sql: &str, interval: &str) {
    match sqlx::query_scalar::<_, i32>(sql)
        .bind(interval)
        .fetch_one(db)
        .await
    {
        Ok(deleted) if deleted > 0 => {
            tracing::info!(job = name, deleted, "cleanup deleted rows");
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(job = name, error = ?e, "cleanup job failed");
        }
    }
}
