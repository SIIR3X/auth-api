//! Background retention: expired operational rows and audit log partitions.
//!
//! This task is the only scheduler: there is no pg_cron job, which would run the
//! retention functions with their SQL defaults instead of the configured retention.
//!
//! Every instance runs the task; a session advisory lock lets one of them sweep
//! at a time. Each job deletes in bounded batches, so a large backlog is cleared
//! in short transactions instead of one long one.

use std::sync::Arc;
use std::time::Duration;

use sqlx::{PgConnection, PgExecutor, PgPool};
use tokio::time::{self, MissedTickBehavior};

use crate::config::Config;

/// Rows deleted per statement.
const BATCH_SIZE: i32 = 5_000;
/// Batches per job per run: a backlog beyond this waits for the next run
/// rather than holding the connection for the whole sweep.
const MAX_BATCHES: usize = 200;
/// Advisory lock shared by every instance.
const LOCK_KEY: &str = "auth_api_cleanup";

/// Spawns a background task that periodically sweeps expired rows.
/// The first run is delayed by one full interval (no cleanup at startup).
pub fn spawn_cleanup_task(db: PgPool, config: Arc<Config>) {
    tokio::spawn(async move {
        let mut ticker = time::interval(Duration::from_secs(config.cleanup.interval_secs));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        ticker.tick().await; // skip the immediate first tick

        loop {
            ticker.tick().await;
            if let Err(e) = run_once(&db, &config).await {
                tracing::warn!(error = ?e, "cleanup run failed");
            }
        }
    });
}

/// One sweep. Returns `false` when another instance holds the lock.
pub async fn run_once(db: &PgPool, config: &Config) -> Result<bool, sqlx::Error> {
    let mut conn = db.acquire().await?;
    // The lock belongs to this connection's session: never hand it back to the
    // pool, where an unlock that failed would leave it held.
    conn.close_on_drop();

    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock(hashtextextended($1, 0))")
        .bind(LOCK_KEY)
        .fetch_one(&mut *conn)
        .await?;
    if !locked {
        tracing::debug!("cleanup skipped: another instance is sweeping");
        return Ok(false);
    }

    run_all(&mut conn, config).await;
    Ok(true)
}

async fn run_all(conn: &mut PgConnection, config: &Config) {
    let c = &config.cleanup;
    let jobs = [
        (
            "cleanup_expired_sessions",
            "SELECT cleanup_expired_sessions($1::interval, $2)",
            format!("{} days", c.sessions_grace_days),
        ),
        (
            "cleanup_expired_email_2fa_codes",
            "SELECT cleanup_expired_email_2fa_codes($1::interval, $2)",
            format!("{} days", c.tokens_grace_days),
        ),
        (
            "cleanup_expired_email_verification_tokens",
            "SELECT cleanup_expired_email_verification_tokens($1::interval, $2)",
            format!("{} days", c.tokens_grace_days),
        ),
        (
            "cleanup_expired_password_reset_tokens",
            "SELECT cleanup_expired_password_reset_tokens($1::interval, $2)",
            format!("{} days", c.tokens_grace_days),
        ),
        (
            "cleanup_expired_magic_link_tokens",
            "SELECT cleanup_expired_magic_link_tokens($1::interval, $2)",
            format!("{} days", c.tokens_grace_days),
        ),
        (
            "cleanup_expired_recovery_codes",
            "SELECT cleanup_expired_recovery_codes($1::interval, $2)",
            format!("{} days", c.recovery_codes_grace_days),
        ),
        (
            "cleanup_old_login_attempts",
            "SELECT cleanup_old_login_attempts($1::interval, $2)",
            format!("{} days", c.login_attempts_retention_days),
        ),
        // Consumed codes stay an hour so a replay still finds its session.
        (
            "cleanup_expired_authorization_codes",
            "SELECT cleanup_expired_authorization_codes($1::interval, $2)",
            "1 hour".to_owned(),
        ),
        (
            "cleanup_stale_known_devices",
            "SELECT cleanup_stale_known_devices($1::interval, $2)",
            format!("{} days", c.known_devices_retention_days),
        ),
        (
            "cleanup_finished_webhook_deliveries",
            "SELECT cleanup_finished_webhook_deliveries($1::interval, $2)",
            format!("{} days", c.webhook_deliveries_retention_days),
        ),
        // Published events stay a week for investigation.
        (
            "cleanup_published_events",
            "SELECT cleanup_published_events($1::interval, $2)",
            "7 days".to_owned(),
        ),
        // TOTP replay-guard rows live ~90 s (one step of skew on each side);
        // the repository already self-cleans per user, this sweeps leftovers.
        (
            "cleanup_used_totp_codes",
            "SELECT cleanup_used_totp_codes($1::interval, $2)",
            "90 seconds".to_owned(),
        ),
    ];

    for (name, sql, interval) in &jobs {
        sweep(conn, name, sql, interval).await;
    }

    if config.audit.ip_retention_days > 0 {
        sweep(
            conn,
            "coarsen_audit_addresses",
            "SELECT coarsen_audit_addresses($1::interval, $2)",
            &format!("{} days", config.audit.ip_retention_days),
        )
        .await;
    }

    if c.unverified_accounts_retention_days > 0 {
        sweep(
            conn,
            "purge_unverified_accounts",
            "SELECT purge_unverified_accounts($1::interval, $2)",
            &format!("{} days", c.unverified_accounts_retention_days),
        )
        .await;
    }

    if let Err(e) = rotate_audit_log(&mut *conn, config.audit.retention_months).await {
        tracing::warn!(error = ?e, "audit log partition rotation failed");
    }
}

async fn sweep(conn: &mut PgConnection, name: &str, sql: &str, interval: &str) {
    let mut deleted_total = 0i64;
    for _ in 0..MAX_BATCHES {
        match sqlx::query_scalar::<_, i32>(sql)
            .bind(interval)
            .bind(BATCH_SIZE)
            .fetch_one(&mut *conn)
            .await
        {
            Ok(deleted) => {
                deleted_total += i64::from(deleted);
                if deleted < BATCH_SIZE {
                    break;
                }
            }
            Err(e) => {
                metrics::counter!("auth_cleanup_failures_total", "job" => name.to_owned())
                    .increment(1);
                tracing::warn!(job = name, error = ?e, "cleanup job failed");
                break;
            }
        }
    }
    if deleted_total > 0 {
        metrics::counter!("auth_cleanup_deleted_rows_total", "job" => name.to_owned())
            .increment(u64::try_from(deleted_total).unwrap_or(0));
        tracing::info!(job = name, deleted = deleted_total, "cleanup deleted rows");
    }
}

/// Create upcoming monthly audit partitions and drop those past retention
/// (`0` keeps every partition).
pub async fn rotate_audit_log<'e>(
    executor: impl PgExecutor<'e>,
    retention_months: u32,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT rotate_audit_log_partitions($1)")
        .bind(i32::try_from(retention_months).unwrap_or(i32::MAX))
        .execute(executor)
        .await?;
    Ok(())
}
