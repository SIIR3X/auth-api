//! Saturation of the connection pools, published as Prometheus gauges.
//!
//! A pool that runs out of connections shows up first as requests waiting for
//! one; these gauges show it before the timeouts do.

use std::time::Duration;

use sqlx::PgPool;

use super::redis_pool::RedisPool;

/// How often the gauges are refreshed.
const INTERVAL: Duration = Duration::from_secs(10);

/// Refresh the pool gauges every [`INTERVAL`] for the life of the process.
pub fn spawn(db: PgPool, db_max: u32, redis: RedisPool) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            record(&db, db_max, &redis);
        }
    });
}

fn record(db: &PgPool, db_max: u32, redis: &RedisPool) {
    let size = db.size();
    let idle = u32::try_from(db.num_idle()).unwrap_or(u32::MAX);
    metrics::gauge!("auth_db_pool_connections", "state" => "max").set(f64::from(db_max));
    metrics::gauge!("auth_db_pool_connections", "state" => "open").set(f64::from(size));
    metrics::gauge!("auth_db_pool_connections", "state" => "idle").set(f64::from(idle));
    metrics::gauge!("auth_db_pool_connections", "state" => "in_use")
        .set(f64::from(size.saturating_sub(idle)));

    let status = redis.status();
    metrics::gauge!("auth_redis_pool_connections", "state" => "max").set(status.max_size as f64);
    metrics::gauge!("auth_redis_pool_connections", "state" => "open").set(status.size as f64);
    metrics::gauge!("auth_redis_pool_connections", "state" => "available")
        .set(status.available as f64);
    metrics::gauge!("auth_redis_pool_waiting").set(status.waiting as f64);
}
