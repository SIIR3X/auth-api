//! Redis connection pool.
//!
//! A thin wrapper around `deadpool_redis`'s manager whose only change is *when*
//! a recycled connection is checked.
//!
//! deadpool-redis pings on every checkout: its `recycle` sends `UNWATCH` +
//! `PING` and waits for the reply before the caller's own command is written.
//! That is a full round trip in front of every rate-limit check, blocklist
//! lookup and pre-auth read, the cheapest operations in the service, whose
//! latency it therefore doubles. A connection used moments ago has already
//! shown it is alive.
//!
//! An idle connection is different: a server restart, an idle timeout or a
//! middlebox dropping the flow are only detectable by trying. So the ping is
//! kept, gated on the connection having been idle long enough for any of that
//! to have happened.
//!
//! The trade: a connection dropped within the grace window is handed out and
//! fails on first use. That failure already existed between the ping and the
//! command, and every caller treats a Redis error as a Redis error.

use std::time::Duration;

use deadpool::{
    Runtime,
    managed::{self, Metrics, RecycleResult, Timeouts},
};
use deadpool_redis::redis::{RedisError, aio::MultiplexedConnection};

use crate::config::RedisConfig;

/// How long a connection must have sat unused before a checkout re-pings it.
///
/// Far below any sane server-side idle timeout, far above the interval at
/// which a busy pool reuses the same connection: a loaded service pays nothing
/// and an idle one still verifies before it trusts.
const PING_AFTER_IDLE: Duration = Duration::from_secs(5);

/// Pool of multiplexed Redis connections.
pub type RedisPool = managed::Pool<Manager>;

/// A checked-out connection. Derefs to [`MultiplexedConnection`], so it is used
/// like one; pass `&mut *conn` where a `ConnectionLike` is expected.
pub type RedisConnection = managed::Object<Manager>;

pub struct Manager {
    inner: deadpool_redis::Manager,
}

impl Manager {
    pub fn new(url: &str) -> Result<Self, RedisError> {
        Ok(Self {
            inner: deadpool_redis::Manager::new(url)?,
        })
    }
}

impl managed::Manager for Manager {
    type Type = MultiplexedConnection;
    type Error = RedisError;

    async fn create(&self) -> Result<MultiplexedConnection, RedisError> {
        managed::Manager::create(&self.inner).await
    }

    async fn recycle(
        &self,
        conn: &mut MultiplexedConnection,
        metrics: &Metrics,
    ) -> RecycleResult<RedisError> {
        if metrics.last_used() < PING_AFTER_IDLE {
            return Ok(());
        }
        managed::Manager::recycle(&self.inner, conn, metrics).await
    }
}

/// Build the pool from configuration. Connections are opened lazily.
pub fn build(cfg: &RedisConfig) -> Result<RedisPool, String> {
    let wait = Duration::from_millis(cfg.wait_timeout_ms);
    let manager = Manager::new(&cfg.url).map_err(|e| e.to_string())?;
    managed::Pool::builder(manager)
        .max_size(cfg.pool_size as usize)
        .timeouts(Timeouts {
            wait: Some(wait),
            create: Some(wait),
            recycle: Some(wait),
        })
        .runtime(Runtime::Tokio1)
        .build()
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_grace_window_is_shorter_than_any_plausible_idle_timeout() {
        // Redis's own `timeout` defaults to 0 (never); deployments that set one
        // use minutes. Staying well under keeps dead connections out of the pool.
        assert!(PING_AFTER_IDLE < Duration::from_secs(30));
    }

    #[test]
    fn a_malformed_url_is_a_build_error() {
        let cfg = RedisConfig {
            url: "not a url".into(),
            pool_size: 1,
            wait_timeout_ms: 100,
        };
        assert!(build(&cfg).is_err());
    }
}
