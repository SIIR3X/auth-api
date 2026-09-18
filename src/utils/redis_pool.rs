//! Redis connection pool.
//!
//! A thin wrapper around `deadpool_redis`'s manager that changes *when* a
//! recycled connection is checked, and remembers which connections failed.
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
//! A connection whose transport failed is never recycled, whatever its idle
//! time. Without that, a Redis restart under traffic was never recovered from:
//! each request failed on a dead connection, the failure counted as a use, and
//! the connection never went idle long enough to be pinged and replaced.

use std::time::Duration;

use deadpool::{
    Runtime,
    managed::{self, Metrics, RecycleError, RecycleResult, Timeouts},
};
use deadpool_redis::redis::{
    Cmd, Pipeline, RedisError, RedisFuture, RedisResult, Value,
    aio::{ConnectionLike, MultiplexedConnection},
};

use crate::config::RedisConfig;

/// How long a connection must have sat unused before a checkout re-pings it.
///
/// Far below any sane server-side idle timeout, far above the interval at
/// which a busy pool reuses the same connection: a loaded service pays nothing
/// and an idle one still verifies before it trusts.
const PING_AFTER_IDLE: Duration = Duration::from_secs(5);

/// Pool of multiplexed Redis connections.
pub type RedisPool = managed::Pool<Manager>;

/// A checked-out connection. Derefs to [`Connection`], which implements the
/// Redis command traits; pass `&mut *conn` where a `ConnectionLike` is expected.
pub type RedisConnection = managed::Object<Manager>;

/// A pooled connection that remembers whether its transport failed.
pub struct Connection {
    inner: MultiplexedConnection,
    broken: bool,
}

impl Connection {
    fn observe<T>(&mut self, result: &RedisResult<T>) {
        if let Err(error) = result
            && transport_failed(error)
        {
            self.broken = true;
        }
    }
}

/// Errors that say nothing more will come through this connection, as opposed
/// to a command the server refused.
fn transport_failed(error: &RedisError) -> bool {
    error.is_io_error()
        || error.is_connection_dropped()
        || error.is_timeout()
        || error.is_unrecoverable_error()
}

impl ConnectionLike for Connection {
    fn req_packed_command<'a>(&'a mut self, cmd: &'a Cmd) -> RedisFuture<'a, Value> {
        Box::pin(async move {
            let result = self.inner.req_packed_command(cmd).await;
            self.observe(&result);
            result
        })
    }

    fn req_packed_commands<'a>(
        &'a mut self,
        cmd: &'a Pipeline,
        offset: usize,
        count: usize,
    ) -> RedisFuture<'a, Vec<Value>> {
        Box::pin(async move {
            let result = self.inner.req_packed_commands(cmd, offset, count).await;
            self.observe(&result);
            result
        })
    }

    fn get_db(&self) -> i64 {
        self.inner.get_db()
    }
}

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
    type Type = Connection;
    type Error = RedisError;

    async fn create(&self) -> Result<Connection, RedisError> {
        Ok(Connection {
            inner: managed::Manager::create(&self.inner).await?,
            broken: false,
        })
    }

    async fn recycle(&self, conn: &mut Connection, metrics: &Metrics) -> RecycleResult<RedisError> {
        if conn.broken {
            return Err(RecycleError::message("the connection failed; replacing it"));
        }
        if metrics.last_used() < PING_AFTER_IDLE {
            return Ok(());
        }
        managed::Manager::recycle(&self.inner, &mut conn.inner, metrics).await
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

    #[test]
    fn transport_errors_mark_a_connection_for_replacement() {
        let refused = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        assert!(transport_failed(&RedisError::from(refused)));
        let reset = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset");
        assert!(transport_failed(&RedisError::from(reset)));
    }
}
