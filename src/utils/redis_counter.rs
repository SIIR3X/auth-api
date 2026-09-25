//! Atomic attempt budgets backed by Redis.
//!
//! Every brute-force guard in the service follows the same shape: count an
//! attempt, refuse once a limit is reached, reset on success. Reading the
//! counter and incrementing it in two round trips lets concurrent requests all
//! read the same value and all get through, so a budget of five becomes as many
//! guesses as an attacker can fire in parallel.
//!
//! [`consume`] reserves the attempt *before* the guarded check runs, in one Lua
//! script that increments every budget involved (per token, per user, per IP...)
//! and arms the window on first use. A request either gets its slot or is
//! refused; there is no interleaving in between.

use std::sync::LazyLock;

use deadpool_redis::redis::Script;

use super::redis_pool::RedisPool;

use crate::error::AppError;

/// INCR each key, arm its TTL on first hit, and report whether any budget is
/// now past its limit. ARGV holds `limit, window_secs` pairs, one per key.
static CONSUME: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r#"
local exceeded = 0
local counts = {}
for i, key in ipairs(KEYS) do
    local limit = tonumber(ARGV[2 * i - 1])
    local window = tonumber(ARGV[2 * i])
    local n = redis.call('INCR', key)
    if n == 1 then
        redis.call('EXPIRE', key, window)
    end
    if n > limit then
        exceeded = 1
    end
    counts[i] = n
end
table.insert(counts, 1, exceeded)
return counts
"#,
    )
});

/// Like [`CONSUME`], but in order and stopping at the first budget past its
/// limit: the budgets after it are left untouched (count 0).
static CONSUME_IN_ORDER: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r#"
local exceeded = 0
local counts = {}
for i, key in ipairs(KEYS) do
    counts[i] = 0
end
for i, key in ipairs(KEYS) do
    local limit = tonumber(ARGV[2 * i - 1])
    local window = tonumber(ARGV[2 * i])
    local n = redis.call('INCR', key)
    if n == 1 then
        redis.call('EXPIRE', key, window)
    end
    counts[i] = n
    if n > limit then
        exceeded = 1
        break
    end
end
table.insert(counts, 1, exceeded)
return counts
"#,
    )
});

/// One attempt budget: at most `limit` attempts on `key` per `window_secs`.
#[derive(Debug, Clone, Copy)]
pub struct Budget<'a> {
    pub key: &'a str,
    pub limit: i64,
    pub window_secs: u64,
}

/// Outcome of [`consume`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Consumed {
    /// True when at least one budget is exhausted: the caller must refuse.
    pub exceeded: bool,
    /// Attempt count of each budget after this one, in the order given.
    pub counts: Vec<i64>,
}

impl Consumed {
    /// Highest attempt count across budgets, handy for exponential backoff.
    pub fn max_count(&self) -> i64 {
        self.counts.iter().copied().max().unwrap_or(0)
    }
}

/// Reserve one attempt against every budget, atomically.
///
/// Fails closed: when Redis cannot be reached the attempt is refused with
/// `ServiceUnavailable`, because an unenforceable budget is no budget at all.
pub async fn consume(redis: &RedisPool, budgets: &[Budget<'_>]) -> Result<Consumed, AppError> {
    run(redis, &CONSUME, budgets).await
}

/// Reserve one attempt against the budgets in order, atomically, stopping at
/// the first one already exhausted: an attempt refused by a narrow budget
/// (one session) does not also count against a wider one (the account), so
/// whoever exhausts their own budget cannot go on filling the owner's.
/// Fails closed like [`consume`].
pub async fn consume_in_order(
    redis: &RedisPool,
    budgets: &[Budget<'_>],
) -> Result<Consumed, AppError> {
    run(redis, &CONSUME_IN_ORDER, budgets).await
}

async fn run(
    redis: &RedisPool,
    script: &Script,
    budgets: &[Budget<'_>],
) -> Result<Consumed, AppError> {
    if budgets.is_empty() {
        return Ok(Consumed {
            exceeded: false,
            counts: Vec::new(),
        });
    }

    let mut conn = redis
        .get()
        .await
        .map_err(|_| redis_failure("redis_unavailable"))?;

    let mut invocation = script.prepare_invoke();
    for budget in budgets {
        invocation
            .key(budget.key)
            .arg(budget.limit)
            .arg(budget.window_secs);
    }

    let raw: Vec<i64> = invocation
        .invoke_async(&mut *conn)
        .await
        .map_err(|_| redis_failure("redis_query_failed"))?;

    let (exceeded, counts) = raw
        .split_first()
        .map(|(flag, counts)| (*flag == 1, counts.to_vec()))
        .unwrap_or((false, Vec::new()));

    Ok(Consumed { exceeded, counts })
}

/// A budget that cannot be read: counted in `auth_redis_errors_total`, refused.
fn redis_failure(reason: &'static str) -> AppError {
    metrics::counter!("auth_redis_errors_total", "operation" => "budget").increment(1);
    AppError::ServiceUnavailable(reason)
}

/// Current attempt count of a budget, without consuming one.
pub async fn peek(redis: &RedisPool, key: &str) -> Result<i64, AppError> {
    use deadpool_redis::redis::AsyncCommands;

    let mut conn = redis
        .get()
        .await
        .map_err(|_| redis_failure("redis_unavailable"))?;
    let count: Option<i64> = conn
        .get(key)
        .await
        .map_err(|_| redis_failure("redis_query_failed"))?;
    Ok(count.unwrap_or(0))
}

/// Clear budgets after a success. Best-effort: a stale counter only delays the
/// user until its window expires, it never lets an attacker through.
/// Claim a cooldown: `true` when `key` was free and is now held for
/// `ttl_secs`, `false` when a previous claim still holds it. One `SET NX EX`,
/// before the guarded action: concurrent requests cannot all see the key free
/// and all act. Fails open (a Redis outage claims nothing and allows the
/// action), like the volume budgets.
/// [`claim_cooldown`] for actions whose repetition does harm (regenerating
/// recovery codes replaces the owner's): a Redis outage refuses the action.
pub async fn claim_cooldown_strict(
    redis: &RedisPool,
    key: &str,
    ttl_secs: u64,
) -> Result<bool, AppError> {
    let mut conn = redis
        .get()
        .await
        .map_err(|_| redis_failure("redis_unavailable"))?;
    let claimed: Option<String> = deadpool_redis::redis::cmd("SET")
        .arg(key)
        .arg(1)
        .arg("NX")
        .arg("EX")
        .arg(ttl_secs)
        .query_async(&mut *conn)
        .await
        .map_err(|_| redis_failure("redis_query_failed"))?;
    Ok(claimed.is_some())
}

pub async fn claim_cooldown(redis: &RedisPool, key: &str, ttl_secs: u64) -> bool {
    let Ok(mut conn) = redis.get().await else {
        return true;
    };
    let claimed: Result<Option<String>, _> = deadpool_redis::redis::cmd("SET")
        .arg(key)
        .arg(1)
        .arg("NX")
        .arg("EX")
        .arg(ttl_secs)
        .query_async(&mut *conn)
        .await;
    claimed.map(|reply| reply.is_some()).unwrap_or(true)
}

/// Give back one attempt on each budget, after the guarded action turned out
/// legitimate. Best-effort, like `reset`.
pub async fn release(redis: &RedisPool, keys: &[&str]) {
    use deadpool_redis::redis::AsyncCommands;

    if let Ok(mut conn) = redis.get().await {
        for key in keys {
            let _: Result<i64, _> = conn.decr(*key, 1).await;
        }
    }
}

pub async fn reset(redis: &RedisPool, keys: &[&str]) {
    use deadpool_redis::redis::AsyncCommands;

    if keys.is_empty() {
        return;
    }
    if let Ok(mut conn) = redis.get().await {
        let _: Result<(), _> = conn.del(keys).await;
    }
}

#[cfg(test)]
mod cooldown_tests {
    /// A cooldown guarding a harmful repetition refuses when Redis is down;
    /// a volume cooldown lets the action through (SEC-68).
    #[tokio::test]
    async fn a_strict_cooldown_fails_closed() {
        let pool = crate::utils::redis_pool::build(&crate::config::RedisConfig {
            url: "redis://127.0.0.1:1".into(),
            pool_size: 1,
            wait_timeout_ms: 100,
        })
        .unwrap();
        assert!(super::claim_cooldown_strict(&pool, "k", 60).await.is_err());
        assert!(super::claim_cooldown(&pool, "k", 60).await);
    }
}
