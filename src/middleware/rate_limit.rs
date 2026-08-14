//! IP-based token bucket rate limiter backed by Redis.
//!
//! Each client IP gets a bucket with `burst_size` tokens that refills at
//! `requests_per_second` tokens per second. The state is stored in Redis as a
//! sorted set so it survives restarts and works across multiple instances.
//!
//! Algorithm: sliding window counter using a Redis sorted set per IP.
//! Each request adds one entry with score = now_ms. Entries older than the
//! window are pruned on every check. If the count exceeds the limit the
//! request is rejected with 429.

use std::{
    net::IpAddr,
    sync::atomic::{AtomicU64, Ordering},
};

use axum::{
    body::Body,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use deadpool_redis::{Pool as RedisPool, redis::Script};
use ipnetwork::IpNetwork;

use crate::handlers::extractors::ClientIp;

const WINDOW_MS: u64 = 60_000; // 1 minute sliding window

/// Per-process monotonic counter used to make sorted-set members unique without
/// calling the RNG on every request.
static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);
const RATE_LIMIT_LUA: &str = r#"
local key = KEYS[1]
local now_ms = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]

redis.call('ZREMRANGEBYSCORE', key, '-inf', now_ms - window_ms)

local count = redis.call('ZCARD', key)
if count >= limit then
    redis.call('PEXPIRE', key, window_ms + 1000)
    return 0
end

redis.call('ZADD', key, now_ms, member)
redis.call('PEXPIRE', key, window_ms + 1000)
return 1
"#;

async fn check_rate_limit(
    redis: &RedisPool,
    key_prefix: &str,
    ip: &str,
    limit: u64,
) -> Result<bool, anyhow::Error> {
    let mut conn = redis.get().await?;

    let key = format!("{key_prefix}:{ip}");
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as u64;

    let member = format!(
        "{now_ms}-{}",
        REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let script = Script::new(RATE_LIMIT_LUA);
    let allowed: i32 = script
        .key(&key)
        .arg(now_ms as i64)
        .arg(WINDOW_MS as i64)
        .arg(limit as i64)
        .arg(&member)
        .invoke_async(&mut conn)
        .await?;

    Ok(allowed == 1)
}

/// Key a client address for rate limiting and abuse budgets.
///
/// IPv4 addresses are used as-is. An IPv6 client is bucketed by its /64, the
/// prefix a single subscriber is typically delegated: otherwise rotating through
/// interface identifiers would reset every per-IP limit at will.
pub fn ip_bucket(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
        },
    }
}

// Extractor-free version for use as a plain function from a closure middleware.
// Returns (pool, limit) as state so the router can configure different limits
// per route group.

#[derive(Clone)]
pub struct RateLimitState {
    pub redis: RedisPool,
    pub limit: u64,
    pub trusted_proxy_cidrs: Vec<IpNetwork>,
    pub fail_open_on_redis_error: bool,
    pub allow_requests_without_ip: bool,
    /// Redis key prefix for the rate-limit sorted set.
    /// Defaults to "rl" when not set. Use different prefixes for buckets that
    /// must track independently (e.g. "rl_auth" for auth-only limits).
    pub key_prefix: &'static str,
}

pub async fn layer_with_state(
    State(state): State<RateLimitState>,
    client_ip: ClientIp,
    req: Request<Body>,
    next: Next,
) -> Response {
    let ip = match client_ip.0 {
        Some(ip) => ip_bucket(ip.ip()),
        None if state.allow_requests_without_ip => return next.run(req).await,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "client IP unavailable").into_response(),
    };

    match check_rate_limit(&state.redis, state.key_prefix, &ip, state.limit).await {
        Ok(true) => next.run(req).await,
        Ok(false) => (
            StatusCode::TOO_MANY_REQUESTS,
            [("Retry-After", "60")],
            "rate limit exceeded",
        )
            .into_response(),
        Err(e) => {
            if state.fail_open_on_redis_error {
                tracing::warn!(ip = %ip, error = %e, "rate limit Redis error, failing open");
                next.run(req).await
            } else {
                tracing::warn!(ip = %ip, error = %e, "rate limit Redis error, failing closed");
                (StatusCode::SERVICE_UNAVAILABLE, "rate limiter unavailable").into_response()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ip_bucket;

    #[test]
    fn ipv4_addresses_are_kept_whole() {
        assert_eq!(ip_bucket("203.0.113.7".parse().unwrap()), "203.0.113.7");
    }

    #[test]
    fn ipv6_addresses_share_their_64() {
        let a = ip_bucket("2001:db8:1:2:aaaa::1".parse().unwrap());
        let b = ip_bucket("2001:db8:1:2:ffff:ffff:ffff:ffff".parse().unwrap());
        assert_eq!(a, b);
        assert_eq!(a, "2001:db8:1:2::/64");
        assert_ne!(a, ip_bucket("2001:db8:1:3::1".parse().unwrap()));
    }

    #[test]
    fn ipv4_mapped_ipv6_addresses_use_the_ipv4_bucket() {
        assert_eq!(
            ip_bucket("::ffff:198.51.100.4".parse().unwrap()),
            "198.51.100.4"
        );
    }
}
