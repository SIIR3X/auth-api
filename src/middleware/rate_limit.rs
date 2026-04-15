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

pub async fn layer(
    State(redis): State<RedisPool>,
    client_ip: ClientIp,
    limit: u64,
    fail_open_on_redis_error: bool,
    allow_requests_without_ip: bool,
    req: Request,
    next: Next,
) -> Response {
    let ip = match client_ip.0 {
        Some(ip) => ip.ip().to_string(),
        None if allow_requests_without_ip => return next.run(req).await,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "client IP unavailable").into_response(),
    };

    match check_rate_limit(&redis, &ip, limit).await {
        Ok(true) => next.run(req).await,
        Ok(false) => (
            StatusCode::TOO_MANY_REQUESTS,
            [("Retry-After", "60")],
            "rate limit exceeded",
        )
            .into_response(),
        Err(e) => {
            if fail_open_on_redis_error {
                tracing::warn!(ip = %ip, error = %e, "rate limit Redis error, failing open");
                next.run(req).await
            } else {
                tracing::error!(ip = %ip, error = %e, "rate limit Redis error, failing closed");
                (StatusCode::SERVICE_UNAVAILABLE, "rate limiter unavailable").into_response()
            }
        }
    }
}

async fn check_rate_limit(redis: &RedisPool, ip: &str, limit: u64) -> Result<bool, anyhow::Error> {
    let mut conn = redis.get().await?;

    let key = format!("rl:{ip}");
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as u64;

    let member = format!("{now_ms}-{}", uuid::Uuid::new_v4());
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
}

pub async fn layer_with_state(
    State(state): State<RateLimitState>,
    client_ip: ClientIp,
    req: Request<Body>,
    next: Next,
) -> Response {
    let ip = match client_ip.0 {
        Some(ip) => ip.ip().to_string(),
        None if state.allow_requests_without_ip => return next.run(req).await,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "client IP unavailable").into_response(),
    };

    match check_rate_limit(&state.redis, &ip, state.limit).await {
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
                tracing::error!(ip = %ip, error = %e, "rate limit Redis error, failing closed");
                (StatusCode::SERVICE_UNAVAILABLE, "rate limiter unavailable").into_response()
            }
        }
    }
}
