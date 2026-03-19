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
use deadpool_redis::{redis::AsyncCommands, Pool as RedisPool};

use crate::handlers::extractors::ClientIp;

const WINDOW_MS: u64 = 60_000; // 1 minute sliding window

pub async fn layer(
    State(redis): State<RedisPool>,
    client_ip: ClientIp,
    limit: u64,
    req: Request,
    next: Next,
) -> Response {
    // If we cannot determine the IP we let the request through.
    // Blocking unknown IPs would break legitimate clients behind certain proxies.
    let ip = match client_ip.0 {
        Some(ip) => ip.ip().to_string(),
        None => return next.run(req).await,
    };

    match check_rate_limit(&redis, &ip, limit).await {
        Ok(true) => next.run(req).await,
        Ok(false) => (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response(),
        // On Redis failure, fail open to avoid taking down the API.
        Err(e) => {
            tracing::warn!(ip = %ip, error = %e, "rate limit Redis error, failing open");
            next.run(req).await
        }
    }
}

async fn check_rate_limit(redis: &RedisPool, ip: &str, limit: u64) -> Result<bool, anyhow::Error> {
    let mut conn = redis.get().await?;

    let key = format!("rl:{ip}");
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as u64;
    let window_start = now_ms.saturating_sub(WINDOW_MS);

    // Remove expired entries, then count the current window.
    let _: () = conn.zrembyscore(&key, "-inf", window_start as f64).await?;
    let count: u64 = conn.zcard(&key).await?;

    if count >= limit {
        return Ok(false);
    }

    // Add a unique member scored by current timestamp, then set TTL.
    let member = format!("{now_ms}-{}", uuid::Uuid::new_v4());
    let _: () = conn.zadd(&key, member, now_ms as f64).await?;
    let _: () = conn.pexpire(&key, (WINDOW_MS + 1000) as i64).await?;

    Ok(true)
}

// Extractor-free version for use as a plain function from a closure middleware.
// Returns (pool, limit) as state so the router can configure different limits
// per route group.

#[derive(Clone)]
pub struct RateLimitState {
    pub redis: RedisPool,
    pub limit: u64,
}

pub async fn layer_with_state(
    State(state): State<RateLimitState>,
    client_ip: ClientIp,
    req: Request<Body>,
    next: Next,
) -> Response {
    let ip = match client_ip.0 {
        Some(ip) => ip.ip().to_string(),
        None => return next.run(req).await,
    };

    match check_rate_limit(&state.redis, &ip, state.limit).await {
        Ok(true) => next.run(req).await,
        Ok(false) => (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response(),
        Err(e) => {
            tracing::warn!(ip = %ip, error = %e, "rate limit Redis error, failing open");
            next.run(req).await
        }
    }
}
