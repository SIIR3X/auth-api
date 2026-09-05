//! Per-client rate limiting backed by Redis.
//!
//! Each bucket is a sliding-window estimate over one minute, kept as one small
//! hash per client: the count of the current fixed window, the count of the
//! previous one, and which window "current" is. The estimate weights the
//! previous window by the part of it still inside the sliding minute. Memory
//! and work are O(1) per request, where a sorted set of timestamps grew with
//! the limit.
//!
//! A route can be subject to several buckets (the general one and the stricter
//! auth one). They are checked in a single script call: a request is counted in
//! every bucket or in none, and a refused request consumes nothing.

use std::{net::IpAddr, sync::LazyLock};

use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderValue, StatusCode, header::RETRY_AFTER},
    middleware::Next,
    response::{IntoResponse, Response},
};
use deadpool_redis::redis::Script;
use ipnetwork::IpNetwork;

use crate::utils::redis_pool::RedisPool;

use super::client_ip::ClientIp;

/// Length of the sliding window.
const WINDOW_MS: u64 = 60_000;

/// KEYS: one hash per bucket. ARGV: now_ms, window_ms, then one limit per key.
/// Returns 0 when allowed, otherwise the milliseconds until the first refusing
/// bucket frees a slot (at least 1).
static SLIDING_WINDOW: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r#"
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local current = math.floor(now / window)
local into = (now % window) / window

local state = {}
for i, key in ipairs(KEYS) do
    local limit = tonumber(ARGV[2 + i])
    local fields = redis.call('HMGET', key, 'w', 'c', 'p')
    local w, c, p = tonumber(fields[1]), tonumber(fields[2]) or 0, tonumber(fields[3]) or 0
    if w == nil or w < current - 1 then
        c, p = 0, 0
    elseif w == current - 1 then
        c, p = 0, c
    end
    if p * (1 - into) + c + 1 > limit then
        local wait = window - (now % window)
        if c + 1 <= limit and p > 0 then
            -- Only the previous window's weight is in the way: it decays
            -- continuously, so the slot frees before the window turns.
            local needed = (p * (1 - into) + c + 1 - limit) / p
            wait = math.ceil(needed * window)
        end
        return math.max(wait, 1)
    end
    state[i] = {c, p}
end

for i, key in ipairs(KEYS) do
    redis.call('HSET', key, 'w', current, 'c', state[i][1] + 1, 'p', state[i][2])
    redis.call('PEXPIRE', key, 2 * window)
end
return 0
"#,
    )
});

/// One rate-limit bucket: `limit` requests per minute under `prefix:{client}`.
#[derive(Clone, Copy, Debug)]
pub struct Bucket {
    pub prefix: &'static str,
    pub limit: u64,
}

#[derive(Clone)]
pub struct RateLimitState {
    pub redis: RedisPool,
    /// Every bucket a request through this layer counts against.
    pub buckets: Vec<Bucket>,
    pub trusted_proxy_cidrs: Vec<IpNetwork>,
    pub fail_open_on_redis_error: bool,
    pub allow_requests_without_ip: bool,
}

/// `Ok(None)` when allowed, `Ok(Some(wait_ms))` when refused.
async fn check(
    redis: &RedisPool,
    buckets: &[Bucket],
    client: &str,
) -> Result<Option<u64>, anyhow::Error> {
    let mut conn = redis.get().await?;
    let now_ms = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
    )?;

    let mut invocation = SLIDING_WINDOW.prepare_invoke();
    for bucket in buckets {
        invocation.key(format!("{}:{client}", bucket.prefix));
    }
    invocation.arg(now_ms).arg(WINDOW_MS);
    for bucket in buckets {
        invocation.arg(bucket.limit);
    }

    let wait_ms: u64 = invocation.invoke_async(&mut *conn).await?;
    Ok((wait_ms > 0).then_some(wait_ms))
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
/// The network [`ip_bucket`] keys a client by: the address itself for IPv4, its
/// /64 for IPv6. Budgets counted in SQL use it to group addresses the way the
/// Redis budgets do.
pub fn ip_bucket_network(ip: IpAddr) -> ipnetwork::IpNetwork {
    match ip {
        IpAddr::V4(v4) => ipnetwork::IpNetwork::from(IpAddr::V4(v4)),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => ipnetwork::IpNetwork::from(IpAddr::V4(v4)),
            None => {
                let s = v6.segments();
                let prefix = std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0);
                ipnetwork::IpNetwork::new(IpAddr::V6(prefix), 64)
                    .expect("64 is a valid IPv6 prefix length")
            }
        },
    }
}
pub async fn layer_with_state(
    State(state): State<RateLimitState>,
    client_ip: ClientIp,
    req: Request<Body>,
    next: Next,
) -> Response {
    let client = match client_ip.0 {
        Some(ip) => ip_bucket(ip.ip()),
        None if state.allow_requests_without_ip => return next.run(req).await,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "client IP unavailable").into_response(),
    };

    match check(&state.redis, &state.buckets, &client).await {
        Ok(None) => next.run(req).await,
        Ok(Some(wait_ms)) => {
            let retry_after = wait_ms.div_ceil(1000).max(1);
            let mut res = (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
            res.headers_mut()
                .insert(RETRY_AFTER, HeaderValue::from(retry_after));
            res
        }
        Err(e) if state.fail_open_on_redis_error => {
            tracing::warn!(client = %client, error = %e, "rate limit Redis error, failing open");
            next.run(req).await
        }
        Err(e) => {
            tracing::warn!(client = %client, error = %e, "rate limit Redis error, failing closed");
            (StatusCode::SERVICE_UNAVAILABLE, "rate limiter unavailable").into_response()
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
    #[test]
    fn sql_budgets_group_addresses_like_redis_budgets() {
        use super::ip_bucket_network;

        let network = ip_bucket_network("2001:db8:1:2:aaaa::1".parse().unwrap());
        assert_eq!(network.to_string(), "2001:db8:1:2::/64");
        assert!(network.contains("2001:db8:1:2:ffff::9".parse().unwrap()));
        assert!(!network.contains("2001:db8:1:3::1".parse().unwrap()));
        assert_eq!(
            ip_bucket_network("203.0.113.7".parse().unwrap()).to_string(),
            "203.0.113.7/32"
        );
        assert_eq!(
            ip_bucket_network("::ffff:198.51.100.4".parse().unwrap()).to_string(),
            "198.51.100.4/32"
        );
    }
}
