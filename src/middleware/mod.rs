//! Tower middleware layers applied to the Axum router.
//!
//! - client_ip: the client address behind trusted reverse proxies
//! - access_log: one structured line per request (route template, status, latency)
//! - request_id: injects a unique x-request-id header into every request and response
//! - security_headers: adds standard defensive HTTP headers to every response
//! - rate_limit: sliding-window limits per client IP backed by Redis

pub mod access_log;
pub mod client_ip;
pub mod rate_limit;
pub mod request_id;
pub mod security_headers;
