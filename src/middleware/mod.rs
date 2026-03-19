//! Tower middleware layers applied to the Axum router.
//!
//! - request_id: injects a unique x-request-id header into every request and response
//! - security_headers: adds standard defensive HTTP headers to every response
//! - rate_limit: token bucket per client IP backed by Redis

pub mod rate_limit;
pub mod request_id;
pub mod security_headers;
