//! Security headers middleware.
//!
//! Appends defensive HTTP headers to every response. These headers are a
//! baseline defence-in-depth measure and do not replace proper CORS or CSP
//! configuration at the reverse-proxy level.

use axum::{extract::Request, middleware::Next, response::Response};

pub async fn layer(req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let headers = res.headers_mut();

    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    headers.insert("x-frame-options", "DENY".parse().unwrap());
    headers.insert("x-xss-protection", "0".parse().unwrap());
    headers.insert(
        "strict-transport-security",
        "max-age=63072000; includeSubDomains".parse().unwrap(),
    );
    headers.insert("referrer-policy", "strict-origin-when-cross-origin".parse().unwrap());
    headers.insert(
        "permissions-policy",
        "geolocation=(), microphone=(), camera=()".parse().unwrap(),
    );

    res
}
