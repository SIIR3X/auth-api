//! Security headers middleware.
//!
//! Appends defensive HTTP headers to every response. These headers are a
//! baseline defence-in-depth measure and do not replace proper CORS or CSP
//! configuration at the reverse-proxy level.
//!
//! CSP policy rationale (pure JSON API, no HTML or scripts served):
//!   default-src 'none'     - block all resource loading by default
//!   base-uri 'none'        - prevent base tag injection attacks
//!   form-action 'none'     - prevent form submissions pointing elsewhere
//!   frame-ancestors 'none' - redundant with X-Frame-Options but explicit

use axum::{
    extract::{Request, State},
    http::HeaderValue,
    middleware::Next,
    response::Response,
};

const CSP: &str = "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

#[derive(Clone)]
pub struct SecurityHeadersState {
    pub enable_hsts: bool,
}

pub async fn layer(
    State(state): State<SecurityHeadersState>,
    req: Request,
    next: Next,
) -> Response {
    let mut res = next.run(req).await;
    let headers = res.headers_mut();

    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert("x-xss-protection", HeaderValue::from_static("0"));
    if state.enable_hsts {
        headers.insert(
            "strict-transport-security",
            HeaderValue::from_static("max-age=63072000; includeSubDomains"),
        );
    }
    headers.insert(
        "referrer-policy",
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("geolocation=(), microphone=(), camera=()"),
    );
    headers.insert("content-security-policy", HeaderValue::from_static(CSP));
    // Prevent tokens and sensitive data from being cached by proxies or browsers.
    headers.insert("cache-control", HeaderValue::from_static("no-store"));

    res
}
