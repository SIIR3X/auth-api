//! Access log: one structured line per request.
//!
//! Logs the route template (`/oauth/device/{user_code}`), never the raw path,
//! so codes and identifiers carried in URLs stay out of the logs. Health checks
//! log at debug to keep probes from drowning real traffic.

use std::time::Instant;

use tracing::Instrument;

use axum::{
    extract::{MatchedPath, Request},
    middleware::Next,
    response::Response,
};

use super::request_id::X_REQUEST_ID;

pub async fn layer(req: Request, next: Next) -> Response {
    let started = Instant::now();
    let method = req.method().clone();
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|path| path.as_str().to_owned());
    let request_id = req
        .headers()
        .get(&X_REQUEST_ID)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let route = route.as_deref().unwrap_or("<unmatched>");
    let span = crate::telemetry::request_span(&method, route, req.headers());

    let res = next.run(req).instrument(span.clone()).await;

    let status = res.status().as_u16();
    span.record("http.response.status_code", status);
    let _entered = span.enter();
    let latency_ms = started.elapsed().as_secs_f64() * 1000.0;
    let request_id = request_id.as_deref().unwrap_or("-");

    if matches!(route, "/health" | "/live" | "/ready") {
        tracing::debug!(target: "access", %method, route, status, latency_ms, request_id);
    } else if status >= 500 {
        tracing::warn!(target: "access", %method, route, status, latency_ms, request_id);
    } else {
        tracing::info!(target: "access", %method, route, status, latency_ms, request_id);
    }
    res
}
