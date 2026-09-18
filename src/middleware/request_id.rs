//! Request ID middleware.
//!
//! Keeps the `x-request-id` of the incoming request (set by nginx) when it is a
//! plausible identifier, otherwise generates a UUID v4. The identifier is
//! forwarded on the response and carried by a `request` span, so every log line
//! of the request, service logs included, can be correlated with nginx's.

use axum::{
    extract::Request,
    http::{HeaderName, HeaderValue},
    middleware::Next,
    response::Response,
};
use tracing::Instrument;
use uuid::Uuid;

pub static X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

pub async fn layer(mut req: Request, next: Next) -> Response {
    let id = req
        .headers()
        .get(&X_REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .filter(|id| is_acceptable(id))
        .map(|s| s.to_owned())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    let header_value =
        HeaderValue::from_str(&id).unwrap_or_else(|_| HeaderValue::from_static("invalid"));

    req.headers_mut()
        .insert(&X_REQUEST_ID, header_value.clone());

    let span = tracing::info_span!("request", request_id = %id);
    let mut res = next.run(req).instrument(span).await;
    res.headers_mut().insert(&X_REQUEST_ID, header_value);
    res
}

/// A client-supplied identifier ends up in every log line of the request:
/// short, and made of characters that cannot forge a log field.
fn is_acceptable(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plausible_identifiers_are_kept() {
        for id in [
            "3f2b9c1e-7d4a-4c1b-9a53-0d3c8f6e2b11",
            "a1b2c3",
            "nginx:req.42_x",
        ] {
            assert!(is_acceptable(id), "{id}");
        }
    }

    #[test]
    fn forged_or_oversized_identifiers_are_replaced() {
        let long = "a".repeat(65);
        for id in [
            "",
            "a b",
            "x\"y",
            "id\nlevel=error",
            "{json}",
            long.as_str(),
        ] {
            assert!(!is_acceptable(id), "{id:?}");
        }
    }
}
