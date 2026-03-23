//! Request ID middleware.
//!
//! Reads x-request-id from the incoming request if present, otherwise generates
//! a new UUID v4. The ID is forwarded on the response so clients can correlate logs.

use axum::{
    extract::Request,
    http::{HeaderName, HeaderValue},
    middleware::Next,
    response::Response,
};
use uuid::Uuid;

pub static X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

pub async fn layer(mut req: Request, next: Next) -> Response {
    let id = req
        .headers()
        .get(&X_REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    let header_value =
        HeaderValue::from_str(&id).unwrap_or_else(|_| HeaderValue::from_static("invalid"));

    req.headers_mut()
        .insert(&X_REQUEST_ID, header_value.clone());

    let mut res = next.run(req).await;
    res.headers_mut().insert(&X_REQUEST_ID, header_value);
    res
}
