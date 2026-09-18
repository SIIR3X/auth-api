//! Every error response carries an `ErrorBody`.
//!
//! Handlers return `AppError`, which renders one. Responses produced before a
//! handler runs do not: the router's 404 and 405, the extractor rejections
//! (malformed JSON, missing content type, a body over the limit), the rate
//! limiter and the request timeout answer in plain text, and the JSON
//! rejections quote the parser. This layer gives those responses the
//! documented shape and keeps their status and headers (`Retry-After`,
//! `Allow`): clients parse one format, and no parser detail leaks.

use axum::{
    body::Body,
    extract::Request,
    http::{
        HeaderValue, StatusCode,
        header::{CONTENT_LENGTH, CONTENT_TYPE},
    },
    middleware::Next,
    response::Response,
};

use crate::error::ErrorBody;

pub async fn layer(req: Request, next: Next) -> Response {
    normalize(next.run(req).await)
}

fn normalize(response: Response) -> Response {
    let status = response.status();
    if !(status.is_client_error() || status.is_server_error()) {
        return response;
    }
    let is_json = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/json"));
    if is_json {
        return response;
    }

    let (code, message) = describe(status);
    let body = serde_json::to_vec(&ErrorBody::new(code, message))
        .expect("an error body always serializes");

    let (mut parts, _) = response.into_parts();
    parts.headers.remove(CONTENT_LENGTH);
    parts
        .headers
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    Response::from_parts(parts, Body::from(body))
}

fn describe(status: StatusCode) -> (&'static str, &'static str) {
    match status {
        StatusCode::BAD_REQUEST => ("invalid_request", "The request could not be read."),
        StatusCode::NOT_FOUND => ("not_found", "The requested resource was not found."),
        StatusCode::METHOD_NOT_ALLOWED => (
            "method_not_allowed",
            "This method is not allowed on this resource.",
        ),
        StatusCode::PAYLOAD_TOO_LARGE => ("payload_too_large", "The request body is too large."),
        StatusCode::UNSUPPORTED_MEDIA_TYPE => (
            "unsupported_media_type",
            "The request body must be JSON (Content-Type: application/json).",
        ),
        StatusCode::UNPROCESSABLE_ENTITY => (
            "validation_error",
            "The request body does not have the expected fields and types.",
        ),
        StatusCode::TOO_MANY_REQUESTS => (
            "rate_limit_exceeded",
            "Too many requests. Please slow down.",
        ),
        StatusCode::SERVICE_UNAVAILABLE => (
            "service_unavailable",
            "The service is temporarily unavailable.",
        ),
        status if status.is_server_error() => ("internal_error", "An internal error occurred."),
        _ => ("request_failed", "The request could not be completed."),
    }
}

#[cfg(test)]
mod tests {
    use axum::response::IntoResponse;

    use super::*;

    async fn body_of(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn plain_text_errors_become_error_bodies_with_their_headers() {
        let mut plain = (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
        plain
            .headers_mut()
            .insert("retry-after", HeaderValue::from_static("7"));

        let normalized = normalize(plain);

        assert_eq!(normalized.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(normalized.headers()["retry-after"], "7");
        assert_eq!(normalized.headers()[CONTENT_TYPE], "application/json");
        let body = body_of(normalized).await;
        assert_eq!(body["code"], "rate_limit_exceeded");
        assert!(body["message"].is_string());
    }

    #[tokio::test]
    async fn parser_details_do_not_leak() {
        let rejection = (
            StatusCode::UNPROCESSABLE_ENTITY,
            "Failed to deserialize the JSON body into the target type: missing field `password` at line 1 column 2",
        )
            .into_response();
        let body = body_of(normalize(rejection)).await;
        assert_eq!(body["code"], "validation_error");
        assert!(!body.to_string().contains("password"));
    }

    #[tokio::test]
    async fn json_errors_and_successes_are_left_alone() {
        let json = (
            StatusCode::CONFLICT,
            [(CONTENT_TYPE, "application/json")],
            r#"{"code":"email_taken","message":"x"}"#,
        )
            .into_response();
        assert_eq!(body_of(normalize(json)).await["code"], "email_taken");

        let ok = (StatusCode::OK, "ok").into_response();
        let bytes = axum::body::to_bytes(normalize(ok).into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&bytes[..], b"ok");
    }

    #[test]
    fn every_error_status_has_a_stable_code() {
        assert_eq!(describe(StatusCode::NOT_FOUND).0, "not_found");
        assert_eq!(
            describe(StatusCode::METHOD_NOT_ALLOWED).0,
            "method_not_allowed"
        );
        assert_eq!(
            describe(StatusCode::PAYLOAD_TOO_LARGE).0,
            "payload_too_large"
        );
        assert_eq!(describe(StatusCode::BAD_GATEWAY).0, "internal_error");
        assert_eq!(describe(StatusCode::IM_A_TEAPOT).0, "request_failed");
    }

    #[test]
    fn plain_text_rejections_get_their_own_codes() {
        assert_eq!(describe(StatusCode::BAD_REQUEST).0, "invalid_request");
        assert_eq!(
            describe(StatusCode::UNSUPPORTED_MEDIA_TYPE).0,
            "unsupported_media_type"
        );
        assert_eq!(
            describe(StatusCode::SERVICE_UNAVAILABLE).0,
            "service_unavailable"
        );
    }

    #[tokio::test]
    async fn the_layer_rewrites_what_a_router_answers() {
        use tower::ServiceExt;

        let router = axum::Router::new()
            .route(
                "/down",
                axum::routing::get(|| async { (StatusCode::SERVICE_UNAVAILABLE, "down") }),
            )
            .layer(axum::middleware::from_fn(layer));
        let request = |path: &str| axum::http::Request::get(path).body(Body::empty()).unwrap();

        let down = router.clone().oneshot(request("/down")).await.unwrap();
        assert_eq!(down.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body_of(down).await["code"], "service_unavailable");

        let missing = router.oneshot(request("/nowhere")).await.unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        assert_eq!(body_of(missing).await["code"], "not_found");
    }
}
