//! Security headers and Request-ID middleware tests.
//!
//! Every response must carry the defensive headers injected by the
//! `security_headers` middleware layer, and the `x-request-id` must be
//! echoed back (or generated) on every response.

use crate::common::app::TestApp;

// Security headers

#[tokio::test]
async fn security_headers_present_on_200_response() {
    let app = TestApp::spawn().await;

    // Use an unauthenticated endpoint that reliably returns 200 (or 401).
    // Any response carries the middleware headers.
    let res = app
        .client
        .get(format!("{}/users/me", app.base_url))
        .send()
        .await
        .unwrap();

    let headers = res.headers();

    assert_eq!(
        headers
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff"),
        "x-content-type-options must be 'nosniff'"
    );
    assert_eq!(
        headers.get("x-frame-options").and_then(|v| v.to_str().ok()),
        Some("DENY"),
        "x-frame-options must be 'DENY'"
    );
    assert_eq!(
        headers
            .get("x-xss-protection")
            .and_then(|v| v.to_str().ok()),
        Some("0"),
        "x-xss-protection must be '0'"
    );
    assert_eq!(
        headers.get("cache-control").and_then(|v| v.to_str().ok()),
        Some("no-store"),
        "cache-control must be 'no-store'"
    );
    assert_eq!(
        headers.get("referrer-policy").and_then(|v| v.to_str().ok()),
        Some("strict-origin-when-cross-origin"),
        "referrer-policy must be set"
    );
    let csp = headers
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        csp.contains("default-src 'none'"),
        "CSP must contain default-src 'none', got: {csp}"
    );
    assert!(
        csp.contains("frame-ancestors 'none'"),
        "CSP must contain frame-ancestors 'none', got: {csp}"
    );
}

#[tokio::test]
async fn security_headers_present_on_404_response() {
    let app = TestApp::spawn().await;

    let res = app
        .client
        .get(format!("{}/no-such-route-xyz", app.base_url))
        .send()
        .await
        .unwrap();

    // Headers must be injected regardless of status code.
    assert_eq!(
        res.headers()
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff"),
        "security headers must be present on 404 responses"
    );
    assert_eq!(
        res.headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
        Some("no-store"),
    );
}

// Request ID

#[tokio::test]
async fn request_id_generated_when_not_supplied() {
    let app = TestApp::spawn().await;

    let res = app
        .client
        .get(format!("{}/users/me", app.base_url))
        .send()
        .await
        .unwrap();

    let id = res
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    assert!(
        !id.is_empty(),
        "x-request-id must be generated when not supplied"
    );
    // Should be a valid UUID v4.
    uuid::Uuid::parse_str(id).expect("auto-generated x-request-id must be a valid UUID");
}

#[tokio::test]
async fn request_id_echoed_when_supplied_by_client() {
    let app = TestApp::spawn().await;
    let client_id = uuid::Uuid::new_v4().to_string();

    let res = app
        .client
        .get(format!("{}/users/me", app.base_url))
        .header("x-request-id", &client_id)
        .send()
        .await
        .unwrap();

    let echoed = res
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    assert_eq!(
        echoed, client_id,
        "x-request-id supplied by client must be echoed back"
    );
}

#[tokio::test]
async fn request_id_present_on_auth_error_responses() {
    let app = TestApp::spawn().await;

    // Even 401 responses must carry x-request-id.
    let res = app
        .client
        .post(format!("{}/auth/login", app.base_url))
        .json(&serde_json::json!({
            "identifier": "nobody@example.com",
            "password": "WrongPass1!",
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status().as_u16(), 401);
    assert!(
        res.headers().contains_key("x-request-id"),
        "x-request-id must be present on 401 error responses"
    );
}
