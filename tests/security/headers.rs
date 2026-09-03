//! Security headers and Request-ID middleware tests.
//!
//! Every response must carry the defensive headers injected by the
//! `security_headers` middleware layer, and the `x-request-id` must be
//! echoed back (or generated) on every response.

use auth_api::config::Environment;

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

// Strict-Transport-Security

#[tokio::test]
async fn security_headers_skip_hsts_outside_production() {
    let app = TestApp::spawn().await;

    let res = app
        .client
        .get(format!("{}/users/me", app.base_url))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status().as_u16(), 401);
    assert!(res.headers().get("strict-transport-security").is_none());
    assert!(res.headers().get("content-security-policy").is_some());
}

#[tokio::test]
async fn security_headers_enable_hsts_for_https_production() {
    let app = TestApp::spawn_with_config(|config| {
        config.env = Environment::Production;
        config.server.public_url = "https://api.example.com".into();
        config.server.frontend_url = "https://app.example.com".into();
        config.cors.allowed_origins = vec!["https://app.example.com".into()];
        config.cors.allow_credentials = true;
        // Production validation requires non-empty SMTP credentials and CAPTCHA secret.
        config.mail.smtp.host = "smtp.example.com".into();
        config.mail.smtp.username = "user".into();
        config.mail.smtp.password = "pass".into();
        config.captcha.secret = Some("0x0000000000000000000000000000000000000000".into());
        // Production validation also enforces hardened security defaults.
        config.rate_limit.fail_open_on_redis_error = false;
        config.rate_limit.allow_requests_without_ip = false;
        config.captcha.fail_open_on_error = false;
        config.jwt.strict_session_binding = true;
        // The committed development AES key is refused in production.
        config.crypto.encryption_key = "6M+xtK7VzYMoz/3mc3vJf2e6h9b9yLyx3Eabo/236YE=".into();
    })
    .await;

    let res = app
        .client
        .get(format!("{}/users/me", app.base_url))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status().as_u16(), 401);
    assert_eq!(
        res.headers()
            .get("strict-transport-security")
            .and_then(|value| value.to_str().ok()),
        Some("max-age=63072000; includeSubDomains")
    );
}
