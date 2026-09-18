//! Edge behaviour of the router: public keys, request size, cross-origin access.

use serde_json::{Value, json};

use crate::common::app::TestApp;

#[tokio::test]
async fn jwks_publishes_only_public_ec_keys_and_is_cacheable() {
    let app = TestApp::spawn().await;

    let res = app
        .client
        .get(format!("{}/.well-known/jwks.json", app.base_url))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status().as_u16(), 200);
    assert_eq!(
        res.headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
        Some("public, max-age=300"),
        "public keys are cacheable; the blanket no-store must not apply"
    );

    let body: Value = res.json().await.unwrap();
    let keys = body["keys"].as_array().expect("a JWK set");
    assert!(!keys.is_empty());
    for key in keys {
        assert_eq!(key["kty"], "EC");
        assert_eq!(key["crv"], "P-256");
        assert!(key["kid"].is_string(), "verifiers select keys by kid");
        assert!(
            key.get("d").is_none(),
            "the private scalar must never be published"
        );
    }
}

#[tokio::test]
async fn an_oversized_body_is_refused_before_the_handler() {
    let app = TestApp::spawn().await;

    let res = app
        .post(
            "/auth/login",
            &json!({
                "identifier": "someone@example.com",
                "password": "x".repeat(70_000),
            }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 413);
}

async fn preflight(app: &TestApp, origin: &str) -> reqwest::Response {
    app.client
        .request(
            reqwest::Method::OPTIONS,
            format!("{}/auth/login", app.base_url),
        )
        .header("origin", origin)
        .header("access-control-request-method", "POST")
        .header("access-control-request-headers", "content-type")
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn cross_origin_access_is_limited_to_the_allowlist() {
    let app = TestApp::spawn_with_config(|config| {
        config.cors.allowed_origins = vec!["https://app.example.com".into()];
    })
    .await;

    let allowed = preflight(&app, "https://app.example.com").await;
    assert_eq!(
        allowed
            .headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("https://app.example.com")
    );

    let refused = preflight(&app, "https://evil.example.com").await;
    assert!(
        refused
            .headers()
            .get("access-control-allow-origin")
            .is_none(),
        "an unlisted origin must not be granted access"
    );
}
