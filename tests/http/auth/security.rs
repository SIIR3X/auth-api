use crate::common::app::TestApp;
use rust_api::config::Environment;

#[tokio::test]
async fn auth_routes_fail_closed_when_rate_limiter_backend_is_down() {
    let app = TestApp::spawn_with_config(|config| {
        config.redis.url = "redis://127.0.0.1:1".into();
        config.rate_limit.fail_open_on_redis_error = false;
    })
    .await;

    let res = app
        .post(
            "/auth/login",
            &serde_json::json!({
                "identifier": "nobody@example.com",
                "password": "Password123!",
            }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 503);
}

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
        config.cors.allowed_origins = vec!["https://app.example.com".into()];
        config.cors.allow_credentials = true;
        config.webauthn.rp_id = "api.example.com".into();
        config.webauthn.rp_origin = "https://api.example.com".into();
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
