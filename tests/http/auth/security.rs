use crate::common::app::{TestApp, redis_url_with_db};
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
        // Production validation requires non-empty SMTP credentials.
        config.mail.smtp.host = "smtp.example.com".into();
        config.mail.smtp.username = "user".into();
        config.mail.smtp.password = "pass".into();
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

// Rate limit enforcement

#[tokio::test]
async fn auth_rate_limit_blocks_requests_exceeding_limit() {
    // Spawn an app with a very tight auth rate limit (3 req/min).
    // Uses an isolated Redis DB (4) to avoid interference from parallel tests
    // that all share the same 127.0.0.1 rate-limit key on DB 1.
    let app = TestApp::spawn_with_config(|config| {
        config.rate_limit.auth_requests_per_minute = 3;
        config.rate_limit.fail_open_on_redis_error = false;
        config.rate_limit.allow_requests_without_ip = false;
        config.redis.url = redis_url_with_db(&config.redis.url, 4);
    })
    .await;

    // Clear any residual entries from prior runs of this test.
    app.clear_auth_rate_limit_key("127.0.0.1").await;

    let payload = serde_json::json!({
        "identifier": "rate-limit-test@example.com",
        "password": "AnyPassword1!",
    });

    // First 3 requests: should reach the application (may be 401 creds, not 429).
    for _ in 0..3 {
        let res = app.post("/auth/login", &payload).await;
        assert_ne!(
            res.status().as_u16(),
            429,
            "early requests should not be rate limited"
        );
    }

    // 4th request: must be rate limited.
    let res = app.post("/auth/login", &payload).await;
    assert_eq!(res.status().as_u16(), 429);
}

#[tokio::test]
async fn auth_rate_limit_response_includes_retry_after_header() {
    // Uses isolated Redis DB 5 for the same isolation reason as the test above.
    let app = TestApp::spawn_with_config(|config| {
        config.rate_limit.auth_requests_per_minute = 1;
        config.rate_limit.fail_open_on_redis_error = false;
        config.rate_limit.allow_requests_without_ip = false;
        config.redis.url = redis_url_with_db(&config.redis.url, 5);
    })
    .await;

    app.clear_auth_rate_limit_key("127.0.0.1").await;

    let payload = serde_json::json!({
        "identifier": "retry-after-test@example.com",
        "password": "AnyPassword1!",
    });

    // Exhaust the 1-request bucket.
    let _ = app.post("/auth/login", &payload).await;

    // Second request must be rejected with Retry-After.
    let res = app.post("/auth/login", &payload).await;
    assert_eq!(res.status().as_u16(), 429);
    assert!(
        res.headers().get("retry-after").is_some(),
        "429 response must include Retry-After header"
    );
}

#[tokio::test]
async fn general_rate_limit_blocks_non_auth_routes() {
    // Uses isolated Redis DB 6 for the same isolation reason as auth tests above.
    // Does NOT use authenticated_user: that fixture makes HTTP requests that would
    // consume slots from the tiny bucket (limit=2) before the test assertions start.
    let app = TestApp::spawn_with_config(|config| {
        config.rate_limit.requests_per_minute = 2;
        config.rate_limit.fail_open_on_redis_error = false;
        config.rate_limit.allow_requests_without_ip = false;
        config.redis.url = redis_url_with_db(&config.redis.url, 6);
    })
    .await;

    app.clear_rate_limit_key("127.0.0.1").await;

    // First 2 unauthenticated requests: within the limit (returns 401, not 429).
    for _ in 0..2 {
        let res = app
            .client
            .get(format!("{}/users/me", app.base_url))
            .send()
            .await
            .unwrap();
        assert_ne!(
            res.status().as_u16(),
            429,
            "early requests should not be rate limited"
        );
    }

    // 3rd request: over the limit.
    let res = app
        .client
        .get(format!("{}/users/me", app.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 429);
}
