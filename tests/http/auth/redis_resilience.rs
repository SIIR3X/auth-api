//! Redis-resilience tests - verify the API degrades gracefully when Redis
//! is unavailable, without breaking core authentication flows.
//!
//! Tests index range 370–389.
//!
//! All tests use a dead Redis port (1) so that every `redis.get()` call fails
//! immediately. Operations that fail-open (rate limits, cooldowns) must still
//! allow the request through. Core DB-backed operations must still succeed.

use crate::common::{app::TestApp, fixtures};

/// Spawn an app with Redis pointing to an unreachable port.
async fn app_without_redis() -> TestApp {
    TestApp::spawn_with_config(|c| {
        c.redis.url = "redis://127.0.0.1:1".into();
        c.redis.wait_timeout_ms = 100; // fail fast
        c.rate_limit.fail_open_on_redis_error = true; // don't block requests
    })
    .await
}

// Registration

#[tokio::test]
async fn register_succeeds_when_redis_is_down() {
    let app = app_without_redis().await;
    let res = app
        .post(
            "/auth/register",
            &serde_json::json!({
                "username": "redis_resilience_370",
                "email": "redis_resilience_370@example.com",
                "password": "Password370!ok",
            }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 201);
}

// Login

#[tokio::test]
async fn login_succeeds_when_redis_is_down() {
    // Register + activate entirely within the no-redis app's own DB.
    let app = app_without_redis().await;
    let user = fixtures::register_user(&app, 371).await;
    fixtures::activate_user(&app.db, user.id).await;

    let res = app
        .post(
            "/auth/login",
            &serde_json::json!({
                "identifier": user.email,
                "password": user.password,
            }),
        )
        .await;
    // Login may succeed (200) or require 2FA challenge - either way not 5xx.
    assert!(
        res.status().as_u16() < 500,
        "login must not 5xx when Redis is down, got {}",
        res.status()
    );
}

// Email verification

#[tokio::test]
async fn email_verification_succeeds_when_redis_is_down() {
    // Register then verify entirely within the no-redis app's own DB.
    let app = app_without_redis().await;
    let user = fixtures::register_user(&app, 372).await;
    let token = fixtures::create_email_verification_token(&app.db, user.id, &user.email).await;

    let res = app
        .post(
            "/auth/verify-email",
            &serde_json::json!({ "token": token.raw }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200);
}

// Rate limit fail-closed

#[tokio::test]
async fn rate_limit_fail_closed_returns_503_when_redis_is_down() {
    // With fail_open_on_redis_error=false and dead Redis, the rate limiter
    // must reject every request with 503 instead of passing it through.
    let app = TestApp::spawn_with_config(|c| {
        c.redis.url = "redis://127.0.0.1:1".into();
        c.redis.wait_timeout_ms = 100;
        c.rate_limit.fail_open_on_redis_error = false;
    })
    .await;

    let res = app
        .post(
            "/auth/register",
            &serde_json::json!({
                "username": "rl_fail_closed",
                "email": "rl_fail_closed@example.com",
                "password": "Password374!ok",
            }),
        )
        .await;
    assert_eq!(
        res.status().as_u16(),
        503,
        "fail_open=false must return 503 when Redis is unavailable"
    );
}

// Password reset

#[tokio::test]
async fn password_reset_submit_succeeds_when_redis_is_down() {
    // Register + activate + reset entirely within the no-redis app's own DB.
    let app = app_without_redis().await;
    let user = fixtures::register_user(&app, 373).await;
    fixtures::activate_user(&app.db, user.id).await;
    let token = fixtures::create_password_reset_token(&app.db, user.id).await;

    let res = app
        .post(
            "/auth/reset-password",
            &serde_json::json!({
                "token": token.raw,
                "new_password": "NewPassword373!ok",
            }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200);
}
