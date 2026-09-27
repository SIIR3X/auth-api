//! Captcha service tests.
//!
//! Test categories:
//!   1. Secret not configured --> verification skipped.
//!   2. Empty token with secret configured --> 422 immediately.
//!   3. Mock server: success:true --> ok, success:false --> 422.
//!   4. Upstream unreachable: fail_open --> ok, fail_closed --> 503.
//!   5. Upstream returns non-2xx: fail_open --> ok, fail_closed --> 503.
//!   6. Upstream returns non-JSON body: fail_open --> ok, fail_closed --> 503.

use std::net::SocketAddr;

use axum::{Json, Router, routing::post};
use tokio::net::TcpListener;

use crate::common::{app::TestApp, fixtures};

// helpers

/// Spawn a tiny Axum HTTP server that always returns a fixed hCaptcha-shaped body.
/// Returns the base URL to use as `captcha.verify_url`.
async fn spawn_captcha_mock(success: bool) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        let app = Router::new().route(
            "/verify",
            post(move || async move { Json(serde_json::json!({ "success": success })) }),
        );
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });

    format!("http://127.0.0.1:{port}/verify")
}

/// Attempt to register user `index` via the API with an optional captcha token.
async fn try_register(app: &TestApp, index: usize, captcha_token: Option<&str>) -> u16 {
    let mut body = serde_json::json!({
        "username": format!("cap_user{index}"),
        "email":    format!("cap_user{index}@example.com"),
        "password": format!("Password{index}!ok"),
    });
    if let Some(token) = captcha_token {
        body["captcha_token"] = serde_json::Value::String(token.to_owned());
    }
    app.post("/auth/register", &body).await.status().as_u16()
}

// 1. CAPTCHA disabled

#[tokio::test]
async fn captcha_disabled_register_succeeds_without_token() {
    // Default test config has captcha.secret = None --> verification is skipped.
    let app = TestApp::spawn().await;
    let status = try_register(&app, 1, None).await;
    assert_eq!(
        status, 202,
        "register must succeed when captcha is disabled"
    );
}

#[tokio::test]
async fn captcha_disabled_login_does_not_require_token() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 2).await;
    fixtures::activate_user(&app.db, user.id).await;

    let res = app
        .post(
            "/auth/login",
            &serde_json::json!({
                "identifier": user.email,
                "password": user.password,
                // No captcha_token supplied.
            }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200);
}

// 2. Empty token with secret configured

#[tokio::test]
async fn captcha_empty_token_rejected_when_secret_is_configured() {
    // An unreachable verify_url is intentional: the empty-token check runs
    // before any HTTP call, so the URL is never contacted.
    let app = TestApp::spawn_with_config(|c| {
        c.captcha.secret = Some("test_secret".into());
        c.captcha.verify_url = "http://127.0.0.1:9/verify".into(); // port 9 = discard
        c.captcha.fail_open_on_error = false;
    })
    .await;

    let status = try_register(&app, 3, Some("")).await;
    assert_eq!(status, 422, "empty captcha_token must return 422");
}

#[tokio::test]
async fn captcha_whitespace_only_token_rejected() {
    let app = TestApp::spawn_with_config(|c| {
        c.captcha.secret = Some("test_secret".into());
        c.captcha.verify_url = "http://127.0.0.1:9/verify".into();
        c.captcha.fail_open_on_error = false;
    })
    .await;

    let status = try_register(&app, 4, Some("   ")).await;
    assert_eq!(status, 422, "whitespace-only captcha_token must return 422");
}

// 3. Mock server: token accepted / rejected

#[tokio::test]
async fn captcha_valid_token_accepted_by_mock_server() {
    let verify_url = spawn_captcha_mock(true).await;

    let app = TestApp::spawn_with_config(|c| {
        c.captcha.secret = Some("test_secret".into());
        c.captcha.verify_url = verify_url.clone();
        c.captcha.fail_open_on_error = false;
        c.captcha.request_timeout_secs = 5;
    })
    .await;

    let status = try_register(&app, 5, Some("valid-token-xyz")).await;
    assert_eq!(
        status, 202,
        "register must succeed when mock returns success:true"
    );
}

#[tokio::test]
async fn captcha_invalid_token_rejected_by_mock_server() {
    let verify_url = spawn_captcha_mock(false).await;

    let app = TestApp::spawn_with_config(|c| {
        c.captcha.secret = Some("test_secret".into());
        c.captcha.verify_url = verify_url.clone();
        c.captcha.fail_open_on_error = false;
        c.captcha.request_timeout_secs = 5;
    })
    .await;

    let status = try_register(&app, 6, Some("invalid-token-xyz")).await;
    assert_eq!(
        status, 422,
        "register must fail with 422 when mock returns success:false"
    );
}

// 4. Upstream unreachable

#[tokio::test]
async fn captcha_fail_open_passes_when_upstream_unreachable() {
    // Port 9 (discard) is typically closed/refused immediately.
    let app = TestApp::spawn_with_config(|c| {
        c.captcha.secret = Some("test_secret".into());
        c.captcha.verify_url = "http://127.0.0.1:9/verify".into();
        c.captcha.fail_open_on_error = true;
        c.captcha.request_timeout_secs = 1;
    })
    .await;

    let status = try_register(&app, 7, Some("any-token")).await;
    assert_eq!(
        status, 202,
        "fail_open=true must let the request through when upstream is down"
    );
}

#[tokio::test]
async fn captcha_fail_closed_returns_503_when_upstream_unreachable() {
    let app = TestApp::spawn_with_config(|c| {
        c.captcha.secret = Some("test_secret".into());
        c.captcha.verify_url = "http://127.0.0.1:9/verify".into();
        c.captcha.fail_open_on_error = false;
        c.captcha.request_timeout_secs = 1;
    })
    .await;

    let status = try_register(&app, 8, Some("any-token")).await;
    assert_eq!(
        status, 503,
        "fail_open=false must return 503 when upstream is unreachable"
    );
}

#[tokio::test]
async fn captcha_login_fail_closed_returns_503_when_upstream_unreachable() {
    // Captcha is verified before any DB lookup, so credentials don't need to be real.
    let app = TestApp::spawn_with_config(|c| {
        c.captcha.secret = Some("test_secret".into());
        c.captcha.verify_url = "http://127.0.0.1:9/verify".into();
        c.captcha.fail_open_on_error = false;
        c.captcha.request_timeout_secs = 1;
    })
    .await;

    let res = app
        .post(
            "/auth/login",
            &serde_json::json!({
                "identifier": "anyone@example.com",
                "password": "Password1!ok",
                "captcha_token": "any-token",
            }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 503);
}

// 5. Upstream returns non-2xx

/// Spawn a mock that always responds with the given HTTP status and body.
async fn spawn_captcha_mock_with_status(http_status: u16, body: &'static str) -> String {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        let app = Router::new().route(
            "/verify",
            post(move || async move {
                (StatusCode::from_u16(http_status).unwrap(), body).into_response()
            }),
        );
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });

    format!("http://127.0.0.1:{port}/verify")
}

#[tokio::test]
async fn captcha_fail_open_passes_when_upstream_returns_500() {
    let verify_url = spawn_captcha_mock_with_status(500, "error").await;

    let app = TestApp::spawn_with_config(|c| {
        c.captcha.secret = Some("test_secret".into());
        c.captcha.verify_url = verify_url;
        c.captcha.fail_open_on_error = true;
        c.captcha.request_timeout_secs = 5;
    })
    .await;

    let status = try_register(&app, 9, Some("any-token")).await;
    assert_eq!(
        status, 202,
        "fail_open=true must pass through when upstream returns 500"
    );
}

#[tokio::test]
async fn captcha_fail_closed_returns_503_when_upstream_returns_500() {
    let verify_url = spawn_captcha_mock_with_status(500, "error").await;

    let app = TestApp::spawn_with_config(|c| {
        c.captcha.secret = Some("test_secret".into());
        c.captcha.verify_url = verify_url;
        c.captcha.fail_open_on_error = false;
        c.captcha.request_timeout_secs = 5;
    })
    .await;

    let status = try_register(&app, 10, Some("any-token")).await;
    assert_eq!(
        status, 503,
        "fail_open=false must return 503 when upstream returns 500"
    );
}

// 6. Upstream returns non-JSON body

#[tokio::test]
async fn captcha_fail_open_passes_when_upstream_returns_invalid_json() {
    let verify_url = spawn_captcha_mock_with_status(200, "not-json").await;

    let app = TestApp::spawn_with_config(|c| {
        c.captcha.secret = Some("test_secret".into());
        c.captcha.verify_url = verify_url;
        c.captcha.fail_open_on_error = true;
        c.captcha.request_timeout_secs = 5;
    })
    .await;

    let status = try_register(&app, 11, Some("any-token")).await;
    assert_eq!(
        status, 202,
        "fail_open=true must pass through when upstream returns invalid JSON"
    );
}

#[tokio::test]
async fn captcha_fail_closed_returns_503_when_upstream_returns_invalid_json() {
    let verify_url = spawn_captcha_mock_with_status(200, "not-json").await;

    let app = TestApp::spawn_with_config(|c| {
        c.captcha.secret = Some("test_secret".into());
        c.captcha.verify_url = verify_url;
        c.captcha.fail_open_on_error = false;
        c.captcha.request_timeout_secs = 5;
    })
    .await;

    let status = try_register(&app, 12, Some("any-token")).await;
    assert_eq!(
        status, 503,
        "fail_open=false must return 503 when upstream returns invalid JSON"
    );
}

/// A mock recording what it was asked and answering with `hostname`.
async fn spawn_recording_captcha_mock(
    hostname: &'static str,
) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded = seen.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let app = Router::new().route(
            "/verify",
            post(move |body: String| {
                let recorded = recorded.clone();
                async move {
                    recorded.lock().unwrap().push(body);
                    Json(serde_json::json!({ "success": true, "hostname": hostname }))
                }
            }),
        );
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://127.0.0.1:{port}/verify"), seen)
}

/// A token solved on another site is refused, and the provider hears the
/// client's address and the site key.
#[tokio::test]
async fn a_token_solved_on_another_site_is_refused() {
    let (verify_url, seen) = spawn_recording_captcha_mock("evil.example").await;
    let app = TestApp::spawn_with_config(move |c| {
        c.captcha.secret = Some("test_secret".into());
        c.captcha.verify_url = verify_url.clone();
        c.captcha.fail_open_on_error = false;
        c.captcha.site_key = Some("site-key-1".into());
    })
    .await;
    assert_eq!(try_register(&app, 40, Some("foreign-token")).await, 422);
    let request = seen.lock().unwrap()[0].clone();
    assert!(request.contains("remoteip="), "{request}");
    assert!(request.contains("sitekey=site-key-1"), "{request}");

    let (verify_url, _) = spawn_recording_captcha_mock("localhost").await;
    let app = TestApp::spawn_with_config(move |c| {
        c.captcha.secret = Some("test_secret".into());
        c.captcha.verify_url = verify_url.clone();
        c.captcha.fail_open_on_error = false;
    })
    .await;
    assert_eq!(
        try_register(&app, 41, Some("our-token")).await,
        202,
        "solved on the host of FRONTEND_URL"
    );
}

/// With a CAPTCHA required, the budget of an identifier stops refusing: every
/// attempt already costs a solved challenge, and guessing someone's password
/// must not also keep them from signing in (SEC-67). The lockout still bounds
/// the guesses.
#[tokio::test]
async fn the_captcha_replaces_the_identifier_budget() {
    let verify_url = spawn_captcha_mock(true).await;
    let app = TestApp::spawn_with_config(|c| {
        c.captcha.secret = Some("test_secret".into());
        c.captcha.verify_url = verify_url.clone();
        c.captcha.fail_open_on_error = false;
        c.captcha.request_timeout_secs = 5;
        c.security.lockout_threshold = 50;
    })
    .await;
    let email = "captcha.budget70@example.com";
    let password = "Password70!okay";
    let registered = app
        .post(
            "/auth/register",
            &serde_json::json!({
                "username": "captcha_budget70",
                "email": email,
                "password": password,
                "captcha_token": "valid-token-xyz",
            }),
        )
        .await;
    assert_eq!(registered.status().as_u16(), 202);
    let id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM users WHERE email = $1")
        .bind(email)
        .fetch_one(&app.db)
        .await
        .unwrap();
    fixtures::activate_user(&app.db, id).await;
    let login = |password: &str| {
        serde_json::json!({
            "identifier": email,
            "password": password,
            "captcha_token": "valid-token-xyz",
        })
    };

    // The identifier's budget is spent (10 failures this quarter of an hour).
    for _ in 0..10 {
        sqlx::query(
            "INSERT INTO login_attempts (user_id, attempted_identifier, was_successful, failure_reason)
             VALUES ($1, $2, FALSE, 'invalid_password')",
        )
        .bind(id)
        .bind(email)
        .execute(&app.db)
        .await
        .unwrap();
    }
    let status = app
        .post("/auth/login", &login("Wrong-Password-70!"))
        .await
        .status();
    assert_eq!(status.as_u16(), 401, "a solved challenge is not refused");
    let status = app.post("/auth/login", &login(password)).await.status();
    assert_eq!(status.as_u16(), 200, "the owner still signs in");
}
