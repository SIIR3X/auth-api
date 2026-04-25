use crate::common::{app::TestApp, fixtures};

// forgot-password

#[tokio::test]
async fn forgot_password_returns_200_for_known_email() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 1).await;
    fixtures::activate_user(&app.db, user.id).await;
    app.clear_forgot_password_rate_limit("127.0.0.1").await;

    let res = app
        .post(
            "/auth/forgot-password",
            &serde_json::json!({ "email": user.email }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 200);
}

#[tokio::test]
async fn forgot_password_returns_200_for_unknown_email() {
    // Anti-enumeration: the endpoint must not reveal whether the email exists.
    let app = TestApp::spawn().await;
    app.clear_forgot_password_rate_limit("127.0.0.1").await;

    let res = app
        .post(
            "/auth/forgot-password",
            &serde_json::json!({ "email": "nobody@example.com" }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 200);
}

// reset-password

#[tokio::test]
async fn reset_password_success_allows_login_with_new_password() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 2).await;
    fixtures::activate_user(&app.db, user.id).await;
    app.clear_reset_password_rate_limit("127.0.0.1").await;

    let token = fixtures::create_password_reset_token(&app.db, user.id).await;
    let new_password = "NewPassword1!ok";

    let res = app
        .post(
            "/auth/reset-password",
            &serde_json::json!({
                "token": token.raw,
                "new_password": new_password,
            }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200);

    // Login with the new password must succeed.
    let login = app
        .post(
            "/auth/login",
            &serde_json::json!({
                "identifier": user.email,
                "password": new_password,
            }),
        )
        .await;
    assert_eq!(login.status().as_u16(), 200);

    // Login with the old password must fail.
    let old_login = app
        .post(
            "/auth/login",
            &serde_json::json!({
                "identifier": user.email,
                "password": user.password,
            }),
        )
        .await;
    assert_eq!(old_login.status().as_u16(), 401);
}

#[tokio::test]
async fn reset_password_with_invalid_token_rejected() {
    let app = TestApp::spawn().await;
    app.clear_reset_password_rate_limit("127.0.0.1").await;

    let res = app
        .post(
            "/auth/reset-password",
            &serde_json::json!({
                "token": "this-token-does-not-exist",
                "new_password": "NewPassword1!ok",
            }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 401);
}

#[tokio::test]
async fn reset_password_with_expired_token_rejected() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 3).await;
    fixtures::activate_user(&app.db, user.id).await;
    app.clear_reset_password_rate_limit("127.0.0.1").await;

    let token = fixtures::create_expired_password_reset_token(&app.db, user.id).await;

    let res = app
        .post(
            "/auth/reset-password",
            &serde_json::json!({
                "token": token.raw,
                "new_password": "NewPassword1!ok",
            }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 401);
}

#[tokio::test]
async fn reset_password_with_already_used_token_rejected() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 4).await;
    fixtures::activate_user(&app.db, user.id).await;
    app.clear_reset_password_rate_limit("127.0.0.1").await;

    let token = fixtures::create_used_password_reset_token(&app.db, user.id).await;

    let res = app
        .post(
            "/auth/reset-password",
            &serde_json::json!({
                "token": token.raw,
                "new_password": "NewPassword1!ok",
            }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 401);
}

#[tokio::test]
async fn reset_password_with_weak_password_rejected() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 5).await;
    fixtures::activate_user(&app.db, user.id).await;

    let token = fixtures::create_password_reset_token(&app.db, user.id).await;

    // Too short - fails the validate_password check at handler level.
    let res = app
        .post(
            "/auth/reset-password",
            &serde_json::json!({
                "token": token.raw,
                "new_password": "short",
            }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 422);
}

#[tokio::test]
async fn reset_password_revokes_all_active_sessions() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 6).await;
    app.clear_reset_password_rate_limit("127.0.0.1").await;

    // Sanity: the token works before reset.
    let before = app.get_auth("/users/me", &user.access_token).await;
    assert_eq!(before.status().as_u16(), 200);

    let token = fixtures::create_password_reset_token(&app.db, user.id).await;

    let res = app
        .post(
            "/auth/reset-password",
            &serde_json::json!({
                "token": token.raw,
                "new_password": "NewPassword1!ok",
            }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200);

    // The old access token must no longer be valid (session revoked).
    let after = app.get_auth("/users/me", &user.access_token).await;
    assert!(
        after.status().as_u16() == 401 || after.status().as_u16() == 403,
        "expected 401 or 403 after password reset, got {}",
        after.status()
    );
}

// forgot-password rate limiting

#[tokio::test]
async fn forgot_password_rate_limited_after_5_requests() {
    // Use a unique virtual IP via X-Forwarded-For so the rate-limit counter is
    // completely isolated from other tests that share the real `fp_req:127.0.0.1` key.
    let app = TestApp::spawn_with_config(|c| {
        c.server.trusted_proxy_cidrs = vec!["127.0.0.0/8".parse().unwrap()];
    })
    .await;

    let virtual_ip = "192.0.2.9"; // TEST-NET-1, unique to this test

    // Clear any leftover counter from a previous run sharing the same Redis.
    app.clear_forgot_password_rate_limit(virtual_ip).await;

    // Send 5 requests - all must succeed (limit rejects once count reaches 5).
    for _ in 0..5 {
        let res = app
            .client
            .post(format!("{}/auth/forgot-password", app.base_url))
            .header("X-Forwarded-For", virtual_ip)
            .json(&serde_json::json!({ "email": "anyone@example.com" }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            res.status().as_u16(),
            200,
            "requests before limit must succeed"
        );
    }

    // The 6th request must be rate-limited (429).
    let res = app
        .client
        .post(format!("{}/auth/forgot-password", app.base_url))
        .header("X-Forwarded-For", virtual_ip)
        .json(&serde_json::json!({ "email": "anyone@example.com" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.status().as_u16(),
        429,
        "expected 429 after 5 forgot-password requests"
    );
}

// verify-email

#[tokio::test]
async fn verify_email_activates_unverified_account() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 7).await;
    app.clear_verify_email_rate_limit("127.0.0.1").await;

    // Account must be unverified initially (cannot login).
    let before = app
        .post(
            "/auth/login",
            &serde_json::json!({
                "identifier": user.email,
                "password": user.password,
            }),
        )
        .await;
    assert_eq!(before.status().as_u16(), 403);

    let token = fixtures::create_email_verification_token(&app.db, user.id, &user.email).await;

    let res = app
        .post(
            "/auth/verify-email",
            &serde_json::json!({ "token": token.raw }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200);

    // After verification the user can log in.
    let after = app
        .post(
            "/auth/login",
            &serde_json::json!({
                "identifier": user.email,
                "password": user.password,
            }),
        )
        .await;
    assert_eq!(after.status().as_u16(), 200);
}

#[tokio::test]
async fn verify_email_with_invalid_token_rejected() {
    let app = TestApp::spawn().await;
    app.clear_verify_email_rate_limit("127.0.0.1").await;

    let res = app
        .post(
            "/auth/verify-email",
            &serde_json::json!({ "token": "not-a-valid-token" }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 401);
}

#[tokio::test]
async fn verify_email_with_already_used_token_rejected() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 8).await;
    app.clear_verify_email_rate_limit("127.0.0.1").await;

    let token = fixtures::create_email_verification_token(&app.db, user.id, &user.email).await;

    // Use it once - succeeds.
    let first = app
        .post(
            "/auth/verify-email",
            &serde_json::json!({ "token": token.raw }),
        )
        .await;
    assert_eq!(first.status().as_u16(), 200);

    // Use it again - must fail.
    let second = app
        .post(
            "/auth/verify-email",
            &serde_json::json!({ "token": token.raw }),
        )
        .await;
    assert_eq!(second.status().as_u16(), 401);
}
