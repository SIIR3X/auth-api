use crate::common::{app::TestApp, fixtures};

// P3: login edge cases

#[tokio::test]
async fn login_response_contains_access_and_refresh_token() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 10).await;
    fixtures::activate_user(&app.db, user.id).await;

    let res = app
        .post(
            "/auth/login",
            &serde_json::json!({ "identifier": user.email, "password": user.password }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200);

    let body: serde_json::Value = res.json().await.unwrap();
    assert!(
        body["access_token"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false),
        "access_token missing or empty"
    );
    assert!(
        body["refresh_token"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false),
        "refresh_token missing or empty"
    );
}

#[tokio::test]
async fn login_remember_me_true_produces_longer_session_than_false() {
    let app = TestApp::spawn().await;

    // Create two users to avoid session count interference.
    let user_long = fixtures::register_user(&app, 11).await;
    fixtures::activate_user(&app.db, user_long.id).await;
    let user_short = fixtures::register_user(&app, 12).await;
    fixtures::activate_user(&app.db, user_short.id).await;

    // Login with remember_me: true.
    let r_long: serde_json::Value = app
        .post(
            "/auth/login",
            &serde_json::json!({
                "identifier": user_long.email,
                "password": user_long.password,
                "remember_me": true,
            }),
        )
        .await
        .json()
        .await
        .unwrap();
    let token_long = r_long["access_token"].as_str().unwrap();

    // Login with remember_me: false (or omitted, defaults to false).
    let r_short: serde_json::Value = app
        .post(
            "/auth/login",
            &serde_json::json!({
                "identifier": user_short.email,
                "password": user_short.password,
                "remember_me": false,
            }),
        )
        .await
        .json()
        .await
        .unwrap();
    let token_short = r_short["access_token"].as_str().unwrap();

    // Read expires_at from session list for each user.
    let sessions_long: serde_json::Value = app
        .get_auth("/users/me/sessions", token_long)
        .await
        .json()
        .await
        .unwrap();
    let sessions_short: serde_json::Value = app
        .get_auth("/users/me/sessions", token_short)
        .await
        .json()
        .await
        .unwrap();

    let exp_long = sessions_long.as_array().unwrap()[0]["expires_at"]
        .as_i64()
        .unwrap();
    let exp_short = sessions_short.as_array().unwrap()[0]["expires_at"]
        .as_i64()
        .unwrap();

    assert!(
        exp_long > exp_short,
        "expected remember_me=true session (exp={exp_long}) to expire later than remember_me=false (exp={exp_short})"
    );
}

#[tokio::test]
async fn login_with_device_name_stored_in_session() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 13).await;
    fixtures::activate_user(&app.db, user.id).await;

    let res: serde_json::Value = app
        .post(
            "/auth/login",
            &serde_json::json!({
                "identifier": user.email,
                "password": user.password,
                "device_name": "My Laptop",
            }),
        )
        .await
        .json()
        .await
        .unwrap();

    let access_token = res["access_token"].as_str().unwrap();

    let sessions: serde_json::Value = app
        .get_auth("/users/me/sessions", access_token)
        .await
        .json()
        .await
        .unwrap();

    let session = &sessions.as_array().unwrap()[0];
    assert_eq!(
        session["device_name"].as_str(),
        Some("My Laptop"),
        "device_name not stored in session"
    );
}

#[tokio::test]
async fn login_suspended_user_returns_403() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 14).await;

    // Activate the user, then immediately suspend them.
    fixtures::activate_user(&app.db, user.id).await;
    sqlx::query("UPDATE users SET status = 'suspended' WHERE id = $1")
        .bind(user.id)
        .execute(&app.db)
        .await
        .expect("failed to suspend user");

    let res = app
        .post(
            "/auth/login",
            &serde_json::json!({ "identifier": user.email, "password": user.password }),
        )
        .await;

    assert_eq!(
        res.status().as_u16(),
        403,
        "expected 403 for suspended user"
    );
}

#[tokio::test]
async fn login_audit_log_entry_created() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 15).await;
    fixtures::activate_user(&app.db, user.id).await;

    let res = app
        .post(
            "/auth/login",
            &serde_json::json!({ "identifier": user.email, "password": user.password }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200);

    // Verify the audit_log contains a Login entry for this user.
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE user_id = $1 AND action = 'login'",
    )
    .bind(user.id)
    .fetch_one(&app.db)
    .await
    .expect("failed to query audit_log");

    assert!(
        count >= 1,
        "expected at least one login audit entry, got {count}"
    );
}

#[tokio::test]
async fn login_returns_403_for_inactive_account() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 16).await;

    // Activate, then flip to inactive directly in the DB.
    fixtures::activate_user(&app.db, user.id).await;
    sqlx::query("UPDATE users SET status = 'inactive' WHERE id = $1")
        .bind(user.id)
        .execute(&app.db)
        .await
        .expect("failed to set user inactive");

    let res = app
        .post(
            "/auth/login",
            &serde_json::json!({ "identifier": user.email, "password": user.password }),
        )
        .await;

    assert_eq!(
        res.status().as_u16(),
        403,
        "expected 403 for inactive account"
    );
}

// existing tests

#[tokio::test]
async fn login_success() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 1).await;

    assert!(!user.access_token.is_empty());
    assert!(!user.refresh_token.is_empty());
}

#[tokio::test]
async fn login_wrong_password() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 2).await;
    fixtures::activate_user(&app.db, user.id).await;

    let res = app
        .post(
            "/auth/login",
            &serde_json::json!({
                "identifier": user.email,
                "password": "WrongPassword!",
            }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 401);
}

#[tokio::test]
async fn login_unknown_user() {
    let app = TestApp::spawn().await;

    let res = app
        .post(
            "/auth/login",
            &serde_json::json!({
                "identifier": "nobody@example.com",
                "password": "SomePassword1!",
            }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 401);
}

#[tokio::test]
async fn login_unverified_email() {
    let app = TestApp::spawn().await;

    // Register but do NOT activate
    let user = fixtures::register_user(&app, 3).await;

    let res = app
        .post(
            "/auth/login",
            &serde_json::json!({
                "identifier": user.email,
                "password": user.password,
            }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 403);
}

#[tokio::test]
async fn login_by_username() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 4).await;
    fixtures::activate_user(&app.db, user.id).await;

    let res = app
        .post(
            "/auth/login",
            &serde_json::json!({
                "identifier": user.username,
                "password": user.password,
            }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 200);

    let body: serde_json::Value = res.json().await.unwrap();
    assert!(body["access_token"].as_str().is_some());
}

#[tokio::test]
async fn logout_invalidates_token() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 5).await;

    let res = app
        .post_auth("/auth/logout", &user.access_token, &serde_json::json!({}))
        .await;
    assert_eq!(res.status().as_u16(), 204);

    // The revoked session token should no longer work
    let res2 = app.get_auth("/users/me", &user.access_token).await;
    // JWT is still valid but session is revoked - service should reject it
    // depending on implementation this may be 401 or 403
    assert!(
        res2.status().as_u16() == 401 || res2.status().as_u16() == 403,
        "expected 401 or 403 after logout, got {}",
        res2.status()
    );
}
