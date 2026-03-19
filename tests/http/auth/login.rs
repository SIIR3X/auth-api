use crate::common::{app::TestApp, fixtures};

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
    // JWT is still valid but session is revoked — service should reject it
    // depending on implementation this may be 401 or 403
    assert!(
        res2.status().as_u16() == 401 || res2.status().as_u16() == 403,
        "expected 401 or 403 after logout, got {}",
        res2.status()
    );
}
