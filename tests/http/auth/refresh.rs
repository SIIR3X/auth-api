use crate::common::{app::TestApp, fixtures};

#[tokio::test]
async fn refresh_returns_new_tokens() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 1).await;

    let res = app
        .post(
            "/auth/refresh",
            &serde_json::json!({ "refresh_token": user.refresh_token }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 200);

    let body: serde_json::Value = res.json().await.unwrap();
    let new_access = body["access_token"].as_str().unwrap();
    let new_refresh = body["refresh_token"].as_str().unwrap();

    assert!(!new_access.is_empty());
    assert!(!new_refresh.is_empty());
    // Tokens must rotate
    assert_ne!(new_access, user.access_token);
    assert_ne!(new_refresh, user.refresh_token);
}

#[tokio::test]
async fn refresh_token_replay_is_rejected() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 2).await;

    // First refresh succeeds
    let res1 = app
        .post(
            "/auth/refresh",
            &serde_json::json!({ "refresh_token": user.refresh_token }),
        )
        .await;
    assert_eq!(res1.status().as_u16(), 200);

    // Replaying the same refresh token must fail
    let res2 = app
        .post(
            "/auth/refresh",
            &serde_json::json!({ "refresh_token": user.refresh_token }),
        )
        .await;
    assert_eq!(res2.status().as_u16(), 401);
}

#[tokio::test]
async fn refresh_invalid_token_rejected() {
    let app = TestApp::spawn().await;

    let res = app
        .post(
            "/auth/refresh",
            &serde_json::json!({ "refresh_token": "not-a-valid-token" }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 401);
}

#[tokio::test]
async fn new_access_token_is_usable() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 3).await;

    let res = app
        .post(
            "/auth/refresh",
            &serde_json::json!({ "refresh_token": user.refresh_token }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200);

    let body: serde_json::Value = res.json().await.unwrap();
    let new_access = body["access_token"].as_str().unwrap();

    let profile_res = app.get_auth("/users/me", new_access).await;
    assert_eq!(profile_res.status().as_u16(), 200);
}
