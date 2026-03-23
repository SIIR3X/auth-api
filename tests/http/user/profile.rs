use crate::common::{app::TestApp, fixtures};

#[tokio::test]
async fn me_returns_profile() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 1).await;

    let res = app.get_auth("/users/me", &user.access_token).await;
    assert_eq!(res.status().as_u16(), 200);

    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["username"], user.username);
    assert_eq!(body["email"], user.email);
    assert_eq!(body["status"], "active");
}

#[tokio::test]
async fn me_requires_auth() {
    let app = TestApp::spawn().await;

    let res = app
        .client
        .get(format!("{}/users/me", app.base_url))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status().as_u16(), 401);
}

#[tokio::test]
async fn change_username_success() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 2).await;

    let res = app
        .patch_auth(
            "/users/me/username",
            &user.access_token,
            &serde_json::json!({ "username": "newname123" }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 204);

    let profile = app.get_auth("/users/me", &user.access_token).await;
    let body: serde_json::Value = profile.json().await.unwrap();
    assert_eq!(body["username"], "newname123");
}

#[tokio::test]
async fn change_username_conflict() {
    let app = TestApp::spawn().await;
    let user1 = fixtures::authenticated_user(&app, 3).await;
    let user2 = fixtures::authenticated_user(&app, 4).await;

    // user2 tries to steal user1's username
    let res = app
        .patch_auth(
            "/users/me/username",
            &user2.access_token,
            &serde_json::json!({ "username": user1.username }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 409);
}

#[tokio::test]
async fn change_locale_success() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 5).await;

    let res = app
        .patch_auth(
            "/users/me/locale",
            &user.access_token,
            &serde_json::json!({ "locale": "fr" }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 204);
}

#[tokio::test]
async fn change_email_requires_current_password() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 6).await;

    let res = app
        .patch_auth(
            "/users/me/email",
            &user.access_token,
            &serde_json::json!({
                "email": "new-email@example.com",
                "current_password": "WrongPassword!",
            }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 401);
}

#[tokio::test]
async fn change_email_success_updates_email_and_requires_reverification() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 7).await;

    let res = app
        .patch_auth(
            "/users/me/email",
            &user.access_token,
            &serde_json::json!({
                "email": "new-email@example.com",
                "current_password": user.password,
            }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 204);

    let profile = app.get_auth("/users/me", &user.access_token).await;
    assert_eq!(profile.status().as_u16(), 200);

    let body: serde_json::Value = profile.json().await.unwrap();
    assert_eq!(body["email"], "new-email@example.com");
    assert_eq!(body["status"], "pending_verification");
}

#[tokio::test]
async fn change_email_without_password_requires_recent_reauth() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 8).await;

    app.clear_recent_reauth(&user.access_token).await;

    let res = app
        .patch_auth(
            "/users/me/email",
            &user.access_token,
            &serde_json::json!({
                "email": "recent-auth@example.com"
            }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 403);

    let res = app
        .post_auth(
            "/users/me/reauth",
            &user.access_token,
            &serde_json::json!({ "current_password": user.password }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 204);

    let res = app
        .patch_auth(
            "/users/me/email",
            &user.access_token,
            &serde_json::json!({
                "email": "recent-auth@example.com"
            }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 204);
}
