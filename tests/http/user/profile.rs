use crate::common::{app::TestApp, fixtures};

// DELETE /users/me

#[tokio::test]
async fn delete_account_requires_auth() {
    let app = TestApp::spawn().await;

    let res = app
        .client
        .delete(format!("{}/users/me", app.base_url))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status().as_u16(), 401);
}

#[tokio::test]
async fn delete_account_with_correct_password_succeeds() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 10).await;
    app.clear_recent_reauth(&user.access_token).await;

    let res = app
        .delete_auth_json(
            "/users/me",
            &user.access_token,
            &serde_json::json!({ "current_password": user.password }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 204);
}

#[tokio::test]
async fn delete_account_with_wrong_password_rejected() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 11).await;
    app.clear_recent_reauth(&user.access_token).await;

    let res = app
        .delete_auth_json(
            "/users/me",
            &user.access_token,
            &serde_json::json!({ "current_password": "WrongPassword1!" }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 401);
}

#[tokio::test]
async fn delete_account_without_password_and_no_recent_reauth_rejected() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 12).await;
    app.clear_recent_reauth(&user.access_token).await;

    // No password provided, no recent reauth → 403.
    let res = app
        .delete_auth_json("/users/me", &user.access_token, &serde_json::json!({}))
        .await;

    assert_eq!(res.status().as_u16(), 403);
}

#[tokio::test]
async fn delete_account_with_recent_reauth_succeeds_without_password() {
    let app = TestApp::spawn().await;
    // authenticated_user already marks recent reauth on login.
    let user = fixtures::authenticated_user(&app, 13).await;

    let res = app
        .delete_auth_json("/users/me", &user.access_token, &serde_json::json!({}))
        .await;

    assert_eq!(res.status().as_u16(), 204);
}

#[tokio::test]
async fn deleted_account_token_no_longer_works() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 14).await;

    // Delete with the token while reauth is fresh.
    let del = app
        .delete_auth_json("/users/me", &user.access_token, &serde_json::json!({}))
        .await;
    assert_eq!(del.status().as_u16(), 204);

    // Any subsequent authenticated request must fail.
    let after = app.get_auth("/users/me", &user.access_token).await;
    assert!(
        after.status().as_u16() == 401 || after.status().as_u16() == 403,
        "expected 401 or 403 after account deletion, got {}",
        after.status()
    );
}

// GET/PATCH /users/me

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
async fn change_locale_invalid_locale_rejected() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 12).await;

    let res = app
        .patch_auth(
            "/users/me/locale",
            &user.access_token,
            &serde_json::json!({ "locale": "xx" }),
        )
        .await;

    assert_eq!(
        res.status().as_u16(),
        422,
        "unsupported locale must return 422"
    );
}

#[tokio::test]
async fn change_locale_requires_auth() {
    let app = TestApp::spawn().await;

    let res = app
        .client
        .patch(format!("{}/users/me/locale", app.base_url))
        .json(&serde_json::json!({ "locale": "fr" }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status().as_u16(), 401);
}
