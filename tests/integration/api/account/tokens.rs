//! Personal access tokens: `/users/me/tokens` and their exchange.

use auth_api::repositories::role as role_repo;
use serde_json::{Value, json};

use crate::common::{
    app::TestApp,
    fixtures::{self, AuthenticatedUser},
};

/// An account holding `audit:read` and `users:read` (through the admin role).
async fn account(app: &TestApp, index: usize) -> AuthenticatedUser {
    let user = fixtures::authenticated_user(app, index).await;
    let role = role_repo::find_by_name(&app.db, "admin")
        .await
        .unwrap()
        .unwrap();
    role_repo::assign_to_user(&app.db, user.id, role.id, None)
        .await
        .unwrap();
    user
}

async fn create(app: &TestApp, user: &AuthenticatedUser, body: Value) -> (u16, Value) {
    let response = app
        .post_auth("/users/me/tokens", &user.access_token, &body)
        .await;
    let status = response.status().as_u16();
    (status, response.json().await.unwrap_or(Value::Null))
}

async fn exchange(app: &TestApp, secret: &str) -> (u16, Value) {
    let response = app
        .post(
            "/auth/personal-access-tokens/exchange",
            &json!({ "token": secret }),
        )
        .await;
    let status = response.status().as_u16();
    (status, response.json().await.unwrap_or(Value::Null))
}

#[tokio::test]
async fn a_token_is_exchanged_for_access_tokens_carrying_its_scopes_only() {
    let app = TestApp::spawn().await;
    let user = account(&app, 1).await;

    let (status, created) = create(
        &app,
        &user,
        json!({ "name": "backup script", "scopes": ["audit:read"], "expires_in_days": 30 }),
    )
    .await;
    assert_eq!(status, 201, "{created}");
    let secret = created["secret"].as_str().unwrap();
    assert!(secret.starts_with("aapat_"));

    let listed: Value = app
        .get_auth("/users/me/tokens", &user.access_token)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(listed[0]["name"], "backup script");
    assert!(listed[0].get("secret").is_none());
    assert!(!listed.to_string().contains(secret));

    let (status, exchanged) = exchange(&app, secret).await;
    assert_eq!(status, 200, "{exchanged}");
    assert_eq!(exchanged["token_type"], "Bearer");
    let access = exchanged["access_token"].as_str().unwrap();
    let claims = app.decode_access_token(access);
    assert_eq!(claims.permissions, ["audit:read"]);
    assert!(claims.roles.is_empty());
    assert_eq!(app.get_auth("/users/me", access).await.status(), 200);

    let listed: Value = app
        .get_auth("/users/me/tokens", &user.access_token)
        .await
        .json()
        .await
        .unwrap();
    assert!(listed[0]["last_used_at"].is_number());

    let sessions: Value = app
        .get_auth("/users/me/sessions", &user.access_token)
        .await
        .json()
        .await
        .unwrap();
    assert!(
        sessions
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["session_type"] == "personal_access_token"
                && s["device_name"] == "backup script")
    );
}

#[tokio::test]
async fn a_revoked_token_and_its_access_tokens_stop_working() {
    let app = TestApp::spawn().await;
    let user = account(&app, 1).await;
    let (_, created) = create(&app, &user, json!({ "name": "ci" })).await;
    let secret = created["secret"].as_str().unwrap();
    let (_, exchanged) = exchange(&app, secret).await;
    let access = exchanged["access_token"].as_str().unwrap();

    let response = app
        .delete_auth(
            &format!("/users/me/tokens/{}", created["id"].as_str().unwrap()),
            &user.access_token,
        )
        .await;
    assert_eq!(response.status(), 204);

    assert_eq!(exchange(&app, secret).await.0, 401);
    assert_eq!(app.get_auth("/users/me", access).await.status(), 401);
    let listed: Value = app
        .get_auth("/users/me/tokens", &user.access_token)
        .await
        .json()
        .await
        .unwrap();
    assert!(listed.as_array().unwrap().is_empty());

    let other = account(&app, 2).await;
    let response = app
        .delete_auth(
            &format!("/users/me/tokens/{}", created["id"].as_str().unwrap()),
            &other.access_token,
        )
        .await;
    assert_eq!(response.status(), 404);
}

#[tokio::test]
async fn tokens_expire_and_follow_the_account_status() {
    let app = TestApp::spawn().await;
    let user = account(&app, 1).await;
    let (_, created) = create(&app, &user, json!({ "name": "ci", "expires_in_days": 1 })).await;
    let secret = created["secret"].as_str().unwrap().to_owned();

    sqlx::query("UPDATE users SET status = 'suspended' WHERE id = $1")
        .bind(user.id)
        .execute(&app.db)
        .await
        .unwrap();
    let (status, body) = exchange(&app, &secret).await;
    assert_eq!(status, 403);
    assert_eq!(body["code"], "account_suspended");

    sqlx::query("UPDATE users SET status = 'active' WHERE id = $1")
        .bind(user.id)
        .execute(&app.db)
        .await
        .unwrap();
    app.clock.advance(time::Duration::days(2));
    let (status, body) = exchange(&app, &secret).await;
    assert_eq!(status, 401);
    assert_eq!(body["code"], "token_expired");
}

#[tokio::test]
async fn creation_is_checked() {
    let app = TestApp::spawn().await;
    let user = account(&app, 1).await;

    for body in [
        json!({ "name": " " }),
        json!({ "name": "ci", "expires_in_days": 0 }),
        json!({ "name": "ci", "expires_in_days": 366 }),
        json!({ "name": "ci", "scopes": ["planets:destroy"] }),
    ] {
        let (status, response) = create(&app, &user, body.clone()).await;
        assert_eq!(status, 422, "{body}: {response}");
    }

    for index in 0..20 {
        let (status, _) = create(&app, &user, json!({ "name": format!("token {index}") })).await;
        assert_eq!(status, 201);
    }
    let (status, response) = create(&app, &user, json!({ "name": "one more" })).await;
    assert_eq!(status, 409);
    assert_eq!(response["code"], "too_many_tokens");

    app.clear_recent_reauth(&user.access_token).await;
    sqlx::query("DELETE FROM personal_access_tokens WHERE user_id = $1")
        .bind(user.id)
        .execute(&app.db)
        .await
        .unwrap();
    let (status, response) = create(&app, &user, json!({ "name": "ci" })).await;
    assert_eq!(status, 403);
    assert_eq!(response["code"], "reauthentication_required");

    for malformed in ["", "aapat_short", "not-a-token", &"a".repeat(49)] {
        assert_eq!(exchange(&app, malformed).await.0, 401, "{malformed}");
    }
}
