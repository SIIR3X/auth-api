//! Token introspection (RFC 7662) and revocation (RFC 7009).

use serde_json::{Value, json};

use super::form;
use crate::common::{
    app::TestApp,
    fixtures::{self, AuthenticatedUser},
};

const RESOURCE_SERVER: (&str, &str) = ("resource-server", "aacs_resource-server-secret");

async fn setup(app: &TestApp) {
    sqlx::query(
        "INSERT INTO registered_clients (client_id, display_name, is_primary, client_secret_hash)
         VALUES ($1, 'Resource server', FALSE, $2)",
    )
    .bind(RESOURCE_SERVER.0)
    .bind(auth_api::utils::crypto::sha256(RESOURCE_SERVER.1.as_bytes()).to_vec())
    .execute(&app.db)
    .await
    .unwrap();
    for (client_id, primary) in [("cli-app", true), ("other-app", false)] {
        sqlx::query(
            "INSERT INTO registered_clients (client_id, display_name, is_primary) VALUES ($1, $1, $2)",
        )
        .bind(client_id)
        .bind(primary)
        .execute(&app.db)
        .await
        .unwrap();
    }
}

/// Tokens of `cli-app` for `user`, through the device flow.
async fn client_tokens(app: &TestApp, user: &AuthenticatedUser) -> Value {
    let (_, started) = form(
        app,
        "/oauth/device_authorization",
        &[("client_id", "cli-app")],
        None,
    )
    .await;
    let approved = app
        .post_auth(
            "/oauth/device/verify",
            &user.access_token,
            &json!({ "user_code": started["user_code"] }),
        )
        .await;
    assert_eq!(approved.status(), 200);
    let (status, tokens) = form(
        app,
        "/oauth/token",
        &[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", started["device_code"].as_str().unwrap()),
            ("client_id", "cli-app"),
        ],
        None,
    )
    .await;
    assert_eq!(status, 200, "{tokens}");
    tokens
}

async fn introspect(app: &TestApp, token: &str) -> Value {
    let (status, body) = form(
        app,
        "/oauth/introspect",
        &[("token", token)],
        Some(RESOURCE_SERVER),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    body
}

async fn revoke(app: &TestApp, token: &str, client_id: &str) -> u16 {
    form(
        app,
        "/oauth/revoke",
        &[("token", token), ("client_id", client_id)],
        None,
    )
    .await
    .0
}

#[tokio::test]
async fn a_resource_server_learns_what_a_token_is_worth() {
    let app = TestApp::spawn().await;
    setup(&app).await;
    let user = fixtures::authenticated_user(&app, 1).await;
    let tokens = client_tokens(&app, &user).await;

    let access = introspect(&app, tokens["access_token"].as_str().unwrap()).await;
    assert_eq!(access["active"], true);
    assert_eq!(access["token_type"], "access_token");
    assert_eq!(access["client_id"], "cli-app");
    assert_eq!(access["sub"], user.id.to_string());
    assert!(access["exp"].is_number() && access["jti"].is_string());

    let refresh = introspect(&app, tokens["refresh_token"].as_str().unwrap()).await;
    assert_eq!(refresh["active"], true);
    assert_eq!(refresh["token_type"], "refresh_token");

    // A first-party session has no client.
    let own = introspect(&app, &user.access_token).await;
    assert_eq!(own["active"], true);
    assert!(own.get("client_id").is_none());

    for garbage in ["nope", "a.b.c", "aapat_short"] {
        assert_eq!(introspect(&app, garbage).await, json!({ "active": false }));
    }

    let (status, body) = form(
        &app,
        "/oauth/introspect",
        &[("token", "nope"), ("client_id", "cli-app")],
        None,
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("unauthorized_client"))
    );
    let (status, body) = form(
        &app,
        "/oauth/introspect",
        &[("token", "nope")],
        Some((RESOURCE_SERVER.0, "aacs_wrong")),
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (401, Some("invalid_client"))
    );
}

#[tokio::test]
async fn revoking_a_refresh_token_ends_its_session() {
    let app = TestApp::spawn().await;
    setup(&app).await;
    let user = fixtures::authenticated_user(&app, 1).await;
    let tokens = client_tokens(&app, &user).await;
    let refresh_token = tokens["refresh_token"].as_str().unwrap();

    assert_eq!(revoke(&app, refresh_token, "cli-app").await, 200);
    assert_eq!(introspect(&app, refresh_token).await["active"], false);
    assert_eq!(
        introspect(&app, tokens["access_token"].as_str().unwrap()).await["active"],
        false
    );
    let (status, _) = form(
        &app,
        "/oauth/token",
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", "cli-app"),
        ],
        None,
    )
    .await;
    assert_eq!(status, 400);

    // Revoking again, or something unknown, answers the same.
    assert_eq!(revoke(&app, refresh_token, "cli-app").await, 200);
    assert_eq!(revoke(&app, "unknown-token", "cli-app").await, 200);
}

#[tokio::test]
async fn revoking_an_access_token_ends_that_token_only() {
    let app = TestApp::spawn().await;
    setup(&app).await;
    let user = fixtures::authenticated_user(&app, 1).await;
    let tokens = client_tokens(&app, &user).await;
    let access = tokens["access_token"].as_str().unwrap();

    assert_eq!(revoke(&app, access, "cli-app").await, 200);
    assert_eq!(introspect(&app, access).await["active"], false);
    assert_eq!(app.get_auth("/users/me", access).await.status(), 401);
    assert_eq!(
        introspect(&app, tokens["refresh_token"].as_str().unwrap()).await["active"],
        true
    );
}

#[tokio::test]
async fn a_client_cannot_revoke_the_tokens_of_another() {
    let app = TestApp::spawn().await;
    setup(&app).await;
    let user = fixtures::authenticated_user(&app, 1).await;
    let tokens = client_tokens(&app, &user).await;

    for token in [
        tokens["access_token"].as_str().unwrap(),
        tokens["refresh_token"].as_str().unwrap(),
        user.access_token.as_str(),
        user.refresh_token.as_str(),
    ] {
        assert_eq!(revoke(&app, token, "other-app").await, 200);
        assert_eq!(introspect(&app, token).await["active"], true, "{token}");
    }
}
