//! Token introspection (RFC 7662) and revocation (RFC 7009).

use serde_json::{Value, json};

use super::{claims, form};
use crate::common::{
    app::TestApp,
    fixtures::{self, AuthenticatedUser},
};

const RESOURCE_SERVER: (&str, &str) = ("resource-server", "aacs_resource-server-secret");

async fn setup(app: &TestApp) {
    sqlx::query(
        "INSERT INTO registered_clients (client_id, display_name, is_primary, client_secret_hash, allows_introspection)
         VALUES ($1, 'Resource server', FALSE, $2, TRUE)",
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

/// Sessions of `user_id` not revoked.
async fn live_sessions(app: &TestApp, user_id: uuid::Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL")
        .bind(user_id)
        .fetch_one(&app.db)
        .await
        .unwrap()
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

    // A refresh token is its client's secret: another client learns nothing.
    let refresh = introspect(&app, tokens["refresh_token"].as_str().unwrap()).await;
    assert_eq!(refresh, json!({ "active": false }));

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
        live_sessions(&app, user.id).await,
        2,
        "the session lives on"
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
    }
    for token in [
        tokens["access_token"].as_str().unwrap(),
        user.access_token.as_str(),
    ] {
        assert_eq!(introspect(&app, token).await["active"], true, "{token}");
    }
    assert_eq!(
        live_sessions(&app, user.id).await,
        2,
        "no session was revoked"
    );
}

/// Personal access tokens belong to accounts, and refresh tokens to their
/// client: introspection by another client says nothing of either (SEC-62).
#[tokio::test]
async fn introspection_reveals_no_personal_or_foreign_refresh_token() {
    let app = TestApp::spawn().await;
    setup(&app).await;
    let user = fixtures::authenticated_user(&app, 2).await;
    let created: Value = app
        .post_auth(
            "/users/me/tokens",
            &user.access_token,
            &json!({ "name": "ci" }),
        )
        .await
        .json()
        .await
        .unwrap();

    for token in [
        created["secret"].as_str().unwrap(),
        user.refresh_token.as_str(),
    ] {
        assert_eq!(introspect(&app, token).await, json!({ "active": false }));
    }
}

/// Only a resource server introspects the tokens of others; another
/// confidential client learns nothing of them. A resource server registered
/// with scopes learns only those, and the session a token comes from shows
/// (SEC-72).
#[tokio::test]
async fn only_resource_servers_introspect_the_tokens_of_others() {
    let app = TestApp::spawn().await;
    setup(&app).await;
    let plain = ("plain-confidential", "aacs_plain-confidential-secret");
    sqlx::query(
        "INSERT INTO registered_clients (client_id, display_name, client_secret_hash)
         VALUES ($1, $1, $2)",
    )
    .bind(plain.0)
    .bind(auth_api::utils::crypto::sha256(plain.1.as_bytes()).to_vec())
    .execute(&app.db)
    .await
    .unwrap();
    let user = fixtures::authenticated_user(&app, 3).await;

    let (status, body) = form(
        &app,
        "/oauth/introspect",
        &[("token", user.access_token.as_str())],
        Some(plain),
    )
    .await;
    assert_eq!((status, body), (200, json!({ "active": false })));

    let seen = introspect(&app, &user.access_token).await;
    assert_eq!(seen["active"], true);
    assert_eq!(seen["session_type"], "web");

    sqlx::query("UPDATE registered_clients SET scopes = ARRAY['audit:read'] WHERE client_id = $1")
        .bind(RESOURCE_SERVER.0)
        .execute(&app.db)
        .await
        .unwrap();
    let narrowed = introspect(&app, &user.access_token).await;
    assert!(narrowed.get("scope").is_none(), "{narrowed}");

    let created: Value = app
        .post_auth(
            "/users/me/tokens",
            &user.access_token,
            &json!({ "name": "ci" }),
        )
        .await
        .json()
        .await
        .unwrap();
    let exchanged: Value = app
        .post(
            "/auth/personal-access-tokens/exchange",
            &json!({ "token": created["secret"] }),
        )
        .await
        .json()
        .await
        .unwrap();
    let script = introspect(&app, exchanged["access_token"].as_str().unwrap()).await;
    assert_eq!(script["session_type"], "personal_access_token");
    assert_eq!(
        claims(exchanged["access_token"].as_str().unwrap())["session_type"],
        "personal_access_token"
    );
}
