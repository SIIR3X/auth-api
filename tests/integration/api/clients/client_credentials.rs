//! The client credentials grant (RFC 6749 section 4.4).

use reqwest::Method;
use serde_json::{Value, json};

use super::{claims, form};
use crate::{
    api::admin::{admin, body},
    common::app::TestApp,
};

const SECRET: &str = "aacs_backend-secret";

async fn register(app: &TestApp, allowed: bool, scopes: &[&str], secret: bool) {
    sqlx::query(
        "INSERT INTO registered_clients
             (client_id, display_name, scopes, client_secret_hash, allows_client_credentials)
         VALUES ('backend', 'Backend', $1, $2, $3)",
    )
    .bind(scopes.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    .bind(secret.then(|| auth_api::utils::crypto::sha256(SECRET.as_bytes()).to_vec()))
    .bind(allowed)
    .execute(&app.db)
    .await
    .unwrap();
}

async fn token(app: &TestApp, extra: &[(&str, &str)]) -> (u16, Value) {
    let mut parameters = vec![("grant_type", "client_credentials")];
    parameters.extend_from_slice(extra);
    form(app, "/oauth/token", &parameters, Some(("backend", SECRET))).await
}

#[tokio::test]
async fn a_client_obtains_a_token_for_itself_with_its_scopes() {
    let app = TestApp::spawn().await;
    register(&app, true, &["audit:read", "users:read"], true).await;

    let (status, issued) = token(&app, &[]).await;
    assert_eq!(status, 200, "{issued}");
    assert!(issued.get("refresh_token").is_none());
    assert_eq!(issued["scope"], "audit:read users:read");
    let access = issued["access_token"].as_str().unwrap();
    let decoded = claims(access);
    assert_eq!(decoded["client_id"], "backend");
    assert_eq!(decoded["sid"], uuid::Uuid::nil().to_string());
    assert_eq!(decoded["permissions"], json!(["audit:read", "users:read"]));
    assert!(decoded.get("roles").is_none());

    let (_, narrowed) = token(&app, &[("scope", "users:read")]).await;
    assert_eq!(narrowed["scope"], "users:read");
    let (status, refused) = token(&app, &[("scope", "users:manage")]).await;
    assert_eq!(
        (status, refused["error"].as_str()),
        (400, Some("invalid_scope"))
    );

    // Not a user: the account routes refuse it.
    assert_eq!(app.get_auth("/users/me", access).await.status(), 401);
}

#[tokio::test]
async fn the_grant_is_reserved_to_confidential_clients_that_enable_it() {
    let app = TestApp::spawn().await;
    register(&app, false, &["users:read"], true).await;
    let (status, refused) = token(&app, &[]).await;
    assert_eq!(
        (status, refused["error"].as_str()),
        (400, Some("unauthorized_client"))
    );

    let admin = admin(&app, 1).await;
    let save = |allowed: bool, scopes: Value| json!({ "display_name": "Backend", "scopes": scopes, "allows_client_credentials": allowed });
    let request = |payload: Value| {
        app.client
            .request(Method::PUT, app.url("/admin/clients/backend"))
            .bearer_auth(&admin.token)
            .json(&payload)
            .send()
    };
    let (status, saved) = body(request(save(true, json!(["users:read"]))).await.unwrap()).await;
    assert_eq!(status, 200, "{saved}");
    assert_eq!(saved["allows_client_credentials"], true);
    assert_eq!(token(&app, &[]).await.0, 200);

    let (status, _) = body(request(save(true, json!([]))).await.unwrap()).await;
    assert_eq!(status, 422, "the grant needs scopes");
    let (status, _) = body(
        request(json!({ "display_name": "Backend", "scopes": [] }))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        status, 422,
        "scopes cannot be dropped while the grant is on"
    );

    // Removing the secret turns the grant off.
    let removed = app
        .client
        .delete(app.url("/admin/clients/backend/secret"))
        .bearer_auth(&admin.token)
        .send()
        .await
        .unwrap();
    assert_eq!(removed.status(), 204);
    let (_, clients) = body(app.get_auth("/admin/clients", &admin.token).await).await;
    assert_eq!(clients[0]["allows_client_credentials"], false);
    let (status, _) = body(request(save(true, json!(["users:read"]))).await.unwrap()).await;
    assert_eq!(status, 422, "the grant needs a secret");
}

#[tokio::test]
async fn a_client_token_is_introspected_and_revoked() {
    let app = TestApp::spawn().await;
    register(&app, true, &["users:read"], true).await;
    let (_, issued) = token(&app, &[]).await;
    let access = issued["access_token"].as_str().unwrap();

    let introspect = |token: String| {
        let app = &app;
        async move {
            form(
                app,
                "/oauth/introspect",
                &[("token", &token)],
                Some(("backend", SECRET)),
            )
            .await
            .1
        }
    };
    let active = introspect(access.to_owned()).await;
    assert_eq!(active["active"], true);
    assert_eq!(active["client_id"], "backend");
    assert_eq!(active["scope"], "users:read");

    let (status, _) = form(
        &app,
        "/oauth/revoke",
        &[("token", access)],
        Some(("backend", SECRET)),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        introspect(access.to_owned()).await,
        json!({ "active": false })
    );

    // Turning the grant off ends the tokens already issued.
    let (_, issued) = token(&app, &[]).await;
    sqlx::query("UPDATE registered_clients SET allows_client_credentials = FALSE")
        .execute(&app.db)
        .await
        .unwrap();
    assert_eq!(
        introspect(issued["access_token"].as_str().unwrap().to_owned()).await["active"],
        false
    );
}
