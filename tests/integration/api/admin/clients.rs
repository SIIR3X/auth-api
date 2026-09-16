//! `/admin/clients`.

use reqwest::Method;
use serde_json::{Value, json};

use super::{admin, body};
use crate::common::app::TestApp;

async fn send(
    app: &TestApp,
    method: Method,
    path: &str,
    token: &str,
    payload: Value,
) -> (u16, Value) {
    body(
        app.client
            .request(method, app.url(path))
            .bearer_auth(token)
            .json(&payload)
            .send()
            .await
            .unwrap(),
    )
    .await
}

#[tokio::test]
async fn a_client_is_registered_updated_listed_and_removed_with_its_sessions() {
    let app = TestApp::spawn().await;
    let admin = admin(&app, 1).await;

    let settings = json!({
        "display_name": "Desktop app",
        "scopes": ["users:read"],
        "redirect_uris": ["http://127.0.0.1/callback"],
        "allows_loopback_redirect": true,
        "default_max_sessions": 3
    });
    let (status, created) = send(
        &app,
        Method::PUT,
        "/admin/clients/desktop-app",
        &admin.token,
        settings.clone(),
    )
    .await;
    assert_eq!(status, 201, "{created}");
    assert_eq!(created["default_max_sessions"], 3);

    let mut renamed = settings;
    renamed["display_name"] = json!("Desktop");
    let (status, updated) = send(
        &app,
        Method::PUT,
        "/admin/clients/desktop-app",
        &admin.token,
        renamed,
    )
    .await;
    assert_eq!(status, 200, "{updated}");
    assert_eq!(updated["display_name"], "Desktop");

    let (status, clients) = body(app.get_auth("/admin/clients", &admin.token).await).await;
    assert_eq!(status, 200);
    assert!(
        clients
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["client_id"] == "desktop-app")
    );

    // A session held through the client ends with it.
    sqlx::query("UPDATE sessions SET client_id = 'desktop-app' WHERE user_id = $1")
        .bind(admin.user.id)
        .execute(&app.db)
        .await
        .unwrap();
    let other = super::admin(&app, 2).await;
    let (status, _) = send(
        &app,
        Method::DELETE,
        "/admin/clients/desktop-app",
        &other.token,
        json!({}),
    )
    .await;
    assert_eq!(status, 204);
    assert_eq!(app.get_auth("/users/me", &admin.token).await.status(), 401);
    let (status, _) = send(
        &app,
        Method::DELETE,
        "/admin/clients/desktop-app",
        &other.token,
        json!({}),
    )
    .await;
    assert_eq!(status, 404);

    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action::text FROM audit_log WHERE action::text LIKE 'client_%' ORDER BY created_at",
    )
    .fetch_all(&app.db)
    .await
    .unwrap();
    assert_eq!(
        actions,
        ["client_registered", "client_updated", "client_deleted"]
    );
}

#[tokio::test]
async fn invalid_client_settings_are_refused() {
    let app = TestApp::spawn().await;
    let admin = admin(&app, 1).await;

    for (path, settings) in [
        ("/admin/clients/bad%20id", json!({ "display_name": "App" })),
        ("/admin/clients/app", json!({ "display_name": " " })),
        (
            "/admin/clients/app",
            json!({ "display_name": "App", "redirect_uris": ["not a uri"] }),
        ),
        (
            "/admin/clients/app",
            json!({ "display_name": "App", "default_max_sessions": 0 }),
        ),
        (
            "/admin/clients/app",
            json!({ "display_name": "App", "scopes": ["planets:destroy"] }),
        ),
    ] {
        let (status, response) =
            send(&app, Method::PUT, path, &admin.token, settings.clone()).await;
        assert_eq!(status, 422, "{settings}: {response}");
    }

    let primary = json!({ "display_name": "App", "is_primary": true });
    let (status, _) = send(
        &app,
        Method::PUT,
        "/admin/clients/first",
        &admin.token,
        primary.clone(),
    )
    .await;
    assert_eq!(status, 201);
    let (status, response) = send(
        &app,
        Method::PUT,
        "/admin/clients/second",
        &admin.token,
        primary,
    )
    .await;
    assert_eq!(status, 409);
    assert_eq!(response["code"], "primary_client_exists");
}
