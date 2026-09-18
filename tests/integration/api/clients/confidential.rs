//! Confidential clients: a client with a secret authenticates at the token and
//! device authorization endpoints (RFC 6749 section 2.3.1).

use reqwest::Method;
use serde_json::{Value, json};

use super::form;
use crate::{
    api::admin::{admin, body},
    common::app::TestApp,
};

async fn register(app: &TestApp) {
    sqlx::query(
        "INSERT INTO registered_clients (client_id, display_name, is_primary)
         VALUES ('backend', 'Backend', TRUE)",
    )
    .execute(&app.db)
    .await
    .unwrap();
}

async fn secret_for(app: &TestApp, token: &str) -> String {
    let (status, response) = body(
        app.client
            .request(Method::POST, app.url("/admin/clients/backend/secret"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, 200, "{response}");
    response["client_secret"].as_str().unwrap().to_owned()
}

fn error(body: &Value) -> &str {
    body["error"].as_str().unwrap_or_default()
}

#[tokio::test]
async fn a_confidential_client_must_authenticate_with_its_secret() {
    let app = TestApp::spawn().await;
    register(&app).await;
    let admin = admin(&app, 1).await;
    let secret = secret_for(&app, &admin.token).await;
    assert!(secret.starts_with("aacs_"));
    let (_, clients) = body(app.get_auth("/admin/clients", &admin.token).await).await;
    assert_eq!(clients[0]["confidential"], true);

    let path = "/oauth/device_authorization";
    let (status, response) = form(&app, path, &[("client_id", "backend")], None).await;
    assert_eq!((status, error(&response)), (401, "invalid_client"));

    let (status, response) = form(&app, path, &[], Some(("backend", "aacs_wrong"))).await;
    assert_eq!((status, error(&response)), (401, "invalid_client"));

    let response = app
        .client
        .post(app.url(path))
        .basic_auth("backend", Some("aacs_wrong"))
        .form(&[("scope", "")])
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.headers()["www-authenticate"],
        "Basic realm=\"auth-api\""
    );

    let (status, response) = form(&app, path, &[], Some(("backend", &secret))).await;
    assert_eq!(status, 200, "{response}");
    let (status, response) = form(
        &app,
        path,
        &[("client_id", "backend"), ("client_secret", &secret)],
        None,
    )
    .await;
    assert_eq!(status, 200, "{response}");

    let (status, response) = form(
        &app,
        path,
        &[("client_secret", &secret)],
        Some(("backend", &secret)),
    )
    .await;
    assert_eq!((status, error(&response)), (400, "invalid_request"));

    // The poll authenticates too.
    let device_code = response["device_code"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let (status, response) = form(
        &app,
        "/oauth/token",
        &[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", &device_code),
            ("client_id", "backend"),
        ],
        None,
    )
    .await;
    assert_eq!((status, error(&response)), (401, "invalid_client"));
}

#[tokio::test]
async fn a_public_client_has_no_secret_to_present() {
    let app = TestApp::spawn().await;
    register(&app).await;
    let admin = admin(&app, 1).await;
    let secret = secret_for(&app, &admin.token).await;

    let response = app
        .client
        .delete(app.url("/admin/clients/backend/secret"))
        .bearer_auth(&admin.token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 204);

    let path = "/oauth/device_authorization";
    let (status, response) = form(&app, path, &[], Some(("backend", &secret))).await;
    assert_eq!((status, error(&response)), (401, "invalid_client"));
    let (status, _) = form(&app, path, &[("client_id", "backend")], None).await;
    assert_eq!(status, 200);

    let (status, _) = body(
        app.client
            .post(app.url("/admin/clients/nobody/secret"))
            .bearer_auth(&admin.token)
            .json(&json!({}))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, 404);

    let rotations: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'client_secret_rotated'")
            .fetch_one(&app.db)
            .await
            .unwrap();
    assert_eq!(rotations, 2);
}

#[tokio::test]
async fn unsupported_grants_and_malformed_requests_are_named() {
    let app = TestApp::spawn().await;
    register(&app).await;

    let (status, response) = form(&app, "/oauth/token", &[("grant_type", "password")], None).await;
    assert_eq!((status, error(&response)), (400, "unsupported_grant_type"));
    let (status, response) = form(&app, "/oauth/token", &[], None).await;
    assert_eq!((status, error(&response)), (400, "invalid_request"));

    let response = app
        .client
        .post(app.url("/oauth/token"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("grant_type=refresh_token&grant_type=refresh_token")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let body: Value = response.json().await.unwrap();
    assert_eq!(error(&body), "invalid_request");

    let (status, response) = form(
        &app,
        "/oauth/token",
        &[
            ("grant_type", "authorization_code"),
            ("client_id", "backend"),
        ],
        None,
    )
    .await;
    assert_eq!((status, error(&response)), (400, "invalid_request"));
    assert!(
        response["error_description"]
            .as_str()
            .unwrap()
            .ends_with("is required")
    );
}
