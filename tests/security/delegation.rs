//! Delegated tokens (SEC-42): a token issued to a client application or
//! obtained from a personal access token acts within what was granted to it,
//! never as the account itself.
//!
//! Before the control, such a token reached every account route, and could
//! approve on its own a device flow of the instance's application: a new,
//! unrestricted session carrying every role of the account, administration
//! included.

use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use utoipa::OpenApi;
use uuid::Uuid;

use crate::common::{
    app::TestApp,
    fixtures::{self, AuthenticatedUser},
};

async fn register_client(app: &TestApp, client_id: &str, is_primary: bool) {
    sqlx::query(
        "INSERT INTO registered_clients (client_id, display_name, is_primary, default_max_sessions)
         VALUES ($1, $1, $2, 5)",
    )
    .bind(client_id)
    .bind(is_primary)
    .execute(&app.db)
    .await
    .unwrap();
}

async fn form(app: &TestApp, path: &str, parameters: &[(&str, &str)]) -> (StatusCode, Value) {
    let response = app
        .client
        .post(app.url(path))
        .form(parameters)
        .send()
        .await
        .unwrap();
    let status = response.status();
    (status, response.json().await.unwrap_or(Value::Null))
}

/// Start a device flow for `client_id`: `(device_code, user_code)`.
async fn start_device_flow(app: &TestApp, client_id: &str) -> (String, String) {
    let (status, body) = form(
        app,
        "/oauth/device_authorization",
        &[("client_id", client_id)],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    (
        body["device_code"].as_str().unwrap().to_owned(),
        body["user_code"].as_str().unwrap().to_owned(),
    )
}

async fn poll(app: &TestApp, device_code: &str, client_id: &str) -> (StatusCode, Value) {
    form(
        app,
        "/oauth/token",
        &[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", device_code),
            ("client_id", client_id),
        ],
    )
    .await
}

async fn approve(app: &TestApp, access_token: &str, body: Value) -> (StatusCode, Value) {
    let response = app
        .post_auth("/oauth/device/verify", access_token, &body)
        .await;
    let status = response.status();
    (status, response.json().await.unwrap_or(Value::Null))
}

/// An access token of a device session of `client_id`, approved by `user`.
async fn client_session(app: &TestApp, user: &AuthenticatedUser, client_id: &str) -> String {
    let (device_code, user_code) = start_device_flow(app, client_id).await;
    let (status, body) = approve(
        app,
        &user.access_token,
        json!({ "user_code": user_code, "current_password": user.password }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = poll(app, &device_code, client_id).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["access_token"].as_str().unwrap().to_owned()
}

/// An access token exchanged from a personal access token of `user`.
async fn personal_access_session(app: &TestApp, user: &AuthenticatedUser) -> String {
    let created: Value = app
        .post_auth(
            "/users/me/tokens",
            &user.access_token,
            &json!({ "name": "script" }),
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
    exchanged["access_token"].as_str().unwrap().to_owned()
}

/// Every documented operation reserved to first-party sessions.
fn first_party_operations() -> Vec<(Method, String)> {
    let document = serde_json::to_value(auth_api::openapi::ApiDoc::openapi()).unwrap();
    let mut operations = Vec::new();
    for (template, item) in document["paths"].as_object().unwrap() {
        if !auth_api::openapi::requires_first_party(template) {
            continue;
        }
        for method in item.as_object().unwrap().keys() {
            if let Ok(method) = method.to_ascii_uppercase().parse::<Method>() {
                operations.push((method, template.clone()));
            }
        }
    }
    assert!(operations.len() >= 50, "found {}", operations.len());
    operations
}

fn concrete(template: &str) -> String {
    template
        .split('/')
        .map(|segment| match segment {
            "{user_code}" => "ABCD-2345".to_owned(),
            s if s.starts_with('{') => Uuid::new_v4().to_string(),
            s => s.to_owned(),
        })
        .collect::<Vec<_>>()
        .join("/")
}

async fn assert_refused_as_delegated(app: &TestApp, label: &str, token: &str) {
    for (method, template) in first_party_operations() {
        let mut request = app
            .client
            .request(method.clone(), app.url(&concrete(&template)))
            .bearer_auth(token);
        if method != Method::GET {
            request = request.json(&json!({}));
        }
        let response = request.send().await.unwrap();
        let status = response.status();
        let body: Value = response.json().await.unwrap_or(Value::Null);
        assert_eq!(
            (status, body["code"].as_str()),
            (StatusCode::FORBIDDEN, Some("first_party_session_required")),
            "{method} {template} answered {label} with {status} {body}"
        );
    }
}

#[tokio::test]
async fn delegated_tokens_are_refused_on_every_account_approval_and_admin_route() {
    let app = TestApp::spawn().await;
    register_client(&app, "third-party", false).await;
    let user = fixtures::authenticated_user(&app, 0).await;

    let client_token = client_session(&app, &user, "third-party").await;
    assert_refused_as_delegated(&app, "a third-party client token", &client_token).await;

    let pat_token = personal_access_session(&app, &user).await;
    assert_refused_as_delegated(&app, "a personal access token", &pat_token).await;
}

#[tokio::test]
async fn a_delegated_token_cannot_approve_itself_an_unrestricted_session() {
    let app = TestApp::spawn().await;
    register_client(&app, "primary-app", true).await;
    register_client(&app, "third-party", false).await;
    let user = fixtures::authenticated_user(&app, 1).await;
    let delegated = client_session(&app, &user, "third-party").await;

    // The chain of the finding: a flow of the instance's own application,
    // approved with the delegated token, polled for a full session.
    let (device_code, user_code) = start_device_flow(&app, "primary-app").await;
    let (status, body) = approve(&app, &delegated, json!({ "user_code": user_code })).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "first_party_session_required");

    let (status, body) = poll(&app, &device_code, "primary-app").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "authorization_pending", "{body}");
}

#[tokio::test]
async fn delegated_tokens_keep_the_routes_meant_for_clients() {
    let app = TestApp::spawn().await;
    register_client(&app, "third-party", false).await;
    let user = fixtures::authenticated_user(&app, 2).await;
    let delegated = client_session(&app, &user, "third-party").await;

    let response = app.post_auth("/auth/logout", &delegated, &json!({})).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn the_instance_application_without_scopes_acts_as_the_account() {
    let app = TestApp::spawn().await;
    register_client(&app, "primary-app", true).await;
    let user = fixtures::authenticated_user(&app, 3).await;
    let token = client_session(&app, &user, "primary-app").await;

    let response = app.get_auth("/users/me", &token).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn approving_another_client_needs_a_recent_reauthentication() {
    let app = TestApp::spawn().await;
    register_client(&app, "primary-app", true).await;
    register_client(&app, "third-party", false).await;
    let user = fixtures::authenticated_user(&app, 4).await;
    app.clear_recent_reauth(&user.access_token).await;

    let (_, user_code) = start_device_flow(&app, "third-party").await;
    let preview: Value = app
        .get_auth(&format!("/oauth/device/{user_code}"), &user.access_token)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(preview["reauthentication_required"], true);

    let (status, body) = approve(&app, &user.access_token, json!({ "user_code": user_code })).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "reauthentication_required");

    let (status, body) = approve(
        &app,
        &user.access_token,
        json!({ "user_code": user_code, "current_password": user.password }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // The instance's own application too: a code handed over by someone
    // else is how a device flow is phished (SEC-62).
    app.clear_recent_reauth(&user.access_token).await;
    let (_, user_code) = start_device_flow(&app, "primary-app").await;
    let (status, body) = approve(&app, &user.access_token, json!({ "user_code": user_code })).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, body) = approve(
        &app,
        &user.access_token,
        json!({ "user_code": user_code, "current_password": user.password }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// The approval screen of a device says how much of the account it would get,
/// like the consent of the authorization code flow (SEC-62).
#[tokio::test]
async fn the_device_approval_screen_shows_what_it_grants() {
    let app = TestApp::spawn().await;
    register_client(&app, "primary-app", true).await;
    sqlx::query(
        "INSERT INTO registered_clients (client_id, display_name, is_primary, default_max_sessions, scopes)
         VALUES ('reporting', 'reporting', FALSE, 5, ARRAY['users:read'])",
    )
    .execute(&app.db)
    .await
    .unwrap();
    let user = fixtures::authenticated_user(&app, 5).await;

    let (_, user_code) = start_device_flow(&app, "primary-app").await;
    let preview: Value = app
        .get_auth(&format!("/oauth/device/{user_code}"), &user.access_token)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(preview["unrestricted"], true, "{preview}");

    let (status, body) = form(
        &app,
        "/oauth/device_authorization",
        &[("client_id", "reporting"), ("scope", "users:read")],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let preview: Value = app
        .get_auth(
            &format!("/oauth/device/{}", body["user_code"].as_str().unwrap()),
            &user.access_token,
        )
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(preview["unrestricted"], false, "{preview}");
    assert_eq!(preview["unavailable_scopes"], json!(["users:read"]));
}

/// A public client is only named: a flood naming it from other addresses does
/// not spend the budget of its users (SEC-62).
#[tokio::test]
async fn a_public_clients_budget_is_split_by_address() {
    use deadpool_redis::redis::AsyncCommands;

    let app = TestApp::spawn().await;
    register_client(&app, "public-app", false).await;
    let mut conn = app.redis.get().await.unwrap();
    let _: () = conn
        .set_ex("oauth_client_rpm:public-app", 1_000_000, 60)
        .await
        .unwrap();

    let (status, body) = form(
        &app,
        "/oauth/device_authorization",
        &[("client_id", "public-app")],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// A device's consent is what the user held when approving: a permission the
/// user obtains later does not reach the device without a new consent
/// (SEC-72).
#[tokio::test]
async fn a_device_consent_is_frozen_at_the_approval() {
    let app = TestApp::spawn().await;
    sqlx::query(
        "INSERT INTO registered_clients (client_id, display_name, is_primary, default_max_sessions, scopes)
         VALUES ('reporting', 'reporting', FALSE, 5, ARRAY['users:read'])",
    )
    .execute(&app.db)
    .await
    .unwrap();
    let user = fixtures::authenticated_user(&app, 6).await;

    let (status, started) = form(
        &app,
        "/oauth/device_authorization",
        &[("client_id", "reporting"), ("scope", "users:read")],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{started}");
    let (status, body) = approve(
        &app,
        &user.access_token,
        json!({ "user_code": started["user_code"], "current_password": user.password }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = poll(&app, started["device_code"].as_str().unwrap(), "reporting").await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let scopes: Vec<String> = sqlx::query_scalar(
        "SELECT scopes FROM sessions WHERE user_id = $1 AND client_id = 'reporting'",
    )
    .bind(user.id)
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert!(
        scopes.is_empty(),
        "consented beyond what the user held: {scopes:?}"
    );
}
