//! Administrative privileges (SEC-59): no administrator grants themselves
//! permissions, pushes the others out, or acts unnoticed with a stolen token.

use reqwest::Method;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{Admin, admin, body, enroll_second_factor, prove_second_factor, token_with};
use crate::common::{app::TestApp, fixtures};

async fn send(app: &TestApp, method: Method, path: &str, token: &str, json: Value) -> (u16, Value) {
    body(
        app.client
            .request(method, app.url(path))
            .bearer_auth(token)
            .json(&json)
            .send()
            .await
            .unwrap(),
    )
    .await
}

/// An administrator holding only `roles:manage`, through a role of its own.
async fn role_manager(app: &TestApp, by: &Admin) -> (fixtures::AuthenticatedUser, String) {
    let (status, created) = send(
        app,
        Method::POST,
        "/admin/roles",
        &by.token,
        json!({ "name": "support", "permissions": ["roles:manage"] }),
    )
    .await;
    assert_eq!(status, 201, "{created}");
    let manager = fixtures::authenticated_user(app, 30).await;
    enroll_second_factor(app, manager.id).await;
    let (status, granted) = send(
        app,
        Method::POST,
        &format!("/admin/users/{}/roles", manager.id),
        &by.token,
        json!({ "role": "support" }),
    )
    .await;
    assert_eq!(status, 204, "{granted}");
    prove_second_factor(app, &manager).await;
    let token = token_with(app, &manager, &["roles:manage"]);
    (manager, token)
}

#[tokio::test]
async fn nobody_adds_to_a_role_they_hold_a_permission_they_lack() {
    let app = TestApp::spawn().await;
    let admin = admin(&app, 1).await;
    let (_, token) = role_manager(&app, &admin).await;

    let (status, _) = send(
        &app,
        Method::PUT,
        "/admin/roles/support/permissions",
        &token,
        json!({ "permissions": ["roles:manage", "users:manage", "audit:read"] }),
    )
    .await;
    assert_eq!(
        status, 403,
        "a role manager cannot make themselves a full administrator"
    );
}

#[tokio::test]
async fn the_default_role_never_grants_administration() {
    let app = TestApp::spawn().await;
    let admin = admin(&app, 1).await;
    let (status, response) = send(
        &app,
        Method::PUT,
        "/admin/roles/user/permissions",
        &admin.token,
        json!({ "permissions": ["users:read"] }),
    )
    .await;
    assert_eq!(
        (status, response["code"].as_str()),
        (409, Some("default_role_administration"))
    );
}

#[tokio::test]
async fn actions_that_push_out_or_reopen_need_a_recent_reauthentication() {
    let app = TestApp::spawn().await;
    let admin = admin(&app, 1).await;
    let (status, _) = send(
        &app,
        Method::POST,
        "/admin/roles",
        &admin.token,
        json!({ "name": "doomed", "permissions": [] }),
    )
    .await;
    assert_eq!(status, 201);
    let other = fixtures::authenticated_user(&app, 2).await;
    app.clear_recent_reauth(&admin.token).await;

    let id = Uuid::new_v4();
    for (method, path) in [
        (
            Method::DELETE,
            format!("/admin/users/{}/roles/admin", other.id),
        ),
        (Method::DELETE, "/admin/roles/doomed".to_owned()),
        (Method::POST, format!("/admin/users/{}/unlock", other.id)),
        (
            Method::POST,
            format!("/admin/users/{}/reactivate", other.id),
        ),
        (Method::DELETE, "/admin/clients/some-client".to_owned()),
        (Method::DELETE, format!("/admin/webhooks/{id}")),
        (
            Method::POST,
            format!("/admin/webhooks/{id}/deliveries/{id}/retry"),
        ),
    ] {
        let (status, response) = send(&app, method.clone(), &path, &admin.token, json!({})).await;
        assert_eq!(
            (status, response["code"].as_str()),
            (403, Some("reauthentication_required")),
            "{method} {path}"
        );
    }
}

#[tokio::test]
async fn an_administrator_cannot_unlock_their_own_account() {
    let app = TestApp::spawn().await;
    let admin = admin(&app, 1).await;
    let (status, _) = send(
        &app,
        Method::POST,
        &format!("/admin/users/{}/unlock", admin.user.id),
        &admin.token,
        json!({}),
    )
    .await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn the_owner_hears_of_what_an_administrator_changed() {
    let app = TestApp::spawn().await;
    let admin = admin(&app, 1).await;
    let target = fixtures::authenticated_user(&app, 2).await;

    let (status, _) = send(
        &app,
        Method::POST,
        &format!("/admin/users/{}/suspend", target.id),
        &admin.token,
        json!({}),
    )
    .await;
    assert_eq!(status, 204);
    let mail = app
        .mail
        .wait_for(&target.email, "An administrator changed your account")
        .await;
    assert!(mail.html.contains("suspended"), "{}", mail.html);
}

#[tokio::test]
async fn deleting_a_role_leaves_a_trace_in_each_holders_history() {
    let app = TestApp::spawn().await;
    let admin = admin(&app, 1).await;
    let (manager, _) = role_manager(&app, &admin).await;

    let (status, _) = send(
        &app,
        Method::DELETE,
        "/admin/roles/support",
        &admin.token,
        json!({}),
    )
    .await;
    assert_eq!(status, 204);
    let revoked: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE user_id = $1 AND action = 'role_revoked'
           AND metadata->>'role' = 'support'",
    )
    .bind(manager.id)
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert_eq!(revoked, 1);
}

#[tokio::test]
async fn an_administrator_keeps_a_second_factor() {
    let app = TestApp::spawn().await;
    let admin = admin(&app, 1).await;
    let method: Uuid = sqlx::query_scalar("SELECT id FROM two_factor_methods WHERE user_id = $1")
        .bind(admin.user.id)
        .fetch_one(&app.db)
        .await
        .unwrap();

    let (status, response) = send(
        &app,
        Method::DELETE,
        &format!("/users/me/two-factor/email/{method}"),
        &admin.user.access_token,
        json!({ "current_password": admin.user.password }),
    )
    .await;
    assert_eq!(
        (status, response["code"].as_str()),
        (409, Some("administrator_needs_second_factor"))
    );
}
