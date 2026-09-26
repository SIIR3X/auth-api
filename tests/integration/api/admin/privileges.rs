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

/// An administrator can remove what someone who knew the password may have
/// added; the owner is told (SEC-69).
#[tokio::test]
async fn an_administrator_removes_the_ways_in_of_a_compromised_account() {
    let app = TestApp::spawn().await;
    let admin = admin(&app, 1).await;
    let target = fixtures::authenticated_user(&app, 2).await;
    enroll_second_factor(&app, target.id).await;

    let (status, response) = send(
        &app,
        Method::DELETE,
        &format!("/admin/users/{}/access-factors", target.id),
        &admin.token,
        json!({}),
    )
    .await;
    assert_eq!(status, 204, "{response}");
    let methods: i64 =
        sqlx::query_scalar("SELECT count(*) FROM two_factor_methods WHERE user_id = $1")
            .bind(target.id)
            .fetch_one(&app.db)
            .await
            .unwrap();
    assert_eq!(methods, 0);
    // Every session goes, the browser one included: whoever planted a factor
    // may be signed in through it.
    let me = app
        .client
        .get(app.url("/users/me"))
        .bearer_auth(&target.access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(me.status(), 401);
    app.mail
        .wait_for(&target.email, "An administrator changed your account")
        .await;

    // An administrator's own second factor stays.
    let other = admin_with_index(&app, 3).await;
    let (status, response) = send(
        &app,
        Method::DELETE,
        &format!("/admin/users/{}/access-factors", other.user.id),
        &admin.token,
        json!({}),
    )
    .await;
    assert_eq!(
        (status, response["code"].as_str()),
        (409, Some("administrator_needs_second_factor"))
    );
}

async fn admin_with_index(app: &TestApp, index: usize) -> Admin {
    admin(app, index).await
}

/// Nobody grants a permission they do not hold, to any role: a role manager
/// cannot create or extend a role with more than they have (SEC-70).
#[tokio::test]
async fn nobody_grants_a_permission_they_lack() {
    let app = TestApp::spawn().await;
    let admin = admin(&app, 1).await;
    let (_, token) = role_manager(&app, &admin).await;

    let (status, _) = send(
        &app,
        Method::POST,
        "/admin/roles",
        &token,
        json!({ "name": "superadmin", "permissions": ["roles:manage", "users:manage"] }),
    )
    .await;
    assert_eq!(status, 403);
    let (status, _) = send(
        &app,
        Method::POST,
        "/admin/roles",
        &admin.token,
        json!({ "name": "empty", "permissions": [] }),
    )
    .await;
    assert_eq!(status, 201);
    let (status, _) = send(
        &app,
        Method::PUT,
        "/admin/roles/empty/permissions",
        &token,
        json!({ "permissions": ["audit:read"] }),
    )
    .await;
    assert_eq!(
        status, 403,
        "a role the manager does not hold is no exception"
    );
}

/// A forced reset leaves no trace of the administrator's address in the link
/// the owner exports, and a client change is audited as a diff (SEC-70).
#[tokio::test]
async fn administrative_traces_describe_the_change_not_the_administrator() {
    let app = TestApp::spawn().await;
    let admin = admin(&app, 1).await;
    let target = fixtures::authenticated_user(&app, 2).await;
    let (status, _) = send(
        &app,
        Method::POST,
        &format!("/admin/users/{}/password-reset", target.id),
        &admin.token,
        json!({}),
    )
    .await;
    assert_eq!(status, 204);
    let addresses: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM password_reset_tokens WHERE user_id = $1 AND request_ip IS NOT NULL",
    )
    .bind(target.id)
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert_eq!(addresses, 0);

    for uri in ["https://one.example.com/cb", "https://two.example.com/cb"] {
        let (status, body) = send(
            &app,
            Method::PUT,
            "/admin/clients/audited-app",
            &admin.token,
            json!({ "display_name": "Audited", "redirect_uris": [uri], "unrestricted": true }),
        )
        .await;
        assert!(status == 200 || status == 201, "{status} {body}");
    }
    let changes: Value = sqlx::query_scalar(
        "SELECT metadata->'changes' FROM audit_log WHERE action = 'client_updated'
         ORDER BY created_at DESC LIMIT 1",
    )
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert_eq!(
        changes["redirect_hosts"],
        json!({ "before": ["one.example.com"], "after": ["two.example.com"] })
    );
}

/// Granting or withdrawing a role delegates every permission it holds: a
/// role manager can neither hand `admin` to an account they control nor
/// strip it, or a permission of it, from anyone (SEC-74).
#[tokio::test]
async fn nobody_grants_or_withdraws_a_role_holding_more_than_they_have() {
    let app = TestApp::spawn().await;
    let admin = admin(&app, 1).await;
    let (_, token) = role_manager(&app, &admin).await;
    let puppet = fixtures::authenticated_user(&app, 31).await;
    enroll_second_factor(&app, puppet.id).await;

    let (status, _) = send(
        &app,
        Method::POST,
        &format!("/admin/users/{}/roles", puppet.id),
        &token,
        json!({ "role": "admin" }),
    )
    .await;
    assert_eq!(status, 403, "admin goes to no puppet");
    let (status, _) = send(
        &app,
        Method::DELETE,
        &format!("/admin/users/{}/roles/admin", admin.user.id),
        &token,
        json!({}),
    )
    .await;
    assert_eq!(status, 403, "nor is it taken from a greater administrator");
    let (status, _) = send(
        &app,
        Method::PUT,
        "/admin/roles/admin/permissions",
        &token,
        json!({ "permissions": ["roles:manage"] }),
    )
    .await;
    assert_eq!(status, 403, "nor emptied of what the manager lacks");
    let (status, _) = send(
        &app,
        Method::DELETE,
        "/admin/roles/admin",
        &token,
        json!({}),
    )
    .await;
    assert_eq!(status, 403, "nor deleted");

    // What the manager holds stays theirs to delegate.
    let (status, response) = send(
        &app,
        Method::POST,
        &format!("/admin/users/{}/roles", puppet.id),
        &token,
        json!({ "role": "support" }),
    )
    .await;
    assert_eq!(status, 204, "{response}");
    let (status, response) = send(
        &app,
        Method::DELETE,
        &format!("/admin/users/{}/roles/support", puppet.id),
        &token,
        json!({}),
    )
    .await;
    assert_eq!(status, 204, "{response}");
}

/// A forced reset asking for the access factors to go is one change: refused
/// for an administrator's last second factor, it revokes nothing (SEC-75).
#[tokio::test]
async fn a_refused_forced_reset_revokes_nothing() {
    let app = TestApp::spawn().await;
    let admin = admin(&app, 1).await;
    let other = admin_with_index(&app, 3).await;

    let (status, response) = send(
        &app,
        Method::POST,
        &format!("/admin/users/{}/password-reset", other.user.id),
        &admin.token,
        json!({ "revoke_access_factors": true }),
    )
    .await;
    assert_eq!(
        (status, response["code"].as_str()),
        (409, Some("administrator_needs_second_factor"))
    );
    let me = app
        .client
        .get(app.url("/users/me"))
        .bearer_auth(&other.token)
        .send()
        .await
        .unwrap();
    assert_eq!(me.status(), 200, "the sessions stay");
}

/// A role gaining administration makes administrators of its holders: each
/// must have a second factor, is audited and told (SEC-82).
#[tokio::test]
async fn a_role_grants_administration_only_to_holders_with_a_second_factor() {
    let app = TestApp::spawn().await;
    let admin = admin(&app, 1).await;
    let (status, _) = send(
        &app,
        Method::POST,
        "/admin/roles",
        &admin.token,
        json!({ "name": "helpers", "permissions": [] }),
    )
    .await;
    assert_eq!(status, 201);
    let holder = fixtures::authenticated_user(&app, 32).await;
    let (status, _) = send(
        &app,
        Method::POST,
        &format!("/admin/users/{}/roles", holder.id),
        &admin.token,
        json!({ "role": "helpers" }),
    )
    .await;
    assert_eq!(status, 204);

    let extend = json!({ "permissions": ["users:read"] });
    let (status, response) = send(
        &app,
        Method::PUT,
        "/admin/roles/helpers/permissions",
        &admin.token,
        extend.clone(),
    )
    .await;
    assert_eq!(
        (status, response["code"].as_str()),
        (409, Some("holders_without_second_factor"))
    );

    enroll_second_factor(&app, holder.id).await;
    let (status, response) = send(
        &app,
        Method::PUT,
        "/admin/roles/helpers/permissions",
        &admin.token,
        extend,
    )
    .await;
    assert_eq!(status, 200, "{response}");
    let added: Value = sqlx::query_scalar(
        "SELECT metadata->'added' FROM audit_log
         WHERE user_id = $1 AND action = 'role_permissions_changed'",
    )
    .bind(holder.id)
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert_eq!(added, json!(["users:read"]));
}

/// The primary client is the command line's on every route: removing it or
/// changing how it authenticates is refused too (SEC-82).
#[tokio::test]
async fn the_primary_client_is_neither_removed_nor_rekeyed_over_http() {
    let app = TestApp::spawn().await;
    let admin = admin(&app, 1).await;
    sqlx::query(
        "INSERT INTO registered_clients (client_id, display_name, is_primary) VALUES ('own', 'Own', TRUE)",
    )
    .execute(&app.db)
    .await
    .unwrap();
    for (method, path) in [
        (Method::DELETE, "/admin/clients/own"),
        (Method::POST, "/admin/clients/own/secret"),
        (Method::DELETE, "/admin/clients/own/secret"),
    ] {
        let (status, response) = send(&app, method.clone(), path, &admin.token, json!({})).await;
        assert_eq!(
            (status, response["code"].as_str()),
            (409, Some("primary_client_managed_by_command_line")),
            "{method} {path}"
        );
    }
    let (status, _) = send(
        &app,
        Method::GET,
        &format!("/admin/webhooks/{}/deliveries", Uuid::new_v4()),
        &admin.token,
        json!({}),
    )
    .await;
    assert_eq!(status, 404, "an unknown webhook has no deliveries to list");
}
