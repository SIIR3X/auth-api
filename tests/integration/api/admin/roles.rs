//! `/admin/roles`, `/admin/permissions` and the roles of an account.

use reqwest::Method;
use serde_json::{Value, json};

use super::{admin, body, enroll_second_factor};
use crate::common::{app::TestApp, fixtures};

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

async fn permissions_of(app: &TestApp, user_id: uuid::Uuid) -> Vec<String> {
    let (_, permissions) = auth_api::repositories::role::find_rbac_names(&app.db, user_id)
        .await
        .unwrap();
    permissions
}

#[tokio::test]
async fn roles_and_permissions_are_listed() {
    let app = TestApp::spawn().await;
    let admin = admin(&app, 1).await;

    let (status, roles) = body(app.get_auth("/admin/roles", &admin.token).await).await;
    assert_eq!(status, 200, "{roles}");
    let admin_role = roles
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "admin")
        .unwrap();
    assert_eq!(admin_role["is_default"], false);
    assert!(
        admin_role["permissions"]
            .as_array()
            .unwrap()
            .contains(&json!("roles:manage"))
    );

    let (status, permissions) = body(app.get_auth("/admin/permissions", &admin.token).await).await;
    assert_eq!(status, 200);
    assert!(
        permissions
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "audit:read")
    );
}

#[tokio::test]
async fn a_role_is_created_granted_changed_taken_back_and_deleted() {
    let app = TestApp::spawn().await;
    let admin = admin(&app, 1).await;
    let member = fixtures::authenticated_user(&app, 2).await;
    enroll_second_factor(&app, member.id).await;

    let (status, created) = send(
        &app,
        Method::POST,
        "/admin/roles",
        &admin.token,
        json!({ "name": "support", "description": "Helpdesk", "permissions": ["users:read", "users:read"] }),
    )
    .await;
    assert_eq!(status, 201, "{created}");
    assert_eq!(created["permissions"], json!(["users:read"]));

    let (status, _) = send(
        &app,
        Method::POST,
        "/admin/roles",
        &admin.token,
        json!({ "name": "support" }),
    )
    .await;
    assert_eq!(status, 409);

    let path = format!("/admin/users/{}/roles", member.id);
    let (status, response) = send(
        &app,
        Method::POST,
        &path,
        &admin.token,
        json!({ "role": "support" }),
    )
    .await;
    assert_eq!(status, 204, "{response}");
    assert!(
        permissions_of(&app, member.id)
            .await
            .contains(&"users:read".to_owned())
    );

    let (status, changed) = send(
        &app,
        Method::PUT,
        "/admin/roles/support/permissions",
        &admin.token,
        json!({ "permissions": ["audit:read"] }),
    )
    .await;
    assert_eq!(status, 200, "{changed}");
    let now = permissions_of(&app, member.id).await;
    assert!(now.contains(&"audit:read".to_owned()) && !now.contains(&"users:read".to_owned()));

    let (status, _) = send(
        &app,
        Method::DELETE,
        &format!("{path}/support"),
        &admin.token,
        json!({}),
    )
    .await;
    assert_eq!(status, 204);
    assert!(
        !permissions_of(&app, member.id)
            .await
            .contains(&"audit:read".to_owned())
    );

    let (status, _) = send(
        &app,
        Method::DELETE,
        "/admin/roles/support",
        &admin.token,
        json!({}),
    )
    .await;
    assert_eq!(status, 204);
    let (status, _) = send(
        &app,
        Method::DELETE,
        "/admin/roles/support",
        &admin.token,
        json!({}),
    )
    .await;
    assert_eq!(status, 404);

    let recorded: Vec<String> = sqlx::query_scalar(
        "SELECT action::text FROM audit_log
         WHERE metadata->>'administrator_id' = $1 ORDER BY created_at, action::text",
    )
    .bind(admin.user.id.to_string())
    .fetch_all(&app.db)
    .await
    .unwrap();
    for action in [
        "role_created",
        "role_assigned",
        "role_permissions_changed",
        "role_revoked",
        "role_deleted",
    ] {
        assert!(
            recorded.contains(&action.to_owned()),
            "{action} missing from {recorded:?}"
        );
    }
}

#[tokio::test]
async fn invalid_names_and_unknown_permissions_are_refused() {
    let app = TestApp::spawn().await;
    let admin = admin(&app, 1).await;

    let (status, _) = send(
        &app,
        Method::POST,
        "/admin/roles",
        &admin.token,
        json!({ "name": "Support Team" }),
    )
    .await;
    assert_eq!(status, 422);
    let (status, response) = send(
        &app,
        Method::POST,
        "/admin/roles",
        &admin.token,
        json!({ "name": "support", "permissions": ["planets:destroy"] }),
    )
    .await;
    assert_eq!(status, 422);
    assert!(
        response["message"]
            .as_str()
            .unwrap()
            .contains("planets:destroy")
    );
}

#[tokio::test]
async fn nobody_can_remove_the_last_way_to_manage_roles_or_the_default_role() {
    let app = TestApp::spawn().await;
    let admin = admin(&app, 1).await;

    let (status, response) = send(
        &app,
        Method::DELETE,
        &format!("/admin/users/{}/roles/admin", admin.user.id),
        &admin.token,
        json!({}),
    )
    .await;
    assert_eq!(status, 409);
    assert_eq!(response["code"], "last_administrator");

    let (status, response) = send(
        &app,
        Method::PUT,
        "/admin/roles/admin/permissions",
        &admin.token,
        json!({ "permissions": ["users:read"] }),
    )
    .await;
    assert_eq!(status, 409);
    assert_eq!(response["code"], "last_administrator");

    let (status, response) = send(
        &app,
        Method::DELETE,
        "/admin/roles/admin",
        &admin.token,
        json!({}),
    )
    .await;
    assert_eq!(status, 409);
    assert_eq!(response["code"], "last_administrator");

    let (status, response) = send(
        &app,
        Method::DELETE,
        "/admin/roles/user",
        &admin.token,
        json!({}),
    )
    .await;
    assert_eq!(status, 409);
    assert_eq!(response["code"], "default_role");

    // With a second administrator, the first can step down.
    let other = fixtures::authenticated_user(&app, 2).await;
    enroll_second_factor(&app, other.id).await;
    let (status, _) = send(
        &app,
        Method::POST,
        &format!("/admin/users/{}/roles", other.id),
        &admin.token,
        json!({ "role": "admin" }),
    )
    .await;
    assert_eq!(status, 204);
    let (status, _) = send(
        &app,
        Method::DELETE,
        &format!("/admin/users/{}/roles/admin", admin.user.id),
        &admin.token,
        json!({}),
    )
    .await;
    assert_eq!(status, 204);
}

#[tokio::test]
async fn granting_a_role_needs_a_recent_reauthentication() {
    let app = TestApp::spawn().await;
    let admin = admin(&app, 1).await;
    let member = fixtures::authenticated_user(&app, 2).await;
    app.clear_recent_reauth(&admin.token).await;

    let (status, response) = send(
        &app,
        Method::POST,
        &format!("/admin/users/{}/roles", member.id),
        &admin.token,
        json!({ "role": "admin" }),
    )
    .await;
    assert_eq!(status, 403);
    assert_eq!(response["code"], "reauthentication_required");
    assert!(permissions_of(&app, member.id).await.is_empty());
}

#[tokio::test]
async fn an_administrative_role_goes_only_to_an_active_account_with_a_second_factor() {
    let app = TestApp::spawn().await;
    let admin = admin(&app, 1).await;
    let member = fixtures::authenticated_user(&app, 2).await;
    let path = format!("/admin/users/{}/roles", member.id);

    let (status, response) = send(
        &app,
        Method::POST,
        &path,
        &admin.token,
        json!({ "role": "admin" }),
    )
    .await;
    assert_eq!(status, 409, "{response}");
    assert_eq!(response["code"], "administrator_without_second_factor");

    // A role without administrative permission needs nothing.
    let (status, _) = send(
        &app,
        Method::POST,
        &path,
        &admin.token,
        json!({ "role": "user" }),
    )
    .await;
    assert_eq!(status, 204);

    enroll_second_factor(&app, member.id).await;
    let (status, response) = send(
        &app,
        Method::POST,
        &path,
        &admin.token,
        json!({ "role": "admin" }),
    )
    .await;
    assert_eq!(status, 204, "{response}");
}

#[tokio::test]
async fn an_administrator_never_grants_a_role_to_their_own_account() {
    let app = TestApp::spawn().await;
    let admin = admin(&app, 1).await;
    let (status, response) = send(
        &app,
        Method::POST,
        &format!("/admin/users/{}/roles", admin.user.id),
        &admin.token,
        json!({ "role": "user" }),
    )
    .await;
    assert_eq!(status, 403, "{response}");
}

/// An administrator holding `users:manage` only: enough to suspend or delete
/// accounts, not to manage roles.
async fn account_manager(app: &TestApp, index: usize) -> super::Admin {
    let user = fixtures::authenticated_user(app, index).await;
    let role_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO roles (name) VALUES ('account_manager')
         ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id",
    )
    .fetch_one(&app.db)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO role_permissions (role_id, permission_id)
         SELECT $1, id FROM permissions WHERE name = 'users:manage'
         ON CONFLICT DO NOTHING",
    )
    .bind(role_id)
    .execute(&app.db)
    .await
    .unwrap();
    sqlx::query("INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)")
        .bind(user.id)
        .bind(role_id)
        .execute(&app.db)
        .await
        .unwrap();
    super::enroll_second_factor(app, user.id).await;
    super::prove_second_factor(app, &user).await;
    let token = super::token_with(app, &user, &["users:manage"]);
    super::Admin { user, token }
}

#[tokio::test]
async fn the_last_role_manager_is_neither_suspended_nor_deleted() {
    let app = TestApp::spawn().await;
    let owner = admin(&app, 1).await;
    let manager = account_manager(&app, 2).await;

    for (method, path) in [
        (
            Method::POST,
            format!("/admin/users/{}/suspend", owner.user.id),
        ),
        (Method::DELETE, format!("/admin/users/{}", owner.user.id)),
    ] {
        let (status, response) = send(&app, method, &path, &manager.token, json!({})).await;
        assert_eq!(status, 409, "{path}: {response}");
        assert_eq!(response["code"], "last_administrator");
    }

    // Nor by the owner themselves.
    let (status, response) = send(
        &app,
        Method::DELETE,
        "/users/me",
        &owner.user.access_token,
        json!({ "current_password": owner.user.password }),
    )
    .await;
    assert_eq!(status, 409, "{response}");
    assert_eq!(response["code"], "last_administrator");

    // Anyone else goes as before.
    let (status, _) = send(
        &app,
        Method::DELETE,
        "/users/me",
        &manager.user.access_token,
        json!({ "current_password": manager.user.password }),
    )
    .await;
    assert_eq!(status, 204);
}

#[tokio::test]
async fn concurrent_withdrawals_never_leave_nobody_managing_roles() {
    let app = TestApp::spawn().await;
    let first = admin(&app, 1).await;
    let second = admin(&app, 2).await;

    let withdraw = |target: uuid::Uuid| {
        let app = &app;
        let token = first.token.clone();
        async move {
            send(
                app,
                Method::DELETE,
                &format!("/admin/users/{target}/roles/admin"),
                &token,
                json!({}),
            )
            .await
            .0
        }
    };
    let (a, b) = tokio::join!(withdraw(first.user.id), withdraw(second.user.id));
    let mut outcomes = [a, b];
    outcomes.sort();
    assert_eq!(outcomes, [204, 409], "one withdrawal must be refused");
    assert!(
        auth_api::repositories::role::permission_held(&app.db, "roles:manage")
            .await
            .unwrap()
    );
}
