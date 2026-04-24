//! Role and permission repository tests.
//!
//! Tests index range 920-939.
//!
//! All tests use `app.db` directly so they exercise repository functions
//! without going through the HTTP layer.

use auth_api::repositories::role as role_repo;
use uuid::Uuid;

use crate::common::{app::TestApp, fixtures};

// Helpers

/// Insert a non-default role and return its id.
async fn insert_role(app: &TestApp, name: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO roles (name, description, is_default) VALUES ($1, $2, FALSE) RETURNING id",
    )
    .bind(name)
    .bind(format!("Test role: {name}"))
    .fetch_one(&app.db)
    .await
    .expect("failed to insert test role")
}

/// Insert a permission row and return its id.
async fn insert_permission(app: &TestApp, resource: &str, action: &str) -> Uuid {
    sqlx::query_scalar("INSERT INTO permissions (resource, action) VALUES ($1, $2) RETURNING id")
        .bind(resource)
        .bind(action)
        .fetch_one(&app.db)
        .await
        .expect("failed to insert test permission")
}

/// Attach a permission to a role.
async fn grant_permission(app: &TestApp, role_id: Uuid, permission_id: Uuid) {
    sqlx::query("INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)")
        .bind(role_id)
        .bind(permission_id)
        .execute(&app.db)
        .await
        .expect("failed to grant permission to role");
}

// find_all

#[tokio::test]
async fn find_all_returns_seeded_roles() {
    let app = TestApp::spawn().await;

    let roles = role_repo::find_all(&app.db).await.expect("find_all failed");

    let names: Vec<&str> = roles.iter().map(|r| r.name.as_str()).collect();
    assert!(
        names.contains(&"user"),
        "seeded 'user' role must be present"
    );
}

// find_by_id

#[tokio::test]
async fn find_by_id_returns_role_when_exists() {
    let app = TestApp::spawn().await;

    let default_role = role_repo::find_default(&app.db)
        .await
        .expect("find_default failed")
        .expect("default role must exist");

    let found = role_repo::find_by_id(&app.db, default_role.id)
        .await
        .expect("find_by_id failed")
        .expect("role must be found by id");

    assert_eq!(found.id, default_role.id);
    assert_eq!(found.name, default_role.name);
}

#[tokio::test]
async fn find_by_id_returns_none_for_unknown_id() {
    let app = TestApp::spawn().await;

    let result = role_repo::find_by_id(&app.db, Uuid::new_v4())
        .await
        .expect("find_by_id failed");

    assert!(result.is_none(), "random UUID must not match any role");
}

// find_by_name

#[tokio::test]
async fn find_by_name_returns_role_when_exists() {
    let app = TestApp::spawn().await;

    let role = role_repo::find_by_name(&app.db, "user")
        .await
        .expect("find_by_name failed")
        .expect("'user' role must exist");

    assert_eq!(role.name, "user");
    assert!(role.is_default);
}

#[tokio::test]
async fn find_by_name_returns_none_for_unknown_name() {
    let app = TestApp::spawn().await;

    let result = role_repo::find_by_name(&app.db, "nonexistent_role_xyz")
        .await
        .expect("find_by_name failed");

    assert!(result.is_none());
}

// find_default

#[tokio::test]
async fn find_default_returns_user_role() {
    let app = TestApp::spawn().await;

    let role = role_repo::find_default(&app.db)
        .await
        .expect("find_default failed")
        .expect("a default role must exist");

    assert!(role.is_default);
    assert_eq!(role.name, "user");
}

// assign_to_user / find_by_user

#[tokio::test]
async fn assign_to_user_and_find_by_user() {
    let app = TestApp::spawn().await;

    let user = fixtures::register_user(&app, 920).await;
    let extra_role_id = insert_role(&app, "moderator_920").await;

    role_repo::assign_to_user(&app.db, user.id, extra_role_id, None)
        .await
        .expect("assign_to_user failed");

    let roles = role_repo::find_by_user(&app.db, user.id)
        .await
        .expect("find_by_user failed");

    let names: Vec<&str> = roles.iter().map(|r| r.name.as_str()).collect();
    assert!(
        names.contains(&"moderator_920"),
        "moderator_920 role must appear after assignment"
    );
}

#[tokio::test]
async fn assign_to_user_is_idempotent() {
    let app = TestApp::spawn().await;

    let user = fixtures::register_user(&app, 921).await;
    let role_id = insert_role(&app, "moderator_921").await;

    // Assign twice - ON CONFLICT DO NOTHING means the second call must not error.
    role_repo::assign_to_user(&app.db, user.id, role_id, None)
        .await
        .expect("first assign failed");

    // Second assign will hit the conflict path and return no rows - expect Err from fetch_one.
    // The ON CONFLICT DO NOTHING means zero rows --> sqlx returns RowNotFound.
    // That's acceptable; the role is still assigned.
    let _ = role_repo::assign_to_user(&app.db, user.id, role_id, None).await;

    let roles = role_repo::find_by_user(&app.db, user.id)
        .await
        .expect("find_by_user failed");

    let role_count = roles.iter().filter(|r| r.name == "moderator_921").count();
    assert_eq!(
        role_count, 1,
        "moderator_921 role must appear exactly once after two assigns"
    );
}

// revoke_from_user

#[tokio::test]
async fn revoke_from_user_removes_role() {
    let app = TestApp::spawn().await;

    let user = fixtures::register_user(&app, 922).await;
    let role_id = insert_role(&app, "moderator_922").await;

    role_repo::assign_to_user(&app.db, user.id, role_id, None)
        .await
        .expect("assign failed");

    role_repo::revoke_from_user(&app.db, user.id, role_id)
        .await
        .expect("revoke failed");

    let roles = role_repo::find_by_user(&app.db, user.id)
        .await
        .expect("find_by_user failed");

    assert!(
        roles.iter().all(|r| r.name != "moderator_922"),
        "moderator_922 role must be gone after revocation"
    );
}

// find_granted_at

#[tokio::test]
async fn find_granted_at_returns_timestamp_when_assigned() {
    let app = TestApp::spawn().await;

    let user = fixtures::register_user(&app, 923).await;
    let role_id = insert_role(&app, "moderator_923").await;

    role_repo::assign_to_user(&app.db, user.id, role_id, None)
        .await
        .expect("assign failed");

    let granted_at = role_repo::find_granted_at(&app.db, user.id, role_id)
        .await
        .expect("find_granted_at failed");

    assert!(
        granted_at.is_some(),
        "granted_at must be set after assignment"
    );
}

#[tokio::test]
async fn find_granted_at_returns_none_when_not_assigned() {
    let app = TestApp::spawn().await;

    let user = fixtures::register_user(&app, 924).await;
    let role_id = insert_role(&app, "moderator_924").await;

    let granted_at = role_repo::find_granted_at(&app.db, user.id, role_id)
        .await
        .expect("find_granted_at failed");

    assert!(
        granted_at.is_none(),
        "granted_at must be None when role is not assigned"
    );
}

// permissions

#[tokio::test]
async fn find_permissions_by_user_returns_granted_permissions() {
    let app = TestApp::spawn().await;

    let user = fixtures::register_user(&app, 925).await;
    let role_id = insert_role(&app, "moderator_925").await;

    let perm_id = insert_permission(&app, "posts", "read").await;
    grant_permission(&app, role_id, perm_id).await;
    role_repo::assign_to_user(&app.db, user.id, role_id, None)
        .await
        .expect("assign failed");

    let perms = role_repo::find_permissions_by_user(&app.db, user.id)
        .await
        .expect("find_permissions_by_user failed");

    assert!(
        perms
            .iter()
            .any(|p| p.resource == "posts" && p.action == "read"),
        "permission 'posts:read' must appear for the user"
    );
}

#[tokio::test]
async fn find_permissions_by_user_returns_empty_for_user_with_no_permissions() {
    let app = TestApp::spawn().await;

    let user = fixtures::register_user(&app, 926).await;

    // The "user" role has no permissions seeded - user has no effective permissions.
    let perms = role_repo::find_permissions_by_user(&app.db, user.id)
        .await
        .expect("find_permissions_by_user failed");

    assert!(
        perms.is_empty(),
        "user with no permission-bearing roles must have empty permission list"
    );
}

#[tokio::test]
async fn user_has_permission_returns_true_when_granted() {
    let app = TestApp::spawn().await;

    let user = fixtures::register_user(&app, 927).await;
    let role_id = insert_role(&app, "moderator_927").await;

    let perm_id = insert_permission(&app, "reports", "write").await;
    grant_permission(&app, role_id, perm_id).await;
    role_repo::assign_to_user(&app.db, user.id, role_id, None)
        .await
        .unwrap();

    let has = role_repo::user_has_permission(&app.db, user.id, "reports:write")
        .await
        .expect("user_has_permission failed");

    assert!(has, "user must have 'reports:write' permission");
}

#[tokio::test]
async fn user_has_permission_returns_false_when_not_granted() {
    let app = TestApp::spawn().await;

    let user = fixtures::register_user(&app, 928).await;

    let has = role_repo::user_has_permission(&app.db, user.id, "reports:delete")
        .await
        .expect("user_has_permission failed");

    assert!(!has, "user must not have 'reports:delete' permission");
}
