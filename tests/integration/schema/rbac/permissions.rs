use testkit::TestDb;
use testkit::sql::{insert_permission, insert_user};

#[tokio::test]
async fn permissions_generate_name_from_resource_and_action() {
    let db = TestDb::new().await;

    let permission_id = insert_permission(&db.pool, "invoices", "read").await;
    let name: String =
        sqlx::query_scalar::<_, String>("SELECT name FROM permissions WHERE id = $1")
            .bind(permission_id)
            .fetch_one(&db.pool)
            .await
            .expect("failed to load generated permission name");

    assert_eq!(name, "invoices:read");
}

#[tokio::test]
async fn permissions_enforce_unique_resource_action_pairs() {
    let db = TestDb::new().await;

    insert_permission(&db.pool, "sessions", "revoke").await;

    let err = sqlx::query(
        "INSERT INTO permissions (resource, action)
             VALUES ($1, $2)",
    )
    .bind("sessions")
    .bind("revoke")
    .execute(&db.pool)
    .await
    .expect_err("duplicate permission pair should fail");

    testkit::sql::assert_constraint_error(&err, "permissions_resource_action_key");
}

#[tokio::test]
async fn user_roles_join_to_permissions_correctly() {
    let db = TestDb::new().await;

    let user_id = insert_user(&db.pool, 42).await;
    let role_id = sqlx::query_scalar::<_, uuid::Uuid>(
        "INSERT INTO roles (name, is_default) VALUES ('test_role_perm', FALSE) RETURNING id",
    )
    .fetch_one(&db.pool)
    .await
    .expect("failed to insert test role");
    let permission_id = insert_permission(&db.pool, "users", "write").await;

    sqlx::query("INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)")
        .bind(role_id)
        .bind(permission_id)
        .execute(&db.pool)
        .await
        .expect("failed to assign permission to role");
    sqlx::query("INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)")
        .bind(user_id)
        .bind(role_id)
        .execute(&db.pool)
        .await
        .expect("failed to assign role to user");

    let names = sqlx::query_scalar::<_, String>(
        "SELECT p.name
             FROM user_roles ur
             JOIN role_permissions rp ON rp.role_id = ur.role_id
             JOIN permissions p ON p.id = rp.permission_id
             WHERE ur.user_id = $1
             ORDER BY p.name",
    )
    .bind(user_id)
    .fetch_all(&db.pool)
    .await
    .expect("failed to load joined permissions");

    assert_eq!(names, vec!["users:write".to_owned()]);
}
