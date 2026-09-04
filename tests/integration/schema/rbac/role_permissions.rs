use testkit::TestDb;
use testkit::sql::{assert_constraint_error, insert_permission};

#[tokio::test]
async fn role_permissions_enforce_unique_pairs() {
    let db = TestDb::new().await;

    let role_id = sqlx::query_scalar::<_, uuid::Uuid>(
        "INSERT INTO roles (name, is_default) VALUES ('test_role_rp1', FALSE) RETURNING id",
    )
    .fetch_one(&db.pool)
    .await
    .expect("failed to insert test role");
    let permission_id = insert_permission(&db.pool, "audit", "read").await;

    sqlx::query("INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)")
        .bind(role_id)
        .bind(permission_id)
        .execute(&db.pool)
        .await
        .expect("failed to insert first role permission");

    let err = sqlx::query("INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)")
        .bind(role_id)
        .bind(permission_id)
        .execute(&db.pool)
        .await
        .expect_err("duplicate role permission should fail");

    assert_constraint_error(&err, "role_permissions_pkey");
}

#[tokio::test]
async fn deleting_role_cascades_to_role_permissions() {
    let db = TestDb::new().await;

    let role_id = sqlx::query_scalar::<_, uuid::Uuid>(
        "INSERT INTO roles (name, is_default) VALUES ('temporary_role', FALSE) RETURNING id",
    )
    .fetch_one(&db.pool)
    .await
    .expect("failed to insert temporary role");
    let permission_id = insert_permission(&db.pool, "reports", "read").await;

    sqlx::query("INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)")
        .bind(role_id)
        .bind(permission_id)
        .execute(&db.pool)
        .await
        .expect("failed to insert role permission");

    sqlx::query("DELETE FROM roles WHERE id = $1")
        .bind(role_id)
        .execute(&db.pool)
        .await
        .expect("failed to delete role");

    let count: i64 = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM role_permissions WHERE permission_id = $1",
    )
    .bind(permission_id)
    .fetch_one(&db.pool)
    .await
    .expect("failed to count role permissions");

    assert_eq!(count, 0);
}

#[tokio::test]
async fn deleting_permission_cascades_to_role_permissions() {
    let db = TestDb::new().await;

    let role_id = sqlx::query_scalar::<_, uuid::Uuid>(
        "INSERT INTO roles (name, is_default) VALUES ('test_role_rp2', FALSE) RETURNING id",
    )
    .fetch_one(&db.pool)
    .await
    .expect("failed to insert test role");
    let permission_id = insert_permission(&db.pool, "billing", "read").await;

    sqlx::query("INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)")
        .bind(role_id)
        .bind(permission_id)
        .execute(&db.pool)
        .await
        .expect("failed to insert role permission");

    sqlx::query("DELETE FROM permissions WHERE id = $1")
        .bind(permission_id)
        .execute(&db.pool)
        .await
        .expect("failed to delete permission");

    let count: i64 =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM role_permissions WHERE role_id = $1")
            .bind(role_id)
            .fetch_one(&db.pool)
            .await
            .expect("failed to count remaining role permissions");

    assert_eq!(count, 0);
}
