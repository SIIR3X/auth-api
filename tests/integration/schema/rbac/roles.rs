use testkit::TestDb;
use testkit::sql::{assert_constraint_error, insert_user};

#[tokio::test]
async fn roles_seed_contains_single_default_role() {
    let db = TestDb::new().await;

    let count: i64 =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM roles WHERE is_default = TRUE")
            .fetch_one(&db.pool)
            .await
            .expect("failed to count default roles");

    assert_eq!(count, 1);
}

#[tokio::test]
async fn roles_seed_contains_expected_names() {
    let db = TestDb::new().await;

    let names = sqlx::query_scalar::<_, String>("SELECT name FROM roles ORDER BY name")
        .fetch_all(&db.pool)
        .await
        .expect("failed to load seeded roles");

    assert_eq!(names, ["admin", "user"]);
}

#[tokio::test]
async fn roles_enforce_unique_names() {
    let db = TestDb::new().await;

    let err = sqlx::query("INSERT INTO roles (name, is_default) VALUES ('user', FALSE)")
        .execute(&db.pool)
        .await
        .expect_err("duplicate role name should fail");

    assert_constraint_error(&err, "roles_name_key");
}

#[tokio::test]
async fn roles_enforce_single_default_role() {
    let db = TestDb::new().await;

    let err = sqlx::query("INSERT INTO roles (name, is_default) VALUES ('support', TRUE)")
        .execute(&db.pool)
        .await
        .expect_err("a second default role should fail");

    assert_constraint_error(&err, "idx_roles_default");
}

#[tokio::test]
async fn user_roles_enforce_unique_assignments() {
    let db = TestDb::new().await;

    let user_id = insert_user(&db.pool, 41).await;
    let role_id = sqlx::query_scalar::<_, uuid::Uuid>("SELECT id FROM roles WHERE name = 'user'")
        .fetch_one(&db.pool)
        .await
        .expect("failed to load role");

    sqlx::query("INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)")
        .bind(user_id)
        .bind(role_id)
        .execute(&db.pool)
        .await
        .expect("failed to insert user role");

    let err = sqlx::query("INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)")
        .bind(user_id)
        .bind(role_id)
        .execute(&db.pool)
        .await
        .expect_err("duplicate user role should fail");

    assert_constraint_error(&err, "user_roles_pkey");
}
