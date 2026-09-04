use sqlx::Row;
use testkit::TestDb;
use testkit::sql::insert_user;

#[tokio::test]
async fn audit_log_is_append_only() {
    let db = TestDb::new().await;

    let row = sqlx::query(
        "INSERT INTO audit_log (action, metadata)
             VALUES ('login', '{}'::jsonb)
             RETURNING created_at, id",
    )
    .fetch_one(&db.pool)
    .await
    .expect("failed to insert audit event");
    let created_at = row.get::<time::OffsetDateTime, _>(0);
    let id = row.get::<uuid::Uuid, _>(1);

    let update_err =
        sqlx::query("UPDATE audit_log SET action = 'logout' WHERE created_at = $1 AND id = $2")
            .bind(created_at)
            .bind(id)
            .execute(&db.pool)
            .await
            .expect_err("audit log update should fail");

    let delete_err = sqlx::query("DELETE FROM audit_log WHERE created_at = $1 AND id = $2")
        .bind(created_at)
        .bind(id)
        .execute(&db.pool)
        .await
        .expect_err("audit log delete should fail");

    let update_message = update_err
        .as_database_error()
        .map(|err| err.message())
        .unwrap_or_else(|| panic!("expected a PostgreSQL error for audit update"));
    let delete_message = delete_err
        .as_database_error()
        .map(|err| err.message())
        .unwrap_or_else(|| panic!("expected a PostgreSQL error for audit delete"));

    assert!(update_message.contains("append-only"));
    assert!(delete_message.contains("append-only"));
}

#[tokio::test]
async fn audit_log_uses_default_metadata() {
    let db = TestDb::new().await;

    let metadata: String = sqlx::query_scalar(
        "INSERT INTO audit_log (action) VALUES ('login_failed') RETURNING metadata::text",
    )
    .fetch_one(&db.pool)
    .await
    .expect("failed to insert audit row");

    assert_eq!(metadata, "{}");
}

#[tokio::test]
async fn deleting_user_sets_audit_log_user_id_to_null() {
    let db = TestDb::new().await;

    let user_id = insert_user(&db.pool, 71).await;
    let row = sqlx::query(
        "INSERT INTO audit_log (user_id, action)
             VALUES ($1, 'login')
             RETURNING created_at, id",
    )
    .bind(user_id)
    .fetch_one(&db.pool)
    .await
    .expect("failed to insert audit row");
    let created_at = row.get::<time::OffsetDateTime, _>(0);
    let id = row.get::<uuid::Uuid, _>(1);

    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&db.pool)
        .await
        .expect("failed to delete user");

    let remaining_user_id: Option<uuid::Uuid> =
        sqlx::query_scalar("SELECT user_id FROM audit_log WHERE created_at = $1 AND id = $2")
            .bind(created_at)
            .bind(id)
            .fetch_one(&db.pool)
            .await
            .expect("failed to reload audit row");

    assert!(remaining_user_id.is_none());
}
