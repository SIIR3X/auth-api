use crate::common::db::TestDatabase;
use crate::common::fixtures::insert_user;

#[test]
fn audit_log_is_append_only() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let row = db
        .client()
        .query_one(
            "INSERT INTO audit_log (action, metadata)
             VALUES ('login', '{}'::jsonb)
             RETURNING created_at, id",
            &[],
        )
        .expect("failed to insert audit event");
    let created_at = row.get::<_, std::time::SystemTime>(0);
    let id = row.get::<_, uuid::Uuid>(1);

    let update_err = db
        .client()
        .execute(
            "UPDATE audit_log SET action = 'logout' WHERE created_at = $1 AND id = $2",
            &[&created_at, &id],
        )
        .expect_err("audit log update should fail");

    let delete_err = db
        .client()
        .execute(
            "DELETE FROM audit_log WHERE created_at = $1 AND id = $2",
            &[&created_at, &id],
        )
        .expect_err("audit log delete should fail");

    let update_message = update_err
        .as_db_error()
        .map(|err| err.message())
        .unwrap_or_else(|| panic!("expected a PostgreSQL error for audit update"));
    let delete_message = delete_err
        .as_db_error()
        .map(|err| err.message())
        .unwrap_or_else(|| panic!("expected a PostgreSQL error for audit delete"));

    assert!(update_message.contains("append-only"));
    assert!(delete_message.contains("append-only"));
}

#[test]
fn audit_log_uses_default_metadata() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let metadata: String = db
        .client()
        .query_one(
            "INSERT INTO audit_log (action) VALUES ('login_failed') RETURNING metadata::text",
            &[],
        )
        .expect("failed to insert audit row")
        .get(0);

    assert_eq!(metadata, "{}");
}

#[test]
fn deleting_user_sets_audit_log_user_id_to_null() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 71);
    let row = db
        .client()
        .query_one(
            "INSERT INTO audit_log (user_id, action)
             VALUES ($1, 'login')
             RETURNING created_at, id",
            &[&user_id],
        )
        .expect("failed to insert audit row");
    let created_at = row.get::<_, std::time::SystemTime>(0);
    let id = row.get::<_, uuid::Uuid>(1);

    db.client()
        .execute("DELETE FROM users WHERE id = $1", &[&user_id])
        .expect("failed to delete user");

    let remaining_user_id: Option<uuid::Uuid> = db
        .client()
        .query_one(
            "SELECT user_id FROM audit_log WHERE created_at = $1 AND id = $2",
            &[&created_at, &id],
        )
        .expect("failed to reload audit row")
        .get(0);

    assert!(remaining_user_id.is_none());
}
