use crate::common::db::{TestDatabase, assert_constraint};
use crate::common::fixtures::insert_permission;

#[test]
fn role_permissions_enforce_unique_pairs() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let role_id = db
        .client()
        .query_one(
            "INSERT INTO roles (name, is_default) VALUES ('test_role_rp1', FALSE) RETURNING id",
            &[],
        )
        .expect("failed to insert test role")
        .get::<_, uuid::Uuid>(0);
    let permission_id = insert_permission(db.client(), "audit", "read");

    db.client()
        .execute(
            "INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)",
            &[&role_id, &permission_id],
        )
        .expect("failed to insert first role permission");

    let err = db
        .client()
        .execute(
            "INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)",
            &[&role_id, &permission_id],
        )
        .expect_err("duplicate role permission should fail");

    assert_constraint(&err, "role_permissions_pkey");
}

#[test]
fn deleting_role_cascades_to_role_permissions() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let role_id = db
        .client()
        .query_one(
            "INSERT INTO roles (name, is_default) VALUES ('temporary_role', FALSE) RETURNING id",
            &[],
        )
        .expect("failed to insert temporary role")
        .get::<_, uuid::Uuid>(0);
    let permission_id = insert_permission(db.client(), "reports", "read");

    db.client()
        .execute(
            "INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)",
            &[&role_id, &permission_id],
        )
        .expect("failed to insert role permission");

    db.client()
        .execute("DELETE FROM roles WHERE id = $1", &[&role_id])
        .expect("failed to delete role");

    let count: i64 = db
        .client()
        .query_one(
            "SELECT COUNT(*) FROM role_permissions WHERE permission_id = $1",
            &[&permission_id],
        )
        .expect("failed to count role permissions")
        .get(0);

    assert_eq!(count, 0);
}

#[test]
fn deleting_permission_cascades_to_role_permissions() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let role_id = db
        .client()
        .query_one(
            "INSERT INTO roles (name, is_default) VALUES ('test_role_rp2', FALSE) RETURNING id",
            &[],
        )
        .expect("failed to insert test role")
        .get::<_, uuid::Uuid>(0);
    let permission_id = insert_permission(db.client(), "billing", "read");

    db.client()
        .execute(
            "INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)",
            &[&role_id, &permission_id],
        )
        .expect("failed to insert role permission");

    db.client()
        .execute("DELETE FROM permissions WHERE id = $1", &[&permission_id])
        .expect("failed to delete permission");

    let count: i64 = db
        .client()
        .query_one(
            "SELECT COUNT(*) FROM role_permissions WHERE role_id = $1",
            &[&role_id],
        )
        .expect("failed to count remaining role permissions")
        .get(0);

    assert_eq!(count, 0);
}
