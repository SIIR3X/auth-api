use crate::common::db::TestDatabase;
use crate::common::fixtures::{insert_permission, insert_user};

#[test]
fn permissions_generate_name_from_resource_and_action() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let permission_id = insert_permission(db.client(), "users", "read");
    let name: String = db
        .client()
        .query_one(
            "SELECT name FROM permissions WHERE id = $1",
            &[&permission_id],
        )
        .expect("failed to load generated permission name")
        .get(0);

    assert_eq!(name, "users:read");
}

#[test]
fn permissions_enforce_unique_resource_action_pairs() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    insert_permission(db.client(), "sessions", "revoke");

    let err = db
        .client()
        .execute(
            "INSERT INTO permissions (resource, action)
             VALUES ($1, $2)",
            &[&"sessions", &"revoke"],
        )
        .expect_err("duplicate permission pair should fail");

    crate::common::db::assert_constraint(&err, "permissions_resource_action_key");
}

#[test]
fn user_roles_join_to_permissions_correctly() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 42);
    let role_id = db
        .client()
        .query_one(
            "INSERT INTO roles (name, is_default) VALUES ('test_role_perm', FALSE) RETURNING id",
            &[],
        )
        .expect("failed to insert test role")
        .get::<_, uuid::Uuid>(0);
    let permission_id = insert_permission(db.client(), "users", "write");

    db.client()
        .execute(
            "INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)",
            &[&role_id, &permission_id],
        )
        .expect("failed to assign permission to role");
    db.client()
        .execute(
            "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)",
            &[&user_id, &role_id],
        )
        .expect("failed to assign role to user");

    let names = db
        .client()
        .query(
            "SELECT p.name
             FROM user_roles ur
             JOIN role_permissions rp ON rp.role_id = ur.role_id
             JOIN permissions p ON p.id = rp.permission_id
             WHERE ur.user_id = $1
             ORDER BY p.name",
            &[&user_id],
        )
        .expect("failed to load joined permissions")
        .into_iter()
        .map(|row| row.get::<_, String>(0))
        .collect::<Vec<_>>();

    assert_eq!(names, vec!["users:write".to_owned()]);
}
