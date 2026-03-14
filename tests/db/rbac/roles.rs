use crate::common::db::{TestDatabase, assert_constraint};
use crate::common::fixtures::insert_user;

#[test]
fn roles_seed_contains_single_default_role() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let count: i64 = db
        .client()
        .query_one("SELECT COUNT(*) FROM roles WHERE is_default = TRUE", &[])
        .expect("failed to count default roles")
        .get(0);

    assert_eq!(count, 1);
}

#[test]
fn roles_seed_contains_expected_names() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let names = db
        .client()
        .query("SELECT name FROM roles ORDER BY name", &[])
        .expect("failed to load seeded roles")
        .into_iter()
        .map(|row| row.get::<_, String>(0))
        .collect::<Vec<_>>();

    assert_eq!(names, vec!["admin".to_owned(), "user".to_owned()]);
}

#[test]
fn roles_enforce_unique_names() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let err = db
        .client()
        .execute(
            "INSERT INTO roles (name, is_default) VALUES ('user', FALSE)",
            &[],
        )
        .expect_err("duplicate role name should fail");

    assert_constraint(&err, "roles_name_key");
}

#[test]
fn roles_enforce_single_default_role() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let err = db
        .client()
        .execute(
            "INSERT INTO roles (name, is_default) VALUES ('support', TRUE)",
            &[],
        )
        .expect_err("a second default role should fail");

    assert_constraint(&err, "idx_roles_default");
}

#[test]
fn user_roles_enforce_unique_assignments() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 41);
    let role_id = db
        .client()
        .query_one("SELECT id FROM roles WHERE name = 'user'", &[])
        .expect("failed to load role")
        .get::<_, uuid::Uuid>(0);

    db.client()
        .execute(
            "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)",
            &[&user_id, &role_id],
        )
        .expect("failed to insert user role");

    let err = db
        .client()
        .execute(
            "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)",
            &[&user_id, &role_id],
        )
        .expect_err("duplicate user role should fail");

    assert_constraint(&err, "user_roles_pkey");
}
