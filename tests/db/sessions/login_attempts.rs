use crate::common::db::{TestDatabase, assert_constraint};
use crate::common::fixtures::{insert_user, sample_email};

#[test]
fn failed_login_attempts_require_a_failure_reason() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let err = db
        .client()
        .execute(
            "INSERT INTO login_attempts (attempted_identifier, was_successful)
             VALUES ($1, FALSE)",
            &[&sample_email(71)],
        )
        .expect_err("failed login without reason should fail");

    assert_constraint(&err, "login_attempts_failure_reason_consistency");
}

#[test]
fn successful_login_attempts_reject_failure_reasons() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let err = db
        .client()
        .execute(
            "INSERT INTO login_attempts (attempted_identifier, was_successful, failure_reason)
             VALUES ($1, TRUE, 'invalid_password')",
            &[&sample_email(72)],
        )
        .expect_err("successful login with a failure reason should fail");

    assert_constraint(&err, "login_attempts_failure_reason_consistency");
}

#[test]
fn login_attempt_identifiers_cannot_be_blank() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let err = db
        .client()
        .execute(
            "INSERT INTO login_attempts (attempted_identifier, was_successful, failure_reason)
             VALUES ('   ', FALSE, 'unknown_identifier')",
            &[],
        )
        .expect_err("blank attempted identifier should fail");

    assert_constraint(&err, "login_attempts_identifier_not_blank");
}

#[test]
fn login_attempt_queries_can_count_recent_failures_by_identifier() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let identifier = sample_email(73);

    db.client()
        .execute(
            "INSERT INTO login_attempts (attempted_identifier, was_successful, failure_reason, attempted_at)
             VALUES
             ($1, FALSE, 'invalid_password', NOW() - INTERVAL '10 minutes'),
             ($1, FALSE, 'two_factor_failed', NOW() - INTERVAL '5 minutes'),
             ($1, TRUE, NULL, NOW() - INTERVAL '1 minute')",
            &[&identifier],
        )
        .expect("failed to insert login attempts");

    let failures: i64 = db
        .client()
        .query_one(
            "SELECT COUNT(*)
             FROM login_attempts
             WHERE attempted_identifier = $1
               AND was_successful = FALSE
               AND attempted_at >= NOW() - INTERVAL '15 minutes'",
            &[&identifier],
        )
        .expect("failed to count recent failed attempts")
        .get(0);

    assert_eq!(failures, 2);
}

#[test]
fn deleting_user_preserves_login_attempt_history_but_nulls_user_id() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 74);
    let attempted_identifier = sample_email(74);

    let attempt_id = db
        .client()
        .query_one(
            "INSERT INTO login_attempts (user_id, attempted_identifier, was_successful)
             VALUES ($1, $2, TRUE)
             RETURNING id",
            &[&user_id, &attempted_identifier],
        )
        .expect("failed to insert login attempt")
        .get::<_, uuid::Uuid>(0);

    db.client()
        .execute("DELETE FROM users WHERE id = $1", &[&user_id])
        .expect("failed to delete user");

    let row = db
        .client()
        .query_one(
            "SELECT user_id, attempted_identifier
             FROM login_attempts
             WHERE id = $1",
            &[&attempt_id],
        )
        .expect("failed to reload login attempt");

    let preserved_user_id = row.get::<_, Option<uuid::Uuid>>(0);
    let preserved_identifier = row.get::<_, String>(1);

    assert_eq!(preserved_user_id, None);
    assert_eq!(preserved_identifier, attempted_identifier);
}
