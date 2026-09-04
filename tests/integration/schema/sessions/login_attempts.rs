use sqlx::Row;
use testkit::TestDb;
use testkit::sql::{assert_constraint_error, insert_user, sample_email};

#[tokio::test]
async fn failed_login_attempts_require_a_failure_reason() {
    let db = TestDb::new().await;

    let err = sqlx::query(
        "INSERT INTO login_attempts (attempted_identifier, was_successful)
             VALUES ($1, FALSE)",
    )
    .bind(sample_email(71))
    .execute(&db.pool)
    .await
    .expect_err("failed login without reason should fail");

    assert_constraint_error(&err, "login_attempts_failure_reason_consistency");
}

#[tokio::test]
async fn successful_login_attempts_reject_failure_reasons() {
    let db = TestDb::new().await;

    let err = sqlx::query(
        "INSERT INTO login_attempts (attempted_identifier, was_successful, failure_reason)
             VALUES ($1, TRUE, 'invalid_password')",
    )
    .bind(sample_email(72))
    .execute(&db.pool)
    .await
    .expect_err("successful login with a failure reason should fail");

    assert_constraint_error(&err, "login_attempts_failure_reason_consistency");
}

#[tokio::test]
async fn login_attempt_identifiers_cannot_be_blank() {
    let db = TestDb::new().await;

    let err = sqlx::query(
        "INSERT INTO login_attempts (attempted_identifier, was_successful, failure_reason)
             VALUES ('   ', FALSE, 'unknown_identifier')",
    )
    .execute(&db.pool)
    .await
    .expect_err("blank attempted identifier should fail");

    assert_constraint_error(&err, "login_attempts_identifier_not_blank");
}

#[tokio::test]
async fn login_attempt_queries_can_count_recent_failures_by_identifier() {
    let db = TestDb::new().await;

    let identifier = sample_email(73);

    sqlx::query(
        "INSERT INTO login_attempts (attempted_identifier, was_successful, failure_reason, attempted_at)
             VALUES
             ($1, FALSE, 'invalid_password', NOW() - INTERVAL '10 minutes'),
             ($1, FALSE, 'two_factor_failed', NOW() - INTERVAL '5 minutes'),
             ($1, TRUE, NULL, NOW() - INTERVAL '1 minute')",
    )
    .bind(&identifier)
    .execute(&db.pool)
    .await
    .expect("failed to insert login attempts");

    let failures: i64 = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)
             FROM login_attempts
             WHERE attempted_identifier = $1
               AND was_successful = FALSE
               AND attempted_at >= NOW() - INTERVAL '15 minutes'",
    )
    .bind(&identifier)
    .fetch_one(&db.pool)
    .await
    .expect("failed to count recent failed attempts");

    assert_eq!(failures, 2);
}

#[tokio::test]
async fn deleting_user_preserves_login_attempt_history_but_nulls_user_id() {
    let db = TestDb::new().await;

    let user_id = insert_user(&db.pool, 74).await;
    let attempted_identifier = sample_email(74);

    let attempt_id = sqlx::query_scalar::<_, uuid::Uuid>(
        "INSERT INTO login_attempts (user_id, attempted_identifier, was_successful)
             VALUES ($1, $2, TRUE)
             RETURNING id",
    )
    .bind(user_id)
    .bind(&attempted_identifier)
    .fetch_one(&db.pool)
    .await
    .expect("failed to insert login attempt");

    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&db.pool)
        .await
        .expect("failed to delete user");

    let row = sqlx::query(
        "SELECT user_id, attempted_identifier
             FROM login_attempts
             WHERE id = $1",
    )
    .bind(attempt_id)
    .fetch_one(&db.pool)
    .await
    .expect("failed to reload login attempt");

    let preserved_user_id = row.get::<Option<uuid::Uuid>, _>(0);
    let preserved_identifier = row.get::<String, _>(1);

    assert_eq!(preserved_user_id, None);
    assert_eq!(preserved_identifier, attempted_identifier);
}
