use sqlx::Row;
use std::time::Duration;
use testkit::TestDb;
use testkit::sql::{assert_constraint_error, insert_user};

#[tokio::test]
async fn totp_requires_secret() {
    let db = TestDb::new().await;

    let user_id = insert_user(&db.pool, 51).await;
    let err = sqlx::query(
        "INSERT INTO two_factor_methods (user_id, method_type, is_verified)
             VALUES ($1, 'totp', TRUE)",
    )
    .bind(user_id)
    .execute(&db.pool)
    .await
    .expect_err("totp without secret should fail");

    assert_constraint_error(&err, "two_factor_method_payload");
}

#[tokio::test]
async fn email_method_allows_single_entry_per_user() {
    let db = TestDb::new().await;

    let user_id = insert_user(&db.pool, 52).await;
    sqlx::query(
        "INSERT INTO two_factor_methods (user_id, method_type, is_verified)
             VALUES ($1, 'email', TRUE)",
    )
    .bind(user_id)
    .execute(&db.pool)
    .await
    .expect("failed to insert first email 2fa method");

    let err = sqlx::query(
        "INSERT INTO two_factor_methods (user_id, method_type, is_verified)
             VALUES ($1, 'email', TRUE)",
    )
    .bind(user_id)
    .execute(&db.pool)
    .await
    .expect_err("duplicate email method should fail");

    assert_constraint_error(&err, "idx_2fa_user_email");
}

#[tokio::test]
async fn totp_allows_single_entry_per_user() {
    let db = TestDb::new().await;

    let user_id = insert_user(&db.pool, 521).await;
    sqlx::query(
        "INSERT INTO two_factor_methods (user_id, method_type, is_verified, totp_secret)
             VALUES ($1, 'totp', TRUE, $2)",
    )
    .bind(user_id)
    .bind("encrypted-secret-a")
    .execute(&db.pool)
    .await
    .expect("failed to insert first totp method");

    let err = sqlx::query(
        "INSERT INTO two_factor_methods (user_id, method_type, is_verified, totp_secret)
             VALUES ($1, 'totp', TRUE, $2)",
    )
    .bind(user_id)
    .bind("encrypted-secret-b")
    .execute(&db.pool)
    .await
    .expect_err("duplicate totp method should fail");

    assert_constraint_error(&err, "idx_2fa_user_totp");
}

#[tokio::test]
async fn primary_method_must_be_verified() {
    let db = TestDb::new().await;

    let user_id = insert_user(&db.pool, 54).await;
    let err = sqlx::query(
        "INSERT INTO two_factor_methods (user_id, method_type, is_primary, is_verified)
             VALUES ($1, 'email', TRUE, FALSE)",
    )
    .bind(user_id)
    .execute(&db.pool)
    .await
    .expect_err("primary 2fa method must be verified");

    assert_constraint_error(&err, "two_factor_primary_requires_verification");
}

#[tokio::test]
async fn user_can_have_only_one_primary_two_factor_method() {
    let db = TestDb::new().await;

    let user_id = insert_user(&db.pool, 541).await;

    sqlx::query(
        "INSERT INTO two_factor_methods (user_id, method_type, is_primary, is_verified)
             VALUES ($1, 'email', TRUE, TRUE)",
    )
    .bind(user_id)
    .execute(&db.pool)
    .await
    .expect("failed to insert first primary 2fa method");

    let err = sqlx::query(
        "INSERT INTO two_factor_methods (user_id, method_type, is_primary, is_verified, totp_secret)
             VALUES ($1, 'totp', TRUE, TRUE, $2)",
    )
    .bind(user_id)
    .bind("encrypted-secret")
    .execute(&db.pool)
    .await
    .expect_err("second primary 2fa method should fail");

    assert_constraint_error(&err, "idx_2fa_user_primary");
}

#[tokio::test]
async fn deleting_user_cascades_to_two_factor_methods() {
    let db = TestDb::new().await;

    let user_id = insert_user(&db.pool, 55).await;
    sqlx::query(
        "INSERT INTO two_factor_methods (user_id, method_type, is_verified)
             VALUES ($1, 'email', TRUE)",
    )
    .bind(user_id)
    .execute(&db.pool)
    .await
    .expect("failed to insert 2fa method");

    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&db.pool)
        .await
        .expect("failed to delete user");

    let count: i64 =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM two_factor_methods WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&db.pool)
            .await
            .expect("failed to count 2fa methods");

    assert_eq!(count, 0);
}

#[tokio::test]
async fn updating_two_factor_method_touches_updated_at() {
    let db = TestDb::new().await;

    let user_id = insert_user(&db.pool, 56).await;
    let row = sqlx::query(
        "INSERT INTO two_factor_methods (user_id, method_type, is_verified)
             VALUES ($1, 'email', FALSE)
             RETURNING id, updated_at",
    )
    .bind(user_id)
    .fetch_one(&db.pool)
    .await
    .expect("failed to insert 2fa method");
    let method_id = row.get::<uuid::Uuid, _>(0);
    let first_updated_at = row.get::<time::OffsetDateTime, _>(1);

    tokio::time::sleep(Duration::from_millis(5)).await;

    let second_updated_at = sqlx::query_scalar::<_, time::OffsetDateTime>(
        "UPDATE two_factor_methods
             SET is_verified = TRUE
             WHERE id = $1
             RETURNING updated_at",
    )
    .bind(method_id)
    .fetch_one(&db.pool)
    .await
    .expect("failed to update 2fa method");

    assert!(second_updated_at > first_updated_at);
}
