use testkit::TestDb;
use testkit::sql::{assert_constraint_error, fixed_hash, insert_user};

#[tokio::test]
async fn recovery_codes_enforce_position_range_and_uniqueness() {
    let db = TestDb::new().await;

    let user_id = insert_user(&db.pool, 63).await;
    sqlx::query(
        "INSERT INTO recovery_codes (user_id, code_position, code_hash)
             VALUES ($1, 1, $2)",
    )
    .bind(user_id)
    .bind(fixed_hash(9))
    .execute(&db.pool)
    .await
    .expect("failed to insert recovery code");

    let duplicate_err = sqlx::query(
        "INSERT INTO recovery_codes (user_id, code_position, code_hash)
             VALUES ($1, 1, $2)",
    )
    .bind(user_id)
    .bind(fixed_hash(10))
    .execute(&db.pool)
    .await
    .expect_err("duplicate recovery code position should fail");
    assert_constraint_error(&duplicate_err, "recovery_codes_user_position_key");

    let range_err = sqlx::query(
        "INSERT INTO recovery_codes (user_id, code_position, code_hash)
             VALUES ($1, 21, $2)",
    )
    .bind(user_id)
    .bind(fixed_hash(11))
    .execute(&db.pool)
    .await
    .expect_err("out of range recovery code position should fail");
    assert_constraint_error(&range_err, "recovery_codes_position_range");
}

#[tokio::test]
async fn recovery_codes_enforce_unique_hashes() {
    let db = TestDb::new().await;

    let first_user = insert_user(&db.pool, 631).await;
    let second_user = insert_user(&db.pool, 632).await;
    let code_hash = fixed_hash(41);

    sqlx::query(
        "INSERT INTO recovery_codes (user_id, code_position, code_hash)
             VALUES ($1, 1, $2)",
    )
    .bind(first_user)
    .bind(&code_hash)
    .execute(&db.pool)
    .await
    .expect("failed to insert first recovery code");

    let err = sqlx::query(
        "INSERT INTO recovery_codes (user_id, code_position, code_hash)
             VALUES ($1, 1, $2)",
    )
    .bind(second_user)
    .bind(&code_hash)
    .execute(&db.pool)
    .await
    .expect_err("duplicate recovery code hash should fail");

    assert_constraint_error(&err, "recovery_codes_code_hash_key");
}

#[tokio::test]
async fn recovery_codes_reject_used_at_before_creation() {
    let db = TestDb::new().await;

    let user_id = insert_user(&db.pool, 633).await;
    let err = sqlx::query(
        "INSERT INTO recovery_codes (user_id, created_at, used_at, code_position, code_hash)
             VALUES ($1, NOW(), NOW() - INTERVAL '1 minute', 1, $2)",
    )
    .bind(user_id)
    .bind(fixed_hash(42))
    .execute(&db.pool)
    .await
    .expect_err("used_at before creation should fail");

    assert_constraint_error(&err, "recovery_codes_used_after_creation");
}

#[tokio::test]
async fn recovery_codes_require_future_expiration_when_present() {
    let db = TestDb::new().await;

    let user_id = insert_user(&db.pool, 634).await;
    let err = sqlx::query(
        "INSERT INTO recovery_codes (user_id, created_at, expires_at, code_position, code_hash)
             VALUES ($1, NOW(), NOW() - INTERVAL '1 minute', 1, $2)",
    )
    .bind(user_id)
    .bind(fixed_hash(43))
    .execute(&db.pool)
    .await
    .expect_err("expiration before creation should fail");

    assert_constraint_error(&err, "recovery_codes_expiration_consistency");
}

#[tokio::test]
async fn recovery_codes_cleanup_removes_only_expired_unused_codes() {
    let db = TestDb::new().await;

    let user_id = insert_user(&db.pool, 635).await;
    sqlx::query(
        "INSERT INTO recovery_codes (user_id, created_at, code_position, code_hash, expires_at)
             VALUES
             ($1, NOW() - INTERVAL '2 hours', 1, $2, NOW() - INTERVAL '1 hour'),
             ($1, NOW(), 2, $3, NOW() + INTERVAL '1 hour'),
             ($1, NOW() - INTERVAL '2 hours', 3, $4, NOW() - INTERVAL '1 hour')",
    )
    .bind(user_id)
    .bind(fixed_hash(44))
    .bind(fixed_hash(45))
    .bind(fixed_hash(46))
    .execute(&db.pool)
    .await
    .expect("failed to insert recovery codes");
    sqlx::query(
        "UPDATE recovery_codes
             SET used_at = NOW() - INTERVAL '30 minutes'
             WHERE user_id = $1 AND code_hash = $2",
    )
    .bind(user_id)
    .bind(fixed_hash(46))
    .execute(&db.pool)
    .await
    .expect("failed to mark recovery code as used");

    let deleted = sqlx::query(
        "DELETE FROM recovery_codes
             WHERE expires_at < NOW() AND used_at IS NULL",
    )
    .execute(&db.pool)
    .await
    .expect("failed to cleanup recovery codes")
    .rows_affected();

    let remaining: i64 =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM recovery_codes WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&db.pool)
            .await
            .expect("failed to count remaining recovery codes");

    assert_eq!(deleted, 1);
    assert_eq!(remaining, 2);
}
