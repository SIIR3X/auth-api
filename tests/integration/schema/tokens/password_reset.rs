use testkit::TestDb;
use testkit::sql::{assert_constraint_error, fixed_hash, insert_user};

#[tokio::test]
async fn password_reset_tokens_require_future_expiration() {
    let db = TestDb::new().await;

    let user_id = insert_user(&db.pool, 62).await;
    let err = sqlx::query(
        "INSERT INTO password_reset_tokens (user_id, token_hash, created_at, expires_at)
             VALUES ($1, $2, NOW(), NOW() - INTERVAL '1 minute')",
    )
    .bind(user_id)
    .bind(fixed_hash(8))
    .execute(&db.pool)
    .await
    .expect_err("expired password reset token at insert should fail");

    assert_constraint_error(&err, "password_reset_tokens_expires_after_creation");
}

#[tokio::test]
async fn password_reset_tokens_enforce_unique_hashes() {
    let db = TestDb::new().await;

    let first_user_id = insert_user(&db.pool, 621).await;
    let second_user_id = insert_user(&db.pool, 6220).await;
    let token_hash = fixed_hash(31);

    sqlx::query(
        "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
             VALUES ($1, $2, NOW() + INTERVAL '1 hour')",
    )
    .bind(first_user_id)
    .bind(&token_hash)
    .execute(&db.pool)
    .await
    .expect("failed to insert first password reset token");

    let err = sqlx::query(
        "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
             VALUES ($1, $2, NOW() + INTERVAL '1 hour')",
    )
    .bind(second_user_id)
    .bind(&token_hash)
    .execute(&db.pool)
    .await
    .expect_err("duplicate password reset token hash should fail");

    assert_constraint_error(&err, "password_reset_tokens_token_hash_key");
}

#[tokio::test]
async fn password_reset_tokens_allow_only_one_unused_token_per_user() {
    let db = TestDb::new().await;

    let user_id = insert_user(&db.pool, 6211).await;
    sqlx::query(
        "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
             VALUES ($1, $2, NOW() + INTERVAL '1 hour')",
    )
    .bind(user_id)
    .bind(fixed_hash(38))
    .execute(&db.pool)
    .await
    .expect("failed to insert first unused password reset token");

    let err = sqlx::query(
        "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
             VALUES ($1, $2, NOW() + INTERVAL '1 hour')",
    )
    .bind(user_id)
    .bind(fixed_hash(39))
    .execute(&db.pool)
    .await
    .expect_err("a second unused password reset token should fail");

    assert_constraint_error(&err, "idx_password_reset_tokens_user_active");
}

#[tokio::test]
async fn password_reset_tokens_reject_used_at_before_creation() {
    let db = TestDb::new().await;

    let user_id = insert_user(&db.pool, 622).await;
    let err = sqlx::query(
        "INSERT INTO password_reset_tokens (user_id, token_hash, created_at, expires_at, used_at)
             VALUES ($1, $2, NOW(), NOW() + INTERVAL '1 hour', NOW() - INTERVAL '1 minute')",
    )
    .bind(user_id)
    .bind(fixed_hash(32))
    .execute(&db.pool)
    .await
    .expect_err("used_at before creation should fail");

    assert_constraint_error(&err, "password_reset_tokens_used_after_creation");
}

#[tokio::test]
async fn password_reset_tokens_active_query_excludes_used_tokens() {
    let db = TestDb::new().await;

    let user_id = insert_user(&db.pool, 623).await;
    sqlx::query(
        "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
             VALUES ($1, $2, NOW() + INTERVAL '1 hour')",
    )
    .bind(user_id)
    .bind(fixed_hash(33))
    .execute(&db.pool)
    .await
    .expect("failed to insert active password reset token");
    sqlx::query(
        "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at, used_at)
             VALUES ($1, $2, NOW() + INTERVAL '1 hour', NOW())",
    )
    .bind(user_id)
    .bind(fixed_hash(34))
    .execute(&db.pool)
    .await
    .expect("failed to insert used password reset token");

    let count: i64 = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM password_reset_tokens WHERE user_id = $1 AND used_at IS NULL",
    )
    .bind(user_id)
    .fetch_one(&db.pool)
    .await
    .expect("failed to count active password reset tokens");

    assert_eq!(count, 1);
}

#[tokio::test]
async fn password_reset_tokens_cleanup_removes_only_expired_unused_tokens() {
    let db = TestDb::new().await;

    let expired_user_id = insert_user(&db.pool, 624).await;
    let active_user_id = insert_user(&db.pool, 625).await;
    let used_user_id = insert_user(&db.pool, 626).await;
    sqlx::query(
        "INSERT INTO password_reset_tokens (user_id, token_hash, created_at, expires_at)
             VALUES ($1, $2, NOW() - INTERVAL '2 hours', NOW() - INTERVAL '1 hour')",
    )
    .bind(expired_user_id)
    .bind(fixed_hash(35))
    .execute(&db.pool)
    .await
    .expect("failed to insert expired unused token");
    sqlx::query(
        "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
             VALUES ($1, $2, NOW() + INTERVAL '1 hour')",
    )
    .bind(active_user_id)
    .bind(fixed_hash(36))
    .execute(&db.pool)
    .await
    .expect("failed to insert active unused token");
    sqlx::query(
        "INSERT INTO password_reset_tokens (user_id, token_hash, created_at, expires_at, used_at)
             VALUES ($1, $2, NOW() - INTERVAL '2 hours', NOW() - INTERVAL '1 hour', NOW() - INTERVAL '30 minutes')",
    )
    .bind(used_user_id)
    .bind(fixed_hash(37))
    .execute(&db.pool)
    .await
    .expect("failed to insert used token");

    let deleted = sqlx::query(
        "DELETE FROM password_reset_tokens
             WHERE expires_at < NOW() AND used_at IS NULL",
    )
    .execute(&db.pool)
    .await
    .expect("failed to cleanup password reset tokens")
    .rows_affected();

    let remaining: i64 = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM password_reset_tokens
             WHERE user_id IN ($1, $2, $3)",
    )
    .bind(expired_user_id)
    .bind(active_user_id)
    .bind(used_user_id)
    .fetch_one(&db.pool)
    .await
    .expect("failed to count remaining password reset tokens");

    assert_eq!(deleted, 1);
    assert_eq!(remaining, 2);
}
