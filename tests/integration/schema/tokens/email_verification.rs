use testkit::TestDb;
use testkit::sql::{assert_constraint_error, fixed_hash, insert_user, sample_email};

#[tokio::test]
async fn email_verification_tokens_are_fixed_length() {
    let db = TestDb::new().await;

    let user_id = insert_user(&db.pool, 61).await;
    let err = sqlx::query(
        "INSERT INTO email_verification_tokens (user_id, token_hash, expires_at, target_email)
             VALUES ($1, $2, NOW() + INTERVAL '1 hour', $3)",
    )
    .bind(user_id)
    .bind(vec![1_u8; 30])
    .bind(sample_email(61))
    .execute(&db.pool)
    .await
    .expect_err("invalid email verification token hash should fail");

    assert_constraint_error(&err, "email_verification_tokens_token_hash_length");
}

#[tokio::test]
async fn email_verification_tokens_enforce_unique_hashes() {
    let db = TestDb::new().await;

    let first_user_id = insert_user(&db.pool, 611).await;
    let second_user_id = insert_user(&db.pool, 6120).await;
    let token_hash = fixed_hash(21);

    sqlx::query(
        "INSERT INTO email_verification_tokens (user_id, token_hash, expires_at, target_email)
             VALUES ($1, $2, NOW() + INTERVAL '1 hour', $3)",
    )
    .bind(first_user_id)
    .bind(&token_hash)
    .bind(sample_email(611))
    .execute(&db.pool)
    .await
    .expect("failed to insert first email verification token");

    let err = sqlx::query(
        "INSERT INTO email_verification_tokens (user_id, token_hash, expires_at, target_email)
             VALUES ($1, $2, NOW() + INTERVAL '1 hour', $3)",
    )
    .bind(second_user_id)
    .bind(&token_hash)
    .bind(sample_email(6120))
    .execute(&db.pool)
    .await
    .expect_err("duplicate email verification token hash should fail");

    assert_constraint_error(&err, "email_verification_tokens_token_hash_key");
}

#[tokio::test]
async fn email_verification_tokens_allow_only_one_unused_token_per_user() {
    let db = TestDb::new().await;

    let user_id = insert_user(&db.pool, 6111).await;
    sqlx::query(
        "INSERT INTO email_verification_tokens (user_id, token_hash, expires_at, target_email)
             VALUES ($1, $2, NOW() + INTERVAL '1 hour', $3)",
    )
    .bind(user_id)
    .bind(fixed_hash(29))
    .bind(sample_email(6111))
    .execute(&db.pool)
    .await
    .expect("failed to insert first unused email verification token");

    let err = sqlx::query(
        "INSERT INTO email_verification_tokens (user_id, token_hash, expires_at, target_email)
             VALUES ($1, $2, NOW() + INTERVAL '1 hour', $3)",
    )
    .bind(user_id)
    .bind(fixed_hash(30))
    .bind(sample_email(6112))
    .execute(&db.pool)
    .await
    .expect_err("a second unused email verification token should fail");

    assert_constraint_error(&err, "idx_email_verification_tokens_user_active");
}

#[tokio::test]
async fn email_verification_tokens_require_future_expiration() {
    let db = TestDb::new().await;

    let user_id = insert_user(&db.pool, 612).await;
    let err = sqlx::query(
        "INSERT INTO email_verification_tokens (user_id, token_hash, created_at, expires_at, target_email)
             VALUES ($1, $2, NOW(), NOW() - INTERVAL '1 minute', $3)",
    )
    .bind(user_id)
    .bind(fixed_hash(22))
    .bind(sample_email(612))
    .execute(&db.pool)
    .await
    .expect_err("expired email verification token at insert should fail");

    assert_constraint_error(&err, "email_verification_tokens_expires_after_creation");
}

#[tokio::test]
async fn email_verification_tokens_reject_used_at_before_creation() {
    let db = TestDb::new().await;

    let user_id = insert_user(&db.pool, 613).await;
    let err = sqlx::query(
        "INSERT INTO email_verification_tokens (user_id, token_hash, created_at, expires_at, used_at, target_email)
             VALUES ($1, $2, NOW(), NOW() + INTERVAL '1 hour', NOW() - INTERVAL '1 minute', $3)",
    )
    .bind(user_id)
    .bind(fixed_hash(23))
    .bind(sample_email(613))
    .execute(&db.pool)
    .await
    .expect_err("used_at before creation should fail");

    assert_constraint_error(&err, "email_verification_tokens_used_after_creation");
}

#[tokio::test]
async fn email_verification_tokens_active_query_excludes_used_tokens() {
    let db = TestDb::new().await;

    let user_id = insert_user(&db.pool, 614).await;
    sqlx::query(
        "INSERT INTO email_verification_tokens (user_id, token_hash, expires_at, target_email)
             VALUES ($1, $2, NOW() + INTERVAL '1 hour', $3)",
    )
    .bind(user_id)
    .bind(fixed_hash(24))
    .bind(sample_email(614))
    .execute(&db.pool)
    .await
    .expect("failed to insert active token");
    sqlx::query(
        "INSERT INTO email_verification_tokens (user_id, token_hash, expires_at, used_at, target_email)
             VALUES ($1, $2, NOW() + INTERVAL '1 hour', NOW(), $3)",
    )
    .bind(user_id)
    .bind(fixed_hash(25))
    .bind(sample_email(615))
    .execute(&db.pool)
    .await
    .expect("failed to insert used token");

    let count: i64 = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM email_verification_tokens WHERE user_id = $1 AND used_at IS NULL",
    )
    .bind(user_id)
    .fetch_one(&db.pool)
    .await
    .expect("failed to count active email verification tokens");

    assert_eq!(count, 1);
}

#[tokio::test]
async fn email_verification_tokens_cleanup_removes_only_expired_unused_tokens() {
    let db = TestDb::new().await;

    let expired_user_id = insert_user(&db.pool, 615).await;
    let active_user_id = insert_user(&db.pool, 616).await;
    let used_user_id = insert_user(&db.pool, 617).await;
    sqlx::query(
        "INSERT INTO email_verification_tokens (user_id, token_hash, created_at, expires_at, target_email)
             VALUES ($1, $2, NOW() - INTERVAL '2 hours', NOW() - INTERVAL '1 hour', $3)",
    )
    .bind(expired_user_id)
    .bind(fixed_hash(26))
    .bind(sample_email(6151))
    .execute(&db.pool)
    .await
    .expect("failed to insert expired unused token");
    sqlx::query(
        "INSERT INTO email_verification_tokens (user_id, token_hash, expires_at, target_email)
             VALUES ($1, $2, NOW() + INTERVAL '1 hour', $3)",
    )
    .bind(active_user_id)
    .bind(fixed_hash(27))
    .bind(sample_email(616))
    .execute(&db.pool)
    .await
    .expect("failed to insert active unused token");
    sqlx::query(
        "INSERT INTO email_verification_tokens (user_id, token_hash, created_at, expires_at, used_at, target_email)
             VALUES ($1, $2, NOW() - INTERVAL '2 hours', NOW() - INTERVAL '1 hour', NOW() - INTERVAL '30 minutes', $3)",
    )
    .bind(used_user_id)
    .bind(fixed_hash(28))
    .bind(sample_email(617))
    .execute(&db.pool)
    .await
    .expect("failed to insert used token");

    let deleted = sqlx::query(
        "DELETE FROM email_verification_tokens
             WHERE expires_at < NOW() AND used_at IS NULL",
    )
    .execute(&db.pool)
    .await
    .expect("failed to cleanup email verification tokens")
    .rows_affected();

    let remaining: i64 = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM email_verification_tokens
             WHERE user_id IN ($1, $2, $3)",
    )
    .bind(expired_user_id)
    .bind(active_user_id)
    .bind(used_user_id)
    .fetch_one(&db.pool)
    .await
    .expect("failed to count remaining email verification tokens");

    assert_eq!(deleted, 1);
    assert_eq!(remaining, 2);
}

#[tokio::test]
async fn email_verification_tokens_require_a_valid_target_email() {
    let db = TestDb::new().await;

    let user_id = insert_user(&db.pool, 618).await;
    let err = sqlx::query(
        "INSERT INTO email_verification_tokens (user_id, token_hash, expires_at, target_email)
             VALUES ($1, $2, NOW() + INTERVAL '1 hour', 'not-an-email')",
    )
    .bind(user_id)
    .bind(fixed_hash(40))
    .execute(&db.pool)
    .await
    .expect_err("invalid target email should fail");

    assert_constraint_error(&err, "email_verification_tokens_target_email_format");
}

#[tokio::test]
async fn email_verification_tokens_can_target_a_new_email_address() {
    let db = TestDb::new().await;

    let user_id = insert_user(&db.pool, 619).await;
    let target_email = "pending-change@example.com";

    let stored_target_email = sqlx::query_scalar::<_, String>(
        "INSERT INTO email_verification_tokens (user_id, token_hash, expires_at, target_email)
             VALUES ($1, $2, NOW() + INTERVAL '1 hour', $3)
             RETURNING target_email",
    )
    .bind(user_id)
    .bind(fixed_hash(41))
    .bind(target_email)
    .fetch_one(&db.pool)
    .await
    .expect("failed to insert email verification token for a new address");

    assert_eq!(stored_target_email, target_email);
}
