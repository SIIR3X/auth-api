use testkit::TestDb;
use testkit::sql::{SAMPLE_PASSWORD_HASH, assert_constraint_error, sample_email};

#[tokio::test]
async fn users_reject_invalid_email_format() {
    let db = TestDb::new().await;

    let err = sqlx::query(
        "INSERT INTO users (username, email, password_hash)
             VALUES ($1, $2, $3)",
    )
    .bind("bad_email_user")
    .bind("not-an-email")
    .bind(SAMPLE_PASSWORD_HASH)
    .execute(&db.pool)
    .await
    .expect_err("invalid email should fail");

    assert_constraint_error(&err, "users_email_format");
}

#[tokio::test]
async fn users_enforce_unique_email() {
    let db = TestDb::new().await;

    let email = sample_email(1);
    sqlx::query(
        "INSERT INTO users (username, email, password_hash)
             VALUES ($1, $2, $3)",
    )
    .bind("user_unique_a")
    .bind(&email)
    .bind(SAMPLE_PASSWORD_HASH)
    .execute(&db.pool)
    .await
    .expect("failed to insert first user");

    let err = sqlx::query(
        "INSERT INTO users (username, email, password_hash)
             VALUES ($1, $2, $3)",
    )
    .bind("user_unique_b")
    .bind(&email)
    .bind(SAMPLE_PASSWORD_HASH)
    .execute(&db.pool)
    .await
    .expect_err("duplicate email should fail");

    assert_constraint_error(&err, "users_email_key");
}

#[tokio::test]
async fn users_enforce_unique_email_case_insensitively() {
    let db = TestDb::new().await;

    sqlx::query(
        "INSERT INTO users (username, email, password_hash)
             VALUES ($1, $2, $3)",
    )
    .bind("case_user_a")
    .bind("Case@Test.dev")
    .bind(SAMPLE_PASSWORD_HASH)
    .execute(&db.pool)
    .await
    .expect("failed to insert first user");

    let err = sqlx::query(
        "INSERT INTO users (username, email, password_hash)
             VALUES ($1, $2, $3)",
    )
    .bind("case_user_b")
    .bind("case@test.dev")
    .bind(SAMPLE_PASSWORD_HASH)
    .execute(&db.pool)
    .await
    .expect_err("case-insensitive duplicate email should fail");

    assert_constraint_error(&err, "users_email_key");
}

#[tokio::test]
async fn users_enforce_unique_username() {
    let db = TestDb::new().await;

    sqlx::query(
        "INSERT INTO users (username, email, password_hash)
             VALUES ($1, $2, $3)",
    )
    .bind("same_name")
    .bind(sample_email(100))
    .bind(SAMPLE_PASSWORD_HASH)
    .execute(&db.pool)
    .await
    .expect("failed to insert first username");

    let err = sqlx::query(
        "INSERT INTO users (username, email, password_hash)
             VALUES ($1, $2, $3)",
    )
    .bind("same_name")
    .bind(sample_email(101))
    .bind(SAMPLE_PASSWORD_HASH)
    .execute(&db.pool)
    .await
    .expect_err("duplicate username should fail");

    assert_constraint_error(&err, "users_username_key");
}

#[tokio::test]
async fn users_reject_invalid_username_format() {
    let db = TestDb::new().await;

    let err = sqlx::query(
        "INSERT INTO users (username, email, password_hash)
             VALUES ($1, $2, $3)",
    )
    .bind("no spaces allowed")
    .bind(sample_email(102))
    .bind(SAMPLE_PASSWORD_HASH)
    .execute(&db.pool)
    .await
    .expect_err("invalid username should fail");

    assert_constraint_error(&err, "users_username_format");
}

#[tokio::test]
async fn users_reject_too_short_password_hash() {
    let db = TestDb::new().await;

    let short_hash = "short_hash_value";
    let err = sqlx::query(
        "INSERT INTO users (username, email, password_hash)
             VALUES ($1, $2, $3)",
    )
    .bind("short_hash_user")
    .bind(sample_email(103))
    .bind(short_hash)
    .execute(&db.pool)
    .await
    .expect_err("short password hash should fail");

    assert_constraint_error(&err, "users_password_hash_min_length");
}

#[tokio::test]
async fn users_reject_pending_verification_with_verified_timestamp() {
    let db = TestDb::new().await;

    let err = sqlx::query(
        "INSERT INTO users (username, email, password_hash, status, email_verified_at)
             VALUES ($1, $2, $3, 'pending_verification', NOW())",
    )
    .bind("pending_conflict")
    .bind(sample_email(8))
    .bind(SAMPLE_PASSWORD_HASH)
    .execute(&db.pool)
    .await
    .expect_err("pending verification user should not have email_verified_at");

    assert_constraint_error(&err, "users_status_email_verification_consistency");
}

#[tokio::test]
async fn users_require_verified_email_for_active_status() {
    let db = TestDb::new().await;

    let err = sqlx::query(
        "INSERT INTO users (username, email, password_hash, status)
             VALUES ($1, $2, $3, 'active')",
    )
    .bind("active_without_verification")
    .bind(sample_email(104))
    .bind(SAMPLE_PASSWORD_HASH)
    .execute(&db.pool)
    .await
    .expect_err("active users should require email_verified_at");

    assert_constraint_error(&err, "users_status_email_verification_consistency");
}

#[tokio::test]
async fn users_allow_verified_email_for_active_status() {
    let db = TestDb::new().await;

    sqlx::query(
        "INSERT INTO users (username, email, password_hash, status, email_verified_at)
             VALUES ($1, $2, $3, 'active', NOW())",
    )
    .bind("active_verified")
    .bind(sample_email(105))
    .bind(SAMPLE_PASSWORD_HASH)
    .execute(&db.pool)
    .await
    .expect("active verified user should be allowed");
}
