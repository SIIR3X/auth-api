use sqlx::Row;
use std::time::Duration;
use testkit::TestDb;
use testkit::sql::{insert_user, sample_email};

#[tokio::test]
async fn deleting_user_cascades_to_sessions_and_tokens() {
    let db = TestDb::new().await;

    let user_id = insert_user(&db.pool, 21).await;

    sqlx::query(
        "INSERT INTO sessions (user_id, expires_at, token_hash)
             VALUES ($1, NOW() + INTERVAL '1 day', $2)",
    )
    .bind(user_id)
    .bind(vec![1_u8; 32])
    .execute(&db.pool)
    .await
    .expect("failed to insert session");
    sqlx::query(
        "INSERT INTO email_verification_tokens (user_id, token_hash, expires_at, target_email)
             VALUES ($1, $2, NOW() + INTERVAL '1 day', $3)",
    )
    .bind(user_id)
    .bind(vec![2_u8; 32])
    .bind(sample_email(21))
    .execute(&db.pool)
    .await
    .expect("failed to insert email verification token");

    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&db.pool)
        .await
        .expect("failed to delete user");

    let sessions: i64 =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sessions WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&db.pool)
            .await
            .expect("failed to count sessions");
    let tokens: i64 = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM email_verification_tokens WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_one(&db.pool)
    .await
    .expect("failed to count tokens");

    assert_eq!(sessions, 0);
    assert_eq!(tokens, 0);
}

#[tokio::test]
async fn deleting_user_cascades_to_roles_two_factor_and_recovery_data() {
    let db = TestDb::new().await;

    let user_id = insert_user(&db.pool, 22).await;
    let role_id = sqlx::query_scalar::<_, uuid::Uuid>("SELECT id FROM roles WHERE name = 'user'")
        .fetch_one(&db.pool)
        .await
        .expect("failed to load default role");

    sqlx::query("INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)")
        .bind(user_id)
        .bind(role_id)
        .execute(&db.pool)
        .await
        .expect("failed to insert user role");
    sqlx::query(
        "INSERT INTO two_factor_methods (user_id, method_type, is_verified)
             VALUES ($1, 'email', TRUE)",
    )
    .bind(user_id)
    .execute(&db.pool)
    .await
    .expect("failed to insert email 2fa");
    sqlx::query(
        "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
             VALUES ($1, $2, NOW() + INTERVAL '1 day')",
    )
    .bind(user_id)
    .bind(vec![3_u8; 32])
    .execute(&db.pool)
    .await
    .expect("failed to insert password reset token");
    sqlx::query(
        "INSERT INTO recovery_codes (user_id, code_position, code_hash)
             VALUES ($1, 1, $2)",
    )
    .bind(user_id)
    .bind(vec![4_u8; 32])
    .execute(&db.pool)
    .await
    .expect("failed to insert recovery code");

    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&db.pool)
        .await
        .expect("failed to delete user");

    let user_roles: i64 =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM user_roles WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&db.pool)
            .await
            .expect("failed to count user roles");
    let two_factor: i64 =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM two_factor_methods WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&db.pool)
            .await
            .expect("failed to count 2fa methods");
    let password_resets: i64 = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM password_reset_tokens WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_one(&db.pool)
    .await
    .expect("failed to count password reset tokens");
    let recovery_codes: i64 =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM recovery_codes WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&db.pool)
            .await
            .expect("failed to count recovery codes");

    assert_eq!(user_roles, 0);
    assert_eq!(two_factor, 0);
    assert_eq!(password_resets, 0);
    assert_eq!(recovery_codes, 0);
}

#[tokio::test]
async fn updating_user_touches_updated_at() {
    let db = TestDb::new().await;

    let row = sqlx::query(
        "INSERT INTO users (username, email, password_hash)
             VALUES ($1, $2, $3)
             RETURNING id, updated_at",
    )
    .bind("updated_user")
    .bind("updated@example.com")
    .bind(testkit::sql::SAMPLE_PASSWORD_HASH)
    .fetch_one(&db.pool)
    .await
    .expect("failed to insert user");
    let user_id = row.get::<uuid::Uuid, _>(0);
    let first_updated_at = row.get::<time::OffsetDateTime, _>(1);

    tokio::time::sleep(Duration::from_millis(5)).await;

    let second_updated_at = sqlx::query_scalar::<_, time::OffsetDateTime>(
        "UPDATE users
             SET preferred_locale = 'fr'
             WHERE id = $1
             RETURNING updated_at",
    )
    .bind(user_id)
    .fetch_one(&db.pool)
    .await
    .expect("failed to update user");

    assert!(second_updated_at > first_updated_at);
}
