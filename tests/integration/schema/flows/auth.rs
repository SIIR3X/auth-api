use sqlx::Row;
use testkit::TestDb;
use testkit::sql::{SAMPLE_PASSWORD_HASH, fixed_hash, sample_email, sample_username};

#[tokio::test]
async fn registration_verification_and_login_flow_succeeds() {
    let db = TestDb::new().await;

    let email = sample_email(901);
    let username = sample_username(901);
    let verification_hash = fixed_hash(91);
    let session_hash = fixed_hash(92);

    let user_id = sqlx::query_scalar::<_, uuid::Uuid>(
        "INSERT INTO users (username, email, password_hash)
             VALUES ($1, $2, $3)
             RETURNING id",
    )
    .bind(&username)
    .bind(&email)
    .bind(SAMPLE_PASSWORD_HASH)
    .fetch_one(&db.pool)
    .await
    .expect("failed to register pending user");

    sqlx::query(
        "INSERT INTO email_verification_tokens (user_id, token_hash, expires_at, target_email)
             VALUES ($1, $2, NOW() + INTERVAL '1 hour', $3)",
    )
    .bind(user_id)
    .bind(&verification_hash)
    .bind(&email)
    .execute(&db.pool)
    .await
    .expect("failed to create verification token");

    let verification = sqlx::query(
        "UPDATE email_verification_tokens
             SET used_at = NOW()
             WHERE token_hash = $1
               AND used_at IS NULL
               AND expires_at > NOW()
             RETURNING user_id, target_email",
    )
    .bind(&verification_hash)
    .fetch_one(&db.pool)
    .await
    .expect("failed to consume verification token");

    let verified_user_id = verification.get::<uuid::Uuid, _>(0);
    let target_email = verification.get::<String, _>(1);
    assert_eq!(verified_user_id, user_id);
    assert_eq!(target_email, email);

    sqlx::query(
        "UPDATE users
             SET email_verified_at = NOW(),
                 status = 'active'
             WHERE id = $1
               AND email = $2",
    )
    .bind(user_id)
    .bind(&target_email)
    .execute(&db.pool)
    .await
    .expect("failed to activate verified user");

    sqlx::query(
        "INSERT INTO sessions (user_id, expires_at, token_hash)
             VALUES ($1, NOW() + INTERVAL '30 days', $2)",
    )
    .bind(user_id)
    .bind(&session_hash)
    .execute(&db.pool)
    .await
    .expect("failed to create login session");

    let status = sqlx::query(
        "SELECT status::text, email_verified_at IS NOT NULL
             FROM users
             WHERE id = $1",
    )
    .bind(user_id)
    .fetch_one(&db.pool)
    .await
    .expect("failed to reload verified user");

    let user_status = status.get::<String, _>(0);
    let is_verified = status.get::<bool, _>(1);
    let active_sessions = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)
             FROM sessions
             WHERE user_id = $1
               AND revoked_at IS NULL",
    )
    .bind(user_id)
    .fetch_one(&db.pool)
    .await
    .expect("failed to count active sessions");

    assert_eq!(user_status, "active");
    assert!(is_verified);
    assert_eq!(active_sessions, 1);
}
