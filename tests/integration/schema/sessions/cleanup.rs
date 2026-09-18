use sqlx::{PgPool, Row};
use testkit::TestDb;
use testkit::sql::{fixed_hash, insert_user};

#[tokio::test]
async fn sessions_track_only_non_revoked_rows_as_active() {
    let db = TestDb::new().await;

    let user_id = insert_user(&db.pool, 33).await;
    sqlx::query(
        "INSERT INTO sessions (user_id, expires_at, token_hash)
             VALUES ($1, NOW() + INTERVAL '1 day', $2)",
    )
    .bind(user_id)
    .bind(fixed_hash(5))
    .execute(&db.pool)
    .await
    .expect("failed to insert active session");
    sqlx::query(
        "INSERT INTO sessions (user_id, expires_at, revoked_at, token_hash)
             VALUES ($1, NOW() + INTERVAL '1 day', NOW(), $2)",
    )
    .bind(user_id)
    .bind(fixed_hash(6))
    .execute(&db.pool)
    .await
    .expect("failed to insert revoked session");

    let count: i64 = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .fetch_one(&db.pool)
    .await
    .expect("failed to count active sessions");

    assert_eq!(count, 1);
}

#[tokio::test]
async fn sessions_cleanup_query_removes_only_expired_active_sessions() {
    let db = TestDb::new().await;

    let user_id = insert_user(&db.pool, 34).await;
    sqlx::query(
        "INSERT INTO sessions (user_id, created_at, expires_at, token_hash)
             VALUES
             ($1, NOW() - INTERVAL '2 hours', NOW() - INTERVAL '1 hour', $2),
             ($1, NOW(), NOW() + INTERVAL '1 hour', $3),
             ($1, NOW() - INTERVAL '2 hours', NOW() - INTERVAL '1 hour', $4)",
    )
    .bind(user_id)
    .bind(fixed_hash(11))
    .bind(fixed_hash(12))
    .bind(fixed_hash(13))
    .execute(&db.pool)
    .await
    .expect("failed to insert test sessions");
    sqlx::query(
        "UPDATE sessions
             SET revoked_at = NOW()
             WHERE user_id = $1 AND token_hash = $2",
    )
    .bind(user_id)
    .bind(fixed_hash(13))
    .execute(&db.pool)
    .await
    .expect("failed to revoke one expired session");

    let deleted = sqlx::query(
        "DELETE FROM sessions
             WHERE expires_at < NOW() AND revoked_at IS NULL",
    )
    .execute(&db.pool)
    .await
    .expect("failed to run cleanup query")
    .rows_affected();

    let remaining: i64 =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sessions WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&db.pool)
            .await
            .expect("failed to count remaining sessions");

    assert_eq!(deleted, 1);
    assert_eq!(remaining, 2);
}

#[tokio::test]
async fn rotated_sessions_share_a_family_and_leave_only_the_replacement_active() {
    let db = TestDb::new().await;

    let user_id = insert_user(&db.pool, 35).await;
    let original = sqlx::query(
        "INSERT INTO sessions (user_id, expires_at, token_hash)
             VALUES ($1, NOW() + INTERVAL '1 day', $2)
             RETURNING id, session_family_id",
    )
    .bind(user_id)
    .bind(fixed_hash(18))
    .fetch_one(&db.pool)
    .await
    .expect("failed to insert original session");
    let original_id = original.get::<uuid::Uuid, _>(0);
    let family_id = original.get::<uuid::Uuid, _>(1);

    let replacement_id = sqlx::query_scalar::<_, uuid::Uuid>(
        "INSERT INTO sessions (user_id, session_family_id, expires_at, token_hash)
             VALUES ($1, $2, NOW() + INTERVAL '1 day', $3)
             RETURNING id",
    )
    .bind(user_id)
    .bind(family_id)
    .bind(fixed_hash(19))
    .fetch_one(&db.pool)
    .await
    .expect("failed to insert replacement session");

    sqlx::query(
        "UPDATE sessions
             SET revoked_at = NOW(),
                 rotated_at = NOW(),
                 replaced_by_session_id = $2
             WHERE id = $1",
    )
    .bind(original_id)
    .bind(replacement_id)
    .execute(&db.pool)
    .await
    .expect("failed to rotate original session");

    let counts = sqlx::query(
        "SELECT
                 COUNT(*) FILTER (WHERE session_family_id = $1) AS family_count,
                 COUNT(*) FILTER (WHERE session_family_id = $1 AND revoked_at IS NULL) AS active_count
             FROM sessions
             WHERE user_id = $2",
    )
    .bind(family_id)
    .bind(user_id)
    .fetch_one(&db.pool)
    .await
    .expect("failed to inspect rotated sessions");

    let family_count = counts.get::<i64, _>(0);
    let active_count = counts.get::<i64, _>(1);

    assert_eq!(family_count, 2);
    assert_eq!(active_count, 1);
}

#[tokio::test]
async fn sessions_cleanup_function_honours_grace_and_batch_size() {
    let db = TestDb::new().await;

    let user_id = insert_user(&db.pool, 36).await;
    sqlx::query(
        "INSERT INTO sessions (user_id, created_at, expires_at, revoked_at, token_hash)
             VALUES
             ($1, NOW() - INTERVAL '30 days', NOW() - INTERVAL '10 days', NULL, $2),
             ($1, NOW() - INTERVAL '30 days', NOW() - INTERVAL '10 days', NULL, $3),
             ($1, NOW() - INTERVAL '30 days', NOW() - INTERVAL '10 days', NULL, $4),
             ($1, NOW() - INTERVAL '30 days', NOW() + INTERVAL '10 days', NOW() - INTERVAL '10 days', $5),
             ($1, NOW() - INTERVAL '2 days', NOW() - INTERVAL '1 day', NULL, $6),
             ($1, NOW(), NOW() + INTERVAL '1 day', NULL, $7)",
    )
    .bind(user_id)
    .bind(fixed_hash(40))
    .bind(fixed_hash(41))
    .bind(fixed_hash(42))
    .bind(fixed_hash(43))
    .bind(fixed_hash(44))
    .bind(fixed_hash(45))
    .execute(&db.pool)
    .await
    .expect("failed to insert test sessions");

    // Four rows are past the grace period (three expired, one revoked); a batch
    // deletes at most three, the next one the rest.
    assert_eq!(sweep(&db.pool).await, 3);
    assert_eq!(sweep(&db.pool).await, 1);
    assert_eq!(sweep(&db.pool).await, 0);

    let remaining: i64 =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sessions WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&db.pool)
            .await
            .expect("failed to count remaining sessions");
    assert_eq!(remaining, 2, "recently expired and active sessions stay");
}

async fn sweep(pool: &PgPool) -> i32 {
    sqlx::query_scalar::<_, i32>("SELECT cleanup_expired_sessions('7 days'::interval, 3)")
        .fetch_one(pool)
        .await
        .expect("failed to run cleanup function")
}
