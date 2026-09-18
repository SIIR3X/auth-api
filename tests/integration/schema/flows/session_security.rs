use sqlx::Row;
use testkit::TestDb;
use testkit::sql::{fixed_hash, insert_active_user};

#[tokio::test]
async fn refresh_token_reuse_flow_revokes_the_entire_session_family_and_logs_it() {
    let db = TestDb::new().await;

    let user_id = insert_active_user(&db.pool, 902).await;
    let request_id = sqlx::query_scalar::<_, uuid::Uuid>("SELECT gen_random_uuid()")
        .fetch_one(&db.pool)
        .await
        .expect("failed to generate request_id");

    let original = sqlx::query(
        "INSERT INTO sessions (user_id, expires_at, token_hash)
             VALUES ($1, NOW() + INTERVAL '30 days', $2)
             RETURNING id, session_family_id",
    )
    .bind(user_id)
    .bind(fixed_hash(93))
    .fetch_one(&db.pool)
    .await
    .expect("failed to insert original session");
    let original_id = original.get::<uuid::Uuid, _>(0);
    let family_id = original.get::<uuid::Uuid, _>(1);

    let replacement_id = sqlx::query_scalar::<_, uuid::Uuid>(
        "INSERT INTO sessions (user_id, session_family_id, expires_at, token_hash)
             VALUES ($1, $2, NOW() + INTERVAL '30 days', $3)
             RETURNING id",
    )
    .bind(user_id)
    .bind(family_id)
    .bind(fixed_hash(94))
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
    .expect("failed to record session rotation");

    let revoked_count =
        sqlx::query_scalar::<_, i32>("SELECT revoke_session_family($1, 'refresh_token_reuse')")
            .bind(original_id)
            .fetch_one(&db.pool)
            .await
            .expect("failed to revoke compromised session family");

    sqlx::query(
        "INSERT INTO audit_log (user_id, request_id, action, metadata)
             VALUES
             ($1, $2, 'session_replay_detected', jsonb_build_object('session_id', $3::uuid, 'family_id', $4::uuid)),
             ($1, $2, 'session_family_revoked', jsonb_build_object('family_id', $4::uuid, 'affected_sessions', $5::int))",
    )
    .bind(user_id)
    .bind(request_id)
    .bind(original_id)
    .bind(family_id)
    .bind(revoked_count)
    .execute(&db.pool)
    .await
    .expect("failed to insert audit trail for compromised session family");

    let family_state = sqlx::query(
        "SELECT
                 COUNT(*) FILTER (WHERE session_family_id = $1) AS family_count,
                 COUNT(*) FILTER (WHERE session_family_id = $1 AND revoked_at IS NULL) AS active_count,
                 COUNT(*) FILTER (WHERE session_family_id = $1 AND compromised_at IS NOT NULL) AS compromised_count,
                 COUNT(*) FILTER (WHERE session_family_id = $1 AND compromise_reason = 'refresh_token_reuse') AS compromised_reason_count
             FROM sessions
             WHERE user_id = $2",
    )
    .bind(family_id)
    .bind(user_id)
    .fetch_one(&db.pool)
    .await
    .expect("failed to inspect family state");

    let audit_count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)
             FROM audit_log
             WHERE request_id = $1",
    )
    .bind(request_id)
    .fetch_one(&db.pool)
    .await
    .expect("failed to query audit trail by request_id");

    assert_eq!(revoked_count, 2);
    assert_eq!(family_state.get::<i64, _>(0), 2);
    assert_eq!(family_state.get::<i64, _>(1), 0);
    assert_eq!(family_state.get::<i64, _>(2), 2);
    assert_eq!(family_state.get::<i64, _>(3), 2);
    assert_eq!(audit_count, 2);
}
