use crate::common::db::TestDatabase;
use crate::common::fixtures::{fixed_hash, insert_active_user};

#[test]
fn refresh_token_reuse_flow_revokes_the_entire_session_family_and_logs_it() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_active_user(db.client(), 902);
    let request_id = db
        .client()
        .query_one("SELECT gen_random_uuid()", &[])
        .expect("failed to generate request_id")
        .get::<_, uuid::Uuid>(0);

    let original = db
        .client()
        .query_one(
            "INSERT INTO sessions (user_id, expires_at, token_hash)
             VALUES ($1, NOW() + INTERVAL '30 days', $2)
             RETURNING id, session_family_id",
            &[&user_id, &fixed_hash(93)],
        )
        .expect("failed to insert original session");
    let original_id = original.get::<_, uuid::Uuid>(0);
    let family_id = original.get::<_, uuid::Uuid>(1);

    let replacement_id = db
        .client()
        .query_one(
            "INSERT INTO sessions (user_id, session_family_id, expires_at, token_hash)
             VALUES ($1, $2, NOW() + INTERVAL '30 days', $3)
             RETURNING id",
            &[&user_id, &family_id, &fixed_hash(94)],
        )
        .expect("failed to insert replacement session")
        .get::<_, uuid::Uuid>(0);

    db.client()
        .execute(
            "UPDATE sessions
             SET revoked_at = NOW(),
                 rotated_at = NOW(),
                 replaced_by_session_id = $2
             WHERE id = $1",
            &[&original_id, &replacement_id],
        )
        .expect("failed to record session rotation");

    let revoked_count = db
        .client()
        .query_one(
            "SELECT revoke_session_family($1, 'refresh_token_reuse')",
            &[&original_id],
        )
        .expect("failed to revoke compromised session family")
        .get::<_, i32>(0);

    db.client()
        .execute(
            "INSERT INTO audit_log (user_id, request_id, action, metadata)
             VALUES
             ($1, $2, 'session_replay_detected', jsonb_build_object('session_id', $3::uuid, 'family_id', $4::uuid)),
             ($1, $2, 'session_family_revoked', jsonb_build_object('family_id', $4::uuid, 'affected_sessions', $5::int))",
            &[&user_id, &request_id, &original_id, &family_id, &revoked_count],
        )
        .expect("failed to insert audit trail for compromised session family");

    let family_state = db
        .client()
        .query_one(
            "SELECT
                 COUNT(*) FILTER (WHERE session_family_id = $1) AS family_count,
                 COUNT(*) FILTER (WHERE session_family_id = $1 AND revoked_at IS NULL) AS active_count,
                 COUNT(*) FILTER (WHERE session_family_id = $1 AND compromised_at IS NOT NULL) AS compromised_count,
                 COUNT(*) FILTER (WHERE session_family_id = $1 AND compromise_reason = 'refresh_token_reuse') AS compromised_reason_count
             FROM sessions
             WHERE user_id = $2",
            &[&family_id, &user_id],
        )
        .expect("failed to inspect family state");

    let audit_count = db
        .client()
        .query_one(
            "SELECT COUNT(*)
             FROM audit_log
             WHERE request_id = $1",
            &[&request_id],
        )
        .expect("failed to query audit trail by request_id")
        .get::<_, i64>(0);

    assert_eq!(revoked_count, 2);
    assert_eq!(family_state.get::<_, i64>(0), 2);
    assert_eq!(family_state.get::<_, i64>(1), 0);
    assert_eq!(family_state.get::<_, i64>(2), 2);
    assert_eq!(family_state.get::<_, i64>(3), 2);
    assert_eq!(audit_count, 2);
}
