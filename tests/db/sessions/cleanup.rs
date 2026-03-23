use crate::common::db::TestDatabase;
use crate::common::fixtures::{fixed_hash, insert_user};

#[test]
fn sessions_track_only_non_revoked_rows_as_active() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 33);
    db.client()
        .execute(
            "INSERT INTO sessions (user_id, expires_at, token_hash)
             VALUES ($1, NOW() + INTERVAL '1 day', $2)",
            &[&user_id, &fixed_hash(5)],
        )
        .expect("failed to insert active session");
    db.client()
        .execute(
            "INSERT INTO sessions (user_id, expires_at, revoked_at, token_hash)
             VALUES ($1, NOW() + INTERVAL '1 day', NOW(), $2)",
            &[&user_id, &fixed_hash(6)],
        )
        .expect("failed to insert revoked session");

    let count: i64 = db
        .client()
        .query_one(
            "SELECT COUNT(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL",
            &[&user_id],
        )
        .expect("failed to count active sessions")
        .get(0);

    assert_eq!(count, 1);
}

#[test]
fn sessions_cleanup_query_removes_only_expired_active_sessions() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 34);
    db.client()
        .execute(
            "INSERT INTO sessions (user_id, created_at, expires_at, token_hash)
             VALUES
             ($1, NOW() - INTERVAL '2 hours', NOW() - INTERVAL '1 hour', $2),
             ($1, NOW(), NOW() + INTERVAL '1 hour', $3),
             ($1, NOW() - INTERVAL '2 hours', NOW() - INTERVAL '1 hour', $4)",
            &[&user_id, &fixed_hash(11), &fixed_hash(12), &fixed_hash(13)],
        )
        .expect("failed to insert test sessions");
    db.client()
        .execute(
            "UPDATE sessions
             SET revoked_at = NOW()
             WHERE user_id = $1 AND token_hash = $2",
            &[&user_id, &fixed_hash(13)],
        )
        .expect("failed to revoke one expired session");

    let deleted = db
        .client()
        .execute(
            "DELETE FROM sessions
             WHERE expires_at < NOW() AND revoked_at IS NULL",
            &[],
        )
        .expect("failed to run cleanup query");

    let remaining: i64 = db
        .client()
        .query_one(
            "SELECT COUNT(*) FROM sessions WHERE user_id = $1",
            &[&user_id],
        )
        .expect("failed to count remaining sessions")
        .get(0);

    assert_eq!(deleted, 1);
    assert_eq!(remaining, 2);
}

#[test]
fn rotated_sessions_share_a_family_and_leave_only_the_replacement_active() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 35);
    let original = db
        .client()
        .query_one(
            "INSERT INTO sessions (user_id, expires_at, token_hash)
             VALUES ($1, NOW() + INTERVAL '1 day', $2)
             RETURNING id, session_family_id",
            &[&user_id, &fixed_hash(18)],
        )
        .expect("failed to insert original session");
    let original_id = original.get::<_, uuid::Uuid>(0);
    let family_id = original.get::<_, uuid::Uuid>(1);

    let replacement_id = db
        .client()
        .query_one(
            "INSERT INTO sessions (user_id, session_family_id, expires_at, token_hash)
             VALUES ($1, $2, NOW() + INTERVAL '1 day', $3)
             RETURNING id",
            &[&user_id, &family_id, &fixed_hash(19)],
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
        .expect("failed to rotate original session");

    let counts = db
        .client()
        .query_one(
            "SELECT
                 COUNT(*) FILTER (WHERE session_family_id = $1) AS family_count,
                 COUNT(*) FILTER (WHERE session_family_id = $1 AND revoked_at IS NULL) AS active_count
             FROM sessions
             WHERE user_id = $2",
            &[&family_id, &user_id],
        )
        .expect("failed to inspect rotated sessions");

    let family_count = counts.get::<_, i64>(0);
    let active_count = counts.get::<_, i64>(1);

    assert_eq!(family_count, 2);
    assert_eq!(active_count, 1);
}
