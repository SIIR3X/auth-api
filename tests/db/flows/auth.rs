use crate::common::db::TestDatabase;
use crate::common::fixtures::{SAMPLE_PASSWORD_HASH, fixed_hash, sample_email, sample_username};

#[test]
fn registration_verification_and_login_flow_succeeds() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let email = sample_email(901);
    let username = sample_username(901);
    let verification_hash = fixed_hash(91);
    let session_hash = fixed_hash(92);

    let user_id = db
        .client()
        .query_one(
            "INSERT INTO users (username, email, password_hash)
             VALUES ($1, $2, $3)
             RETURNING id",
            &[&username, &email, &SAMPLE_PASSWORD_HASH],
        )
        .expect("failed to register pending user")
        .get::<_, uuid::Uuid>(0);

    db.client()
        .execute(
            "INSERT INTO email_verification_tokens (user_id, token_hash, expires_at, target_email)
             VALUES ($1, $2, NOW() + INTERVAL '1 hour', $3)",
            &[&user_id, &verification_hash, &email],
        )
        .expect("failed to create verification token");

    let verification = db
        .client()
        .query_one(
            "UPDATE email_verification_tokens
             SET used_at = NOW()
             WHERE token_hash = $1
               AND used_at IS NULL
               AND expires_at > NOW()
             RETURNING user_id, target_email",
            &[&verification_hash],
        )
        .expect("failed to consume verification token");

    let verified_user_id = verification.get::<_, uuid::Uuid>(0);
    let target_email = verification.get::<_, String>(1);
    assert_eq!(verified_user_id, user_id);
    assert_eq!(target_email, email);

    db.client()
        .execute(
            "UPDATE users
             SET email_verified_at = NOW(),
                 status = 'active'
             WHERE id = $1
               AND email = $2",
            &[&user_id, &target_email],
        )
        .expect("failed to activate verified user");

    db.client()
        .execute(
            "INSERT INTO sessions (user_id, expires_at, token_hash)
             VALUES ($1, NOW() + INTERVAL '30 days', $2)",
            &[&user_id, &session_hash],
        )
        .expect("failed to create login session");

    let status = db
        .client()
        .query_one(
            "SELECT status::text, email_verified_at IS NOT NULL
             FROM users
             WHERE id = $1",
            &[&user_id],
        )
        .expect("failed to reload verified user");

    let user_status = status.get::<_, String>(0);
    let is_verified = status.get::<_, bool>(1);
    let active_sessions = db
        .client()
        .query_one(
            "SELECT COUNT(*)
             FROM sessions
             WHERE user_id = $1
               AND revoked_at IS NULL",
            &[&user_id],
        )
        .expect("failed to count active sessions")
        .get::<_, i64>(0);

    assert_eq!(user_status, "active");
    assert!(is_verified);
    assert_eq!(active_sessions, 1);
}
