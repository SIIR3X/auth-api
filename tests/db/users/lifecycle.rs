use crate::common::db::TestDatabase;
use crate::common::fixtures::{insert_user, sample_email};
use std::thread;
use std::time::Duration;

#[test]
fn deleting_user_cascades_to_sessions_and_tokens() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 21);

    db.client()
        .execute(
            "INSERT INTO sessions (user_id, expires_at, token_hash)
             VALUES ($1, NOW() + INTERVAL '1 day', $2)",
            &[&user_id, &vec![1_u8; 32]],
        )
        .expect("failed to insert session");
    db.client()
        .execute(
            "INSERT INTO email_verification_tokens (user_id, token_hash, expires_at, target_email)
             VALUES ($1, $2, NOW() + INTERVAL '1 day', $3)",
            &[&user_id, &vec![2_u8; 32], &sample_email(21)],
        )
        .expect("failed to insert email verification token");

    db.client()
        .execute("DELETE FROM users WHERE id = $1", &[&user_id])
        .expect("failed to delete user");

    let sessions: i64 = db
        .client()
        .query_one("SELECT COUNT(*) FROM sessions WHERE user_id = $1", &[&user_id])
        .expect("failed to count sessions")
        .get(0);
    let tokens: i64 = db
        .client()
        .query_one(
            "SELECT COUNT(*) FROM email_verification_tokens WHERE user_id = $1",
            &[&user_id],
        )
        .expect("failed to count tokens")
        .get(0);

    assert_eq!(sessions, 0);
    assert_eq!(tokens, 0);
}

#[test]
fn deleting_user_cascades_to_roles_two_factor_and_recovery_data() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 22);
    let role_id = db
        .client()
        .query_one("SELECT id FROM roles WHERE name = 'user'", &[])
        .expect("failed to load default role")
        .get::<_, uuid::Uuid>(0);

    db.client()
        .execute(
            "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)",
            &[&user_id, &role_id],
        )
        .expect("failed to insert user role");
    db.client()
        .execute(
            "INSERT INTO two_factor_methods (user_id, method_type, is_verified)
             VALUES ($1, 'email', TRUE)",
            &[&user_id],
        )
        .expect("failed to insert email 2fa");
    db.client()
        .execute(
            "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
             VALUES ($1, $2, NOW() + INTERVAL '1 day')",
            &[&user_id, &vec![3_u8; 32]],
        )
        .expect("failed to insert password reset token");
    db.client()
        .execute(
            "INSERT INTO recovery_codes (user_id, code_position, code_hash)
             VALUES ($1, 1, $2)",
            &[&user_id, &vec![4_u8; 32]],
        )
        .expect("failed to insert recovery code");

    db.client()
        .execute("DELETE FROM users WHERE id = $1", &[&user_id])
        .expect("failed to delete user");

    let user_roles: i64 = db
        .client()
        .query_one("SELECT COUNT(*) FROM user_roles WHERE user_id = $1", &[&user_id])
        .expect("failed to count user roles")
        .get(0);
    let two_factor: i64 = db
        .client()
        .query_one(
            "SELECT COUNT(*) FROM two_factor_methods WHERE user_id = $1",
            &[&user_id],
        )
        .expect("failed to count 2fa methods")
        .get(0);
    let password_resets: i64 = db
        .client()
        .query_one(
            "SELECT COUNT(*) FROM password_reset_tokens WHERE user_id = $1",
            &[&user_id],
        )
        .expect("failed to count password reset tokens")
        .get(0);
    let recovery_codes: i64 = db
        .client()
        .query_one(
            "SELECT COUNT(*) FROM recovery_codes WHERE user_id = $1",
            &[&user_id],
        )
        .expect("failed to count recovery codes")
        .get(0);

    assert_eq!(user_roles, 0);
    assert_eq!(two_factor, 0);
    assert_eq!(password_resets, 0);
    assert_eq!(recovery_codes, 0);
}

#[test]
fn updating_user_touches_updated_at() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let row = db
        .client()
        .query_one(
            "INSERT INTO users (username, email, password_hash)
             VALUES ($1, $2, $3)
             RETURNING id, updated_at",
            &[&"updated_user", &"updated@example.com", &crate::common::fixtures::SAMPLE_PASSWORD_HASH],
        )
        .expect("failed to insert user");
    let user_id = row.get::<_, uuid::Uuid>(0);
    let first_updated_at = row.get::<_, std::time::SystemTime>(1);

    thread::sleep(Duration::from_millis(5));

    let second_updated_at = db
        .client()
        .query_one(
            "UPDATE users
             SET preferred_locale = 'fr'
             WHERE id = $1
             RETURNING updated_at",
            &[&user_id],
        )
        .expect("failed to update user")
        .get::<_, std::time::SystemTime>(0);

    assert!(second_updated_at > first_updated_at);
}
