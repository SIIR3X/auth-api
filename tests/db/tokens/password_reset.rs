use crate::common::db::{TestDatabase, assert_constraint};
use crate::common::fixtures::{fixed_hash, insert_user};

#[test]
fn password_reset_tokens_require_future_expiration() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 62);
    let err = db
        .client()
        .execute(
            "INSERT INTO password_reset_tokens (user_id, token_hash, created_at, expires_at)
             VALUES ($1, $2, NOW(), NOW() - INTERVAL '1 minute')",
            &[&user_id, &fixed_hash(8)],
        )
        .expect_err("expired password reset token at insert should fail");

    assert_constraint(&err, "password_reset_tokens_expires_after_creation");
}

#[test]
fn password_reset_tokens_enforce_unique_hashes() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let first_user_id = insert_user(db.client(), 621);
    let second_user_id = insert_user(db.client(), 6220);
    let token_hash = fixed_hash(31);

    db.client()
        .execute(
            "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
             VALUES ($1, $2, NOW() + INTERVAL '1 hour')",
            &[&first_user_id, &token_hash],
        )
        .expect("failed to insert first password reset token");

    let err = db
        .client()
        .execute(
            "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
             VALUES ($1, $2, NOW() + INTERVAL '1 hour')",
            &[&second_user_id, &token_hash],
        )
        .expect_err("duplicate password reset token hash should fail");

    assert_constraint(&err, "password_reset_tokens_token_hash_key");
}

#[test]
fn password_reset_tokens_allow_only_one_unused_token_per_user() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 6211);
    db.client()
        .execute(
            "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
             VALUES ($1, $2, NOW() + INTERVAL '1 hour')",
            &[&user_id, &fixed_hash(38)],
        )
        .expect("failed to insert first unused password reset token");

    let err = db
        .client()
        .execute(
            "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
             VALUES ($1, $2, NOW() + INTERVAL '1 hour')",
            &[&user_id, &fixed_hash(39)],
        )
        .expect_err("a second unused password reset token should fail");

    assert_constraint(&err, "idx_password_reset_tokens_user_active");
}

#[test]
fn password_reset_tokens_reject_used_at_before_creation() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 622);
    let err = db
        .client()
        .execute(
            "INSERT INTO password_reset_tokens (user_id, token_hash, created_at, expires_at, used_at)
             VALUES ($1, $2, NOW(), NOW() + INTERVAL '1 hour', NOW() - INTERVAL '1 minute')",
            &[&user_id, &fixed_hash(32)],
        )
        .expect_err("used_at before creation should fail");

    assert_constraint(&err, "password_reset_tokens_used_after_creation");
}

#[test]
fn password_reset_tokens_active_query_excludes_used_tokens() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 623);
    db.client()
        .execute(
            "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
             VALUES ($1, $2, NOW() + INTERVAL '1 hour')",
            &[&user_id, &fixed_hash(33)],
        )
        .expect("failed to insert active password reset token");
    db.client()
        .execute(
            "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at, used_at)
             VALUES ($1, $2, NOW() + INTERVAL '1 hour', NOW())",
            &[&user_id, &fixed_hash(34)],
        )
        .expect("failed to insert used password reset token");

    let count: i64 = db
        .client()
        .query_one(
            "SELECT COUNT(*) FROM password_reset_tokens WHERE user_id = $1 AND used_at IS NULL",
            &[&user_id],
        )
        .expect("failed to count active password reset tokens")
        .get(0);

    assert_eq!(count, 1);
}

#[test]
fn password_reset_tokens_cleanup_removes_only_expired_unused_tokens() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let expired_user_id = insert_user(db.client(), 624);
    let active_user_id = insert_user(db.client(), 625);
    let used_user_id = insert_user(db.client(), 626);
    db.client()
        .execute(
            "INSERT INTO password_reset_tokens (user_id, token_hash, created_at, expires_at)
             VALUES ($1, $2, NOW() - INTERVAL '2 hours', NOW() - INTERVAL '1 hour')",
            &[&expired_user_id, &fixed_hash(35)],
        )
        .expect("failed to insert expired unused token");
    db.client()
        .execute(
            "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
             VALUES ($1, $2, NOW() + INTERVAL '1 hour')",
            &[&active_user_id, &fixed_hash(36)],
        )
        .expect("failed to insert active unused token");
    db.client()
        .execute(
            "INSERT INTO password_reset_tokens (user_id, token_hash, created_at, expires_at, used_at)
             VALUES ($1, $2, NOW() - INTERVAL '2 hours', NOW() - INTERVAL '1 hour', NOW() - INTERVAL '30 minutes')",
            &[&used_user_id, &fixed_hash(37)],
        )
        .expect("failed to insert used token");

    let deleted = db
        .client()
        .execute(
            "DELETE FROM password_reset_tokens
             WHERE expires_at < NOW() AND used_at IS NULL",
            &[],
        )
        .expect("failed to cleanup password reset tokens");

    let remaining: i64 = db
        .client()
        .query_one(
            "SELECT COUNT(*) FROM password_reset_tokens
             WHERE user_id IN ($1, $2, $3)",
            &[&expired_user_id, &active_user_id, &used_user_id],
        )
        .expect("failed to count remaining password reset tokens")
        .get(0);

    assert_eq!(deleted, 1);
    assert_eq!(remaining, 2);
}
