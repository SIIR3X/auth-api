use crate::common::db::{TestDatabase, assert_constraint};
use crate::common::fixtures::{fixed_hash, insert_user, sample_email};

#[test]
fn email_verification_tokens_are_fixed_length() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 61);
    let err = db
        .client()
        .execute(
            "INSERT INTO email_verification_tokens (user_id, token_hash, expires_at, target_email)
             VALUES ($1, $2, NOW() + INTERVAL '1 hour', $3)",
            &[&user_id, &vec![1_u8; 30], &sample_email(61)],
        )
        .expect_err("invalid email verification token hash should fail");

    assert_constraint(&err, "email_verification_tokens_token_hash_length");
}

#[test]
fn email_verification_tokens_enforce_unique_hashes() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let first_user_id = insert_user(db.client(), 611);
    let second_user_id = insert_user(db.client(), 6120);
    let token_hash = fixed_hash(21);

    db.client()
        .execute(
            "INSERT INTO email_verification_tokens (user_id, token_hash, expires_at, target_email)
             VALUES ($1, $2, NOW() + INTERVAL '1 hour', $3)",
            &[&first_user_id, &token_hash, &sample_email(611)],
        )
        .expect("failed to insert first email verification token");

    let err = db
        .client()
        .execute(
            "INSERT INTO email_verification_tokens (user_id, token_hash, expires_at, target_email)
             VALUES ($1, $2, NOW() + INTERVAL '1 hour', $3)",
            &[&second_user_id, &token_hash, &sample_email(6120)],
        )
        .expect_err("duplicate email verification token hash should fail");

    assert_constraint(&err, "email_verification_tokens_token_hash_key");
}

#[test]
fn email_verification_tokens_allow_only_one_unused_token_per_user() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 6111);
    db.client()
        .execute(
            "INSERT INTO email_verification_tokens (user_id, token_hash, expires_at, target_email)
             VALUES ($1, $2, NOW() + INTERVAL '1 hour', $3)",
            &[&user_id, &fixed_hash(29), &sample_email(6111)],
        )
        .expect("failed to insert first unused email verification token");

    let err = db
        .client()
        .execute(
            "INSERT INTO email_verification_tokens (user_id, token_hash, expires_at, target_email)
             VALUES ($1, $2, NOW() + INTERVAL '1 hour', $3)",
            &[&user_id, &fixed_hash(30), &sample_email(6112)],
        )
        .expect_err("a second unused email verification token should fail");

    assert_constraint(&err, "idx_email_verification_tokens_user_active");
}

#[test]
fn email_verification_tokens_require_future_expiration() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 612);
    let err = db
        .client()
        .execute(
            "INSERT INTO email_verification_tokens (user_id, token_hash, created_at, expires_at, target_email)
             VALUES ($1, $2, NOW(), NOW() - INTERVAL '1 minute', $3)",
            &[&user_id, &fixed_hash(22), &sample_email(612)],
        )
        .expect_err("expired email verification token at insert should fail");

    assert_constraint(&err, "email_verification_tokens_expires_after_creation");
}

#[test]
fn email_verification_tokens_reject_used_at_before_creation() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 613);
    let err = db
        .client()
        .execute(
            "INSERT INTO email_verification_tokens (user_id, token_hash, created_at, expires_at, used_at, target_email)
             VALUES ($1, $2, NOW(), NOW() + INTERVAL '1 hour', NOW() - INTERVAL '1 minute', $3)",
            &[&user_id, &fixed_hash(23), &sample_email(613)],
        )
        .expect_err("used_at before creation should fail");

    assert_constraint(&err, "email_verification_tokens_used_after_creation");
}

#[test]
fn email_verification_tokens_active_query_excludes_used_tokens() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 614);
    db.client()
        .execute(
            "INSERT INTO email_verification_tokens (user_id, token_hash, expires_at, target_email)
             VALUES ($1, $2, NOW() + INTERVAL '1 hour', $3)",
            &[&user_id, &fixed_hash(24), &sample_email(614)],
        )
        .expect("failed to insert active token");
    db.client()
        .execute(
            "INSERT INTO email_verification_tokens (user_id, token_hash, expires_at, used_at, target_email)
             VALUES ($1, $2, NOW() + INTERVAL '1 hour', NOW(), $3)",
            &[&user_id, &fixed_hash(25), &sample_email(615)],
        )
        .expect("failed to insert used token");

    let count: i64 = db
        .client()
        .query_one(
            "SELECT COUNT(*) FROM email_verification_tokens WHERE user_id = $1 AND used_at IS NULL",
            &[&user_id],
        )
        .expect("failed to count active email verification tokens")
        .get(0);

    assert_eq!(count, 1);
}

#[test]
fn email_verification_tokens_cleanup_removes_only_expired_unused_tokens() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let expired_user_id = insert_user(db.client(), 615);
    let active_user_id = insert_user(db.client(), 616);
    let used_user_id = insert_user(db.client(), 617);
    db.client()
        .execute(
            "INSERT INTO email_verification_tokens (user_id, token_hash, created_at, expires_at, target_email)
             VALUES ($1, $2, NOW() - INTERVAL '2 hours', NOW() - INTERVAL '1 hour', $3)",
            &[&expired_user_id, &fixed_hash(26), &sample_email(6151)],
        )
        .expect("failed to insert expired unused token");
    db.client()
        .execute(
            "INSERT INTO email_verification_tokens (user_id, token_hash, expires_at, target_email)
             VALUES ($1, $2, NOW() + INTERVAL '1 hour', $3)",
            &[&active_user_id, &fixed_hash(27), &sample_email(616)],
        )
        .expect("failed to insert active unused token");
    db.client()
        .execute(
            "INSERT INTO email_verification_tokens (user_id, token_hash, created_at, expires_at, used_at, target_email)
             VALUES ($1, $2, NOW() - INTERVAL '2 hours', NOW() - INTERVAL '1 hour', NOW() - INTERVAL '30 minutes', $3)",
            &[&used_user_id, &fixed_hash(28), &sample_email(617)],
        )
        .expect("failed to insert used token");

    let deleted = db
        .client()
        .execute(
            "DELETE FROM email_verification_tokens
             WHERE expires_at < NOW() AND used_at IS NULL",
            &[],
        )
        .expect("failed to cleanup email verification tokens");

    let remaining: i64 = db
        .client()
        .query_one(
            "SELECT COUNT(*) FROM email_verification_tokens
             WHERE user_id IN ($1, $2, $3)",
            &[&expired_user_id, &active_user_id, &used_user_id],
        )
        .expect("failed to count remaining email verification tokens")
        .get(0);

    assert_eq!(deleted, 1);
    assert_eq!(remaining, 2);
}

#[test]
fn email_verification_tokens_require_a_valid_target_email() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 618);
    let err = db
        .client()
        .execute(
            "INSERT INTO email_verification_tokens (user_id, token_hash, expires_at, target_email)
             VALUES ($1, $2, NOW() + INTERVAL '1 hour', 'not-an-email')",
            &[&user_id, &fixed_hash(40)],
        )
        .expect_err("invalid target email should fail");

    assert_constraint(&err, "email_verification_tokens_target_email_format");
}

#[test]
fn email_verification_tokens_can_target_a_new_email_address() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 619);
    let target_email = "pending-change@example.com";

    let stored_target_email = db
        .client()
        .query_one(
            "INSERT INTO email_verification_tokens (user_id, token_hash, expires_at, target_email)
             VALUES ($1, $2, NOW() + INTERVAL '1 hour', $3)
             RETURNING target_email",
            &[&user_id, &fixed_hash(41), &target_email],
        )
        .expect("failed to insert email verification token for a new address")
        .get::<_, String>(0);

    assert_eq!(stored_target_email, target_email);
}
