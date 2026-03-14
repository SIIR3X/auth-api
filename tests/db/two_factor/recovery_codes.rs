use crate::common::db::{TestDatabase, assert_constraint};
use crate::common::fixtures::{fixed_hash, insert_user};

#[test]
fn recovery_codes_enforce_position_range_and_uniqueness() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 63);
    db.client()
        .execute(
            "INSERT INTO recovery_codes (user_id, code_position, code_hash)
             VALUES ($1, 1, $2)",
            &[&user_id, &fixed_hash(9)],
        )
        .expect("failed to insert recovery code");

    let duplicate_err = db
        .client()
        .execute(
            "INSERT INTO recovery_codes (user_id, code_position, code_hash)
             VALUES ($1, 1, $2)",
            &[&user_id, &fixed_hash(10)],
        )
        .expect_err("duplicate recovery code position should fail");
    assert_constraint(&duplicate_err, "recovery_codes_user_position_key");

    let range_err = db
        .client()
        .execute(
            "INSERT INTO recovery_codes (user_id, code_position, code_hash)
             VALUES ($1, 21, $2)",
            &[&user_id, &fixed_hash(11)],
        )
        .expect_err("out of range recovery code position should fail");
    assert_constraint(&range_err, "recovery_codes_position_range");
}

#[test]
fn recovery_codes_enforce_unique_hashes() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let first_user = insert_user(db.client(), 631);
    let second_user = insert_user(db.client(), 632);
    let code_hash = fixed_hash(41);

    db.client()
        .execute(
            "INSERT INTO recovery_codes (user_id, code_position, code_hash)
             VALUES ($1, 1, $2)",
            &[&first_user, &code_hash],
        )
        .expect("failed to insert first recovery code");

    let err = db
        .client()
        .execute(
            "INSERT INTO recovery_codes (user_id, code_position, code_hash)
             VALUES ($1, 1, $2)",
            &[&second_user, &code_hash],
        )
        .expect_err("duplicate recovery code hash should fail");

    assert_constraint(&err, "recovery_codes_code_hash_key");
}

#[test]
fn recovery_codes_reject_used_at_before_creation() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 633);
    let err = db
        .client()
        .execute(
            "INSERT INTO recovery_codes (user_id, created_at, used_at, code_position, code_hash)
             VALUES ($1, NOW(), NOW() - INTERVAL '1 minute', 1, $2)",
            &[&user_id, &fixed_hash(42)],
        )
        .expect_err("used_at before creation should fail");

    assert_constraint(&err, "recovery_codes_used_after_creation");
}

#[test]
fn recovery_codes_require_future_expiration_when_present() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 634);
    let err = db
        .client()
        .execute(
            "INSERT INTO recovery_codes (user_id, created_at, expires_at, code_position, code_hash)
             VALUES ($1, NOW(), NOW() - INTERVAL '1 minute', 1, $2)",
            &[&user_id, &fixed_hash(43)],
        )
        .expect_err("expiration before creation should fail");

    assert_constraint(&err, "recovery_codes_expiration_consistency");
}

#[test]
fn recovery_codes_cleanup_removes_only_expired_unused_codes() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 635);
    db.client()
        .execute(
            "INSERT INTO recovery_codes (user_id, created_at, code_position, code_hash, expires_at)
             VALUES
             ($1, NOW() - INTERVAL '2 hours', 1, $2, NOW() - INTERVAL '1 hour'),
             ($1, NOW(), 2, $3, NOW() + INTERVAL '1 hour'),
             ($1, NOW() - INTERVAL '2 hours', 3, $4, NOW() - INTERVAL '1 hour')",
            &[&user_id, &fixed_hash(44), &fixed_hash(45), &fixed_hash(46)],
        )
        .expect("failed to insert recovery codes");
    db.client()
        .execute(
            "UPDATE recovery_codes
             SET used_at = NOW() - INTERVAL '30 minutes'
             WHERE user_id = $1 AND code_hash = $2",
            &[&user_id, &fixed_hash(46)],
        )
        .expect("failed to mark recovery code as used");

    let deleted = db
        .client()
        .execute(
            "DELETE FROM recovery_codes
             WHERE expires_at < NOW() AND used_at IS NULL",
            &[],
        )
        .expect("failed to cleanup recovery codes");

    let remaining: i64 = db
        .client()
        .query_one(
            "SELECT COUNT(*) FROM recovery_codes WHERE user_id = $1",
            &[&user_id],
        )
        .expect("failed to count remaining recovery codes")
        .get(0);

    assert_eq!(deleted, 1);
    assert_eq!(remaining, 2);
}
