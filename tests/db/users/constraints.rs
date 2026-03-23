use crate::common::db::{TestDatabase, assert_constraint};
use crate::common::fixtures::{SAMPLE_PASSWORD_HASH, sample_email};

#[test]
fn users_reject_invalid_email_format() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let err = db
        .client()
        .execute(
            "INSERT INTO users (username, email, password_hash)
             VALUES ($1, $2, $3)",
            &[&"bad_email_user", &"not-an-email", &SAMPLE_PASSWORD_HASH],
        )
        .expect_err("invalid email should fail");

    assert_constraint(&err, "users_email_format");
}

#[test]
fn users_enforce_unique_email() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let email = sample_email(1);
    db.client()
        .execute(
            "INSERT INTO users (username, email, password_hash)
             VALUES ($1, $2, $3)",
            &[&"user_unique_a", &email, &SAMPLE_PASSWORD_HASH],
        )
        .expect("failed to insert first user");

    let err = db
        .client()
        .execute(
            "INSERT INTO users (username, email, password_hash)
             VALUES ($1, $2, $3)",
            &[&"user_unique_b", &email, &SAMPLE_PASSWORD_HASH],
        )
        .expect_err("duplicate email should fail");

    assert_constraint(&err, "users_email_key");
}

#[test]
fn users_enforce_unique_email_case_insensitively() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    db.client()
        .execute(
            "INSERT INTO users (username, email, password_hash)
             VALUES ($1, $2, $3)",
            &[&"case_user_a", &"Case@Test.dev", &SAMPLE_PASSWORD_HASH],
        )
        .expect("failed to insert first user");

    let err = db
        .client()
        .execute(
            "INSERT INTO users (username, email, password_hash)
             VALUES ($1, $2, $3)",
            &[&"case_user_b", &"case@test.dev", &SAMPLE_PASSWORD_HASH],
        )
        .expect_err("case-insensitive duplicate email should fail");

    assert_constraint(&err, "users_email_key");
}

#[test]
fn users_enforce_unique_username() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    db.client()
        .execute(
            "INSERT INTO users (username, email, password_hash)
             VALUES ($1, $2, $3)",
            &[&"same_name", &sample_email(100), &SAMPLE_PASSWORD_HASH],
        )
        .expect("failed to insert first username");

    let err = db
        .client()
        .execute(
            "INSERT INTO users (username, email, password_hash)
             VALUES ($1, $2, $3)",
            &[&"same_name", &sample_email(101), &SAMPLE_PASSWORD_HASH],
        )
        .expect_err("duplicate username should fail");

    assert_constraint(&err, "users_username_key");
}

#[test]
fn users_reject_invalid_username_format() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let err = db
        .client()
        .execute(
            "INSERT INTO users (username, email, password_hash)
             VALUES ($1, $2, $3)",
            &[
                &"no spaces allowed",
                &sample_email(102),
                &SAMPLE_PASSWORD_HASH,
            ],
        )
        .expect_err("invalid username should fail");

    assert_constraint(&err, "users_username_format");
}

#[test]
fn users_reject_too_short_password_hash() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let short_hash = "short_hash_value";
    let err = db
        .client()
        .execute(
            "INSERT INTO users (username, email, password_hash)
             VALUES ($1, $2, $3)",
            &[&"short_hash_user", &sample_email(103), &short_hash],
        )
        .expect_err("short password hash should fail");

    assert_constraint(&err, "users_password_hash_min_length");
}

#[test]
fn users_reject_pending_verification_with_verified_timestamp() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let err = db
        .client()
        .execute(
            "INSERT INTO users (username, email, password_hash, status, email_verified_at)
             VALUES ($1, $2, $3, 'pending_verification', NOW())",
            &[&"pending_conflict", &sample_email(8), &SAMPLE_PASSWORD_HASH],
        )
        .expect_err("pending verification user should not have email_verified_at");

    assert_constraint(&err, "users_status_email_verification_consistency");
}

#[test]
fn users_require_verified_email_for_active_status() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let err = db
        .client()
        .execute(
            "INSERT INTO users (username, email, password_hash, status)
             VALUES ($1, $2, $3, 'active')",
            &[
                &"active_without_verification",
                &sample_email(104),
                &SAMPLE_PASSWORD_HASH,
            ],
        )
        .expect_err("active users should require email_verified_at");

    assert_constraint(&err, "users_status_email_verification_consistency");
}

#[test]
fn users_allow_verified_email_for_active_status() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    db.client()
        .execute(
            "INSERT INTO users (username, email, password_hash, status, email_verified_at)
             VALUES ($1, $2, $3, 'active', NOW())",
            &[
                &"active_verified",
                &sample_email(105),
                &SAMPLE_PASSWORD_HASH,
            ],
        )
        .expect("active verified user should be allowed");
}
