use crate::common::db::{TestDatabase, assert_constraint};
use crate::common::fixtures::insert_user;
use std::thread;
use std::time::Duration;

#[test]
fn totp_requires_secret() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 51);
    let err = db
        .client()
        .execute(
            "INSERT INTO two_factor_methods (user_id, method_type, is_verified)
             VALUES ($1, 'totp', TRUE)",
            &[&user_id],
        )
        .expect_err("totp without secret should fail");

    assert_constraint(&err, "two_factor_method_payload");
}

#[test]
fn non_webauthn_methods_require_zero_sign_count() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 510);
    let err = db
        .client()
        .execute(
            "INSERT INTO two_factor_methods (user_id, method_type, is_verified, webauthn_sign_count)
             VALUES ($1, 'email', TRUE, 1)",
            &[&user_id],
        )
        .expect_err("non-webauthn methods should not store sign counts");

    assert_constraint(&err, "two_factor_webauthn_sign_count_usage");
}

#[test]
fn webauthn_methods_allow_positive_sign_count() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 511);
    db.client()
        .execute(
            "INSERT INTO two_factor_methods (
                user_id, method_type, is_verified, webauthn_sign_count, webauthn_credential_id, webauthn_public_key
             ) VALUES ($1, 'webauthn', TRUE, 7, $2, $3)",
            &[&user_id, &"credential-sign-count", &"public-key-sign-count"],
        )
        .expect("webauthn methods should allow positive sign counts");
}

#[test]
fn email_method_allows_single_entry_per_user() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 52);
    db.client()
        .execute(
            "INSERT INTO two_factor_methods (user_id, method_type, is_verified)
             VALUES ($1, 'email', TRUE)",
            &[&user_id],
        )
        .expect("failed to insert first email 2fa method");

    let err = db
        .client()
        .execute(
            "INSERT INTO two_factor_methods (user_id, method_type, is_verified)
             VALUES ($1, 'email', TRUE)",
            &[&user_id],
        )
        .expect_err("duplicate email method should fail");

    assert_constraint(&err, "idx_2fa_user_email");
}

#[test]
fn totp_allows_single_entry_per_user() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 521);
    db.client()
        .execute(
            "INSERT INTO two_factor_methods (user_id, method_type, is_verified, totp_secret)
             VALUES ($1, 'totp', TRUE, $2)",
            &[&user_id, &"encrypted-secret-a"],
        )
        .expect("failed to insert first totp method");

    let err = db
        .client()
        .execute(
            "INSERT INTO two_factor_methods (user_id, method_type, is_verified, totp_secret)
             VALUES ($1, 'totp', TRUE, $2)",
            &[&user_id, &"encrypted-secret-b"],
        )
        .expect_err("duplicate totp method should fail");

    assert_constraint(&err, "idx_2fa_user_totp");
}

#[test]
fn webauthn_allows_multiple_credentials_per_user() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 53);
    db.client()
        .execute(
            "INSERT INTO two_factor_methods (
                user_id, method_type, is_verified, webauthn_credential_id, webauthn_public_key
             ) VALUES ($1, 'webauthn', TRUE, $2, $3)",
            &[&user_id, &"credential-a", &"public-key-a"],
        )
        .expect("failed to insert first webauthn credential");
    db.client()
        .execute(
            "INSERT INTO two_factor_methods (
                user_id, method_type, is_verified, webauthn_credential_id, webauthn_public_key
             ) VALUES ($1, 'webauthn', TRUE, $2, $3)",
            &[&user_id, &"credential-b", &"public-key-b"],
        )
        .expect("failed to insert second webauthn credential");

    let count: i64 = db
        .client()
        .query_one(
            "SELECT COUNT(*) FROM two_factor_methods WHERE user_id = $1 AND method_type = 'webauthn'",
            &[&user_id],
        )
        .expect("failed to count webauthn methods")
        .get(0);

    assert_eq!(count, 2);
}

#[test]
fn webauthn_credentials_must_be_globally_unique() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let first_user = insert_user(db.client(), 531);
    let second_user = insert_user(db.client(), 532);

    db.client()
        .execute(
            "INSERT INTO two_factor_methods (
                user_id, method_type, is_verified, webauthn_credential_id, webauthn_public_key
             ) VALUES ($1, 'webauthn', TRUE, $2, $3)",
            &[&first_user, &"shared-credential", &"public-key-a"],
        )
        .expect("failed to insert first shared credential");

    let err = db
        .client()
        .execute(
            "INSERT INTO two_factor_methods (
                user_id, method_type, is_verified, webauthn_credential_id, webauthn_public_key
             ) VALUES ($1, 'webauthn', TRUE, $2, $3)",
            &[&second_user, &"shared-credential", &"public-key-b"],
        )
        .expect_err("duplicate webauthn credential should fail");

    assert_constraint(&err, "idx_2fa_webauthn_credential");
}

#[test]
fn primary_method_must_be_verified() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 54);
    let err = db
        .client()
        .execute(
            "INSERT INTO two_factor_methods (user_id, method_type, is_primary, is_verified)
             VALUES ($1, 'email', TRUE, FALSE)",
            &[&user_id],
        )
        .expect_err("primary 2fa method must be verified");

    assert_constraint(&err, "two_factor_primary_requires_verification");
}

#[test]
fn user_can_have_only_one_primary_two_factor_method() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 541);

    db.client()
        .execute(
            "INSERT INTO two_factor_methods (user_id, method_type, is_primary, is_verified)
             VALUES ($1, 'email', TRUE, TRUE)",
            &[&user_id],
        )
        .expect("failed to insert first primary 2fa method");

    let err = db
        .client()
        .execute(
            "INSERT INTO two_factor_methods (user_id, method_type, is_primary, is_verified, totp_secret)
             VALUES ($1, 'totp', TRUE, TRUE, $2)",
            &[&user_id, &"encrypted-secret"],
        )
        .expect_err("second primary 2fa method should fail");

    assert_constraint(&err, "idx_2fa_user_primary");
}

#[test]
fn deleting_user_cascades_to_two_factor_methods() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 55);
    db.client()
        .execute(
            "INSERT INTO two_factor_methods (user_id, method_type, is_verified)
             VALUES ($1, 'email', TRUE)",
            &[&user_id],
        )
        .expect("failed to insert 2fa method");

    db.client()
        .execute("DELETE FROM users WHERE id = $1", &[&user_id])
        .expect("failed to delete user");

    let count: i64 = db
        .client()
        .query_one(
            "SELECT COUNT(*) FROM two_factor_methods WHERE user_id = $1",
            &[&user_id],
        )
        .expect("failed to count 2fa methods")
        .get(0);

    assert_eq!(count, 0);
}

#[test]
fn updating_two_factor_method_touches_updated_at() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 56);
    let row = db
        .client()
        .query_one(
            "INSERT INTO two_factor_methods (user_id, method_type, is_verified)
             VALUES ($1, 'email', FALSE)
             RETURNING id, updated_at",
            &[&user_id],
        )
        .expect("failed to insert 2fa method");
    let method_id = row.get::<_, uuid::Uuid>(0);
    let first_updated_at = row.get::<_, std::time::SystemTime>(1);

    thread::sleep(Duration::from_millis(5));

    let second_updated_at = db
        .client()
        .query_one(
            "UPDATE two_factor_methods
             SET is_verified = TRUE
             WHERE id = $1
             RETURNING updated_at",
            &[&method_id],
        )
        .expect("failed to update 2fa method")
        .get::<_, std::time::SystemTime>(0);

    assert!(second_updated_at > first_updated_at);
}
