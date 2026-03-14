use crate::common::db::{TestDatabase, assert_constraint};
use crate::common::fixtures::{fixed_hash, insert_user};

#[test]
fn sessions_require_32_byte_hashes() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 31);
    let err = db
        .client()
        .execute(
            "INSERT INTO sessions (user_id, expires_at, token_hash)
             VALUES ($1, NOW() + INTERVAL '1 day', $2)",
            &[&user_id, &vec![1_u8; 31]],
        )
        .expect_err("31-byte token hash should fail");

    assert_constraint(&err, "sessions_token_hash_length");
}

#[test]
fn sessions_enforce_unique_token_hash() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 34);
    let token_hash = fixed_hash(7);

    db.client()
        .execute(
            "INSERT INTO sessions (user_id, expires_at, token_hash)
             VALUES ($1, NOW() + INTERVAL '1 day', $2)",
            &[&user_id, &token_hash],
        )
        .expect("failed to insert first session");

    let err = db
        .client()
        .execute(
            "INSERT INTO sessions (user_id, expires_at, token_hash)
             VALUES ($1, NOW() + INTERVAL '1 day', $2)",
            &[&user_id, &token_hash],
        )
        .expect_err("duplicate token hash should fail");

    assert_constraint(&err, "sessions_token_hash_key");
}

#[test]
fn sessions_require_expiration_after_creation() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 35);
    let err = db
        .client()
        .execute(
            "INSERT INTO sessions (user_id, created_at, expires_at, token_hash)
             VALUES ($1, NOW(), NOW() - INTERVAL '1 minute', $2)",
            &[&user_id, &fixed_hash(8)],
        )
        .expect_err("session expiration before creation should fail");

    assert_constraint(&err, "sessions_expires_after_creation");
}

#[test]
fn sessions_reject_revocation_before_creation() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 32);
    let err = db
        .client()
        .execute(
            "INSERT INTO sessions (user_id, created_at, expires_at, revoked_at, token_hash)
             VALUES ($1, NOW(), NOW() + INTERVAL '1 day', NOW() - INTERVAL '1 minute', $2)",
            &[&user_id, &fixed_hash(4)],
        )
        .expect_err("revoked_at before created_at should fail");

    assert_constraint(&err, "sessions_revoked_after_creation");
}

#[test]
fn sessions_reject_compromise_before_creation() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 320);
    let err = db
        .client()
        .execute(
            "INSERT INTO sessions (user_id, created_at, expires_at, revoked_at, compromised_at, compromise_reason, token_hash)
             VALUES (
                 $1,
                 NOW(),
                 NOW() + INTERVAL '1 day',
                 NOW(),
                 NOW() - INTERVAL '1 minute',
                 'refresh_token_reuse',
                 $2
             )",
            &[&user_id, &fixed_hash(42)],
        )
        .expect_err("compromised_at before created_at should fail");

    assert_constraint(&err, "sessions_compromised_after_creation");
}

#[test]
fn sessions_require_compromise_metadata_to_include_a_reason() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 321);
    let err = db
        .client()
        .execute(
            "INSERT INTO sessions (user_id, expires_at, revoked_at, compromised_at, token_hash)
             VALUES ($1, NOW() + INTERVAL '1 day', NOW(), NOW(), $2)",
            &[&user_id, &fixed_hash(43)],
        )
        .expect_err("compromised sessions should require a reason");

    assert_constraint(&err, "sessions_compromise_metadata_consistency");
}

#[test]
fn sessions_reject_rotation_before_creation() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 36);
    let err = db
        .client()
        .execute(
            "INSERT INTO sessions (user_id, created_at, expires_at, revoked_at, rotated_at, replaced_by_session_id, token_hash)
             VALUES ($1, NOW(), NOW() + INTERVAL '1 day', NOW(), NOW() - INTERVAL '1 minute', gen_random_uuid(), $2)",
            &[&user_id, &fixed_hash(14)],
        )
        .expect_err("rotated_at before created_at should fail");

    assert_constraint(&err, "sessions_rotated_after_creation");
}

#[test]
fn sessions_require_rotation_metadata_when_replaced() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 37);
    let replacement_id = db
        .client()
        .query_one(
            "INSERT INTO sessions (user_id, expires_at, token_hash)
             VALUES ($1, NOW() + INTERVAL '1 day', $2)
             RETURNING id",
            &[&user_id, &fixed_hash(15)],
        )
        .expect("failed to insert replacement session")
        .get::<_, uuid::Uuid>(0);

    let err = db
        .client()
        .execute(
            "INSERT INTO sessions (user_id, expires_at, replaced_by_session_id, token_hash)
             VALUES ($1, NOW() + INTERVAL '1 day', $2, $3)",
            &[&user_id, &replacement_id, &fixed_hash(16)],
        )
        .expect_err("replacement metadata without revocation and rotation should fail");

    assert_constraint(&err, "sessions_replacement_metadata_consistency");
}

#[test]
fn sessions_reject_self_replacement() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let user_id = insert_user(db.client(), 38);
    let row = db
        .client()
        .query_one(
            "INSERT INTO sessions (user_id, expires_at, token_hash)
             VALUES ($1, NOW() + INTERVAL '1 day', $2)
             RETURNING id",
            &[&user_id, &fixed_hash(17)],
        )
        .expect("failed to insert session for self-replacement test");
    let session_id = row.get::<_, uuid::Uuid>(0);

    let err = db
        .client()
        .execute(
            "UPDATE sessions
             SET revoked_at = NOW(),
                 rotated_at = NOW(),
                 replaced_by_session_id = $2
             WHERE id = $1",
            &[&session_id, &session_id],
        )
        .expect_err("self replacement should fail");

    assert_constraint(&err, "sessions_not_self_replaced");
}
