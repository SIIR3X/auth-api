use testkit::TestDb;
use testkit::sql::{assert_constraint_error, fixed_hash, insert_user};

#[tokio::test]
async fn sessions_require_32_byte_hashes() {
    let db = TestDb::new().await;

    let user_id = insert_user(&db.pool, 31).await;
    let err = sqlx::query(
        "INSERT INTO sessions (user_id, expires_at, token_hash)
             VALUES ($1, NOW() + INTERVAL '1 day', $2)",
    )
    .bind(user_id)
    .bind(vec![1_u8; 31])
    .execute(&db.pool)
    .await
    .expect_err("31-byte token hash should fail");

    assert_constraint_error(&err, "sessions_token_hash_length");
}

#[tokio::test]
async fn sessions_enforce_unique_token_hash() {
    let db = TestDb::new().await;

    let user_id = insert_user(&db.pool, 34).await;
    let token_hash = fixed_hash(7);

    sqlx::query(
        "INSERT INTO sessions (user_id, expires_at, token_hash)
             VALUES ($1, NOW() + INTERVAL '1 day', $2)",
    )
    .bind(user_id)
    .bind(&token_hash)
    .execute(&db.pool)
    .await
    .expect("failed to insert first session");

    let err = sqlx::query(
        "INSERT INTO sessions (user_id, expires_at, token_hash)
             VALUES ($1, NOW() + INTERVAL '1 day', $2)",
    )
    .bind(user_id)
    .bind(&token_hash)
    .execute(&db.pool)
    .await
    .expect_err("duplicate token hash should fail");

    assert_constraint_error(&err, "sessions_token_hash_key");
}

#[tokio::test]
async fn sessions_require_expiration_after_creation() {
    let db = TestDb::new().await;

    let user_id = insert_user(&db.pool, 35).await;
    let err = sqlx::query(
        "INSERT INTO sessions (user_id, created_at, expires_at, token_hash)
             VALUES ($1, NOW(), NOW() - INTERVAL '1 minute', $2)",
    )
    .bind(user_id)
    .bind(fixed_hash(8))
    .execute(&db.pool)
    .await
    .expect_err("session expiration before creation should fail");

    assert_constraint_error(&err, "sessions_expires_after_creation");
}

#[tokio::test]
async fn sessions_reject_revocation_before_creation() {
    let db = TestDb::new().await;

    let user_id = insert_user(&db.pool, 32).await;
    let err = sqlx::query(
        "INSERT INTO sessions (user_id, created_at, expires_at, revoked_at, token_hash)
             VALUES ($1, NOW(), NOW() + INTERVAL '1 day', NOW() - INTERVAL '1 minute', $2)",
    )
    .bind(user_id)
    .bind(fixed_hash(4))
    .execute(&db.pool)
    .await
    .expect_err("revoked_at before created_at should fail");

    assert_constraint_error(&err, "sessions_revoked_after_creation");
}

#[tokio::test]
async fn sessions_reject_compromise_before_creation() {
    let db = TestDb::new().await;

    let user_id = insert_user(&db.pool, 320).await;
    let err = sqlx::query(
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
    )
    .bind(user_id)
    .bind(fixed_hash(42))
    .execute(&db.pool)
    .await
    .expect_err("compromised_at before created_at should fail");

    assert_constraint_error(&err, "sessions_compromised_after_creation");
}

#[tokio::test]
async fn sessions_require_compromise_metadata_to_include_a_reason() {
    let db = TestDb::new().await;

    let user_id = insert_user(&db.pool, 321).await;
    let err = sqlx::query(
        "INSERT INTO sessions (user_id, expires_at, revoked_at, compromised_at, token_hash)
             VALUES ($1, NOW() + INTERVAL '1 day', NOW(), NOW(), $2)",
    )
    .bind(user_id)
    .bind(fixed_hash(43))
    .execute(&db.pool)
    .await
    .expect_err("compromised sessions should require a reason");

    assert_constraint_error(&err, "sessions_compromise_metadata_consistency");
}

#[tokio::test]
async fn sessions_reject_rotation_before_creation() {
    let db = TestDb::new().await;

    let user_id = insert_user(&db.pool, 36).await;
    let err = sqlx::query(
        "INSERT INTO sessions (user_id, created_at, expires_at, revoked_at, rotated_at, replaced_by_session_id, token_hash)
             VALUES ($1, NOW(), NOW() + INTERVAL '1 day', NOW(), NOW() - INTERVAL '1 minute', gen_random_uuid(), $2)",
    )
    .bind(user_id)
    .bind(fixed_hash(14))
    .execute(&db.pool)
    .await
    .expect_err("rotated_at before created_at should fail");

    assert_constraint_error(&err, "sessions_rotated_after_creation");
}

#[tokio::test]
async fn sessions_require_rotation_metadata_when_replaced() {
    let db = TestDb::new().await;

    let user_id = insert_user(&db.pool, 37).await;
    let replacement_id = sqlx::query_scalar::<_, uuid::Uuid>(
        "INSERT INTO sessions (user_id, expires_at, token_hash)
             VALUES ($1, NOW() + INTERVAL '1 day', $2)
             RETURNING id",
    )
    .bind(user_id)
    .bind(fixed_hash(15))
    .fetch_one(&db.pool)
    .await
    .expect("failed to insert replacement session");

    let err = sqlx::query(
        "INSERT INTO sessions (user_id, expires_at, replaced_by_session_id, token_hash)
             VALUES ($1, NOW() + INTERVAL '1 day', $2, $3)",
    )
    .bind(user_id)
    .bind(replacement_id)
    .bind(fixed_hash(16))
    .execute(&db.pool)
    .await
    .expect_err("replacement metadata without revocation and rotation should fail");

    assert_constraint_error(&err, "sessions_replacement_metadata_consistency");
}

#[tokio::test]
async fn sessions_reject_self_replacement() {
    let db = TestDb::new().await;

    let user_id = insert_user(&db.pool, 38).await;
    let session_id = sqlx::query_scalar::<_, uuid::Uuid>(
        "INSERT INTO sessions (user_id, expires_at, token_hash)
             VALUES ($1, NOW() + INTERVAL '1 day', $2)
             RETURNING id",
    )
    .bind(user_id)
    .bind(fixed_hash(17))
    .fetch_one(&db.pool)
    .await
    .expect("failed to insert session for self-replacement test");

    let err = sqlx::query(
        "UPDATE sessions
             SET revoked_at = NOW(),
                 rotated_at = NOW(),
                 replaced_by_session_id = $2
             WHERE id = $1",
    )
    .bind(session_id)
    .bind(session_id)
    .execute(&db.pool)
    .await
    .expect_err("self replacement should fail");

    assert_constraint_error(&err, "sessions_not_self_replaced");
}
