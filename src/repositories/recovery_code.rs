//! Repository for the `recovery_codes` table.
//!
//! Codes are stored as 32-byte hashes. Plaintext codes are generated and
//! shown once at the service layer and never stored.

use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::domain::two_factor::RecoveryCode;

// Writes

/// Inserts a full set of recovery codes atomically.
/// All existing unused codes for the user should be deleted first
/// by calling `delete_all_by_user` within the same transaction at the service level.
/// `expires_at` is None when recovery codes never expire.
pub async fn create_batch(
    pool: &PgPool,
    user_id: Uuid,
    codes: &[(i16, &[u8])],
    expires_at: Option<time::OffsetDateTime>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;

    for (position, hash) in codes {
        sqlx::query(
            "INSERT INTO recovery_codes (user_id, code_position, code_hash, expires_at)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(user_id)
        .bind(position)
        .bind(*hash)
        .bind(expires_at)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(())
}

/// Replaces the full recovery-code set in a single transaction.
/// If any insert fails, the previous codes remain untouched.
pub async fn replace_all_by_user(
    pool: &PgPool,
    user_id: Uuid,
    codes: &[(i16, &[u8])],
    expires_at: Option<time::OffsetDateTime>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    replace_all_in_tx(&mut tx, user_id, codes, expires_at).await?;
    tx.commit().await?;
    Ok(())
}

/// Marks a single code as consumed. Returns false if the code was already used.
pub async fn consume(pool: &PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
    let result =
        sqlx::query("UPDATE recovery_codes SET used_at = NOW() WHERE id = $1 AND used_at IS NULL")
            .bind(id)
            .execute(pool)
            .await?;
    Ok(result.rows_affected() == 1)
}

/// Removes all codes for a user. Called before generating a new set.
pub async fn delete_all_by_user(pool: &PgPool, user_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM recovery_codes WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn replace_all_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    codes: &[(i16, &[u8])],
    expires_at: Option<time::OffsetDateTime>,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM recovery_codes WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut **tx)
        .await?;

    for (position, hash) in codes {
        sqlx::query(
            "INSERT INTO recovery_codes (user_id, code_position, code_hash, expires_at)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(user_id)
        .bind(*position)
        .bind(*hash)
        .bind(expires_at)
        .execute(&mut **tx)
        .await?;
    }

    Ok(())
}

// Reads

pub async fn find_unused_by_user(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Vec<RecoveryCode>, sqlx::Error> {
    sqlx::query_as::<_, RecoveryCode>(
        "SELECT * FROM recovery_codes
         WHERE user_id = $1 AND used_at IS NULL
         ORDER BY code_position",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}

/// Finds an unused code by its hash. Used to validate a submitted recovery code.
pub async fn find_by_hash(
    pool: &PgPool,
    code_hash: &[u8],
) -> Result<Option<RecoveryCode>, sqlx::Error> {
    sqlx::query_as::<_, RecoveryCode>(
        "SELECT * FROM recovery_codes WHERE code_hash = $1 AND used_at IS NULL LIMIT 1",
    )
    .bind(code_hash)
    .fetch_optional(pool)
    .await
}
