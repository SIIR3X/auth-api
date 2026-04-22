//! Repository for the `two_factor_methods` table.

use sqlx::PgPool;
use uuid::Uuid;

use crate::domain::two_factor::{TwoFactorMethod, TwoFactorType};

// Input types

pub struct NewTwoFactorMethod<'a> {
    pub user_id: Uuid,
    pub method_type: TwoFactorType,
    /// Encrypted ciphertext; must never be the raw TOTP secret.
    pub totp_secret: Option<&'a str>,
}

// Writes

pub async fn create(
    pool: &PgPool,
    input: &NewTwoFactorMethod<'_>,
) -> Result<TwoFactorMethod, sqlx::Error> {
    sqlx::query_as::<_, TwoFactorMethod>(
        "INSERT INTO two_factor_methods (user_id, method_type, totp_secret)
         VALUES ($1, $2, $3)
         RETURNING *",
    )
    .bind(input.user_id)
    .bind(&input.method_type)
    .bind(input.totp_secret)
    .fetch_one(pool)
    .await
}

pub async fn mark_verified(pool: &PgPool, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE two_factor_methods SET is_verified = TRUE WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Sets this method as primary; the DB unique index enforces one primary per user.
pub async fn set_primary(pool: &PgPool, id: Uuid, user_id: Uuid) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;

    sqlx::query(
        "UPDATE two_factor_methods SET is_primary = FALSE WHERE user_id = $1 AND is_primary = TRUE",
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        "UPDATE two_factor_methods SET is_primary = TRUE WHERE id = $1 AND is_verified = TRUE",
    )
    .bind(id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(())
}

pub async fn delete(pool: &PgPool, id: Uuid, user_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM two_factor_methods WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

// Reads

pub async fn find_by_user(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Vec<TwoFactorMethod>, sqlx::Error> {
    sqlx::query_as::<_, TwoFactorMethod>(
        "SELECT * FROM two_factor_methods WHERE user_id = $1 ORDER BY created_at",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}

pub async fn find_by_id_and_user(
    pool: &PgPool,
    id: Uuid,
    user_id: Uuid,
) -> Result<Option<TwoFactorMethod>, sqlx::Error> {
    sqlx::query_as::<_, TwoFactorMethod>(
        "SELECT * FROM two_factor_methods WHERE id = $1 AND user_id = $2",
    )
    .bind(id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
}

pub async fn find_primary_by_user(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Option<TwoFactorMethod>, sqlx::Error> {
    sqlx::query_as::<_, TwoFactorMethod>(
        "SELECT * FROM two_factor_methods WHERE user_id = $1 AND is_primary = TRUE LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
}

/// Returns (id, totp_secret) for every verified TOTP method that has a secret.
/// Used exclusively during encryption key rotation.
pub async fn find_all_totp_secrets(pool: &PgPool) -> Result<Vec<(Uuid, String)>, sqlx::Error> {
    let rows: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, totp_secret
         FROM two_factor_methods
         WHERE method_type = 'totp' AND totp_secret IS NOT NULL",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Updates the encrypted TOTP secret for a single method row.
pub async fn update_totp_secret(
    pool: &PgPool,
    id: Uuid,
    new_secret: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE two_factor_methods SET totp_secret = $2 WHERE id = $1")
        .bind(id)
        .bind(new_secret)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn find_by_type(
    pool: &PgPool,
    user_id: Uuid,
    method_type: TwoFactorType,
) -> Result<Option<TwoFactorMethod>, sqlx::Error> {
    sqlx::query_as::<_, TwoFactorMethod>(
        "SELECT * FROM two_factor_methods WHERE user_id = $1 AND method_type = $2 LIMIT 1",
    )
    .bind(user_id)
    .bind(method_type)
    .fetch_optional(pool)
    .await
}

pub async fn find_all_by_type(
    pool: &PgPool,
    user_id: Uuid,
    method_type: TwoFactorType,
) -> Result<Vec<TwoFactorMethod>, sqlx::Error> {
    sqlx::query_as::<_, TwoFactorMethod>(
        "SELECT * FROM two_factor_methods WHERE user_id = $1 AND method_type = $2 ORDER BY created_at",
    )
    .bind(user_id)
    .bind(method_type)
    .fetch_all(pool)
    .await
}
