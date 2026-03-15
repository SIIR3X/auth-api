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
    pub webauthn_credential_id: Option<&'a str>,
    pub webauthn_public_key: Option<&'a str>,
}

// Writes

pub async fn create(
    pool: &PgPool,
    input: &NewTwoFactorMethod<'_>,
) -> Result<TwoFactorMethod, sqlx::Error> {
    sqlx::query_as::<_, TwoFactorMethod>(
        "INSERT INTO two_factor_methods
             (user_id, method_type, totp_secret, webauthn_credential_id, webauthn_public_key)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING *",
    )
    .bind(input.user_id)
    .bind(&input.method_type)
    .bind(input.totp_secret)
    .bind(input.webauthn_credential_id)
    .bind(input.webauthn_public_key)
    .fetch_one(pool)
    .await
}

pub async fn mark_verified(pool: &PgPool, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE two_factor_methods SET is_verified = TRUE WHERE id = $1",
    )
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

/// Increments the WebAuthn sign counter to detect cloned authenticators.
pub async fn update_webauthn_sign_count(
    pool: &PgPool,
    id: Uuid,
    sign_count: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE two_factor_methods SET webauthn_sign_count = $2, last_used_at = NOW() WHERE id = $1",
    )
    .bind(id)
    .bind(sign_count)
    .execute(pool)
    .await?;
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
