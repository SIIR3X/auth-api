//! Repository for the `email_2fa_codes` table.

use sqlx::{PgPool, Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

pub struct NewEmail2faCode<'a> {
    pub user_id: Uuid,
    pub code_hash: &'a [u8],
    pub expires_at: OffsetDateTime,
}

/// Inserts a new code, invalidating any existing active codes for the same user.
pub async fn create(pool: &PgPool, input: &NewEmail2faCode<'_>) -> Result<Uuid, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let id = replace_active_in_tx(&mut tx, input).await?;
    tx.commit().await?;
    Ok(id)
}

/// Returns the most recent active (not used, not expired) code for a user.
pub async fn find_active_by_user(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Option<Email2faCode>, sqlx::Error> {
    sqlx::query_as::<_, Email2faCode>(
        "SELECT * FROM email_2fa_codes
         WHERE user_id = $1 AND used_at IS NULL AND expires_at > now()
         ORDER BY created_at DESC
         LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
}

/// Finds a code by its hash regardless of state (used to verify and consume it).
pub async fn find_by_hash(
    pool: &PgPool,
    code_hash: &[u8],
) -> Result<Option<Email2faCode>, sqlx::Error> {
    sqlx::query_as::<_, Email2faCode>("SELECT * FROM email_2fa_codes WHERE code_hash = $1 LIMIT 1")
        .bind(code_hash)
        .fetch_optional(pool)
        .await
}

/// Marks a code as used. Returns true if the row was updated.
pub async fn consume(pool: &PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
    let result =
        sqlx::query("UPDATE email_2fa_codes SET used_at = now() WHERE id = $1 AND used_at IS NULL")
            .bind(id)
            .execute(pool)
            .await?;

    Ok(result.rows_affected() == 1)
}

#[derive(Debug, sqlx::FromRow)]
pub struct Email2faCode {
    pub id: Uuid,
    pub user_id: Uuid,
    pub code_hash: Vec<u8>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub used_at: Option<OffsetDateTime>,
}

impl Email2faCode {
    pub fn is_expired(&self) -> bool {
        self.expires_at < crate::utils::time::now()
    }

    pub fn is_used(&self) -> bool {
        self.used_at.is_some()
    }
}

pub async fn replace_active_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    input: &NewEmail2faCode<'_>,
) -> Result<Uuid, sqlx::Error> {
    sqlx::query("DELETE FROM email_2fa_codes WHERE user_id = $1 AND used_at IS NULL")
        .bind(input.user_id)
        .execute(&mut **tx)
        .await?;

    let row: (Uuid,) = sqlx::query_as(
        "INSERT INTO email_2fa_codes (user_id, code_hash, expires_at)
         VALUES ($1, $2, $3)
         RETURNING id",
    )
    .bind(input.user_id)
    .bind(input.code_hash)
    .bind(input.expires_at)
    .fetch_one(&mut **tx)
    .await?;

    Ok(row.0)
}
