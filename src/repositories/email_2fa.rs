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

/// Finds the user's live (unused, unexpired) code matching one of `code_hashes`
/// (the digest of the submitted code under each key of the keyring).
///
/// Scoped to the user on purpose: a 6-digit code is not unique across accounts,
/// and an unscoped lookup could return another user's row, fail a valid code,
/// and scan the whole table. `idx_email_2fa_codes_user` serves this query.
pub async fn find_active_by_user_and_hash(
    pool: &PgPool,
    user_id: Uuid,
    code_hashes: &[Vec<u8>],
) -> Result<Option<Email2faCode>, sqlx::Error> {
    sqlx::query_as::<_, Email2faCode>(
        "SELECT * FROM email_2fa_codes
         WHERE user_id = $1
           AND code_hash = ANY($2)
           AND used_at IS NULL
           AND expires_at > now()
         ORDER BY created_at DESC
         LIMIT 1",
    )
    .bind(user_id)
    .bind(code_hashes)
    .fetch_optional(pool)
    .await
}

/// Marks a code as used. Returns true if the row was updated, false if it was
/// already used or expired in the meantime.
/// Mark the code used, and the other live code of its account with it: the
/// previous code, kept alive by a resend, ends with the one that worked.
pub async fn consume(pool: &PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let user_id: Option<Uuid> = sqlx::query_scalar(
        "UPDATE email_2fa_codes SET used_at = now()
         WHERE id = $1 AND used_at IS NULL AND expires_at > now()
         RETURNING user_id",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(user_id) = user_id else {
        return Ok(false);
    };
    sqlx::query(
        "UPDATE email_2fa_codes SET used_at = now() WHERE user_id = $1 AND used_at IS NULL",
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(true)
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
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        self.expires_at < now
    }

    pub fn is_used(&self) -> bool {
        self.used_at.is_some()
    }
}

pub async fn replace_active_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    input: &NewEmail2faCode<'_>,
) -> Result<Uuid, sqlx::Error> {
    // The latest unused code survives the new one: a resend, possibly asked
    // by someone else holding the challenge, must not kill the code its owner
    // is typing. Two codes at most are live, and both end when one is used.
    sqlx::query(
        "DELETE FROM email_2fa_codes
         WHERE user_id = $1 AND used_at IS NULL
           AND id <> COALESCE((
               SELECT id FROM email_2fa_codes
               WHERE user_id = $1 AND used_at IS NULL
               ORDER BY created_at DESC
               LIMIT 1
           ), '00000000-0000-0000-0000-000000000000')",
    )
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
