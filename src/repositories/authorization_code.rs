//! Repository for `authorization_codes` (migration 0023).
//!
//! Redemption is one statement that consumes and returns the code, so two
//! concurrent redemptions cannot both succeed.

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuthorizationCode {
    pub id: Uuid,
    pub user_id: Uuid,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub scopes: Option<Vec<String>>,
    pub expires_at: OffsetDateTime,
    pub consumed_at: Option<OffsetDateTime>,
    pub session_id: Option<Uuid>,
}

pub struct NewAuthorizationCode<'a> {
    pub code_hash: &'a [u8],
    pub user_id: Uuid,
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub code_challenge: &'a str,
    pub scopes: Option<&'a [String]>,
    pub expires_at: OffsetDateTime,
}

const COLUMNS: &str = "id, user_id, client_id, redirect_uri, code_challenge, scopes, expires_at, consumed_at, session_id";

pub async fn create(pool: &PgPool, input: &NewAuthorizationCode<'_>) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO authorization_codes
             (code_hash, user_id, client_id, redirect_uri, code_challenge, scopes, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING id",
    )
    .bind(input.code_hash)
    .bind(input.user_id)
    .bind(input.client_id)
    .bind(input.redirect_uri)
    .bind(input.code_challenge)
    .bind(input.scopes)
    .bind(input.expires_at)
    .fetch_one(pool)
    .await
}

/// Consume a live code in one statement. `None` for unknown, expired or already
/// consumed codes; [`find`] tells them apart when needed.
pub async fn consume(
    pool: &PgPool,
    code_hash: &[u8],
) -> Result<Option<AuthorizationCode>, sqlx::Error> {
    sqlx::query_as::<_, AuthorizationCode>(&format!(
        "UPDATE authorization_codes
            SET consumed_at = NOW()
          WHERE code_hash = $1 AND consumed_at IS NULL AND expires_at > NOW()
         RETURNING {COLUMNS}"
    ))
    .bind(code_hash)
    .fetch_optional(pool)
    .await
}

/// The row behind a code hash, consumed or not.
pub async fn find(
    pool: &PgPool,
    code_hash: &[u8],
) -> Result<Option<AuthorizationCode>, sqlx::Error> {
    sqlx::query_as::<_, AuthorizationCode>(&format!(
        "SELECT {COLUMNS} FROM authorization_codes WHERE code_hash = $1"
    ))
    .bind(code_hash)
    .fetch_optional(pool)
    .await
}

/// Remember which session a code produced, so a replay can revoke it.
pub async fn attach_session(pool: &PgPool, id: Uuid, session_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE authorization_codes SET session_id = $2 WHERE id = $1")
        .bind(id)
        .bind(session_id)
        .execute(pool)
        .await?;
    Ok(())
}
