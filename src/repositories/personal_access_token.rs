//! Repository for `personal_access_tokens`.

use sqlx::{PgExecutor, PgPool};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::personal_access_token::PersonalAccessToken;

pub struct NewPersonalAccessToken<'a> {
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub name: &'a str,
    pub token_hash: &'a [u8],
    pub scopes: &'a [String],
    pub expires_at: OffsetDateTime,
}

/// A token found by its secret, with the state of its session.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PresentedToken {
    #[sqlx(flatten)]
    pub token: PersonalAccessToken,
    pub session_revoked_at: Option<OffsetDateTime>,
}

pub async fn create<'e>(
    executor: impl PgExecutor<'e>,
    input: &NewPersonalAccessToken<'_>,
) -> Result<PersonalAccessToken, sqlx::Error> {
    sqlx::query_as::<_, PersonalAccessToken>(
        "INSERT INTO personal_access_tokens
             (user_id, session_id, name, token_hash, scopes, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id, user_id, session_id, name, scopes, created_at, expires_at, last_used_at",
    )
    .bind(input.user_id)
    .bind(input.session_id)
    .bind(input.name)
    .bind(input.token_hash)
    .bind(input.scopes)
    .bind(input.expires_at)
    .fetch_one(executor)
    .await
}

/// The account's tokens that still work, newest first.
pub async fn find_active_by_user(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Vec<PersonalAccessToken>, sqlx::Error> {
    sqlx::query_as::<_, PersonalAccessToken>(
        "SELECT t.id, t.user_id, t.session_id, t.name, t.scopes, t.created_at, t.expires_at, t.last_used_at
         FROM personal_access_tokens t
         JOIN sessions s ON s.id = t.session_id
         WHERE t.user_id = $1 AND s.revoked_at IS NULL AND t.expires_at > NOW()
         ORDER BY t.created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}

pub async fn count_active_by_user<'e>(
    executor: impl PgExecutor<'e>,
    user_id: Uuid,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM personal_access_tokens t
         JOIN sessions s ON s.id = t.session_id
         WHERE t.user_id = $1 AND s.revoked_at IS NULL AND t.expires_at > NOW()",
    )
    .bind(user_id)
    .fetch_one(executor)
    .await
}

pub async fn find_owned(
    pool: &PgPool,
    id: Uuid,
    user_id: Uuid,
) -> Result<Option<PersonalAccessToken>, sqlx::Error> {
    sqlx::query_as::<_, PersonalAccessToken>(
        "SELECT t.id, t.user_id, t.session_id, t.name, t.scopes, t.created_at, t.expires_at, t.last_used_at
         FROM personal_access_tokens t WHERE t.id = $1 AND t.user_id = $2",
    )
    .bind(id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
}

pub async fn find_by_hash(
    pool: &PgPool,
    token_hash: &[u8],
) -> Result<Option<PresentedToken>, sqlx::Error> {
    sqlx::query_as::<_, PresentedToken>(
        "SELECT t.id, t.user_id, t.session_id, t.name, t.scopes, t.created_at, t.expires_at, t.last_used_at, s.revoked_at AS session_revoked_at
         FROM personal_access_tokens t
         JOIN sessions s ON s.id = t.session_id
         WHERE t.token_hash = $1",
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await
}

/// Record a use of the token and of its session.
pub async fn touch(pool: &PgPool, token: &PersonalAccessToken) -> Result<(), sqlx::Error> {
    sqlx::query(
        "WITH token AS (
             UPDATE personal_access_tokens SET last_used_at = NOW() WHERE id = $1
         )
         UPDATE sessions SET last_used_at = NOW() WHERE id = $2",
    )
    .bind(token.id)
    .bind(token.session_id)
    .execute(pool)
    .await?;
    Ok(())
}
