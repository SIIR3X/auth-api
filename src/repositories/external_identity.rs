//! Repository for `external_identities`.

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ExternalIdentity {
    pub id: Uuid,
    pub user_id: Uuid,
    pub provider: String,
    pub subject: String,
    pub created_at: OffsetDateTime,
    pub last_used_at: Option<OffsetDateTime>,
}

pub async fn find_by_subject(
    pool: &PgPool,
    provider: &str,
    subject: &str,
) -> Result<Option<ExternalIdentity>, sqlx::Error> {
    sqlx::query_as::<_, ExternalIdentity>(
        "SELECT * FROM external_identities WHERE provider = $1 AND subject = $2",
    )
    .bind(provider)
    .bind(subject)
    .fetch_optional(pool)
    .await
}

pub async fn find_by_user(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Vec<ExternalIdentity>, sqlx::Error> {
    sqlx::query_as::<_, ExternalIdentity>(
        "SELECT * FROM external_identities WHERE user_id = $1 ORDER BY created_at",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}

/// Link an identity to an account. A unique violation means the identity, or
/// an identity at this provider for this account, is already linked.
pub async fn link(
    pool: &PgPool,
    user_id: Uuid,
    provider: &str,
    subject: &str,
) -> Result<ExternalIdentity, sqlx::Error> {
    sqlx::query_as::<_, ExternalIdentity>(
        "INSERT INTO external_identities (user_id, provider, subject)
         VALUES ($1, $2, $3)
         RETURNING *",
    )
    .bind(user_id)
    .bind(provider)
    .bind(subject)
    .fetch_one(pool)
    .await
}

pub async fn touch(pool: &PgPool, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE external_identities SET last_used_at = NOW() WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete_owned(pool: &PgPool, id: Uuid, user_id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM external_identities WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() == 1)
}
