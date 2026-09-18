//! Repository for `passkeys`.

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Passkey {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub algorithm: i32,
    pub sign_count: i64,
    pub aaguid: Uuid,
    pub name: String,
    pub backup_eligible: bool,
    pub backed_up: bool,
    pub created_at: OffsetDateTime,
    pub last_used_at: Option<OffsetDateTime>,
}

pub struct NewPasskey<'a> {
    pub user_id: Uuid,
    pub credential_id: &'a [u8],
    pub public_key: &'a [u8],
    pub algorithm: i64,
    pub sign_count: u32,
    pub aaguid: Uuid,
    pub name: &'a str,
    pub backup_eligible: bool,
    pub backed_up: bool,
}

/// Store a new passkey; `None` when the credential is already registered.
pub async fn create(pool: &PgPool, input: &NewPasskey<'_>) -> Result<Option<Passkey>, sqlx::Error> {
    sqlx::query_as::<_, Passkey>(
        "INSERT INTO passkeys
             (user_id, credential_id, public_key, algorithm, sign_count, aaguid, name,
              backup_eligible, backed_up)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         ON CONFLICT (credential_id) DO NOTHING
         RETURNING *",
    )
    .bind(input.user_id)
    .bind(input.credential_id)
    .bind(input.public_key)
    .bind(i32::try_from(input.algorithm).unwrap_or(0))
    .bind(i64::from(input.sign_count))
    .bind(input.aaguid)
    .bind(input.name)
    .bind(input.backup_eligible)
    .bind(input.backed_up)
    .fetch_optional(pool)
    .await
}

pub async fn find_by_credential_id(
    pool: &PgPool,
    credential_id: &[u8],
) -> Result<Option<Passkey>, sqlx::Error> {
    sqlx::query_as::<_, Passkey>("SELECT * FROM passkeys WHERE credential_id = $1")
        .bind(credential_id)
        .fetch_optional(pool)
        .await
}

pub async fn find_by_user(pool: &PgPool, user_id: Uuid) -> Result<Vec<Passkey>, sqlx::Error> {
    sqlx::query_as::<_, Passkey>("SELECT * FROM passkeys WHERE user_id = $1 ORDER BY created_at")
        .bind(user_id)
        .fetch_all(pool)
        .await
}

pub async fn exists_for_user(pool: &PgPool, user_id: Uuid) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM passkeys WHERE user_id = $1)")
        .bind(user_id)
        .fetch_one(pool)
        .await
}

/// Record a use, only if the counter still holds the value that was read: two
/// concurrent assertions with the same counter cannot both pass.
pub async fn record_use(
    pool: &PgPool,
    id: Uuid,
    expected_count: i64,
    new_count: u32,
    backed_up: bool,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE passkeys
         SET sign_count = $3, backed_up = $4, last_used_at = NOW()
         WHERE id = $1 AND sign_count = $2",
    )
    .bind(id)
    .bind(expected_count)
    .bind(i64::from(new_count))
    .bind(backed_up)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn delete_owned(pool: &PgPool, id: Uuid, user_id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM passkeys WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() == 1)
}
