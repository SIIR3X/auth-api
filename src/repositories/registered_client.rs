//! Repository for the `registered_clients` table.

use sqlx::{PgExecutor, PgPool};

use crate::domain::registered_client::RegisteredClient;

/// Registration data written by `auth-api --register-client`.
pub struct NewRegisteredClient<'a> {
    pub client_id: &'a str,
    pub display_name: &'a str,
    pub is_primary: bool,
    pub scopes: &'a [String],
    pub redirect_uris: &'a [String],
    pub allows_loopback_redirect: bool,
    pub default_max_sessions: i16,
}

/// Find a registered client by its client_id.
pub async fn find_by_id(
    pool: &PgPool,
    client_id: &str,
) -> Result<Option<RegisteredClient>, sqlx::Error> {
    sqlx::query_as::<_, RegisteredClient>("SELECT * FROM registered_clients WHERE client_id = $1")
        .bind(client_id)
        .fetch_optional(pool)
        .await
}

/// Find the primary client. A partial unique index allows at most one.
pub async fn find_primary(pool: &PgPool) -> Result<Option<RegisteredClient>, sqlx::Error> {
    sqlx::query_as::<_, RegisteredClient>(
        "SELECT * FROM registered_clients WHERE is_primary = TRUE LIMIT 1",
    )
    .fetch_optional(pool)
    .await
}

/// Create a client, or update every setting of an existing one.
pub async fn upsert<'e>(
    executor: impl PgExecutor<'e>,
    client: &NewRegisteredClient<'_>,
) -> Result<RegisteredClient, sqlx::Error> {
    sqlx::query_as::<_, RegisteredClient>(
        "INSERT INTO registered_clients
             (client_id, display_name, is_primary, scopes, redirect_uris,
              allows_loopback_redirect, default_max_sessions)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (client_id) DO UPDATE SET
             display_name = EXCLUDED.display_name,
             is_primary = EXCLUDED.is_primary,
             scopes = EXCLUDED.scopes,
             redirect_uris = EXCLUDED.redirect_uris,
             allows_loopback_redirect = EXCLUDED.allows_loopback_redirect,
             default_max_sessions = EXCLUDED.default_max_sessions
         RETURNING *",
    )
    .bind(client.client_id)
    .bind(client.display_name)
    .bind(client.is_primary)
    .bind(client.scopes)
    .bind(client.redirect_uris)
    .bind(client.allows_loopback_redirect)
    .bind(client.default_max_sessions)
    .fetch_one(executor)
    .await
}

pub async fn find_all(pool: &PgPool) -> Result<Vec<RegisteredClient>, sqlx::Error> {
    sqlx::query_as::<_, RegisteredClient>("SELECT * FROM registered_clients ORDER BY client_id")
        .fetch_all(pool)
        .await
}

/// Remove a client; its consents and authorization codes go with it. Returns
/// whether it existed.
pub async fn delete<'e>(
    executor: impl PgExecutor<'e>,
    client_id: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM registered_clients WHERE client_id = $1")
        .bind(client_id)
        .execute(executor)
        .await?;
    Ok(result.rows_affected() == 1)
}

/// Whether the client exists, locking its row until the transaction ends.
pub async fn lock_existing<'e>(
    executor: impl PgExecutor<'e>,
    client_id: &str,
) -> Result<bool, sqlx::Error> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT client_id FROM registered_clients WHERE client_id = $1 FOR UPDATE")
            .bind(client_id)
            .fetch_optional(executor)
            .await?;
    Ok(row.is_some())
}

/// Set the digest of the client's secret, or clear it to make the client
/// public. Returns whether the client exists.
pub async fn set_secret_hash(
    pool: &PgPool,
    client_id: &str,
    secret_hash: Option<&[u8]>,
) -> Result<bool, sqlx::Error> {
    let result =
        sqlx::query("UPDATE registered_clients SET client_secret_hash = $2 WHERE client_id = $1")
            .bind(client_id)
            .bind(secret_hash)
            .execute(pool)
            .await?;
    Ok(result.rows_affected() == 1)
}
