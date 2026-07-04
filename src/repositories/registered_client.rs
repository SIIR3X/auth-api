//! Repository for the `registered_clients` table.

use sqlx::PgPool;

use crate::domain::registered_client::RegisteredClient;

/// Find a registered client by its client_id.
/// Returns None if the client_id is not registered.
pub async fn find_by_id(
    pool: &PgPool,
    client_id: &str,
) -> Result<Option<RegisteredClient>, sqlx::Error> {
    sqlx::query_as::<_, RegisteredClient>("SELECT * FROM registered_clients WHERE client_id = $1")
        .bind(client_id)
        .fetch_optional(pool)
        .await
}
