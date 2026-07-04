//! Repository for the `user_client_quotas` table.

use sqlx::PgPool;
use uuid::Uuid;

use crate::domain::client_quota::UserClientQuota;

/// Find the quota for a specific user + client_id pair.
/// Returns None if the user has no quota for this client (access denied).
pub async fn find_by_user_and_client(
    pool: &PgPool,
    user_id: Uuid,
    client_id: &str,
) -> Result<Option<UserClientQuota>, sqlx::Error> {
    sqlx::query_as::<_, UserClientQuota>(
        "SELECT * FROM user_client_quotas WHERE user_id = $1 AND client_id = $2",
    )
    .bind(user_id)
    .bind(client_id)
    .fetch_optional(pool)
    .await
}
