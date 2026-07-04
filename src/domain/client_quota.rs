//! User client quota domain type.
//!
//! Maps the `user_client_quotas` table. Controls how many concurrent
//! device sessions a user is allowed per client application.

use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserClientQuota {
    pub id: Uuid,
    pub user_id: Uuid,
    pub client_id: String,
    pub max_sessions: i16,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}
