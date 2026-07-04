//! Registered client domain type.
//!
//! Maps the `registered_clients` table. Represents a known client application
//! that can authenticate users via the device authorization flow.

use time::OffsetDateTime;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RegisteredClient {
    pub client_id: String,
    pub display_name: String,
    pub is_primary: bool,
    pub created_at: OffsetDateTime,
}
