//! Role and permission domain types.
//!
//! Maps the `roles`, `permissions`, `role_permissions`, and `user_roles` tables.
//! The `name` field on Permission is a generated column (resource:action)
//! and is read-only from the application side.

use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Role {
    pub id: Uuid,
    pub created_at: OffsetDateTime,
    pub is_default: bool,
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Permission {
    pub id: Uuid,
    pub created_at: OffsetDateTime,
    pub resource: String,
    pub action: String,
    // Generated column: resource || ':' || action
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserRole {
    pub user_id: Uuid,
    pub role_id: Uuid,
    pub granted_by: Option<Uuid>,
    pub granted_at: OffsetDateTime,
}
