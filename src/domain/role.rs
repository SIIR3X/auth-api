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

/// Permissions of the administration routes. A token carrying none of them
/// cannot reach `/admin`.
pub const ADMIN_PERMISSIONS: [&str; 6] = [
    "users:read",
    "users:manage",
    "roles:manage",
    "clients:manage",
    "audit:read",
    "webhooks:manage",
];

pub fn is_admin_permission(permission: &str) -> bool {
    ADMIN_PERMISSIONS.contains(&permission)
}
