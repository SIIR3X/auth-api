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

/// The permission that manages roles: at least one account must keep it, or
/// nobody could grant anything again without the command line.
pub const ROLES_MANAGE: &str = "roles:manage";

/// Role names: lower-case ASCII letters, digits and underscores, starting with a
/// letter, 2 to 50 characters.
pub fn is_valid_role_name(name: &str) -> bool {
    (2..=50).contains(&name.len())
        && name.as_bytes()[0].is_ascii_lowercase()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_names_are_lower_case_identifiers() {
        for valid in ["admin", "support_2", "ab"] {
            assert!(is_valid_role_name(valid), "{valid}");
        }
        for invalid in ["", "a", "Admin", "2fa", "_x", "sup-port", &"a".repeat(51)] {
            assert!(!is_valid_role_name(invalid), "{invalid}");
        }
    }

    #[test]
    fn administrative_permissions_are_recognized() {
        assert!(is_admin_permission("users:read"));
        assert!(!is_admin_permission("profile:read"));
    }
}
