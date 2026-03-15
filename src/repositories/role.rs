//! Repository for `roles`, `permissions`, `role_permissions`, and `user_roles`.

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::role::{Permission, Role, UserRole};

// Roles

pub async fn find_all(pool: &PgPool) -> Result<Vec<Role>, sqlx::Error> {
    sqlx::query_as::<_, Role>("SELECT * FROM roles ORDER BY name")
        .fetch_all(pool)
        .await
}

pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Role>, sqlx::Error> {
    sqlx::query_as::<_, Role>("SELECT * FROM roles WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn find_by_name(pool: &PgPool, name: &str) -> Result<Option<Role>, sqlx::Error> {
    sqlx::query_as::<_, Role>("SELECT * FROM roles WHERE name = $1")
        .bind(name)
        .fetch_optional(pool)
        .await
}

/// Returns the role automatically assigned on registration.
pub async fn find_default(pool: &PgPool) -> Result<Option<Role>, sqlx::Error> {
    sqlx::query_as::<_, Role>("SELECT * FROM roles WHERE is_default = TRUE LIMIT 1")
        .fetch_optional(pool)
        .await
}

// User roles

pub async fn find_by_user(pool: &PgPool, user_id: Uuid) -> Result<Vec<Role>, sqlx::Error> {
    sqlx::query_as::<_, Role>(
        "SELECT r.*
         FROM roles r
         JOIN user_roles ur ON ur.role_id = r.id
         WHERE ur.user_id = $1",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}

pub async fn assign_to_user(
    pool: &PgPool,
    user_id: Uuid,
    role_id: Uuid,
    granted_by: Option<Uuid>,
) -> Result<UserRole, sqlx::Error> {
    sqlx::query_as::<_, UserRole>(
        "INSERT INTO user_roles (user_id, role_id, granted_by)
         VALUES ($1, $2, $3)
         ON CONFLICT (user_id, role_id) DO NOTHING
         RETURNING *",
    )
    .bind(user_id)
    .bind(role_id)
    .bind(granted_by)
    .fetch_one(pool)
    .await
}

pub async fn revoke_from_user(
    pool: &PgPool,
    user_id: Uuid,
    role_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2")
        .bind(user_id)
        .bind(role_id)
        .execute(pool)
        .await?;
    Ok(())
}

// Permissions

/// Returns all permissions granted to a user across all their roles.
pub async fn find_permissions_by_user(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Vec<Permission>, sqlx::Error> {
    sqlx::query_as::<_, Permission>(
        "SELECT DISTINCT p.*
         FROM permissions p
         JOIN role_permissions rp ON rp.permission_id = p.id
         JOIN user_roles ur ON ur.role_id = rp.role_id
         WHERE ur.user_id = $1",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}

/// Single-query permission check; avoids loading the full permission list.
pub async fn user_has_permission(
    pool: &PgPool,
    user_id: Uuid,
    permission_name: &str,
) -> Result<bool, sqlx::Error> {
    let row: (bool,) = sqlx::query_as(
        "SELECT EXISTS (
             SELECT 1
             FROM permissions p
             JOIN role_permissions rp ON rp.permission_id = p.id
             JOIN user_roles ur ON ur.role_id = rp.role_id
             WHERE ur.user_id = $1
             AND p.name = $2
         )",
    )
    .bind(user_id)
    .bind(permission_name)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

pub async fn find_granted_at(
    pool: &PgPool,
    user_id: Uuid,
    role_id: Uuid,
) -> Result<Option<OffsetDateTime>, sqlx::Error> {
    let row: Option<(OffsetDateTime,)> =
        sqlx::query_as("SELECT granted_at FROM user_roles WHERE user_id = $1 AND role_id = $2")
            .bind(user_id)
            .bind(role_id)
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|r| r.0))
}
