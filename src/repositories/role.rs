//! Repository for `roles`, `permissions`, `role_permissions`, and `user_roles`.

use sqlx::{PgExecutor, PgPool};
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

/// Role and permission names a user holds, in one round trip: what an access
/// token carries.
pub async fn find_rbac_names(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<(Vec<String>, Vec<String>), sqlx::Error> {
    sqlx::query_as::<_, (Vec<String>, Vec<String>)>(
        "SELECT
             COALESCE(ARRAY(
                 SELECT r.name::TEXT FROM user_roles ur
                 JOIN roles r ON r.id = ur.role_id
                 WHERE ur.user_id = $1
                 ORDER BY r.name
             ), '{}'),
             COALESCE(ARRAY(
                 SELECT DISTINCT p.name FROM user_roles ur
                 JOIN role_permissions rp ON rp.role_id = ur.role_id
                 JOIN permissions p ON p.id = rp.permission_id
                 WHERE ur.user_id = $1
                 ORDER BY p.name
             ), '{}')",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
}

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

pub async fn assign_to_user<'e>(
    executor: impl sqlx::PgExecutor<'e>,
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
    .fetch_one(executor)
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

// Administration

/// Every role with the names of the permissions it grants.
pub async fn find_all_with_permissions(
    pool: &PgPool,
) -> Result<Vec<(Role, Vec<String>)>, sqlx::Error> {
    let roles = find_all(pool).await?;
    let grants: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT rp.role_id, p.name FROM role_permissions rp
         JOIN permissions p ON p.id = rp.permission_id
         ORDER BY p.name",
    )
    .fetch_all(pool)
    .await?;
    Ok(roles
        .into_iter()
        .map(|role| {
            let names = grants
                .iter()
                .filter(|(role_id, _)| *role_id == role.id)
                .map(|(_, name)| name.clone())
                .collect();
            (role, names)
        })
        .collect())
}

pub async fn find_all_permissions(pool: &PgPool) -> Result<Vec<Permission>, sqlx::Error> {
    sqlx::query_as::<_, Permission>("SELECT * FROM permissions ORDER BY name")
        .fetch_all(pool)
        .await
}

/// The names among `names` that are not permissions.
pub async fn unknown_permissions(
    pool: &PgPool,
    names: &[String],
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT requested.name FROM UNNEST($1::text[]) AS requested (name)
         WHERE NOT EXISTS (SELECT 1 FROM permissions p WHERE p.name = requested.name)
         ORDER BY requested.name",
    )
    .bind(names)
    .fetch_all(pool)
    .await
}

pub async fn create<'e>(
    executor: impl PgExecutor<'e>,
    name: &str,
    description: Option<&str>,
) -> Result<Role, sqlx::Error> {
    sqlx::query_as::<_, Role>("INSERT INTO roles (name, description) VALUES ($1, $2) RETURNING *")
        .bind(name)
        .bind(description)
        .fetch_one(executor)
        .await
}

/// Make the role grant exactly `names`.
pub async fn set_permissions(
    tx: &mut sqlx::PgConnection,
    role_id: Uuid,
    names: &[String],
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM role_permissions WHERE role_id = $1")
        .bind(role_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO role_permissions (role_id, permission_id)
         SELECT $1, id FROM permissions WHERE name = ANY($2)",
    )
    .bind(role_id)
    .bind(names)
    .execute(&mut *tx)
    .await?;
    Ok(())
}

pub async fn delete<'e>(executor: impl PgExecutor<'e>, role_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM roles WHERE id = $1")
        .bind(role_id)
        .execute(executor)
        .await?;
    Ok(())
}

/// Remove the role from the user. Returns whether the user held it.
pub async fn unassign<'e>(
    executor: impl PgExecutor<'e>,
    user_id: Uuid,
    role_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2")
        .bind(user_id)
        .bind(role_id)
        .execute(executor)
        .await?;
    Ok(result.rows_affected() == 1)
}

/// Whether any account holds `permission`.
pub async fn permission_held<'e>(
    executor: impl PgExecutor<'e>,
    permission: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1 FROM user_roles ur
             JOIN role_permissions rp ON rp.role_id = ur.role_id
             JOIN permissions p ON p.id = rp.permission_id
             WHERE p.name = $1
         )",
    )
    .bind(permission)
    .fetch_one(executor)
    .await
}
