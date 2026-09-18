//! `/admin/roles`, `/admin/permissions` and the roles of an account.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    domain::role::Role,
    error::AppError,
    handlers::extractors::{AdminUser, ClientIp},
    repositories::role as role_repo,
    services::admin::roles as admin_roles,
    state::AppState,
};

use super::actor;

#[derive(Serialize, utoipa::ToSchema)]
pub struct PermissionResponse {
    /// `resource:action`.
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct RoleResponse {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Given to every new account.
    pub is_default: bool,
    pub permissions: Vec<String>,
    pub created_at: i64,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct CreateRoleRequest {
    pub name: String,
    pub description: Option<String>,
    #[serde(default)]
    pub permissions: Vec<String>,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct RolePermissionsRequest {
    pub permissions: Vec<String>,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct AssignRoleRequest {
    pub role: String,
}

fn role_response(role: Role, permissions: Vec<String>) -> RoleResponse {
    RoleResponse {
        name: role.name,
        description: role.description,
        is_default: role.is_default,
        permissions,
        created_at: role.created_at.unix_timestamp(),
    }
}

#[utoipa::path(
    get,
    path = "/admin/permissions",
    tag = "admin",
    responses(
        (status = 200, description = "Every permission a role can grant", body = [PermissionResponse]),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Missing `roles:manage`, or no second factor enrolled", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn permissions(
    admin: AdminUser,
    State(state): State<AppState>,
) -> Result<Json<Vec<PermissionResponse>>, AppError> {
    admin.require(&state, "roles:manage").await?;
    let permissions = role_repo::find_all_permissions(&state.db).await?;
    Ok(Json(
        permissions
            .into_iter()
            .map(|p| PermissionResponse {
                name: p.name,
                description: p.description,
            })
            .collect(),
    ))
}

#[utoipa::path(
    get,
    path = "/admin/roles",
    tag = "admin",
    responses(
        (status = 200, description = "Every role with its permissions", body = [RoleResponse]),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Missing `roles:manage`, or no second factor enrolled", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn list(
    admin: AdminUser,
    State(state): State<AppState>,
) -> Result<Json<Vec<RoleResponse>>, AppError> {
    admin.require(&state, "roles:manage").await?;
    let roles = admin_roles::list(&state).await?;
    Ok(Json(
        roles
            .into_iter()
            .map(|(role, permissions)| role_response(role, permissions))
            .collect(),
    ))
}

#[utoipa::path(
    post,
    path = "/admin/roles",
    tag = "admin",
    request_body = CreateRoleRequest,
    responses(
        (status = 201, description = "Role created", body = RoleResponse),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Missing `roles:manage`, no second factor, or re-authentication required", body = crate::error::ErrorBody),
        (status = 409, description = "`role_exists`", body = crate::error::ErrorBody),
        (status = 422, description = "Invalid name or unknown permission", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn create(
    admin: AdminUser,
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(body): Json<CreateRoleRequest>,
) -> Result<(StatusCode, Json<RoleResponse>), AppError> {
    admin.require(&state, "roles:manage").await?;
    let (role, permissions) = admin_roles::create(
        &state,
        &actor(&admin, ip),
        &body.name,
        body.description.as_deref(),
        &body.permissions,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(role_response(role, permissions))))
}

#[utoipa::path(
    put,
    path = "/admin/roles/{name}/permissions",
    tag = "admin",
    params(("name" = String, Path, description = "Role name")),
    request_body = RolePermissionsRequest,
    responses(
        (status = 200, description = "The role now grants exactly these permissions", body = RoleResponse),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Missing `roles:manage`, no second factor, or re-authentication required", body = crate::error::ErrorBody),
        (status = 404, description = "No such role", body = crate::error::ErrorBody),
        (status = 409, description = "`last_administrator`: nobody would keep `roles:manage`", body = crate::error::ErrorBody),
        (status = 422, description = "Unknown permission", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn set_permissions(
    admin: AdminUser,
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(name): Path<String>,
    Json(body): Json<RolePermissionsRequest>,
) -> Result<Json<RoleResponse>, AppError> {
    admin.require(&state, "roles:manage").await?;
    let (role, permissions) =
        admin_roles::set_permissions(&state, &actor(&admin, ip), &name, &body.permissions).await?;
    Ok(Json(role_response(role, permissions)))
}

#[utoipa::path(
    delete,
    path = "/admin/roles/{name}",
    tag = "admin",
    params(("name" = String, Path, description = "Role name")),
    responses(
        (status = 204, description = "Role deleted and taken back from every account"),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Missing `roles:manage`, or no second factor enrolled", body = crate::error::ErrorBody),
        (status = 404, description = "No such role", body = crate::error::ErrorBody),
        (status = 409, description = "`default_role`, or `last_administrator`", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn delete(
    admin: AdminUser,
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(name): Path<String>,
) -> Result<StatusCode, AppError> {
    admin.require(&state, "roles:manage").await?;
    admin_roles::delete(&state, &actor(&admin, ip), &name).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/admin/users/{id}/roles",
    tag = "admin",
    params(("id" = Uuid, Path, description = "Account id")),
    request_body = AssignRoleRequest,
    responses(
        (status = 204, description = "Role granted, or already held"),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Missing `roles:manage`, no second factor, or re-authentication required", body = crate::error::ErrorBody),
        (status = 404, description = "No such account or role", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn assign(
    admin: AdminUser,
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(user_id): Path<Uuid>,
    Json(body): Json<AssignRoleRequest>,
) -> Result<StatusCode, AppError> {
    admin.require(&state, "roles:manage").await?;
    admin_roles::assign(&state, &actor(&admin, ip), user_id, &body.role).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/admin/users/{id}/roles/{name}",
    tag = "admin",
    params(
        ("id" = Uuid, Path, description = "Account id"),
        ("name" = String, Path, description = "Role name"),
    ),
    responses(
        (status = 204, description = "Role taken back, or not held"),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Missing `roles:manage`, or no second factor enrolled", body = crate::error::ErrorBody),
        (status = 404, description = "No such role", body = crate::error::ErrorBody),
        (status = 409, description = "`last_administrator`: nobody would keep `roles:manage`", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn unassign(
    admin: AdminUser,
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path((user_id, name)): Path<(Uuid, String)>,
) -> Result<StatusCode, AppError> {
    admin.require(&state, "roles:manage").await?;
    admin_roles::unassign(&state, &actor(&admin, ip), user_id, &name).await?;
    Ok(StatusCode::NO_CONTENT)
}
