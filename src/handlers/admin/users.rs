//! `/admin/users`: finding an account and acting on it.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    domain::user::{User, UserStatus},
    error::AppError,
    handlers::{
        audit::{decode_cursor, encode_cursor, page_limit, rows_to_fetch, split_page},
        extractors::{AdminUser, ClientIp},
        user::{CurrentPasswordRequest, user_status_str},
    },
    services::admin::users as admin_users,
    state::AppState,
};

use super::actor;

#[derive(Deserialize, utoipa::ToSchema)]
pub struct SearchParams {
    /// Start of the address or of the username, case-insensitive.
    pub query: Option<String>,
    /// `active`, `inactive`, `suspended` or `pending_verification`.
    pub status: Option<String>,
    pub limit: Option<i64>,
    /// `next_cursor` of the previous page.
    pub cursor: Option<String>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct AdminUserSummary {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub status: String,
    pub preferred_locale: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_login_at: Option<i64>,
    /// Present while a sign-in lockout lasts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locked_until: Option<i64>,
    pub created_at: i64,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct AdminUserPage {
    pub users: Vec<AdminUserSummary>,
    /// Pass back as `cursor` to read the next page; absent on the last one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct AdminUserDetail {
    #[serde(flatten)]
    pub account: AdminUserSummary,
    pub roles: Vec<String>,
    /// Verified second factors.
    pub two_factor_methods: usize,
    pub active_sessions: usize,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct RevokedSessionsResponse {
    pub revoked: u64,
}

fn summary(state: &AppState, user: User) -> AdminUserSummary {
    let now = state.clock.now();
    AdminUserSummary {
        id: user.id,
        status: user_status_str(&user.status),
        locked_until: user
            .locked_until
            .filter(|until| *until > now)
            .map(|until| until.unix_timestamp()),
        email_verified_at: user.email_verified_at.map(|t| t.unix_timestamp()),
        last_login_at: user.last_login_at.map(|t| t.unix_timestamp()),
        created_at: user.created_at.unix_timestamp(),
        username: user.username,
        email: user.email,
        preferred_locale: user.preferred_locale,
    }
}

fn parse_status(status: &str) -> Result<UserStatus, AppError> {
    match status {
        "active" => Ok(UserStatus::Active),
        "inactive" => Ok(UserStatus::Inactive),
        "suspended" => Ok(UserStatus::Suspended),
        "pending_verification" => Ok(UserStatus::PendingVerification),
        _ => Err(AppError::Validation("unknown status".into())),
    }
}

#[utoipa::path(
    get,
    path = "/admin/users",
    tag = "admin",
    params(
        ("query" = Option<String>, Query, description = "Start of the address or username"),
        ("status" = Option<String>, Query, description = "active, inactive, suspended or pending_verification"),
        ("limit" = Option<i64>, Query, description = "Accounts per page, 1-200 (default 50)"),
        ("cursor" = Option<String>, Query, description = "next_cursor of the previous page"),
    ),
    responses(
        (status = 200, description = "Accounts, newest first", body = AdminUserPage),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Missing `users:read`, or no second factor enrolled", body = crate::error::ErrorBody),
        (status = 422, description = "Invalid status or cursor", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn search(
    admin: AdminUser,
    State(state): State<AppState>,
    Query(params): Query<SearchParams>,
) -> Result<Json<AdminUserPage>, AppError> {
    admin.require(&state, "users:read").await?;
    let limit = page_limit(params.limit);
    let status = params.status.as_deref().map(parse_status).transpose()?;
    let before = params.cursor.as_deref().map(decode_cursor).transpose()?;

    let rows = admin_users::search(
        &state,
        params.query.as_deref(),
        status.as_ref(),
        before,
        rows_to_fetch(limit),
    )
    .await?;
    let (rows, more) = split_page(rows, limit);
    let next_cursor = more
        .then(|| {
            rows.last()
                .map(|last| encode_cursor(last.created_at, last.id))
        })
        .flatten();

    Ok(Json(AdminUserPage {
        users: rows.into_iter().map(|user| summary(&state, user)).collect(),
        next_cursor,
    }))
}

#[utoipa::path(
    get,
    path = "/admin/users/{id}",
    tag = "admin",
    params(("id" = Uuid, Path, description = "Account id")),
    responses(
        (status = 200, description = "The account", body = AdminUserDetail),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Missing `users:read`, or no second factor enrolled", body = crate::error::ErrorBody),
        (status = 404, description = "No such account", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn detail(
    admin: AdminUser,
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<AdminUserDetail>, AppError> {
    admin.require(&state, "users:read").await?;
    let detail = admin_users::detail(&state, user_id).await?;
    Ok(Json(AdminUserDetail {
        account: summary(&state, detail.user),
        roles: detail.roles,
        two_factor_methods: detail.two_factor_methods,
        active_sessions: detail.active_sessions,
    }))
}

#[utoipa::path(
    post,
    path = "/admin/users/{id}/suspend",
    tag = "admin",
    params(("id" = Uuid, Path, description = "Account id")),
    responses(
        (status = 204, description = "Suspended and signed out everywhere, or already suspended"),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Missing `users:manage`, no second factor enrolled, or the administrator's own account", body = crate::error::ErrorBody),
        (status = 404, description = "No such account", body = crate::error::ErrorBody),
        (status = 422, description = "The account was never verified", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn suspend(
    admin: AdminUser,
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(user_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    admin.require(&state, "users:manage").await?;
    admin_users::suspend(&state, &actor(&admin, ip), user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/admin/users/{id}/reactivate",
    tag = "admin",
    params(("id" = Uuid, Path, description = "Account id")),
    responses(
        (status = 204, description = "Active again, or already active"),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Missing `users:manage`, or no second factor enrolled", body = crate::error::ErrorBody),
        (status = 404, description = "No such account", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn reactivate(
    admin: AdminUser,
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(user_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    admin.require(&state, "users:manage").await?;
    admin_users::reactivate(&state, &actor(&admin, ip), user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/admin/users/{id}/unlock",
    tag = "admin",
    params(("id" = Uuid, Path, description = "Account id")),
    responses(
        (status = 204, description = "Lockouts ended and past failures forgiven"),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Missing `users:manage`, or no second factor enrolled", body = crate::error::ErrorBody),
        (status = 404, description = "No such account", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn unlock(
    admin: AdminUser,
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(user_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    admin.require(&state, "users:manage").await?;
    admin_users::unlock(&state, &actor(&admin, ip), user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/admin/users/{id}/sessions",
    tag = "admin",
    params(("id" = Uuid, Path, description = "Account id")),
    responses(
        (status = 200, description = "Signed out everywhere", body = RevokedSessionsResponse),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Missing `users:manage`, no second factor enrolled, or the administrator's own account", body = crate::error::ErrorBody),
        (status = 404, description = "No such account", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn revoke_sessions(
    admin: AdminUser,
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(user_id): Path<Uuid>,
) -> Result<Json<RevokedSessionsResponse>, AppError> {
    admin.require(&state, "users:manage").await?;
    let revoked = admin_users::revoke_sessions(&state, &actor(&admin, ip), user_id).await?;
    Ok(Json(RevokedSessionsResponse { revoked }))
}

#[utoipa::path(
    post,
    path = "/admin/users/{id}/password-reset",
    tag = "admin",
    params(("id" = Uuid, Path, description = "Account id")),
    responses(
        (status = 204, description = "Signed out everywhere and a reset link mailed to the owner"),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Missing `users:manage`, no second factor enrolled, or the administrator's own account", body = crate::error::ErrorBody),
        (status = 404, description = "No such account", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn force_password_reset(
    admin: AdminUser,
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(user_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    admin.require(&state, "users:manage").await?;
    admin_users::force_password_reset(&state, &actor(&admin, ip), user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/admin/users/{id}",
    tag = "admin",
    params(("id" = Uuid, Path, description = "Account id")),
    request_body = Option<CurrentPasswordRequest>,
    responses(
        (status = 204, description = "Account deleted and `user.deleted` announced"),
        (status = 401, description = "Missing, invalid or revoked access token, or wrong password", body = crate::error::ErrorBody),
        (status = 403, description = "Missing `users:manage`, no second factor, the administrator's own account, or re-authentication required", body = crate::error::ErrorBody),
        (status = 404, description = "No such account", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn delete(
    admin: AdminUser,
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(user_id): Path<Uuid>,
    body: Option<Json<CurrentPasswordRequest>>,
) -> Result<StatusCode, AppError> {
    admin.require(&state, "users:manage").await?;
    let current_password = body.and_then(|Json(b)| b.current_password);
    admin_users::delete(
        &state,
        &actor(&admin, ip),
        user_id,
        current_password.as_deref(),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}
