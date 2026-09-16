//! `/admin/audit`: the audit log of every account.

use axum::{
    Json,
    extract::{Query, State},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    error::AppError,
    handlers::{
        audit::{
            AuditEntryResponse, action_name, decode_cursor, encode_cursor, page_limit,
            rows_to_fetch, split_page,
        },
        extractors::AdminUser,
    },
    repositories::audit as audit_repo,
    state::AppState,
};

#[derive(Deserialize, utoipa::ToSchema)]
pub struct AdminAuditParams {
    /// Only this account's entries.
    pub user_id: Option<Uuid>,
    /// Only this action, such as `login_failed`.
    pub action: Option<String>,
    pub limit: Option<i64>,
    /// `next_cursor` of the previous page.
    pub cursor: Option<String>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct AdminAuditEntry {
    /// Absent once the account is deleted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<Uuid>,
    #[serde(flatten)]
    pub entry: AuditEntryResponse,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct AdminAuditPage {
    pub entries: Vec<AdminAuditEntry>,
    /// Pass back as `cursor` to read the next page; absent on the last one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[utoipa::path(
    get,
    path = "/admin/audit",
    tag = "admin",
    params(
        ("user_id" = Option<Uuid>, Query, description = "Only this account's entries"),
        ("action" = Option<String>, Query, description = "Only this action"),
        ("limit" = Option<i64>, Query, description = "Entries per page, 1-200 (default 50)"),
        ("cursor" = Option<String>, Query, description = "next_cursor of the previous page"),
    ),
    responses(
        (status = 200, description = "Audit entries, newest first", body = AdminAuditPage),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Missing `audit:read`, or no second factor enrolled", body = crate::error::ErrorBody),
        (status = 422, description = "Invalid cursor or account id", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn list(
    admin: AdminUser,
    State(state): State<AppState>,
    Query(params): Query<AdminAuditParams>,
) -> Result<Json<AdminAuditPage>, AppError> {
    admin.require(&state, "audit:read").await?;
    let limit = page_limit(params.limit);
    let before = params.cursor.as_deref().map(decode_cursor).transpose()?;

    let rows = audit_repo::find_page(
        &state.db,
        params.user_id,
        params.action.as_deref(),
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

    Ok(Json(AdminAuditPage {
        entries: rows
            .into_iter()
            .map(|entry| AdminAuditEntry {
                user_id: entry.user_id,
                entry: AuditEntryResponse {
                    id: entry.id,
                    created_at: entry.created_at.unix_timestamp(),
                    action: action_name(&entry.action),
                    ip_address: entry.ip_address.map(|net| net.ip().to_string()),
                    request_id: entry.request_id,
                    metadata: entry.metadata,
                },
            })
            .collect(),
        next_cursor,
    }))
}
