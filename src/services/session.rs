//! Session management: list active sessions, revoke one or all.

use ipnetwork::IpNetwork;
use serde_json::json;
use uuid::Uuid;

use crate::{
    domain::{audit::AuditAction, session::Session},
    error::AppError,
    repositories::{
        audit::{self, NewAuditEntry},
        session as session_repo,
    },
    state::AppState,
};

pub async fn list_active(state: &AppState, user_id: Uuid) -> Result<Vec<Session>, AppError> {
    session_repo::find_active_by_user(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))
}

/// Revokes a specific session. Verifies ownership before revoking.
pub async fn revoke(
    state: &AppState,
    user_id: Uuid,
    session_id: Uuid,
    ip: Option<IpNetwork>,
) -> Result<(), AppError> {
    let session = session_repo::find_by_id(&state.db, session_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::NotFound)?;

    // Ownership check
    if session.user_id != user_id {
        return Err(AppError::Forbidden);
    }

    session_repo::revoke(&state.db, session_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user_id),
            request_id: None,
            action: AuditAction::SessionRevoked,
            ip_address: ip,
            metadata: json!({"session_id": session_id}),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    Ok(())
}

/// Revokes all active sessions for the user (sign out everywhere).
pub async fn revoke_all(
    state: &AppState,
    user_id: Uuid,
    ip: Option<IpNetwork>,
) -> Result<u64, AppError> {
    let count = session_repo::revoke_all_by_user(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user_id),
            request_id: None,
            action: AuditAction::SessionRevoked,
            ip_address: ip,
            metadata: json!({"count": count, "all": true}),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    Ok(count)
}
