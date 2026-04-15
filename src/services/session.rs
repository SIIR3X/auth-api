//! Session management: list active sessions, revoke one or all.

use ipnetwork::IpNetwork;
use serde_json::json;
use uuid::Uuid;

use crate::{
    domain::audit::AuditAction,
    error::AppError,
    repositories::{
        audit::{self, NewAuditEntry},
        session::{self as session_repo, ActiveSessionSummary},
    },
    state::AppState,
};

use super::{auth as auth_svc, reauth as reauth_svc};

pub async fn list_active(
    state: &AppState,
    user_id: Uuid,
) -> Result<Vec<ActiveSessionSummary>, AppError> {
    session_repo::find_active_summary_by_user(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))
}

/// Revokes a specific session. Verifies ownership before revoking.
pub async fn revoke(
    state: &AppState,
    user_id: Uuid,
    current_session_id: Uuid,
    session_id: Uuid,
    ip: Option<IpNetwork>,
    request_id: Option<Uuid>,
) -> Result<(), AppError> {
    reauth_svc::require_recent_reauth_or_password(
        state,
        user_id,
        current_session_id,
        None,
        ip,
        request_id,
        "revoke_session",
    )
    .await?;

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

    // Blacklist the refresh token so it cannot be used even before DB TTL expires.
    auth_svc::blocklist_refresh_token(state, &session.token_hash, session.expires_at).await;
    auth_svc::invalidate_session_cache(state, session.id);
    reauth_svc::clear_recent_reauth(state, session.id).await;

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user_id),
            request_id,
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
/// Requires the user's current password as confirmation.
pub async fn revoke_all(
    state: &AppState,
    user_id: Uuid,
    current_session_id: Uuid,
    current_password: Option<&str>,
    ip: Option<IpNetwork>,
    request_id: Option<Uuid>,
) -> Result<u64, AppError> {
    reauth_svc::require_recent_reauth_or_password(
        state,
        user_id,
        current_session_id,
        current_password,
        ip,
        request_id,
        "revoke_all_sessions",
    )
    .await?;

    // Collect active sessions before revoking so we can blacklist their tokens.
    let active = session_repo::find_active_by_user(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    let count = session_repo::revoke_all_by_user(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    let session_ids = active.iter().map(|s| s.id).collect::<Vec<_>>();
    auth_svc::invalidate_session_caches(state, &session_ids).await;

    for s in &active {
        auth_svc::blocklist_refresh_token(state, &s.token_hash, s.expires_at).await;
        reauth_svc::clear_recent_reauth(state, s.id).await;
    }

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user_id),
            request_id,
            action: AuditAction::SessionRevoked,
            ip_address: ip,
            metadata: json!({"count": count, "all": true}),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    Ok(count)
}
