//! Recent re-authentication service for sensitive actions.
//!
//! An explicit re-authentication (`POST /users/me/reauth`, or a
//! `current_password` supplied with a sensitive request) marks the current
//! session as "recently re-authenticated" for a short TTL in Redis. Signing in
//! does not: a fresh session obtained by an approved device code or a stolen
//! login must not be able to change the password or remove 2FA without it.
//!
//! Sensitive actions then require either a live marker on the session or the
//! user's current password, which refreshes the marker.

use deadpool_redis::redis::AsyncCommands;
use ipnetwork::IpNetwork;
use serde_json::json;
use uuid::Uuid;

use crate::{
    domain::audit::AuditAction,
    error::AppError,
    repositories::audit::{self, NewAuditEntry},
    state::AppState,
};

use super::user as user_svc;

const REAUTH_PREFIX: &str = "reauth:";

pub async fn mark_recent_reauth(state: &AppState, session_id: Uuid) {
    let ttl = state.config.security.sensitive_action_reauth_secs;
    if ttl == 0 {
        return;
    }

    if let Ok(mut conn) = state.redis.get().await {
        let key = reauth_key(session_id);
        // The value is when the password was proved: OpenID Connect `max_age`
        // and `auth_time` need it.
        let proven_at = state.clock.now().unix_timestamp();
        let _: Result<(), _> = conn.set_ex(&key, proven_at, ttl).await;
    }
}

pub async fn clear_recent_reauth(state: &AppState, session_id: Uuid) {
    if let Ok(mut conn) = state.redis.get().await {
        let key = reauth_key(session_id);
        let _: Result<(), _> = conn.del(&key).await;
    }
}

/// When the session last proved the password, while that proof still stands.
pub async fn reauth_proven_at(state: &AppState, session_id: Uuid) -> Option<i64> {
    let mut conn = state.redis.get().await.ok()?;
    let value: Option<String> = conn.get(reauth_key(session_id)).await.ok()?;
    value?.parse().ok()
}

pub async fn has_recent_reauth(state: &AppState, session_id: Uuid) -> bool {
    match state.redis.get().await {
        Ok(mut conn) => {
            let key = reauth_key(session_id);
            conn.exists::<_, bool>(&key).await.unwrap_or(false)
        }
        Err(_) => false,
    }
}

pub async fn reauthenticate(
    state: &AppState,
    user_id: Uuid,
    session_id: Uuid,
    current_password: &str,
    ip: Option<IpNetwork>,
    request_id: Option<Uuid>,
    reason: &'static str,
) -> Result<(), AppError> {
    user_svc::verify_password(state, user_id, session_id, current_password).await?;
    // Audited first: a proof of the password that left no trace grants
    // nothing.
    record_reauth_event(state, user_id, ip, request_id, reason).await?;
    mark_recent_reauth(state, session_id).await;
    Ok(())
}

pub async fn require_recent_reauth_or_password(
    state: &AppState,
    user_id: Uuid,
    session_id: Uuid,
    current_password: Option<&str>,
    ip: Option<IpNetwork>,
    request_id: Option<Uuid>,
    reason: &'static str,
) -> Result<(), AppError> {
    if let Some(current_password) = current_password {
        return reauthenticate(
            state,
            user_id,
            session_id,
            current_password,
            ip,
            request_id,
            reason,
        )
        .await;
    }

    if has_recent_reauth(state, session_id).await {
        Ok(())
    } else {
        Err(AppError::ReauthenticationRequired)
    }
}

async fn record_reauth_event(
    state: &AppState,
    user_id: Uuid,
    ip: Option<IpNetwork>,
    request_id: Option<Uuid>,
    reason: &'static str,
) -> Result<(), AppError> {
    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user_id),
            request_id,
            action: AuditAction::Reauthenticated,
            ip_address: ip,
            metadata: json!({ "reason": reason }),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))
}

fn reauth_key(session_id: Uuid) -> String {
    format!("{}{}", REAUTH_PREFIX, session_id)
}
