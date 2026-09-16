//! Client applications: the settings `auth-api --register-client` writes, over
//! HTTP.

use serde_json::json;

use crate::{
    domain::{
        audit::AuditAction,
        registered_client::{self as client_domain, RegisteredClient},
    },
    error::AppError,
    repositories::{
        audit::{self, NewAuditEntry},
        registered_client::{self as client_repo, NewRegisteredClient},
        role as role_repo, session as session_repo,
    },
    services::{auth as auth_svc, reauth as reauth_svc},
    state::AppState,
};

use super::Actor;

pub async fn list(state: &AppState) -> Result<Vec<RegisteredClient>, AppError> {
    Ok(client_repo::find_all(&state.db).await?)
}

/// Create the client, or replace every setting of an existing one. Returns the
/// client and whether it was created.
pub async fn save(
    state: &AppState,
    actor: &Actor,
    client: &NewRegisteredClient<'_>,
) -> Result<(RegisteredClient, bool), AppError> {
    client_domain::check_settings(
        client.client_id,
        client.display_name,
        client.redirect_uris,
        client.default_max_sessions,
    )
    .map_err(AppError::Validation)?;
    let unknown = role_repo::unknown_permissions(&state.db, client.scopes).await?;
    if !unknown.is_empty() {
        return Err(AppError::Validation(format!(
            "unknown scopes: {}",
            unknown.join(", ")
        )));
    }
    reauth_svc::require_recent_reauth_or_password(
        state,
        actor.user_id,
        actor.session_id,
        None,
        actor.ip,
        actor.request_id,
        "admin_save_client",
    )
    .await?;

    let mut tx = state.db.begin().await?;
    let existed = client_repo::lock_existing(&mut *tx, client.client_id).await?;
    let saved = client_repo::upsert(&mut *tx, client).await.map_err(|e| {
        AppError::from_unique_violation(
            e,
            &[("idx_registered_clients_primary", "primary_client_exists")],
        )
    })?;
    audit::append(
        &mut *tx,
        &entry(
            actor,
            if existed {
                AuditAction::ClientUpdated
            } else {
                AuditAction::ClientRegistered
            },
            json!({ "client_id": saved.client_id }),
        ),
    )
    .await?;
    tx.commit().await?;
    Ok((saved, !existed))
}

/// Remove the client and end every session it holds.
pub async fn delete(state: &AppState, actor: &Actor, client_id: &str) -> Result<(), AppError> {
    let mut tx = state.db.begin().await?;
    let revoked = session_repo::revoke_by_client(&mut *tx, client_id).await?;
    if !client_repo::delete(&mut *tx, client_id).await? {
        return Err(AppError::NotFound);
    }
    audit::append(
        &mut *tx,
        &entry(
            actor,
            AuditAction::ClientDeleted,
            json!({ "client_id": client_id, "sessions_revoked": revoked.len() }),
        ),
    )
    .await?;
    tx.commit().await?;

    let ids = revoked.iter().map(|s| s.id).collect::<Vec<_>>();
    auth_svc::invalidate_session_caches(state, &ids).await;
    for session in &revoked {
        auth_svc::blocklist_refresh_token(state, &session.token_hash, session.expires_at).await;
    }
    Ok(())
}

fn entry(actor: &Actor, action: AuditAction, extra: serde_json::Value) -> NewAuditEntry {
    NewAuditEntry {
        user_id: Some(actor.user_id),
        request_id: actor.request_id,
        action,
        ip_address: actor.ip,
        metadata: actor.metadata(extra),
    }
}
