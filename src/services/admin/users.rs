//! Accounts seen and changed by an administrator.

use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    domain::{
        audit::AuditAction,
        user::{self as user_domain, User, UserStatus},
    },
    error::AppError,
    repositories::{
        audit::{self, NewAuditEntry},
        role as role_repo, session as session_repo, two_factor as two_factor_repo,
        user as user_repo,
    },
    services::{auth as auth_svc, events, reauth as reauth_svc, user as user_svc},
    state::AppState,
    utils::redis_counter,
};

use super::Actor;

/// An account with what an administrator needs to help its owner.
pub struct UserDetail {
    pub user: User,
    pub roles: Vec<String>,
    pub two_factor_methods: usize,
    pub active_sessions: usize,
}

pub async fn search(
    state: &AppState,
    query: Option<&str>,
    status: Option<&UserStatus>,
    before: Option<(OffsetDateTime, Uuid)>,
    limit: i64,
) -> Result<Vec<User>, AppError> {
    let pattern = query
        .filter(|q| !q.trim().is_empty())
        .map(user_domain::prefix_pattern);
    Ok(user_repo::search(&state.db, pattern.as_deref(), status, before, limit).await?)
}

pub async fn detail(state: &AppState, user_id: Uuid) -> Result<UserDetail, AppError> {
    let user = find(state, user_id).await?;
    let (roles, methods, sessions) = tokio::try_join!(
        role_repo::find_by_user(&state.db, user_id),
        two_factor_repo::find_by_user(&state.db, user_id),
        session_repo::find_active_by_user(&state.db, user_id),
    )?;
    Ok(UserDetail {
        user,
        roles: roles.into_iter().map(|role| role.name).collect(),
        two_factor_methods: methods.iter().filter(|m| m.is_verified).count(),
        active_sessions: sessions.len(),
    })
}

/// Suspend the account and end its sessions. Suspending a suspended account
/// changes nothing.
pub async fn suspend(state: &AppState, actor: &Actor, user_id: Uuid) -> Result<(), AppError> {
    refuse_own_account(actor, user_id)?;
    let user = find(state, user_id).await?;
    if user.status == UserStatus::PendingVerification {
        return Err(AppError::Validation(
            "an account that was never verified cannot be suspended; delete it instead".into(),
        ));
    }

    let active = session_repo::find_active_by_user(&state.db, user_id).await?;
    let mut tx = state.db.begin().await?;
    if !user_repo::suspend(&mut *tx, user_id).await? {
        return Ok(());
    }
    session_repo::revoke_all_by_user(&mut *tx, user_id).await?;
    audit::append(
        &mut *tx,
        &entry(
            actor,
            user_id,
            AuditAction::AccountSuspended,
            json!({ "sessions_revoked": active.len() }),
        ),
    )
    .await?;
    events::enqueue(
        &mut *tx,
        "user.suspended",
        &events::UserSuspended { user_id },
    )
    .await?;
    events::enqueue(
        &mut *tx,
        "user.sessions_revoked",
        &events::UserSessionsRevoked { user_id },
    )
    .await?;
    tx.commit().await?;
    events::wake();

    forget_sessions(state, &active).await;
    Ok(())
}

/// Lift a suspension. Reactivating an active account changes nothing.
pub async fn reactivate(state: &AppState, actor: &Actor, user_id: Uuid) -> Result<(), AppError> {
    find(state, user_id).await?;
    let mut tx = state.db.begin().await?;
    if !user_repo::reactivate(&mut *tx, user_id).await? {
        return Ok(());
    }
    audit::append(
        &mut *tx,
        &entry(actor, user_id, AuditAction::AccountReactivated, json!({})),
    )
    .await?;
    events::enqueue(
        &mut *tx,
        "user.reactivated",
        &events::UserReactivated { user_id },
    )
    .await?;
    tx.commit().await?;
    events::wake();
    Ok(())
}

/// End a lockout: the sign-in lockout and the re-authentication one.
pub async fn unlock(state: &AppState, actor: &Actor, user_id: Uuid) -> Result<(), AppError> {
    find(state, user_id).await?;
    user_repo::clear_lockout(&state.db, user_id).await?;
    redis_counter::reset(&state.redis, &[&user_svc::reauth_fail_key(user_id)]).await;
    audit::append(
        &state.db,
        &entry(actor, user_id, AuditAction::AccountUnlocked, json!({})),
    )
    .await?;
    Ok(())
}

/// Sign the account out everywhere.
pub async fn revoke_sessions(
    state: &AppState,
    actor: &Actor,
    user_id: Uuid,
) -> Result<u64, AppError> {
    refuse_own_account(actor, user_id)?;
    find(state, user_id).await?;
    let active = session_repo::find_active_by_user(&state.db, user_id).await?;

    let mut tx = state.db.begin().await?;
    let count = session_repo::revoke_all_by_user(&mut *tx, user_id).await?;
    audit::append(
        &mut *tx,
        &entry(
            actor,
            user_id,
            AuditAction::SessionRevoked,
            json!({ "count": count, "all": true }),
        ),
    )
    .await?;
    events::enqueue(
        &mut *tx,
        "user.sessions_revoked",
        &events::UserSessionsRevoked { user_id },
    )
    .await?;
    tx.commit().await?;
    events::wake();

    forget_sessions(state, &active).await;
    Ok(count)
}

/// Sign the account out everywhere and mail its owner a reset link, for an
/// account whose password is believed known to someone else.
pub async fn force_password_reset(
    state: &AppState,
    actor: &Actor,
    user_id: Uuid,
) -> Result<(), AppError> {
    refuse_own_account(actor, user_id)?;
    let user = find(state, user_id).await?;
    let active = session_repo::find_active_by_user(&state.db, user_id).await?;

    let mut tx = state.db.begin().await?;
    let count = session_repo::revoke_all_by_user(&mut *tx, user_id).await?;
    audit::append(
        &mut *tx,
        &entry(
            actor,
            user_id,
            AuditAction::PasswordResetForced,
            json!({ "sessions_revoked": count }),
        ),
    )
    .await?;
    events::enqueue(
        &mut *tx,
        "user.sessions_revoked",
        &events::UserSessionsRevoked { user_id },
    )
    .await?;
    tx.commit().await?;
    events::wake();

    forget_sessions(state, &active).await;
    auth_svc::send_reset_link(state, &user, actor.ip, None).await
}

/// Delete the account like its owner would, after a recent re-authentication of
/// the administrator.
pub async fn delete(
    state: &AppState,
    actor: &Actor,
    user_id: Uuid,
    current_password: Option<&str>,
) -> Result<(), AppError> {
    refuse_own_account(actor, user_id)?;
    reauth_svc::require_recent_reauth_or_password(
        state,
        actor.user_id,
        actor.session_id,
        current_password,
        actor.ip,
        actor.request_id,
        "admin_delete_account",
    )
    .await?;
    find(state, user_id).await?;
    user_svc::erase_account(
        state,
        user_id,
        actor.metadata(json!({})),
        actor.ip,
        actor.request_id,
    )
    .await
}

async fn find(state: &AppState, user_id: Uuid) -> Result<User, AppError> {
    user_repo::find_by_id(&state.db, user_id)
        .await?
        .ok_or(AppError::NotFound)
}

/// Administrators change their own account through `/users/me`, where the
/// usual re-authentication applies; suspending or deleting themselves from
/// here would also lock the last administrator out.
fn refuse_own_account(actor: &Actor, user_id: Uuid) -> Result<(), AppError> {
    if actor.user_id == user_id {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

fn entry(
    actor: &Actor,
    user_id: Uuid,
    action: AuditAction,
    extra: serde_json::Value,
) -> NewAuditEntry {
    NewAuditEntry {
        user_id: Some(user_id),
        request_id: actor.request_id,
        action,
        ip_address: actor.ip,
        metadata: actor.metadata(extra),
    }
}

/// Make revoked sessions stop working now rather than when caches expire.
async fn forget_sessions(state: &AppState, sessions: &[crate::domain::session::Session]) {
    let ids = sessions.iter().map(|s| s.id).collect::<Vec<_>>();
    auth_svc::invalidate_session_caches(state, &ids).await;
    for session in sessions {
        auth_svc::blocklist_refresh_token(state, &session.token_hash, session.expires_at).await;
        reauth_svc::clear_recent_reauth(state, session.id).await;
    }
}
