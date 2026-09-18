//! Roles, the permissions they grant, and who holds them.
//!
//! A role change reaches access tokens when they are refreshed; `/admin` routes
//! check the database on every request and see it at once.

use serde_json::json;
use uuid::Uuid;

use crate::{
    domain::{
        audit::AuditAction,
        role::{self as role_domain, Role},
    },
    error::AppError,
    repositories::{
        audit::{self, NewAuditEntry},
        role as role_repo, user as user_repo,
    },
    services::reauth as reauth_svc,
    state::AppState,
};

use super::Actor;

pub async fn list(state: &AppState) -> Result<Vec<(Role, Vec<String>)>, AppError> {
    Ok(role_repo::find_all_with_permissions(&state.db).await?)
}

pub async fn create(
    state: &AppState,
    actor: &Actor,
    name: &str,
    description: Option<&str>,
    permissions: &[String],
) -> Result<(Role, Vec<String>), AppError> {
    if !role_domain::is_valid_role_name(name) {
        return Err(AppError::Validation(
            "role name must be 2 to 50 lower-case letters, digits or underscores, starting with a letter".into(),
        ));
    }
    if description.is_some_and(|d| d.chars().count() > 500) {
        return Err(AppError::Validation(
            "description must be at most 500 characters".into(),
        ));
    }
    let permissions = known_permissions(state, permissions).await?;
    require_reauth(state, actor, "admin_create_role").await?;

    let mut tx = state.db.begin().await?;
    let role = role_repo::create(&mut *tx, name, description)
        .await
        .map_err(|e| AppError::from_unique_violation(e, &[("roles_name_key", "role_exists")]))?;
    role_repo::set_permissions(&mut tx, role.id, &permissions).await?;
    audit::append(
        &mut *tx,
        &own_entry(
            actor,
            AuditAction::RoleCreated,
            json!({ "role": role.name, "permissions": permissions }),
        ),
    )
    .await?;
    tx.commit().await?;
    Ok((role, permissions))
}

/// Make the role grant exactly `permissions`.
pub async fn set_permissions(
    state: &AppState,
    actor: &Actor,
    name: &str,
    permissions: &[String],
) -> Result<(Role, Vec<String>), AppError> {
    let role = find(state, name).await?;
    let permissions = known_permissions(state, permissions).await?;
    require_reauth(state, actor, "admin_change_role").await?;

    let mut tx = state.db.begin().await?;
    role_repo::set_permissions(&mut tx, role.id, &permissions).await?;
    keep_an_administrator(&mut tx).await?;
    audit::append(
        &mut *tx,
        &own_entry(
            actor,
            AuditAction::RolePermissionsChanged,
            json!({ "role": role.name, "permissions": permissions }),
        ),
    )
    .await?;
    tx.commit().await?;
    Ok((role, permissions))
}

pub async fn delete(state: &AppState, actor: &Actor, name: &str) -> Result<(), AppError> {
    let role = find(state, name).await?;
    if role.is_default {
        return Err(AppError::Conflict("default_role"));
    }

    let mut tx = state.db.begin().await?;
    role_repo::delete(&mut *tx, role.id).await?;
    keep_an_administrator(&mut tx).await?;
    audit::append(
        &mut *tx,
        &own_entry(
            actor,
            AuditAction::RoleDeleted,
            json!({ "role": role.name }),
        ),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Grant a role to an account. Granting a role it holds changes nothing.
pub async fn assign(
    state: &AppState,
    actor: &Actor,
    user_id: Uuid,
    name: &str,
) -> Result<(), AppError> {
    let role = find(state, name).await?;
    user_repo::find_by_id(&state.db, user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    require_reauth(state, actor, "admin_assign_role").await?;

    let mut tx = state.db.begin().await?;
    match role_repo::assign_to_user(&mut *tx, user_id, role.id, Some(actor.user_id)).await {
        Ok(_) => {}
        // ON CONFLICT DO NOTHING returns no row: the role was already held.
        Err(sqlx::Error::RowNotFound) => return Ok(()),
        Err(e) => return Err(e.into()),
    }
    audit::append(
        &mut *tx,
        &target_entry(actor, user_id, AuditAction::RoleAssigned, &role.name),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Take a role back. Taking back a role the account does not hold changes nothing.
pub async fn unassign(
    state: &AppState,
    actor: &Actor,
    user_id: Uuid,
    name: &str,
) -> Result<(), AppError> {
    let role = find(state, name).await?;

    let mut tx = state.db.begin().await?;
    if !role_repo::unassign(&mut *tx, user_id, role.id).await? {
        return Ok(());
    }
    keep_an_administrator(&mut tx).await?;
    audit::append(
        &mut *tx,
        &target_entry(actor, user_id, AuditAction::RoleRevoked, &role.name),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

async fn find(state: &AppState, name: &str) -> Result<Role, AppError> {
    role_repo::find_by_name(&state.db, name)
        .await?
        .ok_or(AppError::NotFound)
}

/// The requested permissions, deduplicated and sorted, all existing.
async fn known_permissions(
    state: &AppState,
    requested: &[String],
) -> Result<Vec<String>, AppError> {
    let mut permissions = requested.to_vec();
    permissions.sort();
    permissions.dedup();
    let unknown = role_repo::unknown_permissions(&state.db, &permissions).await?;
    if !unknown.is_empty() {
        return Err(AppError::Validation(format!(
            "unknown permissions: {}",
            unknown.join(", ")
        )));
    }
    Ok(permissions)
}

/// Granting permissions is how an administrator gains more: it needs a recent
/// re-authentication, like the account's own sensitive actions.
async fn require_reauth(
    state: &AppState,
    actor: &Actor,
    reason: &'static str,
) -> Result<(), AppError> {
    reauth_svc::require_recent_reauth_or_password(
        state,
        actor.user_id,
        actor.session_id,
        None,
        actor.ip,
        actor.request_id,
        reason,
    )
    .await
}

/// Refuse a change that would leave nobody able to manage roles; the
/// transaction is then rolled back.
async fn keep_an_administrator(tx: &mut sqlx::PgConnection) -> Result<(), AppError> {
    if role_repo::permission_held(&mut *tx, role_domain::ROLES_MANAGE).await? {
        Ok(())
    } else {
        Err(AppError::Conflict("last_administrator"))
    }
}

/// Changes to roles themselves belong to no account: they are recorded in the
/// administrator's own history.
fn own_entry(actor: &Actor, action: AuditAction, extra: serde_json::Value) -> NewAuditEntry {
    NewAuditEntry {
        user_id: Some(actor.user_id),
        request_id: actor.request_id,
        action,
        ip_address: actor.ip,
        metadata: actor.metadata(extra),
    }
}

fn target_entry(actor: &Actor, user_id: Uuid, action: AuditAction, role: &str) -> NewAuditEntry {
    NewAuditEntry {
        user_id: Some(user_id),
        request_id: actor.request_id,
        action,
        ip_address: actor.ip,
        metadata: actor.metadata(json!({ "role": role })),
    }
}
