//! Personal access tokens: created by an account for its scripts, exchanged
//! for short-lived access tokens carrying only the scopes chosen at creation.

use ipnetwork::IpNetwork;
use serde_json::json;
use time::Duration;
use uuid::Uuid;

use crate::{
    domain::{
        audit::AuditAction,
        personal_access_token::{self as pat, PersonalAccessToken},
        session::SessionType,
    },
    error::AppError,
    repositories::{
        audit::{self, NewAuditEntry},
        personal_access_token::{self as pat_repo, NewPersonalAccessToken},
        role as role_repo,
        session::{self as session_repo, NewSession},
        user as user_repo,
    },
    services::{auth as auth_svc, reauth as reauth_svc},
    state::AppState,
    utils::crypto,
};

pub struct CreatedToken {
    pub token: PersonalAccessToken,
    /// Shown once; only its digest is stored.
    pub secret: String,
}

pub struct ExchangedToken {
    pub access_token: String,
    pub expires_in: u64,
}

#[allow(clippy::too_many_arguments)]
pub async fn create(
    state: &AppState,
    user_id: Uuid,
    current_session_id: Uuid,
    name: &str,
    scopes: &[String],
    lifetime_days: Option<i64>,
    ip: Option<IpNetwork>,
    request_id: Option<Uuid>,
) -> Result<CreatedToken, AppError> {
    let name = pat::valid_name(name).ok_or_else(|| {
        AppError::Validation("name must be 1 to 100 characters without control characters".into())
    })?;
    let lifetime_days = lifetime_days.unwrap_or(pat::DEFAULT_LIFETIME_DAYS);
    if !(1..=pat::MAX_LIFETIME_DAYS).contains(&lifetime_days) {
        return Err(AppError::Validation(format!(
            "expires_in_days must be between 1 and {}",
            pat::MAX_LIFETIME_DAYS
        )));
    }
    let (_, held) = role_repo::find_rbac_names(&state.db, user_id).await?;
    let scopes = pat::grantable_scopes(scopes, &held).map_err(|missing| {
        AppError::Validation(format!(
            "scopes not held by the account: {}",
            missing.join(", ")
        ))
    })?;
    reauth_svc::require_recent_reauth_or_password(
        state,
        user_id,
        current_session_id,
        None,
        ip,
        request_id,
        "create_personal_access_token",
    )
    .await?;

    let random = crypto::generate_token();
    let secret = pat::format_token(&random);
    let expires_at = state.clock.now() + Duration::days(lifetime_days);

    let mut tx = state.db.begin().await?;
    if pat_repo::count_active_by_user(&mut *tx, user_id).await? >= pat::MAX_ACTIVE_PER_ACCOUNT {
        return Err(AppError::Conflict("too_many_tokens"));
    }
    // The session's refresh token is never handed out: the digest of a secret
    // nobody keeps.
    let session = session_repo::create(
        &mut *tx,
        &NewSession {
            user_id,
            session_family_id: Uuid::new_v4(),
            expires_at,
            ip_address: ip,
            device_name: Some(name),
            remember_me: false,
            token_hash: &crypto::sha256(crypto::generate_token().as_bytes()),
            user_agent: None,
            session_type: SessionType::PersonalAccessToken,
            client_id: None,
            family_created_at: None,
            scopes: Some(&scopes),
        },
    )
    .await?;
    let token = pat_repo::create(
        &mut *tx,
        &NewPersonalAccessToken {
            user_id,
            session_id: session.id,
            name,
            token_hash: &crypto::sha256(random.as_bytes()),
            scopes: &scopes,
            expires_at,
        },
    )
    .await?;
    audit::append(
        &mut *tx,
        &NewAuditEntry {
            user_id: Some(user_id),
            request_id,
            action: AuditAction::PersonalAccessTokenCreated,
            ip_address: ip,
            metadata: json!({ "token_id": token.id, "scopes": scopes }),
        },
    )
    .await?;
    tx.commit().await?;

    Ok(CreatedToken { token, secret })
}

pub async fn list(state: &AppState, user_id: Uuid) -> Result<Vec<PersonalAccessToken>, AppError> {
    Ok(pat_repo::find_active_by_user(&state.db, user_id).await?)
}

/// Revoke a token of the account. Revoking needs no re-authentication: it only
/// takes access away.
pub async fn revoke(
    state: &AppState,
    user_id: Uuid,
    id: Uuid,
    ip: Option<IpNetwork>,
    request_id: Option<Uuid>,
) -> Result<(), AppError> {
    let token = pat_repo::find_owned(&state.db, id, user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    session_repo::revoke(&state.db, token.session_id).await?;
    auth_svc::invalidate_session_caches(state, &[token.session_id]).await;
    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user_id),
            request_id,
            action: AuditAction::PersonalAccessTokenRevoked,
            ip_address: ip,
            metadata: json!({ "token_id": token.id }),
        },
    )
    .await?;
    Ok(())
}

/// An access token for the token's session, with its scopes intersected with
/// the account's current permissions.
pub async fn exchange(state: &AppState, presented: &str) -> Result<ExchangedToken, AppError> {
    let random = pat::random_part(presented).ok_or(AppError::TokenInvalid)?;
    let found = pat_repo::find_by_hash(&state.db, &crypto::sha256(random.as_bytes()))
        .await?
        .ok_or(AppError::TokenInvalid)?;
    if found.session_revoked_at.is_some() {
        return Err(AppError::TokenInvalid);
    }
    if found.token.expires_at <= state.clock.now() {
        return Err(AppError::TokenExpired);
    }
    let user = user_repo::find_by_id(&state.db, found.token.user_id)
        .await?
        .ok_or(AppError::TokenInvalid)?;
    auth_svc::ensure_account_usable(&user, state.clock.now())?;

    pat_repo::touch(&state.db, &found.token).await?;
    let access_token = auth_svc::build_access_token(
        user.id,
        found.token.session_id,
        Some(&found.token.scopes),
        state,
    )
    .await?;
    Ok(ExchangedToken {
        access_token,
        expires_in: state.config.jwt.access_expiry_secs,
    })
}
