//! User profile management: read profile, change username/password/locale.
//!
//! Email changes are handled by the email_change service (two-step OTP flow).
//! Password changes revoke all active sessions to force re-login.

use ipnetwork::IpNetwork;
use serde_json::json;
use uuid::Uuid;

use crate::{
    domain::{audit::AuditAction, user::User},
    error::AppError,
    repositories::{
        audit::{self, NewAuditEntry},
        session as session_repo, user as user_repo,
    },
    state::AppState,
    utils::password,
};

use super::{auth as auth_svc, email::AccessItem, events, reauth as reauth_svc};
use crate::utils::redis_counter::{self, Budget};

/// Redis key prefix of the re-authentication failure budgets.
/// Protects re-authentication / sensitive-action endpoints (`change_password`,
/// `change_username`, sessions::revoke, email-change flow, ...) from
/// brute-force when an access token has been stolen: even with a valid
/// access token, an attacker cannot try unlimited passwords.
const REAUTH_FAIL_PREFIX: &str = "reauth_failures:";
/// TTL of the counters (1 hour). Resets after a period of inactivity so a
/// legitimate user mistyping yesterday is not blocked today.
const REAUTH_FAIL_TTL_SECS: u64 = 3600;
/// The account-wide ceiling, in multiples of `LOCKOUT_THRESHOLD`: high enough
/// that one stolen session exhausting its own budget leaves the owner's
/// sessions able to re-authenticate, low enough to bound the guesses made
/// through several sessions.
const REAUTH_ACCOUNT_CEILING_FACTOR: i64 = 3;

/// The account-wide re-authentication budget (reset by an administrator's
/// unlock).
pub(crate) fn reauth_fail_key(user_id: Uuid) -> String {
    format!("{}{}", REAUTH_FAIL_PREFIX, user_id)
}

/// The budget of one session.
fn session_reauth_fail_key(user_id: Uuid, session_id: Uuid) -> String {
    format!("{REAUTH_FAIL_PREFIX}{user_id}:{session_id}")
}

/// Verifies a user's current password from `session_id`. Returns
/// Err(ReauthenticationFailed) on mismatch: the caller is already signed in,
/// so "invalid email or password" would mislead.
///
/// Guesses are counted per session and per account. Once a session reaches
/// `LOCKOUT_THRESHOLD` failures, that session gets `AccountLocked` until the
/// window ends, whatever it submits; the account-wide ceiling is three times
/// higher. A stolen session thus locks itself out, not the owner's own
/// sessions, which keep revoking it and changing the password.
pub async fn verify_password(
    state: &AppState,
    user_id: Uuid,
    session_id: Uuid,
    password: &str,
) -> Result<(), AppError> {
    let user = user_repo::find_by_id(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::NotFound)?;

    let threshold = i64::from(state.config.security.lockout_threshold);
    let session_key = session_reauth_fail_key(user_id, session_id);
    let account_key = reauth_fail_key(user_id);

    // Reserve the attempt before Argon2 runs, in one atomic step: parallel
    // guesses cannot all read a count below the threshold. Fails closed when
    // Redis is unavailable, like every budget guarding a secret.
    let attempt = redis_counter::consume(
        &state.redis,
        &[
            Budget {
                key: &session_key,
                limit: threshold,
                window_secs: REAUTH_FAIL_TTL_SECS,
            },
            Budget {
                key: &account_key,
                limit: threshold.saturating_mul(REAUTH_ACCOUNT_CEILING_FACTOR),
                window_secs: REAUTH_FAIL_TTL_SECS,
            },
        ],
    )
    .await?;
    if attempt.exceeded {
        return Err(AppError::AccountLocked);
    }

    let valid = password::verify_async(password, &user.password_hash, &state.config.crypto)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    if !valid {
        if attempt.counts[0] >= threshold {
            // Threshold just reached: a distinct error, so the caller (and the
            // logs) can tell the lockout from a mistyped password.
            tracing::warn!(
                user_id = %user_id,
                failures = attempt.counts[0],
                "reauth lockout triggered for session"
            );
            return Err(AppError::AccountLocked);
        }
        return Err(AppError::ReauthenticationFailed);
    }

    // A success proves the password: earlier typos stop counting, for this
    // session and for the account. A session that exhausted its own budget
    // stays locked until its window ends.
    redis_counter::reset(&state.redis, &[&session_key, &account_key]).await;

    Ok(())
}

pub async fn get_profile(state: &AppState, user_id: Uuid) -> Result<User, AppError> {
    user_repo::find_by_id(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::NotFound)
}

pub async fn change_username(
    state: &AppState,
    user_id: Uuid,
    new_username: &str,
    ip: Option<IpNetwork>,
    request_id: Option<Uuid>,
) -> Result<(), AppError> {
    if user_repo::find_by_username(&state.db, new_username)
        .await?
        .is_some()
    {
        return Err(AppError::Conflict("username_taken"));
    }

    // The rename and its audit entry commit together.
    let mut tx = state.db.begin().await?;
    user_repo::update_username(&mut *tx, user_id, new_username)
        .await
        // The pre-check can race with another rename; the constraint decides.
        .map_err(|e| {
            AppError::from_unique_violation(e, &[("users_username_lower_key", "username_taken")])
        })?;

    audit::append(
        &mut *tx,
        &NewAuditEntry {
            user_id: Some(user_id),
            request_id,
            action: AuditAction::UsernameChanged,
            ip_address: ip,
            metadata: json!({}),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;
    tx.commit().await?;

    Ok(())
}

/// Verifies the current password before applying the new one, then revokes all sessions.
/// Requires a verified email.
#[allow(clippy::too_many_arguments)]
pub async fn change_password(
    state: &AppState,
    user_id: Uuid,
    current_session_id: Uuid,
    current_password: Option<&str>,
    new_password: &str,
    keep_current_session: bool,
    ip: Option<IpNetwork>,
    request_id: Option<Uuid>,
) -> Result<(), AppError> {
    reauth_svc::require_recent_reauth_or_password(
        state,
        user_id,
        current_session_id,
        current_password,
        ip,
        request_id,
        "change_password",
    )
    .await?;

    let user = user_repo::find_by_id(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::NotFound)?;

    if user.email_verified_at.is_none() {
        return Err(AppError::EmailNotVerified);
    }

    crate::services::pwned::ensure_not_breached(state, new_password).await?;

    let new_hash = password::hash_async(new_password, &state.config.crypto)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    let revoked_session_ids = session_repo::find_active_by_user(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .into_iter()
        .map(|session| session.id)
        .filter(|id| !keep_current_session || *id != current_session_id)
        .collect::<Vec<_>>();

    // The new hash, the revocation of the sessions, the audit entry and the
    // events commit together.
    let mut tx = state.db.begin().await?;

    user_repo::update_password_hash(&mut *tx, user_id, &new_hash).await?;
    // A reset or sign-in link requested before the change would bypass it.
    crate::repositories::token::revoke_mailbox_links(&mut tx, user_id).await?;

    // Other devices must sign in with the new password; the current session
    // too unless the caller keeps it.
    if keep_current_session {
        session_repo::revoke_others(&mut *tx, user_id, current_session_id).await?;
    } else {
        session_repo::revoke_all_by_user(&mut *tx, user_id).await?;
    }

    audit::append(
        &mut *tx,
        &NewAuditEntry {
            user_id: Some(user_id),
            request_id,
            action: AuditAction::PasswordChanged,
            ip_address: ip,
            metadata: json!({}),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    events::enqueue(
        &mut *tx,
        "user.password_changed",
        &events::UserPasswordChanged { user_id },
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

    auth_svc::invalidate_session_caches(state, &revoked_session_ids).await;
    // A second-factor challenge opened with the old password dies with it, as
    // after a reset: it would otherwise still open a session.
    auth_svc::purge_user_pre_auth_and_email_change(state, user.id).await;

    notify_password_changed(state, &user, Vec::new()).await;

    Ok(())
}

/// What opens the account besides its password: passkeys, verified second
/// factors, personal access tokens and external identities. Best effort: an
/// error leaves the list shorter, never the notification unsent.
pub(crate) async fn access_summary(state: &AppState, user_id: Uuid) -> Vec<AccessItem> {
    use crate::domain::two_factor::TwoFactorType;
    use crate::repositories::{
        external_identity as identity_repo, passkey as passkey_repo,
        personal_access_token as pat_repo, two_factor as tf_repo,
    };

    let (passkeys, methods, tokens, identities) = tokio::join!(
        passkey_repo::find_by_user(&state.db, user_id),
        tf_repo::find_by_user(&state.db, user_id),
        pat_repo::find_active_by_user(&state.db, user_id),
        identity_repo::find_by_user(&state.db, user_id),
    );
    let mut access = Vec::new();
    access.extend(
        passkeys
            .unwrap_or_default()
            .into_iter()
            .map(|p| AccessItem {
                kind: "passkey",
                name: p.name,
            }),
    );
    access.extend(
        methods
            .unwrap_or_default()
            .into_iter()
            .filter(|m| m.is_verified)
            .map(|m| AccessItem {
                kind: match m.method_type {
                    TwoFactorType::Totp => "totp",
                    TwoFactorType::Email => "email",
                },
                name: String::new(),
            }),
    );
    access.extend(tokens.unwrap_or_default().into_iter().map(|t| AccessItem {
        kind: "personal_access_token",
        name: t.name,
    }));
    access.extend(
        identities
            .unwrap_or_default()
            .into_iter()
            .map(|i| AccessItem {
                kind: "external_identity",
                name: i.provider,
            }),
    );
    access
}

/// Tell the owner their password changed, listing what still opens the account
/// and what the change removed.
pub(crate) async fn notify_password_changed(
    state: &AppState,
    user: &User,
    removed: Vec<super::email::AccessItem>,
) {
    let access = access_summary(state, user.id).await;
    let mailer = state.mailer.clone();
    let templates = state.templates.clone();
    let mail_cfg = state.config.mail.clone();
    let email_to = user.email.clone();
    let username = user.username.clone();
    let locale = user.preferred_locale.clone();
    super::email::dispatch_best_effort("password_changed_email", async move {
        super::email::send_password_changed(
            &mailer,
            templates.as_ref(),
            &mail_cfg,
            &email_to,
            &username,
            &locale,
            &access,
            &removed,
        )
        .await
    });
}

/// Tell the owner a way into the account was added (passkey, personal access
/// token, external identity).
pub(crate) async fn notify_access_added(state: &AppState, user_id: Uuid, access: AccessItem) {
    let Ok(Some(user)) = user_repo::find_by_id(&state.db, user_id).await else {
        return;
    };
    let mailer = state.mailer.clone();
    let templates = state.templates.clone();
    let mail_cfg = state.config.mail.clone();
    super::email::dispatch_best_effort("access_added_email", async move {
        super::email::send_access_added(
            &mailer,
            templates.as_ref(),
            &mail_cfg,
            &user.email,
            &user.username,
            &user.preferred_locale,
            &access,
        )
        .await
    });
}

/// Permanently deletes the user account and all associated data.
/// Requires the current password for confirmation.
/// The audit entry is written before deletion so it can reference the user_id.
pub async fn delete_account(
    state: &AppState,
    user_id: Uuid,
    current_session_id: Uuid,
    current_password: Option<&str>,
    ip: Option<IpNetwork>,
    request_id: Option<Uuid>,
) -> Result<(), AppError> {
    reauth_svc::require_recent_reauth_or_password(
        state,
        user_id,
        current_session_id,
        current_password,
        ip,
        request_id,
        "delete_account",
    )
    .await?;

    user_repo::find_by_id(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::NotFound)?;

    erase_account(state, user_id, json!({}), ip, request_id).await
}

/// Delete the account and everything linked to it, announce it, and forget its
/// traces. `metadata` goes to the `account_deleted` audit entry and must not
/// identify the account.
pub(crate) async fn erase_account(
    state: &AppState,
    user_id: Uuid,
    metadata: serde_json::Value,
    ip: Option<IpNetwork>,
    request_id: Option<Uuid>,
) -> Result<(), AppError> {
    // Collect active session IDs before deletion so we can invalidate their
    // Redis cache entries - otherwise the session validity cache would stay
    // warm for up to SESSION_CACHE_TTL_SECS after the account is gone.
    let session_ids: Vec<_> = session_repo::find_active_by_user(&state.db, user_id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|s| s.id)
        .collect();

    // Downstream services erase their data on `user.deleted`, and the user id is
    // the only key to it. The audit entry, the event and the deletion commit
    // together: the account is never gone without its event, and the event
    // never announces a deletion that failed. The event waits in the outbox
    // while NATS is down.
    // Deleting the last active account able to manage roles would leave the
    // deployment without one: refused, whoever asks (the owner or an admin).
    let mut tx = state.db.begin().await?;
    // Read under the account's lock: a role granted meanwhile is seen.
    user_repo::lock_row(&mut *tx, user_id).await?;
    let manages_roles = crate::repositories::role::user_has_permission(
        &mut *tx,
        user_id,
        crate::domain::role::ROLES_MANAGE,
    )
    .await?;

    // Appended before the deletion: the foreign key then sets its user_id to NULL.
    audit::append(
        &mut *tx,
        &NewAuditEntry {
            user_id: Some(user_id),
            request_id,
            action: AuditAction::AccountDeleted,
            ip_address: ip,
            // No identity in the metadata: the audit log outlives the account,
            // and an erased user must not remain readable in it.
            metadata,
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    events::enqueue(&mut *tx, "user.deleted", &events::UserDeleted { user_id }).await?;

    user_repo::forget_traces(&mut *tx, user_id).await?;
    user_repo::delete(&mut *tx, user_id).await?;
    if manages_roles {
        super::admin::roles::keep_an_administrator(&mut tx).await?;
    }

    tx.commit().await?;
    events::wake();

    auth_svc::invalidate_session_caches(state, &session_ids).await;

    Ok(())
}

pub async fn change_locale(state: &AppState, user_id: Uuid, locale: &str) -> Result<(), AppError> {
    user_repo::update_locale(&state.db, user_id, locale)
        .await
        .map_err(|e| AppError::Internal(e.into()))
}

pub async fn reauthenticate(
    state: &AppState,
    user_id: Uuid,
    session_id: Uuid,
    current_password: &str,
    ip: Option<IpNetwork>,
    request_id: Option<Uuid>,
) -> Result<(), AppError> {
    reauth_svc::reauthenticate(
        state,
        user_id,
        session_id,
        current_password,
        ip,
        request_id,
        "user_initiated",
    )
    .await
}

/// Everything stored about the account, after a recent re-authentication: the
/// document is as sensitive as the account itself.
pub async fn export_data(
    state: &AppState,
    user_id: Uuid,
    session_id: Uuid,
    ip: Option<IpNetwork>,
    request_id: Option<Uuid>,
) -> Result<serde_json::Value, AppError> {
    reauth_svc::require_recent_reauth_or_password(
        state,
        user_id,
        session_id,
        None,
        ip,
        request_id,
        "export_data",
    )
    .await?;

    // Audited first, so the export records itself.
    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user_id),
            request_id,
            action: AuditAction::DataExported,
            ip_address: ip,
            metadata: json!({}),
        },
    )
    .await?;

    crate::repositories::export::account_document(&state.db, user_id)
        .await?
        .ok_or(AppError::NotFound)
}

/// Refuse, before the transaction commits, a change that leaves an account
/// holding administrative permissions without any second factor: the
/// administration would refuse it, but the permissions would stay in its
/// tokens behind its password alone. Run after locking the account's row.
pub(crate) async fn keep_a_second_factor_for_administrators(
    tx: &mut sqlx::PgConnection,
    user_id: Uuid,
) -> Result<(), AppError> {
    if crate::repositories::role::holds_administration(&mut *tx, user_id).await?
        && !user_repo::has_second_factor(&mut *tx, user_id).await?
    {
        return Err(AppError::Conflict("administrator_needs_second_factor"));
    }
    Ok(())
}
