//! Forgotten password: reset token issuance and redemption.

use super::*;

/// Always returns Ok (or 429 for an abusive IP) so the response never reveals
/// whether an account exists.
///
/// Both outcomes take the same time: the work for a known address runs, and the
/// response is padded to `FORGOT_PASSWORD_MIN_DURATION` either way. Padding only
/// the unknown path, as before, made the unknown address the slow one.
pub async fn forgot_password(
    state: &AppState,
    email: &str,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    request_id: Option<Uuid>,
) -> Result<(), AppError> {
    if let Some(ip_val) = ip {
        let key = format!("fp_req:{}", ip_bucket(ip_val.ip()));
        if budget_exhausted(
            state,
            &key,
            MAX_FORGOT_PASSWORD_BY_IP,
            FORGOT_PASSWORD_IP_WINDOW_SECS,
        )
        .await
        {
            return Err(AppError::RateLimitExceeded);
        }
    }

    let started = std::time::Instant::now();
    let result = issue_password_reset(state, email, ip, user_agent, request_id).await;
    let elapsed = started.elapsed();
    if elapsed < FORGOT_PASSWORD_MIN_DURATION {
        tokio::time::sleep(FORGOT_PASSWORD_MIN_DURATION - elapsed).await;
    }
    result
}

pub(super) async fn issue_password_reset(
    state: &AppState,
    email: &str,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    request_id: Option<Uuid>,
) -> Result<(), AppError> {
    let Some(user) = user_repo::find_by_email(&state.db, email).await? else {
        return Ok(());
    };

    // Cap resets per account across every IP, so nobody can flood a mailbox or
    // keep invalidating its pending link from many addresses.
    let account_key = format!("fp_account:{}", user.id);
    if budget_exhausted(
        state,
        &account_key,
        MAX_FORGOT_PASSWORD_BY_ACCOUNT,
        FORGOT_PASSWORD_ACCOUNT_WINDOW_SECS,
    )
    .await
    {
        return Ok(());
    }

    // Revoke any previous pending reset before issuing a new one
    token::revoke_active_password_reset_by_user(&state.db, user.id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    let raw_token = crypto::generate_token();
    let hash = crypto::sha256(raw_token.as_bytes());

    token::create_password_reset(
        &state.db,
        &NewPasswordResetToken {
            user_id: user.id,
            token_hash: &hash,
            expires_at: state.clock.in_secs(RESET_TOKEN_EXPIRY_SECS),
            request_ip: ip,
            request_user_agent: user_agent,
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    let mailer = state.mailer.clone();
    let templates = state.templates.clone();
    let mail_cfg = state.config.mail.clone();
    let email_to = email.to_string();
    let username = user.username.clone();
    let locale = user.preferred_locale.clone();
    let raw_token = raw_token.clone();
    let frontend_url = state.config.server.frontend_url.clone();
    email::dispatch_best_effort("password_reset_email", async move {
        email::send_password_reset_email(
            &mailer,
            templates.as_ref(),
            &mail_cfg,
            &email_to,
            &username,
            &locale,
            &raw_token,
            &frontend_url,
        )
        .await
    });

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user.id),
            request_id,
            action: AuditAction::PasswordResetRequested,
            ip_address: ip,
            metadata: json!({}),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    Ok(())
}

pub async fn reset_password(
    state: &AppState,
    raw_token: &str,
    new_password: &str,
    ip: Option<IpNetwork>,
    request_id: Option<Uuid>,
) -> Result<(), AppError> {
    let hash = crypto::sha256(raw_token.as_bytes());
    guard_token_submission(state, "rp", ip, &hash).await?;

    let record =
        check_one_time_token(state, token::find_password_reset_by_hash(&state.db, &hash)).await?;

    let new_hash = password::hash_async(new_password, &state.config.crypto)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    let revoked_session_ids = session_repo::find_active_by_user(&state.db, record.user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .into_iter()
        .map(|session| session.id)
        .collect::<Vec<_>>();

    // Consuming the token, the new hash, the revocations, the audit entry and
    // the events commit together.
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    let consumed = token::consume_password_reset(&mut *tx, record.id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    if !consumed {
        return Err(AppError::TokenInvalid);
    }

    user_repo::update_password_hash(&mut *tx, record.user_id, &new_hash)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    // Invalidate all active sessions to force re-login with the new password
    session_repo::revoke_all_by_user(&mut *tx, record.user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    // Also purge pending reset tokens
    token::revoke_active_password_reset_by_user(&mut *tx, record.user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    // The reset link went to the account's address: whoever used it owns the
    // address. A pending account is verified with the password its owner just
    // chose, which also takes back an address someone else registered.
    if user_repo::verify_if_pending(&mut *tx, record.user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
    {
        token::revoke_active_verification_by_user(&mut *tx, record.user_id)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
    }

    audit::append(
        &mut *tx,
        &NewAuditEntry {
            user_id: Some(record.user_id),
            request_id,
            action: AuditAction::PasswordResetCompleted,
            ip_address: ip,
            metadata: json!({}),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    events::enqueue(
        &mut *tx,
        "user.password_changed",
        &events::UserPasswordChanged {
            user_id: record.user_id,
        },
    )
    .await?;
    events::enqueue(
        &mut *tx,
        "user.sessions_revoked",
        &events::UserSessionsRevoked {
            user_id: record.user_id,
        },
    )
    .await?;

    tx.commit()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    events::wake();

    invalidate_session_caches(state, &revoked_session_ids).await;

    // Close the post-reset hijack window: any pre-auth (2FA challenge) token
    // or email-change flow that was already in flight before the reset would
    // otherwise survive and could be used by an attacker who knew them.
    // Best-effort: Redis failures here must not fail the reset.
    purge_user_pre_auth_and_email_change(state, record.user_id).await;

    Ok(())
}
