//! Account registration and email verification.

use super::*;

#[allow(clippy::too_many_arguments)]
pub async fn register(
    state: &AppState,
    username: &str,
    email: &str,
    password_plaintext: &str,
    locale: &str,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    request_id: Option<Uuid>,
) -> Result<Option<User>, AppError> {
    // A taken username is reported: it is a public identifier the user picks
    // and must know to change. A taken email is not: answering differently
    // would let anyone test which addresses have an account. Its owner is told
    // by email instead, and the caller gets the same response as a new signup.
    if user_repo::find_by_username(&state.db, username)
        .await?
        .is_some()
    {
        return Err(AppError::Conflict("username_taken"));
    }

    // Hash on every path so a registered address costs the same as a new one.
    let hash = password::hash_async(password_plaintext, &state.config.crypto)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    if let Some(existing) = user_repo::find_by_email(&state.db, email).await? {
        // A pending account gets its verification again, so an owner who lost
        // the first e-mail can finish; an active one is told of the attempt.
        if existing.status == UserStatus::PendingVerification {
            issue_verification(state, &existing, ip, user_agent, request_id).await?;
        } else {
            notify_existing_account(state, &existing);
        }
        return Ok(None);
    }

    let default_role = role::find_default(&state.db)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    let raw_token = crypto::generate_token();
    let hash_bytes = crypto::sha256(raw_token.as_bytes());

    // The account, its role, its verification token, the audit entry and the
    // `user.created` event are committed together.
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    let created = user_repo::create(
        &mut *tx,
        &NewUser {
            username,
            email,
            password_hash: &hash,
            preferred_locale: locale,
        },
    )
    .await;
    let user = match created {
        Ok(user) => user,
        // The pre-checks can race with a concurrent registration; the UNIQUE
        // constraints are authoritative and resolve to the same outcomes.
        Err(e) => {
            return match AppError::from_unique_violation(
                e,
                &[
                    ("users_email_key", "email_taken"),
                    ("users_username_key", "username_taken"),
                ],
            ) {
                AppError::Conflict("email_taken") => Ok(None),
                other => Err(other),
            };
        }
    };

    if let Some(role) = default_role {
        role::assign_to_user(&mut *tx, user.id, role.id, None)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
    }

    token::create_verification(
        &mut *tx,
        &NewEmailVerificationToken {
            user_id: user.id,
            token_hash: &hash_bytes,
            expires_at: state.clock.in_secs(EMAIL_TOKEN_EXPIRY_SECS),
            request_ip: ip,
            request_user_agent: user_agent,
            target_email: email,
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    audit::append(
        &mut *tx,
        &NewAuditEntry {
            user_id: Some(user.id),
            request_id,
            action: AuditAction::Register,
            ip_address: ip,
            metadata: json!({}),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    events::enqueue(
        &mut *tx,
        "user.created",
        &events::UserCreated {
            user_id: user.id,
            email: user.email.clone(),
            username: user.username.clone(),
        },
    )
    .await?;

    tx.commit()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    events::wake();

    let mailer = state.mailer.clone();
    let templates = state.templates.clone();
    let mail_cfg = state.config.mail.clone();
    let email_to = email.to_string();
    let username = username.to_string();
    let locale = locale.to_string();
    let frontend_url = state.config.server.frontend_url.clone();
    email::dispatch_best_effort("verification_email", async move {
        email::send_verification_email(
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

    Ok(Some(user))
}

/// Send a new verification link to a pending account. Answers the same whether
/// the address is unknown, pending or already verified, and in the same time
/// (padded like the forgotten-password request).
pub async fn resend_verification(
    state: &AppState,
    email: &str,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    request_id: Option<Uuid>,
) -> Result<(), AppError> {
    if let Some(ip_val) = ip {
        let key = format!("vr_req:{}", ip_bucket(ip_val.ip()));
        if budget_exhausted(
            state,
            &key,
            MAX_VERIFICATION_RESENDS_BY_IP,
            VERIFICATION_RESEND_IP_WINDOW_SECS,
        )
        .await
        {
            return Err(AppError::RateLimitExceeded);
        }
    }

    let started = std::time::Instant::now();
    let result = match user_repo::find_by_email(&state.db, email).await? {
        Some(user) if user.status == UserStatus::PendingVerification => {
            issue_verification(state, &user, ip, user_agent, request_id).await
        }
        _ => Ok(()),
    };
    let elapsed = started.elapsed();
    if elapsed < FORGOT_PASSWORD_MIN_DURATION {
        tokio::time::sleep(FORGOT_PASSWORD_MIN_DURATION - elapsed).await;
    }
    result
}

/// Replace the pending verification link of `user` and e-mail it, within the
/// per-account budget.
async fn issue_verification(
    state: &AppState,
    user: &User,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    request_id: Option<Uuid>,
) -> Result<(), AppError> {
    let account_key = format!("vr_account:{}", user.id);
    if budget_exhausted(
        state,
        &account_key,
        MAX_VERIFICATION_RESENDS_BY_ACCOUNT,
        VERIFICATION_RESEND_ACCOUNT_WINDOW_SECS,
    )
    .await
    {
        return Ok(());
    }

    let raw_token = crypto::generate_token();
    let hash_bytes = crypto::sha256(raw_token.as_bytes());

    // The previous link stops working when the new one is issued.
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    token::revoke_active_verification_by_user(&mut *tx, user.id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    token::create_verification(
        &mut *tx,
        &NewEmailVerificationToken {
            user_id: user.id,
            token_hash: &hash_bytes,
            expires_at: state.clock.in_secs(EMAIL_TOKEN_EXPIRY_SECS),
            request_ip: ip,
            request_user_agent: user_agent,
            target_email: &user.email,
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;
    audit::append(
        &mut *tx,
        &NewAuditEntry {
            user_id: Some(user.id),
            request_id,
            action: AuditAction::EmailVerificationSent,
            ip_address: ip,
            metadata: json!({}),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;
    tx.commit()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    let mailer = state.mailer.clone();
    let templates = state.templates.clone();
    let mail_cfg = state.config.mail.clone();
    let email_to = user.email.clone();
    let username = user.username.clone();
    let locale = user.preferred_locale.clone();
    let frontend_url = state.config.server.frontend_url.clone();
    email::dispatch_best_effort("verification_email", async move {
        email::send_verification_email(
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
    Ok(())
}

pub async fn verify_email(
    state: &AppState,
    raw_token: &str,
    ip: Option<IpNetwork>,
    request_id: Option<Uuid>,
) -> Result<(), AppError> {
    let hash = crypto::sha256(raw_token.as_bytes());
    guard_token_submission(state, "vf", ip, &hash).await?;

    let record =
        check_one_time_token(state, token::find_verification_by_hash(&state.db, &hash)).await?;

    // Consuming the token, verifying the address and announcing it commit together.
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    let consumed = token::consume_verification(&mut *tx, record.id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    if !consumed {
        return Err(AppError::TokenInvalid);
    }

    user_repo::mark_email_verified(&mut *tx, record.user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    audit::append(
        &mut *tx,
        &NewAuditEntry {
            user_id: Some(record.user_id),
            request_id,
            action: AuditAction::EmailVerified,
            ip_address: ip,
            metadata: json!({}),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    events::enqueue(
        &mut *tx,
        "user.email_verified",
        &events::UserEmailVerified {
            user_id: record.user_id,
            email: record.target_email.clone(),
        },
    )
    .await?;

    tx.commit()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    events::wake();

    Ok(())
}
