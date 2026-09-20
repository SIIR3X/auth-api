//! Account registration and email verification.

use super::*;

/// Register an account. Every answer takes at least
/// `FORGOT_PASSWORD_MIN_DURATION`: a taken address, a pending one and a new one
/// do different work, and the difference must not show in the response time.
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
    let started = std::time::Instant::now();
    let result = register_account(
        state,
        username,
        email,
        password_plaintext,
        locale,
        ip,
        user_agent,
        request_id,
    )
    .await;
    if let Some(rest) = FORGOT_PASSWORD_MIN_DURATION.checked_sub(started.elapsed()) {
        tokio::time::sleep(rest).await;
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn register_account(
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

    // Checked before the address is looked up: the check costs the same
    // whether the address is taken or not.
    crate::services::pwned::ensure_not_breached(state, password_plaintext).await?;

    // Hash on every path so a registered address costs the same as a new one.
    let hash = password::hash_async(password_plaintext, &state.config.crypto)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    if let Some(existing) = user_repo::find_by_email(&state.db, email).await? {
        // A pending account belongs to nobody yet: this registration gets its
        // own link, carrying the credentials it chose. Whoever clicks it
        // activates the account with them, so an attacker who registered the
        // address first does not pick the owner's password. An active account
        // is told of the attempt.
        if existing.status == UserStatus::PendingVerification {
            let credentials = crate::domain::token::PendingCredentials {
                password_hash: hash,
                username: username.to_owned(),
                preferred_locale: locale.to_owned(),
            };
            issue_verification(
                state,
                &existing,
                Some(credentials),
                ip,
                user_agent,
                request_id,
            )
            .await?;
        } else if !budget_exhausted(
            state,
            &format!("ae_account:{}", existing.id),
            MAX_ACCOUNT_EXISTS_NOTICES,
            ACCOUNT_EXISTS_NOTICE_WINDOW_SECS,
        )
        .await
        {
            // At most a few notices an hour: registering the address again
            // and again must not flood its owner.
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
    let mut tx = state.db.begin().await?;

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
                    ("users_username_lower_key", "username_taken"),
                ],
            ) {
                AppError::Conflict("email_taken") => Ok(None),
                other => Err(other),
            };
        }
    };

    if let Some(role) = default_role {
        role::assign_to_user(&mut *tx, user.id, role.id, None).await?;
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
            credentials: None,
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
        &events::UserCreated { user_id: user.id },
    )
    .await?;

    tx.commit().await?;
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
            issue_verification(state, &user, None, ip, user_agent, request_id).await
        }
        _ => Ok(()),
    };
    let elapsed = started.elapsed();
    if elapsed < FORGOT_PASSWORD_MIN_DURATION {
        tokio::time::sleep(FORGOT_PASSWORD_MIN_DURATION - elapsed).await;
    }
    result
}

/// E-mail `user`, a pending account, a new verification link within the
/// per-account budget. The link carries `credentials` when a registration sent
/// it; a resend repeats those of the latest live link. Earlier links stay
/// valid until one of them verifies the account: a later registration or
/// resend must not revoke the link its owner is about to click.
async fn issue_verification(
    state: &AppState,
    user: &User,
    credentials: Option<crate::domain::token::PendingCredentials>,
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

    let mut tx = state.db.begin().await?;
    let credentials = match credentials {
        Some(credentials) => Some(credentials),
        None => token::latest_active_credentials(&mut *tx, user.id).await?,
    };
    token::create_verification(
        &mut *tx,
        &NewEmailVerificationToken {
            user_id: user.id,
            token_hash: &hash_bytes,
            expires_at: state.clock.in_secs(EMAIL_TOKEN_EXPIRY_SECS),
            request_ip: ip,
            request_user_agent: user_agent,
            target_email: &user.email,
            credentials: credentials.as_ref(),
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
    tx.commit().await?;

    // The e-mail names the account the link activates.
    let (username, locale) = match &credentials {
        Some(credentials) => (
            credentials.username.clone(),
            credentials.preferred_locale.clone(),
        ),
        None => (user.username.clone(), user.preferred_locale.clone()),
    };
    let mailer = state.mailer.clone();
    let templates = state.templates.clone();
    let mail_cfg = state.config.mail.clone();
    let email_to = user.email.clone();
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
    let mut tx = state.db.begin().await?;

    let consumed = token::consume_verification(&mut *tx, record.id).await?;
    if !consumed {
        return Err(AppError::TokenInvalid);
    }

    // A link sent by a registration on a pending account activates it with
    // that registration's credentials; the other links of the account die.
    if let (Some(password_hash), Some(username), Some(preferred_locale)) = (
        record.password_hash.clone(),
        record.username.clone(),
        record.preferred_locale.clone(),
    ) {
        user_repo::adopt_pending_credentials(
            &mut *tx,
            record.user_id,
            &crate::domain::token::PendingCredentials {
                password_hash,
                username,
                preferred_locale,
            },
        )
        .await?;
    }
    token::revoke_active_verification_by_user(&mut *tx, record.user_id).await?;

    user_repo::mark_email_verified(&mut *tx, record.user_id).await?;

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
        },
    )
    .await?;

    tx.commit().await?;
    events::wake();

    Ok(())
}
