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
        notify_existing_account(state, &existing);
        return Ok(None);
    }

    let created = user_repo::create(
        &state.db,
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

    // Assign default role if one exists
    if let Some(role) = role::find_default(&state.db)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
    {
        // Best-effort: default role assignment must not block registration.
        let _ = role::assign_to_user(&state.db, user.id, role.id, None).await;
    }

    // Email verification token
    let raw_token = crypto::generate_token();
    let hash_bytes = crypto::sha256(raw_token.as_bytes());

    token::create_verification(
        &state.db,
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

    let mailer = state.mailer.clone();
    let templates = state.templates.clone();
    let mail_cfg = state.config.mail.clone();
    let email_to = email.to_string();
    let username = username.to_string();
    let locale = locale.to_string();
    let raw_token = raw_token.clone();
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

    audit::append(
        &state.db,
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

    events::publish(
        state,
        "user.created",
        &events::UserCreated {
            user_id: user.id,
            email: user.email.clone(),
            username: user.username.clone(),
        },
    )
    .await;

    Ok(Some(user))
}

pub async fn verify_email(
    state: &AppState,
    raw_token: &str,
    ip: Option<IpNetwork>,
    request_id: Option<Uuid>,
) -> Result<(), AppError> {
    use crate::domain::token::OneTimeToken;

    let hash = crypto::sha256(raw_token.as_bytes());
    guard_token_submission(state, "vf", ip, &hash).await?;

    // Constant-time token validation: always perform a DB lookup and apply a
    // minimum delay so that the response time does not reveal whether a token
    // exists. This prevents timing-based enumeration of valid tokens.
    let start = std::time::Instant::now();
    let min_duration = std::time::Duration::from_millis(100);

    let result = async {
        let record = token::find_verification_by_hash(&state.db, &hash)
            .await
            .map_err(|e| AppError::Internal(e.into()))?
            .ok_or(AppError::TokenInvalid)?;

        if record.is_expired(state.clock.now()) {
            return Err(AppError::TokenExpired);
        }
        if record.is_used() {
            return Err(AppError::TokenInvalid);
        }

        Ok(record)
    }
    .await;

    let elapsed = start.elapsed();
    if elapsed < min_duration {
        tokio::time::sleep(min_duration - elapsed).await;
    }

    let record = result?;

    let consumed = token::consume_verification(&state.db, record.id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    if !consumed {
        return Err(AppError::TokenInvalid);
    }

    user_repo::mark_email_verified(&state.db, record.user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    audit::append(
        &state.db,
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

    events::publish(
        state,
        "user.email_verified",
        &events::UserEmailVerified {
            user_id: record.user_id,
            email: record.target_email.clone(),
        },
    )
    .await;

    Ok(())
}
