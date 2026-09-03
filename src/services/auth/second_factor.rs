//! Completing a sign-in paused for a second factor: TOTP, email code, recovery code.

use super::*;

pub async fn complete_two_factor_login(
    state: &AppState,
    pre_auth_token: &str,
    code: &str,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    device_name: Option<&str>,
    request_id: Option<Uuid>,
) -> Result<AuthTokens, AppError> {
    let redis_key = pre_auth_key(pre_auth_token);
    let fail_key = format!("totp_fail:{}", pre_auth_token);

    let mut conn = state
        .redis
        .get()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    let pre_auth_state = load_pre_auth_state_from_redis(&mut conn, &redis_key).await?;
    drop(conn);
    pre_auth_state.expect_method(ChallengeMethod::Totp)?;

    // Do NOT consume the token yet; only on success, so failures can be retried
    // within the attempt budget.
    let user_id = pre_auth_state.user_id;
    let remember_me = pre_auth_state.remember_me;
    let user_fail_key = format!("{TOTP_USER_FAIL_PREFIX}{user_id}");

    // Reserve the attempt before checking the code, atomically, against both
    // the token and the account: concurrent guesses cannot all read the same
    // counter and slip under the limit together.
    let attempt = redis_counter::consume(
        &state.redis,
        &[
            Budget {
                key: &fail_key,
                limit: MAX_TOTP_FAILURES,
                window_secs: PRE_AUTH_TTL_SECS,
            },
            Budget {
                key: &user_fail_key,
                limit: MAX_TOTP_FAILURES_BY_USER,
                window_secs: SECOND_FACTOR_USER_WINDOW_SECS,
            },
        ],
    )
    .await?;
    if attempt.exceeded {
        return Err(AppError::RateLimitExceeded);
    }

    let user = user_repo::find_by_id(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::Unauthorized)?;

    if !user.is_active() {
        return Err(AppError::AccountSuspended);
    }
    if user.is_locked(state.clock.now()) {
        return Err(AppError::AccountLocked);
    }

    // The primary method may have changed since the challenge was issued.
    let method = tf_repo::find_primary_by_user(&state.db, user.id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .filter(|m| m.method_type == crate::domain::two_factor::TwoFactorType::Totp)
        .ok_or(AppError::TokenInvalid)?;

    let encrypted_secret = method
        .totp_secret
        .as_deref()
        .ok_or(AppError::Unauthorized)?;

    let valid = totp::verify_code(
        encrypted_secret,
        code,
        &state.keyring,
        state.config.crypto.totp_skew,
        state.clock.now().unix_timestamp(),
    )
    .map_err(|e| AppError::Internal(e.into()))?;

    // Replay guard: a code already consumed within its validity window is
    // refused. Redis is only a fast path; `used_totp_codes` is the durable
    // authority, checked with an atomic INSERT .. ON CONFLICT, and a database
    // error is propagated (fail-closed).
    let consumed = if valid {
        let used_key = format!("{}{}:{}", TOTP_USED_PREFIX, user_id, code);
        let cached_replay: bool = if let Ok(mut c) = state.redis.get().await {
            c.exists(&used_key).await.unwrap_or(false)
        } else {
            false
        };

        let consumed = !cached_replay
            && tf_repo::try_consume_totp_code(&state.db, user_id, &crypto::sha256(code.as_bytes()))
                .await
                .map_err(|e| AppError::Internal(e.into()))?;

        if consumed && let Ok(mut c) = state.redis.get().await {
            let _: Result<(), _> = c.set_ex(&used_key, 1u8, 60u64).await;
        }
        consumed
    } else {
        false
    };

    if !consumed {
        record_second_factor_failure(state, &user, ip, user_agent, request_id).await;
        metrics::counter!("auth_2fa_failures_total", "method" => "totp").increment(1);
        apply_backoff(attempt.counts[0]).await;
        return Err(AppError::TwoFactorFailed);
    }

    redis_counter::reset(&state.redis, &[&user_fail_key]).await;

    // Consume the pre-auth token now that verification succeeded.
    if let Ok(mut c) = state.redis.get().await {
        let _: Result<(), _> = c.del(&redis_key).await;
        let _: Result<(), _> = c.del(&fail_key).await;
        let _: Result<(), _> = c
            .srem::<_, _, ()>(user_pre_auth_index_key(user_id), pre_auth_token)
            .await;
    }

    let tokens = issue_tokens(
        state,
        user.id,
        ip,
        user_agent,
        device_name,
        remember_me,
        SessionType::Web,
        None,
        None,
        Some(SignIn {
            identifier: None,
            request_id,
            audit_metadata: json!({"two_factor": true}),
        }),
    )
    .await?;

    metrics::counter!("auth_logins_total", "outcome" => "success").increment(1);
    metrics::counter!("auth_2fa_success_total", "method" => "totp").increment(1);
    Ok(tokens)
}

pub async fn complete_email_2fa_login(
    state: &AppState,
    pre_auth_token: &str,
    code: &str,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    device_name: Option<&str>,
    request_id: Option<Uuid>,
) -> Result<AuthTokens, AppError> {
    let redis_key = pre_auth_key(pre_auth_token);

    let mut conn = state
        .redis
        .get()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    let pre_auth_state = load_pre_auth_state_from_redis(&mut conn, &redis_key).await?;
    drop(conn);
    pre_auth_state.expect_method(ChallengeMethod::Email)?;

    let user_id = pre_auth_state.user_id;
    let remember_me = pre_auth_state.remember_me;

    let user = user_repo::find_by_id(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::Unauthorized)?;

    if !user.is_active() {
        return Err(AppError::AccountSuspended);
    }
    if user.is_locked(state.clock.now()) {
        return Err(AppError::AccountLocked);
    }

    if let Err(e) = email_2fa::verify_login_code(state, user_id, pre_auth_token, code).await {
        if matches!(e, AppError::TwoFactorFailed) {
            record_second_factor_failure(state, &user, ip, user_agent, request_id).await;
        }
        return Err(e);
    }

    // Consume the pre-auth token on success.
    if let Ok(mut c) = state.redis.get().await {
        let _: Result<(), _> = c.del(&redis_key).await;
        let _: Result<(), _> = c
            .srem::<_, _, ()>(user_pre_auth_index_key(user_id), pre_auth_token)
            .await;
    }

    let tokens = issue_tokens(
        state,
        user.id,
        ip,
        user_agent,
        device_name,
        remember_me,
        SessionType::Web,
        None,
        None,
        Some(SignIn {
            identifier: None,
            request_id,
            audit_metadata: json!({"two_factor": "email"}),
        }),
    )
    .await?;

    metrics::counter!("auth_logins_total", "outcome" => "success").increment(1);
    metrics::counter!("auth_2fa_success_total", "method" => "email").increment(1);
    Ok(tokens)
}

pub async fn complete_login_with_recovery(
    state: &AppState,
    pre_auth_token: &str,
    recovery_code_plaintext: &str,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    request_id: Option<Uuid>,
) -> Result<AuthTokens, AppError> {
    let redis_key = pre_auth_key(pre_auth_token);
    let fail_key = format!("rc_fail:{}", pre_auth_token);

    let mut conn = state
        .redis
        .get()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    let pre_auth_state = load_pre_auth_state_from_redis(&mut conn, &redis_key).await?;
    drop(conn);

    // Recovery codes stand in for any method, so no method check here. The
    // token stays alive until success.
    let user_id = pre_auth_state.user_id;
    let remember_me = pre_auth_state.remember_me;
    let user_fail_key = format!("{}{}", RC_USER_FAIL_PREFIX, user_id);

    let attempt = redis_counter::consume(
        &state.redis,
        &[
            Budget {
                key: &fail_key,
                limit: MAX_RECOVERY_FAILURES,
                window_secs: PRE_AUTH_TTL_SECS,
            },
            Budget {
                key: &user_fail_key,
                limit: MAX_RECOVERY_FAILURES_BY_USER,
                window_secs: RECOVERY_FAILURE_USER_WINDOW_SECS,
            },
        ],
    )
    .await?;
    if attempt.exceeded {
        return Err(AppError::RateLimitExceeded);
    }

    let user = user_repo::find_by_id(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::Unauthorized)?;

    if !user.is_active() {
        return Err(AppError::AccountSuspended);
    }
    if user.is_locked(state.clock.now()) {
        return Err(AppError::AccountLocked);
    }

    // The lookup refuses used and expired codes, and the UPDATE re-checks both:
    // a code sitting on its deadline can cross it between the two statements.
    let code_hash = crypto::sha256(recovery_code_plaintext.as_bytes());
    let record = recovery_code::find_by_hash(&state.db, &code_hash)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .filter(|r| r.user_id == user_id);

    let consumed = match record {
        Some(record) => recovery_code::consume(&state.db, record.id)
            .await
            .map_err(|e| AppError::Internal(e.into()))?,
        None => false,
    };

    if !consumed {
        record_second_factor_failure(state, &user, ip, user_agent, request_id).await;
        metrics::counter!("auth_2fa_failures_total", "method" => "recovery_code").increment(1);
        apply_backoff(attempt.counts[0]).await;
        return Err(AppError::TwoFactorFailed);
    }

    // Consume the pre-auth token now that recovery succeeded.
    if let Ok(mut c) = state.redis.get().await {
        let _: Result<(), _> = c.del(&redis_key).await;
        let _: Result<(), _> = c.del(&fail_key).await;
        let _: Result<(), _> = c.del(&user_fail_key).await;
        let _: Result<(), _> = c
            .srem::<_, _, ()>(user_pre_auth_index_key(user_id), pre_auth_token)
            .await;
    }

    let tokens = issue_tokens(
        state,
        user.id,
        ip,
        user_agent,
        None,
        remember_me,
        SessionType::Web,
        None,
        None,
        Some(SignIn {
            identifier: None,
            request_id,
            audit_metadata: json!({"two_factor": "recovery_code"}),
        }),
    )
    .await?;

    let mailer = state.mailer.clone();
    let templates = state.templates.clone();
    let mail_cfg = state.config.mail.clone();
    let email_to = user.email.clone();
    let username = user.username.clone();
    let locale = user.preferred_locale.clone();
    email::dispatch_best_effort("recovery_code_used_email", async move {
        email::send_recovery_code_used(
            &mailer,
            templates.as_ref(),
            &mail_cfg,
            &email_to,
            &username,
            &locale,
        )
        .await
    });

    metrics::counter!("auth_logins_total", "outcome" => "success").increment(1);
    metrics::counter!("auth_2fa_success_total", "method" => "recovery_code").increment(1);
    Ok(tokens)
}
