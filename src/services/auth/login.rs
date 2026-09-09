//! Password sign-in: brute-force limits, lockout, and the 2FA hand-off.

use super::*;

/// Tell the owner of an existing account that someone tried to register with
/// their address. Best-effort, like every notification.
pub(super) fn notify_existing_account(state: &AppState, user: &User) {
    let mailer = state.mailer.clone();
    let templates = state.templates.clone();
    let mail_cfg = state.config.mail.clone();
    let email_to = user.email.clone();
    let username = user.username.clone();
    let locale = user.preferred_locale.clone();
    email::dispatch_best_effort("account_exists_email", async move {
        email::send_account_exists(
            &mailer,
            templates.as_ref(),
            &mail_cfg,
            &email_to,
            &username,
            &locale,
        )
        .await
    });
}

#[allow(clippy::too_many_arguments)]
pub async fn login(
    state: &AppState,
    identifier: &str,
    password_plaintext: &str,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    device_name: Option<&str>,
    remember_me: bool,
    request_id: Option<Uuid>,
) -> Result<LoginResult, AppError> {
    let brute_force_cutoff = state.clock.now() - TimeDuration::seconds(BRUTE_FORCE_WINDOW_SECS);

    let ip_failures_fut = async {
        match ip {
            Some(ip_val) => login_attempt::count_recent_failures_by_ip(
                &state.db,
                crate::middleware::rate_limit::ip_bucket_network(ip_val.ip()),
                brute_force_cutoff,
                MAX_FAILURES_BY_IP,
            )
            .await
            .map_err(|e| AppError::Internal(e.into())),
            None => Ok(0),
        }
    };
    let ip_distinct_fut = async {
        match ip {
            Some(ip_val) => {
                if let Ok(mut conn) = state.redis.get().await {
                    let hll_key = format!("{}{}", CS_HLL_PREFIX, ip_bucket(ip_val.ip()));
                    Ok(conn.pfcount(&hll_key).await.unwrap_or(0))
                } else {
                    Ok(0)
                }
            }
            None => Ok(0),
        }
    };
    let identifier_failures_fut = async {
        login_attempt::count_recent_failures_by_identifier(
            &state.db,
            identifier,
            brute_force_cutoff,
            MAX_FAILURES_BY_IDENTIFIER,
        )
        .await
        .map_err(|e| AppError::Internal(e.into()))
    };

    let (ip_failures, distinct_identifiers, failures) =
        tokio::try_join!(ip_failures_fut, ip_distinct_fut, identifier_failures_fut)?;

    if ip_failures >= MAX_FAILURES_BY_IP {
        return Err(AppError::RateLimitExceeded);
    }
    if distinct_identifiers >= CS_MAX_DISTINCT_IDENTIFIERS {
        return Err(AppError::RateLimitExceeded);
    }

    if failures >= MAX_FAILURES_BY_IDENTIFIER {
        return Err(AppError::RateLimitExceeded);
    }

    // User lookup stays index-friendly by branching on email vs username format.
    let user_opt = user_repo::find_by_identifier(&state.db, identifier).await?;

    // Always verify a password hash to prevent timing-based enumeration.
    let (user, password_ok) = match user_opt {
        Some(u) => {
            let ok =
                password::verify_async(password_plaintext, &u.password_hash, &state.config.crypto)
                    .await
                    .map_err(|e| AppError::Internal(e.into()))?;

            // A locked account answers the same whatever the password, after the
            // same Argon2 work. Checking the lock only after a correct password
            // turned the lockout into an oracle confirming the guess.
            if u.is_locked(state.clock.now()) {
                metrics::counter!("auth_logins_total", "outcome" => "locked").increment(1);
                return Err(AppError::AccountLocked);
            }
            (Some(u), ok)
        }
        None => {
            let _ = password::verify_async(
                password_plaintext,
                dummy_hash(&state.config.crypto),
                &state.config.crypto,
            )
            .await;
            (None, false)
        }
    };

    // Record failure and return on bad credentials
    let user = match (user, password_ok) {
        (None, _) => {
            tokio::join!(
                record_failure(
                    &state.db,
                    None,
                    identifier,
                    LoginFailureReason::UnknownIdentifier,
                    ip,
                    user_agent,
                ),
                track_credential_stuffing(state, ip, identifier),
            );
            metrics::counter!("auth_logins_total", "outcome" => "invalid_credentials").increment(1);
            apply_backoff(failures + 1).await;
            return Err(AppError::InvalidCredentials);
        }
        (Some(u), false) => {
            tokio::join!(
                record_failure(
                    &state.db,
                    Some(u.id),
                    identifier,
                    LoginFailureReason::InvalidPassword,
                    ip,
                    user_agent,
                ),
                track_credential_stuffing(state, ip, identifier),
            );

            // After recording the failure, check if the lockout threshold is reached.
            let threshold = i64::from(state.config.security.lockout_threshold);
            let consecutive =
                login_attempt::count_consecutive_failures_by_user(&state.db, u.id, threshold)
                    .await
                    .unwrap_or(0);
            if let Some(locked_until) = lockout_until(
                consecutive,
                state.config.security.lockout_threshold,
                state.config.security.lockout_duration_secs,
                state.clock.now(),
            ) {
                metrics::counter!("auth_lockouts_total").increment(1);
                // Best-effort: lockout and audit must not leak timing information on the login path.
                let _ = user_repo::set_locked_until(&state.db, u.id, locked_until).await;
                let _ = audit::append(
                    &state.db,
                    &NewAuditEntry {
                        user_id: Some(u.id),
                        request_id,
                        action: AuditAction::AccountSuspended,
                        ip_address: ip,
                        metadata: json!({"reason": "lockout", "locked_until": locked_until.unix_timestamp()}),
                    },
                )
                .await;
            }

            metrics::counter!("auth_logins_total", "outcome" => "invalid_credentials").increment(1);
            apply_backoff(failures + 1).await;
            return Err(AppError::InvalidCredentials);
        }
        (Some(u), true) => u,
    };

    // Account status checks
    ensure_status_allows_sign_in(&user)?;

    let primary_method = tf_repo::find_primary_by_user(&state.db, user.id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    // 2FA: issue a short-lived pre-auth token and pause login.
    if let Some(primary) = primary_method.as_ref() {
        let method = match primary.method_type {
            crate::domain::two_factor::TwoFactorType::Email => ChallengeMethod::Email,
            crate::domain::two_factor::TwoFactorType::Totp => ChallengeMethod::Totp,
        };

        let pre_auth_token = crypto::generate_token();
        let redis_key = pre_auth_key(&pre_auth_token);
        let pre_auth_state = PreAuthState {
            user_id: user.id,
            remember_me,
            method: Some(method),
        };
        let serialized =
            serde_json::to_string(&pre_auth_state).map_err(|e| AppError::Internal(e.into()))?;

        let mut conn = state
            .redis
            .get()
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        conn.set_ex::<_, _, ()>(&redis_key, serialized, PRE_AUTH_TTL_SECS)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;

        // Maintain a per-user index so reset_password (and other revocation
        // hooks) can purge active pre-auth tokens without SCAN. Best-effort:
        // a stale entry is harmless because the token itself expires after
        // PRE_AUTH_TTL_SECS, and DEL on a missing key is a no-op.
        let user_index_key = user_pre_auth_index_key(user.id);
        let _: Result<(), _> = conn
            .sadd::<_, _, ()>(&user_index_key, &pre_auth_token)
            .await;
        let _: Result<(), _> = conn
            .expire::<_, ()>(&user_index_key, PRE_AUTH_TTL_SECS as i64)
            .await;

        // For Email 2FA, dispatch the code as soon as the challenge is issued.
        if method == ChallengeMethod::Email {
            email_2fa::send_code(state, user.id).await?;
        }

        metrics::counter!("auth_logins_total", "outcome" => "two_factor_required").increment(1);
        return Ok(LoginResult::TwoFactorRequired {
            pre_auth_token,
            method: method.as_str().to_string(),
        });
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
            identifier: Some(identifier),
            request_id,
            audit_metadata: json!({}),
        }),
    )
    .await?;

    metrics::counter!("auth_logins_total", "outcome" => "success").increment(1);
    Ok(LoginResult::Complete(tokens))
}

/// When a sign-in locks the account: once `consecutive` wrong passwords reach
/// `threshold`, for `duration_secs` from `now`. Saturates instead of wrapping,
/// so an absurd duration locks for a long time rather than not at all.
pub(crate) fn lockout_until(
    consecutive: i64,
    threshold: u32,
    duration_secs: u64,
    now: ::time::OffsetDateTime,
) -> Option<::time::OffsetDateTime> {
    if threshold == 0 || consecutive < i64::from(threshold) {
        return None;
    }
    let duration = i64::try_from(duration_secs)
        .map(TimeDuration::seconds)
        .unwrap_or(TimeDuration::MAX);
    Some(now.saturating_add(duration))
}

#[cfg(test)]
mod lockout_tests {
    use super::*;

    fn now() -> ::time::OffsetDateTime {
        ::time::OffsetDateTime::UNIX_EPOCH + TimeDuration::days(20_000)
    }

    #[test]
    fn the_lock_starts_at_the_threshold() {
        assert_eq!(lockout_until(2, 3, 1800, now()), None);
        assert_eq!(
            lockout_until(3, 3, 1800, now()),
            Some(now() + TimeDuration::seconds(1800))
        );
        assert_eq!(
            lockout_until(9, 3, 60, now()),
            Some(now() + TimeDuration::seconds(60))
        );
    }

    #[test]
    fn a_zero_threshold_never_locks() {
        assert_eq!(lockout_until(0, 0, 1800, now()), None);
        assert_eq!(lockout_until(5, 0, 1800, now()), None);
    }

    #[test]
    fn an_absurd_duration_saturates_instead_of_unlocking() {
        let until = lockout_until(3, 3, u64::MAX, now()).expect("locked");
        assert!(until > now() + TimeDuration::days(365 * 1000));
    }

    mod properties {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            #[test]
            fn a_lock_exactly_follows_the_threshold_and_never_ends_in_the_past(
                consecutive in -5i64..50,
                threshold in 0u32..20,
                duration in any::<u64>(),
                longer in any::<u64>(),
            ) {
                let locked = lockout_until(consecutive, threshold, duration, now());
                prop_assert_eq!(locked.is_some(), threshold > 0 && consecutive >= i64::from(threshold));
                if let Some(until) = locked {
                    prop_assert!(until >= now());
                    let other = lockout_until(consecutive, threshold, duration.max(longer), now()).unwrap();
                    prop_assert!(other >= until, "a longer lockout ended earlier");
                }
            }
        }
    }
}
