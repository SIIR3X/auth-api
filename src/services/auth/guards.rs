//! Abuse guards shared by the flows: attempt budgets, failure records, backoff.

use super::*;
use crate::domain::token::{OneTimeToken, TokenVerdict};

/// Every one-time token submission takes at least this long, found or not.
const ONE_TIME_TOKEN_MIN_DURATION: std::time::Duration = std::time::Duration::from_millis(100);

/// Redis holds the challenge between a password and its second factor: when
/// it cannot be reached, the sign-in is unavailable, not broken.
pub(super) fn redis_unavailable(error: impl std::fmt::Display) -> AppError {
    tracing::warn!(error = %error, "sign-in challenge store unavailable");
    AppError::ServiceUnavailable("redis_unavailable")
}

/// Resends of an e-mail code: twice per challenge, ten times an hour per
/// account. Refused past either, fail closed like the code budgets.
pub(crate) async fn budget_email_resend(
    state: &AppState,
    pre_auth_token: &str,
    user_id: Uuid,
) -> Result<(), AppError> {
    let challenge_key = format!("email2fa_resend:{pre_auth_token}");
    let account_key = format!("email2fa_resend_user:{user_id}");
    let attempt = redis_counter::consume(
        &state.redis,
        &[
            Budget {
                key: &challenge_key,
                limit: MAX_EMAIL_RESENDS_PER_CHALLENGE,
                window_secs: PRE_AUTH_TTL_SECS,
            },
            Budget {
                key: &account_key,
                limit: MAX_EMAIL_RESENDS_PER_ACCOUNT,
                window_secs: SECOND_FACTOR_USER_WINDOW_SECS,
            },
        ],
    )
    .await?;
    if attempt.exceeded {
        return Err(AppError::RateLimitExceeded);
    }
    let user = user_repo::find_by_id(&state.db, user_id)
        .await?
        .ok_or(AppError::TokenInvalid)?;
    ensure_account_usable(&user)
}

/// Mail the owner that their second factor is being guessed, once an hour at
/// most: an account budget exhausted means someone holds the password.
pub(crate) async fn notify_second_factor_pressure(state: &AppState, user_id: Uuid) {
    let key = format!("2fa_pressure_notice:{user_id}");
    if !redis_counter::claim_cooldown(&state.redis, &key, SECOND_FACTOR_USER_WINDOW_SECS).await {
        return;
    }
    let Ok(Some(user)) = user_repo::find_by_id(&state.db, user_id).await else {
        return;
    };
    let mailer = state.mailer.clone();
    let templates = state.templates.clone();
    let mail_cfg = state.config.mail.clone();
    email::dispatch_best_effort("second_factor_attempts_email", async move {
        email::send_second_factor_attempts(
            &mailer,
            templates.as_ref(),
            &mail_cfg,
            &user.email,
            &user.username,
            &user.preferred_locale,
        )
        .await
    });
}

/// The failure budgets of a second factor at sign-in, beside the budget of
/// the challenge itself: `limit` failures per window from one client address,
/// and `SECOND_FACTOR_ACCOUNT_FACTOR` times as many for the account from every
/// address (30 an hour for TOTP codes: a search of the code space stays
/// hopeless, and the owner is mailed when it is spent). Someone holding the password and guessing from their own address
/// exhausts only their share, not the owner's.
pub(crate) fn second_factor_budget_keys(
    prefix: &str,
    user_id: Uuid,
    ip: Option<IpNetwork>,
    limit: i64,
) -> Vec<(String, i64)> {
    let mut keys = vec![(
        format!("{prefix}{user_id}"),
        limit * SECOND_FACTOR_ACCOUNT_FACTOR,
    )];
    if let Some(ip) = ip {
        keys.push((format!("{prefix}{user_id}:{}", ip_bucket(ip.ip())), limit));
    }
    keys
}

/// Whether the account's budget (the first of `second_factor_budget_keys`,
/// behind the challenge's) is the one exceeded.
pub(crate) fn account_budget_exceeded(counts: &[i64], account_limit: i64) -> bool {
    counts.get(1).is_some_and(|count| *count > account_limit)
}

/// The budget of links mailed to `user_id` (`prefix` names the kind): per
/// client address, then for the account as a whole.
pub(super) async fn mailbox_budget_exhausted(
    state: &AppState,
    prefix: &str,
    user_id: Uuid,
    ip: Option<IpNetwork>,
) -> bool {
    if let Some(ip) = ip {
        let key = format!("{prefix}:{user_id}:{}", ip_bucket(ip.ip()));
        if budget_exhausted(
            state,
            &key,
            MAX_MAILBOX_LINKS_BY_ACCOUNT_AND_IP,
            MAILBOX_LINK_ACCOUNT_WINDOW_SECS,
        )
        .await
        {
            return true;
        }
    }
    budget_exhausted(
        state,
        &format!("{prefix}:{user_id}"),
        MAX_MAILBOX_LINKS_BY_ACCOUNT,
        MAILBOX_LINK_ACCOUNT_WINDOW_SECS,
    )
    .await
}

/// Consume one attempt of an abuse-control budget.
///
/// Fails open: these budgets bound volume (mail floods, token scanning) rather
/// than guard a secret, so a Redis outage must not take account recovery down
/// with it. Second-factor budgets, which do guard secrets, fail closed instead.
pub(super) async fn budget_exhausted(
    state: &AppState,
    key: &str,
    limit: i64,
    window_secs: u64,
) -> bool {
    match redis_counter::consume(
        &state.redis,
        &[Budget {
            key,
            limit,
            window_secs,
        }],
    )
    .await
    {
        Ok(attempt) => attempt.exceeded,
        Err(error) => {
            tracing::warn!(key, error = %error, "abuse budget unavailable, failing open");
            false
        }
    }
}

/// Throttle submissions of one-time tokens (email verification, password
/// reset): per IP, and per token hash across every IP. Tokens carry 256 bits,
/// so this is volume control, not the security boundary; it fails open.
pub(super) async fn guard_token_submission(
    state: &AppState,
    kind: &str,
    ip: Option<IpNetwork>,
    token_hash: &[u8; 32],
) -> Result<(), AppError> {
    let hex: String = token_hash.iter().map(|b| format!("{b:02x}")).collect();
    let hash_key = format!("{kind}_tok:{hex}");
    let ip_key = ip.map(|ip| format!("{kind}_fail:{}", ip_bucket(ip.ip())));

    let mut budgets = vec![Budget {
        key: &hash_key,
        limit: MAX_TOKEN_SUBMIT_BY_HASH,
        window_secs: TOKEN_SUBMIT_WINDOW_SECS,
    }];
    if let Some(key) = ip_key.as_deref() {
        budgets.push(Budget {
            key,
            limit: MAX_TOKEN_SUBMIT_BY_IP,
            window_secs: TOKEN_SUBMIT_WINDOW_SECS,
        });
    }

    match redis_counter::consume(&state.redis, &budgets).await {
        Ok(attempt) if attempt.exceeded => Err(AppError::RateLimitExceeded),
        Ok(_) => Ok(()),
        Err(error) => {
            tracing::warn!(error = %error, "token submission budget unavailable, failing open");
            Ok(())
        }
    }
}

/// Add the attempted identifier to the per-IP HyperLogLog for credential-stuffing detection.
/// Fire-and-forget: Redis unavailability does not affect the login flow.
pub(super) async fn track_credential_stuffing(
    state: &AppState,
    ip: Option<IpNetwork>,
    identifier: &str,
) {
    let ip_val = match ip {
        Some(i) => i,
        None => return,
    };
    match state.redis.get().await {
        Ok(mut conn) => {
            let key = format!("{}{}", CS_HLL_PREFIX, ip_bucket(ip_val.ip()));
            // One atomic pipeline: the key never lives without its expiry.
            let _: Result<(), _> = deadpool_redis::redis::pipe()
                .atomic()
                .pfadd(&key, identifier)
                .ignore()
                .expire(&key, CS_WINDOW_SECS as i64)
                .ignore()
                .query_async(&mut *conn)
                .await;
        }
        Err(e) => {
            tracing::warn!(ip = %ip_val.ip(), error = %e, "credential-stuffing tracking skipped: Redis unavailable");
        }
    }
}

pub(super) async fn record_failure(
    db: &sqlx::PgPool,
    user_id: Option<Uuid>,
    identifier: &str,
    reason: LoginFailureReason,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
) {
    let _ = login_attempt::record(
        db,
        &NewLoginAttempt {
            user_id,
            attempted_identifier: crate::domain::login_attempt::storable_identifier(identifier),
            was_successful: false,
            failure_reason: Some(reason),
            request_ip: ip,
            request_user_agent: user_agent,
        },
    )
    .await;
}

/// Record a failed second factor: it lands in `login_attempts` next to password
/// failures and in the audit log.
///
/// It deliberately does not feed the account lockout: whoever fails a second
/// factor already holds the password, and locking would hand them a way to shut
/// the real owner out. The per-token and per-account budgets bound the search.
pub(super) async fn record_second_factor_failure(
    state: &AppState,
    user: &User,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    request_id: Option<Uuid>,
) {
    record_failure(
        &state.db,
        Some(user.id),
        &user.email,
        LoginFailureReason::TwoFactorFailed,
        ip,
        user_agent,
    )
    .await;

    let _ = audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user.id),
            request_id,
            action: AuditAction::TwoFactorFailed,
            ip_address: ip,
            metadata: json!({}),
        },
    )
    .await;
}

pub(super) async fn apply_backoff(failures: i64) {
    backoff::apply(failures).await;
}

/// Refuse an account whose status does not allow signing in, with the answer
/// the password sign-in gives. Every flow ending in tokens goes through it, so
/// a status never reads differently from one route to another.
pub(crate) fn ensure_status_allows_sign_in(user: &User) -> Result<(), AppError> {
    match user.status {
        UserStatus::Active => Ok(()),
        UserStatus::Suspended => Err(AppError::AccountSuspended),
        UserStatus::Inactive => Err(AppError::AccountInactive),
        UserStatus::PendingVerification => Err(AppError::EmailNotVerified),
    }
}

/// [`ensure_status_allows_sign_in`], for flows that do not use the password
/// (second factors after it, passkeys, links, identities, client flows). The
/// lockout guards the password alone: none of these can be guessed, and
/// letting it block them would let anyone who knows the identifier shut the
/// owner out.
pub(crate) fn ensure_account_usable(user: &User) -> Result<(), AppError> {
    ensure_status_allows_sign_in(user)
}

/// Look a one-time token up (email verification, password reset) and judge it.
///
/// The lookup always runs and the answer takes at least
/// [`ONE_TIME_TOKEN_MIN_DURATION`], so the response time does not reveal
/// whether a token exists.
pub(super) async fn check_one_time_token<T: OneTimeToken>(
    state: &AppState,
    lookup: impl std::future::Future<Output = Result<Option<T>, sqlx::Error>>,
) -> Result<T, AppError> {
    let start = std::time::Instant::now();
    let result = async {
        let record = lookup
            .await
            .map_err(|e| AppError::Internal(e.into()))?
            .ok_or(AppError::TokenInvalid)?;
        match record.verdict(state.clock.now()) {
            TokenVerdict::Valid => Ok(record),
            TokenVerdict::Expired => Err(AppError::TokenExpired),
            TokenVerdict::Used => Err(AppError::TokenInvalid),
        }
    }
    .await;

    if let Some(rest) = ONE_TIME_TOKEN_MIN_DURATION.checked_sub(start.elapsed()) {
        tokio::time::sleep(rest).await;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(status: UserStatus, locked_until: Option<::time::OffsetDateTime>) -> User {
        let epoch = ::time::OffsetDateTime::UNIX_EPOCH;
        User {
            id: Uuid::nil(),
            created_at: epoch,
            updated_at: epoch,
            email_verified_at: None,
            last_login_at: None,
            locked_until,
            status,
            preferred_locale: "en".into(),
            username: "jane".into(),
            email: "jane@example.com".into(),
            password_hash: String::new(),
        }
    }

    #[test]
    fn each_status_reads_as_the_password_sign_in_answers_it() {
        assert!(ensure_status_allows_sign_in(&user(UserStatus::Active, None)).is_ok());
        assert!(matches!(
            ensure_status_allows_sign_in(&user(UserStatus::Suspended, None)),
            Err(AppError::AccountSuspended)
        ));
        assert!(matches!(
            ensure_status_allows_sign_in(&user(UserStatus::Inactive, None)),
            Err(AppError::AccountInactive)
        ));
        assert!(matches!(
            ensure_status_allows_sign_in(&user(UserStatus::PendingVerification, None)),
            Err(AppError::EmailNotVerified)
        ));
    }

    #[test]
    fn a_locked_password_does_not_block_the_other_ways_in() {
        let now = ::time::OffsetDateTime::UNIX_EPOCH + ::time::Duration::days(1);
        let later = now + ::time::Duration::seconds(60);
        assert!(ensure_account_usable(&user(UserStatus::Active, Some(later))).is_ok());
        assert!(matches!(
            ensure_account_usable(&user(UserStatus::Inactive, Some(later))),
            Err(AppError::AccountInactive)
        ));
    }
}
