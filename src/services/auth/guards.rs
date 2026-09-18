//! Abuse guards shared by the flows: attempt budgets, failure records, backoff.

use super::*;
use crate::domain::token::{OneTimeToken, TokenVerdict};

/// Every one-time token submission takes at least this long, found or not.
const ONE_TIME_TOKEN_MIN_DURATION: std::time::Duration = std::time::Duration::from_millis(100);

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
            let _: Result<(), _> = conn.pfadd(&key, identifier).await;
            let _: Result<(), _> = conn.expire(&key, CS_WINDOW_SECS as i64).await;
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
            attempted_identifier: identifier,
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

/// [`ensure_status_allows_sign_in`], then the lockout: for flows completing
/// after the password was proven (second factors, client flows).
pub(crate) fn ensure_account_usable(
    user: &User,
    now: ::time::OffsetDateTime,
) -> Result<(), AppError> {
    ensure_status_allows_sign_in(user)?;
    if user.is_locked(now) {
        return Err(AppError::AccountLocked);
    }
    Ok(())
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
    fn a_usable_account_is_allowed_and_unlocked() {
        let now = ::time::OffsetDateTime::UNIX_EPOCH + ::time::Duration::days(1);
        let later = now + ::time::Duration::seconds(1);
        assert!(ensure_account_usable(&user(UserStatus::Active, None), now).is_ok());
        assert!(ensure_account_usable(&user(UserStatus::Active, Some(now)), now).is_ok());
        assert!(matches!(
            ensure_account_usable(&user(UserStatus::Active, Some(later)), now),
            Err(AppError::AccountLocked)
        ));
        assert!(matches!(
            ensure_account_usable(&user(UserStatus::Inactive, Some(later)), now),
            Err(AppError::AccountInactive)
        ));
    }
}
