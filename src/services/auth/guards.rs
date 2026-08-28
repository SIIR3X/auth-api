//! Abuse guards shared by the flows: attempt budgets, failure records, backoff.

use super::*;

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
