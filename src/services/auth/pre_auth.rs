//! Pre-auth state: the short-lived token between a password and its second factor.

use super::*;

pub async fn resolve_pre_auth(
    state: &AppState,
    pre_auth_token: &str,
) -> Result<PreAuthState, AppError> {
    let redis_key = pre_auth_key(pre_auth_token);
    let mut conn = state
        .redis
        .get()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    load_pre_auth_state_from_redis(&mut conn, &redis_key).await
}

pub(super) fn pre_auth_key(pre_auth_token: &str) -> String {
    format!("{}{}", PRE_AUTH_PREFIX, pre_auth_token)
}

pub(super) fn user_pre_auth_index_key(user_id: Uuid) -> String {
    format!("{}{}", USER_PRE_AUTH_PREFIX, user_id)
}

/// Purge every active pre-auth (2FA challenge) and email-change flow token
/// belonging to `user_id`. Called from sensitive-event handlers such as
/// password reset to close the post-reset hijack window.
///
/// Best-effort: any Redis failure is logged and swallowed -- callers must not
/// abort their primary operation (e.g. the password reset itself) on a
/// transient Redis error during cleanup.
pub async fn purge_user_pre_auth_and_email_change(state: &AppState, user_id: Uuid) {
    let mut conn = match state.redis.get().await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, user_id = %user_id, "failed to acquire redis connection for pre-auth purge");
            return;
        }
    };

    // 1. Purge pre-auth (2FA challenge) tokens via the per-user index.
    let index_key = user_pre_auth_index_key(user_id);
    let tokens: Vec<String> = conn.smembers(&index_key).await.unwrap_or_default();
    for token in &tokens {
        let pre_key = pre_auth_key(token);
        let _: Result<(), _> = conn.del(&pre_key).await;
        let _: Result<(), _> = conn.del(format!("totp_fail:{}", token)).await;
        let _: Result<(), _> = conn.del(format!("rc_fail:{}", token)).await;
    }
    let _: Result<(), _> = conn.del(&index_key).await;

    // 2. Purge any in-progress email-change flow for this user. The flow keeps
    // its current flow_token in `email_change_active:{user_id}`, so we don't
    // need to scan.
    let active_key = format!("email_change_active:{}", user_id);
    let active_token: Option<String> = conn.get(&active_key).await.unwrap_or(None);
    if let Some(flow_token) = active_token {
        let _: Result<(), _> = conn
            .del(vec![
                format!("email_change_flow:{}", flow_token),
                format!("email_change_fail:{}", flow_token),
                active_key,
            ])
            .await;
    }
}

pub(super) async fn load_pre_auth_state_from_redis(
    conn: &mut crate::utils::redis_pool::RedisConnection,
    redis_key: &str,
) -> Result<PreAuthState, AppError> {
    let raw: Option<String> = conn
        .get(redis_key)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    let raw = raw.ok_or(AppError::TokenInvalid)?;

    parse_pre_auth_state(&raw)
}

pub(super) fn parse_pre_auth_state(raw: &str) -> Result<PreAuthState, AppError> {
    if let Ok(user_id) = raw.parse::<Uuid>() {
        return Ok(PreAuthState {
            user_id,
            remember_me: false,
            method: None,
        });
    }

    serde_json::from_str(raw).map_err(|_| AppError::TokenInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pre_auth_state_accepts_legacy_uuid_payload() {
        let user_id = Uuid::new_v4();

        let state =
            parse_pre_auth_state(&user_id.to_string()).expect("legacy pre-auth should parse");

        assert_eq!(state.user_id, user_id);
    }

    #[test]
    fn parse_pre_auth_state_ignores_fields_from_older_versions() {
        // Tokens minted before risk scoring was retired carry a `risk` field;
        // they must keep parsing until they expire.
        let user_id = Uuid::new_v4();
        let payload = serde_json::json!({
            "user_id": user_id,
            "risk": { "context": { "ip": "203.0.113.9/32" }, "result": null },
            "remember_me": true,
            "method": "totp"
        });

        let state = parse_pre_auth_state(&payload.to_string()).expect("payload should parse");

        assert_eq!(state.user_id, user_id);
        assert!(state.remember_me);
        assert_eq!(state.method, Some(ChallengeMethod::Totp));
    }
}
