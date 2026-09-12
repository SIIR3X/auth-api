//! Refresh token rotation and logout.

use super::*;

pub async fn refresh_token(
    state: &AppState,
    raw_token: &str,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    request_id: Option<Uuid>,
) -> Result<AuthTokens, AppError> {
    // Brute-force guard on refresh attempts per IP. It bounds volume and guards
    // no secret (refresh tokens carry 256 bits), so it fails open like the other
    // abuse budgets: without Redis the refresh goes on to the database, the
    // durable authority on revocation.
    if let Some(ip_val) = ip {
        let key = format!("refresh_fail:{}", ip_bucket(ip_val.ip()));
        match state.redis.get().await {
            Ok(mut conn) => {
                let failures: i64 = conn.get(&key).await.unwrap_or(0);
                if failures >= MAX_REFRESH_FAILURES_BY_IP {
                    return Err(AppError::RateLimitExceeded);
                }
            }
            Err(error) => {
                tracing::warn!(error = %error, "refresh budget unavailable, failing open");
            }
        }
    }

    let token_hash = crypto::sha256(raw_token.as_bytes());

    // Fast-path: check Redis blocklist before hitting the DB.
    // If Redis is unavailable we deliberately do NOT abort here: the DB
    // revocation check below (`session.revoked_at`) is the durable source of
    // truth. The Redis miss has already been logged at error! by the helper.
    match is_refresh_token_blocked(state, &token_hash).await {
        Ok(true) => return Err(AppError::TokenInvalid),
        Ok(false) => {}
        Err(AppError::ServiceUnavailable(_)) => {
            tracing::warn!(
                "refresh-token Redis blocklist unavailable; relying on DB session.revoked_at fallback"
            );
        }
        Err(e) => return Err(e),
    }

    let session = match session_repo::find_by_token_hash(&state.db, &token_hash)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
    {
        Some(s) => s,
        None => {
            // Increment failure counter on unknown token.
            if let Some(ip_val) = ip {
                let key = format!("refresh_fail:{}", ip_bucket(ip_val.ip()));
                if let Ok(mut conn) = state.redis.get().await {
                    let _: Result<(), _> = conn.incr(&key, 1i64).await;
                    let _: Result<(), _> =
                        conn.expire(&key, REFRESH_FAILURE_WINDOW_SECS as i64).await;
                }
            }
            return Err(AppError::TokenInvalid);
        }
    };

    let policy = RefreshPolicy {
        reuse_grace: REFRESH_REUSE_GRACE,
        max_lifetime_secs: state.config.jwt.max_session_lifetime_secs,
        strict_binding: state.config.jwt.strict_session_binding,
    };
    match session.refresh_verdict(state.clock.now(), ip.map(|n| n.ip()), &policy) {
        RefreshVerdict::Rotate => {}
        RefreshVerdict::ConcurrentRefresh => return Err(AppError::TokenInvalid),
        RefreshVerdict::Expired => return Err(AppError::TokenExpired),
        RefreshVerdict::Replay => {
            session_repo::revoke_family(&state.db, session.id)
                .await
                .map_err(|e| AppError::Internal(e.into()))?;

            audit::append(
                &state.db,
                &NewAuditEntry {
                    user_id: Some(session.user_id),
                    request_id,
                    action: AuditAction::SessionReplayDetected,
                    ip_address: ip,
                    metadata: json!({"session_id": session.id}),
                },
            )
            .await
            .map_err(|e| AppError::Internal(e.into()))?;

            return Err(AppError::TokenInvalid);
        }
        RefreshVerdict::AddressMismatch => {
            metrics::counter!("auth_session_replays_total").increment(1);
            audit::append(
                &state.db,
                &NewAuditEntry {
                    user_id: Some(session.user_id),
                    request_id,
                    action: AuditAction::SessionReplayDetected,
                    ip_address: ip,
                    metadata: json!({
                        "reason": "ip_mismatch",
                        "session_id": session.id,
                        "expected_ip": session.ip_address.map(|n| n.ip().to_string()),
                        "actual_ip": ip.map(|n| n.ip().to_string()),
                    }),
                },
            )
            .await
            .map_err(|e| AppError::Internal(e.into()))?;

            return Err(AppError::Unauthorized);
        }
    }

    let user = user_repo::find_by_id(&state.db, session.user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::Unauthorized)?;

    ensure_status_allows_sign_in(&user)?;

    let new_raw_token = crypto::generate_token();
    let new_hash = crypto::sha256(new_raw_token.as_bytes());

    let expires_at = crate::domain::session::capped_expiry(
        state.clock.now(),
        state.config.jwt.session_ttl_secs(session.remember_me),
        session.family_created_at,
        state.config.jwt.max_session_lifetime_secs,
    );

    let new_session = match session_repo::rotate(
        &state.db,
        session.id,
        &NewSession {
            user_id: user.id,
            session_family_id: session.session_family_id,
            expires_at,
            ip_address: ip,
            device_name: session.device_name.as_deref(),
            remember_me: session.remember_me,
            token_hash: &new_hash,
            user_agent,
            session_type: session.session_type,
            client_id: session.client_id.as_deref(),
            family_created_at: Some(session.family_created_at),
            scopes: None,
        },
    )
    .await
    {
        Ok(session) => session,
        Err(sqlx::Error::RowNotFound) => {
            // Another request rotated this session between our read and the
            // lock. Moments ago: the same client refreshing twice.
            if let Ok(Some(current)) = session_repo::find_by_id(&state.db, session.id).await
                && current.rotated_within(REFRESH_REUSE_GRACE, state.clock.now())
            {
                return Err(AppError::TokenInvalid);
            }
            session_repo::revoke_family(&state.db, session.id)
                .await
                .map_err(|e| AppError::Internal(e.into()))?;

            metrics::counter!("auth_session_replays_total").increment(1);

            audit::append(
                &state.db,
                &NewAuditEntry {
                    user_id: Some(session.user_id),
                    request_id,
                    action: AuditAction::SessionReplayDetected,
                    ip_address: ip,
                    metadata: json!({"session_id": session.id}),
                },
            )
            .await
            .map_err(|e| AppError::Internal(e.into()))?;

            return Err(AppError::TokenInvalid);
        }
        Err(e) => return Err(AppError::Internal(e.into())),
    };

    let access_token = build_access_token(
        user.id,
        new_session.id,
        new_session.scopes.as_deref(),
        state,
    )
    .await?;

    Ok(AuthTokens {
        access_token,
        refresh_token: new_raw_token,
        session: new_session,
    })
}

pub async fn logout(
    state: &AppState,
    session_id: Uuid,
    user_id: Uuid,
    jti: Uuid,
    token_exp: i64,
    ip: Option<IpNetwork>,
    request_id: Option<Uuid>,
) -> Result<(), AppError> {
    // Load session before revoking to get token_hash for RT blacklist.
    let session = session_repo::find_by_id(&state.db, session_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    session_repo::revoke(&state.db, session_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    // Invalidate the Redis session cache so revocation propagates immediately
    // without waiting for SESSION_CACHE_TTL_SECS to expire.
    invalidate_session_cache(state, session_id);

    blocklist_jti(state, jti, token_exp).await;

    if let Some(s) = session {
        blocklist_refresh_token(state, &s.token_hash, s.expires_at).await;
        reauth::clear_recent_reauth(state, s.id).await;
    }

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user_id),
            request_id,
            action: AuditAction::Logout,
            ip_address: ip,
            metadata: json!({"session_id": session_id}),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    Ok(())
}
