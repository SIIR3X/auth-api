//! Refresh token rotation and logout.

use super::*;

/// Rotate a refresh token. `client_id` names the authenticated client of an
/// OAuth token request; `None` is the first-party route, which refreshes only
/// sessions issued to no client: a client's session is refreshed by that client,
/// through the token endpoint and its client authentication.
pub async fn refresh_token(
    state: &AppState,
    raw_token: &str,
    client_id: Option<&str>,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    request_id: Option<Uuid>,
) -> Result<AuthTokens, AppError> {
    // Brute-force guard on refresh attempts per IP. It bounds volume and guards
    // no secret (refresh tokens carry 256 bits), so it fails open like the other
    // abuse budgets: without Redis the refresh goes on to the database, the
    // durable authority on revocation.
    if let Some(ip_val) = ip {
        let key = refresh_failure_key(ip_val);
        match redis_counter::peek(&state.redis, &key).await {
            Ok(failures) if failures >= MAX_REFRESH_FAILURES_BY_IP => {
                return Err(AppError::RateLimitExceeded);
            }
            Ok(_) => {}
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
            note_refresh_failure(state, ip).await;
            return Err(AppError::TokenInvalid);
        }
    };

    if session.client_id.as_deref() != client_id {
        note_refresh_failure(state, ip).await;
        return Err(AppError::TokenInvalid);
    }

    let policy = RefreshPolicy {
        reuse_grace: REFRESH_REUSE_GRACE,
        max_lifetime_secs: state.config.jwt.max_session_lifetime_secs,
        strict_binding: state.config.jwt.strict_session_binding,
    };
    match session.refresh_verdict(state.clock.now(), ip.map(|n| n.ip()), &policy) {
        RefreshVerdict::Rotate => {}
        RefreshVerdict::ConcurrentRefresh
            if rotated_by_this_client(state, &session, ip, user_agent).await =>
        {
            // Two tabs, or a retried request, from the client that rotated
            // the session: refused, the family left alive.
            metrics::counter!("auth_refresh_concurrent_total").increment(1);
            tracing::info!(session_id = %session.id, "rotated refresh token presented within the grace window");
            return Err(AppError::TokenInvalid);
        }
        RefreshVerdict::ConcurrentRefresh => {
            // Within the grace window but from another network or client: the
            // token is in two hands, and the family goes like on any replay.
            note_refresh_failure(state, ip).await;
            revoke_family(state, session.id).await?;
            metrics::counter!("auth_session_replays_total").increment(1);
            audit::append(
                &state.db,
                &NewAuditEntry {
                    user_id: Some(session.user_id),
                    request_id,
                    action: AuditAction::SessionReplayDetected,
                    ip_address: ip,
                    metadata: json!({
                        "session_id": session.id,
                        "reason": "reused_by_another_client",
                    }),
                },
            )
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
            return Err(AppError::TokenInvalid);
        }
        RefreshVerdict::Expired => return Err(AppError::TokenExpired),
        RefreshVerdict::Replay => {
            note_refresh_failure(state, ip).await;
            revoke_family(state, session.id).await?;

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
            note_refresh_failure(state, ip).await;
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
                        // No address in the metadata, which is never coarsened
                        // nor forgotten: the row's own address is the one used.
                        "same_network": same_network(session.ip_address, ip),
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
            mfa: session.mfa,
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
                && rotated_by_this_client(state, &current, ip, user_agent).await
            {
                return Err(AppError::TokenInvalid);
            }
            revoke_family(state, session.id).await?;

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
        new_session.client_id.as_deref(),
        state,
    )
    .await?;

    Ok(AuthTokens {
        access_token,
        refresh_token: new_raw_token,
        session: new_session,
    })
}

fn refresh_failure_key(ip: IpNetwork) -> String {
    format!("refresh_fail:{}", ip_bucket(ip.ip()))
}

/// Count a refused refresh (unknown token, another client's session, a replay,
/// another address) against the address, atomically with its window.
async fn note_refresh_failure(state: &AppState, ip: Option<IpNetwork>) {
    let Some(ip) = ip else { return };
    let key = refresh_failure_key(ip);
    if let Err(error) = redis_counter::consume(
        &state.redis,
        &[Budget {
            key: &key,
            limit: MAX_REFRESH_FAILURES_BY_IP,
            window_secs: REFRESH_FAILURE_WINDOW_SECS,
        }],
    )
    .await
    {
        tracing::warn!(%error, "could not count a refused refresh");
    }
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
    invalidate_session_cache(state, session_id).await;

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

/// Whether the rotation that replaced `session` came from the client now
/// presenting its token again: the same network and the same user agent. Only
/// then is a second use within the grace window a concurrent refresh; the
/// comparison does not depend on how precisely the clocks agree.
async fn rotated_by_this_client(
    state: &AppState,
    session: &Session,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
) -> bool {
    let Some(next_id) = session.replaced_by_session_id else {
        return false;
    };
    let Ok(Some(next)) = session_repo::find_by_id(&state.db, next_id).await else {
        return false;
    };
    let network_matches = match (next.ip_address, ip) {
        (None, None) => true,
        (a, b) => same_network(a, b) == Some(true),
    };
    network_matches && next.user_agent.as_deref() == user_agent
}

/// Whether two client addresses fall in the same network (/24 for IPv4, /48
/// for IPv6): what an investigation needs of a replay, without the addresses.
fn same_network(a: Option<ipnetwork::IpNetwork>, b: Option<ipnetwork::IpNetwork>) -> Option<bool> {
    let (a, b) = (a?.ip(), b?.ip());
    let prefix = |ip: std::net::IpAddr| -> Option<ipnetwork::IpNetwork> {
        let len = if ip.is_ipv4() { 24 } else { 48 };
        ipnetwork::IpNetwork::new(ip, len)
            .ok()
            .and_then(|n| ipnetwork::IpNetwork::new(n.network(), len).ok())
    };
    Some(prefix(a)? == prefix(b)?)
}

#[cfg(test)]
mod same_network_tests {
    use super::same_network;

    #[test]
    fn addresses_compare_by_network() {
        let net = |s: &str| Some(s.parse::<ipnetwork::IpNetwork>().unwrap());
        assert_eq!(
            same_network(net("203.0.113.7"), net("203.0.113.200")),
            Some(true)
        );
        assert_eq!(
            same_network(net("203.0.113.7"), net("198.51.100.7")),
            Some(false)
        );
        assert_eq!(
            same_network(net("2001:db8:1::1"), net("2001:db8:1:ff::2")),
            Some(true)
        );
        assert_eq!(same_network(None, net("203.0.113.7")), None);
    }
}
