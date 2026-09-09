//! Issuing sessions and access tokens, and revoking them.

use super::*;

/// A completed sign-in to record with the session it creates.
pub(crate) struct SignIn<'a> {
    /// Identifier typed at the password step; `None` when the attempt was
    /// already recorded (a second factor completing a login).
    pub identifier: Option<&'a str>,
    pub request_id: Option<Uuid>,
    pub audit_metadata: serde_json::Value,
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn issue_tokens(
    state: &AppState,
    user_id: Uuid,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    device_name: Option<&str>,
    remember_me: bool,
    session_type: SessionType,
    client_id: Option<&str>,
    scopes: Option<&[String]>,
    sign_in: Option<SignIn<'_>>,
) -> Result<AuthTokens, AppError> {
    let raw_token = crypto::generate_token();
    let token_hash = crypto::sha256(raw_token.as_bytes());

    let now = state.clock.now();
    let expires_at = crate::domain::session::capped_expiry(
        now,
        state.config.jwt.session_ttl_secs(remember_me),
        now,
        state.config.jwt.max_session_lifetime_secs,
    );

    let device_name = device_name.and_then(crate::domain::session::device_label);

    // The session and the sign-in records commit together: one round of
    // fsync instead of four, and no session without its audit trail.
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    let session = session_repo::create(
        &mut *tx,
        &NewSession {
            user_id,
            session_family_id: Uuid::new_v4(),
            expires_at,
            ip_address: ip,
            device_name: device_name.as_deref(),
            remember_me,
            token_hash: &token_hash,
            user_agent,
            session_type,
            client_id,
            family_created_at: None,
            scopes,
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    if let Some(sign_in) = sign_in {
        user_repo::record_sign_in(&mut *tx, user_id)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        if let Some(identifier) = sign_in.identifier {
            // The user agent is kept for failures only: a successful attempt
            // is already described by the session it created.
            login_attempt::record(
                &mut *tx,
                &NewLoginAttempt {
                    user_id: Some(user_id),
                    attempted_identifier: identifier,
                    was_successful: true,
                    failure_reason: None,
                    request_ip: ip,
                    request_user_agent: None,
                },
            )
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        }
        audit::append(
            &mut *tx,
            &NewAuditEntry {
                user_id: Some(user_id),
                request_id: sign_in.request_id,
                action: AuditAction::Login,
                ip_address: ip,
                metadata: sign_in.audit_metadata,
            },
        )
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    }

    tx.commit()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    // No re-authentication marker here: a session that was just created (by a
    // password login, an approved device, a 2FA challenge) has not re-proven
    // knowledge of the password for sensitive actions. Only an explicit
    // `POST /users/me/reauth` or a `current_password` in the request does.
    let access_token = build_access_token(user_id, session.id, scopes, state).await?;

    Ok(AuthTokens {
        access_token,
        refresh_token: raw_token,
        session,
    })
}

pub(super) async fn build_access_token(
    user_id: Uuid,
    session_id: uuid::Uuid,
    scopes: Option<&[String]>,
    state: &AppState,
) -> Result<String, AppError> {
    let issued_at = state.clock.now();
    let exp = issued_at
        .saturating_add(::time::Duration::seconds(
            i64::try_from(state.config.jwt.access_expiry_secs).unwrap_or(i64::MAX),
        ))
        .unix_timestamp();

    let (mut role_names, mut permission_names) = role::find_rbac_names(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    // A session issued to a client carries only the permissions consented for
    // that client, re-evaluated against the user's current permissions on every
    // issue and refresh. Roles are dropped: a resource server authorizing by
    // role would otherwise grant more than the consent covered.
    if let Some(scopes) = scopes {
        permission_names.retain(|permission| scopes.contains(permission));
        role_names.clear();
    }

    let mut claims = Claims::new(user_id, session_id, issued_at.unix_timestamp(), exp)
        .with_rbac(role_names, permission_names);
    // Stamp iss/aud so downstream resource servers can pin
    // the token to this issuer and to themselves. `aud` is emitted as a JSON
    // array so a single token can be accepted by multiple downstream services.
    claims.iss = Some(state.config.server.public_url.clone());
    claims.aud = state.config.jwt.audience.clone();

    crate::utils::jwt::encode_token(&claims, &state.jwt_signing_key, Some(&state.jwt_kid))
        .map_err(|e| AppError::Internal(e.into()))
}

/// Add a refresh token hash to the Redis blocklist.
/// TTL is set to the remaining lifetime of the session so the key auto-expires.
/// Fail-open: if Redis is unavailable the revocation is still recorded in DB.
pub async fn blocklist_refresh_token(
    state: &AppState,
    token_hash: &[u8],
    session_expires_at: ::time::OffsetDateTime,
) {
    let ttl = (session_expires_at - state.clock.now()).whole_seconds();
    if ttl <= 0 {
        return;
    }
    let key = format!("{}{}", RT_BLOCKLIST_PREFIX, rt_hash_key(token_hash));
    if let Ok(mut conn) = state.redis.get().await {
        let _: Result<(), _> = conn.set_ex(&key, 1u8, ttl as u64).await;
    }
}

/// Return true if the refresh token hash is in the Redis blocklist.
///
/// Fail-soft: returns `Err(AppError::ServiceUnavailable)` when Redis is unreachable
/// or the EXISTS query fails. The caller (`refresh_token`) is expected to fall back
/// to the database revocation check (`session.revoked_at`) which is the durable
/// source of truth. Returning `false` silently here would let revoked refresh
/// tokens be accepted during a Redis outage (AUTH-H1).
pub async fn is_refresh_token_blocked(
    state: &AppState,
    token_hash: &[u8],
) -> Result<bool, AppError> {
    let key = format!("{}{}", RT_BLOCKLIST_PREFIX, rt_hash_key(token_hash));
    let mut conn = state.redis.get().await.map_err(|e| {
        tracing::error!(
            error = %e,
            "refresh-token blocklist check failed: Redis pool unavailable; falling back to DB revocation check"
        );
        AppError::ServiceUnavailable("redis_unavailable")
    })?;
    conn.exists::<_, bool>(&key).await.map_err(|e| {
        tracing::error!(
            error = %e,
            "refresh-token blocklist EXISTS query failed; falling back to DB revocation check"
        );
        AppError::ServiceUnavailable("redis_query_failed")
    })
}

pub(super) fn rt_hash_key(token_hash: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token_hash)
}

/// Write a JTI to the Redis blocklist with TTL = remaining token lifetime.
/// Fail-open: if Redis is unavailable the logout still succeeds.
pub async fn blocklist_jti(state: &AppState, jti: Uuid, token_exp: i64) {
    let ttl = token_exp - state.clock.now().unix_timestamp();
    if ttl <= 0 {
        return;
    }
    let key = format!("{}{}", JTI_BLOCKLIST_PREFIX, jti);
    if let Ok(mut conn) = state.redis.get().await {
        let _: Result<(), _> = conn.set_ex(&key, 1u8, ttl as u64).await;
    }
}

/// Check that an access token was neither revoked nor issued for a session
/// that has ended.
///
/// The JTI blocklist and the session-validity cache are read in one pipeline,
/// one round trip on every authenticated request. On a cache miss the session
/// is read from the database and cached for SESSION_CACHE_TTL_SECS; both
/// outcomes are cached so replayed revoked tokens do not hammer the database.
///
/// Fails closed: when Redis cannot be read, the revocation of the token cannot
/// be ruled out, so the request is refused with 503 (AUTH-H1).
///
/// **Limitation:** revocations outside explicit logout are reflected once the
/// cache entry expires; logout and revocation paths invalidate it directly.
pub async fn verify_token_state(
    state: &AppState,
    jti: Uuid,
    session_id: Uuid,
) -> Result<(), AppError> {
    let blocklist_key = format!("{JTI_BLOCKLIST_PREFIX}{jti}");
    let cache_key = format!("{SESSION_CACHE_PREFIX}{session_id}");

    let mut conn = state.redis.get().await.map_err(|e| {
        tracing::error!(%jti, error = %e, "token state check failed: Redis pool unavailable; failing closed");
        AppError::ServiceUnavailable("redis_unavailable")
    })?;
    let (blocked, cached): (bool, Option<u8>) = deadpool_redis::redis::pipe()
        .exists(&blocklist_key)
        .get(&cache_key)
        .query_async(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!(%jti, error = %e, "token state pipeline failed; failing closed");
            AppError::ServiceUnavailable("redis_query_failed")
        })?;

    if blocked {
        return Err(AppError::TokenInvalid);
    }

    let active = match cached {
        Some(value) => value == 1,
        None => {
            let session = session_repo::find_validation_by_id(&state.db, session_id)
                .await
                .map_err(|_| AppError::Unauthorized)?
                .ok_or(AppError::Unauthorized)?;
            let active = session.is_active(state.clock.now());
            let _: Result<(), _> = conn
                .set_ex(&cache_key, u8::from(active), SESSION_CACHE_TTL_SECS)
                .await;
            active
        }
    };

    if active {
        Ok(())
    } else {
        Err(AppError::Unauthorized)
    }
}

/// Immediately invalidate the session validity cache entry.
/// Call this on explicit logout to ensure revocation takes effect without waiting for TTL expiry.
/// Best-effort: if Redis is unavailable, the cache expires naturally within SESSION_CACHE_TTL_SECS.
pub fn invalidate_session_cache(state: &AppState, session_id: Uuid) {
    let redis = state.redis.clone();
    let key = format!("{SESSION_CACHE_PREFIX}{session_id}");
    tokio::spawn(async move {
        if let Ok(mut conn) = redis.get().await {
            let _: Result<(), _> = conn.del(&key).await;
        }
    });
}

pub async fn invalidate_session_caches(state: &AppState, session_ids: &[Uuid]) {
    if session_ids.is_empty() {
        return;
    }

    if let Ok(mut conn) = state.redis.get().await {
        let keys: Vec<String> = session_ids
            .iter()
            .map(|id| format!("{SESSION_CACHE_PREFIX}{id}"))
            .collect();
        let _: Result<(), _> = conn.del(keys).await;
    }
}
