//! Device Authorization Flow service (RFC 8628).
//!
//! A device client (CLI, TV, desktop application) starts a flow, the user
//! approves it from a browser where they are signed in, and the device polls
//! until tokens are issued.
//!
//! Redis keys, all expiring with the flow:
//! - `device:{base64url(sha256(device_code))}`: JSON [`DeviceAuthState`]
//! - `device_uc:{user_code}`: reverse lookup to that hash, reserved with
//!   `SET NX` so two live flows can never share a user code
//! - `device_poll:{hash}`: pacing marker behind `slow_down`
//! - `device_scan:{ip bucket}`: budget of unknown user codes per address

use std::sync::LazyLock;

use base64::Engine;
use deadpool_redis::redis::{AsyncCommands, Script};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    domain::{
        device::{PollOutcome, poll_outcome},
        registered_client::RegisteredClient,
        session::SessionType,
    },
    error::AppError,
    middleware::rate_limit::ip_bucket,
    repositories::{registered_client as client_repo, user as user_repo},
    services::{auth as auth_svc, authorize as authorize_svc},
    state::AppState,
    utils::{
        crypto,
        redis_counter::{self, Budget},
    },
};

const DEVICE_KEY_PREFIX: &str = "device:";
const DEVICE_UC_PREFIX: &str = "device_uc:";
const DEVICE_POLL_PREFIX: &str = "device_poll:";
const DEVICE_SCAN_PREFIX: &str = "device_scan:";

/// Draws before `initiate` gives up finding a free user code. Each draw is an
/// atomic reservation; against 23^4 * 8^4 candidates, five is far beyond any
/// realistic number of live flows.
const USER_CODE_ATTEMPTS: usize = 5;

/// Unknown user codes one address may submit per window. Preview and approval
/// both resolve an eight-character code, so without a cap the space could be
/// walked; a human mistypes once or twice.
const MAX_UNKNOWN_CODES_BY_IP: i64 = 10;
const SCAN_WINDOW_SECS: u64 = 300;

/// Replace a flow entry only if it is still exactly what was read, keeping its
/// remaining lifetime: two approvals racing on one code cannot both win.
static COMPARE_AND_SET: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r#"
if redis.call('GET', KEYS[1]) == ARGV[1] then
    redis.call('SET', KEYS[1], ARGV[2], 'KEEPTTL')
    return 1
end
return 0
"#,
    )
});

pub use crate::domain::device::DeviceAuthStatus;

/// Stored in Redis at `device:{hash}`.
#[derive(Debug, Serialize, Deserialize)]
struct DeviceAuthState {
    user_code: String,
    status: DeviceAuthStatus,
    user_id: Option<Uuid>,
    client_id: Option<String>,
    client_ip: Option<String>,
    user_agent: Option<String>,
    created_at: i64,
    /// Scopes the client asked for (`None`: unrestricted).
    #[serde(default)]
    scopes: Option<Vec<String>>,
}

/// RFC 8628 section 3.2.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct DeviceInitResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    /// `verification_uri` with the user code, for a QR code or a link.
    pub verification_uri_complete: String,
    pub expires_in: u64,
    pub interval: u64,
}

/// What the signed-in user is shown before approving a device. Nothing here is
/// secret from the holder of the code; it is what lets them notice a code being
/// claimed by an unexpected client or from an unexpected place.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct DevicePreview {
    pub user_code: String,
    pub client_id: Option<String>,
    pub client_name: Option<String>,
    pub requested_from_ip: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: i64,
}

fn device_hash_encoded(device_code: &str) -> String {
    let hash = crypto::sha256(device_code.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
}

fn device_key(hash_encoded: &str) -> String {
    format!("{DEVICE_KEY_PREFIX}{hash_encoded}")
}

fn uc_key(user_code: &str) -> String {
    format!("{DEVICE_UC_PREFIX}{user_code}")
}

/// Generate a short, human-readable user code in the format "XXXX-XXXX".
/// Uses uppercase letters (excluding ambiguous O, I, L) and digits (excluding 0, 1).
fn generate_user_code() -> String {
    use rand::RngExt;

    const LETTERS: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ";
    const DIGITS: &[u8] = b"23456789";

    let mut rng = rand::rng();
    let part1: String = (0..4)
        .map(|_| LETTERS[rng.random_range(0..LETTERS.len())] as char)
        .collect();
    let part2: String = (0..4)
        .map(|_| DIGITS[rng.random_range(0..DIGITS.len())] as char)
        .collect();

    format!("{part1}-{part2}")
}

fn redis_error(e: impl std::fmt::Display) -> AppError {
    AppError::Internal(anyhow::anyhow!("device flow redis error: {e}"))
}

/// Reserve a free user code pointing at `hash_encoded`.
///
/// `NX` is the point: the reverse keys form a global namespace of eight
/// human-typed characters, so two live flows can draw the same code. A plain
/// `SET` would repoint the older code at the newer device, and the first user's
/// approval would mint tokens for someone else's device. Candidates come from
/// `next_code` so a test can force a collision.
pub async fn reserve_user_code(
    conn: &mut crate::utils::redis_pool::RedisConnection,
    hash_encoded: &str,
    ttl: u64,
    mut next_code: impl FnMut() -> String,
) -> Result<String, AppError> {
    for _ in 0..USER_CODE_ATTEMPTS {
        let candidate = next_code();
        let reserved: Option<String> = deadpool_redis::redis::cmd("SET")
            .arg(uc_key(&candidate))
            .arg(hash_encoded)
            .arg("NX")
            .arg("EX")
            .arg(ttl)
            .query_async(&mut **conn)
            .await
            .map_err(redis_error)?;
        if reserved.is_some() {
            return Ok(candidate);
        }
    }

    Err(AppError::Internal(anyhow::anyhow!(
        "no free device user code after {USER_CODE_ATTEMPTS} draws"
    )))
}

/// Start a device authorization for an authenticated client: every stored
/// entry records a registered client.
pub async fn initiate(
    state: &AppState,
    client_ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    client: &RegisteredClient,
    scopes: Option<Vec<String>>,
) -> Result<DeviceInitResponse, AppError> {
    let device_code = crypto::generate_token();
    let hash_encoded = device_hash_encoded(&device_code);
    let ttl = state.config.device_auth.ttl_secs;

    let mut conn = state
        .redis
        .get()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    // Claim the human code first: the entry must record the code actually won.
    let user_code = reserve_user_code(&mut conn, &hash_encoded, ttl, generate_user_code).await?;

    let entry = DeviceAuthState {
        user_code: user_code.clone(),
        status: DeviceAuthStatus::Pending,
        user_id: None,
        client_id: Some(client.client_id.clone()),
        client_ip: client_ip.map(|ip| ip.ip().to_string()),
        user_agent: user_agent.map(str::to_owned),
        created_at: state.clock.now().unix_timestamp(),
        scopes,
    };
    let entry_json = serde_json::to_string(&entry).map_err(|e| AppError::Internal(e.into()))?;

    conn.set_ex::<_, _, ()>(device_key(&hash_encoded), &entry_json, ttl)
        .await
        .map_err(redis_error)?;

    let verification_uri = state.config.device_auth.verification_uri.clone();
    let verification_uri_complete =
        crate::domain::oauth::redirect_with(&verification_uri, &[("user_code", &user_code)])
            .unwrap_or_else(|| verification_uri.clone());
    Ok(DeviceInitResponse {
        device_code,
        user_code,
        verification_uri,
        verification_uri_complete,
        expires_in: ttl,
        interval: state.config.device_auth.poll_interval_secs,
    })
}

/// Poll for the outcome of a device authorization, as the authenticated client
/// that started it.
pub async fn poll(
    state: &AppState,
    device_code: &str,
    client_id: &str,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    device_name: Option<&str>,
) -> Result<auth_svc::AuthTokens, AppError> {
    let hash_encoded = device_hash_encoded(device_code);
    let dk = device_key(&hash_encoded);

    let mut conn = state
        .redis
        .get()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    let entry_json: Option<String> = conn.get(&dk).await.map_err(redis_error)?;
    let entry: DeviceAuthState =
        serde_json::from_str(&entry_json.ok_or(AppError::DeviceCodeExpired)?)
            .map_err(|e| AppError::Internal(e.into()))?;
    // A device code works for the client it was issued to only.
    if entry.client_id.as_deref() != Some(client_id) {
        return Err(AppError::InvalidAuthorizationCode);
    }

    match poll_outcome(&entry.status, entry.user_id, entry.client_id.as_deref()) {
        PollOutcome::Pending => {
            // RFC 8628 section 3.5: polling faster than the advertised interval
            // is answered with `slow_down`.
            let interval = state.config.device_auth.poll_interval_secs.max(1);
            let paced: Option<String> = deadpool_redis::redis::cmd("SET")
                .arg(format!("{DEVICE_POLL_PREFIX}{hash_encoded}"))
                .arg(1)
                .arg("NX")
                .arg("EX")
                .arg(interval)
                .query_async(&mut *conn)
                .await
                .map_err(redis_error)?;
            if paced.is_none() {
                return Err(AppError::DeviceSlowDown);
            }
            Err(AppError::DeviceAuthPending)
        }
        PollOutcome::Denied => {
            let _: Result<(), _> = conn.del(&dk).await;
            let _: Result<(), _> = conn.del(uc_key(&entry.user_code)).await;
            Err(AppError::DeviceAccessDenied)
        }
        PollOutcome::MissingUser => Err(AppError::Internal(anyhow::anyhow!(
            "authorized device entry missing user_id"
        ))),
        // `initiate` records a registered client on every entry: one without is
        // forged or predates that guarantee, never a reason to skip checks.
        PollOutcome::MissingClient => Err(AppError::DeviceClientUnknown),
        PollOutcome::Authorized { user_id, client_id } => {
            // Re-read client, account and quota: each can change while the user
            // is approving.
            let client = client_repo::find_by_id(&state.db, client_id)
                .await
                .map_err(|e| AppError::Internal(e.into()))?
                .ok_or(AppError::DeviceClientUnknown)?;

            let user = user_repo::find_by_id(&state.db, user_id)
                .await
                .map_err(|e| AppError::Internal(e.into()))?
                .ok_or(AppError::DeviceAccessDenied)?;
            auth_svc::ensure_account_usable(&user, state.clock.now())?;

            // Held until the session exists: concurrent approvals for this user
            // and client count their sessions one at a time.
            let lock = authorize_svc::lock_client_sessions(state, user_id, client_id).await?;
            let (used, allowed) = authorize_svc::session_allowance(state, user_id, &client).await?;
            if allowed.is_some_and(|allowed| used >= allowed) {
                return Err(AppError::DeviceSessionLimitReached);
            }

            // Claim the approval: of concurrent polls, only the one whose DEL
            // removes the entry goes on to issue tokens.
            let claimed: i64 = conn.del(&dk).await.map_err(redis_error)?;
            if claimed != 1 {
                return Err(AppError::DeviceCodeExpired);
            }
            let _: Result<(), _> = conn.del(uc_key(&entry.user_code)).await;
            drop(conn);

            // The consent for a device flow is the approval itself: the session
            // carries the scopes of the request (none: unrestricted).
            let scopes = entry.scopes.as_deref();

            let tokens = auth_svc::issue_tokens(
                state,
                user_id,
                ip,
                user_agent,
                device_name,
                false, // device sessions are never "remember me"
                SessionType::Device,
                Some(client_id),
                scopes,
                None,
            )
            .await?;
            lock.commit()
                .await
                .map_err(|e| AppError::Internal(e.into()))?;

            Ok(tokens)
        }
    }
}

/// Refuse an address that has been asking after codes that do not exist.
async fn guard_code_scan(state: &AppState, ip: Option<IpNetwork>) -> Result<(), AppError> {
    let Some(ip) = ip else { return Ok(()) };
    let key = format!("{DEVICE_SCAN_PREFIX}{}", ip_bucket(ip.ip()));
    if redis_counter::peek(&state.redis, &key).await? >= MAX_UNKNOWN_CODES_BY_IP {
        return Err(AppError::RateLimitExceeded);
    }
    Ok(())
}

/// Count a lookup of a code that is not live. Only misses are counted: a
/// legitimate approval resolves on the first try.
async fn note_unknown_code(state: &AppState, ip: Option<IpNetwork>) {
    let Some(ip) = ip else { return };
    let key = format!("{DEVICE_SCAN_PREFIX}{}", ip_bucket(ip.ip()));
    let budget = Budget {
        key: &key,
        limit: MAX_UNKNOWN_CODES_BY_IP,
        window_secs: SCAN_WINDOW_SECS,
    };
    if let Err(e) = redis_counter::consume(&state.redis, &[budget]).await {
        tracing::warn!(error = %e, "could not record an unknown device code lookup");
    }
}

/// Load the live entry a user code points at: `(device key, raw json, entry)`.
async fn load_entry(
    state: &AppState,
    user_code: &str,
) -> Result<Option<(String, String, DeviceAuthState)>, AppError> {
    let mut conn = state
        .redis
        .get()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    let hash_encoded: Option<String> = conn.get(uc_key(user_code)).await.map_err(redis_error)?;
    let Some(hash_encoded) = hash_encoded else {
        return Ok(None);
    };

    let dk = device_key(&hash_encoded);
    let raw: Option<String> = conn.get(&dk).await.map_err(redis_error)?;
    let Some(raw) = raw else {
        return Ok(None);
    };

    let entry = serde_json::from_str(&raw).map_err(|e| AppError::Internal(e.into()))?;
    Ok(Some((dk, raw, entry)))
}

/// Describe a pending device authorization to the user about to decide on it.
pub async fn describe(
    state: &AppState,
    user_code: &str,
    ip: Option<IpNetwork>,
) -> Result<DevicePreview, AppError> {
    guard_code_scan(state, ip).await?;

    let Some((_, _, entry)) = load_entry(state, user_code).await? else {
        note_unknown_code(state, ip).await;
        return Err(AppError::NotFound);
    };
    if !entry.status.is_undecided() {
        return Err(AppError::Conflict("device_request_already_decided"));
    }

    let client_name = match entry.client_id.as_deref() {
        Some(cid) => client_repo::find_by_id(&state.db, cid)
            .await
            .map_err(|e| AppError::Internal(e.into()))?
            .map(|client| client.display_name),
        None => None,
    };

    Ok(DevicePreview {
        user_code: entry.user_code,
        client_id: entry.client_id,
        client_name,
        requested_from_ip: entry.client_ip,
        user_agent: entry.user_agent,
        created_at: entry.created_at,
    })
}

/// Approve a device authorization request. Called by an authenticated user.
pub async fn verify(
    state: &AppState,
    user_id: Uuid,
    user_code: &str,
    ip: Option<IpNetwork>,
) -> Result<(), AppError> {
    update_status(
        state,
        user_code,
        DeviceAuthStatus::Authorized,
        Some(user_id),
        ip,
    )
    .await
}

/// Deny a device authorization request. Called by an authenticated user.
///
/// RFC 8628 gives a pending request no owner: what stops a stranger cancelling
/// other people's flows is that they cannot find the codes (`guard_code_scan`).
pub async fn deny(
    state: &AppState,
    user_code: &str,
    ip: Option<IpNetwork>,
) -> Result<(), AppError> {
    update_status(state, user_code, DeviceAuthStatus::Denied, None, ip).await
}

async fn update_status(
    state: &AppState,
    user_code: &str,
    new_status: DeviceAuthStatus,
    user_id: Option<Uuid>,
    ip: Option<IpNetwork>,
) -> Result<(), AppError> {
    guard_code_scan(state, ip).await?;

    let Some((dk, raw, mut entry)) = load_entry(state, user_code).await? else {
        note_unknown_code(state, ip).await;
        return Err(AppError::NotFound);
    };
    if !entry.status.is_undecided() {
        return Err(AppError::Conflict("device_request_already_decided"));
    }

    entry.status = new_status;
    entry.user_id = user_id;
    let updated = serde_json::to_string(&entry).map_err(|e| AppError::Internal(e.into()))?;

    let mut conn = state
        .redis
        .get()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    let swapped: i64 = COMPARE_AND_SET
        .key(&dk)
        .arg(&raw)
        .arg(&updated)
        .invoke_async(&mut *conn)
        .await
        .map_err(redis_error)?;

    if swapped != 1 {
        return Err(AppError::Conflict("device_request_already_decided"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_code_has_correct_format() {
        for _ in 0..100 {
            let code = generate_user_code();
            let parts: Vec<&str> = code.split('-').collect();
            assert_eq!(parts.len(), 2);
            assert_eq!(parts[0].len(), 4);
            assert_eq!(parts[1].len(), 4);
            assert!(parts[0].chars().all(|c| c.is_ascii_uppercase()));
            assert!(parts[1].chars().all(|c| c.is_ascii_digit()));
            assert!(!parts[0].contains('O'));
            assert!(!parts[0].contains('I'));
            assert!(!parts[0].contains('L'));
            assert!(!parts[1].contains('0'));
            assert!(!parts[1].contains('1'));
        }
    }

    #[test]
    fn device_key_is_deterministic_and_distinct() {
        assert_eq!(
            device_key(&device_hash_encoded("test-code")),
            device_key(&device_hash_encoded("test-code"))
        );
        assert_ne!(device_hash_encoded("code-a"), device_hash_encoded("code-b"));
    }

    #[test]
    fn device_auth_state_serialization_roundtrip() {
        let state = DeviceAuthState {
            user_code: "ABCD-2345".into(),
            status: DeviceAuthStatus::Pending,
            user_id: None,
            client_id: Some("app_a".into()),
            client_ip: Some("192.168.1.1".into()),
            user_agent: Some("MyApp/1.0".into()),
            created_at: 1700000000,
            scopes: None,
        };

        let json = serde_json::to_string(&state).unwrap();
        let recovered: DeviceAuthState = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.user_code, "ABCD-2345");
        assert_eq!(recovered.status, DeviceAuthStatus::Pending);
        assert!(recovered.user_id.is_none());
    }
}
