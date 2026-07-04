//! Device Authorization Flow service (RFC 8628).
//!
//! Manages the lifecycle of device authorization requests using Redis
//! for ephemeral storage. Desktop apps initiate the flow, users approve
//! via the browser, and the desktop app polls until tokens are available.
//!
//! Redis keys:
//! - `device:{base64url(sha256(device_code))}` -> JSON DeviceAuthState (TTL)
//! - `device_uc:{user_code}` -> base64url(sha256(device_code)) reverse lookup (TTL)

use base64::Engine;
use deadpool_redis::redis::AsyncCommands;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    domain::session::SessionType,
    error::AppError,
    repositories::{
        client_quota as quota_repo, registered_client as client_repo, session as session_repo,
    },
    services::auth as auth_svc,
    state::AppState,
    utils::crypto,
};

// Constants

const DEVICE_KEY_PREFIX: &str = "device:";
const DEVICE_UC_PREFIX: &str = "device_uc:";

// Types

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceAuthStatus {
    Pending,
    Authorized,
    Denied,
}

/// Stored in Redis at key `device:{hash}`.
#[derive(Debug, Serialize, Deserialize)]
struct DeviceAuthState {
    user_code: String,
    status: DeviceAuthStatus,
    user_id: Option<Uuid>,
    client_id: Option<String>,
    client_ip: Option<String>,
    user_agent: Option<String>,
    created_at: i64,
}

// Response types

#[derive(Debug, Serialize)]
pub struct DeviceInitResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: u64,
    pub interval: u64,
}

#[derive(Debug, Serialize)]
pub struct DevicePollResult {
    pub access_token: String,
    pub refresh_token: String,
}

// Helpers

fn device_key(device_code: &str) -> String {
    let hash = crypto::sha256(device_code.as_bytes());
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash);
    format!("{DEVICE_KEY_PREFIX}{encoded}")
}

fn device_hash_encoded(device_code: &str) -> String {
    let hash = crypto::sha256(device_code.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
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

// Public API

/// Start a new device authorization request.
/// Returns the device code (secret, for polling) and user code (for the browser).
pub async fn initiate(
    state: &AppState,
    client_ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    client_id: Option<&str>,
) -> Result<DeviceInitResponse, AppError> {
    let device_code = crypto::generate_token();
    let hash_encoded = device_hash_encoded(&device_code);
    let user_code = generate_user_code();
    let ttl = state.config.device_auth.ttl_secs;

    let entry = DeviceAuthState {
        user_code: user_code.clone(),
        status: DeviceAuthStatus::Pending,
        user_id: None,
        client_id: client_id.map(str::to_owned),
        client_ip: client_ip.map(|ip| ip.ip().to_string()),
        user_agent: user_agent.map(str::to_owned),
        created_at: crate::utils::time::now().unix_timestamp(),
    };

    let entry_json =
        serde_json::to_string(&entry).map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?;

    let mut conn = state
        .redis
        .get()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    // Store device entry keyed by hashed device_code
    let dk = format!("{DEVICE_KEY_PREFIX}{hash_encoded}");
    conn.set_ex::<_, _, ()>(&dk, &entry_json, ttl)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?;

    // Store reverse lookup: user_code -> hash (for the verify step)
    let uk = uc_key(&user_code);
    conn.set_ex::<_, _, ()>(&uk, &hash_encoded, ttl)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?;

    Ok(DeviceInitResponse {
        device_code,
        user_code,
        verification_uri: state.config.device_auth.verification_uri.clone(),
        expires_in: ttl,
        interval: state.config.device_auth.poll_interval_secs,
    })
}

/// Poll for the result of a device authorization request.
/// Returns tokens if approved, or an appropriate error if pending/denied/expired.
pub async fn poll(
    state: &AppState,
    device_code: &str,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    device_name: Option<&str>,
) -> Result<DevicePollResult, AppError> {
    let dk = device_key(device_code);

    let mut conn = state
        .redis
        .get()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    let entry_json: Option<String> = conn
        .get(&dk)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?;

    let entry_json = entry_json.ok_or(AppError::DeviceCodeExpired)?;

    let entry: DeviceAuthState =
        serde_json::from_str(&entry_json).map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?;

    match entry.status {
        DeviceAuthStatus::Pending => Err(AppError::DeviceAuthPending),
        DeviceAuthStatus::Denied => {
            // Clean up both keys after denial is acknowledged
            let uk = uc_key(&entry.user_code);
            let _: Result<(), _> = conn.del(&dk).await;
            let _: Result<(), _> = conn.del(&uk).await;
            Err(AppError::DeviceAccessDenied)
        }
        DeviceAuthStatus::Authorized => {
            let user_id = entry.user_id.ok_or_else(|| {
                AppError::Internal(anyhow::anyhow!("authorized device entry missing user_id"))
            })?;

            // Validate client and enforce session quota
            if let Some(cid) = entry.client_id.as_deref() {
                // Verify the client is registered
                let client = client_repo::find_by_id(&state.db, cid)
                    .await
                    .map_err(|e| AppError::Internal(e.into()))?
                    .ok_or(AppError::DeviceClientUnknown)?;

                // External clients require a per-user quota
                if !client.is_primary {
                    let quota = quota_repo::find_by_user_and_client(&state.db, user_id, cid)
                        .await
                        .map_err(|e| AppError::Internal(e.into()))?
                        .ok_or(AppError::DeviceClientNotAllowed)?;

                    let active_sessions =
                        session_repo::count_active_by_client(&state.db, user_id, cid)
                            .await
                            .map_err(|e| AppError::Internal(e.into()))?;

                    if active_sessions >= quota.max_sessions as i64 {
                        return Err(AppError::DeviceSessionLimitReached);
                    }
                }
            }

            // Clean up both keys
            let uk = uc_key(&entry.user_code);
            let _: Result<(), _> = conn.del(&dk).await;
            let _: Result<(), _> = conn.del(&uk).await;

            // Issue tokens for the authorized user
            let tokens = auth_svc::issue_tokens(
                state,
                user_id,
                ip,
                user_agent,
                device_name,
                false, // device auth sessions are not "remember me"
                SessionType::Device,
                entry.client_id.as_deref(),
            )
            .await?;

            Ok(DevicePollResult {
                access_token: tokens.access_token,
                refresh_token: tokens.refresh_token,
            })
        }
    }
}

/// Approve a device authorization request. Called by an authenticated user.
pub async fn verify(state: &AppState, user_id: Uuid, user_code: &str) -> Result<(), AppError> {
    update_status(
        state,
        user_code,
        DeviceAuthStatus::Authorized,
        Some(user_id),
    )
    .await
}

/// Deny a device authorization request. Called by an authenticated user.
pub async fn deny(state: &AppState, user_code: &str) -> Result<(), AppError> {
    update_status(state, user_code, DeviceAuthStatus::Denied, None).await
}

/// Update the status of a device authorization request looked up by user_code.
async fn update_status(
    state: &AppState,
    user_code: &str,
    new_status: DeviceAuthStatus,
    user_id: Option<Uuid>,
) -> Result<(), AppError> {
    let mut conn = state
        .redis
        .get()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    // Reverse lookup: user_code -> device hash
    let uk = uc_key(user_code);
    let hash_encoded: Option<String> = conn
        .get(&uk)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?;

    let hash_encoded = hash_encoded.ok_or(AppError::NotFound)?;

    let dk = format!("{DEVICE_KEY_PREFIX}{hash_encoded}");
    let entry_json: Option<String> = conn
        .get(&dk)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?;

    let entry_json = entry_json.ok_or(AppError::NotFound)?;

    let mut entry: DeviceAuthState =
        serde_json::from_str(&entry_json).map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?;

    if entry.status != DeviceAuthStatus::Pending {
        return Err(AppError::Conflict("device_code"));
    }

    entry.status = new_status;
    entry.user_id = user_id;

    let updated_json =
        serde_json::to_string(&entry).map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?;

    // Preserve the remaining TTL
    let ttl: i64 = deadpool_redis::redis::cmd("TTL")
        .arg(&dk)
        .query_async(&mut conn)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?;

    if ttl <= 0 {
        return Err(AppError::NotFound);
    }

    conn.set_ex::<_, _, ()>(&dk, &updated_json, ttl as u64)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?;

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
            // No ambiguous characters
            assert!(!parts[0].contains('O'));
            assert!(!parts[0].contains('I'));
            assert!(!parts[0].contains('L'));
            assert!(!parts[1].contains('0'));
            assert!(!parts[1].contains('1'));
        }
    }

    #[test]
    fn device_key_is_deterministic() {
        let a = device_key("test-code");
        let b = device_key("test-code");
        assert_eq!(a, b);
    }

    #[test]
    fn device_key_differs_for_different_codes() {
        assert_ne!(device_key("code-a"), device_key("code-b"));
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
        };

        let json = serde_json::to_string(&state).unwrap();
        let recovered: DeviceAuthState = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.user_code, "ABCD-2345");
        assert_eq!(recovered.status, DeviceAuthStatus::Pending);
        assert!(recovered.user_id.is_none());
    }

    #[test]
    fn device_auth_state_authorized_with_user_id() {
        let state = DeviceAuthState {
            user_code: "WXYZ-6789".into(),
            status: DeviceAuthStatus::Authorized,
            user_id: Some(Uuid::new_v4()),
            client_id: None,
            client_ip: None,
            user_agent: None,
            created_at: 1700000000,
        };

        let json = serde_json::to_string(&state).unwrap();
        let recovered: DeviceAuthState = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.status, DeviceAuthStatus::Authorized);
        assert!(recovered.user_id.is_some());
    }
}
