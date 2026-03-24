//! WebAuthn/passkey service: register and authenticate hardware security keys as a 2FA method.
//!
//! Flow:
//! Registration (protected, user already logged in):
//!   1. POST /users/me/two-factor/webauthn/register/start  -> CreationChallengeResponse
//!   2. POST /users/me/two-factor/webauthn/register/finish -> stores Passkey in DB
//!
//! Authentication (public, during 2FA challenge after password):
//!   1. POST /auth/two-factor/webauthn/start  (pre_auth_token) -> RequestChallengeResponse
//!   2. POST /auth/two-factor/webauthn/finish (pre_auth_token + PublicKeyCredential) -> tokens

use deadpool_redis::redis::AsyncCommands;
use ipnetwork::IpNetwork;
use serde_json::json;
use uuid::Uuid;
use webauthn_rs::prelude::{
    AuthenticationResult, CreationChallengeResponse, Passkey, PasskeyAuthentication,
    PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};

use crate::{
    domain::{audit::AuditAction, two_factor::TwoFactorType},
    error::AppError,
    repositories::{
        audit::{self, NewAuditEntry},
        two_factor as tf_repo, user as user_repo,
    },
    state::AppState,
};

// Redis key prefixes for pending WebAuthn state
const WA_REG_PREFIX: &str = "wa_reg:";
const WA_AUTH_PREFIX: &str = "wa_auth:";
// TTL for pending challenges
const WA_CHALLENGE_TTL_SECS: u64 = 300;
const MAX_WEBAUTHN_KEYS: usize = 10;

// Registration

/// Start passkey registration: generate a challenge and store the pending state in Redis.
/// Returns the JSON challenge to send to the browser.
pub async fn start_registration(
    state: &AppState,
    user_id: Uuid,
    username: &str,
) -> Result<CreationChallengeResponse, AppError> {
    // Collect already-registered credential IDs to exclude duplicates.
    let existing = tf_repo::find_all_by_type(&state.db, user_id, TwoFactorType::Webauthn)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    if existing.len() >= MAX_WEBAUTHN_KEYS {
        return Err(AppError::Conflict("max_webauthn_keys_reached"));
    }

    let exclude_creds = existing
        .iter()
        .filter_map(|m| m.webauthn_credential_id.as_deref())
        .filter_map(base64_to_credential_id)
        .collect::<Vec<_>>();

    let exclude = if exclude_creds.is_empty() {
        None
    } else {
        Some(exclude_creds)
    };

    let (ccr, reg_state) = state
        .webauthn
        .start_passkey_registration(user_id, username, username, exclude)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("webauthn start_registration: {e}")))?;

    // Persist the registration state so we can verify it in finish_registration.
    let key = format!("{}{}", WA_REG_PREFIX, user_id);
    let serialized = serde_json::to_string(&reg_state).map_err(|e| AppError::Internal(e.into()))?;

    let mut conn = state
        .redis
        .get()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    conn.set_ex::<_, _, ()>(&key, serialized, WA_CHALLENGE_TTL_SECS)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("redis set_ex: {e}")))?;

    Ok(ccr)
}

/// Complete passkey registration: verify the browser response and store the credential.
pub async fn finish_registration(
    state: &AppState,
    user_id: Uuid,
    response: &RegisterPublicKeyCredential,
    request_id: Option<Uuid>,
) -> Result<(), AppError> {
    let key = format!("{}{}", WA_REG_PREFIX, user_id);

    let mut conn = state
        .redis
        .get()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    let serialized: Option<String> = conn
        .get(&key)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("redis get: {e}")))?;
    let serialized = serialized.ok_or(AppError::TokenInvalid)?;

    let _: Result<(), _> = conn.del(&key).await;
    drop(conn);

    let reg_state: PasskeyRegistration =
        serde_json::from_str(&serialized).map_err(|_| AppError::TokenInvalid)?;

    let passkey: Passkey = state
        .webauthn
        .finish_passkey_registration(response, &reg_state)
        .map_err(|e| {
            tracing::warn!(error = ?e, user_id = %user_id, "webauthn registration failed");
            AppError::TwoFactorFailed
        })?;

    // Serialize and store the passkey (credential_id + public_key + sign_count).
    let cred_id = credential_id_to_base64(passkey.cred_id());
    let passkey_json = serde_json::to_string(&passkey).map_err(|e| AppError::Internal(e.into()))?;

    let method = tf_repo::create(
        &state.db,
        &tf_repo::NewTwoFactorMethod {
            user_id,
            method_type: TwoFactorType::Webauthn,
            totp_secret: None,
            webauthn_credential_id: Some(&cred_id),
            webauthn_public_key: Some(&passkey_json),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    tf_repo::mark_verified(&state.db, method.id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    // Set as primary if this is the first verified 2FA method.
    let has_primary = tf_repo::find_primary_by_user(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .is_some();

    if !has_primary {
        tf_repo::set_primary(&state.db, method.id, user_id)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
    }

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user_id),
            request_id,
            action: AuditAction::TwoFactorEnabled,
            ip_address: None,
            metadata: json!({"method": "webauthn"}),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    Ok(())
}

// Disable

/// Removes a specific WebAuthn credential. Requires the user's current password.
/// Recovery codes are removed only if this was the last 2FA method.
pub async fn disable(
    state: &AppState,
    user_id: Uuid,
    current_session_id: Uuid,
    method_id: Uuid,
    current_password: Option<&str>,
    ip: Option<IpNetwork>,
    request_id: Option<Uuid>,
) -> Result<(), AppError> {
    super::reauth::require_recent_reauth_or_password(
        state,
        user_id,
        current_session_id,
        current_password,
        ip,
        request_id,
        "disable_webauthn",
    )
    .await?;

    let user = user_repo::find_by_id(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::NotFound)?;

    crate::repositories::two_factor::delete(&state.db, method_id, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    // Remove recovery codes only if no other 2FA method remains active.
    let remaining = crate::repositories::two_factor::find_by_user(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    if remaining.is_empty() {
        crate::repositories::recovery_code::delete_all_by_user(&state.db, user_id)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
    }

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user_id),
            request_id,
            action: AuditAction::TwoFactorDisabled,
            ip_address: ip,
            metadata: json!({"method": "webauthn", "method_id": method_id}),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    let mailer = state.mailer.clone();
    let templates = state.templates.clone();
    let mail_cfg = state.config.mail.clone();
    let email_to = user.email.clone();
    let username = user.username.clone();
    let locale = user.preferred_locale.clone();
    super::email::dispatch_best_effort("webauthn_disabled_email", async move {
        super::email::send_two_factor_disabled(
            &mailer,
            templates.as_ref(),
            &mail_cfg,
            &email_to,
            &username,
            &locale,
            "webauthn",
        )
        .await
    });

    Ok(())
}

// Authentication

/// Start passkey authentication for 2FA: generate a challenge keyed to the pre_auth_token.
/// All registered passkeys for the user are included so any of them can satisfy the challenge.
pub async fn start_authentication(
    state: &AppState,
    pre_auth_token: &str,
    user_id: Uuid,
) -> Result<RequestChallengeResponse, AppError> {
    // Load all registered WebAuthn credentials for this user.
    let methods = tf_repo::find_all_by_type(&state.db, user_id, TwoFactorType::Webauthn)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    if methods.is_empty() {
        return Err(AppError::Unauthorized);
    }

    let passkeys: Vec<Passkey> = methods.iter().map(load_passkey).collect::<Result<_, _>>()?;

    let (rcr, auth_state) = state
        .webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("webauthn start_authentication: {e}")))?;

    let key = format!("{}{}", WA_AUTH_PREFIX, pre_auth_token);
    let serialized =
        serde_json::to_string(&auth_state).map_err(|e| AppError::Internal(e.into()))?;

    let mut conn = state
        .redis
        .get()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    conn.set_ex::<_, _, ()>(&key, serialized, WA_CHALLENGE_TTL_SECS)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("redis set_ex: {e}")))?;

    Ok(rcr)
}

/// Complete passkey authentication: verify the browser response and update the sign counter.
/// Returns the `AuthenticationResult` so the caller can update the stored sign count.
pub async fn finish_authentication(
    state: &AppState,
    pre_auth_token: &str,
    user_id: Uuid,
    response: &PublicKeyCredential,
) -> Result<AuthenticationResult, AppError> {
    let auth_key = format!("{}{}", WA_AUTH_PREFIX, pre_auth_token);

    let mut conn = state
        .redis
        .get()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    let serialized: Option<String> = conn
        .get(&auth_key)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("redis get: {e}")))?;
    let serialized = serialized.ok_or(AppError::TokenInvalid)?;
    let _: Result<(), _> = conn.del(&auth_key).await;
    drop(conn);

    let auth_state: PasskeyAuthentication =
        serde_json::from_str(&serialized).map_err(|_| AppError::TokenInvalid)?;

    let auth_result = state
        .webauthn
        .finish_passkey_authentication(response, &auth_state)
        .map_err(|e| {
            tracing::warn!(error = ?e, user_id = %user_id, "webauthn authentication failed");
            AppError::TwoFactorFailed
        })?;

    // Identify which credential was used and validate + update its sign counter.
    let used_cred_id = credential_id_to_base64(auth_result.cred_id());

    let methods = tf_repo::find_all_by_type(&state.db, user_id, TwoFactorType::Webauthn)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    let matched = methods
        .iter()
        .find(|m| m.webauthn_credential_id.as_deref() == Some(&used_cred_id))
        .ok_or(AppError::Unauthorized)?;

    // Sign counter must be strictly increasing (counter = 0 means the authenticator
    // does not implement counters — skip the check only in that case).
    let new_count = auth_result.counter() as i64;
    if new_count != 0 && new_count <= matched.webauthn_sign_count {
        tracing::warn!(
            user_id = %user_id,
            credential_id = %used_cred_id,
            stored_count = matched.webauthn_sign_count,
            presented_count = new_count,
            "webauthn sign counter did not increase — possible cloned authenticator"
        );
        return Err(AppError::TwoFactorFailed);
    }

    tf_repo::update_webauthn_sign_count(&state.db, matched.id, new_count)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    Ok(auth_result)
}

// Helpers

fn load_passkey(method: &crate::domain::two_factor::TwoFactorMethod) -> Result<Passkey, AppError> {
    let json = method
        .webauthn_public_key
        .as_deref()
        .ok_or(AppError::Unauthorized)?;

    serde_json::from_str::<Passkey>(json)
        .map_err(|_| AppError::Internal(anyhow::anyhow!("corrupted webauthn_public_key")))
}

fn credential_id_to_base64(id: &webauthn_rs::prelude::CredentialID) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(id.as_ref())
}

fn base64_to_credential_id(s: &str) -> Option<webauthn_rs::prelude::CredentialID> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .ok()?;
    Some(webauthn_rs::prelude::CredentialID::from(bytes))
}
