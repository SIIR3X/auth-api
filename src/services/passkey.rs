//! Passkeys: registering them on an account, and signing in with them.
//!
//! A passkey sign-in proves possession of the device and user verification on
//! it (biometrics or PIN): two factors, so no second-factor challenge follows.
//! Challenges live in Redis for five minutes and are used once.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use deadpool_redis::redis::AsyncCommands;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    domain::{audit::AuditAction, session::SessionType, webauthn},
    error::AppError,
    middleware::rate_limit::ip_bucket,
    repositories::{
        audit::{self, NewAuditEntry},
        passkey::{self as passkey_repo, NewPasskey, Passkey},
        recovery_code, user as user_repo,
    },
    services::{
        auth::{self as auth_svc, AuthTokens},
        reauth as reauth_svc, two_factor as two_factor_svc,
    },
    state::AppState,
    utils::{
        crypto,
        redis_counter::{self, Budget},
    },
};

const CHALLENGE_TTL_SECS: u64 = 300;
const REGISTRATION_PREFIX: &str = "passkey_reg:";
const AUTHENTICATION_PREFIX: &str = "passkey_auth:";
/// Failed passkey sign-ins per client address (IPv6 /64) per window.
const MAX_FAILURES_BY_IP: i64 = 20;
const FAILURE_WINDOW_SECS: u64 = 900;
/// Passkeys per account.
const MAX_PASSKEYS: usize = 20;

/// A credential as the browser returns it (`PublicKeyCredential.toJSON()`).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CredentialResponse<R> {
    /// base64url credential id.
    #[serde(rename = "rawId")]
    pub raw_id: String,
    pub response: R,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct AttestationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct AssertionResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    pub signature: String,
    #[serde(rename = "userHandle")]
    pub user_handle: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct PendingRegistration {
    challenge: Vec<u8>,
    user_id: Uuid,
}

fn decode(field: &'static str, value: &str) -> Result<Vec<u8>, AppError> {
    B64URL
        .decode(value.trim_end_matches('='))
        .map_err(|_| AppError::Validation(format!("{field} is not base64url")))
}

fn redis_error(e: impl std::fmt::Display) -> AppError {
    AppError::Internal(anyhow::anyhow!("passkey redis error: {e}"))
}

// Registration

/// `PublicKeyCredentialCreationOptions` for a new passkey of the account.
pub async fn registration_options(
    state: &AppState,
    user_id: Uuid,
    session_id: Uuid,
    ip: Option<IpNetwork>,
    request_id: Option<Uuid>,
) -> Result<Value, AppError> {
    reauth_svc::require_recent_reauth_or_password(
        state,
        user_id,
        session_id,
        None,
        ip,
        request_id,
        "register_passkey",
    )
    .await?;
    let user = user_repo::find_by_id(&state.db, user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let existing = passkey_repo::find_by_user(&state.db, user_id).await?;
    if existing.len() >= MAX_PASSKEYS {
        return Err(AppError::Conflict("too_many_passkeys"));
    }

    let challenge = crypto::random_bytes::<32>().to_vec();
    let pending = serde_json::to_string(&PendingRegistration {
        challenge: challenge.clone(),
        user_id,
    })
    .map_err(|e| AppError::Internal(e.into()))?;
    let mut conn = state.redis.get().await.map_err(redis_error)?;
    conn.set_ex::<_, _, ()>(
        format!("{REGISTRATION_PREFIX}{session_id}"),
        pending,
        CHALLENGE_TTL_SECS,
    )
    .await
    .map_err(redis_error)?;

    let config = &state.config.webauthn;
    Ok(json!({
        "challenge": B64URL.encode(&challenge),
        "rp": { "id": config.rp_id, "name": config.rp_name },
        "user": {
            "id": B64URL.encode(user.id.as_bytes()),
            "name": user.username,
            "displayName": user.username,
        },
        "pubKeyCredParams": webauthn::ALGORITHMS
            .iter()
            .map(|alg| json!({ "type": "public-key", "alg": alg }))
            .collect::<Vec<_>>(),
        "timeout": CHALLENGE_TTL_SECS * 1000,
        "attestation": "none",
        "authenticatorSelection": {
            "residentKey": "required",
            "requireResidentKey": true,
            "userVerification": "required",
        },
        "excludeCredentials": existing
            .iter()
            .map(|p| json!({ "type": "public-key", "id": B64URL.encode(&p.credential_id) }))
            .collect::<Vec<_>>(),
    }))
}

pub struct Registered {
    pub passkey: Passkey,
    /// Recovery codes, when the account had none left: a passkey can be lost.
    pub recovery_codes: Option<Vec<String>>,
}

/// Verify a registration response and store the passkey.
pub async fn register(
    state: &AppState,
    user_id: Uuid,
    session_id: Uuid,
    name: &str,
    credential: &CredentialResponse<AttestationResponse>,
    ip: Option<IpNetwork>,
    request_id: Option<Uuid>,
) -> Result<Registered, AppError> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 100 {
        return Err(AppError::Validation(
            "name must be 1 to 100 characters".into(),
        ));
    }
    let mut conn = state.redis.get().await.map_err(redis_error)?;
    let pending: Option<String> = conn
        .get_del(format!("{REGISTRATION_PREFIX}{session_id}"))
        .await
        .map_err(redis_error)?;
    drop(conn);
    let pending: PendingRegistration = serde_json::from_str(
        &pending
            .ok_or_else(|| AppError::Validation("no passkey registration is pending".into()))?,
    )
    .map_err(|e| AppError::Internal(e.into()))?;
    if pending.user_id != user_id {
        return Err(AppError::Forbidden);
    }

    let invalid =
        |e: webauthn::WebAuthnError| AppError::Validation(format!("invalid passkey: {}", e.0));
    let config = &state.config.webauthn;
    let client_data = decode("clientDataJSON", &credential.response.client_data_json)?;
    webauthn::check_client_data(
        &client_data,
        "webauthn.create",
        &pending.challenge,
        &config.origins,
    )
    .map_err(invalid)?;
    let auth_data = webauthn::attestation_auth_data(&decode(
        "attestationObject",
        &credential.response.attestation_object,
    )?)
    .map_err(invalid)?;
    let parsed = webauthn::parse_authenticator_data(&auth_data).map_err(invalid)?;
    parsed.check(&config.rp_id).map_err(invalid)?;
    let attested = parsed
        .attested
        .as_ref()
        .ok_or_else(|| AppError::Validation("invalid passkey: no credential".into()))?;
    if attested.credential_id != decode("rawId", &credential.raw_id)? {
        return Err(AppError::Validation(
            "invalid passkey: credential id mismatch".into(),
        ));
    }
    let key = webauthn::parse_cose_key(&attested.public_key).map_err(invalid)?;

    let passkey = passkey_repo::create(
        &state.db,
        &NewPasskey {
            user_id,
            credential_id: &attested.credential_id,
            public_key: &attested.public_key,
            algorithm: key.algorithm(),
            sign_count: parsed.sign_count,
            aaguid: Uuid::from_bytes(attested.aaguid),
            name,
            backup_eligible: parsed.backup_eligible(),
            backed_up: parsed.backed_up(),
        },
    )
    .await?
    .ok_or(AppError::Conflict("passkey_already_registered"))?;

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user_id),
            request_id,
            action: AuditAction::PasskeyRegistered,
            ip_address: ip,
            metadata: json!({ "passkey_id": passkey.id }),
        },
    )
    .await?;

    let recovery_codes = if recovery_code::count_usable_by_user(&state.db, user_id).await? == 0 {
        Some(two_factor_svc::create_recovery_codes_internal(state, user_id).await?)
    } else {
        None
    };
    Ok(Registered {
        passkey,
        recovery_codes,
    })
}

pub async fn list(state: &AppState, user_id: Uuid) -> Result<Vec<Passkey>, AppError> {
    Ok(passkey_repo::find_by_user(&state.db, user_id).await?)
}

pub async fn remove(
    state: &AppState,
    user_id: Uuid,
    session_id: Uuid,
    id: Uuid,
    current_password: Option<&str>,
    ip: Option<IpNetwork>,
    request_id: Option<Uuid>,
) -> Result<(), AppError> {
    reauth_svc::require_recent_reauth_or_password(
        state,
        user_id,
        session_id,
        current_password,
        ip,
        request_id,
        "remove_passkey",
    )
    .await?;
    if !passkey_repo::delete_owned(&state.db, id, user_id).await? {
        return Err(AppError::NotFound);
    }
    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user_id),
            request_id,
            action: AuditAction::PasskeyRemoved,
            ip_address: ip,
            metadata: json!({ "passkey_id": id }),
        },
    )
    .await?;
    Ok(())
}

// Sign-in

/// `PublicKeyCredentialRequestOptions` for a sign-in with any passkey of this
/// relying party: the browser offers the user's passkeys, no identifier needed.
pub async fn authentication_options(state: &AppState) -> Result<Value, AppError> {
    let challenge = crypto::random_bytes::<32>();
    let mut conn = state.redis.get().await.map_err(redis_error)?;
    conn.set_ex::<_, _, ()>(authentication_key(&challenge), 1u8, CHALLENGE_TTL_SECS)
        .await
        .map_err(redis_error)?;
    Ok(json!({
        "challenge": B64URL.encode(challenge),
        "rpId": state.config.webauthn.rp_id,
        "timeout": CHALLENGE_TTL_SECS * 1000,
        "userVerification": "required",
        "allowCredentials": [],
    }))
}

fn authentication_key(challenge: &[u8]) -> String {
    let digest = crypto::sha256(challenge);
    format!(
        "{AUTHENTICATION_PREFIX}{}",
        digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}

/// Sign in with a passkey assertion. Every refusal is the same
/// `invalid_credentials`, and counts against the address.
pub async fn sign_in(
    state: &AppState,
    credential: &CredentialResponse<AssertionResponse>,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    device_name: Option<&str>,
    remember_me: bool,
    request_id: Option<Uuid>,
) -> Result<AuthTokens, AppError> {
    let failure_key = ip.map(|ip| format!("passkey_fail:{}", ip_bucket(ip.ip())));
    if let Some(key) = failure_key.as_deref()
        && redis_counter::peek(&state.redis, key).await? >= MAX_FAILURES_BY_IP
    {
        return Err(AppError::RateLimitExceeded);
    }

    match verify_assertion(state, credential).await {
        Ok((passkey, user)) => {
            auth_svc::ensure_account_usable(&user, state.clock.now())?;
            auth_svc::issue_tokens(
                state,
                user.id,
                ip,
                user_agent,
                device_name,
                remember_me,
                SessionType::Web,
                None,
                None,
                Some(auth_svc::SignIn {
                    identifier: Some(&user.username),
                    request_id,
                    audit_metadata: json!({ "method": "passkey", "passkey_id": passkey.id }),
                }),
            )
            .await
        }
        Err(error) => {
            if let Some(key) = failure_key.as_deref() {
                let budget = Budget {
                    key,
                    limit: MAX_FAILURES_BY_IP,
                    window_secs: FAILURE_WINDOW_SECS,
                };
                if let Err(e) = redis_counter::consume(&state.redis, &[budget]).await {
                    tracing::warn!(error = %e, "could not count a failed passkey sign-in");
                }
            }
            Err(error)
        }
    }
}

async fn verify_assertion(
    state: &AppState,
    credential: &CredentialResponse<AssertionResponse>,
) -> Result<(Passkey, crate::domain::user::User), AppError> {
    let refused = |reason: &str| {
        tracing::info!(reason, "passkey sign-in refused");
        AppError::InvalidCredentials
    };
    let decode = |value: &str| {
        B64URL
            .decode(value.trim_end_matches('='))
            .map_err(|_| refused("encoding"))
    };
    let config = &state.config.webauthn;
    let client_data = decode(&credential.response.client_data_json)?;
    let challenge = webauthn::challenge_of(&client_data).map_err(|e| refused(e.0))?;

    // The challenge is used up whatever follows.
    let mut conn = state.redis.get().await.map_err(redis_error)?;
    let issued: i64 = conn
        .del(authentication_key(&challenge))
        .await
        .map_err(redis_error)?;
    drop(conn);
    if issued != 1 {
        return Err(refused("unknown or used challenge"));
    }
    webauthn::check_client_data(&client_data, "webauthn.get", &challenge, &config.origins)
        .map_err(|e| refused(e.0))?;

    let passkey = passkey_repo::find_by_credential_id(&state.db, &decode(&credential.raw_id)?)
        .await?
        .ok_or_else(|| refused("unknown credential"))?;
    if let Some(handle) = credential.response.user_handle.as_deref()
        && decode(handle)? != passkey.user_id.as_bytes()
    {
        return Err(refused("user handle mismatch"));
    }
    let auth_data = decode(&credential.response.authenticator_data)?;
    let parsed = webauthn::parse_authenticator_data(&auth_data).map_err(|e| refused(e.0))?;
    parsed.check(&config.rp_id).map_err(|e| refused(e.0))?;
    let key = webauthn::parse_cose_key(&passkey.public_key).map_err(|e| refused(e.0))?;
    if !webauthn::verify_assertion(
        &key,
        &auth_data,
        &client_data,
        &decode(&credential.response.signature)?,
    ) {
        return Err(refused("bad signature"));
    }
    let stored = u32::try_from(passkey.sign_count).unwrap_or(u32::MAX);
    if webauthn::counter_regressed(stored, parsed.sign_count) {
        tracing::warn!(passkey_id = %passkey.id, "passkey counter did not grow: possible clone");
        return Err(refused("counter regressed"));
    }
    if !passkey_repo::record_use(
        &state.db,
        passkey.id,
        passkey.sign_count,
        parsed.sign_count,
        parsed.backed_up(),
    )
    .await?
    {
        return Err(refused("concurrent use"));
    }
    let user = user_repo::find_by_id(&state.db, passkey.user_id)
        .await?
        .ok_or_else(|| refused("account gone"))?;
    Ok((passkey, user))
}
