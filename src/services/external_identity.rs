//! Signing in with an external identity provider, and linking one to an account.
//!
//! 1. **start**: the frontend asks for the provider's authorization URL. It gets
//!    a `binding` secret with it, which it keeps in the browser.
//! 2. **callback**: the provider sends the browser back here. The code is
//!    exchanged, the person identified, and the outcome stored for two minutes
//!    under a one-time code the browser carries to the frontend.
//! 3. **complete**: the frontend presents that code with its `binding`. An
//!    outcome produced for another browser (a callback URL someone was tricked
//!    into opening) does not match its binding and is refused.
//!
//! Identities are matched by the provider's subject only. An email address, even
//! verified by the provider, never links an identity to an account: the owner
//! links it while signed in.

use std::{collections::HashMap, sync::LazyLock, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use deadpool_redis::redis::AsyncCommands;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{
    config::{IdentityProviderConfig, IdentityProviderKind},
    domain::{audit::AuditAction, external_identity as domain, oauth},
    error::AppError,
    repositories::{
        audit::{self, NewAuditEntry},
        external_identity::{self as identity_repo, ExternalIdentity},
        user as user_repo,
    },
    services::{auth as auth_svc, reauth as reauth_svc},
    state::AppState,
    utils::crypto,
};

const PENDING_PREFIX: &str = "external_pending:";
const OUTCOME_PREFIX: &str = "external_outcome:";
const PENDING_TTL_SECS: u64 = 600;
const OUTCOME_TTL_SECS: u64 = 120;
/// Provider metadata and keys are kept this long before being fetched again.
const DISCOVERY_TTL: Duration = Duration::from_secs(600);

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Intent {
    SignIn,
    Link,
}

#[derive(Serialize, Deserialize)]
struct Pending {
    provider: String,
    intent: Intent,
    user_id: Option<Uuid>,
    verifier: String,
    nonce: String,
    binding_hash: String,
}

#[derive(Serialize, Deserialize)]
struct Outcome {
    provider: String,
    intent: Intent,
    binding_hash: String,
    /// The account signing in, or the account the identity was linked to.
    user_id: Option<Uuid>,
    identity_id: Option<Uuid>,
    /// Stable error code when the flow failed.
    error: Option<String>,
}

pub struct Started {
    pub authorization_url: String,
    pub binding: String,
}

fn provider<'a>(state: &'a AppState, name: &str) -> Result<&'a IdentityProviderConfig, AppError> {
    state
        .config
        .identity_providers
        .iter()
        .find(|p| p.name == name)
        .ok_or(AppError::NotFound)
}

fn redirect_uri(state: &AppState, provider: &IdentityProviderConfig) -> String {
    format!(
        "{}/auth/external/{}/callback",
        state.config.server.public_url, provider.name
    )
}

fn hex_digest(value: &str) -> String {
    crypto::sha256(value.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn redis_error(e: impl std::fmt::Display) -> AppError {
    AppError::Internal(anyhow::anyhow!("external identity redis error: {e}"))
}

/// Begin a sign-in (no account) or a link (`user_id`, re-authenticated).
pub async fn start(
    state: &AppState,
    provider_name: &str,
    intent: Intent,
    user_id: Option<Uuid>,
) -> Result<Started, AppError> {
    let provider = provider(state, provider_name)?;
    let state_param = crypto::generate_token();
    let verifier = crypto::generate_token();
    let nonce = crypto::generate_token();
    let binding = crypto::generate_token();
    let challenge = B64URL.encode(crypto::sha256(verifier.as_bytes()));

    let endpoint = match provider.kind {
        IdentityProviderKind::Oidc => discovery(state, provider).await?["authorization_endpoint"]
            .as_str()
            .ok_or_else(|| AppError::ServiceUnavailable("identity_provider"))?
            .to_owned(),
        IdentityProviderKind::Github => provider.authorization_url.clone(),
    };
    let redirect = redirect_uri(state, provider);
    let scope = provider.scopes.join(" ");
    let mut parameters = vec![
        ("response_type", "code"),
        ("client_id", provider.client_id.as_str()),
        ("redirect_uri", redirect.as_str()),
        ("scope", scope.as_str()),
        ("state", state_param.as_str()),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ];
    if provider.kind == IdentityProviderKind::Oidc {
        parameters.push(("nonce", nonce.as_str()));
    }
    let authorization_url = oauth::redirect_with(&endpoint, &parameters)
        .ok_or_else(|| AppError::ServiceUnavailable("identity_provider"))?;

    let pending = serde_json::to_string(&Pending {
        provider: provider.name.clone(),
        intent,
        user_id,
        verifier,
        nonce,
        binding_hash: hex_digest(&binding),
    })
    .map_err(|e| AppError::Internal(e.into()))?;
    let mut conn = state.redis.get().await.map_err(redis_error)?;
    conn.set_ex::<_, _, ()>(
        format!("{PENDING_PREFIX}{}", hex_digest(&state_param)),
        pending,
        PENDING_TTL_SECS,
    )
    .await
    .map_err(redis_error)?;

    Ok(Started {
        authorization_url,
        binding,
    })
}

/// Handle the provider's redirect: always answers with the frontend URL to send
/// the browser to, carrying a one-time `code` (or `error` when the request
/// cannot be matched to a sign-in at all).
pub async fn callback(
    state: &AppState,
    provider_name: &str,
    parameters: &[(String, String)],
) -> Result<String, AppError> {
    let frontend = |params: &[(&str, &str)]| {
        oauth::redirect_with(&state.config.external_login_uri, params)
            .ok_or_else(|| AppError::Internal(anyhow::anyhow!("EXTERNAL_LOGIN_URI does not parse")))
    };
    let provider = provider(state, provider_name)?;
    let Some(state_param) = oauth::parameter(parameters, "state") else {
        return frontend(&[("error", "invalid_request")]);
    };
    let mut conn = state.redis.get().await.map_err(redis_error)?;
    let pending: Option<String> = conn
        .get_del(format!("{PENDING_PREFIX}{}", hex_digest(state_param)))
        .await
        .map_err(redis_error)?;
    drop(conn);
    let Some(pending) = pending.and_then(|p| serde_json::from_str::<Pending>(&p).ok()) else {
        return frontend(&[("error", "expired")]);
    };
    if pending.provider != provider.name {
        return frontend(&[("error", "invalid_request")]);
    }

    let result = match (
        oauth::parameter(parameters, "error"),
        oauth::parameter(parameters, "code"),
    ) {
        (None, Some(code)) => identify(state, provider, code, &pending).await,
        _ => Err("provider_refused"),
    };
    let mut outcome = Outcome {
        provider: provider.name.clone(),
        intent: pending.intent,
        binding_hash: pending.binding_hash.clone(),
        user_id: None,
        identity_id: None,
        error: None,
    };
    match result {
        Ok(subject) => match settle(state, provider, &pending, &subject).await? {
            Ok((user_id, identity_id)) => {
                outcome.user_id = Some(user_id);
                outcome.identity_id = Some(identity_id);
            }
            Err(code) => outcome.error = Some(code.into()),
        },
        Err(reason) => {
            tracing::warn!(provider = provider.name, reason, "external sign-in failed");
            outcome.error = Some("provider_error".into());
        }
    }

    let code = crypto::generate_token();
    let stored = serde_json::to_string(&outcome).map_err(|e| AppError::Internal(e.into()))?;
    let mut conn = state.redis.get().await.map_err(redis_error)?;
    conn.set_ex::<_, _, ()>(
        format!("{OUTCOME_PREFIX}{}", hex_digest(&code)),
        stored,
        OUTCOME_TTL_SECS,
    )
    .await
    .map_err(redis_error)?;
    frontend(&[("code", &code)])
}

/// Exchange the code and name the person.
async fn identify(
    state: &AppState,
    provider: &IdentityProviderConfig,
    code: &str,
    pending: &Pending,
) -> Result<String, &'static str> {
    let redirect = redirect_uri(state, provider);
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect.as_str()),
        ("client_id", provider.client_id.as_str()),
        ("client_secret", provider.client_secret.as_str()),
        ("code_verifier", pending.verifier.as_str()),
    ];
    match provider.kind {
        IdentityProviderKind::Oidc => {
            let metadata = discovery(state, provider)
                .await
                .map_err(|_| "discovery failed")?;
            let token_endpoint = metadata["token_endpoint"]
                .as_str()
                .ok_or("no token endpoint")?;
            let tokens: Value = post_form(state, token_endpoint, &form).await?;
            let id_token = tokens["id_token"].as_str().ok_or("no id token")?;
            let claims = verify_id_token(state, provider, &metadata, id_token).await?;
            domain::id_token_subject(
                &claims,
                &domain::IdTokenExpectations {
                    issuer: &provider.issuer,
                    client_id: &provider.client_id,
                    nonce: &pending.nonce,
                    now: state.clock.now().unix_timestamp(),
                },
            )
        }
        IdentityProviderKind::Github => {
            let tokens: Value = post_form(state, &provider.token_url, &form).await?;
            let access_token = tokens["access_token"].as_str().ok_or("no access token")?;
            let user: Value = state
                .http_client
                .get(&provider.user_url)
                .bearer_auth(access_token)
                .header("accept", "application/vnd.github+json")
                .header("user-agent", "auth-api")
                .send()
                .await
                .map_err(|_| "user request failed")?
                .error_for_status()
                .map_err(|_| "user request refused")?
                .json()
                .await
                .map_err(|_| "malformed user")?;
            domain::github_subject(&user).ok_or("no user id")
        }
    }
}

async fn post_form(
    state: &AppState,
    url: &str,
    form: &[(&str, &str)],
) -> Result<Value, &'static str> {
    state
        .http_client
        .post(url)
        .header("accept", "application/json")
        .form(form)
        .send()
        .await
        .map_err(|_| "token request failed")?
        .error_for_status()
        .map_err(|_| "token request refused")?
        .json()
        .await
        .map_err(|_| "malformed token response")
}

/// Verify the ID token's signature with the provider's published keys.
async fn verify_id_token(
    state: &AppState,
    provider: &IdentityProviderConfig,
    metadata: &Value,
    id_token: &str,
) -> Result<Value, &'static str> {
    let header = jsonwebtoken::decode_header(id_token).map_err(|_| "malformed id token")?;
    if !matches!(
        header.alg,
        jsonwebtoken::Algorithm::RS256
            | jsonwebtoken::Algorithm::ES256
            | jsonwebtoken::Algorithm::PS256
            | jsonwebtoken::Algorithm::EdDSA
    ) {
        return Err("unsupported id token algorithm");
    }
    let jwks_uri = metadata["jwks_uri"].as_str().ok_or("no jwks uri")?;
    let jwks = fetch_json(state, &format!("jwks:{}", provider.name), jwks_uri, false).await?;
    let set: jsonwebtoken::jwk::JwkSet =
        serde_json::from_value(jwks).map_err(|_| "malformed jwks")?;
    let jwk = match header.kid.as_deref() {
        Some(kid) => set.find(kid),
        None if set.keys.len() == 1 => set.keys.first(),
        None => None,
    }
    .ok_or("unknown signing key")?;
    let key = jsonwebtoken::DecodingKey::from_jwk(jwk).map_err(|_| "unusable signing key")?;
    let mut validation = jsonwebtoken::Validation::new(header.alg);
    // Claims are checked against the application clock in the domain.
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    jsonwebtoken::decode::<Value>(id_token, &key, &validation)
        .map(|data| data.claims)
        .map_err(|_| "bad id token signature")
}

static DISCOVERED: LazyLock<RwLock<HashMap<String, (std::time::Instant, Value)>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

async fn discovery(state: &AppState, provider: &IdentityProviderConfig) -> Result<Value, AppError> {
    fetch_json(
        state,
        &format!("discovery:{}", provider.issuer),
        &format!("{}/.well-known/openid-configuration", provider.issuer),
        true,
    )
    .await
    .map_err(|reason| {
        tracing::warn!(
            provider = provider.name,
            reason,
            "identity provider discovery failed"
        );
        AppError::ServiceUnavailable("identity_provider")
    })
}

async fn fetch_json(
    state: &AppState,
    cache_key: &str,
    url: &str,
    check_issuer: bool,
) -> Result<Value, &'static str> {
    if let Some((fetched, value)) = DISCOVERED.read().await.get(cache_key)
        && fetched.elapsed() < DISCOVERY_TTL
    {
        return Ok(value.clone());
    }
    let value: Value = state
        .http_client
        .get(url)
        .send()
        .await
        .map_err(|_| "metadata request failed")?
        .error_for_status()
        .map_err(|_| "metadata request refused")?
        .json()
        .await
        .map_err(|_| "malformed metadata")?;
    if check_issuer && value["issuer"].as_str().is_none() {
        return Err("metadata without issuer");
    }
    DISCOVERED.write().await.insert(
        cache_key.to_owned(),
        (std::time::Instant::now(), value.clone()),
    );
    Ok(value)
}

/// Resolve an identified person: the account signing in, or the link made.
async fn settle(
    state: &AppState,
    provider: &IdentityProviderConfig,
    pending: &Pending,
    subject: &str,
) -> Result<Result<(Uuid, Uuid), &'static str>, AppError> {
    let existing = identity_repo::find_by_subject(&state.db, &provider.name, subject).await?;
    match (pending.intent, existing, pending.user_id) {
        (Intent::SignIn, Some(identity), _) => {
            identity_repo::touch(&state.db, identity.id).await?;
            Ok(Ok((identity.user_id, identity.id)))
        }
        (Intent::SignIn, None, _) => Ok(Err("not_linked")),
        (Intent::Link, Some(identity), Some(user_id)) if identity.user_id == user_id => {
            Ok(Ok((user_id, identity.id)))
        }
        (Intent::Link, Some(_), _) => Ok(Err("already_linked")),
        (Intent::Link, None, Some(user_id)) => {
            match identity_repo::link(&state.db, user_id, &provider.name, subject).await {
                Ok(identity) => {
                    audit::append(
                        &state.db,
                        &NewAuditEntry {
                            user_id: Some(user_id),
                            request_id: None,
                            action: AuditAction::ExternalIdentityLinked,
                            ip_address: None,
                            metadata: json!({ "provider": provider.name }),
                        },
                    )
                    .await?;
                    Ok(Ok((user_id, identity.id)))
                }
                Err(sqlx::Error::Database(e)) if e.code().as_deref() == Some("23505") => {
                    Ok(Err("already_linked"))
                }
                Err(e) => Err(e.into()),
            }
        }
        (Intent::Link, None, None) => Ok(Err("invalid_request")),
    }
}

/// Take the outcome of a callback for this browser and this intent.
async fn take_outcome(
    state: &AppState,
    code: &str,
    binding: &str,
    intent: Intent,
) -> Result<Outcome, AppError> {
    let mut conn = state.redis.get().await.map_err(redis_error)?;
    let stored: Option<String> = conn
        .get_del(format!("{OUTCOME_PREFIX}{}", hex_digest(code)))
        .await
        .map_err(redis_error)?;
    drop(conn);
    let outcome: Outcome = stored
        .and_then(|s| serde_json::from_str(&s).ok())
        .ok_or(AppError::TokenInvalid)?;
    if outcome.binding_hash != hex_digest(binding) || outcome.intent != intent {
        return Err(AppError::TokenInvalid);
    }
    match outcome.error.as_deref() {
        None => Ok(outcome),
        Some("not_linked") => Err(AppError::Conflict("external_identity_not_linked")),
        Some("already_linked") => Err(AppError::Conflict("external_identity_already_linked")),
        Some(_) => Err(AppError::ServiceUnavailable("identity_provider")),
    }
}

/// Finish a sign-in: the external identity stands for the password; a second
/// factor enrolled on the account is still required.
#[allow(clippy::too_many_arguments)]
pub async fn complete_sign_in(
    state: &AppState,
    code: &str,
    binding: &str,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    device_name: Option<&str>,
    remember_me: bool,
    request_id: Option<Uuid>,
) -> Result<auth_svc::LoginResult, AppError> {
    let outcome = take_outcome(state, code, binding, Intent::SignIn).await?;
    let user = user_repo::find_by_id(&state.db, outcome.user_id.ok_or(AppError::TokenInvalid)?)
        .await?
        .ok_or(AppError::TokenInvalid)?;
    auth_svc::ensure_account_usable(&user, state.clock.now())?;
    auth_svc::first_factor_proven(
        state,
        &user,
        None,
        ip,
        user_agent,
        device_name,
        remember_me,
        request_id,
        json!({ "method": "external", "provider": outcome.provider }),
    )
    .await
}

/// Finish a link started by `user_id`.
pub async fn complete_link(
    state: &AppState,
    user_id: Uuid,
    code: &str,
    binding: &str,
) -> Result<ExternalIdentity, AppError> {
    let outcome = take_outcome(state, code, binding, Intent::Link).await?;
    if outcome.user_id != Some(user_id) {
        return Err(AppError::TokenInvalid);
    }
    identity_repo::find_by_user(&state.db, user_id)
        .await?
        .into_iter()
        .find(|identity| Some(identity.id) == outcome.identity_id)
        .ok_or(AppError::NotFound)
}

/// Start linking a provider to a signed-in, re-authenticated account.
pub async fn start_link(
    state: &AppState,
    user_id: Uuid,
    session_id: Uuid,
    provider_name: &str,
    ip: Option<IpNetwork>,
    request_id: Option<Uuid>,
) -> Result<Started, AppError> {
    reauth_svc::require_recent_reauth_or_password(
        state,
        user_id,
        session_id,
        None,
        ip,
        request_id,
        "link_external_identity",
    )
    .await?;
    start(state, provider_name, Intent::Link, Some(user_id)).await
}

pub async fn list(state: &AppState, user_id: Uuid) -> Result<Vec<ExternalIdentity>, AppError> {
    Ok(identity_repo::find_by_user(&state.db, user_id).await?)
}

pub async fn unlink(
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
        "unlink_external_identity",
    )
    .await?;
    if !identity_repo::delete_owned(&state.db, id, user_id).await? {
        return Err(AppError::NotFound);
    }
    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user_id),
            request_id,
            action: AuditAction::ExternalIdentityUnlinked,
            ip_address: ip,
            metadata: json!({ "identity_id": id }),
        },
    )
    .await?;
    Ok(())
}
