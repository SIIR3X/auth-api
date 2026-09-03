//! Authorization Code flow with PKCE for native and browser clients
//! (RFC 6749 section 4.1, RFC 7636, RFC 8252).
//!
//! 1. **describe**: the signed-in user's front end asks what a request is about
//!    before showing a consent screen. Nothing is minted.
//! 2. **approve**: the user consents; a single-use code bound to the client's
//!    PKCE challenge, redirect URI and the consented scopes is minted.
//! 3. **redeem**: the client exchanges the code for tokens by presenting the
//!    verifier. The verifier never leaves the client, so an intercepted code is
//!    worthless on its own.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use ipnetwork::IpNetwork;
use uuid::Uuid;

use crate::{
    domain::{registered_client::RegisteredClient, session::SessionType},
    error::AppError,
    repositories::{
        authorization_code::{self as code_repo, NewAuthorizationCode},
        client_quota as quota_repo, registered_client as client_repo, role as role_repo,
        session as session_repo, user as user_repo,
    },
    services::{auth as auth_svc, reauth as reauth_svc},
    state::AppState,
    utils::crypto,
};

/// Lifetime of a minted code. RFC 6749 allows ten minutes; the browser redirects
/// within a second, so one minute is generous.
const CODE_TTL_SECS: u64 = 60;

/// What a consent screen shows.
pub struct AuthorizationRequest {
    pub client_id: String,
    pub client_name: String,
    /// Permissions this approval would grant: the client's scopes intersected
    /// with the user's. Empty with `unrestricted` for a client without scopes.
    pub scopes: Vec<String>,
    pub unrestricted: bool,
    /// Scopes the client asks for that this user does not hold.
    pub unavailable_scopes: Vec<String>,
    pub sessions_used: i64,
    /// `None`: no session limit applies to this user and client.
    pub sessions_allowed: Option<i64>,
}

/// An approval to mint a code for.
pub struct Approval<'a> {
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub code_challenge: &'a str,
    pub code_challenge_method: &'a str,
    pub current_password: Option<&'a str>,
    pub ip: Option<IpNetwork>,
    pub request_id: Option<Uuid>,
}

/// What a client presents to redeem a code.
pub struct Redemption<'a> {
    pub code: &'a str,
    pub verifier: &'a str,
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub ip: Option<IpNetwork>,
    pub user_agent: Option<&'a str>,
    pub device_name: Option<&'a str>,
}

/// Validate a request without minting anything, for the consent screen.
pub async fn describe(
    state: &AppState,
    user_id: Uuid,
    client_id: &str,
    redirect_uri: &str,
) -> Result<AuthorizationRequest, AppError> {
    let client = load_client(state, client_id).await?;
    validate_redirect(&client, redirect_uri)?;

    let held = permission_names(state, user_id).await?;
    let scopes = if client.scopes.is_empty() {
        Vec::new()
    } else {
        client.granted(&held)
    };
    let unavailable_scopes = client
        .scopes
        .iter()
        .filter(|scope| !held.contains(scope))
        .cloned()
        .collect();
    let (sessions_used, sessions_allowed) = session_allowance(state, user_id, &client).await?;

    Ok(AuthorizationRequest {
        client_id: client.client_id.clone(),
        client_name: client.display_name.clone(),
        unrestricted: client.scopes.is_empty(),
        scopes,
        unavailable_scopes,
        sessions_used,
        sessions_allowed,
    })
}

/// Mint a single-use code for an approval the user has just given. Returns the
/// code in clear, once: only its hash is stored.
pub async fn approve(state: &AppState, approval: &Approval<'_>) -> Result<String, AppError> {
    let client = load_client(state, approval.client_id).await?;
    validate_redirect(&client, approval.redirect_uri)?;
    validate_challenge(approval.code_challenge, approval.code_challenge_method)?;

    // A third-party client obtains a long-lived session on the user's behalf:
    // consenting to one requires a fresh proof of the password, exactly like
    // other sensitive actions. The primary client is the instance's own app.
    if !client.is_primary {
        reauth_svc::require_recent_reauth_or_password(
            state,
            approval.user_id,
            approval.session_id,
            approval.current_password,
            approval.ip,
            approval.request_id,
            "authorize_client",
        )
        .await?;
    }

    ensure_account_usable(state, approval.user_id).await?;

    // Scopes are frozen at consent: a later widening of the client's
    // registration must not widen what this approval grants.
    let scopes = if client.scopes.is_empty() {
        None
    } else {
        Some(client.granted(&permission_names(state, approval.user_id).await?))
    };

    let code = crypto::generate_token();
    code_repo::create(
        &state.db,
        &NewAuthorizationCode {
            code_hash: &crypto::sha256(code.as_bytes()),
            user_id: approval.user_id,
            client_id: &client.client_id,
            redirect_uri: approval.redirect_uri,
            code_challenge: approval.code_challenge,
            scopes: scopes.as_deref(),
            expires_at: state.clock.in_secs(CODE_TTL_SECS),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    Ok(code)
}

/// Exchange a code and its verifier for a session.
///
/// The code is consumed before anything else is checked, so a failed attempt
/// (wrong verifier, wrong redirect) ends the code instead of leaving it open to
/// further guesses. Every refusal answers identically.
pub async fn redeem(
    state: &AppState,
    request: &Redemption<'_>,
) -> Result<auth_svc::AuthTokens, AppError> {
    let hash = crypto::sha256(request.code.as_bytes());

    let Some(entry) = code_repo::consume(&state.db, &hash)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
    else {
        revoke_on_replay(state, &hash).await;
        return Err(AppError::InvalidAuthorizationCode);
    };

    if entry.client_id != request.client_id
        || entry.redirect_uri != request.redirect_uri
        || !verifier_matches(&entry.code_challenge, request.verifier)
    {
        return Err(AppError::InvalidAuthorizationCode);
    }

    let client = load_client(state, &entry.client_id).await?;
    ensure_account_usable(state, entry.user_id).await?;

    // Serialize redemptions for this user and client so two concurrent
    // exchanges cannot both slip under the session limit. The transaction only
    // holds the advisory lock; dropping it on any exit releases the lock.
    let mut lock = state
        .db
        .begin()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("authorize:{}:{}", entry.user_id, entry.client_id))
        .execute(&mut *lock)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    let (used, allowed) = session_allowance(state, entry.user_id, &client).await?;
    if allowed.is_some_and(|allowed| used >= allowed) {
        return Err(AppError::DeviceSessionLimitReached);
    }

    let tokens = auth_svc::issue_tokens(
        state,
        entry.user_id,
        request.ip,
        request.user_agent,
        request.device_name,
        false,
        SessionType::Device,
        Some(&entry.client_id),
        entry.scopes.as_deref(),
        None,
    )
    .await?;

    lock.commit()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    if let Err(e) = code_repo::attach_session(&state.db, entry.id, tokens.session.id).await {
        tracing::warn!(error = %e, "could not link the authorization code to its session");
    }

    Ok(tokens)
}

/// RFC 6749 section 4.1.2: a code presented again after redemption means it
/// leaked; the tokens issued from it are revoked.
async fn revoke_on_replay(state: &AppState, code_hash: &[u8]) {
    let Ok(Some(seen)) = code_repo::find(&state.db, code_hash).await else {
        return;
    };
    if seen.consumed_at.is_none() {
        return;
    }
    tracing::warn!(client_id = %seen.client_id, "authorization code replayed after redemption");
    if let Some(session_id) = seen.session_id
        && let Err(e) = session_repo::revoke_family(&state.db, session_id).await
    {
        tracing::error!(error = %e, "could not revoke the session of a replayed code");
    }
}

async fn ensure_account_usable(state: &AppState, user_id: Uuid) -> Result<(), AppError> {
    let user = user_repo::find_by_id(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::Unauthorized)?;
    if !user.is_active() {
        return Err(AppError::AccountSuspended);
    }
    if user.is_locked(state.clock.now()) {
        return Err(AppError::AccountLocked);
    }
    Ok(())
}

/// RFC 7636 section 4.2: S256 only, a 43-character base64url SHA-256 digest.
/// `plain` would let whoever saw the challenge redeem the code.
fn validate_challenge(challenge: &str, method: &str) -> Result<(), AppError> {
    if method != "S256" {
        return Err(AppError::Validation(
            "only the S256 code_challenge_method is accepted".into(),
        ));
    }
    if challenge.len() != 43 || !challenge.bytes().all(is_base64url) {
        return Err(AppError::Validation(
            "code_challenge must be a base64url-encoded SHA-256 digest".into(),
        ));
    }
    Ok(())
}

fn is_base64url(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

/// RFC 7636 section 4.1 (verifier charset and length) and 4.6 (S256), compared
/// in constant time.
fn verifier_matches(challenge: &str, verifier: &str) -> bool {
    let well_formed = (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b));
    if !well_formed {
        return false;
    }
    let expected = B64URL.encode(crypto::sha256(verifier.as_bytes()));
    constant_time_eq(expected.as_bytes(), challenge.as_bytes())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Accept a redirect URI registered for the client, exactly; or, for a client
/// allowing loopback redirects, `http://127.0.0.1:<any port>/<path>` or
/// `http://[::1]:<any port>/<path>` where the path is registered on a loopback
/// URI (RFC 8252 section 7.3: native apps cannot know their port in advance).
/// `localhost` is refused: it can resolve elsewhere.
fn validate_redirect(client: &RegisteredClient, redirect_uri: &str) -> Result<(), AppError> {
    if client
        .redirect_uris
        .iter()
        .any(|registered| registered == redirect_uri)
    {
        return Ok(());
    }

    let loopback_ok = client.allows_loopback_redirect
        && reqwest::Url::parse(redirect_uri).is_ok_and(|url| {
            is_loopback(&url)
                && url.port().is_some()
                && url.as_str() == redirect_uri
                && client
                    .redirect_uris
                    .iter()
                    .filter_map(|registered| reqwest::Url::parse(registered).ok())
                    .any(|registered| is_loopback(&registered) && registered.path() == url.path())
        });

    if loopback_ok {
        Ok(())
    } else {
        Err(AppError::Validation(
            "redirect_uri is not registered for this client".into(),
        ))
    }
}

fn is_loopback(url: &reqwest::Url) -> bool {
    url.scheme() == "http"
        && matches!(url.host_str(), Some("127.0.0.1") | Some("[::1]"))
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
}

async fn session_allowance(
    state: &AppState,
    user_id: Uuid,
    client: &RegisteredClient,
) -> Result<(i64, Option<i64>), AppError> {
    let quota = quota_repo::find_by_user_and_client(&state.db, user_id, &client.client_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    let used = session_repo::count_active_by_client(&state.db, user_id, &client.client_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    Ok((used, client.session_limit(quota.as_ref())))
}

async fn load_client(state: &AppState, client_id: &str) -> Result<RegisteredClient, AppError> {
    client_repo::find_by_id(&state.db, client_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::DeviceClientUnknown)
}

async fn permission_names(state: &AppState, user_id: Uuid) -> Result<Vec<String>, AppError> {
    Ok(role_repo::find_permissions_by_user(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .into_iter()
        .map(|permission| permission.name)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(uris: &[&str], loopback: bool) -> RegisteredClient {
        RegisteredClient {
            client_id: "app".into(),
            display_name: "App".into(),
            is_primary: false,
            created_at: ::time::OffsetDateTime::now_utc(),
            scopes: vec![],
            redirect_uris: uris.iter().map(|u| u.to_string()).collect(),
            allows_loopback_redirect: loopback,
            default_max_sessions: 5,
        }
    }

    #[test]
    fn registered_redirects_match_exactly() {
        let c = client(&["https://app.example.com/callback"], false);
        assert!(validate_redirect(&c, "https://app.example.com/callback").is_ok());
        assert!(validate_redirect(&c, "https://app.example.com/callback/").is_err());
        assert!(validate_redirect(&c, "https://app.example.com/callback?x=1").is_err());
    }

    #[test]
    fn loopback_redirects_accept_any_port_on_a_registered_path() {
        let c = client(&["http://127.0.0.1/callback"], true);
        assert!(validate_redirect(&c, "http://127.0.0.1:53817/callback").is_ok());
        assert!(validate_redirect(&c, "http://[::1]:53817/callback").is_ok());
        assert!(validate_redirect(&c, "http://127.0.0.1:53817/other").is_err());
        assert!(validate_redirect(&c, "http://localhost:53817/callback").is_err());
        assert!(validate_redirect(&c, "http://user@127.0.0.1:53817/callback").is_err());
        assert!(validate_redirect(&c, "http://127.0.0.1:53817/callback?next=x").is_err());
        assert!(
            validate_redirect(
                &client(&["http://127.0.0.1/callback"], false),
                "http://127.0.0.1:53817/callback"
            )
            .is_err()
        );
    }

    #[test]
    fn challenges_and_verifiers_follow_rfc_7636() {
        let verifier = "a".repeat(64);
        let challenge = B64URL.encode(crypto::sha256(verifier.as_bytes()));
        assert!(validate_challenge(&challenge, "S256").is_ok());
        assert!(validate_challenge(&challenge, "plain").is_err());
        assert!(validate_challenge("short", "S256").is_err());
        assert!(verifier_matches(&challenge, &verifier));
        assert!(!verifier_matches(&challenge, &"b".repeat(64)));
        assert!(!verifier_matches(&challenge, "a"));
        assert!(!verifier_matches(
            &challenge,
            &format!("{}!", "a".repeat(63))
        ));
    }
}
