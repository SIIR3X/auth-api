//! OAuth 2.1 endpoints (RFC 6749, RFC 7636, RFC 8252, RFC 8414, RFC 8628):
//! client authentication, authorization requests, the token endpoint and
//! device authorization.
//!
//! The authorization endpoint validates a request, stores it for ten minutes
//! and sends the browser to the auth frontend, where the signed-in user reviews
//! it (`/oauth/authorization-requests/{id}`) and approves or denies it. Every
//! answer then goes back to the client through its registered redirect URI.

use deadpool_redis::redis::AsyncCommands;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    domain::{
        oauth::{self, ErrorCode},
        registered_client::RegisteredClient,
    },
    error::AppError,
    repositories::role as role_repo,
    services::{
        auth::{self as auth_svc, AuthTokens},
        authorize as authorize_svc, device as device_svc,
    },
    state::AppState,
    utils::crypto,
};

/// How long a user has to approve an authorization request.
const REQUEST_TTL_SECS: u64 = 600;
const REQUEST_PREFIX: &str = "oauth_request:";

/// An OAuth error answer: `{ "error", "error_description" }`.
#[derive(Debug)]
pub struct OAuthError {
    pub code: ErrorCode,
    pub description: Option<String>,
    /// Set when the client tried `client_secret_basic`: the answer then carries
    /// `WWW-Authenticate` (RFC 6749 section 5.2).
    pub basic_challenge: bool,
}

impl OAuthError {
    pub fn new(code: ErrorCode, description: impl Into<String>) -> Self {
        Self {
            code,
            description: Some(description.into()),
            basic_challenge: false,
        }
    }

    pub fn status(&self) -> u16 {
        if self.code == ErrorCode::InvalidClient {
            401
        } else {
            400
        }
    }
}

/// A failure of an OAuth endpoint: an OAuth error, or an outage and rate limit
/// answered like everywhere else.
#[derive(Debug)]
pub enum EndpointError {
    OAuth(OAuthError),
    App(AppError),
}

impl From<OAuthError> for EndpointError {
    fn from(error: OAuthError) -> Self {
        Self::OAuth(error)
    }
}

impl From<AppError> for EndpointError {
    fn from(error: AppError) -> Self {
        use AppError as E;
        let code = match &error {
            E::Validation(message) => {
                return Self::OAuth(OAuthError::new(ErrorCode::InvalidRequest, message.clone()));
            }
            E::DeviceAuthPending => ErrorCode::AuthorizationPending,
            E::DeviceSlowDown => ErrorCode::SlowDown,
            E::DeviceCodeExpired => ErrorCode::ExpiredToken,
            E::DeviceAccessDenied => ErrorCode::AccessDenied,
            E::DeviceClientUnknown => ErrorCode::InvalidClient,
            E::InvalidAuthorizationCode
            | E::TokenInvalid
            | E::TokenExpired
            | E::Unauthorized
            | E::AccountSuspended
            | E::AccountInactive
            | E::AccountLocked
            | E::EmailNotVerified
            | E::DeviceSessionLimitReached
            | E::Forbidden => ErrorCode::InvalidGrant,
            _ => return Self::App(error),
        };
        // Whoever holds a refresh token or a device code learns nothing of the
        // account's state: suspended, locked, inactive or unverified all read
        // the same.
        let description = match &error {
            E::AccountSuspended | E::AccountInactive | E::AccountLocked | E::EmailNotVerified => {
                "the grant is not valid".to_owned()
            }
            _ => error.to_string(),
        };
        Self::OAuth(OAuthError::new(code, description))
    }
}

impl From<sqlx::Error> for EndpointError {
    fn from(error: sqlx::Error) -> Self {
        Self::App(error.into())
    }
}

// Client authentication

/// Wrong client secrets one address may present per window. Secrets carry 256
/// bits: this bounds volume, it is not what keeps them secret.
const MAX_CLIENT_AUTH_FAILURES_BY_IP: i64 = 20;
const CLIENT_AUTH_FAILURE_WINDOW_SECS: u64 = 900;
/// Requests one client may make per minute to the token, introspection and
/// revocation endpoints. These run under the general per-address limit: a
/// resource server introspecting from one address, or clients behind one NAT,
/// are bounded per client instead of by the strict per-address limit.
const CLIENT_REQUESTS_PER_MINUTE: i64 = 1_200;

/// The budget of wrong secrets presented from `ip` for the client id the
/// request claims: one address guessing one client's secret is throttled,
/// without shutting the endpoints for the other clients and users behind the
/// same address.
fn client_failure_key(ip: IpNetwork, claimed_client_id: &str) -> String {
    let claimed: String = crypto::sha256(claimed_client_id.as_bytes())[..16]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!(
        "oauth_client_fail:{}:{claimed}",
        crate::middleware::rate_limit::ip_bucket(ip.ip())
    )
}

/// The client id a request claims, and whether it presents a secret: only
/// requests presenting one can guess one.
fn claimed_secret_holder(
    authorization: Option<&str>,
    parameters: &[(String, String)],
) -> Option<String> {
    match authorization.filter(|h| h.to_ascii_lowercase().starts_with("basic ")) {
        Some(header) => Some(
            oauth::basic_credentials(header)
                .map(|(id, _)| id)
                .unwrap_or_default(),
        ),
        None => oauth::parameter(parameters, "client_secret").map(|_| {
            oauth::parameter(parameters, "client_id")
                .unwrap_or_default()
                .to_owned()
        }),
    }
}

/// The client making a token or device authorization request: authenticated
/// with its secret when it has one (`client_secret_basic` or
/// `client_secret_post`), identified by `client_id` when it is public.
///
/// Wrong secrets count against the address, and every authenticated request
/// against the client: both budgets bound volume and fail open.
pub async fn authenticate_client(
    state: &AppState,
    authorization: Option<&str>,
    parameters: &[(String, String)],
    ip: Option<IpNetwork>,
) -> Result<RegisteredClient, EndpointError> {
    let failure_key = ip
        .zip(claimed_secret_holder(authorization, parameters))
        .map(|(ip, claimed)| client_failure_key(ip, &claimed));
    if let Some(key) = &failure_key
        && crate::utils::redis_counter::peek(&state.redis, key)
            .await
            .unwrap_or(0)
            >= MAX_CLIENT_AUTH_FAILURES_BY_IP
    {
        return Err(AppError::RateLimitExceeded.into());
    }
    let client = identify_client(state, authorization, parameters).await;
    match &client {
        Err(EndpointError::OAuth(error)) if error.code == ErrorCode::InvalidClient => {
            if let Some(key) = &failure_key {
                let _ = crate::utils::redis_counter::consume(
                    &state.redis,
                    &[crate::utils::redis_counter::Budget {
                        key: &key,
                        limit: MAX_CLIENT_AUTH_FAILURES_BY_IP,
                        window_secs: CLIENT_AUTH_FAILURE_WINDOW_SECS,
                    }],
                )
                .await;
            }
        }
        Ok(client) => {
            // A confidential client proved its secret: its budget is its own.
            // A public client is only named, by anyone: its budget is split
            // by address, so a flood from a few addresses cannot spend the
            // share of every one of its users.
            let key = match ip {
                Some(ip) if !client.is_confidential() => format!(
                    "oauth_client_rpm:{}:{}",
                    client.client_id,
                    crate::middleware::rate_limit::ip_bucket(ip.ip())
                ),
                _ => format!("oauth_client_rpm:{}", client.client_id),
            };
            let consumed = crate::utils::redis_counter::consume(
                &state.redis,
                &[crate::utils::redis_counter::Budget {
                    key: &key,
                    limit: CLIENT_REQUESTS_PER_MINUTE,
                    window_secs: 60,
                }],
            )
            .await;
            if consumed.is_ok_and(|attempt| attempt.exceeded) {
                return Err(AppError::RateLimitExceeded.into());
            }
        }
        Err(_) => {}
    }
    client
}

async fn identify_client(
    state: &AppState,
    authorization: Option<&str>,
    parameters: &[(String, String)],
) -> Result<RegisteredClient, EndpointError> {
    let basic = authorization.filter(|h| h.to_ascii_lowercase().starts_with("basic "));
    let invalid = |description: &str, basic_challenge: bool| {
        EndpointError::OAuth(OAuthError {
            code: ErrorCode::InvalidClient,
            description: Some(description.to_owned()),
            basic_challenge,
        })
    };

    let (client_id, secret) = match basic {
        Some(header) => {
            let (id, secret) = oauth::basic_credentials(header)
                .ok_or_else(|| invalid("malformed Basic credentials", true))?;
            if oauth::parameter(parameters, "client_secret").is_some() {
                return Err(OAuthError::new(
                    ErrorCode::InvalidRequest,
                    "client credentials must use a single method",
                )
                .into());
            }
            if oauth::parameter(parameters, "client_id").is_some_and(|param| param != id) {
                return Err(OAuthError::new(
                    ErrorCode::InvalidRequest,
                    "client_id does not match the Basic credentials",
                )
                .into());
            }
            (id, Some(secret))
        }
        None => {
            let id = oauth::parameter(parameters, "client_id").ok_or_else(|| {
                OAuthError::new(ErrorCode::InvalidRequest, "client_id is required")
            })?;
            (
                id.to_owned(),
                oauth::parameter(parameters, "client_secret").map(str::to_owned),
            )
        }
    };

    // One description for every failure: which client ids exist, and which
    // hold a secret, is not the caller's to learn.
    let Some(client) =
        crate::repositories::registered_client::find_by_id(&state.db, &client_id).await?
    else {
        return Err(invalid("client authentication failed", basic.is_some()));
    };
    match (&client.client_secret_hash, secret) {
        (Some(expected), Some(secret)) => {
            let presented = crypto::sha256(secret.as_bytes());
            if !constant_time_eq(&presented, expected) {
                return Err(invalid("client authentication failed", basic.is_some()));
            }
        }
        (Some(_), None) => {
            return Err(invalid("client authentication failed", basic.is_some()));
        }
        (None, Some(_)) => {
            return Err(invalid("client authentication failed", basic.is_some()));
        }
        (None, None) => {}
    }
    Ok(client)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    crypto::constant_time_eq(a, b)
}

// Authorization requests

#[derive(Debug, Serialize, Deserialize)]
struct StoredRequest {
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    scopes: Option<Vec<String>>,
    state: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
    /// OpenID Connect `max_age` (`prompt=login` is 0): the password must have
    /// been proved this many seconds ago at most when the request is approved.
    #[serde(default)]
    max_age: Option<i64>,
    /// The first signed-in user who looked at the request: only they decide it.
    #[serde(default)]
    viewer: Option<Uuid>,
}

/// Where `GET /oauth/authorize` sends the browser.
pub enum AuthorizeOutcome {
    /// To the consent page, with the stored request's id.
    Consent(String),
    /// Back to the client, with an error.
    Refused(String),
}

/// Validate an authorization request. Until the client and its redirect URI are
/// known good, errors are answered directly (never redirected to an unchecked
/// URI); after that, through the redirect.
pub async fn start_authorization(
    state: &AppState,
    parameters: &[(String, String)],
) -> Result<AuthorizeOutcome, EndpointError> {
    let param = |name| oauth::parameter(parameters, name);
    let client_id = param("client_id")
        .ok_or_else(|| OAuthError::new(ErrorCode::InvalidRequest, "client_id is required"))?;
    let client = authorize_svc::load_client(state, client_id).await?;
    let redirect_uri = match param("redirect_uri") {
        Some(uri) => uri.to_owned(),
        // RFC 6749 section 3.1.2.3: optional when exactly one is registered.
        None if client.redirect_uris.len() == 1 => client.redirect_uris[0].clone(),
        None => {
            return Err(
                OAuthError::new(ErrorCode::InvalidRequest, "redirect_uri is required").into(),
            );
        }
    };
    authorize_svc::validate_redirect(&client, &redirect_uri)?;

    let client_state = param("state").filter(|s| s.len() <= oauth::MAX_STATE_LEN);
    let issuer = state.config.server.public_url.as_str();
    let refuse = |code: ErrorCode, description: &str| {
        let mut response = vec![("error", code.as_str()), ("error_description", description)];
        if let Some(client_state) = client_state {
            response.push(("state", client_state));
        }
        // RFC 9207: the client learns which server answered (mix-up defence).
        response.push(("iss", issuer));
        oauth::redirect_with(&redirect_uri, &response)
            .map(AuthorizeOutcome::Refused)
            .ok_or_else(|| {
                EndpointError::OAuth(OAuthError::new(
                    ErrorCode::InvalidRequest,
                    "invalid redirect_uri",
                ))
            })
    };

    if param("state").is_some_and(|s| s.len() > oauth::MAX_STATE_LEN) {
        return refuse(ErrorCode::InvalidRequest, "state is too long");
    }
    if param("nonce").is_some_and(|n| n.chars().count() > oauth::MAX_STATE_LEN) {
        return refuse(ErrorCode::InvalidRequest, "nonce is too long");
    }
    if param("response_type") != Some("code") {
        return refuse(
            ErrorCode::UnsupportedResponseType,
            "only the code response type is supported",
        );
    }
    // OpenID Connect parameters this server does not honour are refused rather
    // than ignored: a client relying on them must know.
    if param("request").is_some() {
        return refuse(
            ErrorCode::RequestNotSupported,
            "request objects are not supported",
        );
    }
    if param("request_uri").is_some() {
        return refuse(
            ErrorCode::RequestUriNotSupported,
            "request_uri is not supported",
        );
    }
    if param("response_mode").is_some_and(|mode| mode != "query") {
        return refuse(
            ErrorCode::InvalidRequest,
            "only the query response mode is supported",
        );
    }
    let prompt: Vec<&str> = param("prompt").unwrap_or_default().split(' ').collect();
    if prompt.contains(&"none") {
        return refuse(
            ErrorCode::InteractionRequired,
            "the consent page always asks the user",
        );
    }
    let max_age = match param("max_age").map(str::parse::<i64>) {
        None => None,
        Some(Ok(age)) if age >= 0 => Some(age),
        Some(_) => {
            return refuse(
                ErrorCode::InvalidRequest,
                "max_age must be a number of seconds",
            );
        }
    };
    let max_age = if prompt.contains(&"login") {
        Some(0)
    } else {
        max_age
    };
    let Some(code_challenge) = param("code_challenge") else {
        return refuse(ErrorCode::InvalidRequest, "code_challenge is required");
    };
    if let Err(AppError::Validation(message)) = authorize_svc::validate_challenge(
        code_challenge,
        param("code_challenge_method").unwrap_or("plain"),
    ) {
        return refuse(ErrorCode::InvalidRequest, &message);
    }
    let scopes = match check_scopes(state, &client, param("scope")).await? {
        Ok(scopes) => scopes,
        Err(message) => return refuse(ErrorCode::InvalidScope, &message),
    };

    let id = crypto::generate_token();
    let stored = serde_json::to_string(&StoredRequest {
        client_id: client.client_id,
        redirect_uri,
        code_challenge: code_challenge.to_owned(),
        scopes,
        state: client_state.map(str::to_owned),
        nonce: param("nonce").map(str::to_owned),
        max_age,
        viewer: None,
    })
    .map_err(|e| AppError::Internal(e.into()))?;
    let mut conn = state
        .redis
        .get()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    conn.set_ex::<_, _, ()>(request_key(&id), stored, REQUEST_TTL_SECS)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    Ok(AuthorizeOutcome::Consent(id))
}

/// The scopes of a request, or a message for `invalid_scope`.
async fn check_scopes(
    state: &AppState,
    client: &RegisteredClient,
    scope: Option<&str>,
) -> Result<Result<Option<Vec<String>>, String>, AppError> {
    let requested = match oauth::parse_scope(scope) {
        Ok(requested) => requested,
        Err(message) => return Ok(Err(message)),
    };
    let scopes = match oauth::requested_scopes(requested, &client.scopes) {
        Ok(scopes) => scopes,
        Err(outside) => {
            return Ok(Err(format!(
                "scopes not allowed for this client: {}",
                outside.join(" ")
            )));
        }
    };
    if let Some(scopes) = &scopes {
        let permissions: Vec<String> = scopes
            .iter()
            .filter(|scope| !crate::domain::oidc::is_oidc_scope(scope))
            .cloned()
            .collect();
        let unknown = role_repo::unknown_permissions(&state.db, &permissions).await?;
        if !unknown.is_empty() {
            return Ok(Err(format!("unknown scopes: {}", unknown.join(" "))));
        }
    }
    Ok(Ok(scopes))
}

fn request_key(id: &str) -> String {
    format!("{REQUEST_PREFIX}{}", hex(&crypto::sha256(id.as_bytes())))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

async fn load_request(state: &AppState, id: &str) -> Result<(Loaded, RegisteredClient), AppError> {
    let mut conn = state
        .redis
        .get()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    let raw: Option<String> = conn
        .get(request_key(id))
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    let raw = raw.ok_or(AppError::NotFound)?;
    let request: StoredRequest =
        serde_json::from_str(&raw).map_err(|e| AppError::Internal(e.into()))?;
    let client = authorize_svc::load_client(state, &request.client_id)
        .await
        .map_err(|_| AppError::NotFound)?;
    Ok((Loaded { request, raw }, client))
}

/// A stored request as read, with the exact value read: claiming it swaps
/// that value only if nobody changed it meanwhile.
struct Loaded {
    request: StoredRequest,
    raw: String,
}

/// Replace a value only if it is still the one read, keeping its expiry.
static CLAIM_REQUEST: std::sync::LazyLock<deadpool_redis::redis::Script> =
    std::sync::LazyLock::new(|| {
        deadpool_redis::redis::Script::new(
            r#"
if redis.call('GET', KEYS[1]) == ARGV[1] then
    redis.call('SET', KEYS[1], ARGV[2], 'KEEPTTL')
    return 1
end
return 0
"#,
        )
    });

/// Remove the request: of concurrent decisions, only the one that removed it
/// goes on.
async fn take_request(state: &AppState, id: &str) -> Result<(), AppError> {
    let mut conn = state
        .redis
        .get()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    let removed: i64 = conn
        .del(request_key(id))
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    if removed == 1 {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

/// What the consent page shows.
pub struct RequestDescription {
    pub request: authorize_svc::AuthorizationRequest,
    pub redirect_uri: String,
    pub reauthentication_required: bool,
}

pub async fn describe_request(
    state: &AppState,
    user_id: Uuid,
    session_id: Uuid,
    id: &str,
) -> Result<RequestDescription, AppError> {
    let (request, client) = load_request(state, id).await?;
    let request = claim_request(state, id, request, user_id).await?;
    let description =
        authorize_svc::describe(state, user_id, &client, request.scopes.as_deref()).await?;
    let reauthentication_required =
        !password_fresh_enough(state, session_id, request.max_age).await;
    Ok(RequestDescription {
        request: description,
        redirect_uri: request.redirect_uri,
        reauthentication_required,
    })
}

/// Tie the request to the first signed-in user who looks at it: someone else
/// who learnt its id cannot decide it. A request already tied to another user
/// is not found for them.
async fn claim_request(
    state: &AppState,
    id: &str,
    loaded: Loaded,
    user_id: Uuid,
) -> Result<StoredRequest, AppError> {
    let Loaded { mut request, raw } = loaded;
    match request.viewer {
        Some(viewer) if viewer == user_id => Ok(request),
        Some(_) => Err(AppError::NotFound),
        None => {
            request.viewer = Some(user_id);
            let stored =
                serde_json::to_string(&request).map_err(|e| AppError::Internal(e.into()))?;
            let mut conn = state
                .redis
                .get()
                .await
                .map_err(|e| AppError::Internal(e.into()))?;
            // Only if nobody claimed it since it was read, keeping its expiry:
            // of two users reading it unclaimed, one gets it.
            let claimed: i64 = CLAIM_REQUEST
                .key(request_key(id))
                .arg(&raw)
                .arg(stored)
                .invoke_async(&mut *conn)
                .await
                .map_err(|e| AppError::Internal(e.into()))?;
            if claimed != 1 {
                return Err(AppError::NotFound);
            }
            Ok(request)
        }
    }
}

/// Whether the session's proof of the password is recent enough for a
/// request's `max_age` (any standing proof when there is none).
async fn password_fresh_enough(state: &AppState, session_id: Uuid, max_age: Option<i64>) -> bool {
    let Some(proven_at) = crate::services::reauth::reauth_proven_at(state, session_id).await else {
        return false;
    };
    let age = state.clock.now().unix_timestamp() - proven_at;
    // `max_age=0` (and `prompt=login`) asks for the password again, always.
    max_age.is_none_or(|max_age| max_age > 0 && age <= max_age)
}

/// Approve a request: the redirect carrying the code and state.
pub async fn approve_request(
    state: &AppState,
    user_id: Uuid,
    session_id: Uuid,
    id: &str,
    current_password: Option<&str>,
    ip: Option<IpNetwork>,
    request_id: Option<Uuid>,
) -> Result<String, AppError> {
    let (request, client) = load_request(state, id).await?;
    let request = claim_request(state, id, request, user_id).await?;
    // The client as registered now: a redirect URI removed since the request
    // was made no longer receives a code.
    authorize_svc::validate_redirect(&client, &request.redirect_uri)?;
    // A request with `max_age` needs a proof of the password that recent: an
    // older one asks for the password again.
    if current_password.is_none()
        && !password_fresh_enough(state, session_id, request.max_age).await
    {
        return Err(AppError::ReauthenticationRequired);
    }
    // The password is checked before the request is taken: a missing or wrong
    // one leaves the request to approve once the user has confirmed it. Every
    // client needs it, the instance's own application included: an approval
    // mints a new, long-lived session, and an access token alone must not be
    // enough to obtain one.
    crate::services::reauth::require_recent_reauth_or_password(
        state,
        user_id,
        session_id,
        current_password,
        ip,
        request_id,
        "authorize_client",
    )
    .await?;
    take_request(state, id).await?;
    let auth_time = crate::services::reauth::reauth_proven_at(state, session_id)
        .await
        .and_then(|at| ::time::OffsetDateTime::from_unix_timestamp(at).ok())
        .unwrap_or_else(|| state.clock.now());
    let approval = authorize_svc::Approval {
        user_id,
        session_id,
        client: &client,
        redirect_uri: &request.redirect_uri,
        code_challenge: &request.code_challenge,
        requested: request.scopes.as_deref(),
        nonce: request.nonce.as_deref(),
        auth_time,
        // Proven above: the recent re-authentication marker now stands for it.
        current_password: None,
        ip,
        request_id,
    };
    let code = authorize_svc::approve(state, &approval).await?;

    let mut response = vec![("code", code.as_str())];
    if let Some(client_state) = request.state.as_deref() {
        response.push(("state", client_state));
    }
    response.push(("iss", state.config.server.public_url.as_str()));
    oauth::redirect_with(&request.redirect_uri, &response)
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("stored redirect_uri does not parse")))
}

/// Deny a request: the redirect carrying `access_denied`.
pub async fn deny_request(state: &AppState, user_id: Uuid, id: &str) -> Result<String, AppError> {
    let (request, _) = load_request(state, id).await?;
    let request = claim_request(state, id, request, user_id).await?;
    take_request(state, id).await?;
    let mut response = vec![
        ("error", ErrorCode::AccessDenied.as_str()),
        ("error_description", "the user denied the request"),
    ];
    if let Some(client_state) = request.state.as_deref() {
        response.push(("state", client_state));
    }
    response.push(("iss", state.config.server.public_url.as_str()));
    oauth::redirect_with(&request.redirect_uri, &response)
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("stored redirect_uri does not parse")))
}

// Token endpoint

/// RFC 6749 section 5.1.
pub struct TokenResponse {
    pub access_token: String,
    /// Absent for the client credentials grant.
    pub refresh_token: Option<String>,
    pub scopes: Option<Vec<String>>,
    pub expires_in: u64,
    /// Present when the session was granted the `openid` scope.
    pub id_token: Option<String>,
}

pub async fn token(
    state: &AppState,
    authorization: Option<&str>,
    parameters: &[(String, String)],
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
) -> Result<TokenResponse, EndpointError> {
    let param = |name: &'static str| oauth::parameter(parameters, name);
    let grant_type = param("grant_type")
        .ok_or_else(|| OAuthError::new(ErrorCode::InvalidRequest, "grant_type is required"))?;
    if ![
        oauth::GRANT_AUTHORIZATION_CODE,
        oauth::GRANT_REFRESH_TOKEN,
        oauth::GRANT_DEVICE_CODE,
        oauth::GRANT_CLIENT_CREDENTIALS,
    ]
    .contains(&grant_type)
    {
        return Err(OAuthError::new(
            ErrorCode::UnsupportedGrantType,
            format!("unsupported grant_type {grant_type}"),
        )
        .into());
    }
    let client = authenticate_client(state, authorization, parameters, ip).await?;
    let required = |name: &'static str| {
        param(name).ok_or_else(|| {
            EndpointError::OAuth(OAuthError::new(
                ErrorCode::InvalidRequest,
                format!("{name} is required"),
            ))
        })
    };
    let device_name = param("device_name");
    let expires_in = state.config.jwt.access_expiry_secs;

    if grant_type == oauth::GRANT_CLIENT_CREDENTIALS {
        return client_credentials(state, &client, param("scope")).await;
    }

    let (tokens, nonce) = match grant_type {
        oauth::GRANT_AUTHORIZATION_CODE => {
            let redirect_uri = match param("redirect_uri") {
                Some(uri) => uri.to_owned(),
                None if client.redirect_uris.len() == 1 => client.redirect_uris[0].clone(),
                None => required("redirect_uri")?.to_owned(),
            };
            authorize_svc::redeem(
                state,
                &authorize_svc::Redemption {
                    code: required("code")?,
                    verifier: required("code_verifier")?,
                    client_id: &client.client_id,
                    redirect_uri: &redirect_uri,
                    ip,
                    user_agent,
                    device_name,
                },
            )
            .await?
        }
        oauth::GRANT_REFRESH_TOKEN => (
            auth_svc::refresh_token(
                state,
                required("refresh_token")?,
                Some(&client.client_id),
                ip,
                user_agent,
                None,
            )
            .await?,
            None,
        ),
        _ => (
            device_svc::poll(
                state,
                required("device_code")?,
                &client.client_id,
                ip,
                user_agent,
                device_name,
            )
            .await?,
            None,
        ),
    };

    let id_token = if crate::domain::oidc::requests_identity(tokens.session.scopes.as_deref()) {
        Some(id_token(state, &client, &tokens, nonce).await?)
    } else {
        None
    };
    Ok(TokenResponse {
        access_token: tokens.access_token,
        refresh_token: Some(tokens.refresh_token),
        scopes: tokens.session.scopes,
        expires_in,
        id_token,
    })
}

/// An OpenID Connect ID token for the session's user and this client.
async fn id_token(
    state: &AppState,
    client: &RegisteredClient,
    tokens: &AuthTokens,
    nonce: Option<String>,
) -> Result<String, AppError> {
    let user = crate::repositories::user::find_by_id(&state.db, tokens.session.user_id)
        .await?
        .ok_or(AppError::TokenInvalid)?;
    let scopes = tokens.session.scopes.clone().unwrap_or_default();
    let now = state.clock.now().unix_timestamp();
    let claims = crate::domain::oidc::IdTokenClaims {
        iss: state.config.server.public_url.clone(),
        sub: user.id,
        aud: client.client_id.clone(),
        azp: client.client_id.clone(),
        exp: now
            .saturating_add(i64::try_from(state.config.jwt.access_expiry_secs).unwrap_or(i64::MAX)),
        iat: now,
        // When the user last proved their password for the consent, not when
        // the session was opened.
        auth_time: tokens
            .session
            .auth_time
            .unwrap_or(tokens.session.family_created_at)
            .unix_timestamp(),
        nonce,
        at_hash: crate::domain::oidc::at_hash(&tokens.access_token),
        profile: crate::domain::oidc::user_claims(&user, &scopes),
    };
    crate::utils::jwt::encode_claims(&claims, &state.jwt_signing_key, Some(&state.jwt_kid))
        .map_err(|e| AppError::Internal(e.into()))
}

/// The UserInfo response (OIDC Core 5.3) for an access token of a session
/// granted `openid`.
pub async fn userinfo(
    state: &AppState,
    user_id: Uuid,
    session_id: Uuid,
) -> Result<serde_json::Value, AppError> {
    let session = crate::repositories::session::find_by_id(&state.db, session_id)
        .await?
        .ok_or(AppError::Unauthorized)?;
    if !crate::domain::oidc::requests_identity(session.scopes.as_deref()) {
        return Err(AppError::Forbidden);
    }
    let user = crate::repositories::user::find_by_id(&state.db, user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let claims =
        crate::domain::oidc::user_claims(&user, session.scopes.as_deref().unwrap_or_default());
    let mut response = serde_json::to_value(claims).map_err(|e| AppError::Internal(e.into()))?;
    if let serde_json::Value::Object(object) = &mut response {
        object.insert("sub".into(), serde_json::Value::String(user.id.to_string()));
    }
    Ok(response)
}

/// A token for the client itself (RFC 6749 section 4.4): no user, no session,
/// no refresh token; the permissions of its scopes, narrowed by `scope`.
async fn client_credentials(
    state: &AppState,
    client: &RegisteredClient,
    scope: Option<&str>,
) -> Result<TokenResponse, EndpointError> {
    if !client.is_confidential() || !client.allows_client_credentials {
        return Err(OAuthError::new(
            ErrorCode::UnauthorizedClient,
            "this client may not use the client credentials grant",
        )
        .into());
    }
    // No user takes part: the OpenID Connect scopes, which describe one, have
    // no meaning here and are refused rather than issued as permissions.
    if scope.is_some_and(|scope| {
        scope
            .split_ascii_whitespace()
            .any(crate::domain::oidc::is_oidc_scope)
    }) {
        return Err(OAuthError::new(
            ErrorCode::InvalidScope,
            "OpenID Connect scopes need a user: not with the client credentials grant",
        )
        .into());
    }
    let mut scopes = check_scopes(state, client, scope)
        .await?
        .map_err(|message| OAuthError::new(ErrorCode::InvalidScope, message))?
        .unwrap_or_default();
    scopes.retain(|scope| !crate::domain::oidc::is_oidc_scope(scope));

    let issuer = state.config.server.public_url.clone();
    let now = state.clock.now().unix_timestamp();
    let expires_in = state.config.jwt.access_expiry_secs;
    let mut claims = crate::utils::jwt::Claims::new(
        oauth::client_subject(&issuer, &client.client_id),
        Uuid::nil(),
        now,
        now.saturating_add(i64::try_from(expires_in).unwrap_or(i64::MAX)),
    )
    .with_rbac(Vec::new(), scopes.clone());
    claims.client_id = Some(client.client_id.clone());
    claims.sub_type = Some("client".to_owned());
    claims.iss = Some(issuer);
    claims.aud = state.config.jwt.audience.clone();
    let access_token =
        crate::utils::jwt::encode_token(&claims, &state.jwt_signing_key, Some(&state.jwt_kid))
            .map_err(|e| AppError::Internal(e.into()))?;
    metrics::counter!("auth_client_credentials_tokens_total").increment(1);

    Ok(TokenResponse {
        access_token,
        refresh_token: None,
        scopes: Some(scopes),
        expires_in,
        id_token: None,
    })
}

// Device authorization

pub async fn device_authorization(
    state: &AppState,
    authorization: Option<&str>,
    parameters: &[(String, String)],
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
) -> Result<device_svc::DeviceInitResponse, EndpointError> {
    let client = authenticate_client(state, authorization, parameters, ip).await?;
    let scopes = check_scopes(state, &client, oauth::parameter(parameters, "scope"))
        .await?
        .map_err(|message| OAuthError::new(ErrorCode::InvalidScope, message))?;
    Ok(device_svc::initiate(state, ip, user_agent, &client, scopes).await?)
}

// Introspection (RFC 7662) and revocation (RFC 7009)

/// What introspection says about a token. `None` fields are left out.
#[derive(Debug, Default, Serialize, utoipa::ToSchema)]
pub struct Introspection {
    pub active: bool,
    /// `access_token` or `refresh_token`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<&'static str>,
    /// For a user's token, the session it comes from: `web`, `device`, or
    /// `personal_access_token` for a script.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_type: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<Uuid>,
}

/// The kind of a presented token, from its shape.
enum Presented<'a> {
    Access(&'a str),
    Personal,
    Refresh(&'a str),
}

fn classify(token: &str) -> Presented<'_> {
    if crate::domain::personal_access_token::random_part(token).is_some() {
        Presented::Personal
    } else if token.split('.').count() == 3 {
        Presented::Access(token)
    } else {
        Presented::Refresh(token)
    }
}

/// Introspect a token for a confidential client (a resource server). Anything
/// unknown, expired or revoked is `{ "active": false }` and nothing more.
pub async fn introspect(
    state: &AppState,
    authorization: Option<&str>,
    parameters: &[(String, String)],
    ip: Option<IpNetwork>,
) -> Result<Introspection, EndpointError> {
    let client = authenticate_client(state, authorization, parameters, ip).await?;
    if !client.is_confidential() {
        return Err(OAuthError::new(
            ErrorCode::UnauthorizedClient,
            "introspection is reserved to confidential clients",
        )
        .into());
    }
    let token = oauth::parameter(parameters, "token")
        .ok_or_else(|| OAuthError::new(ErrorCode::InvalidRequest, "token is required"))?;
    let now = state.clock.now();

    let introspection = match classify(token) {
        Presented::Access(jwt) => {
            let Some(claims) = verified_claims(state, jwt) else {
                return Ok(Introspection::default());
            };
            // A resource server introspects anyone's access tokens; another
            // confidential client only its own: it has no business learning
            // what other tokens are worth.
            if !client.allows_introspection
                && claims.client_id.as_deref() != Some(client.client_id.as_str())
            {
                return Ok(Introspection::default());
            }
            let active = match claims.client_id.as_deref() {
                // A client credentials token: active while not revoked and the
                // client may still use the grant.
                Some(client_id) if claims.sid.is_nil() => {
                    !auth_svc::is_jti_blocked(state, claims.jti).await?
                        && crate::repositories::registered_client::find_by_id(&state.db, client_id)
                            .await?
                            .is_some_and(|c| c.allows_client_credentials)
                }
                _ => auth_svc::verify_token_state(state, claims.jti, claims.sid)
                    .await
                    .is_ok(),
            };
            if !active {
                return Ok(Introspection::default());
            }
            let session = if claims.sid.is_nil() {
                None
            } else {
                crate::repositories::session::find_by_id(&state.db, claims.sid).await?
            };
            let session_client = claims
                .client_id
                .clone()
                .or_else(|| session.as_ref().and_then(|s| s.client_id.clone()));
            // A resource server registered with scopes learns only those.
            let scope: Vec<&str> = claims
                .permissions
                .iter()
                .filter(|p| client.scopes.is_empty() || client.scopes.contains(p))
                .map(String::as_str)
                .collect();
            Introspection {
                active: true,
                token_type: Some("access_token"),
                session_type: session.map(|s| s.session_type.as_str()),
                scope: Some(scope.join(" ")).filter(|s| !s.is_empty()),
                client_id: session_client,
                sub: Some(claims.sub),
                exp: Some(claims.exp),
                iat: Some(claims.iat),
                iss: claims.iss,
                aud: Some(claims.aud).filter(|aud| !aud.is_empty()),
                jti: Some(claims.jti),
            }
        }
        Presented::Refresh(raw) => {
            let Some(session) = crate::repositories::session::find_by_token_hash(
                &state.db,
                &crypto::sha256(raw.as_bytes()),
            )
            .await?
            .filter(|s| s.is_active(now) && s.rotated_at.is_none())
            // A refresh token is its client's secret: only that client learns
            // anything of it.
            .filter(|s| s.client_id.as_deref() == Some(client.client_id.as_str())) else {
                return Ok(Introspection::default());
            };
            Introspection {
                active: true,
                token_type: Some("refresh_token"),
                scope: session.scopes.as_ref().map(|s| s.join(" ")),
                client_id: session.client_id,
                sub: Some(session.user_id),
                exp: Some(session.expires_at.unix_timestamp()),
                iat: Some(session.created_at.unix_timestamp()),
                ..Introspection::default()
            }
        }
        // Personal access tokens belong to accounts, not to clients.
        Presented::Personal => Introspection::default(),
    };
    Ok(introspection)
}

/// The claims of an access token this instance signed for itself, unexpired.
fn verified_claims(state: &AppState, jwt: &str) -> Option<crate::utils::jwt::Claims> {
    let claims = crate::utils::jwt::decode_token_with_keys(
        jwt,
        &state.jwt_verifying_keys,
        state.clock.now().unix_timestamp(),
    )
    .ok()?;
    let issuer = state.config.server.public_url.as_str();
    crate::utils::jwt::validate_iss_aud(&claims, issuer, issuer).ok()?;
    Some(claims)
}

/// Revoke a token issued to the requesting client. Unknown tokens, and tokens
/// of other clients, are answered the same way and left alone (RFC 7009
/// section 2.2): the answer reveals nothing.
pub async fn revoke(
    state: &AppState,
    authorization: Option<&str>,
    parameters: &[(String, String)],
    ip: Option<IpNetwork>,
) -> Result<(), EndpointError> {
    let client = authenticate_client(state, authorization, parameters, ip).await?;
    let token = oauth::parameter(parameters, "token")
        .ok_or_else(|| OAuthError::new(ErrorCode::InvalidRequest, "token is required"))?;
    let owned = |session: &crate::domain::session::Session| {
        session.client_id.as_deref() == Some(&client.client_id)
    };

    match classify(token) {
        Presented::Access(jwt) => {
            let Some(claims) = verified_claims(state, jwt) else {
                return Ok(());
            };
            if claims.sid.is_nil() {
                if claims.client_id.as_deref() == Some(&client.client_id) {
                    auth_svc::blocklist_jti(state, claims.jti, claims.exp).await;
                }
                return Ok(());
            }
            if let Some(session) =
                crate::repositories::session::find_by_id(&state.db, claims.sid).await?
                && owned(&session)
            {
                auth_svc::blocklist_jti(state, claims.jti, claims.exp).await;
            }
        }
        Presented::Refresh(raw) => {
            if let Some(session) = crate::repositories::session::find_by_token_hash(
                &state.db,
                &crypto::sha256(raw.as_bytes()),
            )
            .await?
                && owned(&session)
                && session.revoked_at.is_none()
            {
                // The access tokens of the grant end with its session.
                crate::repositories::session::revoke(&state.db, session.id).await?;
                auth_svc::invalidate_session_caches(state, &[session.id]).await;
                auth_svc::blocklist_refresh_token(state, &session.token_hash, session.expires_at)
                    .await;
                crate::repositories::audit::append(
                    &state.db,
                    &crate::repositories::audit::NewAuditEntry {
                        user_id: Some(session.user_id),
                        request_id: None,
                        action: crate::domain::audit::AuditAction::SessionRevoked,
                        ip_address: ip,
                        metadata: serde_json::json!({
                            "session_id": session.id,
                            "by": "client",
                            "client_id": client.client_id,
                        }),
                    },
                )
                .await?;
            }
        }
        // Personal access tokens belong to accounts, not clients.
        Presented::Personal => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_states_read_the_same_to_a_client() {
        let descriptions: Vec<Option<String>> = [
            AppError::AccountSuspended,
            AppError::AccountInactive,
            AppError::AccountLocked,
            AppError::EmailNotVerified,
        ]
        .into_iter()
        .map(|error| match EndpointError::from(error) {
            EndpointError::OAuth(error) => {
                assert_eq!(error.code, ErrorCode::InvalidGrant);
                error.description
            }
            EndpointError::App(_) => panic!("not an OAuth error"),
        })
        .collect();
        assert!(descriptions.windows(2).all(|pair| pair[0] == pair[1]));
    }
}
