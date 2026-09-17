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
        Self::OAuth(OAuthError::new(code, error.to_string()))
    }
}

impl From<sqlx::Error> for EndpointError {
    fn from(error: sqlx::Error) -> Self {
        Self::App(error.into())
    }
}

// Client authentication

/// The client making a token or device authorization request: authenticated
/// with its secret when it has one (`client_secret_basic` or
/// `client_secret_post`), identified by `client_id` when it is public.
pub async fn authenticate_client(
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

    let Some(client) =
        crate::repositories::registered_client::find_by_id(&state.db, &client_id).await?
    else {
        return Err(invalid("unknown client", basic.is_some()));
    };
    match (&client.client_secret_hash, secret) {
        (Some(expected), Some(secret)) => {
            let presented = crypto::sha256(secret.as_bytes());
            if !constant_time_eq(&presented, expected) {
                return Err(invalid("client authentication failed", basic.is_some()));
            }
        }
        (Some(_), None) => {
            return Err(invalid("this client must authenticate", basic.is_some()));
        }
        (None, Some(_)) => {
            return Err(invalid("this client has no secret", basic.is_some()));
        }
        (None, None) => {}
    }
    Ok(client)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// Authorization requests

#[derive(Debug, Serialize, Deserialize)]
struct StoredRequest {
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    scopes: Option<Vec<String>>,
    state: Option<String>,
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
    let refuse = |code: ErrorCode, description: &str| {
        let mut response = vec![("error", code.as_str()), ("error_description", description)];
        if let Some(client_state) = client_state {
            response.push(("state", client_state));
        }
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
    if param("response_type") != Some("code") {
        return refuse(
            ErrorCode::UnsupportedResponseType,
            "only the code response type is supported",
        );
    }
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
        let unknown = role_repo::unknown_permissions(&state.db, scopes).await?;
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

async fn load_request(
    state: &AppState,
    id: &str,
) -> Result<(StoredRequest, RegisteredClient), AppError> {
    let mut conn = state
        .redis
        .get()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    let raw: Option<String> = conn
        .get(request_key(id))
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    let request: StoredRequest = serde_json::from_str(&raw.ok_or(AppError::NotFound)?)
        .map_err(|e| AppError::Internal(e.into()))?;
    let client = authorize_svc::load_client(state, &request.client_id)
        .await
        .map_err(|_| AppError::NotFound)?;
    Ok((request, client))
}

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
    let description =
        authorize_svc::describe(state, user_id, &client, request.scopes.as_deref()).await?;
    Ok(RequestDescription {
        request: description,
        redirect_uri: request.redirect_uri,
        reauthentication_required: authorize_svc::requires_reauthentication(
            state, session_id, &client,
        )
        .await,
    })
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
    // The password is checked before the request is taken: a missing or wrong
    // one leaves the request to approve once the user has confirmed it.
    if !client.is_primary {
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
    }
    take_request(state, id).await?;
    let approval = authorize_svc::Approval {
        user_id,
        session_id,
        client: &client,
        redirect_uri: &request.redirect_uri,
        code_challenge: &request.code_challenge,
        requested: request.scopes.as_deref(),
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
    oauth::redirect_with(&request.redirect_uri, &response)
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("stored redirect_uri does not parse")))
}

/// Deny a request: the redirect carrying `access_denied`.
pub async fn deny_request(state: &AppState, id: &str) -> Result<String, AppError> {
    let (request, _) = load_request(state, id).await?;
    take_request(state, id).await?;
    let mut response = vec![
        ("error", ErrorCode::AccessDenied.as_str()),
        ("error_description", "the user denied the request"),
    ];
    if let Some(client_state) = request.state.as_deref() {
        response.push(("state", client_state));
    }
    oauth::redirect_with(&request.redirect_uri, &response)
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("stored redirect_uri does not parse")))
}

// Token endpoint

/// RFC 6749 section 5.1.
pub struct TokenResponse {
    pub tokens: AuthTokens,
    pub expires_in: u64,
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
    ]
    .contains(&grant_type)
    {
        return Err(OAuthError::new(
            ErrorCode::UnsupportedGrantType,
            format!("unsupported grant_type {grant_type}"),
        )
        .into());
    }
    let client = authenticate_client(state, authorization, parameters).await?;
    let required = |name: &'static str| {
        param(name).ok_or_else(|| {
            EndpointError::OAuth(OAuthError::new(
                ErrorCode::InvalidRequest,
                format!("{name} is required"),
            ))
        })
    };
    let device_name = param("device_name");

    let tokens = match grant_type {
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
        oauth::GRANT_REFRESH_TOKEN => {
            auth_svc::refresh_token(
                state,
                required("refresh_token")?,
                Some(&client.client_id),
                ip,
                user_agent,
                None,
            )
            .await?
        }
        _ => {
            device_svc::poll(
                state,
                required("device_code")?,
                &client.client_id,
                ip,
                user_agent,
                device_name,
            )
            .await?
        }
    };
    Ok(TokenResponse {
        tokens,
        expires_in: state.config.jwt.access_expiry_secs,
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
    let client = authenticate_client(state, authorization, parameters).await?;
    let scopes = check_scopes(state, &client, oauth::parameter(parameters, "scope"))
        .await?
        .map_err(|message| OAuthError::new(ErrorCode::InvalidScope, message))?;
    Ok(device_svc::initiate(state, ip, user_agent, &client, scopes).await?)
}
