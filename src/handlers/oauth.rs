//! OAuth 2.1 endpoints: metadata, authorization, token, device authorization,
//! and the routes the auth frontend uses to approve requests.

use axum::{
    Json,
    body::Bytes,
    extract::{Path, RawQuery, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    domain::oauth::{self, ErrorCode},
    error::AppError,
    repositories::role as role_repo,
    services::{
        device as device_svc,
        oauth::{self as oauth_svc, AuthorizeOutcome, EndpointError, OAuthError},
    },
    state::AppState,
};

use super::extractors::{AuthUser, ClientIp, UserAgent};

/// RFC 6749 section 5.2.
#[derive(Serialize, utoipa::ToSchema)]
pub struct OAuthErrorBody {
    /// `invalid_request`, `invalid_client`, `invalid_grant`, ...
    pub error: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

impl IntoResponse for EndpointError {
    fn into_response(self) -> Response {
        match self {
            Self::App(error) => error.into_response(),
            Self::OAuth(error) => {
                let status =
                    StatusCode::from_u16(error.status()).unwrap_or(StatusCode::BAD_REQUEST);
                let mut response = (
                    status,
                    [
                        (header::CACHE_CONTROL, "no-store"),
                        (header::PRAGMA, "no-cache"),
                    ],
                    Json(OAuthErrorBody {
                        error: error.code.as_str(),
                        error_description: error.description,
                    }),
                )
                    .into_response();
                if error.basic_challenge {
                    response.headers_mut().insert(
                        header::WWW_AUTHENTICATE,
                        HeaderValue::from_static("Basic realm=\"auth-api\""),
                    );
                }
                response
            }
        }
    }
}

/// RFC 6749 section 5.1.
#[derive(Serialize, utoipa::ToSchema)]
pub struct OAuthTokenResponse {
    pub access_token: String,
    /// Always `Bearer`.
    pub token_type: &'static str,
    /// Seconds.
    pub expires_in: u64,
    pub refresh_token: String,
    /// Space-separated scopes the token carries; absent when unrestricted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// Form fields of `POST /oauth/token`, for the document.
#[derive(Deserialize, utoipa::ToSchema)]
pub struct OAuthTokenRequest {
    /// `authorization_code`, `refresh_token` or
    /// `urn:ietf:params:oauth:grant-type:device_code`.
    pub grant_type: String,
    pub client_id: Option<String>,
    /// `client_secret_post`; or use `Authorization: Basic`.
    pub client_secret: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
    pub device_code: Option<String>,
    /// Label of the new session in the account's session list.
    pub device_name: Option<String>,
}

/// Form fields of `POST /oauth/device_authorization`, for the document.
#[derive(Deserialize, utoipa::ToSchema)]
pub struct DeviceAuthorizationRequest {
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    /// Space-separated permissions; omitted, the client's registered scopes.
    pub scope: Option<String>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct AuthorizationRequestResponse {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uri: String,
    /// Permissions the approval would grant.
    pub scopes: Vec<String>,
    /// The request names no scope and the client has none: the session would
    /// carry every permission of the user.
    pub unrestricted: bool,
    /// Requested scopes the user does not hold.
    pub unavailable_scopes: Vec<String>,
    pub sessions_used: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sessions_allowed: Option<i64>,
    /// Approving needs `current_password` (or a recent `POST /users/me/reauth`).
    pub reauthentication_required: bool,
}

#[derive(Deserialize, Default, utoipa::ToSchema)]
pub struct ApproveAuthorizationRequest {
    pub current_password: Option<String>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct AuthorizationDecisionResponse {
    /// Where to send the browser: the client's redirect URI with the response.
    pub redirect_to: String,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct DeviceVerifyRequest {
    pub user_code: String,
    #[serde(default = "default_approve")]
    pub approve: bool,
}

fn default_approve() -> bool {
    true
}

fn form(headers: &HeaderMap, body: &[u8]) -> Result<Vec<(String, String)>, EndpointError> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if !content_type
        .to_ascii_lowercase()
        .starts_with("application/x-www-form-urlencoded")
    {
        return Err(OAuthError::new(
            ErrorCode::InvalidRequest,
            "the body must be application/x-www-form-urlencoded",
        )
        .into());
    }
    oauth::form_parameters(body)
        .map_err(|message| OAuthError::new(ErrorCode::InvalidRequest, message).into())
}

fn authorization(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
}

#[utoipa::path(
    get,
    path = "/.well-known/oauth-authorization-server",
    tag = "oauth",
    responses(
        (status = 200, description = "Authorization server metadata (RFC 8414)", body = Object),
    ),
)]
pub async fn metadata(State(state): State<AppState>) -> Result<impl IntoResponse, AppError> {
    let issuer = state
        .config
        .server
        .public_url
        .trim_end_matches('/')
        .to_owned();
    let scopes: Vec<String> = role_repo::find_all_permissions(&state.db)
        .await?
        .into_iter()
        .map(|p| p.name)
        .collect();
    Ok((
        [(header::CACHE_CONTROL, "public, max-age=300")],
        Json(json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/oauth/authorize"),
            "token_endpoint": format!("{issuer}/oauth/token"),
            "device_authorization_endpoint": format!("{issuer}/oauth/device_authorization"),
            "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
            "scopes_supported": scopes,
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": [
                oauth::GRANT_AUTHORIZATION_CODE,
                oauth::GRANT_REFRESH_TOKEN,
                oauth::GRANT_DEVICE_CODE,
            ],
            "token_endpoint_auth_methods_supported": ["none", "client_secret_basic", "client_secret_post"],
            "code_challenge_methods_supported": ["S256"],
            "authorization_response_iss_parameter_supported": false,
        })),
    ))
}

#[utoipa::path(
    get,
    path = "/oauth/authorize",
    tag = "oauth",
    params(
        ("response_type" = String, Query, description = "`code`"),
        ("client_id" = String, Query, description = "Registered client"),
        ("redirect_uri" = Option<String>, Query, description = "A registered redirect URI; optional when the client has exactly one"),
        ("code_challenge" = String, Query, description = "S256 PKCE challenge"),
        ("code_challenge_method" = String, Query, description = "`S256`"),
        ("scope" = Option<String>, Query, description = "Space-separated permissions; omitted, the client's registered scopes"),
        ("state" = Option<String>, Query, description = "Echoed back, at most 512 bytes"),
    ),
    responses(
        (status = 303, description = "To the consent page (`OAUTH_CONSENT_URI?request_id=...`), or back to the client with `error`"),
        (status = 400, description = "Unknown client or unregistered redirect URI: never redirected", body = OAuthErrorBody),
        (status = 401, description = "Unknown client", body = OAuthErrorBody),
    ),
)]
pub async fn authorize(
    State(state): State<AppState>,
    RawQuery(query): RawQuery,
) -> Result<Response, EndpointError> {
    let parameters = oauth::form_parameters(query.unwrap_or_default().as_bytes())
        .map_err(|message| OAuthError::new(ErrorCode::InvalidRequest, message))?;
    let location = match oauth_svc::start_authorization(&state, &parameters).await? {
        AuthorizeOutcome::Consent(id) => oauth::redirect_with(
            &state.config.device_auth.consent_uri,
            &[("request_id", &id)],
        )
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("OAUTH_CONSENT_URI does not parse")))?,
        AuthorizeOutcome::Refused(location) => location,
    };
    Ok(Redirect::to(&location).into_response())
}

#[utoipa::path(
    get,
    path = "/oauth/authorization-requests/{id}",
    tag = "oauth",
    params(("id" = String, Path, description = "`request_id` given to the consent page")),
    responses(
        (status = 200, description = "What the consent page shows", body = AuthorizationRequestResponse),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 404, description = "Unknown, decided or expired request", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn describe_request(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<AuthorizationRequestResponse>, AppError> {
    let described = oauth_svc::describe_request(&state, auth.user_id, auth.session_id, &id).await?;
    let request = described.request;
    Ok(Json(AuthorizationRequestResponse {
        client_id: request.client_id,
        client_name: request.client_name,
        redirect_uri: described.redirect_uri,
        scopes: request.scopes,
        unrestricted: request.unrestricted,
        unavailable_scopes: request.unavailable_scopes,
        sessions_used: request.sessions_used,
        sessions_allowed: request.sessions_allowed,
        reauthentication_required: described.reauthentication_required,
    }))
}

#[utoipa::path(
    post,
    path = "/oauth/authorization-requests/{id}/approve",
    tag = "oauth",
    params(("id" = String, Path, description = "`request_id` given to the consent page")),
    request_body = Option<ApproveAuthorizationRequest>,
    responses(
        (status = 200, description = "Approved; send the browser to `redirect_to`", body = AuthorizationDecisionResponse),
        (status = 401, description = "Missing, invalid or revoked access token, or wrong password", body = crate::error::ErrorBody),
        (status = 403, description = "Re-authentication required, or account unusable", body = crate::error::ErrorBody),
        (status = 404, description = "Unknown, decided or expired request", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn approve_request(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    auth: AuthUser,
    Path(id): Path<String>,
    body: Option<Json<ApproveAuthorizationRequest>>,
) -> Result<Json<AuthorizationDecisionResponse>, AppError> {
    let current_password = body.and_then(|Json(b)| b.current_password);
    let redirect_to = oauth_svc::approve_request(
        &state,
        auth.user_id,
        auth.session_id,
        &id,
        current_password.as_deref(),
        ip,
        auth.request_id,
    )
    .await?;
    Ok(Json(AuthorizationDecisionResponse { redirect_to }))
}

#[utoipa::path(
    post,
    path = "/oauth/authorization-requests/{id}/deny",
    tag = "oauth",
    params(("id" = String, Path, description = "`request_id` given to the consent page")),
    responses(
        (status = 200, description = "Denied; send the browser to `redirect_to`", body = AuthorizationDecisionResponse),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 404, description = "Unknown, decided or expired request", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn deny_request(
    State(state): State<AppState>,
    _auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<AuthorizationDecisionResponse>, AppError> {
    let redirect_to = oauth_svc::deny_request(&state, &id).await?;
    Ok(Json(AuthorizationDecisionResponse { redirect_to }))
}

#[utoipa::path(
    post,
    path = "/oauth/token",
    tag = "oauth",
    request_body(content = OAuthTokenRequest, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "Tokens (RFC 6749 section 5.1)", body = OAuthTokenResponse),
        (status = 400, description = "`invalid_request`, `invalid_grant`, `unsupported_grant_type`, `authorization_pending`, `slow_down`, `expired_token`, `access_denied`", body = OAuthErrorBody),
        (status = 401, description = "`invalid_client`", body = OAuthErrorBody),
    ),
)]
pub async fn token(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    UserAgent(ua): UserAgent,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, EndpointError> {
    let parameters = form(&headers, &body)?;
    let issued = oauth_svc::token(
        &state,
        authorization(&headers),
        &parameters,
        ip,
        ua.as_deref(),
    )
    .await?;
    let scope = issued.tokens.session.scopes.as_ref().map(|s| s.join(" "));
    Ok((
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(OAuthTokenResponse {
            access_token: issued.tokens.access_token,
            token_type: "Bearer",
            expires_in: issued.expires_in,
            refresh_token: issued.tokens.refresh_token,
            scope,
        }),
    )
        .into_response())
}

#[utoipa::path(
    post,
    path = "/oauth/device_authorization",
    tag = "oauth",
    request_body(content = DeviceAuthorizationRequest, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "Flow started (RFC 8628 section 3.2)", body = device_svc::DeviceInitResponse),
        (status = 400, description = "`invalid_request` or `invalid_scope`", body = OAuthErrorBody),
        (status = 401, description = "`invalid_client`", body = OAuthErrorBody),
    ),
)]
pub async fn device_authorization(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    UserAgent(ua): UserAgent,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, EndpointError> {
    let parameters = form(&headers, &body)?;
    let started = oauth_svc::device_authorization(
        &state,
        authorization(&headers),
        &parameters,
        ip,
        ua.as_deref(),
    )
    .await?;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(started)).into_response())
}

#[utoipa::path(
    get,
    path = "/oauth/device/{user_code}",
    tag = "oauth",
    params(("user_code" = String, Path, description = "Code shown on the device, XXXX-9999")),
    responses(
        (status = 200, description = "What the user is about to approve", body = device_svc::DevicePreview),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 404, description = "Unknown or expired code", body = crate::error::ErrorBody),
        (status = 409, description = "Already decided", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn describe_device(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    _auth: AuthUser,
    Path(user_code): Path<String>,
) -> Result<Json<device_svc::DevicePreview>, AppError> {
    validate_user_code(&user_code)?;
    Ok(Json(device_svc::describe(&state, &user_code, ip).await?))
}

#[utoipa::path(
    post,
    path = "/oauth/device/verify",
    tag = "oauth",
    request_body = DeviceVerifyRequest,
    responses(
        (status = 200, description = "Decision recorded"),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 404, description = "Unknown or expired code", body = crate::error::ErrorBody),
        (status = 409, description = "Already decided", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn verify_device(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    auth: AuthUser,
    Json(body): Json<DeviceVerifyRequest>,
) -> Result<StatusCode, AppError> {
    validate_user_code(&body.user_code)?;
    if body.approve {
        device_svc::verify(&state, auth.user_id, &body.user_code, ip).await?;
    } else {
        device_svc::deny(&state, &body.user_code, ip).await?;
    }
    Ok(StatusCode::OK)
}

pub(crate) fn validate_user_code(code: &str) -> Result<(), AppError> {
    let parts: Vec<&str> = code.split('-').collect();
    if parts.len() != 2 || parts[0].len() != 4 || parts[1].len() != 4 {
        return Err(AppError::Validation(
            "user_code must be in XXXX-XXXX format".into(),
        ));
    }
    if !parts[0].chars().all(|c| c.is_ascii_uppercase())
        || !parts[1].chars().all(|c| c.is_ascii_digit())
    {
        return Err(AppError::Validation("invalid user_code format".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_user_code_accepts_valid_format() {
        assert!(validate_user_code("ABCD-2345").is_ok());
        assert!(validate_user_code("WXYZ-6789").is_ok());
    }

    #[test]
    fn validate_user_code_rejects_malformed_codes() {
        for code in [
            "abcd-2345",
            "ABC-2345",
            "ABCDE-2345",
            "ABCD-234",
            "ABCD2345",
            "ABCD-23AB",
            "AB12-2345",
        ] {
            assert!(validate_user_code(code).is_err(), "{code} must be rejected");
        }
    }
}
