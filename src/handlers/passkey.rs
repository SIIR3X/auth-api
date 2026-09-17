//! Passkeys: `/users/me/passkeys` and `/auth/passkeys`.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    error::AppError,
    repositories::passkey::Passkey,
    services::passkey::{
        self as passkey_svc, AssertionResponse, AttestationResponse, CredentialResponse,
    },
    state::AppState,
};

use super::{
    extractors::{AuthUser, ClientIp, UserAgent},
    user::CurrentPasswordRequest,
};

#[derive(Deserialize, utoipa::ToSchema)]
pub struct RegisterPasskeyRequest {
    /// Label shown in the passkey list, such as "iPhone".
    pub name: String,
    /// The `PublicKeyCredential` returned by `navigator.credentials.create()`.
    pub credential: CredentialResponse<AttestationResponse>,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct PasskeySignInRequest {
    /// The `PublicKeyCredential` returned by `navigator.credentials.get()`.
    pub credential: CredentialResponse<AssertionResponse>,
    pub device_name: Option<String>,
    pub remember_me: Option<bool>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct PasskeyResponse {
    pub id: Uuid,
    pub name: String,
    /// COSE algorithm: -7 (ES256), -8 (EdDSA) or -257 (RS256).
    pub algorithm: i32,
    /// The passkey can be synced to other devices.
    pub backup_eligible: bool,
    pub backed_up: bool,
    pub created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<i64>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct RegisteredPasskeyResponse {
    pub passkey: PasskeyResponse,
    /// Shown once, when the account had no recovery code left.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_codes: Option<Vec<String>>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct PasskeySignInResponse {
    pub access_token: String,
    pub refresh_token: String,
}

fn passkey_response(passkey: Passkey) -> PasskeyResponse {
    PasskeyResponse {
        id: passkey.id,
        name: passkey.name,
        algorithm: passkey.algorithm,
        backup_eligible: passkey.backup_eligible,
        backed_up: passkey.backed_up,
        created_at: passkey.created_at.unix_timestamp(),
        last_used_at: passkey.last_used_at.map(|t| t.unix_timestamp()),
    }
}

#[utoipa::path(
    get,
    path = "/users/me/passkeys",
    tag = "passkeys",
    responses(
        (status = 200, description = "The account's passkeys", body = [PasskeyResponse]),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn list(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<PasskeyResponse>>, AppError> {
    let passkeys = passkey_svc::list(&state, auth.user_id).await?;
    Ok(Json(passkeys.into_iter().map(passkey_response).collect()))
}

#[utoipa::path(
    post,
    path = "/users/me/passkeys/options",
    tag = "passkeys",
    responses(
        (status = 200, description = "`PublicKeyCredentialCreationOptions` (JSON form) for `navigator.credentials.create()`; valid five minutes", body = Object),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Recent re-authentication required", body = crate::error::ErrorBody),
        (status = 409, description = "`too_many_passkeys`", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn registration_options(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    auth: AuthUser,
) -> Result<Json<Value>, AppError> {
    Ok(Json(
        passkey_svc::registration_options(
            &state,
            auth.user_id,
            auth.session_id,
            ip,
            auth.request_id,
        )
        .await?,
    ))
}

#[utoipa::path(
    post,
    path = "/users/me/passkeys",
    tag = "passkeys",
    request_body = RegisterPasskeyRequest,
    responses(
        (status = 201, description = "Passkey registered", body = RegisteredPasskeyResponse),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 409, description = "`passkey_already_registered`", body = crate::error::ErrorBody),
        (status = 422, description = "No pending registration, or the response does not verify", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn register(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    auth: AuthUser,
    Json(body): Json<RegisterPasskeyRequest>,
) -> Result<(StatusCode, Json<RegisteredPasskeyResponse>), AppError> {
    let registered = passkey_svc::register(
        &state,
        auth.user_id,
        auth.session_id,
        &body.name,
        &body.credential,
        ip,
        auth.request_id,
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(RegisteredPasskeyResponse {
            passkey: passkey_response(registered.passkey),
            recovery_codes: registered.recovery_codes,
        }),
    ))
}

#[utoipa::path(
    delete,
    path = "/users/me/passkeys/{id}",
    tag = "passkeys",
    params(("id" = Uuid, Path, description = "Passkey id")),
    request_body = Option<CurrentPasswordRequest>,
    responses(
        (status = 204, description = "Passkey removed"),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Recent re-authentication required", body = crate::error::ErrorBody),
        (status = 404, description = "No such passkey on this account", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn remove(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    auth: AuthUser,
    Path(id): Path<Uuid>,
    body: Option<Json<CurrentPasswordRequest>>,
) -> Result<StatusCode, AppError> {
    let current_password = body.and_then(|Json(b)| b.current_password);
    passkey_svc::remove(
        &state,
        auth.user_id,
        auth.session_id,
        id,
        current_password.as_deref(),
        ip,
        auth.request_id,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/auth/passkeys/options",
    tag = "passkeys",
    responses(
        (status = 200, description = "`PublicKeyCredentialRequestOptions` (JSON form) for `navigator.credentials.get()`; valid five minutes, used once", body = Object),
        (status = 429, description = "Rate limited; see Retry-After"),
    ),
)]
pub async fn authentication_options(
    State(state): State<AppState>,
) -> Result<Json<Value>, AppError> {
    Ok(Json(passkey_svc::authentication_options(&state).await?))
}

#[utoipa::path(
    post,
    path = "/auth/passkeys/sign-in",
    tag = "passkeys",
    request_body = PasskeySignInRequest,
    responses(
        (status = 200, description = "Signed in: a passkey with user verification needs no second factor", body = PasskeySignInResponse),
        (status = 401, description = "`invalid_credentials`: the assertion does not verify", body = crate::error::ErrorBody),
        (status = 403, description = "Account locked, suspended or inactive", body = crate::error::ErrorBody),
        (status = 429, description = "Rate limited; see Retry-After"),
    ),
)]
pub async fn sign_in(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    UserAgent(ua): UserAgent,
    Json(body): Json<PasskeySignInRequest>,
) -> Result<Json<PasskeySignInResponse>, AppError> {
    let tokens = passkey_svc::sign_in(
        &state,
        &body.credential,
        ip,
        ua.as_deref(),
        body.device_name.as_deref(),
        body.remember_me.unwrap_or(false),
        None,
    )
    .await?;
    Ok(Json(PasskeySignInResponse {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
    }))
}
