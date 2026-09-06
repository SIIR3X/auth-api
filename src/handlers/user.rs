//! User profile handlers: read and update the authenticated user's profile.

use axum::{Json, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    error::AppError,
    services::{email_change as email_change_svc, reauth as reauth_svc, user as user_svc},
    state::AppState,
};

use super::extractors::{AuthUser, ClientIp};

// Request types

#[derive(Deserialize, utoipa::ToSchema)]
pub struct ChangeUsernameRequest {
    pub username: String,
    pub current_password: Option<String>,
}

/// Optional body for sensitive actions that accept the current password in
/// place of a recent re-authentication.
#[derive(Deserialize, Default, utoipa::ToSchema)]
pub struct CurrentPasswordRequest {
    pub current_password: Option<String>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct FlowTokenResponse {
    pub flow_token: String,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct VerifyCurrentEmailRequest {
    pub flow_token: String,
    pub code: String,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct SubmitNewEmailRequest {
    pub flow_token: String,
    pub new_email: String,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct ConfirmNewEmailRequest {
    pub flow_token: String,
    pub code: String,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct ChangePasswordRequest {
    pub current_password: Option<String>,
    pub new_password: String,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct ChangeLocaleRequest {
    pub locale: String,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct DeleteAccountRequest {
    pub current_password: Option<String>,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct ReauthenticateRequest {
    pub current_password: String,
}

// Response types

#[derive(Serialize, utoipa::ToSchema)]
pub struct UserResponse {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub status: String,
    pub preferred_locale: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_login_at: Option<i64>,
    pub created_at: i64,
}

// Handlers

#[utoipa::path(
    get,
    path = "/users/me",
    tag = "account",
    responses(
        (status = 200, description = "The caller's profile", body = UserResponse),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn me(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<UserResponse>, AppError> {
    let user = user_svc::get_profile(&state, auth.user_id).await?;

    Ok(Json(UserResponse {
        id: user.id,
        username: user.username,
        email: user.email,
        status: user_status_str(&user.status),
        preferred_locale: user.preferred_locale,
        email_verified_at: user.email_verified_at.map(|t| t.unix_timestamp()),
        last_login_at: user.last_login_at.map(|t| t.unix_timestamp()),
        created_at: user.created_at.unix_timestamp(),
    }))
}

#[utoipa::path(
    patch,
    path = "/users/me/username",
    tag = "account",
    request_body = ChangeUsernameRequest,
    responses(
        (status = 204, description = "Username changed"),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Recent re-authentication required", body = crate::error::ErrorBody),
        (status = 409, description = "Username taken", body = crate::error::ErrorBody),
        (status = 422, description = "Invalid input", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn change_username(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    auth: AuthUser,
    Json(body): Json<ChangeUsernameRequest>,
) -> Result<StatusCode, AppError> {
    super::auth::validate_username(&body.username)?;

    reauth_svc::require_recent_reauth_or_password(
        &state,
        auth.user_id,
        auth.session_id,
        body.current_password.as_deref(),
        ip,
        auth.request_id,
        "change_username",
    )
    .await?;

    user_svc::change_username(&state, auth.user_id, &body.username, ip, auth.request_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/users/me/email/start",
    tag = "email-change",
    request_body = Option<CurrentPasswordRequest>,
    responses(
        (status = 200, description = "Code sent to the current address", body = FlowTokenResponse),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Recent re-authentication required", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn start_email_change(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    auth: AuthUser,
    body: Option<Json<CurrentPasswordRequest>>,
) -> Result<Json<FlowTokenResponse>, AppError> {
    let body = body.map(|Json(b)| b).unwrap_or_default();
    let flow_token = email_change_svc::start(
        &state,
        auth.user_id,
        auth.session_id,
        body.current_password.as_deref(),
        ip,
        auth.request_id,
    )
    .await?;
    Ok(Json(FlowTokenResponse { flow_token }))
}

#[utoipa::path(
    post,
    path = "/users/me/email/verify-current",
    tag = "email-change",
    request_body = VerifyCurrentEmailRequest,
    responses(
        (status = 204, description = "Current address confirmed"),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn verify_current_email(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<VerifyCurrentEmailRequest>,
) -> Result<StatusCode, AppError> {
    email_change_svc::verify_current(&state, auth.user_id, &body.flow_token, &body.code).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/users/me/email/submit",
    tag = "email-change",
    request_body = SubmitNewEmailRequest,
    responses(
        (status = 204, description = "Code sent to the new address"),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 409, description = "Address taken", body = crate::error::ErrorBody),
        (status = 422, description = "Invalid input", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn submit_new_email(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    auth: AuthUser,
    Json(body): Json<SubmitNewEmailRequest>,
) -> Result<StatusCode, AppError> {
    super::auth::validate_email(&body.new_email)?;
    email_change_svc::submit_new(
        &state,
        auth.user_id,
        &body.flow_token,
        &body.new_email,
        ip,
        auth.request_id,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/users/me/email/confirm",
    tag = "email-change",
    request_body = ConfirmNewEmailRequest,
    responses(
        (status = 204, description = "Address changed; other sessions revoked"),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 409, description = "Address taken", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn confirm_new_email(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    auth: AuthUser,
    Json(body): Json<ConfirmNewEmailRequest>,
) -> Result<StatusCode, AppError> {
    email_change_svc::confirm_new(
        &state,
        auth.user_id,
        auth.session_id,
        &body.flow_token,
        &body.code,
        ip,
        auth.request_id,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    patch,
    path = "/users/me/password",
    tag = "account",
    request_body = ChangePasswordRequest,
    responses(
        (status = 204, description = "Password changed; other sessions revoked"),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Recent re-authentication required", body = crate::error::ErrorBody),
        (status = 422, description = "Invalid input", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn change_password(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    auth: AuthUser,
    Json(body): Json<ChangePasswordRequest>,
) -> Result<StatusCode, AppError> {
    validate_password(&body.new_password)?;

    user_svc::change_password(
        &state,
        auth.user_id,
        auth.session_id,
        body.current_password.as_deref(),
        &body.new_password,
        ip,
        auth.request_id,
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    patch,
    path = "/users/me/locale",
    tag = "account",
    request_body = ChangeLocaleRequest,
    responses(
        (status = 204, description = "Locale changed"),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 422, description = "Invalid input", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn change_locale(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<ChangeLocaleRequest>,
) -> Result<StatusCode, AppError> {
    validate_locale(&body.locale)?;
    user_svc::change_locale(&state, auth.user_id, &body.locale).await?;
    Ok(StatusCode::NO_CONTENT)
}

const SUPPORTED_LOCALES: &[&str] = &["en", "fr"];

pub fn validate_locale(locale: &str) -> Result<(), AppError> {
    if !SUPPORTED_LOCALES.contains(&locale) {
        return Err(AppError::Validation(format!(
            "unsupported locale; accepted values: {}",
            SUPPORTED_LOCALES.join(", ")
        )));
    }
    Ok(())
}

/// Validates a plaintext password against the application password policy.
///
/// Rules (all must be satisfied):
///   - at least 10 characters
///   - no more than 128 characters (Argon2id DoS guard)
///   - at least one ASCII digit (0-9)
///   - at least one ASCII uppercase letter (A-Z)
///   - at least one ASCII punctuation / symbol character
///
/// Note: NIST SP 800-63B recommends favouring length over composition rules.
/// These constraints are intentionally modest; raising the minimum length is
/// more effective than adding more character-class requirements.
pub fn validate_password(password: &str) -> Result<(), AppError> {
    // Characters, not bytes: an accented password of ten bytes may hold seven.
    if password.chars().count() < 10 {
        return Err(AppError::Validation(
            "password must be at least 10 characters".into(),
        ));
    }
    // The upper bound stays in bytes: sign-in refuses longer input before
    // hashing, so every accepted password must remain usable there.
    if password.len() > 128 {
        return Err(AppError::Validation(
            "password must not exceed 128 bytes".into(),
        ));
    }
    if !password.chars().any(|c| c.is_ascii_digit()) {
        return Err(AppError::Validation(
            "password must contain at least one digit (0-9)".into(),
        ));
    }
    if !password.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(AppError::Validation(
            "password must contain at least one uppercase letter (A-Z)".into(),
        ));
    }
    // is_ascii_punctuation covers: !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
    if !password.chars().any(|c| c.is_ascii_punctuation()) {
        return Err(AppError::Validation(
            "password must contain at least one special character (!@#$... etc.)".into(),
        ));
    }
    Ok(())
}

#[utoipa::path(
    delete,
    path = "/users/me",
    tag = "account",
    request_body = Option<DeleteAccountRequest>,
    responses(
        (status = 204, description = "Account deleted"),
        (status = 401, description = "Missing, invalid or revoked access token", body = crate::error::ErrorBody),
        (status = 403, description = "Recent re-authentication required", body = crate::error::ErrorBody),
    ),
    security(("bearer" = [])),
)]
pub async fn delete_account(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    auth: AuthUser,
    body: Option<Json<DeleteAccountRequest>>,
) -> Result<StatusCode, AppError> {
    let current_password = body.and_then(|Json(b)| b.current_password);
    user_svc::delete_account(
        &state,
        auth.user_id,
        auth.session_id,
        current_password.as_deref(),
        ip,
        auth.request_id,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/users/me/reauth",
    tag = "account",
    request_body = ReauthenticateRequest,
    responses(
        (status = 204, description = "Re-authenticated for SENSITIVE_ACTION_REAUTH_SECS"),
        (status = 401, description = "Wrong password or invalid token", body = crate::error::ErrorBody),
        (status = 403, description = "Too many wrong passwords: `account_locked` until the window ends", body = crate::error::ErrorBody),
        (status = 429, description = "Rate limited; see Retry-After"),
    ),
    security(("bearer" = [])),
)]
pub async fn reauthenticate(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    auth: AuthUser,
    Json(body): Json<ReauthenticateRequest>,
) -> Result<StatusCode, AppError> {
    user_svc::reauthenticate(
        &state,
        auth.user_id,
        auth.session_id,
        &body.current_password,
        ip,
        auth.request_id,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn user_status_str(status: &crate::domain::user::UserStatus) -> String {
    use crate::domain::user::UserStatus;
    match status {
        UserStatus::Active => "active",
        UserStatus::Inactive => "inactive",
        UserStatus::Suspended => "suspended",
        UserStatus::PendingVerification => "pending_verification",
    }
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_minimum_counts_characters_not_bytes() {
        // Found by the fuzzer: ten bytes, seven characters.
        assert!(validate_password("n@My\u{202E}e 1").is_err());
        assert!(validate_password("Ééééééé1!A").is_ok());
    }

    #[test]
    fn password_maximum_counts_bytes() {
        let longest = format!("A1!{}", "a".repeat(125));
        assert!(validate_password(&longest).is_ok());
        assert!(validate_password(&format!("{longest}a")).is_err());
        assert!(validate_password(&format!("A1!{}", "é".repeat(63))).is_err());
    }

    #[test]
    fn password_needs_every_character_class() {
        assert!(validate_password("Password1!").is_ok());
        assert!(validate_password("password1!").is_err());
        assert!(validate_password("Password!!").is_err());
        assert!(validate_password("Password11").is_err());
        assert!(validate_password("Password\u{0663}!").is_err());
    }

    mod properties {
        use proptest::prelude::*;

        use super::super::validate_password;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(1024))]

            #[test]
            fn the_password_policy_is_exactly_its_definition(
                password in prop_oneof!["\\PC{0,140}", "[A-Za-z0-9!?#é]{8,12}", "[a-z]{120,135}A1!"],
            ) {
                let expected = password.chars().count() >= 10
                    && password.len() <= 128
                    && password.chars().any(|c| c.is_ascii_digit())
                    && password.chars().any(|c| c.is_ascii_uppercase())
                    && password.chars().any(|c| c.is_ascii_punctuation());
                prop_assert_eq!(validate_password(&password).is_ok(), expected, "{:?}", password);
            }
        }
    }
}
