//! Centralized error type for the application.
//!
//! AppError covers every failure case the API can produce. Each variant maps
//! to a specific HTTP status and a stable machine-readable code returned in
//! the JSON body. Internal errors are logged server-side but never exposed
//! to the caller.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use std::borrow::Cow;

use serde::Serialize;
use tracing::error;

// Response body

/// Body of every error response.
#[derive(Serialize, utoipa::ToSchema)]
pub struct ErrorBody {
    /// Stable and machine-readable: `invalid_credentials`, `reauthentication_required`, ...
    code: &'static str,
    /// Human-readable explanation; may change between versions.
    #[schema(value_type = String)]
    message: Cow<'static, str>,
}

impl ErrorBody {
    fn new(code: &'static str, message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

// AppError

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    // 401
    #[error("authentication required")]
    Unauthorized,
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("invalid two-factor code")]
    TwoFactorFailed,
    #[error("token expired")]
    TokenExpired,
    #[error("token invalid")]
    TokenInvalid,
    #[error("re-authentication failed")]
    ReauthenticationFailed,

    // 403
    #[error("forbidden")]
    Forbidden,
    #[error("email not verified")]
    EmailNotVerified,
    #[error("account suspended")]
    AccountSuspended,
    #[error("account inactive")]
    AccountInactive,
    #[error("account locked")]
    AccountLocked,
    #[error("two-factor authentication required")]
    TwoFactorRequired,
    #[error("recent re-authentication required")]
    ReauthenticationRequired,

    // 404
    #[error("resource not found")]
    NotFound,

    // 409
    #[error("conflict: {0}")]
    Conflict(&'static str),

    // 422
    #[error("validation failed: {0}")]
    Validation(String),

    // 422 - CAPTCHA
    #[error("captcha verification failed")]
    CaptchaFailed,

    // 400 - Device authorization flow (RFC 8628)
    #[error("device authorization pending")]
    DeviceAuthPending,
    #[error("device code expired")]
    DeviceCodeExpired,
    #[error("device access denied")]
    DeviceAccessDenied,
    #[error("device polling too fast")]
    DeviceSlowDown,

    // 403 - Device session/client restrictions
    #[error("device session limit reached")]
    DeviceSessionLimitReached,
    #[error("device client not allowed")]
    DeviceClientNotAllowed,
    #[error("device client unknown")]
    DeviceClientUnknown,
    #[error("invalid authorization code")]
    InvalidAuthorizationCode,

    // 429
    #[error("rate limit exceeded")]
    RateLimitExceeded,

    // 503
    #[error("dependency unavailable: {0}")]
    ServiceUnavailable(&'static str),

    // 500 - message is logged, never sent to the caller
    #[error("internal error: {0}")]
    Internal(anyhow::Error),
}

impl AppError {
    /// Map a Postgres unique-constraint violation (SQLSTATE 23505) to a domain
    /// `Conflict`; any other database error becomes `Internal`.
    ///
    /// `mappings` pairs a constraint name with the stable conflict code to
    /// return, e.g. `("users_email_key", "email_taken")`. Used by write paths
    /// whose check-then-insert sequence can race with a concurrent request:
    /// the UNIQUE constraint is the authoritative check, so its violation must
    /// surface as the same 409 the pre-check would have produced.
    pub fn from_unique_violation(err: sqlx::Error, mappings: &[(&str, &'static str)]) -> Self {
        if let sqlx::Error::Database(ref db_err) = err
            && db_err.code().as_deref() == Some("23505")
            && let Some(constraint) = db_err.constraint()
            && let Some((_, code)) = mappings.iter().find(|(name, _)| *name == constraint)
        {
            return Self::Conflict(code);
        }

        Self::Internal(err.into())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            // 401
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                ErrorBody::new("unauthorized", "Authentication required."),
            ),
            Self::InvalidCredentials => (
                StatusCode::UNAUTHORIZED,
                ErrorBody::new("invalid_credentials", "Invalid email or password."),
            ),
            Self::TwoFactorFailed => (
                StatusCode::UNAUTHORIZED,
                ErrorBody::new("two_factor_failed", "Invalid two-factor code."),
            ),
            Self::TokenExpired => (
                StatusCode::UNAUTHORIZED,
                ErrorBody::new("token_expired", "This token has expired."),
            ),
            Self::TokenInvalid => (
                StatusCode::UNAUTHORIZED,
                ErrorBody::new("token_invalid", "This token is invalid."),
            ),
            Self::ReauthenticationFailed => (
                StatusCode::UNAUTHORIZED,
                ErrorBody::new(
                    "reauthentication_failed",
                    "The current password is incorrect.",
                ),
            ),

            // 403
            Self::Forbidden => (
                StatusCode::FORBIDDEN,
                ErrorBody::new(
                    "forbidden",
                    "You do not have permission to perform this action.",
                ),
            ),
            Self::EmailNotVerified => (
                StatusCode::FORBIDDEN,
                ErrorBody::new(
                    "email_not_verified",
                    "Please verify your email address first.",
                ),
            ),
            Self::AccountSuspended => (
                StatusCode::FORBIDDEN,
                ErrorBody::new("account_suspended", "This account has been suspended."),
            ),
            Self::AccountInactive => (
                StatusCode::FORBIDDEN,
                ErrorBody::new("account_inactive", "This account is inactive."),
            ),
            Self::AccountLocked => (
                StatusCode::FORBIDDEN,
                ErrorBody::new(
                    "account_locked",
                    "This account is temporarily locked due to too many failed login attempts.",
                ),
            ),
            Self::TwoFactorRequired => (
                StatusCode::FORBIDDEN,
                ErrorBody::new(
                    "two_factor_required",
                    "Two-factor authentication is required.",
                ),
            ),
            Self::ReauthenticationRequired => (
                StatusCode::FORBIDDEN,
                ErrorBody::new(
                    "reauthentication_required",
                    "Recent re-authentication is required for this action.",
                ),
            ),

            // 404
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                ErrorBody::new("not_found", "The requested resource was not found."),
            ),

            // 409
            Self::Conflict(code) => {
                // `code` is a static, stable identifier such as "email_taken":
                // clients branch on it, and it is safe to log.
                tracing::warn!(code, "conflict on unique field");
                (
                    StatusCode::CONFLICT,
                    ErrorBody::new(code, "A resource with this value already exists."),
                )
            }

            // 422
            // Validation messages are written by the handlers for the caller
            // ("password must be at least 10 characters") and never carry
            // internal state, so they are returned as-is.
            Self::Validation(message) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                ErrorBody::new("validation_error", message),
            ),
            Self::CaptchaFailed => (
                StatusCode::UNPROCESSABLE_ENTITY,
                ErrorBody::new(
                    "captcha_failed",
                    "CAPTCHA verification failed. Please try again.",
                ),
            ),

            // 400 - Device authorization flow (RFC 8628)
            Self::DeviceAuthPending => (
                StatusCode::BAD_REQUEST,
                ErrorBody::new(
                    "authorization_pending",
                    "The user has not yet completed authorization.",
                ),
            ),
            Self::DeviceCodeExpired => (
                StatusCode::BAD_REQUEST,
                ErrorBody::new("expired_token", "The device code has expired."),
            ),
            Self::DeviceAccessDenied => (
                StatusCode::BAD_REQUEST,
                ErrorBody::new(
                    "access_denied",
                    "The user denied the authorization request.",
                ),
            ),
            Self::DeviceSlowDown => (
                StatusCode::BAD_REQUEST,
                ErrorBody::new(
                    "slow_down",
                    "Polling too frequently. Increase the interval.",
                ),
            ),

            Self::DeviceSessionLimitReached => (
                StatusCode::FORBIDDEN,
                ErrorBody::new(
                    "device_session_limit_reached",
                    "Maximum number of device sessions reached for this client.",
                ),
            ),

            Self::DeviceClientNotAllowed => (
                StatusCode::FORBIDDEN,
                ErrorBody::new(
                    "device_client_not_allowed",
                    "You do not have access to this client application.",
                ),
            ),

            Self::InvalidAuthorizationCode => (
                StatusCode::BAD_REQUEST,
                ErrorBody::new(
                    "invalid_authorization_code",
                    "The authorization code is invalid, expired or already used.",
                ),
            ),

            Self::DeviceClientUnknown => (
                StatusCode::BAD_REQUEST,
                ErrorBody::new(
                    "device_client_unknown",
                    "The specified client application is not registered.",
                ),
            ),

            // 429
            Self::RateLimitExceeded => (
                StatusCode::TOO_MANY_REQUESTS,
                ErrorBody::new(
                    "rate_limit_exceeded",
                    "Too many requests. Please slow down.",
                ),
            ),

            // 503
            Self::ServiceUnavailable(dependency) => {
                tracing::warn!(dependency, "required upstream dependency is unavailable");
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    ErrorBody::new(
                        "service_unavailable",
                        "A required upstream dependency is unavailable.",
                    ),
                )
            }

            // 500
            Self::Internal(err) => {
                error!(error = %err, "internal server error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ErrorBody::new("internal_error", "An unexpected error occurred."),
                )
            }
        };

        (status, Json(body)).into_response()
    }
}

// From impls for common error sources

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        Self::Internal(anyhow::anyhow!(e))
    }
}

impl From<deadpool_redis::PoolError> for AppError {
    fn from(e: deadpool_redis::PoolError) -> Self {
        Self::Internal(anyhow::anyhow!(e))
    }
}

impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        Self::Internal(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::to_bytes, response::IntoResponse};

    fn status(err: AppError) -> u16 {
        err.into_response().status().as_u16()
    }

    async fn body_code(err: AppError) -> String {
        let resp = err.into_response();
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        v["code"].as_str().unwrap().to_owned()
    }

    // 401

    #[test]
    fn unauthorized_is_401() {
        assert_eq!(status(AppError::Unauthorized), 401);
    }

    #[test]
    fn invalid_credentials_is_401() {
        assert_eq!(status(AppError::InvalidCredentials), 401);
    }

    #[test]
    fn two_factor_failed_is_401() {
        assert_eq!(status(AppError::TwoFactorFailed), 401);
    }

    #[test]
    fn token_expired_is_401() {
        assert_eq!(status(AppError::TokenExpired), 401);
    }

    #[test]
    fn token_invalid_is_401() {
        assert_eq!(status(AppError::TokenInvalid), 401);
    }

    #[tokio::test]
    async fn reauthentication_failed_is_401_with_its_own_code() {
        assert_eq!(status(AppError::ReauthenticationFailed), 401);
        assert_eq!(
            body_code(AppError::ReauthenticationFailed).await,
            "reauthentication_failed"
        );
    }

    // 403

    #[test]
    fn forbidden_is_403() {
        assert_eq!(status(AppError::Forbidden), 403);
    }

    #[test]
    fn email_not_verified_is_403() {
        assert_eq!(status(AppError::EmailNotVerified), 403);
    }

    #[test]
    fn account_suspended_is_403() {
        assert_eq!(status(AppError::AccountSuspended), 403);
    }

    #[test]
    fn account_inactive_is_403() {
        assert_eq!(status(AppError::AccountInactive), 403);
    }

    #[test]
    fn account_locked_is_403() {
        assert_eq!(status(AppError::AccountLocked), 403);
    }

    #[test]
    fn two_factor_required_is_403() {
        assert_eq!(status(AppError::TwoFactorRequired), 403);
    }

    #[test]
    fn reauthentication_required_is_403() {
        assert_eq!(status(AppError::ReauthenticationRequired), 403);
    }

    // 404

    #[test]
    fn not_found_is_404() {
        assert_eq!(status(AppError::NotFound), 404);
    }

    // 409

    #[tokio::test]
    async fn conflict_is_409_with_its_specific_code() {
        assert_eq!(status(AppError::Conflict("email_taken")), 409);
        assert_eq!(
            body_code(AppError::Conflict("username_taken")).await,
            "username_taken"
        );
    }

    #[tokio::test]
    async fn validation_message_is_returned_to_the_caller() {
        let resp = AppError::Validation("password too short".into()).into_response();
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["message"], "password too short");
    }

    #[test]
    fn app_error_implements_display() {
        assert_eq!(
            AppError::ServiceUnavailable("redis").to_string(),
            "dependency unavailable: redis"
        );
    }

    // 422

    #[tokio::test]
    async fn validation_is_422() {
        assert_eq!(status(AppError::Validation("bad".into())), 422);
        assert_eq!(
            body_code(AppError::Validation("bad".into())).await,
            "validation_error"
        );
    }

    #[tokio::test]
    async fn captcha_failed_is_422() {
        assert_eq!(status(AppError::CaptchaFailed), 422);
        assert_eq!(body_code(AppError::CaptchaFailed).await, "captcha_failed");
    }

    // 400 - Device authorization flow

    #[tokio::test]
    async fn device_auth_pending_is_400() {
        assert_eq!(status(AppError::DeviceAuthPending), 400);
        assert_eq!(
            body_code(AppError::DeviceAuthPending).await,
            "authorization_pending"
        );
    }

    #[tokio::test]
    async fn device_code_expired_is_400() {
        assert_eq!(status(AppError::DeviceCodeExpired), 400);
        assert_eq!(
            body_code(AppError::DeviceCodeExpired).await,
            "expired_token"
        );
    }

    #[tokio::test]
    async fn device_access_denied_is_400() {
        assert_eq!(status(AppError::DeviceAccessDenied), 400);
        assert_eq!(
            body_code(AppError::DeviceAccessDenied).await,
            "access_denied"
        );
    }

    #[tokio::test]
    async fn device_slow_down_is_400() {
        assert_eq!(status(AppError::DeviceSlowDown), 400);
        assert_eq!(body_code(AppError::DeviceSlowDown).await, "slow_down");
    }

    #[tokio::test]
    async fn device_session_limit_reached_is_403() {
        assert_eq!(status(AppError::DeviceSessionLimitReached), 403);
        assert_eq!(
            body_code(AppError::DeviceSessionLimitReached).await,
            "device_session_limit_reached"
        );
    }

    #[tokio::test]
    async fn device_client_not_allowed_is_403() {
        assert_eq!(status(AppError::DeviceClientNotAllowed), 403);
        assert_eq!(
            body_code(AppError::DeviceClientNotAllowed).await,
            "device_client_not_allowed"
        );
    }

    #[tokio::test]
    async fn device_client_unknown_is_400() {
        assert_eq!(status(AppError::DeviceClientUnknown), 400);
        assert_eq!(
            body_code(AppError::DeviceClientUnknown).await,
            "device_client_unknown"
        );
    }

    // 429

    #[tokio::test]
    async fn rate_limit_exceeded_is_429() {
        assert_eq!(status(AppError::RateLimitExceeded), 429);
        assert_eq!(
            body_code(AppError::RateLimitExceeded).await,
            "rate_limit_exceeded"
        );
    }

    // 503

    #[tokio::test]
    async fn service_unavailable_is_503() {
        assert_eq!(status(AppError::ServiceUnavailable("captcha")), 503);
        assert_eq!(
            body_code(AppError::ServiceUnavailable("captcha")).await,
            "service_unavailable"
        );
    }

    // 500

    #[tokio::test]
    async fn internal_is_500() {
        assert_eq!(
            status(AppError::Internal(anyhow::anyhow!("test error"))),
            500
        );
        assert_eq!(
            body_code(AppError::Internal(anyhow::anyhow!("test error"))).await,
            "internal_error"
        );
    }

    // From impls

    #[test]
    fn from_anyhow_produces_internal() {
        let err: AppError = anyhow::anyhow!("wrapped").into();
        assert_eq!(status(err), 500);
    }

    #[test]
    fn from_sqlx_error_produces_internal() {
        let sqlx_err = sqlx::Error::RowNotFound;
        let err: AppError = sqlx_err.into();
        assert_eq!(status(err), 500);
    }

    #[test]
    fn from_deadpool_redis_pool_error_produces_internal() {
        let pool_err = deadpool_redis::PoolError::NoRuntimeSpecified;
        let err: AppError = pool_err.into();
        assert_eq!(status(err), 500);
    }
}
