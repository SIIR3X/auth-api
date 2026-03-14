//! Centralized error type for the application.
//!
//! AppError covers every failure case the API can produce. Each variant maps
//! to a specific HTTP status and a stable machine-readable code returned in
//! the JSON body. Internal errors are logged server-side but never exposed
//! to the caller.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use tracing::error;

// Response body

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: &'static str,
}

impl ErrorBody {
    fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }
}

// AppError

#[derive(Debug)]
pub enum AppError {
    // 401
    Unauthorized,
    InvalidCredentials,
    TwoFactorFailed,
    TokenExpired,
    TokenInvalid,

    // 403
    Forbidden,
    EmailNotVerified,
    AccountSuspended,
    AccountInactive,
    TwoFactorRequired,

    // 404
    NotFound,

    // 409
    Conflict(&'static str),

    // 422
    Validation(String),

    // 429
    RateLimitExceeded,

    // 500 - message is logged, never sent to the caller
    Internal(anyhow::Error),
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

            // 403
            Self::Forbidden => (
                StatusCode::FORBIDDEN,
                ErrorBody::new("forbidden", "You do not have permission to perform this action."),
            ),
            Self::EmailNotVerified => (
                StatusCode::FORBIDDEN,
                ErrorBody::new("email_not_verified", "Please verify your email address first."),
            ),
            Self::AccountSuspended => (
                StatusCode::FORBIDDEN,
                ErrorBody::new("account_suspended", "This account has been suspended."),
            ),
            Self::AccountInactive => (
                StatusCode::FORBIDDEN,
                ErrorBody::new("account_inactive", "This account is inactive."),
            ),
            Self::TwoFactorRequired => (
                StatusCode::FORBIDDEN,
                ErrorBody::new("two_factor_required", "Two-factor authentication is required."),
            ),

            // 404
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                ErrorBody::new("not_found", "The requested resource was not found."),
            ),

            // 409
            Self::Conflict(field) => {
                // field is a static str like "email" or "username", safe to log
                let body = ErrorBody::new("conflict", "A resource with this value already exists.");
                error!(field, "conflict on unique field");
                (StatusCode::CONFLICT, body)
            }

            // 422
            Self::Validation(_) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                ErrorBody::new("validation_error", "The request body contains invalid data."),
            ),

            // 429
            Self::RateLimitExceeded => (
                StatusCode::TOO_MANY_REQUESTS,
                ErrorBody::new("rate_limit_exceeded", "Too many requests. Please slow down."),
            ),

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
