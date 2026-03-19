//! Axum request extractors shared across all handlers.
//!
//! AuthUser validates the Bearer token and makes user_id + session_id available
//! to any handler that requires authentication.
//! ClientIp reads the real client IP from reverse-proxy headers before falling
//! back to the direct connection address.

use std::net::IpAddr;

use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts, StatusCode},
};
use ipnetwork::IpNetwork;

use crate::{error::AppError, repositories::session as session_repo, state::AppState, utils::jwt};

// Authenticated user extracted from the JWT Bearer token.

pub struct AuthUser {
    pub user_id: uuid::Uuid,
    pub session_id: uuid::Uuid,
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(AppError::Unauthorized)?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or(AppError::Unauthorized)?;

        let claims = jwt::decode_token(token, &state.config.jwt.secret)
            .map_err(|_| AppError::TokenInvalid)?;

        // Verify the session is still active in the database.
        // This ensures logout and session revocation take effect immediately.
        let session = session_repo::find_by_id(&state.db, claims.sid)
            .await
            .map_err(|_| AppError::Unauthorized)?
            .ok_or(AppError::Unauthorized)?;

        if !session.is_active() {
            return Err(AppError::Unauthorized);
        }

        Ok(Self {
            user_id: claims.sub,
            session_id: claims.sid,
        })
    }
}

// Client IP extracted from standard reverse-proxy headers.

pub struct ClientIp(pub Option<IpNetwork>);

impl<S: Send + Sync> FromRequestParts<S> for ClientIp {
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let ip = parts
            .headers
            .get("x-real-ip")
            .or_else(|| parts.headers.get("x-forwarded-for"))
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .and_then(|s| s.trim().parse::<IpAddr>().ok())
            .map(IpNetwork::from);

        Ok(ClientIp(ip))
    }
}

// User-Agent header as a plain string.

pub struct UserAgent(pub Option<String>);

impl<S: Send + Sync> FromRequestParts<S> for UserAgent {
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let ua = parts
            .headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_owned());

        Ok(UserAgent(ua))
    }
}
