//! Axum request extractors shared across all handlers.
//!
//! AuthUser validates the Bearer token and makes user_id + session_id available
//! to any handler that requires authentication.
//! ClientIp (defined in `middleware::client_ip`) is re-exported for handlers.

use axum::{
    extract::FromRequestParts,
    http::{StatusCode, header, request::Parts},
};

use crate::{
    error::AppError, middleware::request_id::X_REQUEST_ID, services::auth as auth_svc,
    state::AppState, utils::jwt,
};

/// Re-exported: handlers keep extracting the client address from here.
pub use crate::middleware::client_ip::ClientIp;

// Authenticated user extracted from the JWT Bearer token.

pub struct AuthUser {
    pub user_id: uuid::Uuid,
    pub session_id: uuid::Uuid,
    pub jti: uuid::Uuid,
    pub token_exp: i64,
    /// Role names from the JWT (e.g. ["user", "admin"]).
    pub roles: Vec<String>,
    /// Permission names from the JWT (e.g. ["users:read"]).
    pub permissions: Vec<String>,
    /// Request ID injected by the request_id middleware; propagate to audit log entries.
    pub request_id: Option<uuid::Uuid>,
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

        let claims = jwt::decode_token_with_keys(
            token,
            &state.jwt_verifying_keys,
            state.clock.now().unix_timestamp(),
        )
        .map_err(|_| AppError::TokenInvalid)?;

        // Defense-in-depth: even though the signature already proves the token
        // was minted by this auth-api instance, also pin `iss` (must match our
        // public_url) and `aud` (must contain our public_url -- guaranteed by
        // `ensure_self_in_audience` at startup). This rejects tokens that were
        // re-signed by an attacker holding a stolen private key for a sibling
        // deployment, and tokens that were addressed only to downstream
        // resource servers and replayed against auth-api.
        let expected = state.config.server.public_url.as_str();
        if jwt::validate_iss_aud(&claims, expected, expected).is_err() {
            return Err(AppError::TokenInvalid);
        }

        // Revoked token or ended session: one Redis round trip, the database
        // only on a cache miss. Fails closed when Redis is unavailable.
        auth_svc::verify_token_state(state, claims.jti, claims.sid).await?;

        let request_id = parts
            .headers
            .get(&X_REQUEST_ID)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<uuid::Uuid>().ok());

        Ok(Self {
            user_id: claims.sub,
            session_id: claims.sid,
            jti: claims.jti,
            token_exp: claims.exp,
            roles: claims.roles,
            permissions: claims.permissions,
            request_id,
        })
    }
}

/// An administrator: a valid access token carrying at least one administrative
/// permission, from an account with a second factor enrolled. Each handler then
/// requires the permission of its action with [`AdminUser::require`].
pub struct AdminUser {
    pub auth: AuthUser,
}

impl FromRequestParts<AppState> for AdminUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth = AuthUser::from_request_parts(parts, state).await?;
        if !auth
            .permissions
            .iter()
            .any(|permission| crate::domain::role::is_admin_permission(permission))
        {
            return Err(AppError::Forbidden);
        }
        // An administrator's password alone must not open the administration.
        if crate::repositories::two_factor::find_primary_by_user(&state.db, auth.user_id)
            .await?
            .is_none()
        {
            return Err(AppError::TwoFactorRequired);
        }
        Ok(Self { auth })
    }
}

impl AdminUser {
    /// Require `permission`, in the token and still in the database: a role
    /// revoked a minute ago stops working now, not when the token expires.
    pub async fn require(&self, state: &AppState, permission: &str) -> Result<(), AppError> {
        if !self.auth.permissions.iter().any(|p| p == permission)
            || !crate::repositories::role::user_has_permission(
                &state.db,
                self.auth.user_id,
                permission,
            )
            .await?
        {
            return Err(AppError::Forbidden);
        }
        Ok(())
    }
}

// Request ID injected by the request_id middleware.

pub struct RequestId(pub Option<uuid::Uuid>);

impl<S: Send + Sync> FromRequestParts<S> for RequestId {
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let id = parts
            .headers
            .get(&X_REQUEST_ID)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<uuid::Uuid>().ok());

        Ok(RequestId(id))
    }
}

/// Longest user agent kept: sessions, login attempts and audit metadata store it,
/// and nothing downstream needs more.
pub const MAX_USER_AGENT_CHARS: usize = 512;

// User-Agent header as a plain string, truncated to `MAX_USER_AGENT_CHARS`.

pub struct UserAgent(pub Option<String>);

impl<S: Send + Sync> FromRequestParts<S> for UserAgent {
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let ua = parts
            .headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.chars().take(MAX_USER_AGENT_CHARS).collect());

        Ok(UserAgent(ua))
    }
}
