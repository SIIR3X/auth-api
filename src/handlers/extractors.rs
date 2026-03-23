//! Axum request extractors shared across all handlers.
//!
//! AuthUser validates the Bearer token and makes user_id + session_id available
//! to any handler that requires authentication.
//! ClientIp reads the real client IP from reverse-proxy headers before falling
//! back to the direct connection address.

use std::net::{IpAddr, SocketAddr};

use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::{StatusCode, header, request::Parts},
};
use ipnetwork::IpNetwork;

use crate::{
    error::AppError,
    middleware::{rate_limit::RateLimitState, request_id::X_REQUEST_ID},
    repositories::session as session_repo,
    services::auth as auth_svc,
    state::AppState,
    utils::jwt,
};

// Authenticated user extracted from the JWT Bearer token.

pub struct AuthUser {
    pub user_id: uuid::Uuid,
    pub session_id: uuid::Uuid,
    pub jti: uuid::Uuid,
    pub token_exp: i64,
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

        let claims = jwt::decode_token_with_fallback(
            token,
            &state.config.jwt.secret,
            state.config.jwt.previous_secret.as_deref(),
        )
        .map_err(|_| AppError::TokenInvalid)?;

        // Check the JTI blocklist before touching the database.
        if auth_svc::is_jti_blocked(state, claims.jti).await {
            return Err(AppError::TokenInvalid);
        }

        // Verify the session is still active in the database.
        // This ensures logout and session revocation take effect immediately.
        let session = session_repo::find_by_id(&state.db, claims.sid)
            .await
            .map_err(|_| AppError::Unauthorized)?
            .ok_or(AppError::Unauthorized)?;

        if !session.is_active() {
            return Err(AppError::Unauthorized);
        }

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
            request_id,
        })
    }
}

// Client IP extracted from standard reverse-proxy headers.

pub struct ClientIp(pub Option<IpNetwork>);

pub trait TrustedProxySource {
    fn trusted_proxy_cidrs(&self) -> &[IpNetwork];
}

impl TrustedProxySource for AppState {
    fn trusted_proxy_cidrs(&self) -> &[IpNetwork] {
        &self.config.server.trusted_proxy_cidrs
    }
}

impl TrustedProxySource for RateLimitState {
    fn trusted_proxy_cidrs(&self) -> &[IpNetwork] {
        &self.trusted_proxy_cidrs
    }
}

impl<S: Send + Sync + TrustedProxySource> FromRequestParts<S> for ClientIp {
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let trusted = state.trusted_proxy_cidrs();
        let peer_ip = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip());

        let ip = match peer_ip {
            Some(peer) if is_trusted_proxy(peer, trusted) => {
                forwarded_client_ip(parts, trusted).unwrap_or(peer)
            }
            Some(peer) => peer,
            None => return Ok(ClientIp(None)),
        };

        Ok(ClientIp(Some(IpNetwork::from(ip))))
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

fn is_trusted_proxy(ip: IpAddr, trusted_proxy_cidrs: &[IpNetwork]) -> bool {
    trusted_proxy_cidrs.iter().any(|cidr| cidr.contains(ip))
}

fn forwarded_client_ip(parts: &Parts, trusted_proxy_cidrs: &[IpNetwork]) -> Option<IpAddr> {
    if let Some(forwarded_for) = parts
        .headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
    {
        let forwarded_chain = forwarded_for
            .split(',')
            .map(str::trim)
            .filter_map(|raw| raw.parse::<IpAddr>().ok())
            .collect::<Vec<_>>();

        for ip in forwarded_chain.iter().rev() {
            if !is_trusted_proxy(*ip, trusted_proxy_cidrs) {
                return Some(*ip);
            }
        }

        if let Some(first) = forwarded_chain.first() {
            return Some(*first);
        }
    }

    parts
        .headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderValue, Request};

    #[derive(Default)]
    struct TestState {
        trusted_proxy_cidrs: Vec<IpNetwork>,
    }

    impl TrustedProxySource for TestState {
        fn trusted_proxy_cidrs(&self) -> &[IpNetwork] {
            &self.trusted_proxy_cidrs
        }
    }

    #[tokio::test]
    async fn direct_peer_ignores_forwarded_headers() {
        let state = TestState::default();
        let mut req = Request::builder().uri("/").body(()).unwrap();
        req.headers_mut()
            .insert("x-forwarded-for", HeaderValue::from_static("203.0.113.5"));
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 3000))));

        let (mut parts, _) = req.into_parts();
        let client_ip = ClientIp::from_request_parts(&mut parts, &state)
            .await
            .unwrap();

        assert_eq!(client_ip.0.unwrap().ip(), IpAddr::from([127, 0, 0, 1]));
    }

    #[tokio::test]
    async fn trusted_proxy_uses_forwarded_client_ip() {
        let state = TestState {
            trusted_proxy_cidrs: vec!["10.0.0.0/8".parse().unwrap()],
        };
        let mut req = Request::builder().uri("/").body(()).unwrap();
        req.headers_mut().insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.10, 10.1.2.3"),
        );
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([10, 9, 8, 7], 3000))));

        let (mut parts, _) = req.into_parts();
        let client_ip = ClientIp::from_request_parts(&mut parts, &state)
            .await
            .unwrap();

        assert_eq!(client_ip.0.unwrap().ip(), IpAddr::from([198, 51, 100, 10]));
    }
}
