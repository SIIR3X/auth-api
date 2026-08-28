//! The client address, read through trusted reverse proxies.
//!
//! Forwarding headers are honoured only when the direct peer is a trusted
//! proxy; the rightmost untrusted hop of `X-Forwarded-For` is the client.

use std::net::{IpAddr, SocketAddr};

use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::{StatusCode, request::Parts},
};
use ipnetwork::IpNetwork;

use crate::{middleware::rate_limit::RateLimitState, state::AppState};

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
