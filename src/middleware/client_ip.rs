//! The client address, read through trusted reverse proxies.
//!
//! Forwarding headers are honoured only when the direct peer is a trusted
//! proxy; the rightmost untrusted hop of `X-Forwarded-For` is the client.

use std::net::{IpAddr, SocketAddr};

use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::{HeaderMap, StatusCode, request::Parts},
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
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip());
        let ip = resolve_client_ip(peer, &parts.headers, state.trusted_proxy_cidrs());
        Ok(ClientIp(ip.map(IpNetwork::from)))
    }
}

/// The client address of a request: its peer, or, when the peer is a trusted
/// proxy, the address the forwarding headers name. `None` without a peer.
pub(crate) fn resolve_client_ip(
    peer: Option<IpAddr>,
    headers: &HeaderMap,
    trusted_proxy_cidrs: &[IpNetwork],
) -> Option<IpAddr> {
    let peer = peer?;
    if !is_trusted_proxy(peer, trusted_proxy_cidrs) {
        return Some(peer);
    }
    Some(forwarded_client_ip(headers, trusted_proxy_cidrs).unwrap_or(peer))
}

fn is_trusted_proxy(ip: IpAddr, trusted_proxy_cidrs: &[IpNetwork]) -> bool {
    trusted_proxy_cidrs.iter().any(|cidr| cidr.contains(ip))
}

/// The client named by the forwarding headers of a trusted proxy.
///
/// `X-Forwarded-For` is read across every header line, as one list. Walking it
/// from the right, trusted proxies are skipped and the first other hop is the
/// client. A hop that is not an address ends the walk without an answer: what
/// lies to its left was written by someone no proxy vouched for. When every
/// hop is a trusted proxy, the leftmost one is the client. `X-Real-IP` counts
/// only when no `X-Forwarded-For` was sent at all.
fn forwarded_client_ip(headers: &HeaderMap, trusted_proxy_cidrs: &[IpNetwork]) -> Option<IpAddr> {
    let mut lines = headers.get_all("x-forwarded-for").iter().peekable();
    if lines.peek().is_none() {
        return headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<IpAddr>().ok());
    }

    let mut hops = Vec::new();
    for line in lines {
        hops.extend(line.to_str().ok()?.split(',').map(str::trim));
    }

    let mut leftmost_trusted = None;
    for hop in hops.iter().rev() {
        let ip = hop.parse::<IpAddr>().ok()?;
        if !is_trusted_proxy(ip, trusted_proxy_cidrs) {
            return Some(ip);
        }
        leftmost_trusted = Some(ip);
    }
    leftmost_trusted
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
    fn forwarded(lines: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for line in lines {
            headers.append("x-forwarded-for", HeaderValue::from_str(line).unwrap());
        }
        headers
    }

    fn trusted() -> Vec<IpNetwork> {
        vec!["10.0.0.0/8".parse().unwrap()]
    }

    const PROXY: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2));

    #[test]
    fn every_forwarded_line_counts_as_one_list() {
        // A line the client sent, then the proxy's own: the proxy's hop wins.
        let ip = resolve_client_ip(Some(PROXY), &forwarded(&["6.6.6.6", "1.2.3.4"]), &trusted());
        assert_eq!(ip, Some("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn an_unreadable_hop_stops_the_walk_at_the_proxy() {
        for chain in ["6.6.6.6, unknown", "6.6.6.6, 1.2.3.4:5678", ""] {
            let ip = resolve_client_ip(Some(PROXY), &forwarded(&[chain]), &trusted());
            assert_eq!(ip, Some(PROXY), "{chain:?}");
        }
    }

    #[test]
    fn trusted_hops_are_skipped_and_an_all_trusted_chain_names_its_leftmost() {
        let ip = resolve_client_ip(Some(PROXY), &forwarded(&["1.2.3.4, 10.0.0.3"]), &trusted());
        assert_eq!(ip, Some("1.2.3.4".parse().unwrap()));
        let ip = resolve_client_ip(Some(PROXY), &forwarded(&["10.0.0.5, 10.0.0.6"]), &trusted());
        assert_eq!(ip, Some("10.0.0.5".parse().unwrap()));
    }

    #[test]
    fn x_real_ip_counts_only_without_forwarded_for() {
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", HeaderValue::from_static("5.5.5.5"));
        let ip = resolve_client_ip(Some(PROXY), &headers, &trusted());
        assert_eq!(ip, Some("5.5.5.5".parse().unwrap()));

        headers.insert("x-forwarded-for", HeaderValue::from_static("garbage"));
        assert_eq!(
            resolve_client_ip(Some(PROXY), &headers, &trusted()),
            Some(PROXY)
        );
    }

    #[test]
    fn an_untrusted_peer_is_the_client_whatever_the_headers() {
        let peer: IpAddr = "203.0.113.9".parse().unwrap();
        let headers = forwarded(&["1.2.3.4"]);
        assert_eq!(
            resolve_client_ip(Some(peer), &headers, &trusted()),
            Some(peer)
        );
        assert_eq!(resolve_client_ip(None, &headers, &trusted()), None);
    }

    #[test]
    fn the_rate_limiter_reads_its_own_trusted_proxies() {
        let redis = crate::utils::redis_pool::build(&crate::config::RedisConfig {
            url: "redis://127.0.0.1:1".into(),
            pool_size: 1,
            wait_timeout_ms: 10,
        })
        .unwrap();
        let state = RateLimitState {
            redis,
            buckets: Vec::new(),
            trusted_proxy_cidrs: trusted(),
            fail_open_on_redis_error: false,
            allow_requests_without_ip: false,
        };
        assert_eq!(state.trusted_proxy_cidrs(), trusted().as_slice());
    }
}
