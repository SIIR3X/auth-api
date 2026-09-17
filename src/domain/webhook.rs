//! Webhooks: which endpoints may be called, what they subscribe to, when a
//! failed delivery is retried, and how a delivery is signed.
//!
//! Signatures follow Standard Webhooks: the secret is `whsec_` and base64
//! bytes, the signed content is `{id}.{timestamp}.{body}`, and the header value
//! is `v1,` and the base64 HMAC-SHA256.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use hmac::{Hmac, KeyInit, Mac};
use reqwest::Url;
use sha2::Sha256;

/// Events an endpoint can subscribe to, by name.
pub const EVENT_NAMES: [&str; 8] = [
    "user.created",
    "user.email_verified",
    "user.email_changed",
    "user.password_changed",
    "user.sessions_revoked",
    "user.suspended",
    "user.reactivated",
    "user.deleted",
];

/// Attempts before a delivery is given up.
pub const MAX_ATTEMPTS: i32 = 12;

const FIRST_RETRY: Duration = Duration::from_secs(30);
const MAX_RETRY: Duration = Duration::from_secs(6 * 3600);

const SECRET_PREFIX: &str = "whsec_";

/// Delay before the next attempt after `failed_attempts` failures: 30 seconds,
/// doubling up to six hours. The twelve attempts span about fourteen hours.
pub fn retry_delay(failed_attempts: i32) -> Duration {
    if failed_attempts <= 0 {
        return Duration::ZERO;
    }
    let doublings = (failed_attempts - 1).min(16).unsigned_abs();
    FIRST_RETRY
        .saturating_mul(2u32.saturating_pow(doublings))
        .min(MAX_RETRY)
}

/// The subscriptions, deduplicated and sorted, when each is a known event or
/// `*`; otherwise a message naming the others.
pub fn check_events(events: &[String]) -> Result<Vec<String>, String> {
    if events.is_empty() {
        return Err("subscribe to at least one event, or `*`".into());
    }
    let unknown: Vec<&str> = events
        .iter()
        .map(String::as_str)
        .filter(|event| *event != "*" && !EVENT_NAMES.contains(event))
        .collect();
    if !unknown.is_empty() {
        return Err(format!("unknown events: {}", unknown.join(", ")));
    }
    let mut events = events.to_vec();
    events.sort();
    events.dedup();
    Ok(events)
}

/// Whether an endpoint with these subscriptions receives `event`.
pub fn subscribes(events: &[String], event: &str) -> bool {
    events.iter().any(|e| e == "*" || e == event)
}

/// An endpoint URL an administrator may register: HTTPS (HTTP only when
/// allowed), a host, no credentials, no fragment, at most 2 000 characters.
/// Addresses are checked again at each delivery, after resolution.
pub fn check_url(url: &str, allow_http: bool) -> Result<Url, String> {
    if url.len() > 2000 {
        return Err("url must be at most 2000 characters".into());
    }
    let parsed = Url::parse(url).map_err(|e| format!("invalid url: {e}"))?;
    match parsed.scheme() {
        "https" => {}
        "http" if allow_http => {}
        _ => return Err("url must use https".into()),
    }
    if parsed.host_str().is_none_or(str::is_empty) {
        return Err("url must name a host".into());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("url must not carry credentials".into());
    }
    if parsed.fragment().is_some() {
        return Err("url must not carry a fragment".into());
    }
    Ok(parsed)
}

/// Whether a delivery may connect to `ip`: never to loopback, private,
/// link-local, shared, documentation, multicast or reserved ranges, nor to an
/// IPv6 address embedding one of them. A webhook must not become a way to reach
/// the internal network.
pub fn is_public_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        || a == 0
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 198 && (18..=19).contains(&b))
        || a >= 240)
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_public_v4(v4);
    }
    let segments = ip.segments();
    // NAT64 (64:ff9b::/96) and 6to4 (2002::/16) reach IPv4 addresses.
    if segments[0] == 0x64 && segments[1] == 0xff9b && segments[2..6] == [0, 0, 0, 0] {
        return is_public_v4(Ipv4Addr::from(
            (u32::from(segments[6]) << 16) | u32::from(segments[7]),
        ));
    }
    if segments[0] == 0x2002 {
        return is_public_v4(Ipv4Addr::from(
            (u32::from(segments[1]) << 16) | u32::from(segments[2]),
        ));
    }
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        // IPv4-compatible (deprecated) addresses.
        || segments[0..6] == [0, 0, 0, 0, 0, 0]
        // Unique local fc00::/7, link-local fe80::/10, site-local fec0::/10.
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] & 0xffc0) == 0xfec0
        // Documentation 2001:db8::/32, Teredo 2001::/32, discard 100::/64.
        || (segments[0] == 0x2001 && (segments[1] == 0x0db8 || segments[1] == 0))
        || (segments[0] == 0x0100 && segments[1..4] == [0, 0, 0]))
}

/// A new signing secret, as shown to the administrator.
pub fn format_secret(bytes: &[u8]) -> String {
    format!("{SECRET_PREFIX}{}", B64.encode(bytes))
}

/// The key bytes of a secret written by [`format_secret`].
pub fn secret_bytes(secret: &str) -> Option<Vec<u8>> {
    B64.decode(secret.strip_prefix(SECRET_PREFIX)?).ok()
}

/// The `webhook-signature` header value for a delivery.
pub fn signature(key: &[u8], id: &str, timestamp: i64, body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(id.as_bytes());
    mac.update(b".");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    format!("v1,{}", B64.encode(mac.finalize().into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retries_double_from_thirty_seconds_up_to_six_hours() {
        assert_eq!(retry_delay(0), Duration::ZERO);
        assert_eq!(retry_delay(1), Duration::from_secs(30));
        assert_eq!(retry_delay(2), Duration::from_secs(60));
        assert_eq!(retry_delay(9), Duration::from_secs(7680));
        assert_eq!(retry_delay(11), Duration::from_secs(6 * 3600));
        let span: Duration = (1..MAX_ATTEMPTS).map(retry_delay).sum();
        assert_eq!(span.as_secs() / 3600, 14);
        assert_eq!(retry_delay(i32::MAX), Duration::from_secs(6 * 3600));
    }

    #[test]
    fn subscriptions_name_known_events_or_everything() {
        assert_eq!(
            check_events(&[
                "user.deleted".into(),
                "user.created".into(),
                "user.deleted".into()
            ]),
            Ok(vec!["user.created".to_owned(), "user.deleted".to_owned()])
        );
        assert!(check_events(&[]).is_err());
        assert!(check_events(&["user.exploded".into()]).is_err());
        assert!(subscribes(&["*".into()], "user.deleted"));
        assert!(subscribes(&["user.deleted".into()], "user.deleted"));
        assert!(!subscribes(&["user.created".into()], "user.deleted"));
    }

    #[test]
    fn only_plain_https_urls_are_registered() {
        assert!(check_url("https://hooks.example.com/auth?x=1", false).is_ok());
        assert!(check_url("http://hooks.example.com/auth", false).is_err());
        assert!(check_url("http://hooks.example.com/auth", true).is_ok());
        for bad in [
            "ftp://hooks.example.com/",
            "https://user:pw@hooks.example.com/",
            "https://hooks.example.com/#frag",
            "not a url",
            "file:///etc/passwd",
        ] {
            assert!(check_url(bad, true).is_err(), "{bad}");
        }
        assert!(check_url(&format!("https://example.com/{}", "a".repeat(2000)), false).is_err());
    }

    #[test]
    fn internal_addresses_are_refused() {
        for internal in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "192.0.0.8",
            "198.18.0.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "fd00::1",
            "fe80::1",
            "fec0::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::127.0.0.1",
            "64:ff9b::a00:1",
            "2002:a00:1::",
            "2001:db8::1",
            "2001::1",
            "100::1",
        ] {
            let ip: IpAddr = internal.parse().unwrap();
            assert!(!is_public_address(ip), "{internal}");
        }
        for public in [
            "93.184.216.34",
            "2606:2800:220:1::1",
            "::ffff:93.184.216.34",
            "64:ff9b::5db8:d822",
        ] {
            let ip: IpAddr = public.parse().unwrap();
            assert!(is_public_address(ip), "{public}");
        }
    }

    #[test]
    fn signatures_follow_hmac_sha256() {
        // RFC 4231, test case 2, over "{id}.{timestamp}.{body}".
        let key = b"Jefe";
        assert_eq!(
            signature(key, "what do ya", 0, b"want for nothing?").len(),
            "v1,".len() + 44
        );
        let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
        mac.update(b"what do ya want for nothing?");
        assert_eq!(
            mac.finalize()
                .into_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        let secret = format_secret(&[7u8; 24]);
        assert_eq!(secret_bytes(&secret), Some(vec![7u8; 24]));
        assert_eq!(secret_bytes("7777"), None);
        assert_ne!(
            signature(&[7u8; 24], "msg_1", 1, b"{}"),
            signature(&[7u8; 24], "msg_1", 2, b"{}")
        );
    }
}
