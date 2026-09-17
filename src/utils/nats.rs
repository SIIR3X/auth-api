//! Credentials of the NATS broker, read from `NATS_URL`.
//!
//! async-nats connects to the address of a URL but never reads the user
//! information in it: `nats://<token>@nats:4222` reaches the broker with no
//! credentials and is refused. The credentials are therefore split from the URL
//! here and given to the client explicitly.

use async_nats::ConnectOptions;

/// Credentials carried by a `NATS_URL`.
#[derive(Clone, PartialEq, Eq)]
pub enum NatsCredentials {
    None,
    /// `nats://<token>@host:port`
    Token(String),
    /// `nats://<user>:<password>@host:port`
    UserPassword {
        user: String,
        password: String,
    },
}

impl std::fmt::Debug for NatsCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print a secret, whatever logs a value of this type.
        match self {
            Self::None => f.write_str("None"),
            Self::Token(_) => f.write_str("Token(<redacted>)"),
            Self::UserPassword { user, .. } => write!(f, "UserPassword({user}, <redacted>)"),
        }
    }
}

/// Split a `NATS_URL` into the address to connect to and its credentials.
///
/// The address keeps the scheme, host and port and loses the user information,
/// so it can be logged. Percent-encoded credentials are decoded.
pub fn split_credentials(url: &str) -> Result<(String, NatsCredentials), String> {
    let mut parsed = reqwest::Url::parse(url).map_err(|e| format!("not a URL: {e}"))?;
    if parsed.host_str().is_none_or(str::is_empty) {
        return Err("has no host".into());
    }

    let user = percent_decode(parsed.username())?;
    let password = parsed.password().map(percent_decode).transpose()?;
    let credentials = match (user.is_empty(), password) {
        (true, None) => NatsCredentials::None,
        (true, Some(_)) => return Err("has a password without a user".into()),
        (false, None) => NatsCredentials::Token(user),
        (false, Some(password)) => NatsCredentials::UserPassword { user, password },
    };

    parsed
        .set_username("")
        .and_then(|()| parsed.set_password(None))
        .map_err(|()| "cannot carry credentials".to_string())?;
    Ok((parsed.to_string(), credentials))
}

/// Split a `NATS_URL` naming one server or a cluster (`nats://a:4222,nats://b:4222`):
/// the addresses to try, and the credentials they share. The client connects to
/// any of them and follows the cluster when a server goes away.
pub fn split_cluster(urls: &str) -> Result<(Vec<String>, NatsCredentials), String> {
    let mut addresses = Vec::new();
    let mut shared: Option<NatsCredentials> = None;
    for url in urls.split(',').map(str::trim).filter(|u| !u.is_empty()) {
        let (address, credentials) = split_credentials(url)?;
        match &shared {
            Some(seen) if *seen != credentials => {
                return Err("servers of a cluster must share their credentials".into());
            }
            _ => shared = Some(credentials),
        }
        addresses.push(address);
    }
    let credentials = shared.ok_or("names no server")?;
    Ok((addresses, credentials))
}

/// Client options presenting `credentials` to the broker.
pub fn connect_options(credentials: NatsCredentials) -> ConnectOptions {
    match credentials {
        NatsCredentials::None => ConnectOptions::new(),
        NatsCredentials::Token(token) => ConnectOptions::with_token(token),
        NatsCredentials::UserPassword { user, password } => {
            ConnectOptions::with_user_and_password(user, password)
        }
    }
}

fn percent_decode(raw: &str) -> Result<String, String> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes
                .get(i + 1..i + 3)
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or_else(|| "has a malformed percent-encoded credential".to_string())?;
            out.push(hex);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "has credentials that are not UTF-8".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_url_without_user_information_has_no_credentials() {
        assert_eq!(
            split_credentials("nats://nats:4222").unwrap(),
            ("nats://nats:4222".to_string(), NatsCredentials::None)
        );
    }

    #[test]
    fn a_lone_user_is_a_token_and_leaves_the_address() {
        assert_eq!(
            split_credentials("nats://s3cr3t@nats:4222").unwrap(),
            (
                "nats://nats:4222".to_string(),
                NatsCredentials::Token("s3cr3t".into())
            )
        );
    }

    #[test]
    fn a_user_and_password_are_kept_apart() {
        assert_eq!(
            split_credentials("tls://auth:p%40ss@broker.internal:4443").unwrap(),
            (
                "tls://broker.internal:4443".to_string(),
                NatsCredentials::UserPassword {
                    user: "auth".into(),
                    password: "p@ss".into()
                }
            )
        );
        // The URL standard drops an empty password: what is left is a token.
        assert_eq!(
            split_credentials("nats://auth:@nats:4222").unwrap().1,
            NatsCredentials::Token("auth".into())
        );
    }

    #[test]
    fn unreadable_urls_are_refused() {
        for url in [
            "not a url",
            "nats://:secret@nats:4222",
            "nats://bad%zz@nats:4222",
            "nats://%ff@nats:4222",
        ] {
            assert!(split_credentials(url).is_err(), "{url} was accepted");
        }
    }

    #[test]
    fn credentials_never_reach_debug_output() {
        let token = format!("{:?}", NatsCredentials::Token("s3cr3t".into()));
        let pair = format!(
            "{:?}",
            NatsCredentials::UserPassword {
                user: "auth".into(),
                password: "p@ss".into()
            }
        );
        assert!(!token.contains("s3cr3t") && !pair.contains("p@ss"));
        assert!(pair.contains("auth"));
    }

    #[test]
    fn a_cluster_shares_its_credentials() {
        let (addresses, credentials) =
            split_cluster("nats://secret@a:4222, nats://secret@b:4222,").unwrap();
        assert_eq!(addresses, ["nats://a:4222", "nats://b:4222"]);
        assert_eq!(credentials, NatsCredentials::Token("secret".into()));
        assert!(split_cluster("nats://one@a:4222,nats://two@b:4222").is_err());
        assert!(split_cluster(" , ").is_err());
    }
}
