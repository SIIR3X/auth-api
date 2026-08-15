//! Operational commands handled by the binary instead of starting the server.

use crate::repositories::registered_client::NewRegisteredClient;

/// A client registration requested on the command line:
///
/// ```text
/// auth-api --register-client <client_id> --name <display name>
///          [--primary] [--scopes a:b,c:d] [--redirect-uri <uri>]...
///          [--loopback-redirect] [--max-sessions <n>]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRegistration {
    pub client_id: String,
    pub display_name: String,
    pub is_primary: bool,
    pub scopes: Vec<String>,
    pub redirect_uris: Vec<String>,
    pub allows_loopback_redirect: bool,
    pub default_max_sessions: i16,
}

impl ClientRegistration {
    pub fn as_new(&self) -> NewRegisteredClient<'_> {
        NewRegisteredClient {
            client_id: &self.client_id,
            display_name: &self.display_name,
            is_primary: self.is_primary,
            scopes: &self.scopes,
            redirect_uris: &self.redirect_uris,
            allows_loopback_redirect: self.allows_loopback_redirect,
            default_max_sessions: self.default_max_sessions,
        }
    }
}

/// Parse `--register-client` and its options. `Ok(None)` when the flag is absent.
pub fn parse_client_registration(args: &[String]) -> Result<Option<ClientRegistration>, String> {
    let Some(position) = args.iter().position(|a| a == "--register-client") else {
        return Ok(None);
    };

    let value = |index: usize, flag: &str| -> Result<String, String> {
        args.get(index)
            .filter(|v| !v.starts_with("--"))
            .cloned()
            .ok_or_else(|| format!("{flag} needs a value"))
    };

    let client_id = value(position + 1, "--register-client")?;
    if client_id.is_empty()
        || client_id.len() > 100
        || !client_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err("client id must be 1 to 100 of [A-Za-z0-9._-]".into());
    }

    let mut registration = ClientRegistration {
        client_id,
        display_name: String::new(),
        is_primary: false,
        scopes: Vec::new(),
        redirect_uris: Vec::new(),
        allows_loopback_redirect: false,
        default_max_sessions: 5,
    };

    let mut index = position + 2;
    while index < args.len() {
        match args[index].as_str() {
            "--name" => {
                registration.display_name = value(index + 1, "--name")?;
                index += 2;
            }
            "--primary" => {
                registration.is_primary = true;
                index += 1;
            }
            "--scopes" => {
                registration.scopes = value(index + 1, "--scopes")?
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect();
                index += 2;
            }
            "--redirect-uri" => {
                let uri = value(index + 1, "--redirect-uri")?;
                reqwest::Url::parse(&uri)
                    .map_err(|e| format!("invalid redirect uri {uri}: {e}"))?;
                registration.redirect_uris.push(uri);
                index += 2;
            }
            "--loopback-redirect" => {
                registration.allows_loopback_redirect = true;
                index += 1;
            }
            "--max-sessions" => {
                registration.default_max_sessions = value(index + 1, "--max-sessions")?
                    .parse::<i16>()
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or("--max-sessions must be a positive number")?;
                index += 2;
            }
            other => return Err(format!("unknown option for --register-client: {other}")),
        }
    }

    if registration.display_name.trim().is_empty() {
        return Err("--name is required".into());
    }
    Ok(Some(registration))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(line: &str) -> Vec<String> {
        line.split(' ').map(str::to_owned).collect()
    }

    #[test]
    fn absent_flag_is_not_a_command() {
        assert_eq!(parse_client_registration(&args("auth-api")), Ok(None));
    }

    #[test]
    fn full_registration_is_parsed() {
        let parsed = parse_client_registration(&args(
            "auth-api --register-client cli-app --name CLI --primary --scopes users:read,users:manage \
             --redirect-uri http://127.0.0.1/callback --loopback-redirect --max-sessions 3",
        ))
        .unwrap()
        .unwrap();

        assert_eq!(parsed.client_id, "cli-app");
        assert_eq!(parsed.display_name, "CLI");
        assert!(parsed.is_primary && parsed.allows_loopback_redirect);
        assert_eq!(parsed.scopes, vec!["users:read", "users:manage"]);
        assert_eq!(parsed.redirect_uris, vec!["http://127.0.0.1/callback"]);
        assert_eq!(parsed.default_max_sessions, 3);
    }

    #[test]
    fn invalid_registrations_are_refused() {
        for line in [
            "auth-api --register-client",
            "auth-api --register-client bad/id --name X",
            "auth-api --register-client ok",
            "auth-api --register-client ok --name X --max-sessions 0",
            "auth-api --register-client ok --name X --redirect-uri not-a-url",
            "auth-api --register-client ok --name X --bogus",
        ] {
            assert!(parse_client_registration(&args(line)).is_err(), "{line}");
        }
    }
}
