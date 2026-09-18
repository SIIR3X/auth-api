//! Operational commands handled by the binary instead of starting the server.

use serde_json::json;
use sqlx::PgPool;

use crate::{
    domain::audit::AuditAction,
    repositories::{
        audit::{self, NewAuditEntry},
        registered_client::NewRegisteredClient,
        role, user,
    },
};

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
    if !crate::domain::registered_client::is_valid_client_id(&client_id) {
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

/// A role granted on the command line, typically the first administrator:
///
/// ```text
/// auth-api --grant-role <role> --user <email>
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleGrant {
    pub role: String,
    pub email: String,
}

/// Parse `--grant-role` and `--user`. `Ok(None)` when `--grant-role` is absent.
pub fn parse_role_grant(args: &[String]) -> Result<Option<RoleGrant>, String> {
    let Some(position) = args.iter().position(|a| a == "--grant-role") else {
        return Ok(None);
    };
    let value_of = |flag: &str| -> Result<String, String> {
        let index = args
            .iter()
            .position(|a| a == flag)
            .ok_or_else(|| format!("{flag} is required"))?;
        args.get(index + 1)
            .filter(|v| !v.starts_with("--") && !v.is_empty())
            .cloned()
            .ok_or_else(|| format!("{flag} needs a value"))
    };
    let role = args
        .get(position + 1)
        .filter(|v| !v.starts_with("--") && !v.is_empty())
        .cloned()
        .ok_or("--grant-role needs a role name")?;
    Ok(Some(RoleGrant {
        role,
        email: value_of("--user")?,
    }))
}

/// Grant the role to the account, audited. Granting a role the account already
/// holds changes nothing.
pub async fn grant_role(pool: &PgPool, grant: &RoleGrant) -> Result<(), String> {
    let account = user::find_by_email(pool, &grant.email)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("no account with the address {}", grant.email))?;
    let granted = role::find_by_name(pool, &grant.role)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("no role named {}", grant.role))?;

    match role::assign_to_user(pool, account.id, granted.id, None).await {
        Ok(_) => {}
        // ON CONFLICT DO NOTHING returns no row: the role was already held.
        Err(sqlx::Error::RowNotFound) => return Ok(()),
        Err(e) => return Err(e.to_string()),
    }
    audit::append(
        pool,
        &NewAuditEntry {
            user_id: Some(account.id),
            request_id: None,
            action: AuditAction::RoleAssigned,
            ip_address: None,
            metadata: json!({ "role": granted.name, "by": "command_line" }),
        },
    )
    .await
    .map_err(|e| e.to_string())?;
    Ok(())
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

    #[test]
    fn a_role_grant_names_the_role_and_the_account() {
        assert_eq!(
            parse_role_grant(&args("auth-api --grant-role admin --user a@example.com")),
            Ok(Some(RoleGrant {
                role: "admin".into(),
                email: "a@example.com".into()
            }))
        );
        assert_eq!(parse_role_grant(&args("auth-api")), Ok(None));
        assert!(parse_role_grant(&args("auth-api --grant-role --user a@example.com")).is_err());
        assert!(parse_role_grant(&args("auth-api --grant-role admin")).is_err());
        assert!(parse_role_grant(&args("auth-api --grant-role admin --user")).is_err());
    }
}
