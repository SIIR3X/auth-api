//! Operational commands handled by the binary instead of starting the server.

use serde_json::json;
use sqlx::PgPool;

use crate::{
    domain::audit::AuditAction,
    repositories::{
        audit::{self, NewAuditEntry},
        registered_client::{self, NewRegisteredClient},
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

    // The check, the grant and its audit entry commit together, under the
    // account's lock: no role without its trace, no factor removed meanwhile.
    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
    user::lock_row(&mut *tx, account.id)
        .await
        .map_err(|e| e.to_string())?;
    // As over HTTP: the administration refuses every session that did not
    // prove a second factor, so the account must have one first.
    if role::grants_administration(&mut *tx, granted.id)
        .await
        .map_err(|e| e.to_string())?
    {
        let ready = account.status == crate::domain::user::UserStatus::Active
            && user::has_second_factor(&mut *tx, account.id)
                .await
                .map_err(|e| e.to_string())?;
        if !ready {
            return Err(format!(
                "{} must be an active account with a verified second factor or a passkey \
                 before it receives the {} role: sign in and enroll one first",
                grant.email, granted.name
            ));
        }
    }

    match role::assign_to_user(&mut *tx, account.id, granted.id, None).await {
        Ok(_) => {}
        // ON CONFLICT DO NOTHING returns no row: the role was already held.
        Err(sqlx::Error::RowNotFound) => return Ok(()),
        Err(e) => return Err(e.to_string()),
    }
    audit::append(
        &mut *tx,
        &NewAuditEntry {
            user_id: Some(account.id),
            request_id: None,
            action: AuditAction::RoleAssigned,
            ip_address: None,
            metadata: {
                let mut metadata = command_line_origin();
                metadata["role"] = json!(granted.name);
                metadata
            },
        },
    )
    .await
    .map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(())
}

/// Who ran a command-line change: the account on the server (the one behind
/// `sudo` when there is one) and the host. Command-line changes have no
/// administrator account; this is what the audit log can tell of them.
pub fn command_line_origin() -> serde_json::Value {
    let operator = ["SUDO_USER", "USER", "LOGNAME"]
        .iter()
        .find_map(|name| std::env::var(name).ok().filter(|v| !v.is_empty()))
        .unwrap_or_else(|| "unknown".to_owned());
    let host = std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .map(|h| h.trim().to_owned())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());
    json!({ "by": "command_line", "operator": operator, "host": host })
}

/// Save a client application from the command line, validated like the
/// administration does and audited in the same transaction.
pub async fn register_client(
    pool: &PgPool,
    registration: &ClientRegistration,
) -> Result<crate::domain::registered_client::RegisteredClient, String> {
    let client = registration.as_new();
    crate::domain::registered_client::check_settings(
        client.client_id,
        client.display_name,
        client.redirect_uris,
        client.default_max_sessions,
    )?;
    let unknown = role::unknown_permissions(pool, client.scopes)
        .await
        .map_err(|e| e.to_string())?;
    if !unknown.is_empty() {
        return Err(format!("unknown scopes: {}", unknown.join(", ")));
    }

    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
    let existed = registered_client::lock_existing(&mut *tx, client.client_id)
        .await
        .map_err(|e| e.to_string())?;
    let previous = registered_client::find_by_id(&mut *tx, client.client_id)
        .await
        .map_err(|e| e.to_string())?;
    let saved = registered_client::upsert(&mut *tx, &client)
        .await
        .map_err(|e| e.to_string())?;
    audit::append(
        &mut *tx,
        &NewAuditEntry {
            user_id: None,
            request_id: None,
            action: if existed {
                AuditAction::ClientUpdated
            } else {
                AuditAction::ClientRegistered
            },
            ip_address: None,
            metadata: {
                let mut metadata =
                    crate::domain::registered_client::audit_changes(previous.as_ref(), &saved);
                for (key, value) in command_line_origin().as_object().unwrap() {
                    metadata[key] = value.clone();
                }
                metadata
            },
        },
    )
    .await
    .map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(saved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_command_line_change_names_its_operator_and_host() {
        let origin = command_line_origin();
        assert_eq!(origin["by"], "command_line");
        assert!(origin["operator"].as_str().is_some_and(|o| !o.is_empty()));
        assert!(origin["host"].as_str().is_some_and(|h| !h.is_empty()));
    }

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
