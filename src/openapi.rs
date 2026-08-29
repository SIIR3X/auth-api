//! OpenAPI document generated from the handlers, so the contract cannot drift
//! from the code. `docs/dev/api/openapi.yaml` is produced by
//! `cargo run --quiet --bin openapi`; the tests below fail when the committed
//! file is stale or when a routed endpoint is missing from the document.
//!
//! Only the public listener is described: `/metrics` lives on the internal one.

use utoipa::{
    Modify, OpenApi,
    openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Auth API",
        description = "Authentication API: accounts, sessions, second factors and client \
            applications. Issues ES256 access tokens and rotating refresh tokens, and publishes \
            the JWKS resource servers verify them with.",
        license(name = "MIT")
    ),
    servers((url = "http://localhost:3000", description = "Local development")),
    paths(
        crate::handlers::health,
        crate::handlers::jwks,
        crate::handlers::auth::register,
        crate::handlers::auth::login,
        crate::handlers::auth::logout,
        crate::handlers::auth::refresh,
        crate::handlers::auth::verify_email,
        crate::handlers::auth::forgot_password,
        crate::handlers::auth::reset_password,
        crate::handlers::auth::complete_two_factor,
        crate::handlers::auth::recovery_login,
        crate::handlers::auth::complete_email_two_factor,
        crate::handlers::auth::resend_email_two_factor,
        crate::handlers::device::authorize,
        crate::handlers::device::token,
        crate::handlers::device::describe,
        crate::handlers::device::verify,
        crate::handlers::authorize::describe,
        crate::handlers::authorize::approve,
        crate::handlers::authorize::token,
        crate::handlers::user::me,
        crate::handlers::user::change_username,
        crate::handlers::user::start_email_change,
        crate::handlers::user::verify_current_email,
        crate::handlers::user::submit_new_email,
        crate::handlers::user::confirm_new_email,
        crate::handlers::user::change_password,
        crate::handlers::user::change_locale,
        crate::handlers::user::delete_account,
        crate::handlers::user::reauthenticate,
        crate::handlers::audit::list,
        crate::handlers::session::list,
        crate::handlers::session::revoke,
        crate::handlers::session::revoke_all,
        crate::handlers::two_factor::list,
        crate::handlers::two_factor::setup_totp,
        crate::handlers::two_factor::verify_totp_setup,
        crate::handlers::two_factor::disable_totp,
        crate::handlers::two_factor::regenerate_recovery_codes,
        crate::handlers::two_factor::use_recovery_code,
        crate::handlers::two_factor::setup_email_otp,
        crate::handlers::two_factor::send_email_otp_code,
        crate::handlers::two_factor::verify_email_otp_setup,
        crate::handlers::two_factor::disable_email_otp,
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "discovery", description = "Health and public keys"),
        (name = "auth", description = "Registration, sign-in, tokens and two-factor challenges"),
        (name = "device", description = "Device authorization flow (RFC 8628)"),
        (name = "authorize", description = "Authorization code flow with PKCE (RFC 7636)"),
        (name = "account", description = "The caller's profile, security history and re-authentication"),
        (name = "email-change", description = "Changing the account's email address"),
        (name = "sessions", description = "Active sessions"),
        (name = "two-factor", description = "Second factors and recovery codes"),
    )
)]
pub struct ApiDoc;

/// Registers the scheme referenced by `security(("bearer" = []))`.
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi
            .components
            .as_mut()
            .expect("the derived document always has components");
        components.add_security_scheme(
            "bearer",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .build(),
            ),
        );
    }
}

/// The document as YAML, exactly as committed.
pub fn yaml() -> String {
    ApiDoc::openapi()
        .to_yaml()
        .expect("the OpenAPI document serializes to YAML")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    const SPEC_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/docs/dev/api/openapi.yaml");

    #[test]
    fn the_committed_document_matches_the_code() {
        let committed = std::fs::read_to_string(SPEC_PATH).unwrap_or_default();
        assert!(
            committed == yaml(),
            "docs/dev/api/openapi.yaml is stale: run `cargo run --quiet --bin openapi > docs/dev/api/openapi.yaml`"
        );
    }

    /// Every `.route(...)` of the router, with its nesting prefix.
    fn routed_endpoints() -> BTreeSet<(String, String)> {
        let source = include_str!("handlers/mod.rs");
        let functions: Vec<(usize, &str)> = source
            .match_indices("fn ")
            .filter_map(|(at, _)| {
                let name: String = source[at + 3..]
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                (!name.is_empty()).then(|| (at, &source[at + 3..at + 3 + name.len()]))
            })
            .collect();

        let mut routes = BTreeSet::new();
        for (at, _) in source.match_indices(".route(") {
            let call = &source[at..];
            let open = call.find('"').expect("route path") + 1;
            let close = open + call[open..].find('"').expect("route path end");
            let route = &call[open..close];
            let method = call[close..]
                .trim_start_matches(|c: char| c == '"' || c == ',' || c.is_whitespace())
                .split('(')
                .next()
                .expect("route method")
                .to_owned();
            let enclosing = functions
                .iter()
                .rev()
                .find(|(start, _)| *start < at)
                .map(|(_, name)| *name)
                .unwrap_or_default();
            let prefix = match enclosing {
                "auth_router" => "/auth",
                "me_router" | "me_strict_router" => "/users/me",
                _ => "",
            };
            let full = match route {
                "/" => prefix.to_owned(),
                _ => format!("{prefix}{route}"),
            };
            if full != "/metrics" {
                routes.insert((method, full));
            }
        }
        routes
    }

    fn documented_endpoints() -> BTreeSet<(String, String)> {
        let document = serde_json::to_value(ApiDoc::openapi()).expect("document to JSON");
        let mut endpoints = BTreeSet::new();
        for (path, item) in document["paths"].as_object().expect("paths") {
            for method in ["get", "post", "put", "patch", "delete"] {
                if item.get(method).is_some() {
                    endpoints.insert((method.to_owned(), path.clone()));
                }
            }
        }
        endpoints
    }

    #[test]
    fn every_routed_endpoint_is_documented_and_nothing_else() {
        let routed = routed_endpoints();
        let documented = documented_endpoints();
        // A floor, not a count: it catches a parser that silently stops finding routes.
        assert!(
            routed.len() >= 40,
            "the route parser found only {} routes",
            routed.len()
        );
        assert_eq!(
            routed.difference(&documented).collect::<Vec<_>>(),
            Vec::<&(String, String)>::new(),
            "routed but not documented"
        );
        assert_eq!(
            documented.difference(&routed).collect::<Vec<_>>(),
            Vec::<&(String, String)>::new(),
            "documented but not routed"
        );
    }
}
