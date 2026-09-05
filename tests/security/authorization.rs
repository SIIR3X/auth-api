//! Authorization matrix: every documented operation, called with every kind of
//! bad credential.
//!
//! Operations come from the OpenAPI document, and `src/openapi.rs` fails the
//! build when a routed endpoint is missing from it: a new route is covered here
//! as soon as it exists. `PUBLIC` below is the only place an operation can be
//! exempted from authentication, and it must agree with the document.

use std::collections::BTreeSet;

use auth_api::utils::jwt::Claims;
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use testkit::tokens;
use utoipa::OpenApi;
use uuid::Uuid;

use crate::common::{app::TestApp, fixtures};

/// Operations reachable without an access token.
const PUBLIC: &[&str] = &[
    "GET /.well-known/jwks.json",
    "GET /health",
    "POST /auth/authorize/token",
    "POST /auth/device",
    "POST /auth/device/token",
    "POST /auth/forgot-password",
    "POST /auth/login",
    "POST /auth/refresh",
    "POST /auth/register",
    "POST /auth/reset-password",
    "POST /auth/two-factor/complete",
    "POST /auth/two-factor/email/complete",
    "POST /auth/two-factor/email/resend",
    "POST /auth/two-factor/recovery",
    "POST /auth/verify-email",
];

struct Operation {
    method: Method,
    template: String,
    documented_as_protected: bool,
}

impl Operation {
    fn key(&self) -> String {
        format!("{} {}", self.method, self.template)
    }

    /// A concrete path: identifiers the API will not find, well-formed.
    fn path(&self) -> String {
        self.template
            .split('/')
            .map(|segment| match segment {
                "{user_code}" => "ABCD-2345".to_owned(),
                s if s.starts_with('{') => Uuid::new_v4().to_string(),
                s => s.to_owned(),
            })
            .collect::<Vec<_>>()
            .join("/")
    }
}

fn operations() -> Vec<Operation> {
    let document = serde_json::to_value(auth_api::openapi::ApiDoc::openapi()).unwrap();
    let mut operations = Vec::new();
    for (template, item) in document["paths"].as_object().unwrap() {
        for (method, operation) in item.as_object().unwrap() {
            let Ok(method) = method.to_ascii_uppercase().parse::<Method>() else {
                continue;
            };
            let documented_as_protected = operation["security"]
                .as_array()
                .is_some_and(|schemes| schemes.iter().any(|s| s.get("bearer").is_some()));
            operations.push(Operation {
                method,
                template: template.clone(),
                documented_as_protected,
            });
        }
    }
    assert!(
        operations.len() >= 40,
        "found only {} operations",
        operations.len()
    );
    operations
}

fn protected_operations() -> Vec<Operation> {
    operations()
        .into_iter()
        .filter(|op| !PUBLIC.contains(&op.key().as_str()))
        .collect()
}

async fn call(app: &TestApp, op: &Operation, authorization: Option<&str>) -> (StatusCode, Value) {
    let mut request = app.client.request(op.method.clone(), app.url(&op.path()));
    if let Some(value) = authorization {
        request = request.header("authorization", value);
    }
    if op.method != Method::GET {
        request = request.json(&json!({}));
    }
    let response = request.send().await.expect("request failed");
    let status = response.status();
    let body = response.json().await.unwrap_or(Value::Null);
    (status, body)
}

#[test]
fn the_public_list_matches_the_document() {
    let operations = operations();
    let keys: BTreeSet<String> = operations.iter().map(Operation::key).collect();
    for public in PUBLIC {
        assert!(
            keys.contains(*public),
            "{public} is not a documented operation"
        );
    }
    for op in &operations {
        let public = PUBLIC.contains(&op.key().as_str());
        assert_eq!(
            op.documented_as_protected,
            !public,
            "{}: the document and the PUBLIC list disagree on authentication",
            op.key()
        );
    }
}

/// Every protected operation refuses each credential with 401, before reading
/// its input.
async fn assert_refused_everywhere(app: &TestApp, label: &str, authorization: Option<&str>) {
    for op in protected_operations() {
        let (status, body) = call(app, &op, authorization).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{} accepted {label}: {body}",
            op.key()
        );
        assert!(
            matches!(
                body["code"].as_str(),
                Some("unauthorized" | "token_invalid")
            ),
            "{} answered {label} with {body}",
            op.key()
        );
    }
}

#[tokio::test]
async fn missing_or_malformed_credentials_are_refused() {
    let app = TestApp::spawn().await;
    assert_refused_everywhere(&app, "no credentials", None).await;
    assert_refused_everywhere(&app, "a Basic credential", Some("Basic dXNlcjpwYXNz")).await;
    assert_refused_everywhere(&app, "an empty bearer", Some("Bearer ")).await;
    assert_refused_everywhere(&app, "a random bearer", Some("Bearer not.a.token")).await;
    assert_refused_everywhere(&app, "a lowercase scheme", Some("bearer x.y.z")).await;
}

/// A real session, so each forged token fails for its own defect only.
async fn live_session(app: &TestApp, index: usize) -> (fixtures::AuthenticatedUser, Claims) {
    let user = fixtures::authenticated_user(app, index).await;
    let claims = app.decode_access_token(&user.access_token);
    (user, claims)
}

#[tokio::test]
async fn forged_tokens_for_a_live_session_are_refused() {
    let app = TestApp::spawn().await;
    let (_user, genuine) = live_session(&app, 0).await;
    let now = app.state.clock.now().unix_timestamp();

    let mut expired = app.access_claims(genuine.sub, genuine.sid);
    (expired.iat, expired.nbf, expired.exp) = (now - 901, Some(now - 901), now - 1);

    let mut not_yet_valid = app.access_claims(genuine.sub, genuine.sid);
    not_yet_valid.nbf = Some(now + 60);

    let mut foreign_issuer = app.access_claims(genuine.sub, genuine.sid);
    foreign_issuer.iss = Some("https://auth.attacker.example".into());

    let mut foreign_audience = app.access_claims(genuine.sub, genuine.sid);
    foreign_audience.aud = vec!["https://resource.example".into()];

    let mut no_issuer = app.access_claims(genuine.sub, genuine.sid);
    no_issuer.iss = None;

    let unknown_session = app.access_claims(genuine.sub, Uuid::new_v4());

    let forged = [
        ("an expired token", app.sign(&expired)),
        ("a token before its nbf", app.sign(&not_yet_valid)),
        ("a token of another issuer", app.sign(&foreign_issuer)),
        ("a token for another audience", app.sign(&foreign_audience)),
        ("a token without issuer", app.sign(&no_issuer)),
        ("a token for an unknown session", app.sign(&unknown_session)),
        (
            "a token signed by a foreign key",
            tokens::sign_with_foreign_key(&genuine),
        ),
        ("an unsigned token", tokens::unsigned(&genuine)),
        (
            "an HS256 token keyed with the public key",
            tokens::hs256_with_public_key(&genuine),
        ),
    ];
    for (label, token) in forged {
        assert_refused_everywhere(&app, label, Some(&format!("Bearer {token}"))).await;
    }
}

#[tokio::test]
async fn a_token_outlives_neither_its_expiry_nor_its_logout() {
    let app = TestApp::spawn().await;
    let (user, _) = live_session(&app, 0).await;
    let bearer = format!("Bearer {}", user.access_token);

    // Fifteen minutes later, by the application clock.
    app.clock.advance(time::Duration::seconds(901));
    assert_refused_everywhere(&app, "an access token past its expiry", Some(&bearer)).await;
    app.clock.reset();

    let logout = app
        .post_auth("/auth/logout", &user.access_token, &json!({}))
        .await;
    assert_eq!(logout.status(), StatusCode::NO_CONTENT);
    assert_refused_everywhere(
        &app,
        "the access token of a logged out session",
        Some(&bearer),
    )
    .await;
}

/// Guards the matrix itself: a valid token passes authentication everywhere,
/// so the refusals above are the credentials' doing.
#[tokio::test]
async fn a_valid_token_passes_authentication_everywhere() {
    let app = TestApp::spawn().await;
    for (index, op) in protected_operations().into_iter().enumerate() {
        // A fresh account per operation: some of them end the session.
        let (user, _) = live_session(&app, index).await;
        let (status, body) = call(&app, &op, Some(&format!("Bearer {}", user.access_token))).await;
        assert_ne!(
            status,
            StatusCode::UNAUTHORIZED,
            "{} refused a valid token: {body}",
            op.key()
        );
        assert!(
            !status.is_server_error(),
            "{} failed: {status} {body}",
            op.key()
        );
    }
}
