//! Authorization Code with PKCE through `/oauth/authorize` and `/oauth/token`
//! (RFC 6749 4.1, RFC 7636, RFC 8252).
//!
//! - a request is accepted only for a registered client, redirect and S256
//!   challenge; errors before the redirect is trusted are never redirected;
//! - a code is single use: a failed redemption burns it, a replay revokes its session;
//! - a third-party client needs a fresh re-authentication to be approved;
//! - tokens carry only the consented scopes, on issue and on refresh;
//! - session limits and account status are enforced at redemption.

use serde_json::{Value, json};

use super::{Pkce, authorize, claims, form, pkce, query_param};
use crate::common::{
    app::TestApp,
    fixtures::{self, AuthenticatedUser},
};

const PRIMARY: &str = "primary-web";
const PARTNER: &str = "partner-cli";
const CALLBACK: &str = "https://app.example.com/callback";
const LOOPBACK: &str = "http://127.0.0.1/callback";
const CONSENT: &str = "http://localhost:5173/authorize";

async fn register_client(
    app: &TestApp,
    client_id: &str,
    is_primary: bool,
    scopes: &[&str],
    max_sessions: i16,
) {
    sqlx::query(
        "INSERT INTO registered_clients
             (client_id, display_name, is_primary, scopes, redirect_uris, allows_loopback_redirect, default_max_sessions)
         VALUES ($1, $1, $2, $3, $4, TRUE, $5)",
    )
    .bind(client_id)
    .bind(is_primary)
    .bind(scopes.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    .bind(vec![CALLBACK.to_string(), LOOPBACK.to_string()])
    .bind(max_sessions)
    .execute(&app.db)
    .await
    .unwrap();
}

fn parameters<'a>(
    client_id: &'a str,
    redirect_uri: &'a str,
    challenge: &'a str,
    extra: &[(&'a str, &'a str)],
) -> Vec<(&'a str, &'a str)> {
    let mut parameters = vec![
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
        ("state", "xyz-state"),
    ];
    for (name, value) in extra {
        parameters.retain(|(n, _)| n != name);
        parameters.push((name, value));
    }
    parameters
}

/// Start a request and return the `request_id` handed to the consent page.
async fn request(
    app: &TestApp,
    client_id: &str,
    redirect_uri: &str,
    pkce: &Pkce,
    extra: &[(&str, &str)],
) -> String {
    let (status, location, body) = authorize(
        app,
        &parameters(client_id, redirect_uri, &pkce.challenge, extra),
    )
    .await;
    assert_eq!(
        status, 303,
        "authorization request refused: {location} {body}"
    );
    assert!(location.starts_with(CONSENT), "{location}");
    query_param(&location, "request_id").expect("the consent page gets a request id")
}

async fn approve_raw(
    app: &TestApp,
    user: &AuthenticatedUser,
    request_id: &str,
    body: Value,
) -> (u16, Value) {
    let response = app
        .post_auth(
            &format!("/oauth/authorization-requests/{request_id}/approve"),
            &user.access_token,
            &body,
        )
        .await;
    let status = response.status().as_u16();
    (status, response.json().await.unwrap_or(Value::Null))
}

/// Request, approve with the password, and return the code from the redirect.
async fn code_for(
    app: &TestApp,
    user: &AuthenticatedUser,
    client_id: &str,
    redirect_uri: &str,
    pkce: &Pkce,
) -> String {
    let request_id = request(app, client_id, redirect_uri, pkce, &[]).await;
    let (status, body) = approve_raw(
        app,
        user,
        &request_id,
        json!({ "current_password": user.password }),
    )
    .await;
    assert_eq!(status, 200, "approval failed: {body}");
    let redirect = body["redirect_to"].as_str().unwrap();
    assert!(redirect.starts_with(redirect_uri), "{redirect}");
    assert_eq!(query_param(redirect, "state").as_deref(), Some("xyz-state"));
    query_param(redirect, "code").expect("redirect carries a code")
}

async fn redeem(
    app: &TestApp,
    code: &str,
    verifier: &str,
    client_id: &str,
    redirect_uri: &str,
) -> (u16, Value) {
    form(
        app,
        "/oauth/token",
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("code_verifier", verifier),
            ("client_id", client_id),
            ("redirect_uri", redirect_uri),
            ("device_name", "CLI"),
        ],
        None,
    )
    .await
}

async fn refresh(app: &TestApp, refresh_token: &str, client_id: &str) -> (u16, Value) {
    form(
        app,
        "/oauth/token",
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", client_id),
        ],
        None,
    )
    .await
}

#[tokio::test]
async fn a_primary_client_signs_in_end_to_end() {
    let app = TestApp::spawn().await;
    register_client(&app, PRIMARY, true, &[], 5).await;
    let user = fixtures::authenticated_user(&app, 720).await;
    let p = pkce();
    let request_id = request(&app, PRIMARY, CALLBACK, &p, &[]).await;

    let described: Value = app
        .get_auth(
            &format!("/oauth/authorization-requests/{request_id}"),
            &user.access_token,
        )
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(described["client_name"], PRIMARY);
    assert_eq!(described["redirect_uri"], CALLBACK);
    assert_eq!(described["unrestricted"], true);
    assert_eq!(described["reauthentication_required"], false);
    assert!(described.get("sessions_allowed").is_none());

    // The primary client needs no fresh re-authentication.
    app.clear_recent_reauth(&user.access_token).await;
    let (status, body) = approve_raw(&app, &user, &request_id, json!({})).await;
    assert_eq!(status, 200, "{body}");
    let code = query_param(body["redirect_to"].as_str().unwrap(), "code").unwrap();

    let (status, tokens) = redeem(&app, &code, &p.verifier, PRIMARY, CALLBACK).await;
    assert_eq!(status, 200, "{tokens}");
    assert_eq!(tokens["token_type"], "Bearer");
    assert!(tokens["expires_in"].as_u64().unwrap() > 0);
    assert!(tokens.get("scope").is_none());
    assert_eq!(
        claims(tokens["access_token"].as_str().unwrap())["sub"],
        user.id.to_string()
    );

    let (client_id, device_name): (String, String) = sqlx::query_as(
        "SELECT client_id, device_name FROM sessions WHERE user_id = $1 AND session_type = 'device'",
    )
    .bind(user.id)
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert_eq!((client_id.as_str(), device_name.as_str()), (PRIMARY, "CLI"));

    // A decided request cannot be decided again.
    let (status, _) = approve_raw(&app, &user, &request_id, json!({})).await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn describe_requires_a_signed_in_user() {
    let app = TestApp::spawn().await;
    register_client(&app, PRIMARY, true, &[], 5).await;
    let request_id = request(&app, PRIMARY, CALLBACK, &pkce(), &[]).await;

    let res = app
        .get(&format!("/oauth/authorization-requests/{request_id}"))
        .await;
    assert_eq!(res.status().as_u16(), 401);
}

#[tokio::test]
async fn a_denied_request_goes_back_to_the_client() {
    let app = TestApp::spawn().await;
    register_client(&app, PRIMARY, true, &[], 5).await;
    let user = fixtures::authenticated_user(&app, 730).await;
    let request_id = request(&app, PRIMARY, CALLBACK, &pkce(), &[]).await;

    let response = app
        .post_auth(
            &format!("/oauth/authorization-requests/{request_id}/deny"),
            &user.access_token,
            &json!({}),
        )
        .await;
    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.unwrap();
    let redirect = body["redirect_to"].as_str().unwrap();
    assert!(redirect.starts_with(CALLBACK));
    assert_eq!(
        query_param(redirect, "error").as_deref(),
        Some("access_denied")
    );
    assert_eq!(query_param(redirect, "state").as_deref(), Some("xyz-state"));
    assert!(query_param(redirect, "code").is_none());
}

#[tokio::test]
async fn a_replayed_code_is_refused_and_revokes_its_session() {
    let app = TestApp::spawn().await;
    register_client(&app, PRIMARY, true, &[], 5).await;
    let user = fixtures::authenticated_user(&app, 721).await;
    let p = pkce();
    let code = code_for(&app, &user, PRIMARY, CALLBACK, &p).await;

    let (_, tokens) = redeem(&app, &code, &p.verifier, PRIMARY, CALLBACK).await;

    let (status, err) = redeem(&app, &code, &p.verifier, PRIMARY, CALLBACK).await;
    assert_eq!(
        (status, err["error"].as_str()),
        (400, Some("invalid_grant"))
    );

    let (status, _) = refresh(&app, tokens["refresh_token"].as_str().unwrap(), PRIMARY).await;
    assert_eq!(status, 400, "the replayed code's session must be revoked");
}

#[tokio::test]
async fn a_wrong_verifier_burns_the_code() {
    let app = TestApp::spawn().await;
    register_client(&app, PRIMARY, true, &[], 5).await;
    let user = fixtures::authenticated_user(&app, 722).await;
    let p = pkce();
    let code = code_for(&app, &user, PRIMARY, CALLBACK, &p).await;

    let wrong = pkce();
    let (status, _) = redeem(&app, &code, &wrong.verifier, PRIMARY, CALLBACK).await;
    assert_eq!(status, 400);

    let (status, _) = redeem(&app, &code, &p.verifier, PRIMARY, CALLBACK).await;
    assert_eq!(status, 400, "a code must not survive a failed redemption");
}

#[tokio::test]
async fn a_code_is_bound_to_its_client_and_redirect() {
    let app = TestApp::spawn().await;
    register_client(&app, PRIMARY, true, &[], 5).await;
    register_client(&app, PARTNER, false, &[], 5).await;
    let user = fixtures::authenticated_user(&app, 723).await;

    let p = pkce();
    let code = code_for(&app, &user, PRIMARY, CALLBACK, &p).await;
    let (status, _) = redeem(&app, &code, &p.verifier, PARTNER, CALLBACK).await;
    assert_eq!(status, 400);

    let p = pkce();
    let code = code_for(&app, &user, PRIMARY, CALLBACK, &p).await;
    let (status, _) = redeem(&app, &code, &p.verifier, PRIMARY, LOOPBACK).await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn only_registered_or_loopback_redirects_are_accepted() {
    let app = TestApp::spawn().await;
    register_client(&app, PRIMARY, true, &[], 5).await;
    let user = fixtures::authenticated_user(&app, 724).await;
    let p = pkce();

    for redirect in [
        "https://evil.example.com/callback",
        "https://app.example.com/callback/extra",
        "http://localhost:43123/callback",
        "http://127.0.0.1:43123/elsewhere",
    ] {
        let (status, location, body) =
            authorize(&app, &parameters(PRIMARY, redirect, &p.challenge, &[])).await;
        assert_eq!(status, 400, "redirect {redirect}");
        assert!(
            location.is_empty(),
            "an unchecked redirect is never followed"
        );
        assert_eq!(body["error"], "invalid_request");
    }

    let (status, _, body) =
        authorize(&app, &parameters("nobody", CALLBACK, &p.challenge, &[])).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (401, Some("invalid_client"))
    );

    // A loopback code redeems against the exact redirect it was minted for.
    for redirect in [
        "http://[::1]:43123/callback",
        "http://127.0.0.1:43123/callback",
    ] {
        request(&app, PRIMARY, redirect, &p, &[]).await;
    }
    let code = code_for(&app, &user, PRIMARY, "http://127.0.0.1:43123/callback", &p).await;
    let (status, _) = redeem(
        &app,
        &code,
        &p.verifier,
        PRIMARY,
        "http://127.0.0.1:43123/callback",
    )
    .await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn only_s256_challenges_are_accepted() {
    let app = TestApp::spawn().await;
    register_client(&app, PRIMARY, true, &[], 5).await;
    let p = pkce();

    for (extra, expected) in [
        (
            vec![
                ("code_challenge", p.verifier.as_str()),
                ("code_challenge_method", "plain"),
            ],
            "invalid_request",
        ),
        (vec![("code_challenge", "too-short")], "invalid_request"),
        (
            vec![("response_type", "token")],
            "unsupported_response_type",
        ),
    ] {
        let (status, location, _) =
            authorize(&app, &parameters(PRIMARY, CALLBACK, &p.challenge, &extra)).await;
        assert_eq!(status, 303, "{extra:?}");
        assert!(location.starts_with(CALLBACK), "{location}");
        assert_eq!(query_param(&location, "error").as_deref(), Some(expected));
        assert_eq!(
            query_param(&location, "state").as_deref(),
            Some("xyz-state")
        );
    }
}

#[tokio::test]
async fn a_third_party_client_requires_a_fresh_reauthentication() {
    let app = TestApp::spawn().await;
    register_client(&app, PARTNER, false, &[], 5).await;
    let user = fixtures::authenticated_user(&app, 726).await;
    app.clear_recent_reauth(&user.access_token).await;
    let p = pkce();
    let request_id = request(&app, PARTNER, CALLBACK, &p, &[]).await;

    let described: Value = app
        .get_auth(
            &format!("/oauth/authorization-requests/{request_id}"),
            &user.access_token,
        )
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(described["reauthentication_required"], true);

    let (status, err) = approve_raw(&app, &user, &request_id, json!({})).await;
    assert_eq!(
        (status, err["code"].as_str()),
        (403, Some("reauthentication_required"))
    );

    let (status, _) = approve_raw(
        &app,
        &user,
        &request_id,
        json!({ "current_password": "Wrong-Password-1" }),
    )
    .await;
    assert!((400..500).contains(&status), "a wrong password is refused");

    // The refusals left the request to approve.
    let (status, body) = approve_raw(
        &app,
        &user,
        &request_id,
        json!({ "current_password": user.password }),
    )
    .await;
    assert_eq!(status, 200, "{body}");
}

#[tokio::test]
async fn tokens_carry_only_the_consented_scopes_even_after_refresh() {
    let app = TestApp::spawn().await;
    for action in ["read", "write"] {
        sqlx::query(
            "WITH p AS (INSERT INTO permissions (resource, action) VALUES ('docs', $1) RETURNING id)
             INSERT INTO role_permissions (role_id, permission_id)
             SELECT r.id, p.id FROM roles r, p WHERE r.name = 'user'",
        )
        .bind(action)
        .execute(&app.db)
        .await
        .unwrap();
    }
    sqlx::query("INSERT INTO permissions (resource, action) VALUES ('billing', 'read')")
        .execute(&app.db)
        .await
        .unwrap();
    register_client(&app, PARTNER, false, &["docs:read", "billing:read"], 5).await;
    let user = fixtures::authenticated_user(&app, 727).await;

    let p = pkce();
    let request_id = request(&app, PARTNER, CALLBACK, &p, &[]).await;
    let described: Value = app
        .get_auth(
            &format!("/oauth/authorization-requests/{request_id}"),
            &user.access_token,
        )
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(described["scopes"], json!(["docs:read"]));
    assert_eq!(described["unavailable_scopes"], json!(["billing:read"]));

    let code = code_for(&app, &user, PARTNER, CALLBACK, &p).await;
    let (_, tokens) = redeem(&app, &code, &p.verifier, PARTNER, CALLBACK).await;
    assert_eq!(tokens["scope"], "docs:read");
    let issued = claims(tokens["access_token"].as_str().unwrap());
    assert_eq!(issued["permissions"], json!(["docs:read"]));
    assert!(
        issued.get("roles").is_none(),
        "roles are dropped from scoped tokens"
    );

    let refresh_token = tokens["refresh_token"].as_str().unwrap();
    // A client's session is refreshed by that client, at the token endpoint.
    let first_party = app
        .post("/auth/refresh", &json!({ "refresh_token": refresh_token }))
        .await;
    assert_eq!(first_party.status(), 401);
    let (status, refreshed) = refresh(&app, refresh_token, PARTNER).await;
    assert_eq!(status, 200, "{refreshed}");
    let refreshed = claims(refreshed["access_token"].as_str().unwrap());
    assert_eq!(refreshed["permissions"], json!(["docs:read"]));

    // A password sign-in stays unrestricted.
    let mut own = claims(&user.access_token)["permissions"]
        .as_array()
        .unwrap()
        .clone();
    own.sort_by_key(|v| v.as_str().unwrap().to_owned());
    assert_eq!(own, vec![json!("docs:read"), json!("docs:write")]);
}

#[tokio::test]
async fn a_request_asks_for_a_subset_of_the_client_scopes() {
    let app = TestApp::spawn().await;
    register_client(&app, PARTNER, false, &["users:read", "audit:read"], 5).await;
    let p = pkce();

    let (status, location, _) = authorize(
        &app,
        &parameters(
            PARTNER,
            CALLBACK,
            &p.challenge,
            &[("scope", "users:manage")],
        ),
    )
    .await;
    assert_eq!(status, 303);
    assert_eq!(
        query_param(&location, "error").as_deref(),
        Some("invalid_scope")
    );

    let user = fixtures::authenticated_user(&app, 731).await;
    let request_id = request(&app, PARTNER, CALLBACK, &p, &[("scope", "audit:read")]).await;
    let described: Value = app
        .get_auth(
            &format!("/oauth/authorization-requests/{request_id}"),
            &user.access_token,
        )
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(described["unavailable_scopes"], json!(["audit:read"]));
    assert_eq!(described["unrestricted"], false);
}

#[tokio::test]
async fn redemption_enforces_the_session_limit() {
    let app = TestApp::spawn().await;
    register_client(&app, PARTNER, false, &[], 1).await;
    let user = fixtures::authenticated_user(&app, 728).await;

    let first = pkce();
    let code = code_for(&app, &user, PARTNER, CALLBACK, &first).await;
    assert_eq!(
        redeem(&app, &code, &first.verifier, PARTNER, CALLBACK)
            .await
            .0,
        200
    );

    let second = pkce();
    let code = code_for(&app, &user, PARTNER, CALLBACK, &second).await;
    let (status, err) = redeem(&app, &code, &second.verifier, PARTNER, CALLBACK).await;
    assert_eq!(
        (status, err["error"].as_str()),
        (400, Some("invalid_grant"))
    );
    assert!(
        err["error_description"]
            .as_str()
            .unwrap()
            .contains("session limit")
    );
}

#[tokio::test]
async fn a_suspended_account_cannot_redeem_an_approved_code() {
    let app = TestApp::spawn().await;
    register_client(&app, PRIMARY, true, &[], 5).await;
    let user = fixtures::authenticated_user(&app, 729).await;
    let p = pkce();
    let code = code_for(&app, &user, PRIMARY, CALLBACK, &p).await;

    sqlx::query("UPDATE users SET status = 'suspended' WHERE id = $1")
        .bind(user.id)
        .execute(&app.db)
        .await
        .unwrap();

    let (status, err) = redeem(&app, &code, &p.verifier, PRIMARY, CALLBACK).await;
    assert_eq!(
        (status, err["error"].as_str()),
        (400, Some("invalid_grant"))
    );
}

#[tokio::test]
async fn a_registered_redirect_keeps_its_query() {
    let app = TestApp::spawn().await;
    let redirect = "https://app.example.com/callback?tenant=acme";
    sqlx::query(
        "INSERT INTO registered_clients (client_id, display_name, is_primary, redirect_uris)
         VALUES ('tenant-web', 'Tenant', TRUE, $1)",
    )
    .bind(vec![redirect.to_owned()])
    .execute(&app.db)
    .await
    .unwrap();
    let user = fixtures::authenticated_user(&app, 830).await;
    let p = pkce();

    // With a single registered redirect, the parameter may be left out.
    let (status, location, _) = authorize(
        &app,
        &[
            ("response_type", "code"),
            ("client_id", "tenant-web"),
            ("code_challenge", &p.challenge),
            ("code_challenge_method", "S256"),
            ("state", "xyz-state"),
        ],
    )
    .await;
    assert_eq!(status, 303);
    let request_id = query_param(&location, "request_id").unwrap();
    let (_, body) = approve_raw(&app, &user, &request_id, json!({})).await;
    let url = reqwest::Url::parse(body["redirect_to"].as_str().unwrap()).unwrap();
    let names: Vec<String> = url.query_pairs().map(|(k, _)| k.into_owned()).collect();
    assert_eq!(names, ["tenant", "code", "state"]);
    assert_eq!(query_param(url.as_str(), "tenant").as_deref(), Some("acme"));
}
