//! Authorization Code with PKCE (RFC 6749 4.1, RFC 7636, RFC 8252).
//!
//! - a code is minted only for a registered redirect and an S256 challenge;
//! - it is single use: a failed redemption burns it, a replay revokes its session;
//! - a third-party client needs a fresh re-authentication to be approved;
//! - tokens carry only the consented scopes, on issue and on refresh;
//! - session limits and account status are enforced at redemption.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use serde_json::{Value, json};

use crate::common::{
    app::TestApp,
    fixtures::{self, AuthenticatedUser},
};

const PRIMARY: &str = "primary-web";
const PARTNER: &str = "partner-cli";
const CALLBACK: &str = "https://app.example.com/callback";
const LOOPBACK: &str = "http://127.0.0.1/callback";

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

struct Pkce {
    verifier: String,
    challenge: String,
}

fn pkce() -> Pkce {
    let verifier = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    let challenge = B64URL.encode(auth_api::utils::crypto::sha256(verifier.as_bytes()));
    Pkce {
        verifier,
        challenge,
    }
}

async fn approve_raw(
    app: &TestApp,
    user: &AuthenticatedUser,
    client_id: &str,
    redirect_uri: &str,
    extra: Value,
) -> reqwest::Response {
    let mut body = json!({
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": "xyz-state",
    });
    body.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    app.post_auth("/auth/authorize", &user.access_token, &body)
        .await
}

/// Approve and return the code carried by the redirect.
async fn approve(
    app: &TestApp,
    user: &AuthenticatedUser,
    client_id: &str,
    redirect_uri: &str,
    pkce: &Pkce,
) -> String {
    let res = approve_raw(
        app,
        user,
        client_id,
        redirect_uri,
        json!({ "code_challenge": pkce.challenge, "current_password": user.password }),
    )
    .await;
    assert_eq!(res.status().as_u16(), 200, "approval failed");
    let body: Value = res.json().await.unwrap();
    let redirect = reqwest::Url::parse(body["redirect_to"].as_str().unwrap()).unwrap();
    assert!(
        body["redirect_to"]
            .as_str()
            .unwrap()
            .starts_with(redirect_uri)
    );
    let param = |name: &str| {
        redirect
            .query_pairs()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.into_owned())
    };
    assert_eq!(param("state").as_deref(), Some("xyz-state"));
    param("code").expect("redirect carries a code")
}

async fn redeem(
    app: &TestApp,
    code: &str,
    verifier: &str,
    client_id: &str,
    redirect_uri: &str,
) -> reqwest::Response {
    app.post(
        "/auth/authorize/token",
        &json!({
            "code": code,
            "code_verifier": verifier,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "device_name": "CLI",
        }),
    )
    .await
}

async fn status_and_code(res: reqwest::Response) -> (u16, String) {
    let status = res.status().as_u16();
    let body: Value = res.json().await.unwrap_or(Value::Null);
    (status, body["code"].as_str().unwrap_or_default().to_owned())
}

fn claims(access_token: &str) -> Value {
    let payload = access_token.split('.').nth(1).unwrap();
    serde_json::from_slice(&B64URL.decode(payload).unwrap()).unwrap()
}

#[tokio::test]
async fn a_primary_client_signs_in_end_to_end() {
    let app = TestApp::spawn().await;
    register_client(&app, PRIMARY, true, &[], 5).await;
    let user = fixtures::authenticated_user(&app, 720).await;

    let describe: Value = app
        .post_auth(
            "/auth/authorize/describe",
            &user.access_token,
            &json!({ "client_id": PRIMARY, "redirect_uri": CALLBACK }),
        )
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(describe["client_name"], PRIMARY);
    assert_eq!(describe["unrestricted"], true);
    assert!(describe["sessions_allowed"].is_null());

    // The primary client needs no fresh re-authentication.
    app.clear_recent_reauth(&user.access_token).await;
    let p = pkce();
    let res = approve_raw(
        &app,
        &user,
        PRIMARY,
        CALLBACK,
        json!({ "code_challenge": p.challenge }),
    )
    .await;
    assert_eq!(res.status().as_u16(), 200);
    let body: Value = res.json().await.unwrap();
    let redirect = reqwest::Url::parse(body["redirect_to"].as_str().unwrap()).unwrap();
    let code = redirect
        .query_pairs()
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .into_owned();

    let res = redeem(&app, &code, &p.verifier, PRIMARY, CALLBACK).await;
    assert_eq!(res.status().as_u16(), 200);
    let tokens: Value = res.json().await.unwrap();
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
}

#[tokio::test]
async fn describe_requires_a_signed_in_user() {
    let app = TestApp::spawn().await;
    register_client(&app, PRIMARY, true, &[], 5).await;

    let res = app
        .post(
            "/auth/authorize/describe",
            &json!({ "client_id": PRIMARY, "redirect_uri": CALLBACK }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 401);
}

#[tokio::test]
async fn a_replayed_code_is_refused_and_revokes_its_session() {
    let app = TestApp::spawn().await;
    register_client(&app, PRIMARY, true, &[], 5).await;
    let user = fixtures::authenticated_user(&app, 721).await;
    let p = pkce();
    let code = approve(&app, &user, PRIMARY, CALLBACK, &p).await;

    let tokens: Value = redeem(&app, &code, &p.verifier, PRIMARY, CALLBACK)
        .await
        .json()
        .await
        .unwrap();

    let (status, err) =
        status_and_code(redeem(&app, &code, &p.verifier, PRIMARY, CALLBACK).await).await;
    assert_eq!((status, err.as_str()), (400, "invalid_authorization_code"));

    let res = app
        .post(
            "/auth/refresh",
            &json!({ "refresh_token": tokens["refresh_token"] }),
        )
        .await;
    assert_eq!(
        res.status().as_u16(),
        401,
        "the replayed code's session must be revoked"
    );
}

#[tokio::test]
async fn a_wrong_verifier_burns_the_code() {
    let app = TestApp::spawn().await;
    register_client(&app, PRIMARY, true, &[], 5).await;
    let user = fixtures::authenticated_user(&app, 722).await;
    let p = pkce();
    let code = approve(&app, &user, PRIMARY, CALLBACK, &p).await;

    let wrong = pkce();
    let (status, _) =
        status_and_code(redeem(&app, &code, &wrong.verifier, PRIMARY, CALLBACK).await).await;
    assert_eq!(status, 400);

    let (status, _) =
        status_and_code(redeem(&app, &code, &p.verifier, PRIMARY, CALLBACK).await).await;
    assert_eq!(status, 400, "a code must not survive a failed redemption");
}

#[tokio::test]
async fn a_code_is_bound_to_its_client_and_redirect() {
    let app = TestApp::spawn().await;
    register_client(&app, PRIMARY, true, &[], 5).await;
    register_client(&app, PARTNER, false, &[], 5).await;
    let user = fixtures::authenticated_user(&app, 723).await;

    let p = pkce();
    let code = approve(&app, &user, PRIMARY, CALLBACK, &p).await;
    let (status, _) =
        status_and_code(redeem(&app, &code, &p.verifier, PARTNER, CALLBACK).await).await;
    assert_eq!(status, 400);

    let p = pkce();
    let code = approve(&app, &user, PRIMARY, CALLBACK, &p).await;
    let (status, _) =
        status_and_code(redeem(&app, &code, &p.verifier, PRIMARY, LOOPBACK).await).await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn only_registered_or_loopback_redirects_are_accepted() {
    let app = TestApp::spawn().await;
    register_client(&app, PRIMARY, true, &[], 5).await;
    let user = fixtures::authenticated_user(&app, 724).await;
    let p = pkce();

    for (redirect, expected) in [
        ("https://evil.example.com/callback", 422),
        ("https://app.example.com/callback/extra", 422),
        ("http://localhost:43123/callback", 422),
        ("http://127.0.0.1:43123/elsewhere", 422),
        ("http://127.0.0.1:43123/callback", 200),
        ("http://[::1]:43123/callback", 200),
    ] {
        let res = approve_raw(
            &app,
            &user,
            PRIMARY,
            redirect,
            json!({ "code_challenge": p.challenge }),
        )
        .await;
        assert_eq!(res.status().as_u16(), expected, "redirect {redirect}");
    }

    // A loopback code redeems against the exact redirect it was minted for.
    let code = approve(&app, &user, PRIMARY, "http://127.0.0.1:43123/callback", &p).await;
    let res = redeem(
        &app,
        &code,
        &p.verifier,
        PRIMARY,
        "http://127.0.0.1:43123/callback",
    )
    .await;
    assert_eq!(res.status().as_u16(), 200);
}

#[tokio::test]
async fn only_s256_challenges_are_accepted() {
    let app = TestApp::spawn().await;
    register_client(&app, PRIMARY, true, &[], 5).await;
    let user = fixtures::authenticated_user(&app, 725).await;
    let p = pkce();

    for extra in [
        json!({ "code_challenge": p.verifier, "code_challenge_method": "plain" }),
        json!({ "code_challenge": "too-short" }),
    ] {
        let res = approve_raw(&app, &user, PRIMARY, CALLBACK, extra).await;
        assert_eq!(res.status().as_u16(), 422);
    }
}

#[tokio::test]
async fn a_third_party_client_requires_a_fresh_reauthentication() {
    let app = TestApp::spawn().await;
    register_client(&app, PARTNER, false, &[], 5).await;
    let user = fixtures::authenticated_user(&app, 726).await;
    app.clear_recent_reauth(&user.access_token).await;
    let p = pkce();

    let (status, err) = status_and_code(
        approve_raw(
            &app,
            &user,
            PARTNER,
            CALLBACK,
            json!({ "code_challenge": p.challenge }),
        )
        .await,
    )
    .await;
    assert_eq!((status, err.as_str()), (403, "reauthentication_required"));

    let res = approve_raw(
        &app,
        &user,
        PARTNER,
        CALLBACK,
        json!({ "code_challenge": p.challenge, "current_password": "Wrong-Password-1" }),
    )
    .await;
    assert!(
        res.status().is_client_error(),
        "a wrong password is refused"
    );

    approve(&app, &user, PARTNER, CALLBACK, &p).await;
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
    register_client(&app, PARTNER, false, &["docs:read", "billing:read"], 5).await;
    let user = fixtures::authenticated_user(&app, 727).await;

    let describe: Value = app
        .post_auth(
            "/auth/authorize/describe",
            &user.access_token,
            &json!({ "client_id": PARTNER, "redirect_uri": CALLBACK }),
        )
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(describe["scopes"], json!(["docs:read"]));
    assert_eq!(describe["unavailable_scopes"], json!(["billing:read"]));

    let p = pkce();
    let code = approve(&app, &user, PARTNER, CALLBACK, &p).await;
    let tokens: Value = redeem(&app, &code, &p.verifier, PARTNER, CALLBACK)
        .await
        .json()
        .await
        .unwrap();
    let issued = claims(tokens["access_token"].as_str().unwrap());
    assert_eq!(issued["permissions"], json!(["docs:read"]));
    assert!(
        issued.get("roles").is_none(),
        "roles are dropped from scoped tokens"
    );

    let refreshed: Value = app
        .post(
            "/auth/refresh",
            &json!({ "refresh_token": tokens["refresh_token"] }),
        )
        .await
        .json()
        .await
        .unwrap();
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
async fn redemption_enforces_the_session_limit() {
    let app = TestApp::spawn().await;
    register_client(&app, PARTNER, false, &[], 1).await;
    let user = fixtures::authenticated_user(&app, 728).await;

    let first = pkce();
    let code = approve(&app, &user, PARTNER, CALLBACK, &first).await;
    assert_eq!(
        redeem(&app, &code, &first.verifier, PARTNER, CALLBACK)
            .await
            .status()
            .as_u16(),
        200
    );

    let second = pkce();
    let code = approve(&app, &user, PARTNER, CALLBACK, &second).await;
    let (status, err) =
        status_and_code(redeem(&app, &code, &second.verifier, PARTNER, CALLBACK).await).await;
    assert_eq!(
        (status, err.as_str()),
        (403, "device_session_limit_reached")
    );
}

#[tokio::test]
async fn a_suspended_account_cannot_redeem_an_approved_code() {
    let app = TestApp::spawn().await;
    register_client(&app, PRIMARY, true, &[], 5).await;
    let user = fixtures::authenticated_user(&app, 729).await;
    let p = pkce();
    let code = approve(&app, &user, PRIMARY, CALLBACK, &p).await;

    sqlx::query("UPDATE users SET status = 'suspended' WHERE id = $1")
        .bind(user.id)
        .execute(&app.db)
        .await
        .unwrap();

    let (status, err) =
        status_and_code(redeem(&app, &code, &p.verifier, PRIMARY, CALLBACK).await).await;
    assert_eq!((status, err.as_str()), (403, "account_suspended"));
}
