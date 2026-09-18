//! OpenID Connect: ID tokens, UserInfo and discovery.

use serde_json::{Value, json};

use super::{authorize, claims, form, pkce, query_param};
use crate::common::{
    app::TestApp,
    fixtures::{self, AuthenticatedUser},
};

const CALLBACK: &str = "https://rp.example.com/callback";

async fn register(app: &TestApp) {
    sqlx::query(
        "INSERT INTO registered_clients (client_id, display_name, is_primary, redirect_uris)
         VALUES ('rp', 'Relying party', TRUE, $1)",
    )
    .bind(vec![CALLBACK.to_owned()])
    .execute(&app.db)
    .await
    .unwrap();
}

/// Run the code flow with `scope` (and a nonce) and return the token response.
async fn sign_in(app: &TestApp, user: &AuthenticatedUser, scope: &str) -> Value {
    let p = pkce();
    let (status, location, body) = authorize(
        app,
        &[
            ("response_type", "code"),
            ("client_id", "rp"),
            ("redirect_uri", CALLBACK),
            ("code_challenge", &p.challenge),
            ("code_challenge_method", "S256"),
            ("scope", scope),
            ("nonce", "n-0S6_WzA2Mj"),
        ],
    )
    .await;
    assert_eq!(status, 303, "{body}");
    let request_id = query_param(&location, "request_id").unwrap();
    let approved: Value = app
        .post_auth(
            &format!("/oauth/authorization-requests/{request_id}/approve"),
            &user.access_token,
            &json!({}),
        )
        .await
        .json()
        .await
        .unwrap();
    let code = query_param(approved["redirect_to"].as_str().unwrap(), "code").unwrap();
    let (status, tokens) = form(
        app,
        "/oauth/token",
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("code_verifier", &p.verifier),
            ("client_id", "rp"),
            ("redirect_uri", CALLBACK),
        ],
        None,
    )
    .await;
    assert_eq!(status, 200, "{tokens}");
    tokens
}

#[tokio::test]
async fn an_openid_request_gets_an_id_token_bound_to_its_nonce_and_access_token() {
    let app = TestApp::spawn().await;
    register(&app).await;
    let user = fixtures::authenticated_user(&app, 1).await;

    let tokens = sign_in(&app, &user, "openid profile email").await;
    let access = tokens["access_token"].as_str().unwrap();
    let id_token = tokens["id_token"].as_str().expect("an ID token");
    let id = claims(id_token);
    assert_eq!(id["iss"], app.state.config.server.public_url);
    assert_eq!(id["aud"], "rp");
    assert_eq!(id["azp"], "rp");
    assert_eq!(id["sub"], user.id.to_string());
    assert_eq!(id["nonce"], "n-0S6_WzA2Mj");
    assert_eq!(id["at_hash"], auth_api::domain::oidc::at_hash(access));
    assert_eq!(id["preferred_username"], user.username);
    assert_eq!(id["email"], user.email);
    assert_eq!(id["email_verified"], true);
    assert!(id["auth_time"].as_i64().unwrap() <= id["iat"].as_i64().unwrap());

    // Identity scopes grant no permission.
    assert!(claims(access).get("permissions").is_none());

    let (status, refreshed) = form(
        &app,
        "/oauth/token",
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", tokens["refresh_token"].as_str().unwrap()),
            ("client_id", "rp"),
        ],
        None,
    )
    .await;
    assert_eq!(status, 200);
    let renewed = claims(refreshed["id_token"].as_str().unwrap());
    assert!(renewed.get("nonce").is_none());
    assert_eq!(renewed["sub"], user.id.to_string());
}

#[tokio::test]
async fn userinfo_releases_the_claims_of_the_granted_scopes() {
    let app = TestApp::spawn().await;
    register(&app).await;
    let user = fixtures::authenticated_user(&app, 1).await;

    let tokens = sign_in(&app, &user, "openid email").await;
    let response = app
        .get_auth("/oauth/userinfo", tokens["access_token"].as_str().unwrap())
        .await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let info: Value = response.json().await.unwrap();
    assert_eq!(
        info,
        json!({ "sub": user.id, "email": user.email, "email_verified": true })
    );

    // A first-party session, or one without `openid`, is not an OIDC session.
    assert_eq!(
        app.get_auth("/oauth/userinfo", &user.access_token)
            .await
            .status(),
        403
    );
    let plain = sign_in(&app, &user, "profile").await;
    assert!(plain.get("id_token").is_none());
    assert_eq!(
        app.get_auth("/oauth/userinfo", plain["access_token"].as_str().unwrap())
            .await
            .status(),
        403
    );
}

#[tokio::test]
async fn the_provider_publishes_its_configuration() {
    let app = TestApp::spawn().await;
    let configuration: Value = app
        .get("/.well-known/openid-configuration")
        .await
        .json()
        .await
        .unwrap();
    let issuer = app.state.config.server.public_url.trim_end_matches('/');
    assert_eq!(configuration["issuer"], issuer);
    assert_eq!(
        configuration["userinfo_endpoint"],
        format!("{issuer}/oauth/userinfo")
    );
    assert_eq!(
        configuration["id_token_signing_alg_values_supported"],
        json!(["ES256"])
    );
    assert_eq!(configuration["subject_types_supported"], json!(["public"]));
    let scopes = configuration["scopes_supported"].as_array().unwrap();
    assert!(scopes.contains(&json!("openid")) && scopes.contains(&json!("users:read")));
}
