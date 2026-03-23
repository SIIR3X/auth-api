//! WebAuthn HTTP integration tests.
//!
//! Uses `SoftPasskey` from `webauthn-authenticator-rs` to simulate a real
//! hardware authenticator entirely in software, without any browser involvement.
//!
//! Flow under test:
//!   Registration  : POST register/start -> SoftPasskey.do_registration -> POST register/finish
//!   Authentication: login (2FA challenge) -> POST webauthn/start -> SoftPasskey.do_authentication
//!                   -> POST webauthn/finish -> tokens

use serde_json::Value;
use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse, Url};

use crate::common::{app::TestApp, fixtures};

// The RP origin configured in test_config (must match webauthn config rp_origin).
const RP_ORIGIN: &str = "http://localhost:3000";

// ── helpers ──────────────────────────────────────────────────────────────────

/// Register a WebAuthn passkey for the logged-in user.
/// Returns the `WebauthnAuthenticator` (stateful — holds the private key needed for auth).
async fn register_webauthn_key(
    app: &TestApp,
    access_token: &str,
) -> WebauthnAuthenticator<SoftPasskey> {
    // 1. Start registration — server returns a challenge.
    let res = app
        .post_auth(
            "/users/me/two-factor/webauthn/register/start",
            access_token,
            &serde_json::json!({}),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200, "webauthn register/start failed");

    let ccr: CreationChallengeResponse =
        res.json().await.expect("invalid CreationChallengeResponse");

    // 2. Simulate the authenticator.
    let origin = Url::parse(RP_ORIGIN).unwrap();
    // falsify_uv=true: SoftPasskey simulates user verification even without hardware support,
    // needed because webauthn-rs may request UserVerification::Preferred/Required.
    let mut wa = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let reg_response = wa
        .do_registration(origin, ccr)
        .expect("SoftPasskey registration failed");

    // 3. Finish registration — send the credential to the server.
    let res = app
        .post_auth(
            "/users/me/two-factor/webauthn/register/finish",
            access_token,
            &reg_response,
        )
        .await;
    assert_eq!(
        res.status().as_u16(),
        200,
        "webauthn register/finish failed"
    );

    wa
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn webauthn_register_and_login() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 200).await;

    // Register a passkey.
    let mut wa = register_webauthn_key(&app, &user.access_token).await;

    // Login should now require a WebAuthn 2FA challenge.
    let res = app
        .post(
            "/auth/login",
            &serde_json::json!({
                "identifier": user.email,
                "password": user.password,
            }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200);

    let body: Value = res.json().await.unwrap();
    assert_eq!(body["two_factor_required"].as_bool(), Some(true));
    assert_eq!(body["two_factor_method"].as_str(), Some("webauthn"));

    let pre_auth_token = body["pre_auth_token"].as_str().unwrap().to_owned();

    // Start the WebAuthn authentication challenge.
    let res = app
        .post(
            "/auth/two-factor/webauthn/start",
            &serde_json::json!({ "pre_auth_token": pre_auth_token }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200, "webauthn auth/start failed");

    let rcr: RequestChallengeResponse = res.json().await.expect("invalid RequestChallengeResponse");

    // Simulate the authenticator response.
    let origin = Url::parse(RP_ORIGIN).unwrap();
    let credential = wa
        .do_authentication(origin, rcr)
        .expect("SoftPasskey authentication failed");

    // Finish the WebAuthn authentication.
    let res = app
        .post(
            "/auth/two-factor/webauthn/finish",
            &serde_json::json!({
                "pre_auth_token": pre_auth_token,
                "credential": credential,
            }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200, "webauthn auth/finish failed");

    let body: Value = res.json().await.unwrap();
    assert!(
        body["access_token"].as_str().is_some(),
        "expected access_token in response"
    );
}

#[tokio::test]
async fn webauthn_disable_requires_correct_password() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 201).await;

    register_webauthn_key(&app, &user.access_token).await;

    // Fetch the method_id from the DB.
    let (method_id,): (uuid::Uuid,) = sqlx::query_as(
        "SELECT id FROM two_factor_methods WHERE user_id = $1 AND method_type = 'webauthn' LIMIT 1",
    )
    .bind(user.id)
    .fetch_one(&app.db)
    .await
    .expect("no webauthn method found");

    // Wrong password → 401.
    let res = app
        .delete_auth_json(
            &format!("/users/me/two-factor/webauthn/{}", method_id),
            &user.access_token,
            &serde_json::json!({ "current_password": "WrongPass!" }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 401);

    // Correct password → 204.
    let res = app
        .delete_auth_json(
            &format!("/users/me/two-factor/webauthn/{}", method_id),
            &user.access_token,
            &serde_json::json!({ "current_password": user.password }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 204);

    // After disabling, login returns tokens directly.
    let res = app
        .post(
            "/auth/login",
            &serde_json::json!({
                "identifier": user.email,
                "password": user.password,
            }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200);
    let body: Value = res.json().await.unwrap();
    assert!(
        body["access_token"].as_str().is_some(),
        "expected direct login after disabling WebAuthn"
    );
}

#[tokio::test]
async fn webauthn_wrong_credential_rejected() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 202).await;

    register_webauthn_key(&app, &user.access_token).await;

    // Login to get a pre_auth_token.
    let res = app
        .post(
            "/auth/login",
            &serde_json::json!({
                "identifier": user.email,
                "password": user.password,
            }),
        )
        .await;
    let body: Value = res.json().await.unwrap();
    let pre_auth_token = body["pre_auth_token"].as_str().unwrap().to_owned();

    // Start the challenge so Redis auth state is set.
    let res = app
        .post(
            "/auth/two-factor/webauthn/start",
            &serde_json::json!({ "pre_auth_token": pre_auth_token }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200);

    // Submit a garbage credential (wrong signature / unknown key).
    let res = app
        .post(
            "/auth/two-factor/webauthn/finish",
            &serde_json::json!({
                "pre_auth_token": pre_auth_token,
                "credential": {
                    "id": "aGVsbG8",
                    "rawId": "aGVsbG8",
                    "type": "public-key",
                    "response": {
                        "authenticatorData": "aGVsbG8",
                        "clientDataJSON": "aGVsbG8",
                        "signature": "aGVsbG8",
                        "userHandle": null
                    },
                    "extensions": {}
                }
            }),
        )
        .await;
    assert!(
        res.status().as_u16() >= 400,
        "expected error on invalid credential, got {}",
        res.status().as_u16()
    );
}

#[tokio::test]
async fn webauthn_stale_pre_auth_token_rejected() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 203).await;

    register_webauthn_key(&app, &user.access_token).await;

    // Unknown pre_auth_token → 401.
    let res = app
        .post(
            "/auth/two-factor/webauthn/start",
            &serde_json::json!({ "pre_auth_token": uuid::Uuid::new_v4().to_string() }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 401);
}

#[tokio::test]
async fn webauthn_second_key_also_authenticates() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 204).await;

    // Register a first key (becomes primary).
    register_webauthn_key(&app, &user.access_token).await;

    // Register a second key.
    let mut wa2 = register_webauthn_key(&app, &user.access_token).await;

    // Login triggers 2FA.
    let res = app
        .post(
            "/auth/login",
            &serde_json::json!({
                "identifier": user.email,
                "password": user.password,
            }),
        )
        .await;
    let body: Value = res.json().await.unwrap();
    let pre_auth_token = body["pre_auth_token"].as_str().unwrap().to_owned();

    // Auth with the second key.
    let res = app
        .post(
            "/auth/two-factor/webauthn/start",
            &serde_json::json!({ "pre_auth_token": pre_auth_token }),
        )
        .await;
    let rcr: RequestChallengeResponse = res.json().await.expect("invalid RequestChallengeResponse");

    let credential = wa2
        .do_authentication(Url::parse(RP_ORIGIN).unwrap(), rcr)
        .expect("second key authentication failed");

    let res = app
        .post(
            "/auth/two-factor/webauthn/finish",
            &serde_json::json!({
                "pre_auth_token": pre_auth_token,
                "credential": credential,
            }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200, "second key should authenticate");
    let body: Value = res.json().await.unwrap();
    assert!(body["access_token"].as_str().is_some());
}
