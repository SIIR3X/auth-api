//! TOTP 2FA and recovery-code tests.
//!
//! The helper `generate_totp_code` uses totp-rs (already a crate dependency)
//! to produce a valid 6-digit code from the base32 secret returned by setup.

use crate::common::{app::TestApp, fixtures};
use serde_json::Value;

// helpers

/// Generate the current valid TOTP code for a base32-encoded secret.
fn generate_totp_code(base32_secret: &str) -> String {
    use totp_rs::{Algorithm, Secret, TOTP};
    let bytes = Secret::Encoded(base32_secret.to_owned())
        .to_bytes()
        .expect("invalid base32 secret from setup response");
    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, bytes).expect("TOTP construction failed");
    totp.generate_current()
        .expect("failed to get current TOTP code")
}

/// Set up TOTP for a user: calls setup, then verifies with a real code.
/// Returns `(method_id, recovery_codes)`.
async fn setup_totp_for(app: &TestApp, access_token: &str) -> (String, Vec<String>) {
    let res = app
        .post_auth(
            "/users/me/two-factor/totp/setup",
            access_token,
            &serde_json::json!({}),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200, "totp setup failed");

    let body: Value = res.json().await.unwrap();
    let method_id = body["method_id"].as_str().unwrap().to_owned();
    let base32_secret = body["base32_secret"].as_str().unwrap().to_owned();

    let code = generate_totp_code(&base32_secret);

    let res = app
        .post_auth(
            &format!("/users/me/two-factor/totp/{}/verify", method_id),
            access_token,
            &serde_json::json!({ "code": code }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200, "totp verify_setup failed");

    let body: Value = res.json().await.unwrap();
    let recovery_codes: Vec<String> = body["recovery_codes"]
        .as_array()
        .expect("recovery_codes missing from verify response")
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();

    (method_id, recovery_codes)
}

// TOTP setup

#[tokio::test]
async fn totp_setup_response_contains_qr_and_secret() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 200).await;

    let res = app
        .post_auth(
            "/users/me/two-factor/totp/setup",
            &user.access_token,
            &serde_json::json!({}),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200);

    let body: Value = res.json().await.unwrap();
    assert!(body["method_id"].as_str().is_some(), "method_id missing");
    assert!(
        body["base32_secret"].as_str().is_some(),
        "base32_secret missing"
    );
    let qr = body["qr_uri"].as_str().expect("qr_uri missing");
    assert!(qr.starts_with("otpauth://totp/"), "qr_uri has wrong scheme");
}

#[tokio::test]
async fn totp_verify_setup_wrong_code_rejected() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 201).await;

    let res = app
        .post_auth(
            "/users/me/two-factor/totp/setup",
            &user.access_token,
            &serde_json::json!({}),
        )
        .await;
    let body: Value = res.json().await.unwrap();
    let method_id = body["method_id"].as_str().unwrap();

    let res = app
        .post_auth(
            &format!("/users/me/two-factor/totp/{}/verify", method_id),
            &user.access_token,
            &serde_json::json!({ "code": "000000" }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 401);
}

#[tokio::test]
async fn totp_verify_setup_returns_ten_recovery_codes() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 202).await;

    let (_method_id, codes) = setup_totp_for(&app, &user.access_token).await;
    assert_eq!(codes.len(), 10, "expected 10 recovery codes");
    for code in &codes {
        assert!(!code.is_empty());
    }
}

// TOTP login flow

/// Full inline TOTP login flow with captured secret.
#[tokio::test]
async fn totp_login_full_flow() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 204).await;

    // Setup TOTP and capture the secret.
    let setup_res = app
        .post_auth(
            "/users/me/two-factor/totp/setup",
            &user.access_token,
            &serde_json::json!({}),
        )
        .await;
    assert_eq!(setup_res.status().as_u16(), 200);
    let setup_body: Value = setup_res.json().await.unwrap();
    let method_id = setup_body["method_id"].as_str().unwrap();
    let base32_secret = setup_body["base32_secret"].as_str().unwrap().to_owned();

    // Verify setup with a valid code.
    let code = generate_totp_code(&base32_secret);
    let verify_res = app
        .post_auth(
            &format!("/users/me/two-factor/totp/{}/verify", method_id),
            &user.access_token,
            &serde_json::json!({ "code": code }),
        )
        .await;
    assert_eq!(verify_res.status().as_u16(), 200, "verify_setup failed");

    // Login triggers TOTP challenge.
    let login_res = app
        .post(
            "/auth/login",
            &serde_json::json!({
                "identifier": user.email,
                "password": user.password,
            }),
        )
        .await;
    assert_eq!(login_res.status().as_u16(), 200);
    let login_body: Value = login_res.json().await.unwrap();
    assert_eq!(login_body["two_factor_method"].as_str(), Some("totp"));
    let pre_auth_token = login_body["pre_auth_token"].as_str().unwrap().to_owned();

    // Complete TOTP challenge with a fresh valid code.
    let totp_code = generate_totp_code(&base32_secret);
    let complete_res = app
        .post(
            "/auth/two-factor/complete",
            &serde_json::json!({
                "pre_auth_token": pre_auth_token,
                "code": totp_code,
            }),
        )
        .await;
    assert_eq!(
        complete_res.status().as_u16(),
        200,
        "complete_two_factor failed"
    );

    let complete_body: Value = complete_res.json().await.unwrap();
    assert!(complete_body["access_token"].as_str().is_some());
    assert!(complete_body["refresh_token"].as_str().is_some());
}

#[tokio::test]
async fn totp_login_wrong_code_rejected() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 205).await;

    let setup_res = app
        .post_auth(
            "/users/me/two-factor/totp/setup",
            &user.access_token,
            &serde_json::json!({}),
        )
        .await;
    let setup_body: Value = setup_res.json().await.unwrap();
    let method_id = setup_body["method_id"].as_str().unwrap();
    let base32_secret = setup_body["base32_secret"].as_str().unwrap().to_owned();

    let code = generate_totp_code(&base32_secret);
    app.post_auth(
        &format!("/users/me/two-factor/totp/{}/verify", method_id),
        &user.access_token,
        &serde_json::json!({ "code": code }),
    )
    .await;

    let login_res: Value = app
        .post(
            "/auth/login",
            &serde_json::json!({ "identifier": user.email, "password": user.password }),
        )
        .await
        .json()
        .await
        .unwrap();
    let pre_auth_token = login_res["pre_auth_token"].as_str().unwrap();

    let res = app
        .post(
            "/auth/two-factor/complete",
            &serde_json::json!({
                "pre_auth_token": pre_auth_token,
                "code": "000000",
            }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 401);
}

// TOTP disable

#[tokio::test]
async fn totp_disable_wrong_password_rejected() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 206).await;
    app.clear_recent_reauth(&user.access_token).await;

    let setup_res = app
        .post_auth(
            "/users/me/two-factor/totp/setup",
            &user.access_token,
            &serde_json::json!({}),
        )
        .await;
    let setup_body: Value = setup_res.json().await.unwrap();
    let method_id = setup_body["method_id"].as_str().unwrap().to_owned();
    let base32_secret = setup_body["base32_secret"].as_str().unwrap().to_owned();

    let code = generate_totp_code(&base32_secret);
    app.post_auth(
        &format!("/users/me/two-factor/totp/{}/verify", method_id),
        &user.access_token,
        &serde_json::json!({ "code": code }),
    )
    .await;

    let res = app
        .delete_auth_json(
            &format!("/users/me/two-factor/totp/{}", method_id),
            &user.access_token,
            &serde_json::json!({ "current_password": "WrongPass1!" }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 401);
}

#[tokio::test]
async fn totp_disable_correct_password_succeeds_and_login_bypasses_2fa() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 207).await;
    app.clear_recent_reauth(&user.access_token).await;

    let setup_res = app
        .post_auth(
            "/users/me/two-factor/totp/setup",
            &user.access_token,
            &serde_json::json!({}),
        )
        .await;
    let setup_body: Value = setup_res.json().await.unwrap();
    let method_id = setup_body["method_id"].as_str().unwrap().to_owned();
    let base32_secret = setup_body["base32_secret"].as_str().unwrap().to_owned();

    let code = generate_totp_code(&base32_secret);
    app.post_auth(
        &format!("/users/me/two-factor/totp/{}/verify", method_id),
        &user.access_token,
        &serde_json::json!({ "code": code }),
    )
    .await;

    // Disable with correct password.
    let res = app
        .delete_auth_json(
            &format!("/users/me/two-factor/totp/{}", method_id),
            &user.access_token,
            &serde_json::json!({ "current_password": user.password }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 204);

    // Login should now return tokens directly (no 2FA challenge).
    let login_res: Value = app
        .post(
            "/auth/login",
            &serde_json::json!({ "identifier": user.email, "password": user.password }),
        )
        .await
        .json()
        .await
        .unwrap();

    assert!(
        login_res["access_token"].as_str().is_some(),
        "expected direct login after disabling TOTP, got: {login_res}"
    );
}

// Recovery codes

#[tokio::test]
async fn recovery_login_succeeds_with_valid_code() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 208).await;

    let setup_res = app
        .post_auth(
            "/users/me/two-factor/totp/setup",
            &user.access_token,
            &serde_json::json!({}),
        )
        .await;
    let setup_body: Value = setup_res.json().await.unwrap();
    let method_id = setup_body["method_id"].as_str().unwrap();
    let base32_secret = setup_body["base32_secret"].as_str().unwrap().to_owned();

    let code = generate_totp_code(&base32_secret);
    let verify_res: Value = app
        .post_auth(
            &format!("/users/me/two-factor/totp/{}/verify", method_id),
            &user.access_token,
            &serde_json::json!({ "code": code }),
        )
        .await
        .json()
        .await
        .unwrap();
    let recovery_codes: Vec<String> = verify_res["recovery_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();

    // Trigger login → TOTP challenge.
    let login_res: Value = app
        .post(
            "/auth/login",
            &serde_json::json!({ "identifier": user.email, "password": user.password }),
        )
        .await
        .json()
        .await
        .unwrap();
    let pre_auth_token = login_res["pre_auth_token"].as_str().unwrap().to_owned();

    // Complete login using a recovery code instead of TOTP.
    let res = app
        .post(
            "/auth/two-factor/recovery",
            &serde_json::json!({
                "pre_auth_token": pre_auth_token,
                "recovery_code": recovery_codes[0],
            }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200, "recovery login failed");

    let body: Value = res.json().await.unwrap();
    assert!(body["access_token"].as_str().is_some());
}

#[tokio::test]
async fn recovery_login_replay_rejected() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 209).await;

    let setup_res = app
        .post_auth(
            "/users/me/two-factor/totp/setup",
            &user.access_token,
            &serde_json::json!({}),
        )
        .await;
    let setup_body: Value = setup_res.json().await.unwrap();
    let method_id = setup_body["method_id"].as_str().unwrap();
    let base32_secret = setup_body["base32_secret"].as_str().unwrap().to_owned();

    let code = generate_totp_code(&base32_secret);
    let verify_res: Value = app
        .post_auth(
            &format!("/users/me/two-factor/totp/{}/verify", method_id),
            &user.access_token,
            &serde_json::json!({ "code": code }),
        )
        .await
        .json()
        .await
        .unwrap();
    let recovery_code = verify_res["recovery_codes"][0].as_str().unwrap().to_owned();

    // First use: login → challenge → recovery.
    let login1: Value = app
        .post(
            "/auth/login",
            &serde_json::json!({ "identifier": user.email, "password": user.password }),
        )
        .await
        .json()
        .await
        .unwrap();
    let pre_auth1 = login1["pre_auth_token"].as_str().unwrap().to_owned();

    let first = app
        .post(
            "/auth/two-factor/recovery",
            &serde_json::json!({ "pre_auth_token": pre_auth1, "recovery_code": recovery_code }),
        )
        .await;
    assert_eq!(
        first.status().as_u16(),
        200,
        "first recovery login should succeed"
    );

    // Second use: new login challenge, same recovery code.
    let login2: Value = app
        .post(
            "/auth/login",
            &serde_json::json!({ "identifier": user.email, "password": user.password }),
        )
        .await
        .json()
        .await
        .unwrap();
    let pre_auth2 = login2["pre_auth_token"].as_str().unwrap().to_owned();

    let second = app
        .post(
            "/auth/two-factor/recovery",
            &serde_json::json!({ "pre_auth_token": pre_auth2, "recovery_code": recovery_code }),
        )
        .await;
    assert_eq!(
        second.status().as_u16(),
        401,
        "replay of used recovery code must be rejected"
    );
}

#[tokio::test]
async fn recovery_login_wrong_code_rejected() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 210).await;

    let setup_res = app
        .post_auth(
            "/users/me/two-factor/totp/setup",
            &user.access_token,
            &serde_json::json!({}),
        )
        .await;
    let setup_body: Value = setup_res.json().await.unwrap();
    let method_id = setup_body["method_id"].as_str().unwrap();
    let base32_secret = setup_body["base32_secret"].as_str().unwrap().to_owned();

    let code = generate_totp_code(&base32_secret);
    app.post_auth(
        &format!("/users/me/two-factor/totp/{}/verify", method_id),
        &user.access_token,
        &serde_json::json!({ "code": code }),
    )
    .await;

    let login_res: Value = app
        .post(
            "/auth/login",
            &serde_json::json!({ "identifier": user.email, "password": user.password }),
        )
        .await
        .json()
        .await
        .unwrap();
    let pre_auth_token = login_res["pre_auth_token"].as_str().unwrap();

    let res = app
        .post(
            "/auth/two-factor/recovery",
            &serde_json::json!({
                "pre_auth_token": pre_auth_token,
                "recovery_code": "XXXX-XXXX-XXXX-XXXX",
            }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 401);
}

// Recovery code regeneration

#[tokio::test]
async fn regenerate_recovery_codes_with_password_returns_new_codes() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 211).await;
    app.clear_recent_reauth(&user.access_token).await;

    // First set up TOTP so recovery codes exist.
    let setup_res = app
        .post_auth(
            "/users/me/two-factor/totp/setup",
            &user.access_token,
            &serde_json::json!({}),
        )
        .await;
    let setup_body: Value = setup_res.json().await.unwrap();
    let method_id = setup_body["method_id"].as_str().unwrap();
    let base32_secret = setup_body["base32_secret"].as_str().unwrap().to_owned();

    let code = generate_totp_code(&base32_secret);
    let old_codes_res: Value = app
        .post_auth(
            &format!("/users/me/two-factor/totp/{}/verify", method_id),
            &user.access_token,
            &serde_json::json!({ "code": code }),
        )
        .await
        .json()
        .await
        .unwrap();
    let old_codes: Vec<String> = old_codes_res["recovery_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();

    // Regenerate.
    let regen_res = app
        .post_auth(
            "/users/me/two-factor/recovery-codes",
            &user.access_token,
            &serde_json::json!({ "current_password": user.password }),
        )
        .await;
    assert_eq!(regen_res.status().as_u16(), 200);

    let new_codes_body: Value = regen_res.json().await.unwrap();
    let new_codes: Vec<String> = new_codes_body["recovery_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();

    assert_eq!(new_codes.len(), 10, "expected 10 new recovery codes");
    // New codes must differ from old ones.
    assert_ne!(
        old_codes, new_codes,
        "regenerated codes must differ from old codes"
    );
}

#[tokio::test]
async fn regenerate_recovery_codes_without_reauth_rejected() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 212).await;
    app.clear_recent_reauth(&user.access_token).await;

    let res = app
        .post_auth(
            "/users/me/two-factor/recovery-codes",
            &user.access_token,
            &serde_json::json!({}), // no password, no recent reauth
        )
        .await;
    assert_eq!(res.status().as_u16(), 403);
}

// Use recovery code (authenticated endpoint)

#[tokio::test]
async fn use_recovery_code_authenticated_consumes_code() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 213).await;

    let setup_res = app
        .post_auth(
            "/users/me/two-factor/totp/setup",
            &user.access_token,
            &serde_json::json!({}),
        )
        .await;
    let setup_body: Value = setup_res.json().await.unwrap();
    let method_id = setup_body["method_id"].as_str().unwrap();
    let base32_secret = setup_body["base32_secret"].as_str().unwrap().to_owned();

    let code = generate_totp_code(&base32_secret);
    let verify_res: Value = app
        .post_auth(
            &format!("/users/me/two-factor/totp/{}/verify", method_id),
            &user.access_token,
            &serde_json::json!({ "code": code }),
        )
        .await
        .json()
        .await
        .unwrap();
    let recovery_code = verify_res["recovery_codes"][0].as_str().unwrap().to_owned();

    // Use the code via the authenticated endpoint.
    let res = app
        .post_auth(
            "/users/me/two-factor/recovery-codes/use",
            &user.access_token,
            &serde_json::json!({ "code": recovery_code }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 204);

    // Using the same code again must fail.
    let res2 = app
        .post_auth(
            "/users/me/two-factor/recovery-codes/use",
            &user.access_token,
            &serde_json::json!({ "code": recovery_code }),
        )
        .await;
    assert_eq!(
        res2.status().as_u16(),
        401,
        "replaying a consumed recovery code must fail"
    );
}

#[tokio::test]
async fn use_recovery_code_wrong_code_rejected() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 214).await;

    let res = app
        .post_auth(
            "/users/me/two-factor/recovery-codes/use",
            &user.access_token,
            &serde_json::json!({ "code": "NO-SUCH-CODE" }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 401);
}

// P3: TOTP challenge rate limiting and replay

#[tokio::test]
async fn totp_challenge_rate_limited_after_max_failures() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 216).await;

    let (_method_id, _codes) = setup_totp_for(&app, &user.access_token).await;

    // Trigger login to get a pre-auth token.
    let login_res: Value = app
        .post(
            "/auth/login",
            &serde_json::json!({ "identifier": user.email, "password": user.password }),
        )
        .await
        .json()
        .await
        .unwrap();
    let pre_auth_token = login_res["pre_auth_token"].as_str().unwrap().to_owned();

    // Submit 5 wrong TOTP codes to exhaust the per-token failure budget.
    for _ in 0..5 {
        app.post(
            "/auth/two-factor/complete",
            &serde_json::json!({ "pre_auth_token": &pre_auth_token, "code": "000000" }),
        )
        .await;
    }

    // The 6th attempt must be rate-limited (429).
    let res = app
        .post(
            "/auth/two-factor/complete",
            &serde_json::json!({ "pre_auth_token": &pre_auth_token, "code": "000000" }),
        )
        .await;
    assert_eq!(
        res.status().as_u16(),
        429,
        "expected 429 after exhausting TOTP failure budget"
    );
}

#[tokio::test]
async fn totp_replay_within_window_rejected() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 217).await;

    // Setup TOTP and capture the secret so we can generate a real code.
    let setup_res = app
        .post_auth(
            "/users/me/two-factor/totp/setup",
            &user.access_token,
            &serde_json::json!({}),
        )
        .await;
    let setup_body: Value = setup_res.json().await.unwrap();
    let method_id = setup_body["method_id"].as_str().unwrap();
    let base32_secret = setup_body["base32_secret"].as_str().unwrap().to_owned();

    let setup_code = generate_totp_code(&base32_secret);
    app.post_auth(
        &format!("/users/me/two-factor/totp/{}/verify", method_id),
        &user.access_token,
        &serde_json::json!({ "code": setup_code }),
    )
    .await;

    // Login to get first pre-auth token.
    let login1: Value = app
        .post(
            "/auth/login",
            &serde_json::json!({ "identifier": user.email, "password": user.password }),
        )
        .await
        .json()
        .await
        .unwrap();
    let pre_auth1 = login1["pre_auth_token"].as_str().unwrap().to_owned();

    // Complete 2FA successfully with a fresh code.
    let totp_code = generate_totp_code(&base32_secret);
    let first = app
        .post(
            "/auth/two-factor/complete",
            &serde_json::json!({ "pre_auth_token": &pre_auth1, "code": &totp_code }),
        )
        .await;
    assert_eq!(first.status().as_u16(), 200, "first use must succeed");

    // Login again to get a new pre-auth token.
    let login2: Value = app
        .post(
            "/auth/login",
            &serde_json::json!({ "identifier": user.email, "password": user.password }),
        )
        .await
        .json()
        .await
        .unwrap();
    let pre_auth2 = login2["pre_auth_token"].as_str().unwrap().to_owned();

    // Replay the same TOTP code within the 60-second window - must be rejected.
    let second = app
        .post(
            "/auth/two-factor/complete",
            &serde_json::json!({ "pre_auth_token": &pre_auth2, "code": &totp_code }),
        )
        .await;
    assert_eq!(
        second.status().as_u16(),
        401,
        "replaying same TOTP code must be rejected"
    );
}

#[tokio::test]
async fn totp_2fa_fails_when_account_suspended_after_challenge() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 218).await;

    let setup_res = app
        .post_auth(
            "/users/me/two-factor/totp/setup",
            &user.access_token,
            &serde_json::json!({}),
        )
        .await;
    let setup_body: Value = setup_res.json().await.unwrap();
    let method_id = setup_body["method_id"].as_str().unwrap();
    let base32_secret = setup_body["base32_secret"].as_str().unwrap().to_owned();

    let code = generate_totp_code(&base32_secret);
    app.post_auth(
        &format!("/users/me/two-factor/totp/{}/verify", method_id),
        &user.access_token,
        &serde_json::json!({ "code": code }),
    )
    .await;

    // Login to get pre-auth token while account is still active.
    let login_res: Value = app
        .post(
            "/auth/login",
            &serde_json::json!({ "identifier": user.email, "password": user.password }),
        )
        .await
        .json()
        .await
        .unwrap();
    let pre_auth_token = login_res["pre_auth_token"].as_str().unwrap().to_owned();

    // Suspend the account before the 2FA step completes.
    sqlx::query("UPDATE users SET status = 'suspended' WHERE id = $1")
        .bind(user.id)
        .execute(&app.db)
        .await
        .expect("failed to suspend user");

    // Complete 2FA with a valid code - must fail because account is now suspended.
    let totp_code = generate_totp_code(&base32_secret);
    let res = app
        .post(
            "/auth/two-factor/complete",
            &serde_json::json!({ "pre_auth_token": &pre_auth_token, "code": &totp_code }),
        )
        .await;
    assert_eq!(
        res.status().as_u16(),
        403,
        "expected 403 for suspended account during 2FA"
    );
}

#[tokio::test]
async fn recovery_challenge_rate_limited_after_max_failures() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 219).await;

    let (_method_id, _codes) = setup_totp_for(&app, &user.access_token).await;

    // Login to get a pre-auth token.
    let login_res: Value = app
        .post(
            "/auth/login",
            &serde_json::json!({ "identifier": user.email, "password": user.password }),
        )
        .await
        .json()
        .await
        .unwrap();
    let pre_auth_token = login_res["pre_auth_token"].as_str().unwrap().to_owned();

    // Submit 5 wrong recovery codes to exhaust the per-token failure budget.
    for _ in 0..5 {
        app.post(
            "/auth/two-factor/recovery",
            &serde_json::json!({ "pre_auth_token": &pre_auth_token, "recovery_code": "XXXX-XXXX-XXXX-XXXX" }),
        )
        .await;
    }

    // The 6th attempt must be rate-limited (429).
    let res = app
        .post(
            "/auth/two-factor/recovery",
            &serde_json::json!({ "pre_auth_token": &pre_auth_token, "recovery_code": "XXXX-XXXX-XXXX-XXXX" }),
        )
        .await;
    assert_eq!(
        res.status().as_u16(),
        429,
        "expected 429 after exhausting recovery code failure budget"
    );
}

// P3: recovery-code regeneration cooldown

#[tokio::test]
async fn recovery_code_regen_cooldown_blocks_second_immediate_request() {
    // The first regeneration should succeed; the second (within 24 hours) must be rejected.
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 215).await;
    let (_method_id, _codes) = setup_totp_for(&app, &user.access_token).await;

    // Clear any pre-existing cooldown so the first call always succeeds.
    if let Ok(mut conn) = app.redis.get().await {
        let key = format!("rc_regen:{}", user.id);
        let _: Result<(), _> = deadpool_redis::redis::AsyncCommands::del(&mut conn, &key).await;
    }

    // First regeneration must succeed.
    let first = app
        .post_auth(
            "/users/me/two-factor/recovery-codes",
            &user.access_token,
            &serde_json::json!({ "current_password": user.password }),
        )
        .await;
    assert_eq!(first.status().as_u16(), 200, "first regen must succeed");

    // Immediate second regeneration must be blocked by the 24-hour cooldown.
    let second = app
        .post_auth(
            "/users/me/two-factor/recovery-codes",
            &user.access_token,
            &serde_json::json!({ "current_password": user.password }),
        )
        .await;
    assert!(
        second.status().as_u16() == 429 || second.status().as_u16() == 403,
        "expected 429 or 403 for second regen within cooldown window, got {}",
        second.status()
    );
}
