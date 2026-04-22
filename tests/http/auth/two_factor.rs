use crate::common::{app::TestApp, fixtures};
use auth_api::{
    repositories::{email_2fa as email_2fa_repo, recovery_code as recovery_code_repo},
    utils::time,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

// helpers

/// Enable Email 2FA for a user. Returns the method UUID.
/// The setup handler already sends the first code, so we read it from the DB.
async fn setup_email_2fa(app: &TestApp, token: &str, user_id: uuid::Uuid) -> uuid::Uuid {
    // 1. setup (also sends first code)
    let res = app
        .post_auth(
            "/users/me/two-factor/email/setup",
            token,
            &serde_json::json!({}),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200, "email 2fa setup failed");

    let body: Value = res.json().await.unwrap();
    let method_id = uuid::Uuid::parse_str(body["method_id"].as_str().unwrap()).unwrap();

    // 2. read the OTP from the DB and verify setup
    let otp = read_otp_from_db(app, user_id).await;

    let res = app
        .post_auth(
            &format!("/users/me/two-factor/email/{}/verify", method_id),
            token,
            &serde_json::json!({ "code": otp }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200, "email 2fa verify_setup failed");

    // Clear the anti-spam cooldown so the next login can auto-dispatch a new OTP.
    app.clear_email_2fa_cooldown(user_id).await;

    method_id
}

/// Read the latest active OTP hash from the DB and brute-force the plaintext.
async fn read_otp_from_db(app: &TestApp, user_id: uuid::Uuid) -> String {
    let row: (Vec<u8>,) = sqlx::query_as(
        "SELECT code_hash FROM email_2fa_codes
         WHERE user_id = $1 AND used_at IS NULL
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(user_id)
    .fetch_one(&app.db)
    .await
    .expect("no active email_2fa_code found");

    brute_force_otp(&row.0)
}

/// Brute-force a 6-digit OTP from its SHA-256 hash.
fn brute_force_otp(expected_hash: &[u8]) -> String {
    for n in 0u32..1_000_000 {
        let candidate = format!("{:06}", n);
        let h = Sha256::digest(candidate.as_bytes());
        if h.as_slice() == expected_hash {
            return candidate;
        }
    }
    panic!("OTP not found in 6-digit space - unexpected hash");
}

async fn active_email_code_hashes(app: &TestApp, user_id: uuid::Uuid) -> Vec<Vec<u8>> {
    sqlx::query_scalar(
        "SELECT code_hash
         FROM email_2fa_codes
         WHERE user_id = $1 AND used_at IS NULL
         ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(&app.db)
    .await
    .unwrap()
}

async fn recovery_code_hashes(app: &TestApp, user_id: uuid::Uuid) -> Vec<Vec<u8>> {
    sqlx::query_scalar(
        "SELECT code_hash
         FROM recovery_codes
         WHERE user_id = $1
         ORDER BY code_position",
    )
    .bind(user_id)
    .fetch_all(&app.db)
    .await
    .unwrap()
}

// tests

#[tokio::test]
async fn email_2fa_setup_and_login() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 100).await;

    setup_email_2fa(&app, &user.access_token, user.id).await;

    // Login should now require a 2FA challenge.
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
    assert_eq!(body["two_factor_method"].as_str(), Some("email"));

    let pre_auth_token = body["pre_auth_token"].as_str().unwrap().to_owned();

    // Read OTP that was auto-sent on login challenge.
    let otp = read_otp_from_db(&app, user.id).await;

    // Complete the 2FA challenge.
    let res = app
        .post(
            "/auth/two-factor/email/complete",
            &serde_json::json!({
                "pre_auth_token": pre_auth_token,
                "code": otp,
            }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200, "email 2fa complete failed");

    let body: Value = res.json().await.unwrap();
    assert!(
        body["access_token"].as_str().is_some(),
        "expected access_token in response"
    );
}

#[tokio::test]
async fn email_2fa_wrong_code_rejected() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 101).await;

    setup_email_2fa(&app, &user.access_token, user.id).await;

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

    // Submit a deliberately wrong code.
    let res = app
        .post(
            "/auth/two-factor/email/complete",
            &serde_json::json!({
                "pre_auth_token": pre_auth_token,
                "code": "000000",
            }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 401);
}

#[tokio::test]
async fn email_2fa_resend_returns_204() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 102).await;

    setup_email_2fa(&app, &user.access_token, user.id).await;

    // Trigger login to get a pre_auth_token.
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

    // Resend always returns 204 regardless.
    let res = app
        .post(
            "/auth/two-factor/email/resend",
            &serde_json::json!({ "pre_auth_token": pre_auth_token }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 204);
}

#[tokio::test]
async fn email_2fa_disable_requires_correct_password() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 103).await;

    let method_id = setup_email_2fa(&app, &user.access_token, user.id).await;

    // Wrong password → 401.
    let res = app
        .delete_auth_json(
            &format!("/users/me/two-factor/email/{}", method_id),
            &user.access_token,
            &serde_json::json!({ "current_password": "WrongPass!" }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 401);

    // Correct password → 204.
    let res = app
        .delete_auth_json(
            &format!("/users/me/two-factor/email/{}", method_id),
            &user.access_token,
            &serde_json::json!({ "current_password": user.password }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 204);

    // After disabling 2FA, login should return tokens directly.
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
        "expected direct login after disabling 2FA"
    );
}

#[tokio::test]
async fn email_2fa_lockout_after_max_failures() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 104).await;

    setup_email_2fa(&app, &user.access_token, user.id).await;

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

    // Exhaust the 5-attempt budget with wrong codes.
    for _ in 0..5 {
        app.post(
            "/auth/two-factor/email/complete",
            &serde_json::json!({
                "pre_auth_token": &pre_auth_token,
                "code": "000000",
            }),
        )
        .await;
    }

    // 6th attempt (correct OTP) must be rejected - token is burned.
    let otp = read_otp_from_db(&app, user.id).await;
    let res = app
        .post(
            "/auth/two-factor/email/complete",
            &serde_json::json!({
                "pre_auth_token": &pre_auth_token,
                "code": otp,
            }),
        )
        .await;
    assert_eq!(
        res.status().as_u16(),
        429,
        "expected 429 after exhausting failure budget"
    );
}

#[tokio::test]
async fn email_2fa_expired_code_rejected() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 105).await;

    setup_email_2fa(&app, &user.access_token, user.id).await;

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

    // Replace the active OTP with an expired one directly in the DB.
    sqlx::query("UPDATE email_2fa_codes SET expires_at = NOW() - INTERVAL '1 minute' WHERE user_id = $1 AND used_at IS NULL")
        .bind(user.id)
        .execute(&app.db)
        .await
        .expect("failed to expire OTP");

    let res = app
        .post(
            "/auth/two-factor/email/complete",
            &serde_json::json!({
                "pre_auth_token": pre_auth_token,
                "code": "123456", // any code, doesn't matter
            }),
        )
        .await;
    // Expired code → 401 (not found / invalid)
    assert_eq!(res.status().as_u16(), 401);
}

#[tokio::test]
async fn risky_login_without_configured_2fa_falls_back_to_email_challenge() {
    let app = TestApp::spawn_with_config(|config| {
        config.risk.challenge_threshold = 20;
        config.risk.alert_threshold = 10;
    })
    .await;
    let user = fixtures::register_user(&app, 106).await;
    fixtures::activate_user(&app.db, user.id).await;

    let res = app
        .client
        .post(format!("{}/auth/login", app.base_url))
        .header(reqwest::header::USER_AGENT, "RiskyBrowser/1.0")
        .json(&serde_json::json!({
            "identifier": user.email,
            "password": user.password,
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status().as_u16(), 200);

    let body: Value = res.json().await.unwrap();
    assert_eq!(body["two_factor_required"].as_bool(), Some(true));
    assert_eq!(body["two_factor_method"].as_str(), Some("email"));

    let pre_auth_token = body["pre_auth_token"].as_str().unwrap().to_owned();
    let otp = read_otp_from_db(&app, user.id).await;

    let res = app
        .post(
            "/auth/two-factor/email/complete",
            &serde_json::json!({
                "pre_auth_token": pre_auth_token,
                "code": otp,
            }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 200);
}

#[tokio::test]
async fn recovery_code_replacement_rolls_back_on_insert_failure() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 107).await;

    let old_hashes = [vec![91u8; 32], vec![92u8; 32]];
    sqlx::query(
        "INSERT INTO recovery_codes (user_id, code_position, code_hash)
         VALUES ($1, 1, $2), ($1, 2, $3)",
    )
    .bind(user.id)
    .bind(&old_hashes[0])
    .bind(&old_hashes[1])
    .execute(&app.db)
    .await
    .unwrap();

    let new_hashes = [vec![11u8; 32], vec![12u8; 32]];
    let refs = vec![
        (1i16, new_hashes[0].as_slice()),
        (1i16, new_hashes[1].as_slice()),
    ];
    let err = recovery_code_repo::replace_all_by_user(&app.db, user.id, &refs, None)
        .await
        .expect_err("duplicate positions should fail");
    let message = err.to_string();

    assert!(message.contains("recovery_codes_user_position_key"));
    assert_eq!(recovery_code_hashes(&app, user.id).await, old_hashes);
}

#[tokio::test]
async fn email_2fa_code_replacement_rolls_back_on_insert_failure() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 108).await;

    let old_hash = vec![55u8; 32];
    sqlx::query(
        "INSERT INTO email_2fa_codes (user_id, code_hash, expires_at)
         VALUES ($1, $2, $3)",
    )
    .bind(user.id)
    .bind(&old_hash)
    .bind(time::in_secs(600))
    .execute(&app.db)
    .await
    .unwrap();

    sqlx::query(
        r#"
        CREATE OR REPLACE FUNCTION fail_email_2fa_insert()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'forced email_2fa insert failure';
        END;
        $$ LANGUAGE plpgsql;
        "#,
    )
    .execute(&app.db)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER email_2fa_codes_fail_insert
         BEFORE INSERT ON email_2fa_codes
         FOR EACH ROW EXECUTE FUNCTION fail_email_2fa_insert()",
    )
    .execute(&app.db)
    .await
    .unwrap();

    let new_hash = vec![77u8; 32];
    let err = email_2fa_repo::create(
        &app.db,
        &email_2fa_repo::NewEmail2faCode {
            user_id: user.id,
            code_hash: &new_hash,
            expires_at: time::in_secs(600),
        },
    )
    .await
    .expect_err("forced trigger should fail");
    let message = err.to_string();

    assert!(message.contains("forced email_2fa insert failure"));
    assert_eq!(
        active_email_code_hashes(&app, user.id).await,
        vec![old_hash]
    );
}

// P3 remaining: Email 2FA setup edge cases

#[tokio::test]
async fn email_2fa_setup_send_code_resends_otp() {
    // The /two-factor/email/:id/send route must return 204 and produce a new
    // OTP code (the old one is superseded).
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 110).await;

    // 1. Start setup - server sends first code automatically.
    let res = app
        .post_auth(
            "/users/me/two-factor/email/setup",
            &user.access_token,
            &serde_json::json!({}),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200);
    let body: Value = res.json().await.unwrap();
    let _method_id = body["method_id"].as_str().unwrap().to_owned();

    // Read the first code hash.
    let first_hashes = active_email_code_hashes(&app, user.id).await;
    assert!(
        !first_hashes.is_empty(),
        "setup must have sent an initial OTP"
    );

    // 2. Clear cooldown so we can resend immediately.
    app.clear_email_2fa_cooldown(user.id).await;

    // 3. Call the /send route (no method_id - shared per-user endpoint).
    let res = app
        .post_auth(
            "/users/me/two-factor/email/send",
            &user.access_token,
            &serde_json::json!({}),
        )
        .await;
    assert_eq!(res.status().as_u16(), 204, "/send must return 204");

    // 4. A new code must now be active.
    let second_hashes = active_email_code_hashes(&app, user.id).await;
    assert!(!second_hashes.is_empty(), "resend must produce a new OTP");
    // The code should have changed (new hash).
    assert_ne!(
        first_hashes, second_hashes,
        "resent code hash must differ from the original"
    );
}

#[tokio::test]
async fn email_2fa_setup_send_code_cooldown_enforced() {
    // A second /send within 60 seconds must return 429.
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 111).await;

    let res = app
        .post_auth(
            "/users/me/two-factor/email/setup",
            &user.access_token,
            &serde_json::json!({}),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200);
    let body: Value = res.json().await.unwrap();
    let method_id = body["method_id"].as_str().unwrap().to_owned();

    // Do NOT clear the cooldown - it was just armed by setup.
    let _ = method_id; // unused after route correction
    let res = app
        .post_auth(
            "/users/me/two-factor/email/send",
            &user.access_token,
            &serde_json::json!({}),
        )
        .await;
    assert_eq!(
        res.status().as_u16(),
        429,
        "/send within cooldown must return 429"
    );
}

#[tokio::test]
async fn email_2fa_setup_verify_wrong_code_rejected() {
    // /two-factor/email/:id/verify with a wrong code must return 401.
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 112).await;

    let res = app
        .post_auth(
            "/users/me/two-factor/email/setup",
            &user.access_token,
            &serde_json::json!({}),
        )
        .await;
    let body: Value = res.json().await.unwrap();
    let method_id = body["method_id"].as_str().unwrap().to_owned();

    let res = app
        .post_auth(
            &format!("/users/me/two-factor/email/{}/verify", method_id),
            &user.access_token,
            &serde_json::json!({ "code": "000000" }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 401, "wrong code must return 401");
}

#[tokio::test]
async fn email_2fa_setup_verify_lockout_after_max_failures() {
    // 5 consecutive wrong codes must lock the setup attempt (429).
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 113).await;

    let res = app
        .post_auth(
            "/users/me/two-factor/email/setup",
            &user.access_token,
            &serde_json::json!({}),
        )
        .await;
    let body: Value = res.json().await.unwrap();
    let method_id = body["method_id"].as_str().unwrap().to_owned();

    for _ in 0..5 {
        app.post_auth(
            &format!("/users/me/two-factor/email/{}/verify", method_id),
            &user.access_token,
            &serde_json::json!({ "code": "000000" }),
        )
        .await;
    }

    // 6th attempt must be rate-limited.
    let res = app
        .post_auth(
            &format!("/users/me/two-factor/email/{}/verify", method_id),
            &user.access_token,
            &serde_json::json!({ "code": "000000" }),
        )
        .await;
    assert_eq!(
        res.status().as_u16(),
        429,
        "6th wrong code must trigger 429 lockout"
    );
}

#[tokio::test]
async fn email_2fa_setup_verify_expired_code_rejected() {
    // Force-expire all active codes for the user then attempt verify.
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 114).await;

    let res = app
        .post_auth(
            "/users/me/two-factor/email/setup",
            &user.access_token,
            &serde_json::json!({}),
        )
        .await;
    let body: Value = res.json().await.unwrap();
    let method_id = body["method_id"].as_str().unwrap().to_owned();

    // Expire the code by backdating expires_at in the DB.
    sqlx::query(
        "UPDATE email_2fa_codes SET expires_at = NOW() - INTERVAL '1 second'
         WHERE user_id = $1 AND used_at IS NULL",
    )
    .bind(user.id)
    .execute(&app.db)
    .await
    .expect("failed to expire 2fa codes");

    // Read the (now expired) code and try to verify - must return 401.
    let expired_otp = read_otp_from_db(&app, user.id).await;
    let res = app
        .post_auth(
            &format!("/users/me/two-factor/email/{}/verify", method_id),
            &user.access_token,
            &serde_json::json!({ "code": expired_otp }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 401, "expired code must return 401");
}
