//! Email content tests - verify that the API actually dispatches emails with
//! the correct subject and relevant content.
//!
//! Each test spawns a TestApp wired to the shared Mailpit SMTP server, then
//! performs an action that triggers an email and asserts on the captured
//! message via the Mailpit HTTP API.
//!
//! Tests use index range 800-850 to avoid collisions with other test files.
//!
//! Each test uses a unique user index (800-806) so their email addresses never
//! collide. No `delete_all()` calls are needed: `wait_for_message` filters by
//! both recipient and subject, so parallel tests cannot steal each other's mail.

use crate::common::{app::TestApp, fixtures};

// helpers

/// Extract the OTP code from the `email_2fa_codes` table for a user.
/// Tokens are stored as SHA-256 hashes, so we brute-force the 6-digit space.
async fn otp_from_db(app: &TestApp, user_id: uuid::Uuid) -> String {
    let hash: Vec<u8> = sqlx::query_scalar(
        "SELECT code_hash FROM email_2fa_codes
         WHERE user_id = $1 AND used_at IS NULL
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(user_id)
    .fetch_one(&app.db)
    .await
    .expect("no email_2fa_code found");

    use sha2::{Digest, Sha256};
    for n in 0u32..1_000_000 {
        let candidate = format!("{:06}", n);
        let digest = Sha256::digest(candidate.as_bytes());
        if digest.as_slice() == hash {
            return candidate;
        }
    }
    panic!("could not find OTP matching hash");
}

// 1. Registration verification email

#[tokio::test]
async fn register_sends_verification_email() {
    let app = TestApp::spawn_with_mailpit().await;
    let mp = app.mailpit();

    let email = "mailtest_user800@example.com";
    let res = app
        .post(
            "/auth/register",
            &serde_json::json!({
                "username": "mailtest_user800",
                "email": email,
                "password": "Password800!ok",
            }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 201);

    let msg = mp
        .wait_for_message(email, "Verify your email address")
        .await
        .expect("verification email not received within timeout");

    assert_eq!(msg.subject, "Verify your email address");
    assert!(
        msg.html.contains("verify-email"),
        "verification email must contain the verify-email URL fragment"
    );
    assert!(
        msg.html.contains("token="),
        "verification email must contain a token query parameter"
    );
}

// 2. Password-reset email

#[tokio::test]
async fn forgot_password_sends_reset_email() {
    let app = TestApp::spawn_with_mailpit().await;
    let mp = app.mailpit();

    let user = fixtures::register_user(&app, 801).await;
    fixtures::activate_user(&app.db, user.id).await;

    // Clear the per-IP rate limit key so parallel tests don't exhaust the quota.
    if let Ok(mut conn) = app.redis.get().await {
        let _: Result<(), _> =
            deadpool_redis::redis::AsyncCommands::del(&mut conn, "fp_req:127.0.0.1").await;
    }

    let res = app
        .post(
            "/auth/forgot-password",
            &serde_json::json!({ "email": user.email }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200);

    let msg = mp
        .wait_for_message(&user.email, "Reset your password")
        .await
        .expect("password-reset email not received");

    assert_eq!(msg.subject, "Reset your password");
    assert!(
        msg.html.contains("reset-password"),
        "reset email must contain the reset-password URL fragment"
    );
    assert!(
        msg.html.contains("token="),
        "reset email must contain a token query parameter"
    );
}

// 3. Email-OTP 2FA login email

#[tokio::test]
async fn email_2fa_login_sends_otp_email() {
    let app = TestApp::spawn_with_mailpit().await;
    let mp = app.mailpit();

    // Set up email 2FA for the user.
    let user = fixtures::authenticated_user(&app, 802).await;

    // Setup email 2FA - the handler automatically calls send_code internally,
    // so exactly one OTP is created in the DB and one email is dispatched.
    // No explicit /send call: adding one would produce two competing async
    // emails for the same subject, making the assertion non-deterministic.
    let res = app
        .post_auth(
            "/users/me/two-factor/email/setup",
            &user.access_token,
            &serde_json::json!({}),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200);

    let msg = mp
        .wait_for_message(&user.email, "Your login verification code")
        .await
        .expect("OTP email not received");

    assert_eq!(msg.subject, "Your login verification code");

    let otp = otp_from_db(&app, user.id).await;
    assert!(
        msg.html.contains(&otp),
        "OTP email must contain the 6-digit code; got HTML: {}",
        &msg.html[..msg.html.len().min(500)]
    );
}

// 4. Email-change OTP email

#[tokio::test]
async fn email_change_start_sends_otp_email() {
    let app = TestApp::spawn_with_mailpit().await;
    let mp = app.mailpit();

    let user = fixtures::authenticated_user(&app, 803).await;

    let res = app
        .post_auth(
            "/users/me/email/start",
            &user.access_token,
            &serde_json::json!({}),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200);

    let msg = mp
        .wait_for_message(&user.email, "Your email change verification code")
        .await
        .expect("email-change OTP not received");

    assert_eq!(msg.subject, "Your email change verification code");
    assert!(
        msg.html.contains("email"),
        "email-change OTP body must mention email"
    );
}

// 5. Password-changed notification

#[tokio::test]
async fn change_password_sends_notification_email() {
    let app = TestApp::spawn_with_mailpit().await;
    let mp = app.mailpit();

    let user = fixtures::authenticated_user(&app, 804).await;

    let res = app
        .client
        .patch(format!("{}/users/me/password", app.base_url))
        .bearer_auth(&user.access_token)
        .json(&serde_json::json!({
            "current_password": user.password,
            "new_password": "NewPassword804!ok",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 204);

    let msg = mp
        .wait_for_message(&user.email, "Your password has been changed")
        .await
        .expect("password-changed notification not received");

    assert_eq!(msg.subject, "Your password has been changed");
}

// 6. TOTP disabled notification

#[tokio::test]
async fn disable_totp_sends_two_factor_disabled_email() {
    let app = TestApp::spawn_with_mailpit().await;
    let mp = app.mailpit();

    let user = fixtures::authenticated_user(&app, 805).await;

    use totp_rs::{Algorithm, Secret, TOTP};

    let setup_res = app
        .post_auth(
            "/users/me/two-factor/totp/setup",
            &user.access_token,
            &serde_json::json!({}),
        )
        .await;
    assert_eq!(setup_res.status().as_u16(), 200);
    let setup_body: serde_json::Value = setup_res.json().await.unwrap();
    let method_id = setup_body["method_id"].as_str().unwrap();
    let secret_b32 = setup_body["base32_secret"].as_str().unwrap();

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(secret_b32.to_owned()).to_bytes().unwrap(),
    )
    .unwrap();
    let code = totp.generate_current().unwrap();

    let verify_res = app
        .post_auth(
            &format!("/users/me/two-factor/totp/{method_id}/verify"),
            &user.access_token,
            &serde_json::json!({ "code": code }),
        )
        .await;
    assert_eq!(verify_res.status().as_u16(), 200);

    // Disable TOTP - this should fire the notification.
    let del_res = app
        .delete_auth_json(
            &format!("/users/me/two-factor/totp/{method_id}"),
            &user.access_token,
            &serde_json::json!({ "current_password": user.password }),
        )
        .await;
    assert_eq!(del_res.status().as_u16(), 204);

    let msg = mp
        .wait_for_message(&user.email, "Two-factor authentication disabled")
        .await
        .expect("two_factor_disabled notification not received");

    assert_eq!(msg.subject, "Two-factor authentication disabled");
}

// 7. Recovery code used notification

#[tokio::test]
async fn recovery_code_used_sends_notification_email() {
    let app = TestApp::spawn_with_mailpit().await;
    let mp = app.mailpit();

    let user = fixtures::authenticated_user(&app, 806).await;

    use totp_rs::{Algorithm, Secret, TOTP};

    let setup_res = app
        .post_auth(
            "/users/me/two-factor/totp/setup",
            &user.access_token,
            &serde_json::json!({}),
        )
        .await;
    let setup_body: serde_json::Value = setup_res.json().await.unwrap();
    let method_id = setup_body["method_id"].as_str().unwrap();
    let secret_b32 = setup_body["base32_secret"].as_str().unwrap();

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(secret_b32.to_owned()).to_bytes().unwrap(),
    )
    .unwrap();
    let code = totp.generate_current().unwrap();
    let verify_res = app
        .post_auth(
            &format!("/users/me/two-factor/totp/{method_id}/verify"),
            &user.access_token,
            &serde_json::json!({ "code": code }),
        )
        .await;
    let recovery_codes: Vec<String> =
        verify_res.json::<serde_json::Value>().await.unwrap()["recovery_codes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();

    // Login first to get a pre_auth_token (TOTP is enabled --> 2FA required).
    let pre_auth_res = app
        .post(
            "/auth/login",
            &serde_json::json!({
                "identifier": user.email,
                "password": user.password,
            }),
        )
        .await;
    assert_eq!(
        pre_auth_res.status().as_u16(),
        200,
        "login should require 2FA"
    );
    let pre_auth_body: serde_json::Value = pre_auth_res.json().await.unwrap();
    let pre_auth_token = pre_auth_body["pre_auth_token"]
        .as_str()
        .expect("expected pre_auth_token in login response");

    // Use a recovery code to complete login - this fires the notification.
    let login_res = app
        .post(
            "/auth/two-factor/recovery",
            &serde_json::json!({
                "pre_auth_token": pre_auth_token,
                "recovery_code": recovery_codes[0],
            }),
        )
        .await;
    assert_eq!(login_res.status().as_u16(), 200, "recovery login failed");

    let msg = mp
        .wait_for_message(&user.email, "A recovery code was used on your account")
        .await
        .expect("recovery_code_used notification not received");

    assert_eq!(msg.subject, "A recovery code was used on your account");
}
