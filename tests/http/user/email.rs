use crate::common::{app::TestApp, fixtures};

// Happy path

#[tokio::test]
async fn email_change_full_flow_success() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 1).await;
    let new_email = "new1@example.com";

    // Step 1: start - sends OTP to current email
    let res = app
        .post_auth(
            "/users/me/email/start",
            &user.access_token,
            &serde_json::json!({}),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200);
    let body: serde_json::Value = res.json().await.unwrap();
    let flow_token = body["flow_token"].as_str().unwrap().to_owned();

    // Step 2: verify current email OTP
    let otp = app.read_email_change_otp(&flow_token).await;
    let res = app
        .post_auth(
            "/users/me/email/verify-current",
            &user.access_token,
            &serde_json::json!({ "flow_token": flow_token, "code": otp }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 204);

    // Step 3: submit new email - sends OTP to new address
    let res = app
        .post_auth(
            "/users/me/email/submit",
            &user.access_token,
            &serde_json::json!({ "flow_token": flow_token, "new_email": new_email }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 204);

    // Step 4: confirm new email OTP
    let otp = app.read_email_change_otp(&flow_token).await;
    let res = app
        .post_auth(
            "/users/me/email/confirm",
            &user.access_token,
            &serde_json::json!({ "flow_token": flow_token, "code": otp }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 204);

    // The new email should be in place and login should work with it.
    let res = app
        .post(
            "/auth/login",
            &serde_json::json!({ "identifier": new_email, "password": user.password }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200);

    // The old email should no longer be accepted.
    let res = app
        .post(
            "/auth/login",
            &serde_json::json!({ "identifier": user.email, "password": user.password }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 401);
}

// Current-email OTP verification

#[tokio::test]
async fn email_change_verify_current_wrong_code_rejected() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 2).await;

    let res = app
        .post_auth(
            "/users/me/email/start",
            &user.access_token,
            &serde_json::json!({}),
        )
        .await;
    let flow_token = res.json::<serde_json::Value>().await.unwrap()["flow_token"]
        .as_str()
        .unwrap()
        .to_owned();

    let res = app
        .post_auth(
            "/users/me/email/verify-current",
            &user.access_token,
            &serde_json::json!({ "flow_token": flow_token, "code": "000000" }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 401);
}

#[tokio::test]
async fn email_change_steps_cannot_be_skipped() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 3).await;

    let res = app
        .post_auth(
            "/users/me/email/start",
            &user.access_token,
            &serde_json::json!({}),
        )
        .await;
    let flow_token = res.json::<serde_json::Value>().await.unwrap()["flow_token"]
        .as_str()
        .unwrap()
        .to_owned();

    // Try to submit new email before verifying the current one.
    let res = app
        .post_auth(
            "/users/me/email/submit",
            &user.access_token,
            &serde_json::json!({ "flow_token": flow_token, "new_email": "skip@example.com" }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 401);

    // Try to confirm before any of the prior steps.
    let res = app
        .post_auth(
            "/users/me/email/confirm",
            &user.access_token,
            &serde_json::json!({ "flow_token": flow_token, "code": "000000" }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 401);
}

// New email submission

#[tokio::test]
async fn email_change_submit_invalid_email_format_rejected() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 4).await;

    let res = app
        .post_auth(
            "/users/me/email/start",
            &user.access_token,
            &serde_json::json!({}),
        )
        .await;
    let flow_token = res.json::<serde_json::Value>().await.unwrap()["flow_token"]
        .as_str()
        .unwrap()
        .to_owned();

    let otp = app.read_email_change_otp(&flow_token).await;
    app.post_auth(
        "/users/me/email/verify-current",
        &user.access_token,
        &serde_json::json!({ "flow_token": flow_token, "code": otp }),
    )
    .await;

    let res = app
        .post_auth(
            "/users/me/email/submit",
            &user.access_token,
            &serde_json::json!({ "flow_token": flow_token, "new_email": "not-an-email" }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 422);
}

#[tokio::test]
async fn email_change_submit_taken_email_rejected() {
    let app = TestApp::spawn().await;
    let user1 = fixtures::authenticated_user(&app, 5).await;
    let user2 = fixtures::authenticated_user(&app, 6).await;

    // user2 tries to change their email to user1's existing address.
    let res = app
        .post_auth(
            "/users/me/email/start",
            &user2.access_token,
            &serde_json::json!({}),
        )
        .await;
    let flow_token = res.json::<serde_json::Value>().await.unwrap()["flow_token"]
        .as_str()
        .unwrap()
        .to_owned();

    let otp = app.read_email_change_otp(&flow_token).await;
    app.post_auth(
        "/users/me/email/verify-current",
        &user2.access_token,
        &serde_json::json!({ "flow_token": flow_token, "code": otp }),
    )
    .await;

    let res = app
        .post_auth(
            "/users/me/email/submit",
            &user2.access_token,
            &serde_json::json!({ "flow_token": flow_token, "new_email": user1.email }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 409);
}

// New-email OTP verification

#[tokio::test]
async fn email_change_confirm_wrong_code_rejected() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 7).await;
    let new_email = "confirm_wrong7@example.com";

    let flow_token = start_and_verify_current(&app, &user.access_token).await;

    app.post_auth(
        "/users/me/email/submit",
        &user.access_token,
        &serde_json::json!({ "flow_token": flow_token, "new_email": new_email }),
    )
    .await;

    let res = app
        .post_auth(
            "/users/me/email/confirm",
            &user.access_token,
            &serde_json::json!({ "flow_token": flow_token, "code": "000000" }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 401);
}

// Flow token security

#[tokio::test]
async fn email_change_unknown_flow_token_rejected() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 8).await;

    let res = app
        .post_auth(
            "/users/me/email/verify-current",
            &user.access_token,
            &serde_json::json!({ "flow_token": "no-such-token", "code": "000000" }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 401);
}

#[tokio::test]
async fn email_change_token_bound_to_initiating_user() {
    let app = TestApp::spawn().await;
    let user1 = fixtures::authenticated_user(&app, 9).await;
    let user2 = fixtures::authenticated_user(&app, 10).await;

    // user1 starts a flow.
    let res = app
        .post_auth(
            "/users/me/email/start",
            &user1.access_token,
            &serde_json::json!({}),
        )
        .await;
    let flow_token = res.json::<serde_json::Value>().await.unwrap()["flow_token"]
        .as_str()
        .unwrap()
        .to_owned();

    // user2 tries to use user1's flow token.
    let otp = app.read_email_change_otp(&flow_token).await;
    let res = app
        .post_auth(
            "/users/me/email/verify-current",
            &user2.access_token,
            &serde_json::json!({ "flow_token": flow_token, "code": otp }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 401);
}

// Preconditions

#[tokio::test]
async fn email_change_requires_verified_email() {
    let app = TestApp::spawn().await;
    // register_user creates a user whose email is NOT verified.
    let user = fixtures::register_user(&app, 11).await;

    let res = app
        .post(
            "/auth/login",
            &serde_json::json!({ "identifier": user.email, "password": user.password }),
        )
        .await;
    // Login should fail because email is not verified (pending_verification status).
    // In some configurations this returns 200 with limited access; either way the
    // email/start endpoint must reject the request.
    let token = match res.status().as_u16() {
        200 => {
            let body: serde_json::Value = res.json().await.unwrap();
            body["access_token"].as_str().unwrap().to_owned()
        }
        _ => return, // already gated at login, precondition satisfied
    };

    let res = app
        .post_auth("/users/me/email/start", &token, &serde_json::json!({}))
        .await;
    assert_eq!(res.status().as_u16(), 403);
}

// Cooldown

#[tokio::test]
async fn email_change_cooldown_prevents_immediate_second_change() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 12).await;
    let new_email = "cooldown12@example.com";

    // Complete a full flow.
    run_full_flow(&app, &user, new_email).await;

    // Immediately starting another flow must be rejected.
    let res = app
        .post_auth(
            "/users/me/email/start",
            &user.access_token,
            &serde_json::json!({}),
        )
        .await;
    assert_eq!(res.status().as_u16(), 429);
}

#[tokio::test]
async fn email_change_cooldown_lifted_allows_new_flow() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 13).await;
    let new_email = "cooldown_lifted13@example.com";

    run_full_flow(&app, &user, new_email).await;

    // Manually clear the cooldown to simulate time passing.
    app.clear_email_change_cooldown(user.id).await;

    // A new flow should now be accepted.
    let res = app
        .post_auth(
            "/users/me/email/start",
            &user.access_token,
            &serde_json::json!({}),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200);
}

// Helpers

/// Runs steps 1 and 2 (start + verify-current) and returns the flow_token.
async fn start_and_verify_current(app: &TestApp, token: &str) -> String {
    let user_id = {
        let claims =
            auth_api::utils::jwt::decode_token(token, "test-secret-that-is-long-enough-for-hs256")
                .expect("failed to decode access token");
        claims.sub
    };

    let res = app
        .post_auth("/users/me/email/start", token, &serde_json::json!({}))
        .await;
    assert_eq!(res.status().as_u16(), 200);
    let flow_token = res.json::<serde_json::Value>().await.unwrap()["flow_token"]
        .as_str()
        .unwrap()
        .to_owned();

    let otp = app.read_email_change_otp(&flow_token).await;
    let res = app
        .post_auth(
            "/users/me/email/verify-current",
            token,
            &serde_json::json!({ "flow_token": flow_token, "code": otp }),
        )
        .await;
    assert_eq!(
        res.status().as_u16(),
        204,
        "verify-current failed for user {}",
        user_id
    );

    flow_token
}

/// Runs all four steps of the email-change flow to completion.
async fn run_full_flow(app: &TestApp, user: &fixtures::AuthenticatedUser, new_email: &str) {
    let flow_token = start_and_verify_current(app, &user.access_token).await;

    let res = app
        .post_auth(
            "/users/me/email/submit",
            &user.access_token,
            &serde_json::json!({ "flow_token": flow_token, "new_email": new_email }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 204, "submit failed");

    let otp = app.read_email_change_otp(&flow_token).await;
    let res = app
        .post_auth(
            "/users/me/email/confirm",
            &user.access_token,
            &serde_json::json!({ "flow_token": flow_token, "code": otp }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 204, "confirm failed");
}

// Brute-force lockout

#[tokio::test]
async fn email_change_verify_current_lockout_after_max_failures() {
    // 5 wrong OTPs on verify-current must lock the flow (429 on the 6th attempt).
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 12).await;

    let res = app
        .post_auth(
            "/users/me/email/start",
            &user.access_token,
            &serde_json::json!({}),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200);
    let body: serde_json::Value = res.json().await.unwrap();
    let flow_token = body["flow_token"].as_str().unwrap().to_owned();

    for _ in 0..5 {
        app.post_auth(
            "/users/me/email/verify-current",
            &user.access_token,
            &serde_json::json!({ "flow_token": flow_token, "code": "000000" }),
        )
        .await;
    }

    let res = app
        .post_auth(
            "/users/me/email/verify-current",
            &user.access_token,
            &serde_json::json!({ "flow_token": flow_token, "code": "000000" }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 429, "6th wrong OTP must return 429");
}

#[tokio::test]
async fn email_change_confirm_new_lockout_after_max_failures() {
    // 5 wrong OTPs on confirm-new must lock the flow (429 on the 6th attempt).
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 13).await;

    // Complete steps 1–3 correctly.
    let flow_token = start_and_verify_current(&app, &user.access_token).await;
    app.post_auth(
        "/users/me/email/submit",
        &user.access_token,
        &serde_json::json!({ "flow_token": flow_token, "new_email": "new13@example.com" }),
    )
    .await;

    for _ in 0..5 {
        app.post_auth(
            "/users/me/email/confirm",
            &user.access_token,
            &serde_json::json!({ "flow_token": flow_token, "code": "000000" }),
        )
        .await;
    }

    let res = app
        .post_auth(
            "/users/me/email/confirm",
            &user.access_token,
            &serde_json::json!({ "flow_token": flow_token, "code": "000000" }),
        )
        .await;
    assert_eq!(
        res.status().as_u16(),
        429,
        "6th wrong confirm OTP must return 429"
    );
}
