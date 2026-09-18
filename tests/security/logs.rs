//! What reaches the logs: route templates, never secrets.
//!
//! Each test installs a capturing subscriber at trace level for the service,
//! runs flows that handle passwords, tokens and codes, and searches the logs
//! for every one of them.

use serde_json::{Value, json};
use testkit::logs::LogCapture;
use totp_rs::{Algorithm, Secret, TOTP};

use crate::common::{app::TestApp, fixtures};

const LOG_FILTER: &str = "auth_api=trace,access=trace,sqlx=trace,tower_http=trace";

fn assert_absent(logs: &str, secrets: &[(&str, String)]) {
    for (what, secret) in secrets {
        assert!(!secret.is_empty(), "{what} was not captured by the test");
        assert!(
            !logs.contains(secret.as_str()),
            "the logs contain {what} ({secret})"
        );
    }
}

#[tokio::test]
async fn access_logs_carry_route_templates_not_codes() {
    let logs = LogCapture::install(LOG_FILTER);
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 1).await;

    let user_code = "WXYZ-6789";
    app.get_auth(&format!("/oauth/device/{user_code}"), &user.access_token)
        .await;

    let contents = logs.contents();
    assert!(
        contents.contains("/oauth/device/{user_code}"),
        "no access log line for the route: {contents}"
    );
    assert!(
        !contents.contains(user_code),
        "a code carried in a path reached the logs"
    );
}

#[tokio::test]
async fn account_flows_never_log_their_secrets() {
    let logs = LogCapture::install(LOG_FILTER);
    let app = TestApp::spawn().await;
    let mut secrets: Vec<(&str, String)> = Vec::new();

    // Registration and email verification.
    let user = fixtures::register_user(&app, 1).await;
    secrets.push(("the registration password", user.password.clone()));
    let verification = app
        .mail
        .wait_for(&user.email, "Verify your email address")
        .await;
    let verification_token = verification
        .value_after("token=")
        .expect("verification link");
    secrets.push(("the verification token", verification_token.clone()));
    let verified = app
        .post(
            "/auth/verify-email",
            &json!({ "token": verification_token }),
        )
        .await;
    assert!(verified.status().is_success(), "{}", verified.status());

    // Sign-in and refresh.
    let login: Value = app
        .post(
            "/auth/login",
            &json!({ "identifier": user.email, "password": user.password }),
        )
        .await
        .json()
        .await
        .unwrap();
    let access_token = login["access_token"].as_str().unwrap().to_owned();
    let refresh_token = login["refresh_token"].as_str().unwrap().to_owned();
    secrets.push(("an access token", access_token.clone()));
    secrets.push(("a refresh token", refresh_token.clone()));
    let refreshed: Value = app
        .post("/auth/refresh", &json!({ "refresh_token": refresh_token }))
        .await
        .json()
        .await
        .unwrap();
    let access_token = refreshed["access_token"].as_str().unwrap().to_owned();
    secrets.push(("a rotated access token", access_token.clone()));
    secrets.push((
        "a rotated refresh token",
        refreshed["refresh_token"].as_str().unwrap().to_owned(),
    ));

    // Second factor: enrolment, recovery codes, a challenge.
    let reauth = app
        .post_auth(
            "/users/me/reauth",
            &access_token,
            &json!({ "current_password": user.password }),
        )
        .await;
    assert_eq!(reauth.status().as_u16(), 204);
    let setup: Value = app
        .post_auth("/users/me/two-factor/totp/setup", &access_token, &json!({}))
        .await
        .json()
        .await
        .unwrap();
    let secret = setup["base32_secret"].as_str().unwrap().to_owned();
    secrets.push(("the TOTP secret", secret.clone()));
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(secret).to_bytes().unwrap(),
    )
    .unwrap();
    let verified: Value = app
        .post_auth(
            &format!(
                "/users/me/two-factor/totp/{}/verify",
                setup["method_id"].as_str().unwrap()
            ),
            &access_token,
            &json!({ "code": totp.generate_current().unwrap() }),
        )
        .await
        .json()
        .await
        .unwrap();
    let recovery_codes: Vec<String> = verified["recovery_codes"]
        .as_array()
        .expect("recovery codes returned once")
        .iter()
        .map(|code| code.as_str().unwrap().to_owned())
        .collect();
    for code in &recovery_codes {
        secrets.push(("a recovery code", code.clone()));
    }

    let challenge: Value = app
        .post(
            "/auth/login",
            &json!({ "identifier": user.email, "password": user.password }),
        )
        .await
        .json()
        .await
        .unwrap();
    secrets.push((
        "a pre-auth token",
        challenge["pre_auth_token"].as_str().unwrap().to_owned(),
    ));
    let completed = app
        .post(
            "/auth/two-factor/recovery",
            &json!({
                "pre_auth_token": challenge["pre_auth_token"],
                "recovery_code": recovery_codes[0],
            }),
        )
        .await;
    assert!(completed.status().is_success(), "{}", completed.status());

    // Password reset.
    let forgot = app
        .post("/auth/forgot-password", &json!({ "email": user.email }))
        .await;
    assert!(forgot.status().is_success(), "{}", forgot.status());
    let reset_mail = app.mail.wait_for(&user.email, "Reset your password").await;
    let reset_token = reset_mail.value_after("token=").expect("reset link");
    secrets.push(("the reset token", reset_token.clone()));
    let new_password = "An0ther-Secret!pass".to_owned();
    secrets.push(("the new password", new_password.clone()));
    let reset = app
        .post(
            "/auth/reset-password",
            &json!({ "token": reset_token, "new_password": new_password }),
        )
        .await;
    assert!(reset.status().is_success(), "{}", reset.status());

    assert_absent(&logs.contents(), &secrets);
}
