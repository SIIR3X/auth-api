//! Second-factor management and explicit re-authentication.
//!
//! - removing the primary method promotes the remaining verified one, so 2FA
//!   cannot be switched off by removing a single method;
//! - unknown or mismatched method ids answer 404 and change nothing;
//! - an abandoned enrolment can be restarted;
//! - enrolling requires a recent re-authentication or the password;
//! - signing in alone never grants sensitive actions.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::common::{
    app::TestApp,
    fixtures::{self, AuthenticatedUser},
};

fn totp_code(base32_secret: &str) -> String {
    auth_api::utils::totp::current_code(base32_secret).unwrap()
}

async fn enable_totp(app: &TestApp, user: &AuthenticatedUser) -> String {
    let res = app
        .post_auth(
            "/users/me/two-factor/totp/setup",
            &user.access_token,
            &json!({}),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200, "totp setup failed");
    let body: Value = res.json().await.unwrap();
    let method_id = body["method_id"].as_str().unwrap().to_owned();
    let res = app
        .post_auth(
            &format!("/users/me/two-factor/totp/{method_id}/verify"),
            &user.access_token,
            &json!({ "code": totp_code(body["base32_secret"].as_str().unwrap()) }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200, "totp verify failed");
    method_id
}

async fn enable_email_2fa(app: &TestApp, user: &AuthenticatedUser) -> String {
    let res = app
        .post_auth(
            "/users/me/two-factor/email/setup",
            &user.access_token,
            &json!({}),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200, "email setup failed");
    let method_id = res.json::<Value>().await.unwrap()["method_id"]
        .as_str()
        .unwrap()
        .to_owned();

    sqlx::query("UPDATE email_2fa_codes SET code_hash = $2 WHERE user_id = $1 AND used_at IS NULL")
        .bind(user.id)
        .bind(Sha256::digest(b"424242").to_vec())
        .execute(&app.db)
        .await
        .unwrap();

    let res = app
        .post_auth(
            &format!("/users/me/two-factor/email/{method_id}/verify"),
            &user.access_token,
            &json!({ "code": "424242" }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200, "email verify failed");
    app.clear_email_2fa_cooldown(user.id).await;
    method_id
}

/// Sign in with the password only: no explicit re-authentication.
async fn sign_in(app: &TestApp, user: &AuthenticatedUser) -> Value {
    let res = app
        .post(
            "/auth/login",
            &json!({ "identifier": user.email, "password": user.password }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200);
    res.json().await.unwrap()
}

async fn count(app: &TestApp, sql: &str, user_id: uuid::Uuid) -> i64 {
    sqlx::query_scalar(sql)
        .bind(user_id)
        .fetch_one(&app.db)
        .await
        .unwrap()
}

#[tokio::test]
async fn removing_the_primary_method_promotes_the_remaining_one() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 620).await;
    let totp_id = enable_totp(&app, &user).await;
    enable_email_2fa(&app, &user).await;

    let res = app
        .delete_auth(
            &format!("/users/me/two-factor/totp/{totp_id}"),
            &user.access_token,
        )
        .await;
    assert_eq!(res.status().as_u16(), 204);

    let primary_email = count(
        &app,
        "SELECT count(*) FROM two_factor_methods
         WHERE user_id = $1 AND method_type = 'email' AND is_primary",
        user.id,
    )
    .await;
    assert_eq!(primary_email, 1, "email must become primary");
    let codes = count(
        &app,
        "SELECT count(*) FROM recovery_codes WHERE user_id = $1",
        user.id,
    )
    .await;
    assert_eq!(codes, 10, "recovery codes stay while a method remains");

    let challenge = sign_in(&app, &user).await;
    assert_eq!(
        challenge["two_factor_required"], true,
        "2FA must still apply"
    );
    assert_eq!(challenge["two_factor_method"], "email");
}

#[tokio::test]
async fn removing_the_last_method_drops_recovery_codes() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 621).await;
    let totp_id = enable_totp(&app, &user).await;

    let res = app
        .delete_auth(
            &format!("/users/me/two-factor/totp/{totp_id}"),
            &user.access_token,
        )
        .await;
    assert_eq!(res.status().as_u16(), 204);
    let codes = count(
        &app,
        "SELECT count(*) FROM recovery_codes WHERE user_id = $1",
        user.id,
    )
    .await;
    assert_eq!(codes, 0);
}

#[tokio::test]
async fn unknown_or_mismatched_method_ids_answer_404_and_change_nothing() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 622).await;
    enable_totp(&app, &user).await;
    let email_id = enable_email_2fa(&app, &user).await;

    let unknown = app
        .delete_auth(
            &format!("/users/me/two-factor/totp/{}", uuid::Uuid::new_v4()),
            &user.access_token,
        )
        .await;
    assert_eq!(unknown.status().as_u16(), 404);

    let mismatched = app
        .delete_auth(
            &format!("/users/me/two-factor/totp/{email_id}"),
            &user.access_token,
        )
        .await;
    assert_eq!(mismatched.status().as_u16(), 404);

    let methods = count(
        &app,
        "SELECT count(*) FROM two_factor_methods WHERE user_id = $1",
        user.id,
    )
    .await;
    let codes = count(
        &app,
        "SELECT count(*) FROM recovery_codes WHERE user_id = $1",
        user.id,
    )
    .await;
    assert_eq!((methods, codes), (2, 10));
}

#[tokio::test]
async fn an_abandoned_totp_enrolment_can_be_restarted() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 623).await;

    let first = app
        .post_auth(
            "/users/me/two-factor/totp/setup",
            &user.access_token,
            &json!({}),
        )
        .await;
    assert_eq!(first.status().as_u16(), 200);
    let second = app
        .post_auth(
            "/users/me/two-factor/totp/setup",
            &user.access_token,
            &json!({}),
        )
        .await;
    assert_eq!(
        second.status().as_u16(),
        200,
        "restarting setup must not fail"
    );
    let body: Value = second.json().await.unwrap();

    let res = app
        .post_auth(
            &format!(
                "/users/me/two-factor/totp/{}/verify",
                body["method_id"].as_str().unwrap()
            ),
            &user.access_token,
            &json!({ "code": totp_code(body["base32_secret"].as_str().unwrap()) }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200, "the latest secret must verify");

    let again = app
        .post_auth(
            "/users/me/two-factor/totp/setup",
            &user.access_token,
            &json!({}),
        )
        .await;
    assert_eq!(
        again.status().as_u16(),
        409,
        "a verified method is not re-enrolled"
    );
}

#[tokio::test]
async fn enrolling_a_second_factor_requires_reauthentication() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 624).await;
    app.clear_recent_reauth(&user.access_token).await;

    for path in [
        "/users/me/two-factor/totp/setup",
        "/users/me/two-factor/email/setup",
    ] {
        let refused = app.post_auth(path, &user.access_token, &json!({})).await;
        assert_eq!(refused.status().as_u16(), 403, "{path} without reauth");
    }

    let with_password = app
        .post_auth(
            "/users/me/two-factor/totp/setup",
            &user.access_token,
            &json!({ "current_password": user.password }),
        )
        .await;
    assert_eq!(with_password.status().as_u16(), 200);
}

#[tokio::test]
async fn signing_in_does_not_grant_sensitive_actions() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 625).await;
    let fresh = sign_in(&app, &user).await;
    let token = fresh["access_token"].as_str().unwrap();

    let change_password = app
        .patch_auth(
            "/users/me/password",
            token,
            &json!({ "new_password": "Another-Pass-99" }),
        )
        .await;
    assert_eq!(change_password.status().as_u16(), 403);

    let start_email_change = app
        .post_auth("/users/me/email/start", token, &json!({}))
        .await;
    assert_eq!(start_email_change.status().as_u16(), 403);

    let delete_account = app.delete_auth_json("/users/me", token, &json!({})).await;
    assert_eq!(delete_account.status().as_u16(), 403);
}

#[tokio::test]
async fn a_session_can_be_revoked_with_the_current_password() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 626).await;
    let other = sign_in(&app, &user).await;
    app.clear_recent_reauth(&user.access_token).await;

    let sessions: Value = app
        .get_auth("/users/me/sessions", &user.access_token)
        .await
        .json()
        .await
        .unwrap();
    let other_id = sessions
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["is_current"] == false)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let res = app
        .delete_auth_json(
            &format!("/users/me/sessions/{other_id}"),
            &user.access_token,
            &json!({ "current_password": user.password }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 204);

    let revoked = app
        .get_auth("/users/me", other["access_token"].as_str().unwrap())
        .await;
    assert_eq!(revoked.status().as_u16(), 401);
}
