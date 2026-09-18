//! Ways into an account that outlive its password (SEC-44).
//!
//! Whoever held the password for a while can add a passkey or a personal
//! access token, and neither ends with a password reset. The owner hears of
//! each addition, and every password change or reset lists what still opens
//! the account. A pending account taken back by a reset keeps nothing.

use serde_json::{Value, json};
use testkit::authenticator::SoftAuthenticator;

use crate::common::{app::TestApp, fixtures};

const ACCESS_ADDED: &str = "A new way to access your account was added";
const PASSWORD_CHANGED: &str = "Your password has been changed";

#[tokio::test]
async fn adding_a_passkey_or_a_token_is_announced_to_the_owner() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 0).await;

    let created = app
        .post_auth(
            "/users/me/tokens",
            &user.access_token,
            &json!({ "name": "nightly-backup" }),
        )
        .await;
    assert_eq!(created.status().as_u16(), 201);
    let mail = app.mail.wait_for(&user.email, ACCESS_ADDED).await;
    assert!(mail.html.contains("nightly-backup"), "{}", mail.html);

    let mut authenticator = SoftAuthenticator::for_app(&app);
    let options: Value = app
        .post_auth("/users/me/passkeys/options", &user.access_token, &json!({}))
        .await
        .json()
        .await
        .unwrap();
    let credential = authenticator.create(&options);
    let registered = app
        .post_auth(
            "/users/me/passkeys",
            &user.access_token,
            &json!({ "name": "Planted key", "credential": credential }),
        )
        .await;
    assert_eq!(registered.status().as_u16(), 201);
    let mails = app.mail.wait_for_count(&user.email, 3).await;
    assert!(
        mails
            .iter()
            .any(|m| m.subject == ACCESS_ADDED && m.html.contains("Planted key"))
    );
}

#[tokio::test]
async fn a_reset_lists_what_still_opens_the_account() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 1).await;
    // A passkey survives the reset; a personal access token does not (its
    // session is revoked with the others), so only the passkey is listed.
    let mut authenticator = SoftAuthenticator::for_app(&app);
    let options: Value = app
        .post_auth("/users/me/passkeys/options", &user.access_token, &json!({}))
        .await
        .json()
        .await
        .unwrap();
    let credential = authenticator.create(&options);
    let registered = app
        .post_auth(
            "/users/me/passkeys",
            &user.access_token,
            &json!({ "name": "Planted key", "credential": credential }),
        )
        .await;
    assert_eq!(registered.status().as_u16(), 201);
    let created = app
        .post_auth(
            "/users/me/tokens",
            &user.access_token,
            &json!({ "name": "planted-token" }),
        )
        .await;
    assert_eq!(created.status().as_u16(), 201);

    let token = fixtures::create_password_reset_token(&app.db, user.id).await;
    let reset = app
        .post(
            "/auth/reset-password",
            &json!({ "token": token.raw, "new_password": "Brand-New-Pass-9!" }),
        )
        .await;
    assert_eq!(reset.status().as_u16(), 200);

    let mail = app.mail.wait_for(&user.email, PASSWORD_CHANGED).await;
    assert!(mail.html.contains("Planted key"), "{}", mail.html);
    assert!(!mail.html.contains("planted-token"), "{}", mail.html);
}

#[tokio::test]
async fn a_pending_account_taken_back_by_a_reset_keeps_no_other_access() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 2).await;
    // Rows only a signed-in account could have created: planted directly.
    sqlx::query(
        "INSERT INTO external_identities (user_id, provider, subject) VALUES ($1, 'github', '42')",
    )
    .bind(user.id)
    .execute(&app.db)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO recovery_codes (user_id, code_hash, code_position) VALUES ($1, $2, 1)",
    )
    .bind(user.id)
    .bind(auth_api::utils::crypto::sha256(b"planted-code").to_vec())
    .execute(&app.db)
    .await
    .unwrap();

    let token = fixtures::create_password_reset_token(&app.db, user.id).await;
    let reset = app
        .post(
            "/auth/reset-password",
            &json!({ "token": token.raw, "new_password": "Owner-Takes-Back-7!" }),
        )
        .await;
    assert_eq!(reset.status().as_u16(), 200);

    for table in ["external_identities", "recovery_codes"] {
        let left: i64 =
            sqlx::query_scalar(&format!("SELECT count(*) FROM {table} WHERE user_id = $1"))
                .bind(user.id)
                .fetch_one(&app.db)
                .await
                .unwrap();
        assert_eq!(left, 0, "{table} survived the owner's reset");
    }
}
