//! Account pre-hijacking (SEC-43): registering someone's address first must
//! not let an attacker choose the password the owner will activate.
//!
//! Before the control, a registration on a pending address re-sent the link of
//! the existing account and dropped the password the owner had just chosen:
//! clicking it activated the account with the attacker's password.

use serde_json::{Value, json};

use crate::common::app::TestApp;

const SUBJECT: &str = "Verify your email address";
const VICTIM: &str = "prehijack.owner@example.com";
const ATTACKER_PASSWORD: &str = "Attacker-Pass-11!";
const OWNER_PASSWORD: &str = "Owner-Pass-22!ok";

async fn register(app: &TestApp, username: &str, password: &str) -> Value {
    let response = app
        .post(
            "/auth/register",
            &json!({ "username": username, "email": VICTIM, "password": password }),
        )
        .await;
    assert_eq!(response.status().as_u16(), 202);
    response.json().await.unwrap()
}

async fn login_status(app: &TestApp, password: &str) -> u16 {
    app.post(
        "/auth/login",
        &json!({ "identifier": VICTIM, "password": password }),
    )
    .await
    .status()
    .as_u16()
}

#[tokio::test]
async fn the_owner_activates_the_account_with_the_password_they_chose() {
    let app = TestApp::spawn().await;
    let squatted = register(&app, "squatter", ATTACKER_PASSWORD).await;
    app.mail.wait_for(VICTIM, SUBJECT).await;

    let owned = register(&app, "rightful_owner", OWNER_PASSWORD).await;
    assert_eq!(
        squatted, owned,
        "the second registration looks like a first"
    );

    let mails = app.mail.wait_for_count(VICTIM, 2).await;
    let owner_mail = mails.last().unwrap();
    assert!(
        owner_mail.html.contains("rightful_owner"),
        "the link names the account it activates"
    );
    let token = owner_mail.value_after("token=").unwrap();
    let verified = app
        .post("/auth/verify-email", &json!({ "token": token }))
        .await;
    assert_eq!(verified.status().as_u16(), 200);

    assert_eq!(login_status(&app, ATTACKER_PASSWORD).await, 401);
    assert_eq!(login_status(&app, OWNER_PASSWORD).await, 200);
    let username: String = sqlx::query_scalar("SELECT username FROM users WHERE email = $1")
        .bind(VICTIM)
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(username, "rightful_owner");
}

#[tokio::test]
async fn a_resend_repeats_the_latest_registration_not_the_first() {
    let app = TestApp::spawn().await;
    register(&app, "squatter", ATTACKER_PASSWORD).await;
    register(&app, "rightful_owner", OWNER_PASSWORD).await;
    app.mail.wait_for_count(VICTIM, 2).await;

    // Anyone knowing the address can ask for a resend.
    let resent = app
        .post("/auth/verify-email/resend", &json!({ "email": VICTIM }))
        .await;
    assert_eq!(resent.status().as_u16(), 200);
    let mails = app.mail.wait_for_count(VICTIM, 3).await;
    let token = mails.last().unwrap().value_after("token=").unwrap();
    let verified = app
        .post("/auth/verify-email", &json!({ "token": token }))
        .await;
    assert_eq!(verified.status().as_u16(), 200);

    assert_eq!(login_status(&app, ATTACKER_PASSWORD).await, 401);
    assert_eq!(login_status(&app, OWNER_PASSWORD).await, 200);
}
