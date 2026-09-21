//! Account pre-hijacking (SEC-43): whoever registers a pending address, first
//! or second, cannot activate the account with a password its owner did not
//! choose.
//!
//! A verification link proves the mailbox; the password proves which
//! registration it activates. Two regressions are pinned: a registration on a
//! pending address re-sending the first registrant's link (the attacker came
//! first), and a later registration's link carrying the attacker's password to
//! the owner's mailbox (the attacker came second).

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

/// The token of the `n`-th verification e-mail (1-based) sent to the victim.
async fn link(app: &TestApp, n: usize) -> String {
    let mails = app.mail.wait_for_count(VICTIM, n).await;
    mails[n - 1].value_after("token=").unwrap()
}

async fn verify(app: &TestApp, token: &str, password: &str) -> (u16, Value) {
    let response = app
        .post(
            "/auth/verify-email",
            &json!({ "token": token, "password": password }),
        )
        .await;
    let status = response.status().as_u16();
    (status, response.json().await.unwrap_or(Value::Null))
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
async fn an_attacker_registering_first_cannot_pick_the_owners_password() {
    let app = TestApp::spawn().await;
    let squatted = register(&app, "squatter", ATTACKER_PASSWORD).await;
    app.mail.wait_for(VICTIM, SUBJECT).await;
    let owned = register(&app, "rightful_owner", OWNER_PASSWORD).await;
    assert_eq!(
        squatted, owned,
        "the second registration looks like a first"
    );

    // The squatter's link, clicked by the owner, needs the squatter's password.
    let (status, body) = verify(&app, &link(&app, 1).await, OWNER_PASSWORD).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (401, Some("invalid_credentials"))
    );

    let owner_link = link(&app, 2).await;
    let mails = app.mail.wait_for_count(VICTIM, 2).await;
    assert!(
        mails[1].html.contains("rightful_owner"),
        "the link names its account"
    );
    assert_eq!(verify(&app, &owner_link, OWNER_PASSWORD).await.0, 200);

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
async fn an_attacker_registering_second_cannot_slip_their_password_into_a_link() {
    let app = TestApp::spawn().await;
    register(&app, "rightful_owner", OWNER_PASSWORD).await;
    app.mail.wait_for(VICTIM, SUBJECT).await;
    register(&app, "squatter", ATTACKER_PASSWORD).await;

    // The latest link in the owner's mailbox is the attacker's: clicking it
    // with the owner's password activates nothing and leaves it unused.
    let attacker_link = link(&app, 2).await;
    let (status, body) = verify(&app, &attacker_link, OWNER_PASSWORD).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (401, Some("invalid_credentials"))
    );
    let pending: String = sqlx::query_scalar("SELECT status::text FROM users WHERE email = $1")
        .bind(VICTIM)
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(pending, "pending_verification");

    assert_eq!(
        verify(&app, &link(&app, 1).await, OWNER_PASSWORD).await.0,
        200
    );
    assert_eq!(login_status(&app, ATTACKER_PASSWORD).await, 401);
    assert_eq!(login_status(&app, OWNER_PASSWORD).await, 200);
}

#[tokio::test]
async fn a_resend_never_carries_another_registrations_password() {
    let app = TestApp::spawn().await;
    register(&app, "squatter", ATTACKER_PASSWORD).await;
    register(&app, "rightful_owner", OWNER_PASSWORD).await;
    app.mail.wait_for_count(VICTIM, 2).await;

    // Anyone knowing the address can ask for a resend: the new link asks for
    // the password the account was created with, not the latest one chosen.
    let resent = app
        .post("/auth/verify-email/resend", &json!({ "email": VICTIM }))
        .await;
    assert_eq!(resent.status().as_u16(), 200);
    let resent_link = link(&app, 3).await;
    assert_eq!(verify(&app, &resent_link, OWNER_PASSWORD).await.0, 401);

    // The owner's own registration link still works.
    assert_eq!(
        verify(&app, &link(&app, 2).await, OWNER_PASSWORD).await.0,
        200
    );
    assert_eq!(login_status(&app, OWNER_PASSWORD).await, 200);
}
