//! `/auth/magic-link`: signing in with a link sent by email.

use serde_json::{Value, json};

use crate::common::{app::TestApp, fixtures};

const SUBJECT: &str = "Your sign-in link";

async fn request(app: &TestApp, email: &str) -> u16 {
    app.post("/auth/magic-link", &json!({ "email": email }))
        .await
        .status()
        .as_u16()
}

async fn complete(app: &TestApp, token: &str) -> (u16, Value) {
    let response = app
        .post("/auth/magic-link/complete", &json!({ "token": token }))
        .await;
    let status = response.status().as_u16();
    (status, response.json().await.unwrap_or(Value::Null))
}

async fn link_token(app: &TestApp, email: &str) -> String {
    app.mail
        .wait_for(email, SUBJECT)
        .await
        .value_after("#token=")
        .expect("sign-in link")
}

#[tokio::test]
async fn a_link_signs_in_once() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 1).await;
    fixtures::activate_user(&app.db, user.id).await;

    assert_eq!(request(&app, &user.email).await, 200);
    let token = link_token(&app, &user.email).await;

    let (status, tokens) = complete(&app, &token).await;
    assert_eq!(status, 200, "{tokens}");
    let access = tokens["access_token"].as_str().unwrap();
    assert_eq!(app.get_auth("/users/me", access).await.status(), 200);

    let (status, _) = complete(&app, &token).await;
    assert_eq!(status, 401, "a link works once");

    let method: Value = sqlx::query_scalar(
        "SELECT metadata FROM audit_log WHERE user_id = $1 AND action = 'login'",
    )
    .bind(user.id)
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert_eq!(method["method"], "magic_link");
}

#[tokio::test]
async fn a_new_link_replaces_the_previous_one_and_an_old_link_expires() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 1).await;
    fixtures::activate_user(&app.db, user.id).await;

    request(&app, &user.email).await;
    let first = link_token(&app, &user.email).await;
    request(&app, &user.email).await;
    let messages = app.mail.wait_for_count(&user.email, 2).await;
    let second = messages
        .iter()
        .filter(|m| m.subject == SUBJECT)
        .filter_map(|m| m.value_after("#token="))
        .find(|t| *t != first)
        .unwrap();

    assert_eq!(complete(&app, &first).await.0, 401);

    app.clock.advance(time::Duration::minutes(16));
    let (status, body) = complete(&app, &second).await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["code"], "token_expired");
}

#[tokio::test]
async fn a_second_factor_is_still_required() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 1).await;
    fixtures::activate_user(&app.db, user.id).await;
    sqlx::query(
        "INSERT INTO two_factor_methods (user_id, method_type, is_primary, is_verified)
         VALUES ($1, 'email', TRUE, TRUE)",
    )
    .bind(user.id)
    .execute(&app.db)
    .await
    .unwrap();

    request(&app, &user.email).await;
    let token = link_token(&app, &user.email).await;
    let (status, body) = complete(&app, &token).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["two_factor_required"], true);
    assert!(body.get("access_token").is_none());
}

#[tokio::test]
async fn unknown_pending_and_suspended_addresses_answer_alike_and_get_nothing() {
    let app = TestApp::spawn().await;
    let pending = fixtures::register_user(&app, 1).await;
    let suspended = fixtures::register_user(&app, 2).await;
    fixtures::activate_user(&app.db, suspended.id).await;
    sqlx::query("UPDATE users SET status = 'suspended' WHERE id = $1")
        .bind(suspended.id)
        .execute(&app.db)
        .await
        .unwrap();

    for email in ["nobody@example.com", &pending.email, &suspended.email] {
        assert_eq!(request(&app, email).await, 200);
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    for email in [&pending.email, &suspended.email] {
        assert!(
            app.mail
                .messages_to(email)
                .iter()
                .all(|m| m.subject != SUBJECT),
            "{email} received a link"
        );
    }
}

#[tokio::test]
async fn a_suspension_after_the_link_was_sent_stops_it() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 1).await;
    fixtures::activate_user(&app.db, user.id).await;
    request(&app, &user.email).await;
    let token = link_token(&app, &user.email).await;
    sqlx::query("UPDATE users SET status = 'suspended' WHERE id = $1")
        .bind(user.id)
        .execute(&app.db)
        .await
        .unwrap();

    let (status, body) = complete(&app, &token).await;
    assert_eq!(status, 403);
    assert_eq!(body["code"], "account_suspended");
}

#[tokio::test]
async fn links_are_capped_per_account_and_off_unless_enabled() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 1).await;
    fixtures::activate_user(&app.db, user.id).await;
    for _ in 0..5 {
        assert_eq!(request(&app, &user.email).await, 200);
    }
    app.mail.wait_for_count(&user.email, 3).await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let links = app
        .mail
        .messages_to(&user.email)
        .into_iter()
        .filter(|m| m.subject == SUBJECT)
        .count();
    assert_eq!(links, 3);

    let disabled = TestApp::spawn_with_config(|c| c.security.magic_links = false).await;
    assert_eq!(request(&disabled, &user.email).await, 404);
    assert_eq!(complete(&disabled, "anything").await.0, 404);
}
