//! The owner of an account is told about a sign-in from a device the account
//! never used.

use serde_json::{Value, json};

use crate::common::{app::TestApp, fixtures};

const ALERT_SUBJECT: &str = "New sign-in to your account";
const FIREFOX_LINUX_OLD: &str =
    "Mozilla/5.0 (X11; Linux x86_64; rv:139.0) Gecko/20100101 Firefox/139.0";
const FIREFOX_LINUX_NEW: &str =
    "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0";
const CHROME_WINDOWS: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36";

async fn active_user(app: &TestApp, index: usize) -> fixtures::RegisteredUser {
    let user = fixtures::register_user(app, index).await;
    fixtures::activate_user(&app.db, user.id).await;
    user
}

async fn sign_in_with(app: &TestApp, user: &fixtures::RegisteredUser, user_agent: &str) {
    let res = app
        .client
        .post(app.url("/auth/login"))
        .header("user-agent", user_agent)
        .json(&json!({ "identifier": user.email, "password": user.password }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 200);
}

async fn alerts(app: &TestApp, email: &str) -> Vec<testkit::mail::CapturedMail> {
    // Alerts are sent in the background: give them time to arrive.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    app.mail
        .messages_to(email)
        .into_iter()
        .filter(|mail| mail.subject == ALERT_SUBJECT)
        .collect()
}

async fn known_devices(app: &TestApp, user_id: uuid::Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM known_devices WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(&app.db)
        .await
        .unwrap()
}

#[tokio::test]
async fn the_first_sign_in_and_a_browser_update_raise_no_alert() {
    let app = TestApp::spawn().await;
    let user = active_user(&app, 970).await;

    sign_in_with(&app, &user, FIREFOX_LINUX_OLD).await;
    sign_in_with(&app, &user, FIREFOX_LINUX_NEW).await;

    assert!(alerts(&app, &user.email).await.is_empty());
    assert_eq!(known_devices(&app, user.id).await, 1, "one device, updated");
}

#[tokio::test]
async fn a_sign_in_from_a_new_device_alerts_the_owner() {
    let app = TestApp::spawn().await;
    let user = active_user(&app, 971).await;

    sign_in_with(&app, &user, FIREFOX_LINUX_NEW).await;
    sign_in_with(&app, &user, CHROME_WINDOWS).await;

    let sent = app.mail.wait_for(&user.email, ALERT_SUBJECT).await;
    assert!(sent.html.contains("Chrome on Windows"), "{}", sent.html);
    assert_eq!(alerts(&app, &user.email).await.len(), 1);

    let recorded: Value = sqlx::query_scalar(
        "SELECT metadata FROM audit_log WHERE user_id = $1 AND action = 'new_device_login'",
    )
    .bind(user.id)
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert_eq!(recorded, json!({ "device": "Chrome on Windows" }));
}

#[tokio::test]
async fn with_alerts_off_devices_are_still_recorded() {
    let app = TestApp::spawn_with_config(|config| {
        config.security.new_device_alerts = false;
    })
    .await;
    let user = active_user(&app, 972).await;

    sign_in_with(&app, &user, FIREFOX_LINUX_NEW).await;
    sign_in_with(&app, &user, CHROME_WINDOWS).await;

    assert!(alerts(&app, &user.email).await.is_empty());
    assert_eq!(known_devices(&app, user.id).await, 2);
}

#[tokio::test]
async fn devices_unused_for_long_are_forgotten() {
    let app = TestApp::spawn().await;
    let user = active_user(&app, 973).await;
    sign_in_with(&app, &user, FIREFOX_LINUX_NEW).await;
    sqlx::query(
        "UPDATE known_devices SET last_seen_at = NOW() - INTERVAL '100 days' WHERE user_id = $1",
    )
    .bind(user.id)
    .execute(&app.db)
    .await
    .unwrap();

    auth_api::services::cleanup::run_once(&app.db, &app.state.config)
        .await
        .unwrap();

    assert_eq!(known_devices(&app, user.id).await, 0);
}
