//! Lockout and account recovery (SEC-58): guessing a password cannot keep its
//! owner out.
//!
//! Before the control, the count of wrong passwords had no time bound and was
//! reset only by a password sign-in: one guess every lock period kept an
//! account locked for good, a lock blocked passkeys and sign-in links too, a
//! reset did not lift it, a locked account answered differently from an
//! unknown one, and anyone asking for reset links spent the owner's budget and
//! revoked the link they were about to click.

use serde_json::{Value, json};

use crate::common::{
    app::TestApp,
    fixtures::{self, AuthenticatedUser},
};

const LOCKED_SUBJECT: &str = "Sign-in with your password is blocked";
const RESET_SUBJECT: &str = "Reset your password";
const LINK_SUBJECT: &str = "Your sign-in link";
const WRONG: &str = "Wrong-Password-1!";

async fn login(app: &TestApp, identifier: &str, password: &str) -> (u16, Value) {
    let response = app
        .post(
            "/auth/login",
            &json!({ "identifier": identifier, "password": password }),
        )
        .await;
    let status = response.status().as_u16();
    (status, response.json().await.unwrap_or(Value::Null))
}

/// The test configuration locks after 3 wrong passwords.
async fn lock(app: &TestApp, user: &AuthenticatedUser) {
    for _ in 0..3 {
        assert_eq!(login(app, &user.email, WRONG).await.0, 401);
    }
}

async fn post_from(app: &TestApp, ip: &str, path: &str, body: &Value) -> reqwest::Response {
    app.client
        .post(app.url(path))
        .header("x-forwarded-for", ip)
        .json(body)
        .send()
        .await
        .unwrap()
}

async fn sign_in_by_link(app: &TestApp, user: &AuthenticatedUser, nth: usize) -> u16 {
    let res = app
        .post("/auth/magic-link", &json!({ "email": user.email }))
        .await;
    assert_eq!(res.status().as_u16(), 200, "{}", res.text().await.unwrap());
    let mails: Vec<_> = app
        .mail
        .wait_for_count(&user.email, nth)
        .await
        .into_iter()
        .filter(|mail| mail.subject == LINK_SUBJECT)
        .collect();
    let token = mails.last().unwrap().value_after("token=").unwrap();
    app.post("/auth/magic-link/complete", &json!({ "token": token }))
        .await
        .status()
        .as_u16()
}

#[tokio::test]
async fn a_locked_password_answers_like_a_wrong_one_and_tells_the_owner() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 800).await;
    lock(&app, &user).await;

    let (status, body) = login(&app, &user.email, &user.password).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (401, Some("invalid_credentials"))
    );
    let (status, unknown) = login(&app, "nobody-800@example.com", WRONG).await;
    assert_eq!((status, &unknown["code"]), (401, &body["code"]));

    let mail = app.mail.wait_for(&user.email, LOCKED_SUBJECT).await;
    assert!(mail.html.contains("minutes"), "{}", mail.html);
}

#[tokio::test]
async fn a_lock_does_not_outlive_itself() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 801).await;
    lock(&app, &user).await;
    // The lock ends: the guesses before and during it no longer count.
    sqlx::query("UPDATE users SET locked_until = NOW() - INTERVAL '1 second' WHERE id = $1")
        .bind(user.id)
        .execute(&app.db)
        .await
        .unwrap();

    assert_eq!(login(&app, &user.email, WRONG).await.0, 401);
    assert_eq!(
        login(&app, &user.email, &user.password).await.0,
        200,
        "one more guess after a lock must not lock again"
    );
}

#[tokio::test]
async fn any_completed_sign_in_restarts_the_count() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 802).await;
    for _ in 0..2 {
        assert_eq!(login(&app, &user.email, WRONG).await.0, 401);
    }
    assert_eq!(sign_in_by_link(&app, &user, 1).await, 200);
    for _ in 0..2 {
        assert_eq!(login(&app, &user.email, WRONG).await.0, 401);
    }
    assert_eq!(login(&app, &user.email, &user.password).await.0, 200);
}

#[tokio::test]
async fn old_failures_do_not_add_up_with_new_ones() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 803).await;
    for _ in 0..2 {
        assert_eq!(login(&app, &user.email, WRONG).await.0, 401);
    }
    sqlx::query(
        "UPDATE login_attempts SET attempted_at = NOW() - INTERVAL '2 days' WHERE user_id = $1",
    )
    .bind(user.id)
    .execute(&app.db)
    .await
    .unwrap();
    assert_eq!(login(&app, &user.email, WRONG).await.0, 401);
    assert_eq!(login(&app, &user.email, &user.password).await.0, 200);
}

#[tokio::test]
async fn the_other_ways_in_stay_open_while_the_password_is_locked() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 804).await;
    lock(&app, &user).await;
    assert_eq!(sign_in_by_link(&app, &user, 2).await, 200);
}

#[tokio::test]
async fn a_reset_lifts_the_lock() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 805).await;
    lock(&app, &user).await;

    app.post("/auth/forgot-password", &json!({ "email": user.email }))
        .await;
    let token = app
        .mail
        .wait_for(&user.email, RESET_SUBJECT)
        .await
        .value_after("token=")
        .unwrap();
    let res = app
        .post(
            "/auth/reset-password",
            &json!({ "token": token, "new_password": "Brand-New-Pass-805!" }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200);
    assert_eq!(login(&app, &user.email, "Brand-New-Pass-805!").await.0, 200);
}

#[tokio::test]
async fn someone_asking_for_links_neither_spends_nor_revokes_the_owners() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 806).await;
    let resets = |app: &TestApp| {
        app.mail
            .messages_to(&user.email)
            .into_iter()
            .filter(|mail| mail.subject == RESET_SUBJECT)
            .count()
    };

    app.post("/auth/forgot-password", &json!({ "email": user.email }))
        .await;
    let owners = app
        .mail
        .wait_for(&user.email, RESET_SUBJECT)
        .await
        .value_after("token=")
        .unwrap();

    // Someone else asks from their own address until their share is spent.
    // Unique per run: address budgets live in the shared Redis.
    let b = uuid::Uuid::new_v4().into_bytes();
    let other = format!("10.{}.{}.{}", 200 + b[0] % 50, b[1], 1 + b[2] % 254);
    for _ in 0..4 {
        let res = post_from(
            &app,
            &other,
            "/auth/forgot-password",
            &json!({ "email": user.email }),
        )
        .await;
        assert_eq!(res.status().as_u16(), 200);
    }
    app.mail.wait_for_count(&user.email, 4).await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(resets(&app), 4, "3 for the other address, 1 for the owner");

    // The owner still gets a link from their address, and the first still works.
    app.post("/auth/forgot-password", &json!({ "email": user.email }))
        .await;
    app.mail.wait_for_count(&user.email, 5).await;
    let res = app
        .post(
            "/auth/reset-password",
            &json!({ "token": owners, "new_password": "Owner-Choice-806!" }),
        )
        .await;
    assert_eq!(
        res.status().as_u16(),
        200,
        "the owner's first link survived"
    );
}

/// Attempts sent at once are reserved one by one before the hash is computed:
/// a burst cannot slip past the budget of an identifier (SEC-67).
#[tokio::test]
async fn a_burst_of_guesses_cannot_outrun_the_budget() {
    let app = TestApp::spawn_with_config(|c| c.security.lockout_threshold = 50).await;
    let user = fixtures::authenticated_user(&app, 807).await;

    let attempts = (0..16).map(|_| login(&app, &user.email, WRONG));
    let statuses: Vec<u16> = futures::future::join_all(attempts)
        .await
        .into_iter()
        .map(|(status, _)| status)
        .collect();
    let evaluated = statuses.iter().filter(|s| **s == 401).count();
    assert!(
        evaluated <= 10,
        "{evaluated} guesses evaluated: {statuses:?}"
    );
    assert!(
        statuses.iter().filter(|s| **s == 429).count() >= 6,
        "{statuses:?}"
    );
}
