//! Account-level hardening: regression tests for the audit findings.
//!
//! - a locked account answers the same whatever the password;
//! - registration and forgot-password never reveal whether an address exists;
//! - one-time token submissions tolerate a retry;
//! - client input is validated like the database constrains it.

use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::common::{app::TestApp, fixtures};

#[tokio::test]
async fn locked_account_answers_the_same_whatever_the_password() {
    // The test config locks after 3 consecutive wrong passwords.
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 640).await;
    fixtures::activate_user(&app.db, user.id).await;

    for _ in 0..3 {
        let res = app
            .post(
                "/auth/login",
                &json!({ "identifier": user.email, "password": "Wrong-Pass-000" }),
            )
            .await;
        assert_eq!(res.status().as_u16(), 401);
    }

    for password in [user.password.as_str(), "Wrong-Pass-111"] {
        let res = app
            .post(
                "/auth/login",
                &json!({ "identifier": user.email, "password": password }),
            )
            .await;
        assert_eq!(res.status().as_u16(), 403);
        let body: Value = res.json().await.unwrap();
        assert_eq!(body["code"], "account_locked");
    }
}

#[tokio::test]
async fn registering_a_taken_email_looks_like_a_new_signup() {
    let app = TestApp::spawn().await;
    let first = app
        .post(
            "/auth/register",
            &json!({ "username": "enum_first", "email": "enum@example.com", "password": "Password641!ok" }),
        )
        .await;
    assert_eq!(first.status().as_u16(), 202);
    let first_body: Value = first.json().await.unwrap();

    let second = app
        .post(
            "/auth/register",
            &json!({ "username": "enum_second", "email": "enum@example.com", "password": "Password641!ok" }),
        )
        .await;
    assert_eq!(second.status().as_u16(), 202);
    let second_body: Value = second.json().await.unwrap();
    assert_eq!(first_body, second_body, "responses must be identical");

    let accounts: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE email = $1")
        .bind("enum@example.com")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(accounts, 1);
}

#[tokio::test]
async fn a_taken_username_is_reported_with_its_code() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 642).await;

    let res = app
        .post(
            "/auth/register",
            &json!({ "username": user.username, "email": "other642@example.com", "password": "Password642!ok" }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 409);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["code"], "username_taken");
}

#[tokio::test]
async fn forgot_password_takes_the_same_minimum_time_either_way() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 643).await;
    fixtures::activate_user(&app.db, user.id).await;

    for email in [user.email.as_str(), "nobody643@example.com"] {
        let started = Instant::now();
        let res = app
            .post("/auth/forgot-password", &json!({ "email": email }))
            .await;
        assert_eq!(res.status().as_u16(), 200);
        assert!(
            started.elapsed() >= Duration::from_millis(240),
            "{email} answered in {:?}",
            started.elapsed()
        );
    }
}

#[tokio::test]
async fn forgot_password_is_capped_per_account() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 644).await;
    fixtures::activate_user(&app.db, user.id).await;

    for _ in 0..5 {
        let res = app
            .post("/auth/forgot-password", &json!({ "email": user.email }))
            .await;
        assert_eq!(res.status().as_u16(), 200, "the cap must stay silent");
    }

    let issued: i64 =
        sqlx::query_scalar("SELECT count(*) FROM password_reset_tokens WHERE user_id = $1")
            .bind(user.id)
            .fetch_one(&app.db)
            .await
            .unwrap();
    assert_eq!(issued, 3);
}

#[tokio::test]
async fn a_one_time_token_submission_can_be_retried() {
    let app = TestApp::spawn().await;
    let token = uuid::Uuid::new_v4().to_string();

    for _ in 0..2 {
        let res = app
            .post("/auth/verify-email", &json!({ "token": token }))
            .await;
        assert_eq!(res.status().as_u16(), 401, "a retry is not rate limited");
    }
}

#[tokio::test]
async fn a_non_ascii_username_is_a_validation_error() {
    let app = TestApp::spawn().await;
    let res = app
        .post(
            "/auth/register",
            &json!({ "username": "Jos\u{e9}_645", "email": "jose645@example.com", "password": "Password645!ok" }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 422);
}

#[tokio::test]
async fn an_address_the_database_cannot_store_is_a_validation_error() {
    let app = TestApp::spawn().await;
    let res = app
        .post(
            "/auth/register",
            &json!({ "username": "local646", "email": "user@localhost", "password": "Password646!ok" }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 422);
}

#[tokio::test]
async fn an_overlong_device_name_is_stored_truncated() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 647).await;
    fixtures::activate_user(&app.db, user.id).await;

    let res = app
        .post(
            "/auth/login",
            &json!({ "identifier": user.email, "password": user.password, "device_name": "x".repeat(150) }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200);

    let stored: i32 =
        sqlx::query_scalar("SELECT char_length(device_name) FROM sessions WHERE user_id = $1")
            .bind(user.id)
            .fetch_one(&app.db)
            .await
            .unwrap();
    assert_eq!(stored, 100);
}

#[tokio::test]
async fn overlong_login_input_is_rejected_before_hashing() {
    let app = TestApp::spawn().await;
    let res = app
        .post(
            "/auth/login",
            &json!({ "identifier": "a".repeat(300), "password": "Password648!ok" }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 422);
}

#[tokio::test]
async fn a_wrong_reauthentication_password_has_its_own_code() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 649).await;

    let res = app
        .post_auth(
            "/users/me/reauth",
            &user.access_token,
            &json!({ "current_password": "Wrong-Pass-649" }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 401);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["code"], "reauthentication_failed");
}

#[tokio::test]
async fn rotating_ipv6_addresses_within_a_64_does_not_reset_the_failure_budget() {
    let app = TestApp::spawn().await;
    let attempt = |n: u32| {
        let request = app
            .client
            .post(app.url("/auth/login"))
            .header("x-forwarded-for", format!("2001:db8:77:1::{n:x}"))
            .json(&json!({
                "identifier": format!("nobody{n}@example.com"),
                "password": "Wrong-password1!",
            }));
        async move { request.send().await.unwrap().status().as_u16() }
    };

    // Thirty failures, each from its own address of one /64.
    let statuses = futures::future::join_all((1..=30).map(attempt)).await;
    assert!(statuses.iter().all(|status| *status == 401), "{statuses:?}");

    assert_eq!(
        attempt(31).await,
        429,
        "a fresh address in the same /64 escaped the per-address budget"
    );
}

#[tokio::test]
async fn concurrent_reauthentication_guesses_never_exceed_the_budget() {
    // The test configuration locks after 3 wrong passwords.
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 1).await;
    let wrong = json!({ "current_password": "Wrong-password1!" });
    let guess = || app.post_auth("/users/me/reauth", &user.access_token, &wrong);

    let responses = futures::future::join_all((0..20).map(|_| guess())).await;
    let (mut checked, mut locked) = (0, 0);
    for response in responses {
        let body: Value = response.json().await.unwrap();
        match body["code"].as_str() {
            Some("reauthentication_failed") => checked += 1,
            Some("account_locked") => locked += 1,
            other => panic!("unexpected answer {other:?}"),
        }
    }
    // Two plain failures, then the third locks: never more, however parallel.
    assert_eq!(checked, 2, "{checked} guesses were checked past the budget");
    assert_eq!(locked, 18);
}
