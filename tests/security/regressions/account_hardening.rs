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
async fn resending_the_verification_looks_the_same_for_every_address() {
    let app = TestApp::spawn().await;
    let pending = fixtures::register_user(&app, 645).await;
    let active = fixtures::register_user(&app, 646).await;
    fixtures::activate_user(&app.db, active.id).await;

    let mut answers = Vec::new();
    for email in [
        pending.email.as_str(),
        active.email.as_str(),
        "nobody645@example.com",
    ] {
        let started = Instant::now();
        let res = app
            .post("/auth/verify-email/resend", &json!({ "email": email }))
            .await;
        assert!(
            started.elapsed() >= Duration::from_millis(240),
            "{email} answered in {:?}",
            started.elapsed()
        );
        answers.push((res.status().as_u16(), res.text().await.unwrap()));
    }
    assert!(
        answers.windows(2).all(|pair| pair[0] == pair[1]),
        "answers differ: {answers:?}"
    );
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
            .post(
                "/auth/verify-email",
                &json!({ "token": token, "password": "Any-Password-1!" }),
            )
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

/// Registering an active address again and again does not flood its owner:
/// the "someone tried to register" notice is budgeted per account.
#[tokio::test]
async fn registering_a_taken_address_repeatedly_notifies_its_owner_a_few_times() {
    let app = TestApp::spawn().await;
    let owner = fixtures::register_user(&app, 660).await;
    fixtures::activate_user(&app.db, owner.id).await;

    for attempt in 0..6 {
        let res = app
            .post(
                "/auth/register",
                &json!({
                    "username": format!("flooder_{attempt}"),
                    "email": owner.email,
                    "password": "Password660!ok",
                }),
            )
            .await;
        assert_eq!(res.status().as_u16(), 202);
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let notices = app
        .mail
        .messages_to(&owner.email)
        .into_iter()
        .filter(|mail| mail.subject != "Verify your email address")
        .count();
    assert_eq!(notices, 3);
}

/// A reset link or sign-in link mailed before a password change stops working:
/// it would otherwise bypass the change.
#[tokio::test]
async fn a_password_change_ends_the_links_already_mailed() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 661).await;
    let token = fixtures::create_password_reset_token(&app.db, user.id).await;

    let res = app
        .patch_auth(
            "/users/me/password",
            &user.access_token,
            &json!({
                "current_password": user.password,
                "new_password": "Changed-Pass-661!",
            }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 204);

    let res = app
        .post(
            "/auth/reset-password",
            &json!({ "token": token.raw, "new_password": "Attacker-Pass-661!" }),
        )
        .await;
    assert_eq!(
        res.status().as_u16(),
        401,
        "the old reset link still worked"
    );
}

/// Registration takes the same minimum time whether the address is new or
/// taken: the work differs, the response time must not.
#[tokio::test]
async fn registration_takes_a_constant_minimum_time() {
    let app = TestApp::spawn().await;
    let owner = fixtures::register_user(&app, 662).await;
    fixtures::activate_user(&app.db, owner.id).await;

    for email in [owner.email.clone(), "fresh662@example.com".to_owned()] {
        let started = Instant::now();
        let res = app
            .post(
                "/auth/register",
                &json!({ "username": "timing_662", "email": email, "password": "Password662!ok" }),
            )
            .await;
        assert_eq!(res.status().as_u16(), 202);
        assert!(started.elapsed() >= Duration::from_millis(250), "{email}");
    }
}

/// Usernames are unique whatever their case: `Alice` cannot impersonate
/// `alice`, and a sign-in finds the account whatever the case typed.
#[tokio::test]
async fn usernames_differing_only_in_case_cannot_coexist() {
    let app = TestApp::spawn().await;
    let alice = fixtures::register_user(&app, 670).await;
    fixtures::activate_user(&app.db, alice.id).await;

    let res = app
        .post(
            "/auth/register",
            &json!({
                "username": alice.username.to_uppercase(),
                "email": "impostor670@example.com",
                "password": "Password670!ok",
            }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 409);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["code"], "username_taken");

    let res = app
        .post(
            "/auth/login",
            &json!({ "identifier": alice.username.to_uppercase(), "password": alice.password }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200);
}

/// Something typed in the identifier field that is neither an address nor a
/// username (a password typed there by mistake) is not kept.
#[tokio::test]
async fn an_unrecognized_identifier_is_not_recorded() {
    let app = TestApp::spawn().await;
    let res = app
        .post(
            "/auth/login",
            &json!({ "identifier": "My Secret Pa$$word!", "password": "whatever" }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 401);
    let recorded: Vec<String> =
        sqlx::query_scalar("SELECT attempted_identifier::text FROM login_attempts")
            .fetch_all(&app.db)
            .await
            .unwrap();
    assert!(
        !recorded.iter().any(|value| value.contains("Secret")),
        "{recorded:?}"
    );
    assert!(recorded.iter().any(|value| value == "<unrecognized>"));
}
