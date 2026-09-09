//! Second-factor hardening: regression tests for the audit findings.
//!
//! - a TOTP challenge cannot be completed with an email code;
//! - attempt budgets hold under concurrency and span fresh pre-auth tokens;
//! - second-factor failures are recorded like password failures;
//! - expired recovery codes are refused at login;
//! - email OTP lookups are scoped to the challenged user.

use deadpool_redis::redis::AsyncCommands;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::common::{
    app::TestApp,
    fixtures::{self, AuthenticatedUser},
};

fn totp_code(base32_secret: &str, step_offset: i64) -> String {
    use totp_rs::{Algorithm, Secret, TOTP};
    let bytes = Secret::Encoded(base32_secret.to_owned())
        .to_bytes()
        .unwrap();
    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, bytes).unwrap();
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
    totp.generate(now.saturating_add_signed(step_offset * 30))
}

/// A 6-digit code that is not valid anywhere in the accepted window.
fn wrong_totp_code(base32_secret: &str) -> String {
    let valid: Vec<String> = (-2..=2).map(|o| totp_code(base32_secret, o)).collect();
    (0..1_000_000)
        .map(|n| format!("{n:06}"))
        .find(|c| !valid.contains(c))
        .unwrap()
}

/// Enable TOTP on the user's account. Returns (base32 secret, recovery codes).
async fn enable_totp(app: &TestApp, user: &AuthenticatedUser) -> (String, Vec<String>) {
    let res = app
        .post_auth(
            "/users/me/two-factor/totp/setup",
            &user.access_token,
            &json!({ "current_password": user.password }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200, "totp setup failed");
    let body: Value = res.json().await.unwrap();
    let method_id = body["method_id"].as_str().unwrap().to_owned();
    let secret = body["base32_secret"].as_str().unwrap().to_owned();

    let res = app
        .post_auth(
            &format!("/users/me/two-factor/totp/{method_id}/verify"),
            &user.access_token,
            &json!({ "code": totp_code(&secret, 0) }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200, "totp verify failed");
    let body: Value = res.json().await.unwrap();
    let codes = body["recovery_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_owned())
        .collect();
    (secret, codes)
}

async fn login_challenge(app: &TestApp, user: &AuthenticatedUser) -> Value {
    let res = app
        .post(
            "/auth/login",
            &json!({ "identifier": user.email, "password": user.password }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200, "login failed");
    let body: Value = res.json().await.unwrap();
    assert_eq!(
        body["two_factor_required"], true,
        "expected a challenge: {body}"
    );
    body
}

#[tokio::test]
async fn totp_challenge_cannot_be_completed_with_an_email_code() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 600).await;
    enable_totp(&app, &user).await;

    let challenge = login_challenge(&app, &user).await;
    assert_eq!(challenge["two_factor_method"], "totp");
    let pre_auth = challenge["pre_auth_token"].as_str().unwrap();

    let resend = app
        .post(
            "/auth/two-factor/email/resend",
            &json!({ "pre_auth_token": pre_auth }),
        )
        .await;
    assert_eq!(resend.status().as_u16(), 401, "resend must be refused");

    let sent: i64 = sqlx::query_scalar("SELECT count(*) FROM email_2fa_codes WHERE user_id = $1")
        .bind(user.id)
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(sent, 0, "no email code may be issued for a TOTP challenge");

    let complete = app
        .post(
            "/auth/two-factor/email/complete",
            &json!({ "pre_auth_token": pre_auth, "code": "123456" }),
        )
        .await;
    assert_eq!(complete.status().as_u16(), 401);
}

#[tokio::test]
async fn concurrent_totp_guesses_never_exceed_the_token_budget() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 601).await;
    let (secret, _) = enable_totp(&app, &user).await;
    let wrong = wrong_totp_code(&secret);
    let challenge = login_challenge(&app, &user).await;
    let pre_auth = challenge["pre_auth_token"].as_str().unwrap().to_owned();

    let guesses = (0..20).map(|_| {
        let client = app.client.clone();
        let url = format!("{}/auth/two-factor/complete", app.base_url);
        let body = json!({ "pre_auth_token": pre_auth, "code": wrong });
        tokio::spawn(async move {
            client
                .post(url)
                .json(&body)
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        })
    });

    let mut evaluated = 0;
    for guess in guesses {
        if guess.await.unwrap() == 401 {
            evaluated += 1;
        }
    }
    assert!(
        evaluated <= 5,
        "{evaluated} guesses were evaluated, budget is 5"
    );
}

#[tokio::test]
async fn account_budget_blocks_fresh_pre_auth_tokens() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 602).await;
    let (secret, _) = enable_totp(&app, &user).await;

    // Simulate an exhausted per-account budget (20 failures this hour).
    let mut conn = app.redis.get().await.unwrap();
    let _: () = conn
        .set_ex(format!("totp_user_fail:{}", user.id), 20, 3600)
        .await
        .unwrap();

    let challenge = login_challenge(&app, &user).await;
    let res = app
        .post(
            "/auth/two-factor/complete",
            &json!({
                "pre_auth_token": challenge["pre_auth_token"],
                "code": totp_code(&secret, 0),
            }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 429, "even a correct code is refused");
}

#[tokio::test]
async fn second_factor_failures_are_recorded_and_counted_per_account() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 603).await;
    let (secret, _) = enable_totp(&app, &user).await;
    let challenge = login_challenge(&app, &user).await;

    let res = app
        .post(
            "/auth/two-factor/complete",
            &json!({
                "pre_auth_token": challenge["pre_auth_token"],
                "code": wrong_totp_code(&secret),
            }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 401);

    let recorded: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM login_attempts
         WHERE user_id = $1 AND failure_reason = 'two_factor_failed'",
    )
    .bind(user.id)
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert_eq!(recorded, 1);

    let mut conn = app.redis.get().await.unwrap();
    let account_failures: i64 = conn
        .get(format!("totp_user_fail:{}", user.id))
        .await
        .unwrap();
    assert_eq!(account_failures, 1);
}

#[tokio::test]
async fn expired_recovery_code_is_refused_at_login() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 604).await;
    let (_, codes) = enable_totp(&app, &user).await;

    sqlx::query(
        "UPDATE recovery_codes
         SET created_at = NOW() - INTERVAL '2 days', expires_at = NOW() - INTERVAL '1 day'
         WHERE user_id = $1",
    )
    .bind(user.id)
    .execute(&app.db)
    .await
    .unwrap();

    let challenge = login_challenge(&app, &user).await;
    let res = app
        .post(
            "/auth/two-factor/recovery",
            &json!({
                "pre_auth_token": challenge["pre_auth_token"],
                "recovery_code": codes[0],
            }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 401);
}

#[tokio::test]
async fn email_code_lookup_is_scoped_to_the_challenged_user() {
    let app = TestApp::spawn().await;
    let alice = fixtures::authenticated_user(&app, 605).await;
    let bob = fixtures::authenticated_user(&app, 606).await;
    let known_hash = Sha256::digest(b"123456").to_vec();

    // Enable email 2FA for Alice with a code we control.
    let res = app
        .post_auth(
            "/users/me/two-factor/email/setup",
            &alice.access_token,
            &json!({ "current_password": alice.password }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200);
    let method_id = res.json::<Value>().await.unwrap()["method_id"]
        .as_str()
        .unwrap()
        .to_owned();
    set_active_email_code(&app, alice.id, &known_hash).await;
    let res = app
        .post_auth(
            &format!("/users/me/two-factor/email/{method_id}/verify"),
            &alice.access_token,
            &json!({ "code": "123456" }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200);
    app.clear_email_2fa_cooldown(alice.id).await;

    let challenge = login_challenge(&app, &alice).await;
    set_active_email_code(&app, alice.id, &known_hash).await;

    // Bob holds a live code with the same digits, issued earlier.
    sqlx::query(
        "INSERT INTO email_2fa_codes (user_id, code_hash, created_at, expires_at)
         VALUES ($1, $2, NOW() - INTERVAL '1 minute', NOW() + INTERVAL '5 minutes')",
    )
    .bind(bob.id)
    .bind(&known_hash)
    .execute(&app.db)
    .await
    .unwrap();

    let res = app
        .post(
            "/auth/two-factor/email/complete",
            &json!({ "pre_auth_token": challenge["pre_auth_token"], "code": "123456" }),
        )
        .await;
    assert_eq!(
        res.status().as_u16(),
        200,
        "Alice's own code must be accepted"
    );
}

async fn set_active_email_code(app: &TestApp, user_id: uuid::Uuid, hash: &[u8]) {
    sqlx::query("UPDATE email_2fa_codes SET code_hash = $2 WHERE user_id = $1 AND used_at IS NULL")
        .bind(user_id)
        .bind(hash)
        .execute(&app.db)
        .await
        .unwrap();
}

#[tokio::test]
async fn second_factor_failures_do_not_lock_the_account() {
    // The test config locks after 3 consecutive failures.
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 607).await;
    let (secret, _) = enable_totp(&app, &user).await;
    let wrong = wrong_totp_code(&secret);

    let challenge = login_challenge(&app, &user).await;
    for _ in 0..3 {
        let res = app
            .post(
                "/auth/two-factor/complete",
                &json!({ "pre_auth_token": challenge["pre_auth_token"], "code": wrong }),
            )
            .await;
        assert_eq!(res.status().as_u16(), 401);
    }

    let locked: bool = sqlx::query_scalar(
        "SELECT locked_until IS NOT NULL AND locked_until > NOW() FROM users WHERE id = $1",
    )
    .bind(user.id)
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert!(!locked, "failed second factors must not lock the account");

    let next = login_challenge(&app, &user).await;
    let res = app
        .post(
            "/auth/two-factor/complete",
            // The step-0 code confirmed the method and is spent.
            &json!({ "pre_auth_token": next["pre_auth_token"], "code": totp_code(&secret, 1) }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200);
}

#[tokio::test]
async fn a_pre_auth_state_without_a_method_cannot_complete_with_a_recovery_code() {
    use deadpool_redis::redis::AsyncCommands;

    let app = crate::common::app::TestApp::spawn().await;
    let user = crate::common::fixtures::register_user(&app, 1).await;
    crate::common::fixtures::activate_user(&app.db, user.id).await;
    let code = "LEGACY-RECOVERY-CODE";
    let hash = auth_api::utils::crypto::sha256(code.as_bytes());
    auth_api::repositories::recovery_code::replace_all_by_user(
        &app.db,
        user.id,
        &[(1, hash.as_slice())],
        None,
    )
    .await
    .unwrap();

    // The format written before challenges named their method: a bare user id.
    let token = "legacy-pre-auth-token";
    let mut conn = app.redis.get().await.unwrap();
    let _: () = conn
        .set_ex(format!("pre_auth:{token}"), user.id.to_string(), 300)
        .await
        .unwrap();

    let res = app
        .post(
            "/auth/two-factor/recovery",
            &serde_json::json!({ "pre_auth_token": token, "recovery_code": code }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 401);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["code"], "token_invalid");
}

/// Start enabling TOTP. Returns (method id, base32 secret).
async fn start_totp_setup(app: &TestApp, user: &AuthenticatedUser) -> (String, String) {
    let res = app
        .post_auth(
            "/users/me/two-factor/totp/setup",
            &user.access_token,
            &json!({ "current_password": user.password }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200, "totp setup failed");
    let body: Value = res.json().await.unwrap();
    (
        body["method_id"].as_str().unwrap().to_owned(),
        body["base32_secret"].as_str().unwrap().to_owned(),
    )
}

async fn confirm_totp(app: &TestApp, user: &AuthenticatedUser, method_id: &str, code: &str) -> u16 {
    app.post_auth(
        &format!("/users/me/two-factor/totp/{method_id}/verify"),
        &user.access_token,
        &json!({ "code": code }),
    )
    .await
    .status()
    .as_u16()
}

#[tokio::test]
async fn a_code_confirming_a_new_method_cannot_complete_a_sign_in() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 610).await;
    let (method_id, secret) = start_totp_setup(&app, &user).await;
    let code = totp_code(&secret, 0);
    assert_eq!(confirm_totp(&app, &user, &method_id, &code).await, 200);

    let challenge = login_challenge(&app, &user).await;
    let res = app
        .post(
            "/auth/two-factor/complete",
            &json!({ "pre_auth_token": challenge["pre_auth_token"], "code": code }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 401, "the setup code was replayed");
}

#[tokio::test]
async fn confirming_a_new_method_has_an_attempt_budget() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 611).await;
    let (method_id, secret) = start_totp_setup(&app, &user).await;

    let wrong = wrong_totp_code(&secret);
    for attempt in 1..=5 {
        assert_eq!(
            confirm_totp(&app, &user, &method_id, &wrong).await,
            401,
            "attempt {attempt}"
        );
    }
    assert_eq!(
        confirm_totp(&app, &user, &method_id, &totp_code(&secret, 0)).await,
        429,
        "the budget is spent, even for the right code"
    );
}

#[tokio::test]
async fn recovery_code_guesses_share_one_budget_across_routes() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 612).await;
    let (_, recovery_codes) = enable_totp(&app, &user).await;

    for attempt in 1..=10 {
        let res = app
            .post_auth(
                "/users/me/two-factor/recovery-codes/use",
                &user.access_token,
                &json!({ "code": "XXXX-XXXX-XXXX-XXXX" }),
            )
            .await;
        assert_eq!(res.status().as_u16(), 401, "attempt {attempt}");
    }

    let challenge = login_challenge(&app, &user).await;
    let res = app
        .post(
            "/auth/two-factor/recovery",
            &json!({
                "pre_auth_token": challenge["pre_auth_token"],
                "recovery_code": recovery_codes[0],
            }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 429);
}

#[tokio::test]
async fn a_second_factor_answers_an_inactive_account_like_the_password_sign_in() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 613).await;
    let (secret, _) = enable_totp(&app, &user).await;
    let challenge = login_challenge(&app, &user).await;

    sqlx::query("UPDATE users SET status = 'inactive' WHERE id = $1")
        .bind(user.id)
        .execute(&app.db)
        .await
        .unwrap();

    let res = app
        .post(
            "/auth/two-factor/complete",
            &json!({
                "pre_auth_token": challenge["pre_auth_token"],
                "code": totp_code(&secret, 1),
            }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 403);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["code"], "account_inactive");
}
