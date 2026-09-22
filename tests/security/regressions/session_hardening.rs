//! Session and account lifecycle hardening: regression tests for the audit.
//!
//! - the absolute session lifetime counts from the first sign-in, not from the
//!   latest rotation;
//! - two concurrent refreshes from one client no longer log the user out;
//! - an email change neither reactivates an account nor writes addresses into
//!   the audit log;
//! - account deletion leaves no identity in the audit log.

use serde_json::{Value, json};

use crate::common::{app::TestApp, fixtures};

async fn refresh(app: &TestApp, refresh_token: &str) -> reqwest::Response {
    app.post("/auth/refresh", &json!({ "refresh_token": refresh_token }))
        .await
}

#[tokio::test]
async fn session_lifetime_counts_from_the_first_sign_in() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 660).await;

    // A family signed in 91 days ago, whose current row was created just now by
    // a rotation: the default absolute lifetime is 90 days.
    sqlx::query(
        "UPDATE sessions SET family_created_at = NOW() - INTERVAL '91 days' WHERE user_id = $1",
    )
    .bind(user.id)
    .execute(&app.db)
    .await
    .unwrap();

    let res = refresh(&app, &user.refresh_token).await;
    assert_eq!(res.status().as_u16(), 401);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["code"], "token_expired");
}

#[tokio::test]
async fn a_rotation_inherits_the_family_start() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 661).await;

    let res = refresh(&app, &user.refresh_token).await;
    assert_eq!(res.status().as_u16(), 200);

    let starts: Vec<time::OffsetDateTime> =
        sqlx::query_scalar("SELECT DISTINCT family_created_at FROM sessions WHERE user_id = $1")
            .bind(user.id)
            .fetch_all(&app.db)
            .await
            .unwrap();
    assert_eq!(starts.len(), 1, "both rows must share the family start");
}

#[tokio::test]
async fn concurrent_refreshes_keep_the_family_alive() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 662).await;

    let (a, b) = tokio::join!(
        refresh(&app, &user.refresh_token),
        refresh(&app, &user.refresh_token)
    );
    let responses = [a, b];
    let winner = responses
        .into_iter()
        .find(|r| r.status().as_u16() == 200)
        .expect("one refresh must succeed");
    let body: Value = winner.json().await.unwrap();

    let next = refresh(&app, body["refresh_token"].as_str().unwrap()).await;
    assert_eq!(
        next.status().as_u16(),
        200,
        "the winning token must still work: the family was not revoked"
    );
}

async fn change_email(app: &TestApp, token: &str, new_email: &str) {
    let res = app
        .post_auth("/users/me/email/start", token, &json!({}))
        .await;
    assert_eq!(res.status().as_u16(), 200);
    let flow_token = res.json::<Value>().await.unwrap()["flow_token"]
        .as_str()
        .unwrap()
        .to_owned();

    let otp = app.read_email_change_otp(&flow_token).await;
    let res = app
        .post_auth(
            "/users/me/email/verify-current",
            token,
            &json!({ "flow_token": flow_token, "code": otp }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 204);

    let res = app
        .post_auth(
            "/users/me/email/submit",
            token,
            &json!({ "flow_token": flow_token, "new_email": new_email }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 204);

    let otp = app.read_email_change_otp(&flow_token).await;
    let res = app
        .post_auth(
            "/users/me/email/confirm",
            token,
            &json!({ "flow_token": flow_token, "code": otp }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 204);
}

#[tokio::test]
async fn an_email_change_keeps_the_status_and_audits_no_address() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 663).await;

    sqlx::query("UPDATE users SET status = 'inactive' WHERE id = $1")
        .bind(user.id)
        .execute(&app.db)
        .await
        .unwrap();

    // Unique per run: new addresses are budgeted globally, per target.
    let new_email = fixtures::unique("moved663_") + "@example.com";
    change_email(&app, &user.access_token, &new_email).await;

    let status: String = sqlx::query_scalar("SELECT status::text FROM users WHERE id = $1")
        .bind(user.id)
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(
        status, "inactive",
        "confirming an address must not reactivate"
    );

    let leaking: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE user_id = $1 AND metadata::text LIKE '%@%'",
    )
    .bind(user.id)
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert_eq!(
        leaking, 0,
        "audit metadata must not contain email addresses"
    );
}

#[tokio::test]
async fn verifying_an_email_does_not_reactivate_a_suspended_account() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 664).await;

    sqlx::query("UPDATE users SET status = 'suspended' WHERE id = $1")
        .bind(user.id)
        .execute(&app.db)
        .await
        .unwrap();

    auth_api::repositories::user::mark_email_verified(&app.db, user.id)
        .await
        .unwrap();

    let status: String = sqlx::query_scalar("SELECT status::text FROM users WHERE id = $1")
        .bind(user.id)
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(status, "suspended");
}

#[tokio::test]
async fn account_deletion_leaves_no_identity_in_the_audit_log() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 665).await;

    let res = app
        .delete_auth_json("/users/me", &user.access_token, &json!({}))
        .await;
    assert_eq!(res.status().as_u16(), 204);

    let rows: Vec<Value> =
        sqlx::query_scalar("SELECT metadata FROM audit_log WHERE action = 'account_deleted'")
            .fetch_all(&app.db)
            .await
            .unwrap();
    assert_eq!(rows.len(), 1);
    let text = rows[0].to_string();
    assert!(
        !text.contains(&user.email) && !text.contains(&user.username),
        "deletion audit leaks identity: {text}"
    );
}

#[tokio::test]
async fn a_deleted_account_leaves_no_address_or_sign_in_attempt_behind() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 666).await;
    // A failed attempt typed before the account existed carries no account id.
    sqlx::query(
        "INSERT INTO login_attempts (attempted_identifier, was_successful, failure_reason, request_ip)
         VALUES ($1, FALSE, 'unknown_identifier', '10.6.6.6')",
    )
    .bind(&user.email)
    .execute(&app.db)
    .await
    .unwrap();

    let res = app
        .delete_auth_json("/users/me", &user.access_token, &json!({}))
        .await;
    assert_eq!(res.status().as_u16(), 204);

    let attempts: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM login_attempts WHERE user_id = $1 OR attempted_identifier IN ($2, $3)",
    )
    .bind(user.id)
    .bind(&user.email)
    .bind(&user.username)
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert_eq!(attempts, 0, "sign-in attempts outlive the account");

    let addresses: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE user_id IS NULL AND ip_address IS NOT NULL
         AND action IN ('login', 'account_deleted', 'register')",
    )
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert_eq!(
        addresses, 0,
        "audit entries of the account keep its addresses"
    );
}

/// A stolen session guessing the password locks itself out, not the owner:
/// the owner's own session still re-authenticates and revokes it.
#[tokio::test]
async fn a_stolen_session_guessing_the_password_does_not_lock_the_owner_out() {
    let app = TestApp::spawn().await;
    let owner = fixtures::authenticated_user(&app, 700).await;
    let stolen: Value = app
        .post(
            "/auth/login",
            &json!({ "identifier": owner.email, "password": owner.password }),
        )
        .await
        .json()
        .await
        .unwrap();
    let stolen_token = stolen["access_token"].as_str().unwrap();
    let stolen_sid = app.decode_access_token(stolen_token).sid;

    // The test configuration locks after 3 failures.
    for _ in 0..3 {
        app.post_auth(
            "/users/me/reauth",
            stolen_token,
            &json!({ "current_password": "Guess-Guess-1!" }),
        )
        .await;
    }
    let res = app
        .post_auth(
            "/users/me/reauth",
            stolen_token,
            &json!({ "current_password": owner.password }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 403, "the stolen session is locked");

    let res = app
        .delete_auth_json(
            &format!("/users/me/sessions/{stolen_sid}"),
            &owner.access_token,
            &json!({ "current_password": owner.password }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 204, "the owner still acts");
    assert_eq!(app.get_auth("/users/me", stolen_token).await.status(), 401);
}

/// Wrong recovery codes sent through the authenticated route spend a budget of
/// their own: a stolen token cannot exhaust the sign-in budget of the owner.
#[tokio::test]
async fn the_authenticated_recovery_route_spends_its_own_budget() {
    use deadpool_redis::redis::AsyncCommands;

    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 701).await;
    for _ in 0..5 {
        let res = app
            .post_auth(
                "/users/me/two-factor/recovery-codes/use",
                &user.access_token,
                &json!({ "code": "AAAA-BBBB-CCCC-DDDD-EEEE" }),
            )
            .await;
        assert_eq!(res.status().as_u16(), 401);
    }
    let res = app
        .post_auth(
            "/users/me/two-factor/recovery-codes/use",
            &user.access_token,
            &json!({ "code": "AAAA-BBBB-CCCC-DDDD-EEEE" }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 429);

    let mut conn = app.redis.get().await.unwrap();
    let sign_in_budget: Option<i64> = conn.get(format!("rc_user_fail:{}", user.id)).await.unwrap();
    assert_eq!(sign_in_budget, None, "the sign-in budget is untouched");
}

/// A replayed refresh token revokes its family, and the access tokens of that
/// family stop working at once, not when the validity cache expires.
#[tokio::test]
async fn a_revoked_family_loses_its_cached_validity_at_once() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 720).await;

    let rotated: Value = refresh(&app, &user.refresh_token)
        .await
        .json()
        .await
        .unwrap();
    let access = rotated["access_token"].as_str().unwrap();
    // Cached as active by this request.
    assert_eq!(app.get_auth("/users/me", access).await.status(), 200);

    // Past the grace window, the first token comes back: a replay.
    app.clock.advance(time::Duration::seconds(5));
    assert_eq!(refresh(&app, &user.refresh_token).await.status(), 401);
    assert_eq!(
        app.get_auth("/users/me", access).await.status(),
        401,
        "the family's access token still worked from the cache"
    );
}

/// Replayed and foreign refresh tokens count against the address, like
/// unknown ones.
#[tokio::test]
async fn replayed_refresh_tokens_count_against_the_address() {
    use deadpool_redis::redis::AsyncCommands;

    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 721).await;
    refresh(&app, &user.refresh_token).await;
    app.clock.advance(time::Duration::seconds(5));
    refresh(&app, &user.refresh_token).await;

    let mut conn = app.redis.get().await.unwrap();
    let failures: Option<i64> = conn
        .get(format!("refresh_fail:{}", app.client_ip))
        .await
        .unwrap();
    assert_eq!(failures, Some(1));
}

/// Within the grace window, only the client that rotated the session may
/// present the old token again; anyone else is a replay (SEC-61).
#[tokio::test]
async fn a_rotated_token_reused_from_another_client_revokes_the_family() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 722).await;
    let rotated: Value = refresh(&app, &user.refresh_token)
        .await
        .json()
        .await
        .unwrap();

    let b = uuid::Uuid::new_v4().into_bytes();
    let elsewhere = format!("10.{}.{}.{}", 150 + b[0] % 50, b[1], 1 + b[2] % 254);
    let res = app
        .client
        .post(app.url("/auth/refresh"))
        .header("x-forwarded-for", &elsewhere)
        .header("user-agent", "another-client/1.0")
        .json(&json!({ "refresh_token": user.refresh_token }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 401);

    let next = refresh(&app, rotated["refresh_token"].as_str().unwrap()).await;
    assert_eq!(next.status().as_u16(), 401, "the family must be revoked");
}

/// Registrations from one address are budgeted per hour (SEC-61).
#[tokio::test]
async fn registrations_from_one_address_are_budgeted() {
    let app = TestApp::spawn_with_config(|config| {
        config.security.registrations_per_ip_per_hour = 2;
    })
    .await;
    let b = uuid::Uuid::new_v4().into_bytes();
    let from = format!("10.{}.{}.{}", 100 + b[0] % 50, b[1], 1 + b[2] % 254);
    let mut statuses = Vec::new();
    for n in 0..3 {
        let res = app
            .client
            .post(app.url("/auth/register"))
            .header("x-forwarded-for", &from)
            .json(&json!({
                "username": format!("squat{n}_{}", b[3]),
                "email": format!("squat{n}_{}@example.com", uuid::Uuid::new_v4().simple()),
                "password": "Squatting-Pass-1!",
            }))
            .send()
            .await
            .unwrap();
        statuses.push(res.status().as_u16());
    }
    assert_eq!(statuses, [202, 202, 429]);
}
