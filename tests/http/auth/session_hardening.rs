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

    change_email(&app, &user.access_token, "moved663@example.com").await;

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
