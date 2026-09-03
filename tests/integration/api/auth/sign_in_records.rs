//! What a sign-in leaves behind, and the cleanup sweep.
//!
//! - a successful sign-in stamps the account, the ledger and the audit log
//!   together; its user agent is not kept (the session already describes it);
//! - a failed attempt keeps its user agent for investigation;
//! - one instance sweeps at a time.

use serde_json::json;
use uuid::Uuid;

use crate::common::{app::TestApp, fixtures};

async fn login_with_agent(app: &TestApp, identifier: &str, password: &str) -> u16 {
    app.client
        .post(format!("{}/auth/login", app.base_url))
        .header("user-agent", "SignInRecords/1.0")
        .json(&json!({ "identifier": identifier, "password": password }))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

async fn attempts(app: &TestApp, user_id: Uuid) -> Vec<(bool, Option<String>)> {
    sqlx::query_as(
        "SELECT was_successful, request_user_agent FROM login_attempts
         WHERE user_id = $1 ORDER BY attempted_at",
    )
    .bind(user_id)
    .fetch_all(&app.db)
    .await
    .unwrap()
}

#[tokio::test]
async fn a_successful_sign_in_is_recorded_in_one_go() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 740).await;
    fixtures::activate_user(&app.db, user.id).await;
    // A lock that has run out is cleared by the next successful sign-in.
    sqlx::query("UPDATE users SET locked_until = NOW() - INTERVAL '1 minute' WHERE id = $1")
        .bind(user.id)
        .execute(&app.db)
        .await
        .unwrap();

    assert_eq!(
        login_with_agent(&app, &user.email, "Not-The-Password-1").await,
        401
    );
    assert_eq!(
        login_with_agent(&app, &user.email, &user.password).await,
        200
    );

    assert_eq!(
        attempts(&app, user.id).await,
        vec![(false, Some("SignInRecords/1.0".to_owned())), (true, None),]
    );

    let (last_login_set, lock_cleared): (bool, bool) = sqlx::query_as(
        "SELECT last_login_at IS NOT NULL, locked_until IS NULL FROM users WHERE id = $1",
    )
    .bind(user.id)
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert!(last_login_set && lock_cleared);

    let logins: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE user_id = $1 AND action = 'login'",
    )
    .bind(user.id)
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert_eq!(logins, 1);
}

#[tokio::test]
async fn access_tokens_carry_the_roles_the_user_holds() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 741).await;

    let payload = user.access_token.split('.').nth(1).unwrap();
    let claims: serde_json::Value = serde_json::from_slice(
        &base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(claims["roles"], json!(["user"]));
}

#[tokio::test]
async fn only_one_instance_sweeps_at_a_time() {
    let app = TestApp::spawn().await;

    let mut holder = app.db.acquire().await.unwrap();
    sqlx::query("SELECT pg_advisory_lock(hashtextextended('auth_api_cleanup', 0))")
        .execute(&mut *holder)
        .await
        .unwrap();

    let swept = auth_api::services::cleanup::run_once(&app.db, &app.state.config)
        .await
        .unwrap();
    assert!(
        !swept,
        "a sweep must not start while another instance holds the lock"
    );

    sqlx::query("SELECT pg_advisory_unlock(hashtextextended('auth_api_cleanup', 0))")
        .execute(&mut *holder)
        .await
        .unwrap();

    let swept = auth_api::services::cleanup::run_once(&app.db, &app.state.config)
        .await
        .unwrap();
    assert!(swept);
}
