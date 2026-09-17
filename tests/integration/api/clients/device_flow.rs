//! Device authorization (RFC 8628) through `/oauth/device_authorization` and
//! `/oauth/token`.
//!
//! - a flow always runs for an identified, registered client;
//! - an approval is collected once, even under concurrent polls, by that client;
//! - polling is paced, unknown codes are rate limited, decisions are final;
//! - session caps and account status are enforced when tokens are issued;
//! - a device session gets no re-authentication for sensitive actions.

use serde_json::{Value, json};

use super::{claims, form};
use crate::common::{
    app::TestApp,
    fixtures::{self, AuthenticatedUser},
};

async fn register_client(app: &TestApp, client_id: &str, is_primary: bool, max_sessions: i16) {
    sqlx::query(
        "INSERT INTO registered_clients (client_id, display_name, is_primary, default_max_sessions)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(client_id)
    .bind(format!("{client_id} display"))
    .bind(is_primary)
    .bind(max_sessions)
    .execute(&app.db)
    .await
    .unwrap();
}

async fn start(app: &TestApp, parameters: &[(&str, &str)]) -> (u16, Value) {
    form(app, "/oauth/device_authorization", parameters, None).await
}

async fn start_ok(app: &TestApp, client_id: &str) -> (String, String) {
    let (status, body) = start(app, &[("client_id", client_id)]).await;
    assert_eq!(status, 200, "device flow start failed: {body}");
    (
        body["device_code"].as_str().unwrap().to_owned(),
        body["user_code"].as_str().unwrap().to_owned(),
    )
}

async fn approve(app: &TestApp, user: &AuthenticatedUser, user_code: &str) -> u16 {
    app.post_auth(
        "/oauth/device/verify",
        &user.access_token,
        &json!({ "user_code": user_code }),
    )
    .await
    .status()
    .as_u16()
}

async fn poll(app: &TestApp, device_code: &str, client_id: &str) -> (u16, Value) {
    form(
        app,
        "/oauth/token",
        &[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", device_code),
            ("client_id", client_id),
            ("device_name", "Test laptop"),
        ],
        None,
    )
    .await
}

fn error(body: &Value) -> &str {
    body["error"].as_str().unwrap_or_default()
}

#[tokio::test]
async fn a_flow_is_described_to_the_approving_user() {
    let app = TestApp::spawn().await;
    register_client(&app, "primary-app", true, 5).await;
    let user = fixtures::authenticated_user(&app, 700).await;

    let (status, started) = start(&app, &[("client_id", "primary-app")]).await;
    assert_eq!(status, 200);
    let user_code = started["user_code"].as_str().unwrap();
    assert!(
        started["verification_uri_complete"]
            .as_str()
            .unwrap()
            .ends_with(&format!("user_code={user_code}"))
    );
    assert_eq!(started["interval"], 5);

    let preview: Value = app
        .get_auth(&format!("/oauth/device/{user_code}"), &user.access_token)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(preview["client_id"], "primary-app");
    assert_eq!(preview["client_name"], "primary-app display");
    assert!(preview["requested_from_ip"].is_string());
}

#[tokio::test]
async fn a_flow_needs_a_registered_client() {
    let app = TestApp::spawn().await;

    let (status, body) = start(&app, &[]).await;
    assert_eq!((status, error(&body)), (400, "invalid_request"));

    let (status, body) = start(&app, &[("client_id", "unknown-app")]).await;
    assert_eq!((status, error(&body)), (401, "invalid_client"));

    let response = app
        .client
        .post(app.url("/oauth/device_authorization"))
        .json(&json!({ "client_id": "unknown-app" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400, "the body must be form-encoded");
}

#[tokio::test]
async fn a_device_code_works_for_its_client_only() {
    let app = TestApp::spawn().await;
    register_client(&app, "primary-app", true, 5).await;
    register_client(&app, "other-app", false, 5).await;
    let user = fixtures::authenticated_user(&app, 707).await;
    let (device_code, user_code) = start_ok(&app, "primary-app").await;
    assert_eq!(approve(&app, &user, &user_code).await, 200);

    let (status, body) = poll(&app, &device_code, "other-app").await;
    assert_eq!((status, error(&body)), (400, "invalid_grant"));
    let (status, _) = poll(&app, &device_code, "primary-app").await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn a_requested_scope_is_carried_by_the_tokens() {
    let app = TestApp::spawn().await;
    register_client(&app, "primary-app", true, 5).await;
    let user = fixtures::authenticated_user(&app, 708).await;
    let role = auth_api::repositories::role::find_by_name(&app.db, "admin")
        .await
        .unwrap()
        .unwrap();
    auth_api::repositories::role::assign_to_user(&app.db, user.id, role.id, None)
        .await
        .unwrap();

    let (status, body) = start(
        &app,
        &[("client_id", "primary-app"), ("scope", "not:a-permission")],
    )
    .await;
    assert_eq!((status, error(&body)), (400, "invalid_scope"));

    let (_, started) = start(
        &app,
        &[("client_id", "primary-app"), ("scope", "audit:read")],
    )
    .await;
    assert_eq!(
        approve(&app, &user, started["user_code"].as_str().unwrap()).await,
        200
    );
    let (status, tokens) = poll(
        &app,
        started["device_code"].as_str().unwrap(),
        "primary-app",
    )
    .await;
    assert_eq!(status, 200, "{tokens}");
    assert_eq!(tokens["scope"], "audit:read");
    assert_eq!(
        claims(tokens["access_token"].as_str().unwrap())["permissions"],
        json!(["audit:read"])
    );
}

#[tokio::test]
async fn an_approval_is_collected_exactly_once_under_concurrent_polls() {
    let app = TestApp::spawn().await;
    register_client(&app, "primary-app", true, 5).await;
    let user = fixtures::authenticated_user(&app, 701).await;
    let (device_code, user_code) = start_ok(&app, "primary-app").await;
    assert_eq!(approve(&app, &user, &user_code).await, 200);

    let polls = (0..8).map(|_| {
        let client = app.client.clone();
        let url = app.url("/oauth/token");
        let device_code = device_code.clone();
        tokio::spawn(async move {
            client
                .post(url)
                .form(&[
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                    ("device_code", device_code.as_str()),
                    ("client_id", "primary-app"),
                    ("device_name", "Test laptop"),
                ])
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        })
    });
    let mut successes = 0;
    for p in polls {
        if p.await.unwrap() == 200 {
            successes += 1;
        }
    }
    assert_eq!(successes, 1, "tokens must be issued exactly once");

    let (session_type, client_id, device_name): (String, String, String) = sqlx::query_as(
        "SELECT session_type::text, client_id, device_name FROM sessions
         WHERE user_id = $1 AND session_type = 'device'",
    )
    .bind(user.id)
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert_eq!(
        (
            session_type.as_str(),
            client_id.as_str(),
            device_name.as_str()
        ),
        ("device", "primary-app", "Test laptop")
    );
}

#[tokio::test]
async fn polling_faster_than_the_interval_is_slowed_down() {
    let app = TestApp::spawn().await;
    register_client(&app, "primary-app", true, 5).await;
    let (device_code, _) = start_ok(&app, "primary-app").await;

    let (status, body) = poll(&app, &device_code, "primary-app").await;
    assert_eq!((status, error(&body)), (400, "authorization_pending"));
    let (status, body) = poll(&app, &device_code, "primary-app").await;
    assert_eq!((status, error(&body)), (400, "slow_down"));
}

#[tokio::test]
async fn a_non_primary_client_is_capped_without_a_quota_row() {
    let app = TestApp::spawn().await;
    register_client(&app, "partner-app", false, 1).await;
    let user = fixtures::authenticated_user(&app, 702).await;

    for expected in [(200, ""), (400, "invalid_grant")] {
        let (device_code, user_code) = start_ok(&app, "partner-app").await;
        assert_eq!(approve(&app, &user, &user_code).await, 200);
        let (status, body) = poll(&app, &device_code, "partner-app").await;
        assert_eq!(status, expected.0, "{body}");
        if expected.0 != 200 {
            assert_eq!(error(&body), expected.1);
        }
    }
}

#[tokio::test]
async fn unknown_user_codes_are_rate_limited() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 703).await;

    for n in 0..10 {
        let code = format!("ZZZZ-{}", 2222 + n);
        assert_eq!(approve(&app, &user, &code).await, 404);
    }
    assert_eq!(approve(&app, &user, "ZZZZ-9999").await, 429);
}

#[tokio::test]
async fn a_decision_is_final() {
    let app = TestApp::spawn().await;
    register_client(&app, "primary-app", true, 5).await;
    let user = fixtures::authenticated_user(&app, 704).await;
    let (_, user_code) = start_ok(&app, "primary-app").await;

    assert_eq!(approve(&app, &user, &user_code).await, 200);
    assert_eq!(approve(&app, &user, &user_code).await, 409);
}

#[tokio::test]
async fn a_denied_flow_answers_access_denied() {
    let app = TestApp::spawn().await;
    register_client(&app, "primary-app", true, 5).await;
    let user = fixtures::authenticated_user(&app, 709).await;
    let (device_code, user_code) = start_ok(&app, "primary-app").await;
    let response = app
        .post_auth(
            "/oauth/device/verify",
            &user.access_token,
            &json!({ "user_code": user_code, "approve": false }),
        )
        .await;
    assert_eq!(response.status(), 200);

    let (status, body) = poll(&app, &device_code, "primary-app").await;
    assert_eq!((status, error(&body)), (400, "access_denied"));
    let (status, body) = poll(&app, &device_code, "primary-app").await;
    assert_eq!((status, error(&body)), (400, "expired_token"));
}

#[tokio::test]
async fn a_suspended_account_cannot_collect_approved_tokens() {
    let app = TestApp::spawn().await;
    register_client(&app, "primary-app", true, 5).await;
    let user = fixtures::authenticated_user(&app, 705).await;
    let (device_code, user_code) = start_ok(&app, "primary-app").await;
    assert_eq!(approve(&app, &user, &user_code).await, 200);

    sqlx::query("UPDATE users SET status = 'suspended' WHERE id = $1")
        .bind(user.id)
        .execute(&app.db)
        .await
        .unwrap();

    let (status, body) = poll(&app, &device_code, "primary-app").await;
    assert_eq!((status, error(&body)), (400, "invalid_grant"));
}

#[tokio::test]
async fn a_device_session_cannot_change_the_password_without_reauthentication() {
    let app = TestApp::spawn().await;
    register_client(&app, "primary-app", true, 5).await;
    let user = fixtures::authenticated_user(&app, 706).await;
    let (device_code, user_code) = start_ok(&app, "primary-app").await;
    assert_eq!(approve(&app, &user, &user_code).await, 200);

    let (_, tokens) = poll(&app, &device_code, "primary-app").await;
    let res = app
        .patch_auth(
            "/users/me/password",
            tokens["access_token"].as_str().unwrap(),
            &json!({ "new_password": "Device-Owned-77" }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 403);
}

#[tokio::test]
async fn a_live_user_code_is_never_handed_out_twice() {
    let app = TestApp::spawn().await;
    let mut conn = app.redis.get().await.unwrap();
    let taken = format!(
        "TEST-{}",
        2000 + (uuid::Uuid::new_v4().as_u128() % 7000) as u32
    );
    let free = format!(
        "FREE-{}",
        2000 + (uuid::Uuid::new_v4().as_u128() % 7000) as u32
    );

    let first =
        auth_api::services::device::reserve_user_code(&mut conn, "hash-one", 60, || taken.clone())
            .await
            .unwrap();
    assert_eq!(first, taken);

    let mut candidates = vec![free.clone(), taken.clone()];
    let second = auth_api::services::device::reserve_user_code(&mut conn, "hash-two", 60, || {
        candidates.pop().unwrap()
    })
    .await
    .unwrap();
    assert_eq!(
        second, free,
        "a colliding draw must be skipped, not overwritten"
    );

    let still: String =
        deadpool_redis::redis::AsyncCommands::get(&mut *conn, format!("device_uc:{taken}"))
            .await
            .unwrap();
    assert_eq!(still, "hash-one");
}

#[tokio::test]
async fn concurrent_approvals_never_exceed_the_session_limit() {
    let app = TestApp::spawn().await;
    register_client(&app, "partner-app", false, 1).await;
    let user = fixtures::authenticated_user(&app, 720).await;

    let mut device_codes = Vec::new();
    for _ in 0..3 {
        let (device_code, user_code) = start_ok(&app, "partner-app").await;
        assert_eq!(approve(&app, &user, &user_code).await, 200);
        device_codes.push(device_code);
    }

    let polls = device_codes.into_iter().map(|device_code| {
        let client = app.client.clone();
        let url = app.url("/oauth/token");
        tokio::spawn(async move {
            let res = client
                .post(url)
                .form(&[
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                    ("device_code", device_code.as_str()),
                    ("client_id", "partner-app"),
                ])
                .send()
                .await
                .unwrap();
            let status = res.status().as_u16();
            let body: Value = res.json().await.unwrap_or(Value::Null);
            (
                status,
                body["error"].as_str().unwrap_or_default().to_owned(),
            )
        })
    });
    let mut outcomes = Vec::new();
    for poll in polls {
        outcomes.push(poll.await.unwrap());
    }

    let issued = outcomes.iter().filter(|(status, _)| *status == 200).count();
    assert_eq!(issued, 1, "one session for a limit of one: {outcomes:?}");
    assert!(
        outcomes
            .iter()
            .filter(|(status, _)| *status != 200)
            .all(|(status, code)| (*status, code.as_str()) == (400, "invalid_grant")),
        "{outcomes:?}"
    );
    let sessions: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM sessions WHERE user_id = $1 AND client_id = 'partner-app'",
    )
    .bind(user.id)
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert_eq!(sessions, 1);
}
