//! Device authorization flow (RFC 8628): end to end, and the audit findings.
//!
//! - a flow always runs against a registered client (the primary one by default);
//! - an approval is collected once, even under concurrent polls;
//! - polling is paced, unknown codes are rate limited, decisions are final;
//! - session caps and account status are enforced when tokens are issued;
//! - a device session gets no re-authentication for sensitive actions.

use serde_json::{Value, json};

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

async fn start(app: &TestApp, client_id: Option<&str>) -> reqwest::Response {
    let body = match client_id {
        Some(id) => json!({ "client_id": id }),
        None => json!({}),
    };
    app.post("/auth/device", &body).await
}

async fn start_ok(app: &TestApp, client_id: Option<&str>) -> (String, String) {
    let res = start(app, client_id).await;
    assert_eq!(res.status().as_u16(), 200, "device flow start failed");
    let body: Value = res.json().await.unwrap();
    (
        body["device_code"].as_str().unwrap().to_owned(),
        body["user_code"].as_str().unwrap().to_owned(),
    )
}

async fn approve(app: &TestApp, user: &AuthenticatedUser, user_code: &str) -> u16 {
    app.post_auth(
        "/auth/device/verify",
        &user.access_token,
        &json!({ "user_code": user_code }),
    )
    .await
    .status()
    .as_u16()
}

async fn poll(app: &TestApp, device_code: &str) -> reqwest::Response {
    app.post(
        "/auth/device/token",
        &json!({ "device_code": device_code, "device_name": "Test laptop" }),
    )
    .await
}

async fn code_of(res: reqwest::Response) -> (u16, String) {
    let status = res.status().as_u16();
    let body: Value = res.json().await.unwrap_or(Value::Null);
    (status, body["code"].as_str().unwrap_or_default().to_owned())
}

#[tokio::test]
async fn a_flow_without_client_id_runs_against_the_primary_client() {
    let app = TestApp::spawn().await;
    register_client(&app, "primary-app", true, 5).await;
    let user = fixtures::authenticated_user(&app, 700).await;

    let (_, user_code) = start_ok(&app, None).await;

    let preview: Value = app
        .get_auth(&format!("/auth/device/{user_code}"), &user.access_token)
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

    let (status, code) = code_of(start(&app, None).await).await;
    assert_eq!((status, code.as_str()), (400, "device_client_unknown"));

    register_client(&app, "primary-app", true, 5).await;
    let (status, code) = code_of(start(&app, Some("unknown-app")).await).await;
    assert_eq!((status, code.as_str()), (400, "device_client_unknown"));
}

#[tokio::test]
async fn an_approval_is_collected_exactly_once_under_concurrent_polls() {
    let app = TestApp::spawn().await;
    register_client(&app, "primary-app", true, 5).await;
    let user = fixtures::authenticated_user(&app, 701).await;
    let (device_code, user_code) = start_ok(&app, None).await;
    assert_eq!(approve(&app, &user, &user_code).await, 200);

    let polls = (0..8).map(|_| {
        let client = app.client.clone();
        let url = format!("{}/auth/device/token", app.base_url);
        let body = json!({ "device_code": device_code, "device_name": "Test laptop" });
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
    let (device_code, _) = start_ok(&app, None).await;

    let (status, code) = code_of(poll(&app, &device_code).await).await;
    assert_eq!((status, code.as_str()), (400, "authorization_pending"));
    let (status, code) = code_of(poll(&app, &device_code).await).await;
    assert_eq!((status, code.as_str()), (400, "slow_down"));
}

#[tokio::test]
async fn a_non_primary_client_is_capped_without_a_quota_row() {
    let app = TestApp::spawn().await;
    register_client(&app, "partner-app", false, 1).await;
    let user = fixtures::authenticated_user(&app, 702).await;

    for expected in [(200, ""), (403, "device_session_limit_reached")] {
        let (device_code, user_code) = start_ok(&app, Some("partner-app")).await;
        assert_eq!(approve(&app, &user, &user_code).await, 200);
        let (status, code) = code_of(poll(&app, &device_code).await).await;
        assert_eq!(status, expected.0);
        if expected.0 != 200 {
            assert_eq!(code, expected.1);
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
    let (_, user_code) = start_ok(&app, None).await;

    assert_eq!(approve(&app, &user, &user_code).await, 200);
    assert_eq!(approve(&app, &user, &user_code).await, 409);
}

#[tokio::test]
async fn a_suspended_account_cannot_collect_approved_tokens() {
    let app = TestApp::spawn().await;
    register_client(&app, "primary-app", true, 5).await;
    let user = fixtures::authenticated_user(&app, 705).await;
    let (device_code, user_code) = start_ok(&app, None).await;
    assert_eq!(approve(&app, &user, &user_code).await, 200);

    sqlx::query("UPDATE users SET status = 'suspended' WHERE id = $1")
        .bind(user.id)
        .execute(&app.db)
        .await
        .unwrap();

    let (status, code) = code_of(poll(&app, &device_code).await).await;
    assert_eq!((status, code.as_str()), (403, "account_suspended"));
}

#[tokio::test]
async fn a_device_session_cannot_change_the_password_without_reauthentication() {
    let app = TestApp::spawn().await;
    register_client(&app, "primary-app", true, 5).await;
    let user = fixtures::authenticated_user(&app, 706).await;
    let (device_code, user_code) = start_ok(&app, None).await;
    assert_eq!(approve(&app, &user, &user_code).await, 200);

    let tokens: Value = poll(&app, &device_code).await.json().await.unwrap();
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
        deadpool_redis::redis::AsyncCommands::get(&mut conn, format!("device_uc:{taken}"))
            .await
            .unwrap();
    assert_eq!(still, "hash-one");
}
