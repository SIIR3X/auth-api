//! `/admin/webhooks` and the delivery of signed events.

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU16, Ordering},
    },
    time::Duration,
};

use auth_api::{domain::webhook, services::webhooks};
use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use reqwest::Method;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{admin, body};
use crate::common::{app::TestApp, fixtures};

#[derive(Clone, Default)]
struct Receiver {
    received: Arc<Mutex<Vec<(HeaderMap, Bytes)>>>,
    status: Arc<AtomicU16>,
}

impl Receiver {
    async fn start() -> (Self, String) {
        let receiver = Self::default();
        receiver.status.store(200, Ordering::SeqCst);
        let app = Router::new()
            .route("/hook", post(receive))
            .with_state(receiver.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/hook", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (receiver, url)
    }

    fn count(&self) -> usize {
        self.received.lock().unwrap().len()
    }
}

async fn receive(State(receiver): State<Receiver>, headers: HeaderMap, body: Bytes) -> StatusCode {
    receiver.received.lock().unwrap().push((headers, body));
    StatusCode::from_u16(receiver.status.load(Ordering::SeqCst)).unwrap()
}

async fn send(
    app: &TestApp,
    method: Method,
    path: &str,
    token: &str,
    payload: Value,
) -> (u16, Value) {
    body(
        app.client
            .request(method, app.url(path))
            .bearer_auth(token)
            .json(&payload)
            .send()
            .await
            .unwrap(),
    )
    .await
}

async fn eventually(mut check: impl FnMut() -> bool) {
    for _ in 0..100 {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("condition not reached within 10 seconds");
}

async fn delivery_state(app: &TestApp, token: &str, webhook_id: &str) -> Value {
    let (status, deliveries) = send(
        app,
        Method::GET,
        &format!("/admin/webhooks/{webhook_id}/deliveries"),
        token,
        json!({}),
    )
    .await;
    assert_eq!(status, 200, "{deliveries}");
    deliveries
}

#[tokio::test]
async fn a_subscribed_endpoint_receives_signed_events() {
    let app = TestApp::spawn().await;
    let admin = admin(&app, 1).await;
    let (receiver, url) = Receiver::start().await;
    let (unsubscribed, other_url) = Receiver::start().await;

    let (status, created) = send(
        &app,
        Method::POST,
        "/admin/webhooks",
        &admin.token,
        json!({ "url": url, "events": ["user.created"], "description": "CRM" }),
    )
    .await;
    assert_eq!(status, 201, "{created}");
    let secret = created["secret"].as_str().unwrap().to_owned();
    assert!(secret.starts_with("whsec_"));
    send(
        &app,
        Method::POST,
        "/admin/webhooks",
        &admin.token,
        json!({ "url": other_url, "events": ["user.deleted"] }),
    )
    .await;

    let user = fixtures::register_user(&app, 2).await;
    eventually(|| receiver.count() == 1).await;

    let (headers, bytes) = receiver.received.lock().unwrap()[0].clone();
    let id = headers["webhook-id"].to_str().unwrap();
    let timestamp: i64 = headers["webhook-timestamp"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    let key = webhook::secret_bytes(&secret).unwrap();
    assert_eq!(
        headers["webhook-signature"].to_str().unwrap(),
        webhook::signature(&key, id, timestamp, &bytes)
    );
    let event: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(event["event"], "user.created");
    assert_eq!(event["user_id"], user.id.to_string());
    assert_eq!(event["event_id"], id);

    let webhook_id = created["id"].as_str().unwrap();
    let deliveries = delivery_state(&app, &admin.token, webhook_id).await;
    assert_eq!(deliveries[0]["attempts"], 1);
    assert!(deliveries[0]["delivered_at"].is_number());
    assert_eq!(unsubscribed.count(), 0);
}

#[tokio::test]
async fn a_failing_endpoint_is_retried_given_up_and_redelivered_on_demand() {
    let app = TestApp::spawn().await;
    let admin = admin(&app, 1).await;
    let (receiver, url) = Receiver::start().await;
    receiver.status.store(500, Ordering::SeqCst);
    let (_, created) = send(
        &app,
        Method::POST,
        "/admin/webhooks",
        &admin.token,
        json!({ "url": url, "events": ["*"] }),
    )
    .await;
    let webhook_id = created["id"].as_str().unwrap().to_owned();

    fixtures::register_user(&app, 2).await;
    eventually(|| receiver.count() == 1).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let deliveries = delivery_state(&app, &admin.token, &webhook_id).await;
    assert_eq!(deliveries[0]["last_status"], 500);
    assert_eq!(deliveries[0]["attempts"], 1);
    assert!(deliveries[0]["failed_at"].is_null());
    let delivery_id = deliveries[0]["id"].as_str().unwrap().to_owned();

    // The last attempt fails too: given up.
    sqlx::query(
        "UPDATE webhook_deliveries SET attempts = 11, next_attempt_at = NOW() WHERE id = $1",
    )
    .bind(Uuid::parse_str(&delivery_id).unwrap())
    .execute(&app.db)
    .await
    .unwrap();
    webhooks::deliver_once(&app.state).await.unwrap();
    let deliveries = delivery_state(&app, &admin.token, &webhook_id).await;
    assert_eq!(deliveries[0]["attempts"], 12);
    assert!(deliveries[0]["failed_at"].is_number());
    assert!(deliveries[0].get("next_attempt_at").is_none());

    receiver.status.store(204, Ordering::SeqCst);
    let (status, _) = send(
        &app,
        Method::POST,
        &format!("/admin/webhooks/{webhook_id}/deliveries/{delivery_id}/retry"),
        &admin.token,
        json!({}),
    )
    .await;
    assert_eq!(status, 204);
    webhooks::deliver_once(&app.state).await.unwrap();
    eventually(|| receiver.count() >= 3).await;
    let deliveries = delivery_state(&app, &admin.token, &webhook_id).await;
    assert!(deliveries[0]["delivered_at"].is_number(), "{deliveries}");

    let (status, _) = send(
        &app,
        Method::POST,
        &format!(
            "/admin/webhooks/{webhook_id}/deliveries/{}/retry",
            Uuid::new_v4()
        ),
        &admin.token,
        json!({}),
    )
    .await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn internal_addresses_are_never_called() {
    let app = TestApp::spawn_with_config(|c| c.webhooks.allow_private_networks = false).await;
    let admin = admin(&app, 1).await;
    let (receiver, url) = Receiver::start().await;
    let (_, created) = send(
        &app,
        Method::POST,
        "/admin/webhooks",
        &admin.token,
        json!({ "url": url, "events": ["user.created"] }),
    )
    .await;

    fixtures::register_user(&app, 2).await;
    webhooks::deliver_once(&app.state).await.unwrap();
    let deliveries = delivery_state(&app, &admin.token, created["id"].as_str().unwrap()).await;
    assert!(
        deliveries[0]["last_error"]
            .as_str()
            .unwrap()
            .contains("blocked address"),
        "{deliveries}"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(receiver.count(), 0);
}

#[tokio::test]
async fn endpoints_are_checked_updated_rotated_and_removed() {
    let app = TestApp::spawn_with_config(|c| c.webhooks.allow_http = false).await;
    let admin = admin(&app, 1).await;

    for (payload, reason) in [
        (
            json!({ "url": "http://hooks.example.com/", "events": ["*"] }),
            "plain http",
        ),
        (
            json!({ "url": "https://u:p@hooks.example.com/", "events": ["*"] }),
            "credentials",
        ),
        (
            json!({ "url": "https://hooks.example.com/", "events": ["user.exploded"] }),
            "unknown event",
        ),
        (
            json!({ "url": "https://hooks.example.com/", "events": [] }),
            "no event",
        ),
    ] {
        let (status, response) =
            send(&app, Method::POST, "/admin/webhooks", &admin.token, payload).await;
        assert_eq!(status, 422, "{reason}: {response}");
    }

    let (status, created) = send(
        &app,
        Method::POST,
        "/admin/webhooks",
        &admin.token,
        json!({ "url": "https://hooks.example.com/auth", "events": ["user.deleted"], "enabled": false }),
    )
    .await;
    assert_eq!(status, 201);
    let id = created["id"].as_str().unwrap();

    // A disabled endpoint records no delivery.
    fixtures::register_user(&app, 2).await;
    let pending: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM webhook_deliveries")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(pending, 0);

    let (status, updated) = send(
        &app,
        Method::PUT,
        &format!("/admin/webhooks/{id}"),
        &admin.token,
        json!({ "url": "https://hooks.example.com/v2", "events": ["user.created", "user.deleted"] }),
    )
    .await;
    assert_eq!(status, 200, "{updated}");
    assert_eq!(updated["enabled"], true);
    assert_eq!(updated["events"], json!(["user.created", "user.deleted"]));

    let (status, rotated) = send(
        &app,
        Method::POST,
        &format!("/admin/webhooks/{id}/secret"),
        &admin.token,
        json!({}),
    )
    .await;
    assert_eq!(status, 200);
    assert_ne!(rotated["secret"], created["secret"]);

    let (_, listed) = body(app.get_auth("/admin/webhooks", &admin.token).await).await;
    assert_eq!(listed.as_array().unwrap().len(), 1);
    assert!(!listed.to_string().contains("whsec_"));

    let (status, _) = send(
        &app,
        Method::DELETE,
        &format!("/admin/webhooks/{id}"),
        &admin.token,
        json!({}),
    )
    .await;
    assert_eq!(status, 204);
    let (status, _) = send(
        &app,
        Method::DELETE,
        &format!("/admin/webhooks/{id}"),
        &admin.token,
        json!({}),
    )
    .await;
    assert_eq!(status, 404);
    let (status, _) = send(
        &app,
        Method::PUT,
        &format!("/admin/webhooks/{id}"),
        &admin.token,
        json!({ "url": "https://hooks.example.com/", "events": ["*"] }),
    )
    .await;
    assert_eq!(status, 404);

    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action::text FROM audit_log WHERE action::text LIKE 'webhook_%' ORDER BY created_at",
    )
    .fetch_all(&app.db)
    .await
    .unwrap();
    assert_eq!(
        actions,
        [
            "webhook_created",
            "webhook_updated",
            "webhook_secret_rotated",
            "webhook_deleted"
        ]
    );
}
