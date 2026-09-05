//! The service while PostgreSQL, Redis or NATS fail.
//!
//! Each app reaches its dependencies through fault proxies; the test switches a
//! proxy to latency, a hang or refused connections, checks what clients get,
//! restores it and checks the service recovered. The test's own `db` pool
//! bypasses the proxies, to observe what was (not) written.

use std::time::{Duration, Instant};

use serde_json::json;
use testkit::{Fault, TestApp};

use crate::common::fixtures;

async fn app_with_fault_proxies() -> TestApp {
    TestApp::builder()
        .fault_proxies()
        .config(|config| {
            // Fail fast instead of queueing on an unreachable dependency.
            config.database.acquire_timeout_secs = 2;
            config.redis.wait_timeout_ms = 500;
        })
        .spawn()
        .await
}

fn dependencies(app: &TestApp) -> &testkit::app::Dependencies {
    app.dependencies
        .as_ref()
        .expect("spawned with fault proxies")
}

async fn session_count(app: &TestApp, user_id: uuid::Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(&app.db)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_database_outage_refuses_sign_in_cleanly_and_recovers() {
    let app = app_with_fault_proxies().await;
    let user = fixtures::register_user(&app, 1).await;
    fixtures::activate_user(&app.db, user.id).await;
    let credentials = json!({ "identifier": user.email, "password": user.password });

    dependencies(&app).postgres.set(Fault::Refuse);
    let started = Instant::now();
    let refused = app.post("/auth/login", &credentials).await;
    assert_eq!(
        refused.status().as_u16(),
        503,
        "a database outage is a temporary unavailability"
    );
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "took {:?}",
        started.elapsed()
    );
    assert_eq!(
        session_count(&app, user.id).await,
        0,
        "half a sign-in was written"
    );

    dependencies(&app).postgres.set(Fault::None);
    let signed_in = app.post("/auth/login", &credentials).await;
    assert_eq!(signed_in.status().as_u16(), 200, "the pool did not recover");
    assert_eq!(session_count(&app, user.id).await, 1);
}

#[tokio::test]
#[ignore = "long: bounded by the 30 s request timeout"]
async fn a_hung_database_cannot_pin_a_request_forever() {
    let app = app_with_fault_proxies().await;
    let user = fixtures::register_user(&app, 1).await;
    fixtures::activate_user(&app.db, user.id).await;

    dependencies(&app).postgres.set(Fault::Blackhole);
    let started = Instant::now();
    let res = app
        .post(
            "/auth/login",
            &json!({ "identifier": user.email, "password": user.password }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 503);
    assert!(
        started.elapsed() < Duration::from_secs(35),
        "took {:?}",
        started.elapsed()
    );
    dependencies(&app).postgres.set(Fault::None);
}

#[tokio::test]
async fn a_redis_outage_fails_authenticated_requests_closed_and_recovers() {
    let app = app_with_fault_proxies().await;
    let user = fixtures::authenticated_user(&app, 1).await;

    dependencies(&app).redis.set(Fault::Refuse);
    let refused = app.get_auth("/users/me", &user.access_token).await;
    assert_eq!(
        refused.status().as_u16(),
        503,
        "revocation cannot be checked without Redis"
    );

    dependencies(&app).redis.set(Fault::None);
    // The pool may hold broken connections for a moment after the outage.
    let mut status = 0;
    for _ in 0..20 {
        status = app
            .get_auth("/users/me", &user.access_token)
            .await
            .status()
            .as_u16();
        if status == 200 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(status, 200, "Redis access did not recover");
}

#[tokio::test]
async fn a_slow_redis_slows_requests_without_failing_them() {
    let app = app_with_fault_proxies().await;
    let user = fixtures::authenticated_user(&app, 1).await;

    dependencies(&app)
        .redis
        .set(Fault::Latency(Duration::from_millis(100)));
    let res = app.get_auth("/users/me", &user.access_token).await;
    assert_eq!(res.status().as_u16(), 200);
}

#[tokio::test]
async fn an_account_is_not_deleted_while_its_deletion_cannot_be_announced() {
    let app = app_with_fault_proxies().await;
    let user = fixtures::authenticated_user(&app, 1).await;
    let exists = || async {
        sqlx::query_scalar::<_, bool>("SELECT EXISTS (SELECT 1 FROM users WHERE id = $1)")
            .bind(user.id)
            .fetch_one(&app.db)
            .await
            .unwrap()
    };

    dependencies(&app).nats.set(Fault::Refuse);
    let refused = app
        .delete_auth_json("/users/me", &user.access_token, &json!({}))
        .await;
    assert_eq!(
        refused.status().as_u16(),
        503,
        "downstream erasure cannot be guaranteed"
    );
    assert!(exists().await, "the account was deleted without its event");

    dependencies(&app).nats.set(Fault::None);
    let mut status = 0;
    for _ in 0..50 {
        let res = app
            .delete_auth_json("/users/me", &user.access_token, &json!({}))
            .await;
        status = res.status().as_u16();
        if status == 204 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(status, 204, "deletion did not recover with NATS");
    assert!(!exists().await);
}
