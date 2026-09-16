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

#[tokio::test]
async fn a_refresh_goes_through_without_redis() {
    let app = app_with_fault_proxies().await;
    let user = fixtures::authenticated_user(&app, 1).await;

    dependencies(&app).redis.set(Fault::Refuse);
    let res = app
        .post(
            "/auth/refresh",
            &json!({ "refresh_token": user.refresh_token }),
        )
        .await;
    assert_eq!(
        res.status().as_u16(),
        200,
        "the database is the authority on revocation; Redis only speeds it up"
    );
}

async fn ready(app: &TestApp) -> (u16, serde_json::Value) {
    let res = app.get("/ready").await;
    let status = res.status().as_u16();
    (status, res.json().await.unwrap_or_default())
}

/// Poll `/ready` until `check` holds, for up to ten seconds.
async fn ready_until(
    app: &TestApp,
    check: impl Fn(u16, &serde_json::Value) -> bool,
) -> (u16, serde_json::Value) {
    let mut last = ready(app).await;
    for _ in 0..50 {
        if check(last.0, &last.1) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        last = ready(app).await;
    }
    last
}

#[tokio::test]
async fn readiness_follows_each_dependency() {
    let app = app_with_fault_proxies().await;
    assert_eq!(ready(&app).await.0, 200);

    for name in ["redis", "database", "nats"] {
        let proxy = match name {
            "redis" => &dependencies(&app).redis,
            "database" => &dependencies(&app).postgres,
            _ => &dependencies(&app).nats,
        };
        proxy.set(Fault::Refuse);
        let (status, body) = ready_until(&app, |_, body| body[name] == "down").await;
        assert_eq!(
            (status, body[name].as_str()),
            (503, Some("down")),
            "{name}: {body}"
        );

        proxy.set(Fault::None);
        let (status, body) = ready_until(&app, |status, _| status == 200).await;
        assert_eq!(status, 200, "{name} did not recover: {body}");
    }
}

#[tokio::test]
async fn a_token_check_during_a_database_outage_is_an_outage_not_a_sign_out() {
    use deadpool_redis::redis::AsyncCommands;

    let app = app_with_fault_proxies().await;
    let user = fixtures::authenticated_user(&app, 1).await;
    let claims = app.decode_access_token(&user.access_token);
    // Without the cached validity, the check reaches the database.
    let mut conn = app.redis.get().await.unwrap();
    let _: () = conn
        .del(format!("sess_valid:{}", claims.sid))
        .await
        .unwrap();

    dependencies(&app).postgres.set(Fault::Refuse);
    let error = auth_api::services::auth::verify_token_state(&app.state, claims.jti, claims.sid)
        .await
        .expect_err("the session cannot be checked");
    let status = axum::response::IntoResponse::into_response(error).status();
    assert_eq!(status.as_u16(), 503);
}

#[tokio::test]
async fn a_hung_broker_does_not_hold_ordinary_requests() {
    let app = app_with_fault_proxies().await;
    let user = fixtures::authenticated_user(&app, 1).await;

    dependencies(&app).nats.set(Fault::Blackhole);
    let started = Instant::now();
    let res = app
        .patch_auth(
            "/users/me/password",
            &user.access_token,
            &json!({ "current_password": user.password, "new_password": "Another-Pass-2026!" }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 204);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the password change waited {:?} on the broker",
        started.elapsed()
    );
}

#[tokio::test]
async fn events_recorded_while_the_broker_is_down_go_out_when_it_returns() {
    let app = app_with_fault_proxies().await;
    let user = fixtures::authenticated_user(&app, 2).await;
    let pending_event = || async {
        sqlx::query_as::<_, (Option<time::OffsetDateTime>, i32)>(
            "SELECT published_at, attempts FROM event_outbox
             WHERE subject = 'events.auth.user.password_changed' AND payload->>'user_id' = $1",
        )
        .bind(user.id.to_string())
        .fetch_optional(&app.db)
        .await
        .unwrap()
    };

    dependencies(&app).nats.set(Fault::Refuse);
    let res = app
        .patch_auth(
            "/users/me/password",
            &user.access_token,
            &json!({ "current_password": user.password, "new_password": "Another-Pass-2026!" }),
        )
        .await;
    assert_eq!(
        res.status().as_u16(),
        204,
        "the change does not depend on the broker"
    );

    tokio::time::sleep(Duration::from_secs(3)).await;
    let (published, _) = pending_event()
        .await
        .expect("the event is recorded with the change");
    assert!(published.is_none(), "nothing reaches a broker that is down");

    dependencies(&app).nats.set(Fault::None);
    let delivered = tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            if let Some((Some(_), attempts)) = pending_event().await {
                return attempts;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await;
    assert!(
        delivered.is_ok(),
        "the event is published once the broker is back"
    );
}
