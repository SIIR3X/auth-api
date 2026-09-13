//! Liveness and readiness probes, polled by Docker, nginx and the monitoring.

use serde_json::Value;

use crate::common::app::TestApp;

#[tokio::test]
async fn liveness_answers_without_checking_dependencies() {
    let app = TestApp::spawn().await;
    for path in ["/live", "/health"] {
        let res = app.get(path).await;
        assert_eq!(res.status().as_u16(), 200, "{path}");
        assert_eq!(res.text().await.unwrap(), "ok");
    }
}

#[tokio::test]
async fn readiness_reports_every_dependency() {
    let app = TestApp::spawn().await;
    let res = app.get("/ready").await;
    assert_eq!(res.status().as_u16(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(
        body,
        serde_json::json!({ "status": "ready", "database": "up", "redis": "up", "nats": "up" })
    );
}

#[tokio::test]
async fn probes_are_not_rate_limited() {
    let app = TestApp::spawn_with_config(|config| {
        config.rate_limit.requests_per_minute = 2;
    })
    .await;
    app.clear_rate_limit_key(&app.client_ip).await;
    for _ in 0..6 {
        for path in ["/live", "/ready", "/health"] {
            assert_eq!(app.get(path).await.status().as_u16(), 200, "{path}");
        }
    }
}
