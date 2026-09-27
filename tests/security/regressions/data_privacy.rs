//! Personal data (SEC-60): what the account's owner sees, what the audit log
//! keeps, and what downstream services hear.

use serde_json::{Value, json};

use crate::common::{app::TestApp, fixtures};

#[tokio::test]
async fn the_history_names_no_administrator_nor_their_address() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 1).await;
    let administrator = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO audit_log (user_id, action, ip_address, metadata)
         VALUES ($1, 'account_reactivated', '203.0.113.78',
                 jsonb_build_object('by', 'administrator', 'administrator_id', $2::text))",
    )
    .bind(user.id)
    .bind(administrator)
    .execute(&app.db)
    .await
    .unwrap();

    let history: Value = app
        .get_auth("/users/me/audit", &user.access_token)
        .await
        .json()
        .await
        .unwrap();
    let entry = history["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["action"] == "account_reactivated")
        .expect("the change stays in the history");
    assert_eq!(entry["metadata"], json!({ "by": "administrator" }));
    assert_eq!(entry["ip_address"], Value::Null);
}

#[tokio::test]
async fn a_replay_is_audited_without_addresses_in_its_metadata() {
    let app = TestApp::spawn_with_config(|config| config.jwt.strict_session_binding = true).await;
    let user = fixtures::authenticated_user(&app, 2).await;
    sqlx::query("UPDATE sessions SET ip_address = '198.51.100.9' WHERE user_id = $1")
        .bind(user.id)
        .execute(&app.db)
        .await
        .unwrap();

    let res = app
        .post(
            "/auth/refresh",
            &json!({ "refresh_token": user.refresh_token }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 401);
    let metadata: Value = sqlx::query_scalar(
        "SELECT metadata FROM audit_log WHERE user_id = $1 AND action = 'session_replay_detected'",
    )
    .bind(user.id)
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert!(!metadata.to_string().contains("198.51.100.9"), "{metadata}");
    assert_eq!(metadata["same_network"], false);
}

#[tokio::test]
async fn purging_a_never_verified_account_reaches_the_webhooks() {
    let app = TestApp::spawn().await;
    sqlx::query(
        "INSERT INTO webhook_endpoints (url, events, secret)
         VALUES ('https://hooks.example.com/auth', ARRAY['user.deleted'], 'v2:unused')",
    )
    .execute(&app.db)
    .await
    .unwrap();
    let pending = fixtures::register_user(&app, 3).await;
    sqlx::query("UPDATE users SET created_at = NOW() - INTERVAL '30 days' WHERE id = $1")
        .bind(pending.id)
        .execute(&app.db)
        .await
        .unwrap();

    let purged: i32 =
        sqlx::query_scalar("SELECT purge_unverified_accounts('7 days'::interval, 10)")
            .fetch_one(&app.db)
            .await
            .unwrap();
    assert_eq!(purged, 1);
    let deliveries: Vec<Value> = sqlx::query_scalar(
        "SELECT payload FROM webhook_deliveries WHERE event_name = 'user.deleted'",
    )
    .fetch_all(&app.db)
    .await
    .unwrap();
    assert_eq!(deliveries, vec![json!({ "user_id": pending.id })]);
}

#[tokio::test]
async fn the_export_holds_every_way_in_and_where_links_were_asked_from() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 4).await;
    sqlx::query(
        "INSERT INTO external_identities (user_id, provider, subject) VALUES ($1, 'github', '4242')",
    )
    .bind(user.id)
    .execute(&app.db)
    .await
    .unwrap();

    let document: Value = app
        .get_auth("/users/me/export", &user.access_token)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(document["external_identities"][0]["provider"], "github");
    assert!(document["passkeys"].is_array());
    assert!(document["personal_access_tokens"].is_array());
    assert_eq!(document["mailed_link_requests"][0]["kind"], "verification");
}
