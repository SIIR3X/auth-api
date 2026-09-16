//! Domain events: durable account deletion, the transactional outbox and its
//! relay.

use std::time::Duration;

use futures::StreamExt;
use serde_json::{Value, json};

use crate::common::{app::TestApp, fixtures};

/// Subscribe before acting, then wait for the message whose payload carries
/// `user_id`, headers included.
async fn next_message_for(
    subscriber: &mut async_nats::Subscriber,
    user_id: uuid::Uuid,
) -> Option<async_nats::Message> {
    let wanted = user_id.to_string();
    tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(message) = subscriber.next().await {
            let payload: Value = serde_json::from_slice(&message.payload).ok()?;
            if payload["user_id"] == wanted.as_str() {
                return Some(message);
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
}

async fn published_at(app: &TestApp, event_id: &str) -> Option<time::OffsetDateTime> {
    sqlx::query_scalar("SELECT published_at FROM event_outbox WHERE id = $1::uuid")
        .bind(event_id)
        .fetch_one(&app.db)
        .await
        .unwrap()
}

/// Subscribe before acting, then wait for the event carrying `user_id`.
async fn next_event_for(
    subscriber: &mut async_nats::Subscriber,
    user_id: uuid::Uuid,
) -> Option<Value> {
    let wanted = user_id.to_string();
    tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(message) = subscriber.next().await {
            let payload: Value = serde_json::from_slice(&message.payload).ok()?;
            if payload["user_id"] == wanted.as_str() {
                return Some(payload);
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
}

#[tokio::test]
async fn account_deletion_publishes_user_deleted_through_jetstream() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 680).await;
    let mut events = app
        .state
        .nats
        .subscribe("events.auth.user.deleted")
        .await
        .unwrap();

    let res = app
        .delete_auth_json("/users/me", &user.access_token, &json!({}))
        .await;
    assert_eq!(res.status().as_u16(), 204);

    let event = next_event_for(&mut events, user.id).await;
    assert!(event.is_some(), "user.deleted must be published");

    // The stream that stores it is declared by auth-api at startup.
    let stream = async_nats::jetstream::new(app.state.nats.clone())
        .get_stream(auth_api::services::events::USER_STREAM_NAME)
        .await;
    assert!(stream.is_ok(), "AUTH_EVENTS stream must exist");
}

#[tokio::test]
async fn a_password_change_announces_revoked_sessions() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 681).await;
    let mut revoked = app
        .state
        .nats
        .subscribe("events.auth.user.sessions_revoked")
        .await
        .unwrap();
    let mut changed = app
        .state
        .nats
        .subscribe("events.auth.user.password_changed")
        .await
        .unwrap();

    let res = app
        .patch_auth(
            "/users/me/password",
            &user.access_token,
            &json!({ "new_password": "Brand-New-Pass-681" }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 204);

    assert!(next_event_for(&mut changed, user.id).await.is_some());
    assert!(next_event_for(&mut revoked, user.id).await.is_some());
}

#[tokio::test]
async fn an_event_carries_its_identity_in_the_payload_and_as_message_id() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 682).await;
    let mut changed = app
        .state
        .nats
        .subscribe("events.auth.user.password_changed")
        .await
        .unwrap();

    let res = app
        .patch_auth(
            "/users/me/password",
            &user.access_token,
            &json!({ "new_password": "Brand-New-Pass-682" }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 204);

    let message = next_message_for(&mut changed, user.id)
        .await
        .expect("user.password_changed must be published");
    let payload: Value = serde_json::from_slice(&message.payload).unwrap();
    let event_id = payload["event_id"]
        .as_str()
        .expect("an event id")
        .to_owned();
    let occurred_at = payload["occurred_at"].as_str().expect("an occurrence time");
    time::OffsetDateTime::parse(occurred_at, &time::format_description::well_known::Rfc3339)
        .expect("occurred_at is RFC 3339");

    let message_id = message
        .headers
        .as_ref()
        .and_then(|headers| headers.get(async_nats::header::NATS_MESSAGE_ID))
        .map(|value| value.as_str().to_owned());
    assert_eq!(
        message_id.as_deref(),
        Some(event_id.as_str()),
        "JetStream deduplicates on the event id"
    );
    // Subscribers can see the message before the relay records the
    // acknowledgement: wait for it.
    let marked = tokio::time::timeout(Duration::from_secs(5), async {
        while published_at(&app, &event_id).await.is_none() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(marked.is_ok(), "the relay marks what JetStream stored");
}

#[tokio::test]
async fn registration_announces_the_new_account() {
    let app = TestApp::spawn().await;
    let mut created = app
        .state
        .nats
        .subscribe("events.auth.user.created")
        .await
        .unwrap();

    let user = fixtures::register_user(&app, 683).await;

    let message = next_message_for(&mut created, user.id)
        .await
        .expect("user.created must be published");
    let payload: Value = serde_json::from_slice(&message.payload).unwrap();
    let mut fields: Vec<&str> = payload
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();
    assert_eq!(
        fields,
        ["event_id", "occurred_at", "user_id"],
        "events carry no address or username"
    );
}

#[tokio::test]
async fn a_rolled_back_change_records_no_event_and_a_committed_one_is_relayed() {
    let app = TestApp::spawn().await;
    let user_id = uuid::Uuid::new_v4();
    let count = || async {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM event_outbox WHERE payload->>'user_id' = $1",
        )
        .bind(user_id.to_string())
        .fetch_one(&app.db)
        .await
        .unwrap()
    };
    let event = auth_api::services::events::UserSessionsRevoked { user_id };

    let mut tx = app.db.begin().await.unwrap();
    auth_api::services::events::enqueue(&mut *tx, "user.sessions_revoked", &event)
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(count().await, 0, "a rolled-back change announces nothing");

    let mut tx = app.db.begin().await.unwrap();
    auth_api::services::events::enqueue(&mut *tx, "user.sessions_revoked", &event)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    auth_api::services::events::wake();
    assert_eq!(count().await, 1);

    let published = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let pending: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM event_outbox
                 WHERE payload->>'user_id' = $1 AND published_at IS NULL",
            )
            .bind(user_id.to_string())
            .fetch_one(&app.db)
            .await
            .unwrap();
            if pending == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(published.is_ok(), "the relay publishes a committed event");
}

#[tokio::test]
async fn one_instance_relays_at_a_time() {
    let app = TestApp::spawn().await;
    let user_id = uuid::Uuid::new_v4();

    let mut holder = app.db.acquire().await.unwrap();
    sqlx::query("SELECT pg_advisory_lock(hashtextextended('auth_api_event_relay', 0))")
        .execute(&mut *holder)
        .await
        .unwrap();

    auth_api::services::events::enqueue(
        &app.db,
        "user.sessions_revoked",
        &auth_api::services::events::UserSessionsRevoked { user_id },
    )
    .await
    .unwrap();
    let relayed = auth_api::services::events::relay_once(&app.db, &app.state.nats)
        .await
        .unwrap();
    assert_eq!(relayed, 0, "no publication while another instance relays");

    sqlx::query("SELECT pg_advisory_unlock(hashtextextended('auth_api_event_relay', 0))")
        .execute(&mut *holder)
        .await
        .unwrap();
    let relayed = auth_api::services::events::relay_once(&app.db, &app.state.nats)
        .await
        .unwrap();
    assert_eq!(relayed, 1, "the event goes out once the lock is free");
}

#[tokio::test]
async fn published_events_are_swept_after_a_week() {
    let app = TestApp::spawn().await;
    for (subject, published) in [
        ("events.auth.user.old", "NOW() - INTERVAL '8 days'"),
        ("events.auth.user.recent", "NOW() - INTERVAL '1 day'"),
    ] {
        sqlx::query(&format!(
            "INSERT INTO event_outbox (subject, payload, published_at) VALUES ($1, '{{}}', {published})"
        ))
        .bind(subject)
        .execute(&app.db)
        .await
        .unwrap();
    }

    auth_api::services::cleanup::run_once(&app.db, &app.state.config)
        .await
        .unwrap();

    let left: Vec<String> = sqlx::query_scalar(
        "SELECT subject FROM event_outbox WHERE subject LIKE 'events.auth.user.%' ORDER BY subject",
    )
    .fetch_all(&app.db)
    .await
    .unwrap();
    assert_eq!(left, ["events.auth.user.recent"]);
}

#[tokio::test]
async fn old_audit_addresses_keep_only_their_network() {
    let app = TestApp::spawn().await;
    for (ip, age) in [
        ("10.1.2.3", "100 days"),
        ("2001:db8:1:2::7", "100 days"),
        ("10.9.9.9", "1 day"),
    ] {
        sqlx::query(&format!(
            "INSERT INTO audit_log (action, ip_address, created_at)
             VALUES ('login', $1::inet, NOW() - INTERVAL '{age}')"
        ))
        .bind(ip)
        .execute(&app.db)
        .await
        .unwrap();
    }

    auth_api::services::cleanup::run_once(&app.db, &app.state.config)
        .await
        .unwrap();

    let addresses: Vec<String> = sqlx::query_scalar(
        "SELECT ip_address::text FROM audit_log WHERE action = 'login' ORDER BY created_at",
    )
    .fetch_all(&app.db)
    .await
    .unwrap();
    assert_eq!(addresses, ["10.1.2.0/24", "2001:db8:1::/48", "10.9.9.9/32"]);
}

#[tokio::test]
async fn a_failed_publication_holds_the_queue_until_it_is_due_again() {
    let app = TestApp::builder()
        .fault_proxies()
        .without_event_relay()
        .spawn()
        .await;
    let nats = &app.dependencies.as_ref().unwrap().nats;
    let (first, second) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
    let state_of = || async {
        sqlx::query_as::<_, (String, i32, bool, bool)>(
            "SELECT payload->>'user_id', attempts, last_error IS NOT NULL, published_at IS NOT NULL
             FROM event_outbox WHERE payload->>'user_id' = ANY($1) ORDER BY seq",
        )
        .bind(vec![first.to_string(), second.to_string()])
        .fetch_all(&app.db)
        .await
        .unwrap()
    };

    nats.set(testkit::Fault::Refuse);
    for user_id in [first, second] {
        auth_api::services::events::enqueue(
            &app.db,
            "user.sessions_revoked",
            &auth_api::services::events::UserSessionsRevoked { user_id },
        )
        .await
        .unwrap();
    }

    let relayed = auth_api::services::events::relay_once(&app.db, &app.state.nats)
        .await
        .unwrap();
    assert_eq!(relayed, 0);
    assert_eq!(
        state_of().await,
        [
            (first.to_string(), 1, true, false),
            (second.to_string(), 0, false, false)
        ],
        "the failed event is scheduled for a retry and holds the one behind it"
    );

    // Not due yet: nothing is attempted.
    auth_api::services::events::relay_once(&app.db, &app.state.nats)
        .await
        .unwrap();
    assert_eq!(state_of().await[0].1, 1);

    nats.set(testkit::Fault::None);
    sqlx::query("UPDATE event_outbox SET next_attempt_at = NOW() WHERE payload->>'user_id' = $1")
        .bind(first.to_string())
        .execute(&app.db)
        .await
        .unwrap();
    let delivered = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let _ = auth_api::services::events::relay_once(&app.db, &app.state.nats).await;
            let rows = state_of().await;
            if rows.iter().all(|row| row.3) {
                return rows;
            }
            sqlx::query(
                "UPDATE event_outbox SET next_attempt_at = NOW() WHERE published_at IS NULL",
            )
            .execute(&app.db)
            .await
            .unwrap();
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .expect("both events are published once the broker is back");
    assert!(delivered.iter().all(|row| row.3));
}

#[tokio::test]
async fn retention_settings_at_zero_purge_and_coarsen_nothing() {
    let app = TestApp::spawn_with_config(|config| {
        config.cleanup.unverified_accounts_retention_days = 0;
        config.audit.ip_retention_days = 0;
    })
    .await;
    let pending = fixtures::register_user(&app, 690).await;
    sqlx::query("UPDATE users SET created_at = NOW() - INTERVAL '400 days' WHERE id = $1")
        .bind(pending.id)
        .execute(&app.db)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO audit_log (action, ip_address, created_at)
         VALUES ('login', '10.4.4.4', NOW() - INTERVAL '200 days')",
    )
    .execute(&app.db)
    .await
    .unwrap();

    auth_api::services::cleanup::run_once(&app.db, &app.state.config)
        .await
        .unwrap();

    let kept: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE id = $1)")
        .bind(pending.id)
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert!(kept, "0 keeps never-verified accounts");
    let address: String =
        sqlx::query_scalar("SELECT ip_address::text FROM audit_log WHERE ip_address = '10.4.4.4'")
            .fetch_one(&app.db)
            .await
            .unwrap();
    assert_eq!(address, "10.4.4.4/32", "0 keeps full addresses");
}
