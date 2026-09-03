//! Domain events: durable account deletion and session/password notifications.

use std::time::Duration;

use futures::StreamExt;
use serde_json::{Value, json};

use crate::common::{app::TestApp, fixtures};

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
