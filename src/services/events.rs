//! Domain events, delivered to NATS JetStream through a transactional outbox.
//!
//! A service records an event with [`enqueue`] in the transaction of the change
//! it announces, and calls [`wake`] once committed. The relay ([`spawn_relay`])
//! publishes pending events in order and marks each one published only after
//! JetStream stored it:
//!
//! - a committed change always gets its event, even when NATS is down at the
//!   time: it is published once the broker is back;
//! - a rolled-back change announces nothing;
//! - requests never wait for the broker.
//!
//! One instance relays at a time (advisory lock). A publication that fails holds
//! the queue and is retried with backoff, so a user's events never arrive out
//! of order. Delivery is at least once: the event id is the JetStream message id,
//! which deduplicates a publication repeated after a crash, and consumers still
//! process idempotently. Every message carries `event_id` and `occurred_at`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_nats::{HeaderMap, jetstream};
use serde::Serialize;
use sqlx::{PgConnection, PgExecutor, PgPool};
use tokio::sync::Notify;
use uuid::Uuid;

use crate::{
    domain::outbox,
    error::AppError,
    repositories::event_outbox::{self, PendingEvent},
};

/// Subject prefix for all auth-api domain events.
const SUBJECT_PREFIX: &str = "events.auth";

/// The stream capturing user lifecycle events. auth-api produces them, so it
/// owns the stream's shape: consumers bind to it and never create it.
pub const USER_STREAM_NAME: &str = "AUTH_EVENTS";
const USER_SUBJECT_FILTER: &str = "events.auth.user.>";

/// How long an event stays replayable: long enough to outlast an unnoticed
/// consumer outage.
const EVENT_RETENTION: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Disk ceiling of last resort; retention bites first by orders of magnitude.
const EVENT_MAX_BYTES: i64 = 256 * 1024 * 1024;

/// JetStream deduplicates a message id seen within this window: longer than
/// the longest retry delay, so a publication repeated after a crash between the
/// acknowledgement and the outbox update is dropped by the server.
const DUPLICATE_WINDOW: Duration = Duration::from_secs(10 * 60);

/// How long an acknowledged publication may take in all.
const ACKED_PUBLISH_TIMEOUT: Duration = Duration::from_secs(5);

/// How often the relay looks for pending events when nothing woke it.
const RELAY_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Events published per relay run.
const RELAY_BATCH: i64 = 100;

/// Advisory lock held by the instance relaying.
const RELAY_LOCK_KEY: &str = "auth_api_event_relay";

/// Wakes the relay of this process when a transaction recorded events.
static WAKE: Notify = Notify::const_new();

/// Whether this process already declared the stream.
static STREAM_READY: AtomicBool = AtomicBool::new(false);

// Events carry the user id only: they are stored by JetStream for 30 days and
// read by every consumer, and a service that needs an address or a username
// reads it from the API.

#[derive(Debug, Serialize)]
pub struct UserCreated {
    pub user_id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct UserDeleted {
    pub user_id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct UserEmailVerified {
    pub user_id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct UserEmailChanged {
    pub user_id: Uuid,
}

/// The password changed (by the user or through a reset).
#[derive(Debug, Serialize)]
pub struct UserPasswordChanged {
    pub user_id: Uuid,
}

/// Every session of the user (or every other session) was revoked. Services
/// that cache access decisions for the token lifetime can drop them early.
#[derive(Debug, Serialize)]
pub struct UserSessionsRevoked {
    pub user_id: Uuid,
}

/// An administrator suspended the account: its sessions are revoked and it can
/// no longer sign in.
#[derive(Debug, Serialize)]
pub struct UserSuspended {
    pub user_id: Uuid,
}

/// An administrator lifted a suspension.
#[derive(Debug, Serialize)]
pub struct UserReactivated {
    pub user_id: Uuid,
}

/// Record `payload` as the event `events.auth.{event_name}`. Call it with the
/// transaction of the change the event announces, then [`wake`] after the
/// commit.
pub async fn enqueue<'e>(
    executor: impl PgExecutor<'e>,
    event_name: &str,
    payload: &impl Serialize,
) -> Result<(), AppError> {
    let payload = serde_json::to_value(payload).map_err(|e| AppError::Internal(e.into()))?;
    // Webhook deliveries are recorded with the event: an endpoint receives
    // exactly the events that were committed, whatever NATS is doing.
    crate::repositories::webhook::record_event(
        executor,
        &format!("{SUBJECT_PREFIX}.{event_name}"),
        event_name,
        &payload,
    )
    .await?;
    Ok(())
}

/// Tell this process's relay that events were committed, so they go out now
/// instead of at the next poll.
pub fn wake() {
    WAKE.notify_one();
    super::webhooks::wake();
}

/// Relay pending events to JetStream for the life of the process.
///
/// Each round waits for a wake-up or the poll interval first, events left from
/// before a restart included: a relay that reached for a connection the moment
/// it started would do so in every short-lived process, tests included.
pub fn spawn_relay(db: PgPool, nats: async_nats::Client) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                () = tokio::time::sleep(RELAY_POLL_INTERVAL) => {}
                () = WAKE.notified() => {}
            }
            loop {
                match relay_once(&db, &nats).await {
                    // A full batch: more may be waiting.
                    Ok(published) if published == RELAY_BATCH as usize => continue,
                    Ok(_) => break,
                    Err(e) => {
                        tracing::warn!(error = %e, "event relay run failed");
                        break;
                    }
                }
            }
        }
    })
}

/// One relay run: publish the due events at the head of the queue. Returns how
/// many were published; 0 when another instance holds the relay lock.
pub async fn relay_once(db: &PgPool, nats: &async_nats::Client) -> Result<usize, sqlx::Error> {
    let mut conn = db.acquire().await?;

    // Every instance reports the backlog, so the alert does not depend on
    // which one holds the lock.
    let (pending, oldest_secs) = event_outbox::backlog(&mut *conn).await?;
    metrics::gauge!("auth_outbox_pending").set(pending as f64);
    metrics::gauge!("auth_outbox_oldest_pending_age_seconds").set(oldest_secs);
    if pending == 0 {
        return Ok(0);
    }

    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock(hashtextextended($1, 0))")
        .bind(RELAY_LOCK_KEY)
        .fetch_one(&mut *conn)
        .await?;
    if !locked {
        return Ok(0);
    }

    let published = publish_pending(&mut conn, nats).await;

    let unlocked =
        sqlx::query_scalar::<_, bool>("SELECT pg_advisory_unlock(hashtextextended($1, 0))")
            .bind(RELAY_LOCK_KEY)
            .fetch_one(&mut *conn)
            .await;
    if !matches!(unlocked, Ok(true)) {
        // Never hand a connection that may still hold the lock back to the pool.
        conn.close_on_drop();
    }
    published
}

async fn publish_pending(
    conn: &mut PgConnection,
    nats: &async_nats::Client,
) -> Result<usize, sqlx::Error> {
    if let Err(e) = ensure_user_stream_once(nats).await {
        metrics::counter!("auth_events_publish_failures_total", "reason" => "stream").increment(1);
        tracing::warn!(error = %e, "the user event stream is not available; events wait");
        return Ok(0);
    }

    let mut published = 0;
    for event in event_outbox::head(&mut *conn, RELAY_BATCH).await? {
        // The head is not due yet: everything behind it waits, in order.
        if !event.due {
            break;
        }
        match publish_one(nats, &event).await {
            Ok(()) => {
                event_outbox::mark_published(&mut *conn, event.seq).await?;
                metrics::counter!("auth_events_published_total").increment(1);
                published += 1;
            }
            Err((reason, error)) => {
                metrics::counter!("auth_events_publish_failures_total", "reason" => reason)
                    .increment(1);
                let retry_in = outbox::retry_delay(event.attempts.saturating_add(1));
                tracing::warn!(
                    subject = event.subject,
                    attempts = event.attempts + 1,
                    retry_in_secs = retry_in.as_secs(),
                    error,
                    "event not published; the queue waits for it"
                );
                event_outbox::mark_failed(&mut *conn, event.seq, &error, retry_in).await?;
                break;
            }
        }
    }
    Ok(published)
}

/// Publish one event and wait for JetStream to store it.
async fn publish_one(
    nats: &async_nats::Client,
    event: &PendingEvent,
) -> Result<(), (&'static str, String)> {
    let message = outbox::envelope(event.payload.clone(), event.id, event.created_at);
    let bytes = serde_json::to_vec(&message).map_err(|e| ("error", e.to_string()))?;
    let mut headers = HeaderMap::new();
    headers.insert(
        async_nats::header::NATS_MESSAGE_ID,
        event.id.to_string().as_str(),
    );

    // Two awaits: the first hands the message to the server, the second waits
    // for the acknowledgement that it is stored.
    let stored = async {
        jetstream::new(nats.clone())
            .publish_with_headers(event.subject.clone(), headers, bytes.into())
            .await
            .map_err(|e| ("error", e.to_string()))?
            .await
            .map_err(|e| ("error", e.to_string()))
    };
    match tokio::time::timeout(ACKED_PUBLISH_TIMEOUT, stored).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(("timeout", "not stored in time".to_owned())),
    }
}

/// Declare (or update) the user-event stream. Called while the application
/// state is built, and by the relay before it publishes.
///
/// Refuses new events rather than dropping old ones when the ceiling is hit: a
/// dropped `user.deleted` would lose an erasure obligation in silence, while a
/// refused one stays in the outbox, holds the queue and raises
/// `AuthApiEventsStalled`.
pub async fn ensure_user_stream_once(nats: &async_nats::Client) -> Result<(), String> {
    if STREAM_READY.load(Ordering::Relaxed) {
        return Ok(());
    }
    ensure_user_stream(nats).await?;
    STREAM_READY.store(true, Ordering::Relaxed);
    Ok(())
}

/// Declare (or update) the stream unconditionally.
pub async fn ensure_user_stream(nats: &async_nats::Client) -> Result<(), String> {
    jetstream::new(nats.clone())
        .create_or_update_stream(jetstream::stream::Config {
            name: USER_STREAM_NAME.to_owned(),
            subjects: vec![USER_SUBJECT_FILTER.to_owned()],
            max_age: EVENT_RETENTION,
            max_bytes: EVENT_MAX_BYTES,
            duplicate_window: DUPLICATE_WINDOW,
            discard: jetstream::stream::DiscardPolicy::New,
            ..Default::default()
        })
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}
