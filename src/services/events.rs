//! Domain events published to NATS.
//!
//! Two guarantees, chosen per event:
//!
//! - [`publish`] is fire-and-forget: a failed publish is logged and the request
//!   proceeds. Right for events whose loss leaves a stale mirror that a later
//!   event repairs (`user.created`, `user.email_changed`, ...).
//! - [`publish_acked`] waits for JetStream to persist the event and returns the
//!   failure to the caller. Reserved for events whose loss is silent and
//!   permanent: `user.deleted`, whose `user_id` is the only key downstream
//!   services have to erase their data, and which nothing can resend once the
//!   account row is gone.
//!
//! JetStream delivers at least once: consumers must process idempotently.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_nats::jetstream;
use serde::Serialize;
use uuid::Uuid;

use crate::{error::AppError, state::AppState};

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

/// How long a best-effort publication may hold its request.
const PUBLISH_TIMEOUT: Duration = Duration::from_millis(500);

/// How long an acknowledged publication (account deletion) may take in all.
const ACKED_PUBLISH_TIMEOUT: Duration = Duration::from_secs(5);

/// Whether this process already declared the stream.
static STREAM_READY: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Serialize)]
pub struct UserCreated {
    pub user_id: Uuid,
    pub email: String,
    pub username: String,
}

#[derive(Debug, Serialize)]
pub struct UserDeleted {
    pub user_id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct UserEmailVerified {
    pub user_id: Uuid,
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct UserEmailChanged {
    pub user_id: Uuid,
    pub old_email: String,
    pub new_email: String,
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

/// Publish a domain event to `events.auth.{event_name}`, fire-and-forget.
pub async fn publish(state: &AppState, event_name: &str, payload: &impl Serialize) {
    let subject = format!("{SUBJECT_PREFIX}.{event_name}");

    let bytes = match serde_json::to_vec(payload) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(event = event_name, error = %e, "failed to serialize event");
            return;
        }
    };

    // The client queues the message while the broker is reachable, but its
    // queue is bounded: once full, a publication waits. Past the timeout the
    // event is dropped and counted rather than holding the request.
    match tokio::time::timeout(
        PUBLISH_TIMEOUT,
        state.nats.publish(subject.clone(), bytes.into()),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            metrics::counter!("auth_events_publish_failures_total", "reason" => "error")
                .increment(1);
            tracing::error!(subject, error = %e, "failed to publish event to NATS");
        }
        Err(_) => {
            metrics::counter!("auth_events_publish_failures_total", "reason" => "timeout")
                .increment(1);
            tracing::error!(
                subject,
                "publishing an event to NATS timed out; event dropped"
            );
        }
    }
}

/// Declare (or update) the user-event stream. Called once while the
/// application state is built, before any request can publish durably.
///
/// Refuses new events rather than dropping old ones when the ceiling is hit: a
/// dropped `user.deleted` loses an erasure obligation in silence, a refused one
/// fails the deletion with a 503 the caller can retry.
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
            discard: jetstream::stream::DiscardPolicy::New,
            ..Default::default()
        })
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Publish and wait for JetStream to persist the event; fails the caller with
/// `ServiceUnavailable` when it could not be stored.
pub async fn publish_acked(
    state: &AppState,
    event_name: &str,
    payload: &impl Serialize,
) -> Result<(), AppError> {
    let subject = format!("{SUBJECT_PREFIX}.{event_name}");
    let bytes = serde_json::to_vec(payload).map_err(|e| AppError::Internal(e.into()))?;

    // The stream may not exist yet when the broker was unreachable at startup.
    ensure_user_stream_once(&state.nats).await.map_err(|e| {
        tracing::error!(error = %e, "the user event stream is not available");
        AppError::ServiceUnavailable("nats")
    })?;

    // Two awaits: the first hands the message to the server, the second waits
    // for the acknowledgement that it is stored. Dropping the second would keep
    // the signature and lose the guarantee.
    let stored = async {
        jetstream::new(state.nats.clone())
            .publish(subject.clone(), bytes.into())
            .await
            .map_err(|e| {
                tracing::error!(subject, error = %e, "failed to publish durable event");
                AppError::ServiceUnavailable("nats")
            })?
            .await
            .map_err(|e| {
                tracing::error!(subject, error = %e, "durable event was not acknowledged");
                AppError::ServiceUnavailable("nats")
            })
    };
    tokio::time::timeout(ACKED_PUBLISH_TIMEOUT, stored)
        .await
        .map_err(|_| {
            tracing::error!(subject, "durable event was not stored in time");
            AppError::ServiceUnavailable("nats")
        })??;

    Ok(())
}
