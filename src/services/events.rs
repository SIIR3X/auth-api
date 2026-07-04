//! Domain event publishing via NATS JetStream.
//!
//! Events are fire-and-forget: a failed publish is logged but never blocks
//! the request path. Consumers are responsible for idempotent processing.

use serde::Serialize;
use uuid::Uuid;

use crate::state::AppState;

/// Subject prefix for all auth-api domain events.
const SUBJECT_PREFIX: &str = "events.auth";

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

/// Publish a domain event to NATS.
///
/// The subject is constructed as `events.auth.{event_name}`.
/// Failures are logged but never propagated to the caller.
pub async fn publish(state: &AppState, event_name: &str, payload: &impl Serialize) {
    let subject = format!("{SUBJECT_PREFIX}.{event_name}");

    let bytes = match serde_json::to_vec(payload) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(event = event_name, error = %e, "failed to serialize event");
            return;
        }
    };

    if let Err(e) = state.nats.publish(subject.clone(), bytes.into()).await {
        tracing::error!(subject, error = %e, "failed to publish event to NATS");
    }
}
