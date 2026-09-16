//! Decisions of the event outbox relay: when to retry a publication, and the
//! message an event becomes.

use std::time::Duration;

use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

/// Delay before the second attempt.
pub const FIRST_RETRY: Duration = Duration::from_secs(1);
/// Longest delay between two attempts.
pub const MAX_RETRY: Duration = Duration::from_secs(60);

/// Delay before the next attempt after `failed_attempts` failures: one second,
/// doubling up to a minute. The broker is usually back within seconds; a longer
/// outage is retried every minute rather than hammered.
pub fn retry_delay(failed_attempts: i32) -> Duration {
    if failed_attempts <= 0 {
        return Duration::ZERO;
    }
    let doublings = (failed_attempts - 1).min(6).unsigned_abs();
    FIRST_RETRY
        .saturating_mul(2u32.pow(doublings))
        .min(MAX_RETRY)
}

/// The published message: the event's payload with its identity, so consumers
/// can deduplicate (`event_id`) and date what they receive (`occurred_at`, when
/// the transaction of the change started). A payload that is not an object is
/// wrapped under `data`.
pub fn envelope(payload: Value, event_id: Uuid, occurred_at: OffsetDateTime) -> Value {
    let mut object = match payload {
        Value::Object(object) => object,
        other => {
            let mut object = serde_json::Map::new();
            object.insert("data".to_owned(), other);
            object
        }
    };
    object.insert("event_id".to_owned(), Value::String(event_id.to_string()));
    object.insert(
        "occurred_at".to_owned(),
        Value::String(occurred_at.format(&Rfc3339).unwrap_or_default()),
    );
    Value::Object(object)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn retries_double_from_one_second_up_to_a_minute() {
        for (failures, secs) in [
            (i32::MIN, 0),
            (0, 0),
            (1, 1),
            (2, 2),
            (3, 4),
            (6, 32),
            (7, 60),
            (i32::MAX, 60),
        ] {
            assert_eq!(
                retry_delay(failures),
                Duration::from_secs(secs),
                "{failures} failures"
            );
        }
    }

    #[test]
    fn the_envelope_adds_the_event_identity_to_the_payload() {
        let id = Uuid::nil();
        let at = OffsetDateTime::UNIX_EPOCH;
        let message = envelope(json!({ "user_id": "u" }), id, at);
        assert_eq!(
            message,
            json!({
                "user_id": "u",
                "event_id": "00000000-0000-0000-0000-000000000000",
                "occurred_at": "1970-01-01T00:00:00Z",
            })
        );
    }

    #[test]
    fn a_payload_that_is_not_an_object_is_wrapped() {
        let message = envelope(json!([1, 2]), Uuid::nil(), OffsetDateTime::UNIX_EPOCH);
        assert_eq!(message["data"], json!([1, 2]));
        assert!(message["event_id"].is_string());
    }
}
