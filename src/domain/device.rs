//! Device authorization decisions (RFC 8628), apart from their Redis storage.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Where a device request stands. Stored in Redis by name: renaming a variant
/// strands the requests in progress.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceAuthStatus {
    Pending,
    Authorized,
    Denied,
}

impl DeviceAuthStatus {
    /// Only a pending request can be approved or denied: a decision is final.
    pub fn is_undecided(&self) -> bool {
        *self == DeviceAuthStatus::Pending
    }
}

/// What a poll of a stored request leads to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollOutcome<'a> {
    Pending,
    Denied,
    Authorized {
        user_id: Uuid,
        client_id: &'a str,
    },
    /// Approved without an approver: a corrupted or forged entry.
    MissingUser,
    /// Stored without a client: forged, or older than client registration.
    MissingClient,
}

/// Judge a poll from what the request stores.
pub fn poll_outcome<'a>(
    status: &DeviceAuthStatus,
    user_id: Option<Uuid>,
    client_id: Option<&'a str>,
) -> PollOutcome<'a> {
    match (status, user_id, client_id) {
        (DeviceAuthStatus::Pending, _, _) => PollOutcome::Pending,
        (DeviceAuthStatus::Denied, _, _) => PollOutcome::Denied,
        (DeviceAuthStatus::Authorized, None, _) => PollOutcome::MissingUser,
        (DeviceAuthStatus::Authorized, Some(_), None) => PollOutcome::MissingClient,
        (DeviceAuthStatus::Authorized, Some(user_id), Some(client_id)) => {
            PollOutcome::Authorized { user_id, client_id }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_pending_request_can_be_decided() {
        assert!(DeviceAuthStatus::Pending.is_undecided());
        assert!(!DeviceAuthStatus::Authorized.is_undecided());
        assert!(!DeviceAuthStatus::Denied.is_undecided());
    }

    #[test]
    fn statuses_are_stored_under_stable_names() {
        for (status, name) in [
            (DeviceAuthStatus::Pending, "\"pending\""),
            (DeviceAuthStatus::Authorized, "\"authorized\""),
            (DeviceAuthStatus::Denied, "\"denied\""),
        ] {
            assert_eq!(serde_json::to_string(&status).unwrap(), name);
            assert_eq!(
                serde_json::from_str::<DeviceAuthStatus>(name).unwrap(),
                status
            );
        }
    }

    #[test]
    fn an_undecided_or_denied_request_ignores_what_else_it_stores() {
        let user = Some(Uuid::nil());
        for (user_id, client_id) in [(None, None), (user, Some("app"))] {
            assert_eq!(
                poll_outcome(&DeviceAuthStatus::Pending, user_id, client_id),
                PollOutcome::Pending
            );
            assert_eq!(
                poll_outcome(&DeviceAuthStatus::Denied, user_id, client_id),
                PollOutcome::Denied
            );
        }
    }

    #[test]
    fn an_approval_needs_both_its_approver_and_its_client() {
        let user_id = Uuid::new_v4();
        assert_eq!(
            poll_outcome(&DeviceAuthStatus::Authorized, Some(user_id), Some("app")),
            PollOutcome::Authorized {
                user_id,
                client_id: "app"
            }
        );
        assert_eq!(
            poll_outcome(&DeviceAuthStatus::Authorized, None, Some("app")),
            PollOutcome::MissingUser
        );
        assert_eq!(
            poll_outcome(&DeviceAuthStatus::Authorized, None, None),
            PollOutcome::MissingUser,
            "the approver is checked first"
        );
        assert_eq!(
            poll_outcome(&DeviceAuthStatus::Authorized, Some(user_id), None),
            PollOutcome::MissingClient
        );
    }
}
