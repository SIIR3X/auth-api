//! Session domain type.
//!
//! Maps the `sessions` table. token_hash is a SHA-256 digest of the raw
//! token; the plaintext is never persisted.

use ipnetwork::IpNetwork;

use time::OffsetDateTime;
use uuid::Uuid;

/// Longest device label the sessions table stores (`VARCHAR(100)`).
pub const DEVICE_NAME_MAX_CHARS: usize = 100;

/// Normalize a client-supplied device name: control characters removed,
/// whitespace trimmed, at most `DEVICE_NAME_MAX_CHARS` characters. `None` when
/// nothing is left, so an unusable label never reaches the database.
pub fn device_label(raw: &str) -> Option<String> {
    let cleaned: String = raw.chars().filter(|c| !c.is_control()).collect();
    let label: String = cleaned.trim().chars().take(DEVICE_NAME_MAX_CHARS).collect();
    let label = label.trim_end();
    (!label.is_empty()).then(|| label.to_owned())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, sqlx::Type, utoipa::ToSchema)]
#[sqlx(type_name = "session_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum SessionType {
    Web,
    Device,
}

#[derive(Debug, Clone, PartialEq, sqlx::Type)]
#[sqlx(type_name = "session_compromise_reason", rename_all = "snake_case")]
pub enum SessionCompromiseReason {
    RefreshTokenReuse,
    ManualSecurityAction,
    CredentialsRotated,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub session_family_id: Uuid,
    pub last_used_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
    /// When the family's first session was created: the start of the sign-in
    /// that every rotation inherits. The absolute lifetime is measured from it.
    pub family_created_at: OffsetDateTime,
    /// Permissions consented for the client this session was issued to. Tokens
    /// carry the user's permissions restricted to these; `None` is unrestricted
    /// (password sign-in, or a client registered without scopes).
    pub scopes: Option<Vec<String>>,
    pub revoked_at: Option<OffsetDateTime>,
    pub rotated_at: Option<OffsetDateTime>,
    pub compromised_at: Option<OffsetDateTime>,
    pub replaced_by_session_id: Option<Uuid>,
    pub ip_address: Option<IpNetwork>,
    pub device_name: Option<String>,
    pub remember_me: bool,
    // 32-byte SHA-256 digest
    pub token_hash: Vec<u8>,
    pub user_agent: Option<String>,
    pub session_type: SessionType,
    pub client_id: Option<String>,
    pub compromise_reason: Option<SessionCompromiseReason>,
}

impl Session {
    pub fn is_active(&self, now: OffsetDateTime) -> bool {
        self.revoked_at.is_none() && self.expires_at > now
    }

    pub fn is_compromised(&self) -> bool {
        self.compromised_at.is_some()
    }

    /// True when this session was rotated within `grace` and not for a
    /// compromise: presenting its token again is then a concurrent refresh
    /// from the same client (two tabs, a retried request), not a replay.
    pub fn rotated_within(&self, grace: time::Duration, now: OffsetDateTime) -> bool {
        self.compromised_at.is_none()
            && self
                .rotated_at
                .is_some_and(|rotated| now - rotated <= grace)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH + time::Duration::days(20_000)
    }

    fn make_session(revoked: bool, expires_in_secs: i64, compromised: bool) -> Session {
        let now = now();
        Session {
            id: uuid::Uuid::new_v4(),
            user_id: uuid::Uuid::new_v4(),
            session_family_id: uuid::Uuid::new_v4(),
            last_used_at: now,
            expires_at: now + time::Duration::seconds(expires_in_secs),
            created_at: now,
            family_created_at: now,
            scopes: None,
            revoked_at: if revoked { Some(now) } else { None },
            rotated_at: None,
            compromised_at: if compromised { Some(now) } else { None },
            replaced_by_session_id: None,
            ip_address: None,
            device_name: None,
            remember_me: false,
            token_hash: vec![0u8; 32],
            user_agent: None,
            session_type: SessionType::Web,
            client_id: None,
            compromise_reason: None,
        }
    }

    #[test]
    fn is_active_true_when_not_revoked_and_not_expired() {
        assert!(make_session(false, 3600, false).is_active(now()));
    }

    #[test]
    fn is_active_false_when_revoked() {
        assert!(!make_session(true, 3600, false).is_active(now()));
    }

    #[test]
    fn is_active_false_when_expired() {
        assert!(!make_session(false, -1, false).is_active(now()));
    }

    #[test]
    fn is_active_ends_at_the_expiry_instant() {
        let session = make_session(false, 60, false);
        assert!(session.is_active(session.expires_at - time::Duration::nanoseconds(1)));
        assert!(!session.is_active(session.expires_at));
    }

    #[test]
    fn rotated_within_accepts_the_grace_boundary_only() {
        let grace = time::Duration::seconds(2);
        let mut session = make_session(true, 3600, false);
        session.rotated_at = Some(now());

        assert!(session.rotated_within(grace, now()));
        assert!(session.rotated_within(grace, now() + grace));
        assert!(!session.rotated_within(grace, now() + grace + time::Duration::nanoseconds(1)));
    }

    #[test]
    fn rotated_within_is_false_without_rotation_or_after_compromise() {
        let grace = time::Duration::seconds(2);
        assert!(!make_session(true, 3600, false).rotated_within(grace, now()));

        let mut compromised = make_session(true, 3600, true);
        compromised.rotated_at = Some(now());
        assert!(!compromised.rotated_within(grace, now()));
    }

    #[test]
    fn device_label_strips_controls_and_bounds_length() {
        assert_eq!(
            device_label("  My\u{7}Phone \n").as_deref(),
            Some("MyPhone")
        );
        assert_eq!(device_label("\u{0}\t "), None);
        let long = "é".repeat(DEVICE_NAME_MAX_CHARS + 20);
        assert_eq!(
            device_label(&long).unwrap().chars().count(),
            DEVICE_NAME_MAX_CHARS
        );
    }

    #[test]
    fn is_compromised_true_when_compromised_at_is_set() {
        assert!(make_session(false, 3600, true).is_compromised());
    }

    #[test]
    fn is_compromised_false_when_not_compromised() {
        assert!(!make_session(false, 3600, false).is_compromised());
    }

    mod properties {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(512))]

            #[test]
            fn a_device_label_is_bounded_clean_and_stable(raw in "(\\PC|[\\x00-\\x1f\\x7f])*") {
                if let Some(label) = device_label(&raw) {
                    prop_assert!(!label.is_empty());
                    prop_assert!(label.chars().count() <= DEVICE_NAME_MAX_CHARS);
                    prop_assert!(!label.chars().any(char::is_control));
                    prop_assert_eq!(label.trim(), label.as_str());
                    prop_assert_eq!(device_label(&label), Some(label.clone()), "not idempotent");
                }
            }
        }
    }
}
