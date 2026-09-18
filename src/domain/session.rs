//! Session domain type.
//!
//! Maps the `sessions` table. token_hash is a SHA-256 digest of the raw
//! token; the plaintext is never persisted.

use std::net::IpAddr;

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

/// When a session issued or rotated at `now` expires: its refresh lifetime,
/// cut short by the absolute lifetime of the sign-in that started at
/// `family_started_at`. A rotation never dates a session past the moment the
/// refresh would refuse it anyway, so session listings and revocation TTLs
/// stay exact.
pub fn capped_expiry(
    now: OffsetDateTime,
    ttl_secs: u64,
    family_started_at: OffsetDateTime,
    max_lifetime_secs: u64,
) -> OffsetDateTime {
    let seconds = |secs: u64| time::Duration::seconds(i64::try_from(secs).unwrap_or(i64::MAX));
    now.saturating_add(seconds(ttl_secs))
        .min(family_started_at.saturating_add(seconds(max_lifetime_secs)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, sqlx::Type, utoipa::ToSchema)]
#[sqlx(type_name = "session_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum SessionType {
    Web,
    Device,
    PersonalAccessToken,
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

/// What a refresh token presented for a session leads to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshVerdict {
    /// Rotate the session.
    Rotate,
    /// Revoked by a rotation moments ago: the same client refreshing twice.
    /// Refused, the family left alive.
    ConcurrentRefresh,
    /// Revoked earlier: the token leaked, and the family is revoked.
    Replay,
    /// Past its expiry, or past the absolute lifetime of its sign-in.
    Expired,
    /// Presented from another address while sessions are bound to theirs.
    AddressMismatch,
}

/// The rules a refresh is judged by.
#[derive(Debug, Clone, Copy)]
pub struct RefreshPolicy {
    /// How long after a rotation a second use reads as concurrent.
    pub reuse_grace: time::Duration,
    pub max_lifetime_secs: u64,
    pub strict_binding: bool,
}

impl Session {
    /// Judge a refresh presented at `now` from `request_ip`.
    ///
    /// Revocation comes first, so a replayed token is detected even once its
    /// session has expired; then the expiry, the absolute lifetime counted from
    /// the family's first sign-in, and the address binding.
    pub fn refresh_verdict(
        &self,
        now: OffsetDateTime,
        request_ip: Option<IpAddr>,
        policy: &RefreshPolicy,
    ) -> RefreshVerdict {
        if self.revoked_at.is_some() {
            return if self.rotated_within(policy.reuse_grace, now) {
                RefreshVerdict::ConcurrentRefresh
            } else {
                RefreshVerdict::Replay
            };
        }
        if !self.is_active(now) {
            return RefreshVerdict::Expired;
        }
        let max_lifetime = i64::try_from(policy.max_lifetime_secs).unwrap_or(i64::MAX);
        if (now - self.family_created_at).whole_seconds() >= max_lifetime {
            return RefreshVerdict::Expired;
        }
        if policy.strict_binding && self.ip_address.map(|network| network.ip()) != request_ip {
            return RefreshVerdict::AddressMismatch;
        }
        RefreshVerdict::Rotate
    }
}

/// What the per-request token check learned from Redis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenState {
    /// The token's id is on the logout blocklist.
    Revoked,
    /// The session is cached as active.
    Active,
    /// The session is cached as ended (revoked or expired).
    Ended,
    /// Nothing cached: the database decides.
    Unknown,
}

/// Combine the blocklist and the session cache. The blocklist wins: a logout
/// takes effect before the cached validity expires. Only a cached `1` means
/// active; any other cached value reads as ended.
pub fn token_state(blocklisted: bool, cached: Option<u8>) -> TokenState {
    match (blocklisted, cached) {
        (true, _) => TokenState::Revoked,
        (false, None) => TokenState::Unknown,
        (false, Some(1)) => TokenState::Active,
        (false, Some(_)) => TokenState::Ended,
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

    fn policy(strict_binding: bool) -> RefreshPolicy {
        RefreshPolicy {
            reuse_grace: time::Duration::seconds(2),
            max_lifetime_secs: 86_400,
            strict_binding,
        }
    }

    #[test]
    fn a_revoked_session_reads_as_concurrent_only_within_the_grace() {
        let mut session = make_session(true, 3600, false);
        session.rotated_at = Some(now() - time::Duration::seconds(1));
        assert_eq!(
            session.refresh_verdict(now(), None, &policy(false)),
            RefreshVerdict::ConcurrentRefresh
        );
        session.rotated_at = Some(now() - time::Duration::seconds(10));
        assert_eq!(
            session.refresh_verdict(now(), None, &policy(false)),
            RefreshVerdict::Replay
        );
        session.rotated_at = None;
        assert_eq!(
            session.refresh_verdict(now(), None, &policy(false)),
            RefreshVerdict::Replay,
            "a logout is not a rotation"
        );
    }

    #[test]
    fn revocation_is_judged_before_expiry() {
        let session = make_session(true, -60, false);
        assert_eq!(
            session.refresh_verdict(now(), None, &policy(false)),
            RefreshVerdict::Replay
        );
    }

    #[test]
    fn an_expired_or_outlived_session_is_not_rotated() {
        assert_eq!(
            make_session(false, -1, false).refresh_verdict(now(), None, &policy(false)),
            RefreshVerdict::Expired
        );

        let mut session = make_session(false, 3600, false);
        session.family_created_at = now() - time::Duration::seconds(86_400);
        assert_eq!(
            session.refresh_verdict(now(), None, &policy(false)),
            RefreshVerdict::Expired,
            "the lifetime ends at its last second"
        );
        session.family_created_at = now() - time::Duration::seconds(86_399);
        assert_eq!(
            session.refresh_verdict(now(), None, &policy(false)),
            RefreshVerdict::Rotate
        );
    }

    #[test]
    fn a_bound_session_refreshes_only_from_its_address() {
        let mut session = make_session(false, 3600, false);
        session.family_created_at = now();
        let home: IpAddr = "203.0.113.7".parse().unwrap();
        let away: IpAddr = "198.51.100.1".parse().unwrap();
        session.ip_address = Some(IpNetwork::from(home));

        assert_eq!(
            session.refresh_verdict(now(), Some(home), &policy(true)),
            RefreshVerdict::Rotate
        );
        assert_eq!(
            session.refresh_verdict(now(), Some(away), &policy(true)),
            RefreshVerdict::AddressMismatch
        );
        assert_eq!(
            session.refresh_verdict(now(), None, &policy(true)),
            RefreshVerdict::AddressMismatch
        );
        assert_eq!(
            session.refresh_verdict(now(), Some(away), &policy(false)),
            RefreshVerdict::Rotate
        );
    }

    #[test]
    fn the_blocklist_wins_over_the_session_cache() {
        assert_eq!(token_state(true, Some(1)), TokenState::Revoked);
        assert_eq!(token_state(true, None), TokenState::Revoked);
        assert_eq!(token_state(false, Some(1)), TokenState::Active);
        assert_eq!(token_state(false, Some(0)), TokenState::Ended);
        assert_eq!(token_state(false, Some(2)), TokenState::Ended);
        assert_eq!(token_state(false, None), TokenState::Unknown);
    }

    #[test]
    fn a_new_sign_in_expires_with_its_refresh_lifetime() {
        assert_eq!(
            capped_expiry(now(), 3600, now(), 86_400),
            now() + time::Duration::hours(1)
        );
    }

    #[test]
    fn rotations_never_outlive_the_absolute_lifetime() {
        let started = now() - time::Duration::days(2);
        let end = started + time::Duration::days(3);
        assert_eq!(capped_expiry(now(), 30 * 86_400, started, 3 * 86_400), end);
        assert_eq!(capped_expiry(now(), 86_400, started, 3 * 86_400), end);
        assert_eq!(
            capped_expiry(now(), 86_399, started, 3 * 86_400),
            end - time::Duration::seconds(1)
        );
    }

    #[test]
    fn huge_lifetimes_saturate_instead_of_overflowing() {
        assert_eq!(
            capped_expiry(now(), u64::MAX, now(), 60),
            now() + time::Duration::minutes(1)
        );
        assert!(capped_expiry(now(), u64::MAX, now(), u64::MAX) > now());
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
        let long = "\u{e9}".repeat(DEVICE_NAME_MAX_CHARS + 20);
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
