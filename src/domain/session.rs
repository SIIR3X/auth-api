//! Session domain type.
//!
//! Maps the `sessions` table. token_hash is a SHA-256 digest of the raw
//! token; the plaintext is never persisted.

use ipnetwork::IpNetwork;

use time::OffsetDateTime;
use uuid::Uuid;

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
    pub compromise_reason: Option<SessionCompromiseReason>,
}

impl Session {
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none() && self.expires_at > OffsetDateTime::now_utc()
    }

    pub fn is_compromised(&self) -> bool {
        self.compromised_at.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session(revoked: bool, expires_in_secs: i64, compromised: bool) -> Session {
        let now = OffsetDateTime::now_utc();
        Session {
            id: uuid::Uuid::new_v4(),
            user_id: uuid::Uuid::new_v4(),
            session_family_id: uuid::Uuid::new_v4(),
            last_used_at: now,
            expires_at: now + time::Duration::seconds(expires_in_secs),
            created_at: now,
            revoked_at: if revoked { Some(now) } else { None },
            rotated_at: None,
            compromised_at: if compromised { Some(now) } else { None },
            replaced_by_session_id: None,
            ip_address: None,
            device_name: None,
            remember_me: false,
            token_hash: vec![0u8; 32],
            user_agent: None,
            compromise_reason: None,
        }
    }

    #[test]
    fn is_active_true_when_not_revoked_and_not_expired() {
        assert!(make_session(false, 3600, false).is_active());
    }

    #[test]
    fn is_active_false_when_revoked() {
        assert!(!make_session(true, 3600, false).is_active());
    }

    #[test]
    fn is_active_false_when_expired() {
        assert!(!make_session(false, -1, false).is_active());
    }

    #[test]
    fn is_compromised_true_when_compromised_at_is_set() {
        assert!(make_session(false, 3600, true).is_compromised());
    }

    #[test]
    fn is_compromised_false_when_not_compromised() {
        assert!(!make_session(false, 3600, false).is_compromised());
    }
}
