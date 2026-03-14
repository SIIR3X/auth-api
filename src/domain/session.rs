//! Session domain type.
//!
//! Maps the `sessions` table. token_hash is a SHA-256 digest of the raw
//! token; the plaintext is never persisted.

use std::net::IpAddr;

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
    pub ip_address: Option<IpAddr>,
    pub device_name: Option<String>,
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
