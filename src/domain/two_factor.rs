//! Two-factor authentication domain types.
//!
//! Maps `two_factor_methods` and `recovery_codes` tables.
//! totp_secret is stored encrypted at the application layer before insert;
//! the value here is the ciphertext, not the raw secret.

use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, sqlx::Type)]
#[sqlx(type_name = "two_factor_type", rename_all = "snake_case")]
pub enum TwoFactorType {
    Totp,
    Email,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TwoFactorMethod {
    pub id: Uuid,
    pub user_id: Uuid,
    pub last_used_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub method_type: TwoFactorType,
    pub is_primary: bool,
    pub is_verified: bool,
    // Encrypted ciphertext, only set when method_type = Totp
    pub totp_secret: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RecoveryCode {
    pub id: Uuid,
    pub user_id: Uuid,
    pub created_at: OffsetDateTime,
    pub expires_at: Option<OffsetDateTime>,
    pub used_at: Option<OffsetDateTime>,
    // Position within the set, 1..=20
    pub code_position: i16,
    // 32-byte hash of the plaintext code
    pub code_hash: Vec<u8>,
}

impl RecoveryCode {
    pub fn is_used(&self) -> bool {
        self.used_at.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(used: bool) -> RecoveryCode {
        RecoveryCode {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            created_at: time::OffsetDateTime::now_utc(),
            expires_at: None,
            used_at: if used {
                Some(time::OffsetDateTime::now_utc())
            } else {
                None
            },
            code_position: 1,
            code_hash: vec![0u8; 32],
        }
    }

    #[test]
    fn is_used_returns_true_when_used_at_is_set() {
        assert!(code(true).is_used());
    }

    #[test]
    fn is_used_returns_false_when_used_at_is_none() {
        assert!(!code(false).is_used());
    }
}
