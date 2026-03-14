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
    Webauthn,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TwoFactorMethod {
    pub id: Uuid,
    pub user_id: Uuid,
    // Monotonic counter used to detect cloned WebAuthn authenticators
    pub webauthn_sign_count: i64,
    pub last_used_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub method_type: TwoFactorType,
    pub is_primary: bool,
    pub is_verified: bool,
    // Encrypted ciphertext, only set when method_type = Totp
    pub totp_secret: Option<String>,
    // Only set when method_type = Webauthn
    pub webauthn_credential_id: Option<String>,
    pub webauthn_public_key: Option<String>,
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
