//! TOTP setup, verification, and recovery code management.
//!
//! Flow for enabling TOTP:
//!   1. setup_totp      -- generates a secret and stores it unverified in the DB
//!   2. verify_setup    -- user submits the first code; marks the method verified
//!                         and returns one-time recovery codes
//!
//! The TOTP secret is encrypted with AES-256-GCM before storage.
//! Recovery codes are hashed with SHA-256; the plaintext is returned once and never stored.

use serde_json::json;
use uuid::Uuid;

use crate::{
    domain::{audit::AuditAction, two_factor::TwoFactorType},
    error::AppError,
    repositories::{
        audit::{self, NewAuditEntry},
        recovery_code,
        two_factor::{self as tf_repo, NewTwoFactorMethod},
    },
    state::AppState,
    utils::{crypto, totp},
};

pub struct TotpSetupResult {
    pub method_id: Uuid,
    pub base32_secret: String,
    pub qr_uri: String,
}

/// Creates an unverified TOTP method for the user and returns setup data.
/// The user must call `verify_setup` with a valid code to activate it.
pub async fn setup_totp(state: &AppState, user_id: Uuid) -> Result<TotpSetupResult, AppError> {
    let enc_key = crypto::decode_encryption_key(&state.config.crypto.encryption_key)
        .map_err(|e| AppError::Internal(e.into()))?;

    let base32_secret = totp::generate_secret();
    let qr_uri = totp::qr_uri(&base32_secret, "", &state.config.crypto.totp_issuer);
    let encrypted = crypto::encrypt(&base32_secret, &enc_key)
        .map_err(|e| AppError::Internal(e.into()))?;

    let method = tf_repo::create(
        &state.db,
        &NewTwoFactorMethod {
            user_id,
            method_type: TwoFactorType::Totp,
            totp_secret: Some(&encrypted),
            webauthn_credential_id: None,
            webauthn_public_key: None,
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    Ok(TotpSetupResult { method_id: method.id, base32_secret, qr_uri })
}

/// Verifies the first TOTP code to confirm the user scanned the QR correctly.
/// On success: marks the method verified, sets it as primary if it is the first,
/// generates recovery codes, and returns their plaintext (shown once).
pub async fn verify_setup(
    state: &AppState,
    user_id: Uuid,
    method_id: Uuid,
    code: &str,
) -> Result<Vec<String>, AppError> {
    let method = tf_repo::find_by_user(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .into_iter()
        .find(|m| m.id == method_id)
        .ok_or(AppError::NotFound)?;

    if method.is_verified {
        return Err(AppError::Conflict("already_verified"));
    }

    let enc_key = crypto::decode_encryption_key(&state.config.crypto.encryption_key)
        .map_err(|e| AppError::Internal(e.into()))?;

    let encrypted_secret = method.totp_secret.as_deref().ok_or(AppError::NotFound)?;
    let valid = totp::verify_code(encrypted_secret, code, &enc_key)
        .map_err(|e| AppError::Internal(e.into()))?;

    if !valid {
        return Err(AppError::TwoFactorFailed);
    }

    tf_repo::mark_verified(&state.db, method_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    // Make it primary if the user has no other primary method yet
    let has_primary = tf_repo::find_primary_by_user(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .is_some();

    if !has_primary {
        tf_repo::set_primary(&state.db, method_id, user_id)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
    }

    let plaintext_codes = generate_recovery_codes(state, user_id).await?;

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user_id),
            request_id: None,
            action: AuditAction::TwoFactorEnabled,
            ip_address: None,
            metadata: json!({"method": "totp"}),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    Ok(plaintext_codes)
}

/// Generates a fresh set of recovery codes, replacing any existing ones.
/// Returns the plaintext codes which the user must store securely.
pub async fn generate_recovery_codes(
    state: &AppState,
    user_id: Uuid,
) -> Result<Vec<String>, AppError> {
    let plaintext = crypto::generate_recovery_codes(10);

    // Hash each code before storage; position is 1-based
    let hashed: Vec<(i16, Vec<u8>)> = plaintext
        .iter()
        .enumerate()
        .map(|(i, code)| {
            let hash = crypto::sha256(code.as_bytes()).to_vec();
            ((i + 1) as i16, hash)
        })
        .collect();

    let refs: Vec<(i16, &[u8])> = hashed.iter().map(|(pos, h)| (*pos, h.as_slice())).collect();

    recovery_code::delete_all_by_user(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    recovery_code::create_batch(&state.db, user_id, &refs)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    Ok(plaintext)
}

/// Validates and consumes a recovery code in lieu of a TOTP code.
pub async fn use_recovery_code(
    state: &AppState,
    user_id: Uuid,
    code: &str,
) -> Result<(), AppError> {
    let hash = crypto::sha256(code.as_bytes());

    let record = recovery_code::find_by_hash(&state.db, &hash)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .ok_or(AppError::TwoFactorFailed)?;

    // Ensure the code belongs to this user
    if record.user_id != user_id {
        return Err(AppError::TwoFactorFailed);
    }

    let consumed = recovery_code::consume(&state.db, record.id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    if !consumed {
        return Err(AppError::TwoFactorFailed);
    }

    Ok(())
}

pub async fn disable_totp(
    state: &AppState,
    user_id: Uuid,
    method_id: Uuid,
) -> Result<(), AppError> {
    tf_repo::delete(&state.db, method_id, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    // Remove recovery codes since they are tied to TOTP
    recovery_code::delete_all_by_user(&state.db, user_id)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user_id),
            request_id: None,
            action: AuditAction::TwoFactorDisabled,
            ip_address: None,
            metadata: json!({"method": "totp"}),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    Ok(())
}
