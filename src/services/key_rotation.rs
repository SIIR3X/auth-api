//! TOTP encryption key rotation.
//!
//! Decrypts every stored TOTP secret with the previous key and re-encrypts it
//! with the current key. Intended to be run as a one-off CLI command while the
//! server is either stopped or in a maintenance window.
//!
//! Usage:
//!   PREVIOUS_ENCRYPTION_KEY=<old_b64_key> ./auth-api --rotate-totp-keys

use serde_json::json;

use crate::{
    domain::audit::AuditAction,
    error::AppError,
    repositories::{
        audit::{self, NewAuditEntry},
        two_factor as tf_repo,
    },
    state::AppState,
    utils::crypto,
};

pub struct RotationResult {
    pub rotated: usize,
    pub skipped: usize,
    pub failed: usize,
}

/// Re-encrypts all TOTP secrets from `previous_encryption_key` to `encryption_key`.
/// Returns a summary of the operation.
/// Fails fast if `previous_encryption_key` is not configured.
pub async fn rotate_totp_encryption_key(state: &AppState) -> Result<RotationResult, AppError> {
    let prev_b64 = state
        .config
        .crypto
        .previous_encryption_key
        .as_deref()
        .ok_or_else(|| {
            AppError::Internal(anyhow::anyhow!(
                "PREVIOUS_ENCRYPTION_KEY must be set to run key rotation"
            ))
        })?;

    let old_key =
        crypto::decode_encryption_key(prev_b64).map_err(|e| AppError::Internal(e.into()))?;
    let new_key = crypto::decode_encryption_key(&state.config.crypto.encryption_key)
        .map_err(|e| AppError::Internal(e.into()))?;

    if old_key == new_key {
        return Err(AppError::Internal(anyhow::anyhow!(
            "PREVIOUS_ENCRYPTION_KEY and ENCRYPTION_KEY are identical - nothing to rotate"
        )));
    }

    let methods = tf_repo::find_all_totp_secrets(&state.db)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    let total = methods.len();
    let mut rotated = 0usize;
    let mut failed = 0usize;

    for (id, encrypted_secret) in methods {
        match crypto::re_encrypt(&encrypted_secret, &old_key, &new_key) {
            Ok(new_secret) => match tf_repo::update_totp_secret(&state.db, id, &new_secret).await {
                Ok(_) => rotated += 1,
                Err(e) => {
                    tracing::warn!(method_id = %id, error = ?e, "failed to update TOTP secret during rotation");
                    failed += 1;
                }
            },
            Err(e) => {
                tracing::warn!(method_id = %id, error = ?e, "failed to re-encrypt TOTP secret during rotation");
                failed += 1;
            }
        }
    }

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: None,
            request_id: None,
            action: AuditAction::TwoFactorEnabled, // closest available; extend AuditAction if needed
            ip_address: None,
            metadata: json!({
                "event": "totp_key_rotation",
                "total": total,
                "rotated": rotated,
                "failed": failed,
            }),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    Ok(RotationResult {
        rotated,
        skipped: 0,
        failed,
    })
}
