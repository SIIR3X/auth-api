//! Re-encryption of TOTP secrets and webhook signing secrets after an
//! encryption key change.
//!
//! Every secret not yet under the current key is decrypted (with the key its
//! ciphertext names, or by trying both keys for values written before
//! ciphertexts were versioned) and written back under the current key.
//!
//! Each row is replaced only if it still holds the value that was read, so the
//! command is safe beside live traffic, and it can be interrupted and run
//! again: rows already under the current key are skipped.
//!
//! Usage:
//!   ENCRYPTION_KEY=<new> PREVIOUS_ENCRYPTION_KEY=<old> ./auth-api --rotate-totp-keys
//! and remove PREVIOUS_ENCRYPTION_KEY once a run reports nothing rotated or failed.

use serde_json::json;

use crate::{
    domain::audit::AuditAction,
    error::AppError,
    repositories::{
        audit::{self, NewAuditEntry},
        two_factor as tf_repo, webhook as webhook_repo,
    },
    state::AppState,
    utils::crypto,
};

pub struct RotationResult {
    pub rotated: usize,
    pub skipped: usize,
    pub failed: usize,
}

/// Rewrite every TOTP and webhook secret that is not yet a `v2` ciphertext
/// under the current key. Without `PREVIOUS_ENCRYPTION_KEY` it upgrades the
/// older formats in place (binding each secret to its row); with it, it also
/// moves secrets off the previous key. Fails fast when the previous key equals
/// the current one.
pub async fn rotate_totp_encryption_key(state: &AppState) -> Result<RotationResult, AppError> {
    if let Some(previous) = state.config.crypto.previous_encryption_key.as_deref() {
        let old_key =
            crypto::decode_encryption_key(previous).map_err(|e| AppError::Internal(e.into()))?;
        let new_key = crypto::decode_encryption_key(&state.config.crypto.encryption_key)
            .map_err(|e| AppError::Internal(e.into()))?;
        if old_key == new_key {
            return Err(AppError::Internal(anyhow::anyhow!(
                "PREVIOUS_ENCRYPTION_KEY and ENCRYPTION_KEY are identical - nothing to rotate"
            )));
        }
    }

    let keyring = &state.keyring;
    let methods = tf_repo::find_all_totp_secrets(&state.db)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    let endpoints = webhook_repo::find_all_endpoints(&state.db)
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    let total = methods.len() + endpoints.len();
    let (mut rotated, mut skipped, mut failed) = (0usize, 0usize, 0usize);

    for endpoint in endpoints {
        if !keyring.needs_rotation(&endpoint.secret) {
            skipped += 1;
            continue;
        }
        let context = endpoint.id.as_bytes();
        let reencrypted = match keyring
            .decrypt(&endpoint.secret, context)
            .and_then(|plaintext| keyring.encrypt(&plaintext, context))
        {
            Ok(value) => value,
            Err(e) => {
                tracing::warn!(webhook_id = %endpoint.id, error = ?e, "cannot re-encrypt webhook secret");
                failed += 1;
                continue;
            }
        };
        match webhook_repo::rewrap_secret(&state.db, endpoint.id, &endpoint.secret, &reencrypted)
            .await
        {
            Ok(true) => rotated += 1,
            Ok(false) => skipped += 1,
            Err(e) => {
                tracing::warn!(webhook_id = %endpoint.id, error = ?e, "cannot store re-encrypted webhook secret");
                failed += 1;
            }
        }
    }

    for (id, user_id, stored) in methods {
        if !keyring.needs_rotation(&stored) {
            skipped += 1;
            continue;
        }

        let reencrypted = match keyring
            .decrypt(&stored, user_id.as_bytes())
            .and_then(|plaintext| keyring.encrypt(&plaintext, user_id.as_bytes()))
        {
            Ok(value) => value,
            Err(e) => {
                tracing::warn!(method_id = %id, error = ?e, "cannot re-encrypt TOTP secret");
                failed += 1;
                continue;
            }
        };

        match tf_repo::replace_totp_secret(&state.db, id, &stored, &reencrypted).await {
            Ok(true) => rotated += 1,
            // Changed since it was read (re-created or removed): whatever is
            // there now was written with the current key.
            Ok(false) => skipped += 1,
            Err(e) => {
                tracing::warn!(method_id = %id, error = ?e, "cannot store re-encrypted TOTP secret");
                failed += 1;
            }
        }
    }

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: None,
            request_id: None,
            action: AuditAction::EncryptionKeyRotated,
            ip_address: None,
            metadata: json!({
                "scope": "totp_and_webhook_secrets",
                "key_id": keyring.current_kid(),
                "total": total,
                "rotated": rotated,
                "skipped": skipped,
                "failed": failed,
            }),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.into()))?;

    Ok(RotationResult {
        rotated,
        skipped,
        failed,
    })
}

/// Secrets (TOTP, webhook) that cannot be read: under a key the keyring does
/// not hold, or in a format older than `v2`, which does not bind a secret to
/// its row and is no longer read.
pub async fn secrets_under_unknown_keys(state: &AppState) -> Result<usize, AppError> {
    let kids: Vec<String> = state
        .keyring
        .kids()
        .into_iter()
        .map(str::to_owned)
        .collect();
    let count: i64 = sqlx::query_scalar(
        "SELECT
             (SELECT count(*) FROM two_factor_methods
               WHERE totp_secret IS NOT NULL
                 AND (totp_secret !~ '^v2:' OR split_part(totp_secret, ':', 2) <> ALL($1)))
           + (SELECT count(*) FROM webhook_endpoints
               WHERE secret !~ '^v2:' OR split_part(secret, ':', 2) <> ALL($1))",
    )
    .bind(&kids)
    .fetch_one(&state.db)
    .await?;
    Ok(usize::try_from(count).unwrap_or(0))
}
