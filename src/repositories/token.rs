//! Repository for `email_verification_tokens` and `password_reset_tokens`.
//!
//! Token hashes are 32-byte SHA-256 digests. Plaintext tokens are generated
//! at the service layer and never persisted.

use std::net::IpAddr;

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::token::{EmailVerificationToken, PasswordResetToken};

// Input types

pub struct NewEmailVerificationToken<'a> {
    pub user_id: Uuid,
    pub token_hash: &'a [u8],
    pub expires_at: OffsetDateTime,
    pub request_ip: Option<IpAddr>,
    pub request_user_agent: Option<&'a str>,
    pub target_email: &'a str,
}

pub struct NewPasswordResetToken<'a> {
    pub user_id: Uuid,
    pub token_hash: &'a [u8],
    pub expires_at: OffsetDateTime,
    pub request_ip: Option<IpAddr>,
    pub request_user_agent: Option<&'a str>,
}

// Email verification

pub async fn create_verification(
    pool: &PgPool,
    input: &NewEmailVerificationToken<'_>,
) -> Result<EmailVerificationToken, sqlx::Error> {
    sqlx::query_as::<_, EmailVerificationToken>(
        "INSERT INTO email_verification_tokens
             (user_id, token_hash, expires_at, request_ip, request_user_agent, target_email)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING *",
    )
    .bind(input.user_id)
    .bind(input.token_hash)
    .bind(input.expires_at)
    .bind(input.request_ip)
    .bind(input.request_user_agent)
    .bind(input.target_email)
    .fetch_one(pool)
    .await
}

pub async fn find_verification_by_hash(
    pool: &PgPool,
    token_hash: &[u8],
) -> Result<Option<EmailVerificationToken>, sqlx::Error> {
    sqlx::query_as::<_, EmailVerificationToken>(
        "SELECT * FROM email_verification_tokens WHERE token_hash = $1 LIMIT 1",
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await
}

/// Marks the token as used. Returns false if it was already consumed.
pub async fn consume_verification(pool: &PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE email_verification_tokens
         SET used_at = NOW()
         WHERE id = $1 AND used_at IS NULL",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Invalidates any active token before issuing a new one.
pub async fn revoke_active_verification_by_user(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE email_verification_tokens
         SET used_at = NOW()
         WHERE user_id = $1 AND used_at IS NULL",
    )
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(())
}

// Password reset

pub async fn create_password_reset(
    pool: &PgPool,
    input: &NewPasswordResetToken<'_>,
) -> Result<PasswordResetToken, sqlx::Error> {
    sqlx::query_as::<_, PasswordResetToken>(
        "INSERT INTO password_reset_tokens
             (user_id, token_hash, expires_at, request_ip, request_user_agent)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING *",
    )
    .bind(input.user_id)
    .bind(input.token_hash)
    .bind(input.expires_at)
    .bind(input.request_ip)
    .bind(input.request_user_agent)
    .fetch_one(pool)
    .await
}

pub async fn find_password_reset_by_hash(
    pool: &PgPool,
    token_hash: &[u8],
) -> Result<Option<PasswordResetToken>, sqlx::Error> {
    sqlx::query_as::<_, PasswordResetToken>(
        "SELECT * FROM password_reset_tokens WHERE token_hash = $1 LIMIT 1",
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await
}

/// Marks the token as used. Returns false if it was already consumed.
pub async fn consume_password_reset(pool: &PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE password_reset_tokens
         SET used_at = NOW()
         WHERE id = $1 AND used_at IS NULL",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Invalidates any active token before issuing a new one.
pub async fn revoke_active_password_reset_by_user(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE password_reset_tokens
         SET used_at = NOW()
         WHERE user_id = $1 AND used_at IS NULL",
    )
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(())
}
